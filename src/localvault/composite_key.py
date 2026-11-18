"""Composite key v1: key-file and YubiKey factors mixed into the password-derived key.

Spec: docs/formats/COMPOSITE_KEY_V1.md; vectors: tests/vectors/composite_key (Swift and Kotlin
read the same file).  The wrapping key is

    HKDF-SHA256(ikm = Argon2id(password) || secret_1 || secret_2...,
                salt = "localgatekeys|composite|v1",
                info = canonical JSON of the factor list, length = 32)

and with no factors it is the Argon2id output itself, so formats without factors are unchanged.
Each factor stores a short ``check`` so a wrong key file or YubiKey is reported before Argon2 runs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

COMPOSITE_SALT = b"localgatekeys|composite|v1"
CHECK_INFO = b"localgatekeys|factor-check|v1"
KEYFILE = "keyfile"
YUBIKEY_HMAC = "yubikey-hmac"
#: The only kinds, in the only order they may appear in a factor list (and in the HKDF input).
KINDS = (KEYFILE, YUBIKEY_HMAC)
SECRET_SIZE = 32
CHALLENGE_SIZE = 32
PADDED_CHALLENGE_SIZE = 64
YUBIKEY_RESPONSE_SIZE = 20
YUBIKEY_SLOTS = (1, 2)
#: A new challenge ending in one of these is drawn again: a variable-mode YubiKey slot treats the
#: trailing run of the last byte as padding (0x20 is our pad value; 0x00 is the other common pad).
CHALLENGE_REDRAW_BYTES = (0x00, 0x20)
_CHECK = re.compile(r"[0-9a-f]{16}")
_CHALLENGE = re.compile(r"[0-9a-f]{64}")

FactorKind = Literal["keyfile", "yubikey-hmac"]


class FactorMismatch(Exception):
    """The supplied key file or YubiKey is not the one this vault was set up with."""

    def __init__(self, kind: str) -> None:
        super().__init__(f"The {kind} factor does not match")
        self.kind = kind


@dataclass(frozen=True)
class FactorSpec:
    """The public description of one factor, stored next to the password wrapper (never a secret)."""

    kind: FactorKind
    check: str
    slot: int | None = None
    challenge: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError("Unknown factor kind")
        if not isinstance(self.check, str) or not _CHECK.fullmatch(self.check):
            raise ValueError("Factor check must be 16 lower-case hex digits")
        if self.kind == KEYFILE:
            if self.slot is not None or self.challenge is not None:
                raise ValueError("A key-file factor has no slot or challenge")
            return
        if type(self.slot) is not int or self.slot not in YUBIKEY_SLOTS:
            raise ValueError("YubiKey slot must be 1 or 2")
        if not isinstance(self.challenge, str) or not _CHALLENGE.fullmatch(self.challenge):
            raise ValueError("YubiKey challenge must be 64 lower-case hex digits")

    def to_json(self) -> dict[str, Any]:
        """The stored JSON object: only the fields this kind has (no ``None`` values)."""
        value: dict[str, Any] = {"kind": self.kind, "check": self.check}
        if self.slot is not None:
            value["slot"] = self.slot
        if self.challenge is not None:
            value["challenge"] = self.challenge
        return value

    @classmethod
    def from_json(cls, value: Any) -> FactorSpec:
        """Strict parse of a stored factor object; any unknown or missing field is refused."""
        if not isinstance(value, dict):
            raise ValueError("Factor must be an object")
        allowed = {"kind", "check"} if value.get("kind") == KEYFILE else {"kind", "check", "slot", "challenge"}
        if set(value) != allowed:
            raise ValueError("Factor fields are malformed")
        return cls(kind=value["kind"], check=value["check"], slot=value.get("slot"), challenge=value.get("challenge"))

    @property
    def padded_challenge(self) -> bytes:
        """The 64 bytes sent to the YubiKey (``yubikey-hmac`` only)."""
        if self.challenge is None:
            raise ValueError("Only a YubiKey factor has a challenge")
        return pad_challenge(bytes.fromhex(self.challenge))


def validate_specs(specs: Sequence[FactorSpec]) -> None:
    """At most one factor of each kind, ``keyfile`` before ``yubikey-hmac``."""
    if any(not isinstance(spec, FactorSpec) for spec in specs):
        raise ValueError("Factor list must hold FactorSpec values")
    kinds = [spec.kind for spec in specs]
    if kinds != [kind for kind in KINDS if kind in kinds]:
        raise ValueError("Factor list must hold at most one key file then at most one YubiKey")


def info(specs: Sequence[FactorSpec]) -> bytes:
    """Canonical JSON of the factor list: sorted keys, no whitespace (all values are ASCII)."""
    validate_specs(specs)
    return json.dumps([spec.to_json() for spec in specs], separators=(",", ":"), sort_keys=True).encode("ascii")


def factor_check(secret: bytes | bytearray) -> str:
    """Hex of the first 8 bytes of HMAC-SHA256(secret, "localgatekeys|factor-check|v1")."""
    if len(secret) != SECRET_SIZE:
        raise ValueError("Factor secret must be 32 bytes")
    return hmac.new(bytes(secret), CHECK_INFO, hashlib.sha256).digest()[:8].hex()


def yubikey_secret(response20: bytes | bytearray) -> bytes:
    """The factor secret of a YubiKey: SHA-256 of its 20-byte HMAC-SHA1 response."""
    if len(response20) != YUBIKEY_RESPONSE_SIZE:
        raise ValueError("YubiKey response must be 20 bytes")
    return hashlib.sha256(response20).digest()


def pad_challenge(challenge32: bytes) -> bytes:
    """The 32-byte challenge padded to 64 bytes as KeePassXC pads it: 32 bytes of value 0x20.

    These 64 bytes are what goes to the YubiKey, exactly: never hand a YubiKey library the bare
    32 bytes and let it pad.
    """
    if len(challenge32) != CHALLENGE_SIZE:
        raise ValueError("YubiKey challenge must be 32 bytes")
    pad = PADDED_CHALLENGE_SIZE - CHALLENGE_SIZE
    return bytes(challenge32) + bytes([pad]) * pad


def new_challenge() -> bytes:
    """32 random bytes for a ``yubikey-hmac`` factor, never ending in 0x00 or 0x20."""
    while True:
        challenge = os.urandom(CHALLENGE_SIZE)
        if challenge[-1] not in CHALLENGE_REDRAW_BYTES:
            return challenge


def verify(specs: Sequence[FactorSpec], secrets: Sequence[bytes | bytearray]) -> None:
    """Raise ``FactorMismatch(kind)`` for the first secret whose check differs; runs no KDF."""
    validate_specs(specs)
    if len(specs) != len(secrets):
        raise ValueError("One secret per factor is required")
    for spec, secret in zip(specs, secrets, strict=True):
        if not hmac.compare_digest(factor_check(secret), spec.check):
            raise FactorMismatch(spec.kind)


def combine(argon_out: bytes | bytearray, specs: Sequence[FactorSpec],
            secrets: Sequence[bytes | bytearray]) -> bytes | bytearray:
    """The wrapping key; ``argon_out`` itself (same object) when there are no factors.

    With factors the result is a new zeroable ``bytearray``; the caller still owns ``argon_out``.
    """
    validate_specs(specs)
    if len(specs) != len(secrets):
        raise ValueError("One secret per factor is required")
    if not specs:
        return argon_out
    if len(argon_out) != SECRET_SIZE or any(len(secret) != SECRET_SIZE for secret in secrets):
        raise ValueError("Composite key inputs must be 32 bytes each")
    ikm = bytearray(argon_out)
    try:
        for secret in secrets:
            ikm += secret
        return bytearray(HKDF(algorithm=hashes.SHA256(), length=32, salt=COMPOSITE_SALT,
                              info=info(specs)).derive(ikm))
    finally:
        ikm[:] = b"\0" * len(ikm)


def derive_wrapping_key(kdf: Callable[[], bytearray], specs: Sequence[FactorSpec],
                        secrets: Sequence[bytes | bytearray]) -> bytearray:
    """``verify`` first, then run ``kdf`` (the Argon2id step) and ``combine``.

    A wrong factor therefore fails before any Argon2 work.  With no factors the KDF output is
    returned as is; otherwise it is zeroed and the combined key returned.
    """
    verify(specs, secrets)
    argon_out = kdf()
    if not specs:
        return argon_out
    try:
        return cast(bytearray, combine(argon_out, specs, secrets))  # a new buffer when there are factors
    finally:
        argon_out[:] = b"\0" * len(argon_out)
