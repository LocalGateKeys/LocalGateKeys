"""Shared pieces of the LocalGateKeys file envelopes (``.lgkshare``, ``.lgkheir`` and later heir requests).

Every envelope is one canonical JSON object (sorted keys, no spaces, UTF-8) with a clear ``format``,
``version``, ``id`` (a lower-case UUID) and ``sender``.  ``.lgkshare`` adds an AES-GCM ``ciphertext`` under a
one-time code (``share.py``); the signed variant here adds the signer's Ed25519 public key, the payload as
base64 of its exact canonical bytes and an Ed25519 signature:

    {"format", "version", "id", "sender", "signer", "payload", "sig"}

The signature covers ``SIGN_CONTEXT`` followed by the canonical JSON of every field except ``sig``, so the
format name, version, id, sender, signer and payload bytes are all bound.  The byte rules are in
``docs/formats/LGKHEIR_V1.md``.
"""
from __future__ import annotations

import base64
import binascii
import json
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

SIGN_CONTEXT = b"LocalGateKeys signed envelope v1\n"
SENDER_LIMIT = 64
SIGNED_FIELDS = ("format", "version", "id", "sender", "signer", "payload")


class EnvelopeError(ValueError):
    """``reason``: ``malformed``, ``unsupported`` (another version) or ``bad-signature``."""

    def __init__(self, reason: str, message: str = "") -> None:
        super().__init__(message or reason)
        self.reason = reason


def canonical(value: Any) -> bytes:
    """Sorted keys, no spaces, UTF-8 (not ASCII-escaped): the byte form every envelope signs or authenticates."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: Any, size: int | None = None) -> bytes:
    """Strict standard base64 (padding required); ``size`` pins the decoded length."""
    if not isinstance(value, str):
        raise EnvelopeError("malformed")
    try:
        out = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise EnvelopeError("malformed") from None
    if (size is not None and len(out) != size) or b64e(out) != value:
        raise EnvelopeError("malformed")
    return out


def load_object(data: Any, limit: int) -> dict[str, Any]:
    """Parse at most ``limit`` bytes of UTF-8 JSON into an object (duplicate keys refused)."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > limit:
        raise EnvelopeError("malformed")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise EnvelopeError("malformed")
            out[key] = value
        return out

    try:
        value = json.loads(bytes(data).decode("utf-8"), object_pairs_hook=no_duplicates,
                           parse_constant=lambda _c: (_ for _ in ()).throw(EnvelopeError("malformed")))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise EnvelopeError("malformed") from None
    if not isinstance(value, dict):
        raise EnvelopeError("malformed")
    return value


def checked_id(value: Any) -> str:
    """A lower-case canonical UUID string, else ``malformed``."""
    if not isinstance(value, str):
        raise EnvelopeError("malformed")
    try:
        parsed = str(uuid.UUID(value))
    except ValueError:
        raise EnvelopeError("malformed") from None
    if parsed != value:
        raise EnvelopeError("malformed")
    return parsed


@dataclass(frozen=True)
class SignedEnvelope:
    format: str
    version: int
    id: str
    sender: str
    signer: bytes
    payload: dict[str, Any]


def _message(header: dict[str, Any]) -> bytes:
    return SIGN_CONTEXT + canonical({k: header[k] for k in SIGNED_FIELDS})


def seal_signed(fmt: str, version: int, *, package_id: str, sender: str, payload: dict[str, Any],
                signing_key: ed25519.Ed25519PrivateKey) -> bytes:
    """The canonical bytes of one signed envelope."""
    sender = str(sender or "").strip()
    if len(sender) > SENDER_LIMIT:
        raise EnvelopeError("malformed", "sender too long")
    header: dict[str, Any] = {"format": fmt, "version": version, "id": checked_id(package_id), "sender": sender,
                              "signer": b64e(signing_key.public_key().public_bytes_raw()),
                              "payload": b64e(canonical(payload))}
    header["sig"] = b64e(signing_key.sign(_message(header)))
    return canonical(header)


def open_signed(data: Any, fmt: str, version: int, *, limit: int) -> SignedEnvelope:
    """Parse and verify one signed envelope; the signature is checked before the payload is parsed."""
    outer = load_object(data, limit)
    if outer.get("format") != fmt:
        raise EnvelopeError("malformed")
    if outer.get("version") != version or type(outer.get("version")) is not int:
        raise EnvelopeError("unsupported")
    if set(outer) != {*SIGNED_FIELDS, "sig"}:
        raise EnvelopeError("malformed")
    package_id = checked_id(outer["id"])
    sender = outer["sender"]
    if not isinstance(sender, str) or len(sender) > SENDER_LIMIT:
        raise EnvelopeError("malformed")
    signer = b64d(outer["signer"], 32)
    signature = b64d(outer["sig"], 64)
    raw_payload = b64d(outer["payload"])
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(signer).verify(signature, _message(outer))
    except (InvalidSignature, ValueError):
        raise EnvelopeError("bad-signature") from None
    payload = load_object(raw_payload, limit)
    if canonical(payload) != raw_payload:
        raise EnvelopeError("malformed")
    return SignedEnvelope(fmt, version, package_id, sender, signer, payload)
