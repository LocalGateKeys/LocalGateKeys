"""A wipeable holder for secret text, and Argon2id run directly on its buffer.

A Python ``str`` cannot be wiped, so the master password lives here as UTF-8 in a
``bytearray`` that is zeroed when the secret is done with.
"""
from __future__ import annotations

import hmac
from types import TracebackType

from argon2.low_level import ffi, lib

_WIPED = "secret was wiped"


class SecretText:
    """Secret text in a wipeable buffer. Never printed, compared with ==, hashed or pickled."""

    __slots__ = ("_buffer", "_chars")

    def __init__(self, buffer: bytearray, char_count: int) -> None:
        self._buffer: bytearray | None = buffer
        self._chars = char_count

    @classmethod
    def from_str(cls, value: str) -> SecretText:
        if not isinstance(value, str):
            raise TypeError("SecretText needs a str")
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            # The stock message names the offending character; keep it out of every error.
            raise ValueError("secret is not valid text") from None
        return cls(bytearray(encoded), len(value))

    @property
    def buffer(self) -> bytearray:
        if self._buffer is None:
            raise ValueError(_WIPED)
        return self._buffer

    @property
    def char_count(self) -> int:
        if self._buffer is None:
            raise ValueError(_WIPED)
        return self._chars

    def equals(self, other: SecretText) -> bool:
        """Constant-time comparison of the two secrets."""
        return hmac.compare_digest(self.buffer, other.buffer)

    def wipe(self) -> None:
        buffer, self._buffer = self._buffer, None
        if buffer is not None:
            buffer[:] = b"\0" * len(buffer)

    def __enter__(self) -> SecretText:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.wipe()

    def __repr__(self) -> str:
        return "SecretText(***)"

    def __str__(self) -> str:
        raise TypeError("SecretText cannot be converted to str")

    def __eq__(self, other: object) -> bool:
        raise TypeError("compare with SecretText.equals()")

    def __hash__(self) -> int:
        raise TypeError("SecretText is not hashable")

    def __reduce__(self) -> tuple:
        raise TypeError("SecretText cannot be pickled")


def as_secret(value: str | SecretText) -> tuple[SecretText, bool]:
    """Return the secret and whether the caller owns it (and so must wipe it): True for a str."""
    if isinstance(value, SecretText):
        return value, False
    return SecretText.from_str(value), True


def is_blank_secret(value: object) -> bool:
    """True unless ``value`` is a non-empty ``str`` or ``SecretText`` (a wiped one raises ValueError)."""
    if isinstance(value, SecretText):
        return value.char_count == 0
    return not isinstance(value, str) or not value


def secrets_match(first: str | SecretText, second: str | SecretText) -> bool:
    """Constant-time equality of two secrets given as ``str`` or ``SecretText``.

    A ``str`` is copied into a temporary buffer that is wiped before return; a
    ``SecretText`` stays the caller's. Text that cannot be encoded matches nothing.
    """
    owned: list[SecretText] = []
    try:
        pair = []
        for value in (first, second):
            try:
                secret, mine = as_secret(value)
            except ValueError:
                return False
            if mine:
                owned.append(secret)
            pair.append(secret)
        return pair[0].equals(pair[1])
    finally:
        for secret in owned:
            secret.wipe()


def argon2id_raw(secret: bytearray, salt: bytes, *, time_cost: int, memory_cost: int,
                 parallelism: int, hash_len: int) -> bytearray:
    """Argon2id (version 0x13) of ``secret`` without copying it into an immutable object."""
    out = ffi.new("uint8_t[]", hash_len)
    view = ffi.from_buffer("uint8_t[]", secret)
    try:
        rv = lib.argon2_hash(time_cost, memory_cost, parallelism, view, len(secret), salt, len(salt),
                             out, hash_len, ffi.NULL, 0, lib.Argon2_id, lib.ARGON2_VERSION_NUMBER)
        if rv != 0:
            message = ffi.string(lib.argon2_error_message(rv)).decode("ascii", "replace")
            raise RuntimeError(f"Argon2 failed: {message}")
        return bytearray(ffi.buffer(out, hash_len))
    finally:
        del view
        ffi.memmove(out, bytes(hash_len), hash_len)
