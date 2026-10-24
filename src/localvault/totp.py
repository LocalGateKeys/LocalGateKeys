from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


class TotpError(ValueError):
    pass


# Decoded secret bounds. RFC 4226 wants at least 128 bits (16 bytes) but real
# enrolments use 10-byte secrets, so 10 stays the floor. 128 bytes is far above
# any HMAC block size and keeps hostile URIs/exports from allocating freely.
MIN_SECRET_BYTES = 10
MAX_SECRET_BYTES = 128
MAX_URI_LENGTH = 16 * 1024

_DIGESTS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
_DIGITS = (6, 7, 8)
_PERIOD_RANGE = (15, 120)


def wipe(buffer: bytearray) -> None:
    """Overwrite a secret buffer with zeros in place.

    Only mutable buffers can be wiped; callers must keep secrets in a
    bytearray and pass that same object here (not a copy or a slice).
    """
    buffer[:] = b"\0" * len(buffer)


def _padded_base32(compact: str) -> str:
    return compact + "=" * ((8 - len(compact) % 8) % 8)


def _decode_base32(compact: str) -> bytearray:
    """Decode normalized Base32 into a bytearray and discard the bytes copy.

    base64.b32decode can only return immutable bytes; that intermediate copy is
    the residual we cannot avoid in CPython (it is dropped immediately, but not
    overwritten). The bytearray we hand back is what callers wipe.
    """
    try:
        raw = base64.b32decode(_padded_base32(compact), casefold=True)
    except Exception as exc:  # noqa: BLE001
        raise TotpError("TOTP secret is not valid Base32") from exc
    key = bytearray(raw)
    del raw
    if len(key) < MIN_SECRET_BYTES:
        wipe(key)
        raise TotpError("TOTP secret is too short")
    if len(key) > MAX_SECRET_BYTES:
        wipe(key)
        raise TotpError("TOTP secret is too long")
    return key


def _compact_secret(value: str) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        raise TotpError("Invalid TOTP secret length")
    compact = "".join(value.strip().replace("-", "").split()).upper()
    if not compact:
        raise TotpError("TOTP secret cannot be empty")
    return compact


def normalize_secret(value: str) -> str:
    compact = _compact_secret(value)
    wipe(_decode_base32(compact))
    return compact


def decode_secret(secret: str) -> bytearray:
    """Validate a Base32 secret and return its raw key as a wipeable bytearray."""
    return _decode_base32(_compact_secret(secret))


def _validate_params(digits: Any, period: Any, algorithm: Any):
    if type(digits) is not int or digits not in _DIGITS:
        raise TotpError("Unsupported TOTP digit count")
    if type(period) is not int or not _PERIOD_RANGE[0] <= period <= _PERIOD_RANGE[1]:
        raise TotpError("Unsupported TOTP period")
    digestmod = _DIGESTS.get(algorithm.upper()) if isinstance(algorithm, str) else None
    if digestmod is None:
        raise TotpError("Unsupported TOTP algorithm")
    return digestmod


def _single(query: dict[str, list[str]], name: str, default: str) -> str:
    values = query.get(name)
    if values is None:
        return default
    if len(values) != 1:
        raise TotpError(f"Duplicate TOTP {name} parameter")
    return values[0]


def _int_param(query: dict[str, list[str]], name: str, default: int) -> int:
    value = _single(query, name, "")
    if name not in query:
        return default
    if not value.isascii() or not value.isdigit() or len(value) > 6:
        raise TotpError(f"Invalid TOTP {name}")
    return int(value)


def parse_otpauth_uri(uri: str) -> dict[str, str | int]:
    if not isinstance(uri, str) or len(uri) > MAX_URI_LENGTH:
        raise TotpError("Expected an otpauth://totp URI")
    try:
        parsed = urlparse(uri.strip())
        if parsed.scheme != "otpauth" or parsed.netloc.casefold() != "totp":
            raise TotpError("Expected an otpauth://totp URI")
        query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=64)
    except TotpError:
        raise
    except ValueError as exc:
        raise TotpError("Expected an otpauth://totp URI") from exc
    secret = normalize_secret(_single(query, "secret", ""))
    digits = _int_param(query, "digits", 6)
    period = _int_param(query, "period", 30)
    algorithm = _single(query, "algorithm", "SHA1").upper()
    _validate_params(digits, period, algorithm)
    issuer = _single(query, "issuer", "")
    if len(issuer) > 256 or len(parsed.path) > 1024:
        raise TotpError("TOTP label or issuer is too long")
    return {
        "secret": secret,
        "label": unquote(parsed.path.lstrip("/")),
        "issuer": issuer,
        "digits": digits,
        "period": period,
        "algorithm": algorithm,
    }


def generate_totp_from_key(
    key: bytearray,
    *,
    timestamp: int | None = None,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
    wipe_key: bool = True,
) -> tuple[str, int]:
    """Compute (code, seconds_remaining) from a raw key held in a bytearray.

    The key is zeroed in place before returning when ``wipe_key`` is true,
    including on error. Pass ``wipe_key=False`` only to derive a second code
    from the same buffer, and wipe it yourself afterwards.

    Residual copies: ``hmac.new`` copies the key into the HMAC object (padded
    inner/outer blocks in pure Python, or OpenSSL-owned memory). Those copies
    are released with the HMAC object but are not overwritten, so this reduces
    rather than eliminates the secret's lifetime in memory.
    """
    try:
        if type(key) is not bytearray:
            raise TotpError("TOTP key must be a bytearray so it can be wiped")
        if not MIN_SECRET_BYTES <= len(key) <= MAX_SECRET_BYTES:
            raise TotpError("TOTP key length is out of range")
        digestmod = _validate_params(digits, period, algorithm)
        if timestamp is not None and (type(timestamp) is not int or timestamp < 0):
            raise TotpError("Invalid timestamp")
        now = int(time.time()) if timestamp is None else timestamp
        counter = now // period
        mac = hmac.new(key, struct.pack(">Q", counter), digestmod)
        digest = mac.digest()
        del mac
        offset = digest[-1] & 0x0F
        binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
        code = str(binary % (10 ** digits)).zfill(digits)
        return code, period - (now % period)
    finally:
        if wipe_key and type(key) is bytearray:
            wipe(key)


def generate_totp(
    secret: str,
    *,
    timestamp: int | None = None,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> tuple[str, int]:
    _validate_params(digits, period, algorithm)
    if timestamp is not None and (type(timestamp) is not int or timestamp < 0):
        raise TotpError("Invalid timestamp")
    key = decode_secret(secret)
    try:
        return generate_totp_from_key(key, timestamp=timestamp, digits=digits, period=period,
                                      algorithm=algorithm, wipe_key=False)
    finally:
        wipe(key)


def requires_totp_confirmation(settings: Any) -> bool:
    """True when the user asked to confirm every 2FA code release (settings.totp_confirm)."""
    return getattr(settings, "totp_confirm", False) is True


# --- Google Authenticator "Transfer accounts" export -----------------------
# otpauth-migration://offline?data=<base64 MigrationPayload protobuf>.
# Decoded by hand so no protobuf dependency is needed.

_MIGRATION_ALGORITHMS = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512"}
_MIGRATION_DIGITS = {0: 6, 1: 6, 2: 8}
_MIGRATION_TYPE_TOTP = (0, 2)  # unspecified is treated as TOTP, 1 is HOTP
MAX_MIGRATION_BATCHES = 256
MAX_MIGRATION_ACCOUNTS = 256


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(data) or shift > 63:
            raise TotpError("Malformed migration data")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _fields(data: bytes):
    pos = 0
    while pos < len(data):
        key, pos = _varint(data, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _varint(data, pos)
        elif wire == 2:
            length, pos = _varint(data, pos)
            if pos + length > len(data):
                raise TotpError("Malformed migration data")
            value, pos = data[pos : pos + length], pos + length
        elif wire == 1:
            value, pos = data[pos : pos + 8], pos + 8
        elif wire == 5:
            value, pos = data[pos : pos + 4], pos + 4
        else:
            raise TotpError("Malformed migration data")
        if pos > len(data):
            raise TotpError("Malformed migration data")
        yield number, value


def parse_migration_uri(uri: str) -> dict[str, object]:
    """Decode a Google Authenticator export URI.

    Returns {"accounts": [...], "skipped": [...], "batch_index", "batch_size"}.
    Each account has the same keys as parse_otpauth_uri(). HOTP and unknown
    algorithms land in "skipped" with a reason instead of being dropped silently.
    """
    if not isinstance(uri, str) or len(uri) > 64 * 1024:
        raise TotpError("Migration link is too long")
    try:
        parsed = urlparse(uri.strip())
        if parsed.scheme != "otpauth-migration" or parsed.netloc.casefold() != "offline":
            raise TotpError("Expected an otpauth-migration://offline link")
        data = (parse_qs(parsed.query, max_num_fields=64).get("data") or [""])[0]
    except TotpError:
        raise
    except ValueError as exc:
        raise TotpError("Expected an otpauth-migration://offline link") from exc
    if not data:
        raise TotpError("Migration link has no data")
    try:
        # parse_qs turns an unescaped "+" into a space; QR readers vary.
        data = "".join(data.replace(" ", "+").split())
        data = data.replace("-", "+").replace("_", "/")
        raw = base64.b64decode(data + "=" * (-len(data) % 4), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise TotpError("Migration data is not valid Base64") from exc
    accounts: list[dict[str, str | int]] = []
    skipped: list[dict[str, str]] = []
    batch_index, batch_size = 0, 1
    for number, value in _fields(raw):
        if number == 2 and isinstance(value, int):
            batch_size = value
        elif number == 3 and isinstance(value, int):
            batch_index = value
        elif number != 1 or not isinstance(value, bytes):
            continue
        else:
            item: dict[str, object] = {"secret": b"", "name": "", "issuer": "", "algorithm": 0, "digits": 0, "type": 0}
            for sub, sub_value in _fields(value):
                key = {1: "secret", 2: "name", 3: "issuer", 4: "algorithm", 5: "digits", 6: "type"}.get(sub)
                if key:
                    item[key] = sub_value
            name = bytes(item["name"]).decode("utf-8", "replace") if isinstance(item["name"], bytes) else ""
            issuer = bytes(item["issuer"]).decode("utf-8", "replace") if isinstance(item["issuer"], bytes) else ""
            if issuer and name.startswith(issuer + ":"):
                name = name[len(issuer) + 1 :]
            label = {"label": name, "issuer": issuer}
            if len(accounts) + len(skipped) >= MAX_MIGRATION_ACCOUNTS:
                raise TotpError("Migration link contains too many accounts")
            if not all(isinstance(item[k], int) for k in ("type", "algorithm", "digits")):
                skipped.append({**label, "reason": "Malformed account entry"})
                continue
            if item["type"] not in _MIGRATION_TYPE_TOTP:
                skipped.append({**label, "reason": "Counter-based (HOTP) codes are not supported"})
                continue
            algorithm = _MIGRATION_ALGORITHMS.get(item["algorithm"])
            digits = _MIGRATION_DIGITS.get(item["digits"])
            if algorithm is None or digits is None:
                skipped.append({**label, "reason": "Unsupported algorithm or digit count"})
                continue
            secret_bytes = item["secret"] if isinstance(item["secret"], bytes) else b""
            if len(secret_bytes) > MAX_SECRET_BYTES:
                skipped.append({**label, "reason": "TOTP secret is too long"})
                continue
            try:
                secret = normalize_secret(base64.b32encode(secret_bytes).decode("ascii").rstrip("="))
            except TotpError as exc:
                skipped.append({**label, "reason": str(exc)})
                continue
            accounts.append({"secret": secret, **label, "digits": digits, "period": 30, "algorithm": algorithm})
    if not accounts and not skipped:
        raise TotpError("Migration link contains no accounts")
    if not 1 <= batch_size <= MAX_MIGRATION_BATCHES or not 0 <= batch_index < batch_size:
        raise TotpError("Malformed migration data")
    return {"accounts": accounts, "skipped": skipped, "batch_index": batch_index, "batch_size": batch_size}


def match_migration_account(accounts: list[dict], label: str, origin: str = "") -> dict | None:
    """Pick the export account that clearly belongs to a credential, else None."""
    host = urlparse(origin).hostname or ""
    words = {w for w in (label.casefold(), host.casefold(), host.casefold().removeprefix("www.").split(".")[0]) if w}
    def score(acc: dict) -> int:
        issuer = str(acc.get("issuer", "")).casefold()
        name = str(acc.get("label", "")).casefold()
        return sum(1 for w in words if w and (w in issuer or (issuer and issuer in w) or w in name))
    ranked = sorted(((score(a), i) for i, a in enumerate(accounts)), reverse=True)
    if len(accounts) == 1:
        return accounts[0]
    if ranked and ranked[0][0] > 0 and (len(ranked) < 2 or ranked[1][0] < ranked[0][0]):
        return accounts[ranked[0][1]]
    return None
