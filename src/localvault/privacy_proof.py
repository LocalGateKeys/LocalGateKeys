"""Privacy proof: what this device sent, as a signed JSON file (feature pack 2026-11-15, section 5).

The document lists facts read from the device, the claims Windows has guard tests for, and the
network ledger (``net_ledger``: fixed-service hosts and results; website icons and LAN peers as
counts only).  It is signed with the sync device identity's Ed25519 key when sync is set up, and
unsigned otherwise.  No new key is created.  ``verify`` is pure and backs ``lgk proof verify``.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

# lgk.exe (LocalGateKeysCli.spec) bundles neither ``cryptography`` nor ``localvault.updates`` (which imports it), and
# ``lgk proof verify`` must work there: keep this module's import path free of both.


def canonical_json(value: object) -> bytes:
    """Same canonical form as ``updates.canonical_json``: sorted keys, no whitespace, UTF-8."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")

FORMAT = "lgk-privacy-proof"
# Version 2 (2026-11-15): the signature also covers ``signature.alg``, ``device_id`` and ``public_key``. Version-1
# files (whose device id was not signed) are refused as an unsupported version.
VERSION = 2
SIGN_PREFIX = b"localgatekeys|privacy-proof|v2|"
PLATFORMS = frozenset({"windows", "mac", "ios", "android"})
SYNC_MODES = frozenset({"off", "folder", "wifi", "both"})
CLAIMS = ("connections_listed", "no_item_content_sent", "breach_prefix_only")
TOP_KEYS = frozenset({"format", "version", "generated_at", "app", "facts", "claims", "network", "signature"})
FACT_KEYS = {"sync": str, "devices": int, "shares": int, "items": int, "breach_checks": bool,
             "strict_offline": bool, "update_check": bool}
MAX_FILE_BYTES = 1024 * 1024
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

VALID, UNSIGNED, INVALID = "valid", "unsigned", "invalid"


class ProofError(ValueError):
    pass


def signed_bytes(document: Mapping[str, Any]) -> bytes:
    """``SIGN_PREFIX`` + ``canon`` of the whole document with only ``signature.value`` removed (contract 5.2)."""
    body = {key: value for key, value in document.items() if key != "signature"}
    signature = document.get("signature")
    if not isinstance(signature, Mapping):
        raise ProofError("only a document with a signature object has signed bytes")
    body["signature"] = {key: value for key, value in signature.items() if key != "value"}
    return SIGN_PREFIX + canonical_json(body)


def fingerprint(public_key: bytes) -> str:
    """First 8 bytes of SHA-256 of the raw public key, as 16 lower-case hex digits."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def sign(document: Mapping[str, Any], signing_private: bytes, device_id: str) -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(signing_private))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    out = {k: copy.deepcopy(v) for k, v in document.items() if k != "signature"}
    out["signature"] = {"alg": "Ed25519", "device_id": str(device_id),
                        "public_key": base64.b64encode(public).decode("ascii")}
    out["signature"]["value"] = base64.b64encode(key.sign(signed_bytes(out))).decode("ascii")
    return out


def _b64(value: Any, length: int) -> bytes:
    if not isinstance(value, str):
        raise ProofError("base64 value is malformed")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise ProofError("base64 value is malformed") from None
    if len(raw) != length or base64.b64encode(raw).decode("ascii") != value:
        raise ProofError("base64 value is malformed")
    return raw


def _int(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 2**53


def check_shape(doc: Any) -> None:
    """Raise ``ProofError`` unless ``doc`` has exactly the version-2 shape."""
    if not isinstance(doc, dict) or set(doc) != TOP_KEYS:
        raise ProofError("unexpected fields")
    if doc["format"] != FORMAT or type(doc["version"]) is not int:
        raise ProofError("unsupported format or version")
    if doc["version"] == 1:
        raise ProofError("version 1 file: its device id is not signed; export a new proof")
    if doc["version"] != VERSION:
        raise ProofError("unsupported format or version")
    if not isinstance(doc["generated_at"], str) or not _TIME.fullmatch(doc["generated_at"]):
        raise ProofError("generated_at is malformed")
    app = doc["app"]
    if (not isinstance(app, dict) or set(app) != {"platform", "version"} or app["platform"] not in PLATFORMS
            or not isinstance(app["version"], str) or len(app["version"]) > 64):
        raise ProofError("app is malformed")
    facts = doc["facts"]
    if not isinstance(facts, dict) or set(facts) != set(FACT_KEYS):
        raise ProofError("facts are malformed")
    for name, kind in FACT_KEYS.items():
        value = facts[name]
        if kind is bool and type(value) is not bool:
            raise ProofError("facts are malformed")
        if kind is int and not _int(value):
            raise ProofError("facts are malformed")
    if facts["sync"] not in SYNC_MODES:
        raise ProofError("facts are malformed")
    claims = doc["claims"]
    if not isinstance(claims, list) or any(c not in CLAIMS for c in claims) or len(set(claims)) != len(claims):
        raise ProofError("claims are malformed")
    network = doc["network"]
    if not isinstance(network, dict) or set(network) != {"available", "since", "entries", "counts"}:
        raise ProofError("network is malformed")
    if type(network["available"]) is not bool or not isinstance(network["entries"], list) \
            or not isinstance(network["counts"], dict) or len(network["entries"]) > 1000:
        raise ProofError("network is malformed")
    if network["since"] is not None and (not isinstance(network["since"], str) or not _TIME.fullmatch(network["since"])):
        raise ProofError("network is malformed")
    for row in network["entries"]:
        if (not isinstance(row, dict) or set(row) != {"purpose", "host", "result", "at"}
                or not all(isinstance(row[k], str) and len(row[k]) <= 300 for k in row)):
            raise ProofError("network entry is malformed")
    for key, value in network["counts"].items():
        if not isinstance(key, str) or len(key) > 64 or not _int(value):
            raise ProofError("network counts are malformed")
    signature = doc["signature"]
    if signature is not None:
        if (not isinstance(signature, dict) or set(signature) != {"alg", "device_id", "public_key", "value"}
                or signature["alg"] != "Ed25519" or not isinstance(signature["device_id"], str)
                or not 0 < len(signature["device_id"]) <= 128):
            raise ProofError("signature is malformed")


# Ed25519 verification (RFC 8032 section 5.1.7) with the strict checks libsodium applies: S < L; A and R are
# canonical encodings (y < p, and x = 0 only with the sign bit clear); neither A nor R has small order. The same checks
# run before both paths (``cryptography`` and the pure fallback below for lgk.exe, which ships without it), so the
# two give the same answer. Public data only, so no constant-time needs.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_Point = tuple[int, int, int, int]  # extended coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, x*y = T/Z
_IDENTITY: _Point = (0, 1, 1, 0)


def _edwards_add(a: _Point, b: _Point) -> _Point:
    """RFC 8032 5.1.4 addition (complete, so it also doubles)."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    pa, pb = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    pc, pd = 2 * t1 * t2 * _D % _P, 2 * z1 * z2 % _P
    e, f, g, h = pb - pa, pd - pc, pd + pc, pb + pa
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _edwards_mul(scalar: int, point: _Point) -> _Point:
    result = _IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _edwards_add(result, point)
        point = _edwards_add(point, point)
        scalar >>= 1
    return result


def _edwards_equal(a: _Point, b: _Point) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _edwards_decode(raw: bytes) -> _Point | None:
    """RFC 8032 5.1.3; ``None`` for a wrong length, y >= p, x = 0 with the sign bit set, or no square root."""
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P  # d*y^2 + 1 is never 0 (d is not a square)
    if x2 == 0:
        return None if sign else (0, y, 1, 0)
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if x & 1 != sign:
        x = _P - x
    return x, y, 1, x * y % _P


def _small_order(point: _Point) -> bool:
    """True for the 8 points of order 1, 2, 4 or 8 ([8]P is the identity)."""
    for _ in range(3):
        point = _edwards_add(point, point)
    return _edwards_equal(point, _IDENTITY)


_BASE = _edwards_decode((4 * pow(5, _P - 2, _P) % _P).to_bytes(32, "little"))
assert _BASE is not None and not _small_order(_BASE) and _edwards_equal(_edwards_mul(_L, _BASE), _IDENTITY)


def _strict_parts(public: bytes, signature: bytes) -> tuple[_Point, _Point, int] | None:
    """``(A, R, S)`` when the key and signature pass the strict checks, else ``None``."""
    if len(public) != 32 or len(signature) != 64:
        return None
    s = int.from_bytes(signature[32:], "little")
    point_a, point_r = _edwards_decode(public), _edwards_decode(signature[:32])
    if s >= _L or point_a is None or point_r is None or _small_order(point_a) or _small_order(point_r):
        return None
    return point_a, point_r, s


def _ed25519_verify_pure(public: bytes, signature: bytes, message: bytes) -> bool:
    parts = _strict_parts(public, signature)
    if parts is None:
        return False
    point_a, point_r, s = parts
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    # [S]B = R + [k]A (the cofactorless equation, as OpenSSL and libsodium check it; R is canonical, so comparing
    # points is the same as comparing the encoding of [S]B - [k]A with R's bytes).
    return _edwards_equal(_edwards_mul(s, _BASE), _edwards_add(point_r, _edwards_mul(k, point_a)))


def _ed25519_verify(public: bytes, signature: bytes, message: bytes) -> bool:
    if _strict_parts(public, signature) is None:
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:  # lgk.exe
        return _ed25519_verify_pure(public, signature, message)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_document(doc: Any) -> dict[str, Any]:
    """``{"result": valid|unsigned|invalid, "device_id", "fingerprint", "reason"}`` for a parsed document."""
    try:
        check_shape(doc)
    except ProofError as exc:
        return {"result": INVALID, "device_id": None, "fingerprint": None, "reason": str(exc)}
    signature = doc["signature"]
    if signature is None:
        return {"result": UNSIGNED, "device_id": None, "fingerprint": None, "reason": "not signed"}
    try:
        public = _b64(signature["public_key"], 32)
        value = _b64(signature["value"], 64)
        matches = _ed25519_verify(public, value, signed_bytes(doc))
    except (ProofError, ValueError):
        matches = False
    if not matches:
        return {"result": INVALID, "device_id": None, "fingerprint": None, "reason": "signature does not match"}
    return {"result": VALID, "device_id": signature["device_id"], "fingerprint": fingerprint(public), "reason": ""}


def verify_bytes(data: bytes) -> dict[str, Any]:
    from .strict_json import strict_loads

    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_FILE_BYTES:
        return {"result": INVALID, "device_id": None, "fingerprint": None, "reason": "file is too large"}
    try:
        doc = strict_loads(bytes(data))
    except (ValueError, RecursionError, UnicodeDecodeError):
        return {"result": INVALID, "device_id": None, "fingerprint": None, "reason": "not valid JSON"}
    return verify_document(doc)


EXIT_CODES = {VALID: 0, UNSIGNED: 3, INVALID: 1}


def file_name(day: str) -> str:
    return f"LocalGateKeys-privacy-proof-{day}.json"


__all__ = ["CLAIMS", "EXIT_CODES", "FORMAT", "INVALID", "SIGN_PREFIX", "UNSIGNED", "VALID", "VERSION",
           "check_shape", "file_name", "fingerprint", "sign", "signed_bytes", "verify_bytes", "verify_document"]
