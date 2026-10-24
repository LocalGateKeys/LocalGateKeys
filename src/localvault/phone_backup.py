"""The ``LGKMBAK1`` phone backup file: an encrypted, password-protected copy of a phone's vault states.

Layout (frozen by the test vectors; Kotlin and Swift implement the same bytes)::

    file   = canonical_json({"ciphertext": b64(ct || tag), "header": header})   # no trailing newline
    header = {"created_at": int, "format": "LGKMBAK1",
              "kdf": {name, time_cost, memory_cost_kib, parallelism},
              "nonce": b64(12 bytes), "platform": "android" | "ios",
              "salt": b64(16 bytes), "version": 1}
    key    = Argon2id v1.3 (password UTF-8 as typed, salt, kdf) -> 32 bytes
    ct     = AES-256-GCM(key, nonce, plaintext = canonical_json(payload), aad = canonical_json(header))
    payload = {"app_version": str (1..32), "device_id": str (valid id), "pro_hint": bool,
               "states": [{"deleted": bool, "deleted_at": int | null, "id": str,
                           "item": dict | null, "vv": {device: int}} ...],  # sorted by id, unique
               "version": 1}

b64 is standard base64 with padding and must be canonical (re-encoding the decoded bytes gives the same
text). app_version is printable ASCII (0x20..0x7E). The reader rejects any vv counter equal to 0 (a
zero is the same as missing, so the writer never emits one), which keeps read -> write byte-identical. The device identity and group key are never in the file.
Wrong passwords and tampering are indistinguishable: both give ``WRONG_PASSWORD``.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault.sync.engine import EngineError, ItemState, is_valid_id
from localvault.sync.vault_bridge import MAX_SYNC_RECORDS
from localvault.updates import canonical_json
from localvault.vault import MAX_KDF_MEMORY_KIB, MIN_KDF_MEMORY_KIB

FORMAT = "LGKMBAK1"
VERSION = 1
KDF = {"name": "argon2id", "time_cost": 4, "memory_cost_kib": 131072, "parallelism": 4}
MAX_FILE_BYTES = 64 * 1024 * 1024
PLATFORMS = frozenset({"android", "ios"})
WRONG_PASSWORD = "Wrong password, or the file is damaged."

_MAX_INT = 2**53 - 1
_APP_VERSION_RE = re.compile(r"[ -~]{1,32}")
_SALT_LEN = 16
_NONCE_LEN = 12
_KEY_LEN = 32
_ENVELOPE_KEYS = {"ciphertext", "header"}
_HEADER_KEYS = {"created_at", "format", "kdf", "nonce", "platform", "salt", "version"}
_KDF_KEYS = {"name", "time_cost", "memory_cost_kib", "parallelism"}
_PAYLOAD_KEYS = {"app_version", "device_id", "pro_hint", "states", "version"}
_STATE_KEYS = {"deleted", "deleted_at", "id", "item", "vv"}

_MESSAGES = {
    "not-a-backup": "This is not a LocalGateKeys phone backup.",
    "unsupported-version": "This backup was made by a newer version of LocalGateKeys. Update the app and try again.",
    "bad-kdf": "This backup uses unsupported password-protection settings.",
    "wrong-password-or-damaged": WRONG_PASSWORD,
    "bad-payload": "The backup was opened but its contents are not valid.",
    "too-large": "This file is too large to be a phone backup.",
}


class PhoneBackupError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(_MESSAGES[reason])
        self.reason = reason


@dataclass(frozen=True)
class BackupHeader:
    created_at: int
    platform: str
    kdf: dict
    salt: bytes
    nonce: bytes


@dataclass(frozen=True)
class PhoneBackup:
    header: BackupHeader
    device_id: str
    app_version: str
    pro_hint: bool
    states: tuple[ItemState, ...]


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = item
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


_MAX_JSON_INT = 2**63 - 1


def _parse_int(text: str) -> int:
    value = int(text)
    if abs(value) > _MAX_JSON_INT:
        raise ValueError("integer beyond 64 bits")
    return value


def _parse_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):  # e.g. 1e400, which float() turns into inf; the phones refuse it
        raise ValueError("non-finite number")
    return value


def _strict_json(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys,
                      parse_constant=_reject_constant, parse_int=_parse_int, parse_float=_parse_float)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_app_version(value: object) -> bool:
    return isinstance(value, str) and _APP_VERSION_RE.fullmatch(value) is not None


def _kdf_in_bounds(kdf: object) -> bool:
    if not isinstance(kdf, Mapping) or set(kdf) != _KDF_KEYS or kdf["name"] != "argon2id":
        return False
    t, m, p = kdf["time_cost"], kdf["memory_cost_kib"], kdf["parallelism"]
    return (_is_int(t) and _is_int(m) and _is_int(p)
            and 1 <= t <= 10 and MIN_KDF_MEMORY_KIB <= m <= MAX_KDF_MEMORY_KIB and 1 <= p <= 16)


def _derive(password: str, salt: bytes, kdf: Mapping) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=kdf["time_cost"],
        memory_cost=kdf["memory_cost_kib"],
        parallelism=kdf["parallelism"],
        hash_len=_KEY_LEN,
        type=Type.ID,
        version=19,
    )


def _b64d(value: object, length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise PhoneBackupError("not-a-backup")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PhoneBackupError("not-a-backup") from exc
    if (length is not None and len(raw) != length) or base64.b64encode(raw).decode("ascii") != value:
        raise PhoneBackupError("not-a-backup")
    return raw


def _parse_envelope(data: bytes) -> tuple[dict, BackupHeader, bytes]:
    """Cheap checks only; returns (raw header, parsed header, ciphertext). Never runs Argon2."""
    if len(data) > MAX_FILE_BYTES:
        raise PhoneBackupError("too-large")
    try:
        env = _strict_json(data)
    except (ValueError, RecursionError) as exc:  # UnicodeDecodeError is a ValueError
        raise PhoneBackupError("not-a-backup") from exc
    if not isinstance(env, dict) or set(env) != _ENVELOPE_KEYS:
        raise PhoneBackupError("not-a-backup")
    header = env["header"]
    if not isinstance(header, dict) or set(header) != _HEADER_KEYS or header["format"] != FORMAT:
        raise PhoneBackupError("not-a-backup")
    salt = _b64d(header["salt"], _SALT_LEN)
    nonce = _b64d(header["nonce"], _NONCE_LEN)
    ct = _b64d(env["ciphertext"])
    created = header["created_at"]
    if not isinstance(header["platform"], str) or header["platform"] not in PLATFORMS or not _is_int(created) or not 0 <= created <= _MAX_INT:
        raise PhoneBackupError("not-a-backup")
    version = header["version"]
    if not _is_int(version):
        raise PhoneBackupError("not-a-backup")
    if version > VERSION:
        raise PhoneBackupError("unsupported-version")
    if version != VERSION:
        raise PhoneBackupError("not-a-backup")
    if not _kdf_in_bounds(header["kdf"]):
        raise PhoneBackupError("bad-kdf")
    parsed = BackupHeader(created, header["platform"], dict(header["kdf"]), salt, nonce)
    return header, parsed, ct


def inspect_phone_backup(data: bytes) -> BackupHeader:
    """Header of a backup without a password and without any KDF work."""
    return _parse_envelope(data)[1]


def _parse_payload(plain: bytes) -> tuple[str, str, bool, tuple[ItemState, ...]]:
    try:
        payload = _strict_json(plain)
    except (ValueError, RecursionError) as exc:
        raise PhoneBackupError("bad-payload") from exc
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
        raise PhoneBackupError("bad-payload")
    app_version, device_id = payload["app_version"], payload["device_id"]
    if (not _is_int(payload["version"]) or payload["version"] != VERSION
            or not _valid_app_version(app_version)
            or not is_valid_id(device_id) or not isinstance(payload["pro_hint"], bool)
            or not isinstance(payload["states"], list) or len(payload["states"]) > MAX_SYNC_RECORDS):
        raise PhoneBackupError("bad-payload")
    states: list[ItemState] = []
    previous: str | None = None
    for raw in payload["states"]:
        if not isinstance(raw, dict) or set(raw) != _STATE_KEYS:
            raise PhoneBackupError("bad-payload")
        if isinstance(raw["vv"], dict) and any(
                not isinstance(n, bool) and isinstance(n, (int, float)) and n == 0 for n in raw["vv"].values()):
            raise PhoneBackupError("bad-payload")
        try:
            state = ItemState(raw["id"], raw["vv"], raw["deleted"], raw["deleted_at"], raw["item"])
        except (EngineError, TypeError, AttributeError) as exc:
            raise PhoneBackupError("bad-payload") from exc
        if previous is not None and state.item_id <= previous:
            raise PhoneBackupError("bad-payload")  # unsorted or duplicate
        previous = state.item_id
        states.append(state)
    return device_id, app_version, payload["pro_hint"], tuple(states)


def read_phone_backup(data: bytes, password: str) -> PhoneBackup:
    raw_header, header, ct = _parse_envelope(data)
    key = _derive(password, header.salt, header.kdf)
    try:
        plain = AESGCM(key).decrypt(header.nonce, ct, canonical_json(raw_header))
    except (InvalidTag, ValueError) as exc:
        raise PhoneBackupError("wrong-password-or-damaged") from exc
    device_id, app_version, pro_hint, states = _parse_payload(plain)
    return PhoneBackup(header, device_id, app_version, pro_hint, states)


def write_phone_backup(
    states: Iterable[ItemState],
    *,
    password: str,
    device_id: str,
    platform: str,
    app_version: str,
    created_at: int,
    pro_hint: bool,
    kdf: Mapping[str, Any] | None = None,
    _salt: bytes | None = None,
    _nonce: bytes | None = None,
) -> bytes:
    kdf_used = dict(KDF if kdf is None else kdf)
    if not _kdf_in_bounds(kdf_used):
        raise PhoneBackupError("bad-kdf")
    ordered = sorted(states, key=lambda s: s.item_id)
    ids = [s.item_id for s in ordered]
    if (len(ids) != len(set(ids)) or len(ids) > MAX_SYNC_RECORDS
            or not is_valid_id(device_id) or not isinstance(pro_hint, bool)
            or not _valid_app_version(app_version)
            or platform not in PLATFORMS
            or not _is_int(created_at) or not 0 <= created_at <= _MAX_INT):
        raise PhoneBackupError("bad-payload")
    salt = os.urandom(_SALT_LEN) if _salt is None else _salt
    nonce = os.urandom(_NONCE_LEN) if _nonce is None else _nonce
    if len(salt) != _SALT_LEN or len(nonce) != _NONCE_LEN:
        raise ValueError("salt must be 16 bytes and nonce 12 bytes")
    header = {
        "created_at": created_at,
        "format": FORMAT,
        "kdf": kdf_used,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "platform": platform,
        "salt": base64.b64encode(salt).decode("ascii"),
        "version": VERSION,
    }
    payload = {
        "app_version": app_version,
        "device_id": device_id,
        "pro_hint": pro_hint,
        "states": [{"deleted": s.deleted, "deleted_at": s.deleted_at, "id": s.item_id,
                    "item": s.item, "vv": dict(s.vv)} for s in ordered],
        "version": VERSION,
    }
    key = _derive(password, salt, kdf_used)
    ct = AESGCM(key).encrypt(nonce, canonical_json(payload), canonical_json(header))
    return canonical_json({"ciphertext": base64.b64encode(ct).decode("ascii"), "header": header})
