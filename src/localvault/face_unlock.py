"""Encrypted, device-local RGB-webcam unlock envelope.

This is a compatibility/convenience route for ordinary webcams.  It is not a
hardware-backed biometric authenticator: liveness and identity decisions are
made by LocalGateKeys.  The master password remains the recovery method.

No enrollment photograph or video is written to disk.  SFace embeddings and a
random key-wrapping secret are encrypted with Windows DPAPI for the current
Windows account, and authorization is also bound inside the authenticated vault
payload.  A process running as the same Windows user can still attack an
application-level biometric path; use Windows Hello or a future FIDO2 security
key for stronger protection.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import secrets
import struct
import sys
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import atomic_write_json, data_dir
from .face_models import (
    DEFAULT_MATCH_THRESHOLD,
    EMBEDDING_SIZE,
    MODEL_ID,
    normalize_embedding,
)
from .vault import (
    VaultError,
    VaultSession,
    _read_vault_header,
    _unlock_vault_with_face_key,
    unlock_context_for_header,
)
from .windows_hello import wipe

SCHEME = "rgb-webcam-sface-dpapi-aes256gcm-v1"
MAX_RECORD_BYTES = 96 * 1024
FIELDS = {
    "version", "scheme", "profile", "context", "id", "model",
    "template", "protected_secret", "nonce", "ciphertext",
}
# Present after a v2-to-v3 vault upgrade: the original ``context`` stays in the
# AEAD/DPAPI entropy and ``unlock_context`` names the v3 vault state.
OPTIONAL_FIELDS = {"unlock_context"}
STALE_MESSAGE = ("The vault password or header changed (or the vault format was upgraded without this setup). "
                 "Use your master password and set up camera verification again.")
_TEMPLATE_FIELDS = {"version", "model", "threshold", "count", "dimension", "data"}
_FAILURE_LOCK = threading.Lock()
_FAILURES: dict[str, tuple[int, float]] = {}
_FAILURE_FILE_NAME = "face-failures.json"


class FaceError(Exception):
    """Safe local diagnostic that never contains an embedding or secret."""


class FaceCancelled(FaceError):
    pass


class FaceUnavailable(FaceError):
    pass


def envelope_path(vault_path: Path) -> Path:
    return vault_path.with_name(vault_path.stem + ".face.json")


def _encode(value: bytes | bytearray) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_variable(value: Any, *, minimum: int, maximum: int, label: str) -> bytes:
    try:
        if not isinstance(value, str) or len(value) > maximum * 2:
            raise ValueError
        decoded = base64.b64decode(value, validate=True)
        if not minimum <= len(decoded) <= maximum:
            raise ValueError
        return decoded
    except (ValueError, TypeError) as exc:
        raise FaceError(f"The encrypted camera-verification {label} is damaged. Use your master password.") from exc


def _decode_exact(value: Any, size: int, label: str) -> bytes:
    raw = _decode_variable(value, minimum=size, maximum=size, label=label)
    if len(raw) != size:
        raise FaceError(f"The encrypted camera-verification {label} is damaged. Use your master password.")
    return raw


def _context(record: dict[str, Any]) -> bytes:
    public = {name: record[name] for name in ("version", "scheme", "profile", "context", "id", "model")}
    return b"LocalGateKeys|rgb-face-unlock|v1|" + json.dumps(
        public, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _entropy(record: dict[str, Any]) -> bytes:
    return hashlib.sha256(_context(record)).digest()


def _validate_profile(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or "\0" in value:
        raise FaceError("Camera verification belongs to an invalid profile. Use your master password.")
    return value


def _validate_id(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise FaceError("The camera-verification setup is invalid. Use your master password.")
    return value


class DPAPIProtector:
    """Current-user Windows DPAPI wrapper with no UI or roaming service."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise FaceUnavailable("RGB camera verification is currently available only in the Windows app.")
        try:
            import win32crypt  # type: ignore
        except Exception as exc:
            raise FaceUnavailable("Windows data protection is unavailable. Use your master password.") from exc
        self.api = win32crypt
        self.flags = int(getattr(win32crypt, "CRYPTPROTECT_UI_FORBIDDEN", 0x1))

    def protect(self, value: bytes | bytearray, entropy: bytes, description: str) -> bytes:
        try:
            return bytes(self.api.CryptProtectData(bytes(value), description, entropy, None, None, self.flags))
        except Exception as exc:
            raise FaceError("Windows could not encrypt the local camera-verification data.") from exc

    def unprotect(self, value: bytes, entropy: bytes) -> bytearray:
        try:
            _description, plain = self.api.CryptUnprotectData(value, entropy, None, None, self.flags)
            return bytearray(plain)
        except Exception as exc:
            raise FaceError(
                "Windows could not decrypt this profile's camera-verification data. "
                "Use your master password and set it up again."
            ) from exc


def _encode_templates(embeddings: Sequence[Sequence[float]], threshold: float) -> bytearray:
    if not 3 <= len(embeddings) <= 12:
        raise FaceError("Enrollment needs between 3 and 12 clear face samples.")
    if not 0.40 <= float(threshold) <= 0.75:
        raise FaceError("The face-matching threshold is invalid.")
    normalized = [normalize_embedding(values) for values in embeddings]
    packed = bytearray()
    for values in normalized:
        packed.extend(struct.pack(f"<{EMBEDDING_SIZE}f", *values))
    payload = {
        "version": 1,
        "model": MODEL_ID,
        "threshold": float(threshold),
        "count": len(normalized),
        "dimension": EMBEDDING_SIZE,
        "data": _encode(packed),
    }
    wipe(packed)
    return bytearray(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _decode_templates(value: bytes | bytearray) -> tuple[list[list[float]], float]:
    try:
        payload = json.loads(bytes(value).decode("utf-8"))
        if not isinstance(payload, dict) or set(payload) != _TEMPLATE_FIELDS:
            raise ValueError
        if payload["version"] != 1 or payload["model"] != MODEL_ID:
            raise ValueError
        count, dimension = payload["count"], payload["dimension"]
        threshold = float(payload["threshold"])
        if type(count) is not int or not 3 <= count <= 12 or dimension != EMBEDDING_SIZE:
            raise ValueError
        if not 0.40 <= threshold <= 0.75 or not math.isfinite(threshold):
            raise ValueError
        raw = bytearray(base64.b64decode(payload["data"], validate=True))
        expected = count * EMBEDDING_SIZE * 4
        if len(raw) != expected:
            raise ValueError
        templates: list[list[float]] = []
        for index in range(count):
            start = index * EMBEDDING_SIZE * 4
            values = struct.unpack_from(f"<{EMBEDDING_SIZE}f", raw, start)
            templates.append(list(normalize_embedding(values)))
        wipe(raw)
        return templates, threshold
    except (ValueError, TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError, struct.error) as exc:
        raise FaceError(
            "The encrypted face template is damaged or uses a different recognition model. "
            "Use your master password and enroll again."
        ) from exc


def _load_record(path: Path, profile_id: str | None) -> dict[str, Any]:
    try:
        with envelope_path(path).open("rb") as handle:
            raw = handle.read(MAX_RECORD_BYTES + 1)
        if len(raw) > MAX_RECORD_BYTES:
            raise ValueError
        record = json.loads(raw)
        if not isinstance(record, dict) or not FIELDS <= set(record) or set(record) - FIELDS - OPTIONAL_FIELDS:
            raise ValueError
        if "unlock_context" in record and (not isinstance(record["unlock_context"], str)
                                        or not re.fullmatch(r"[0-9a-f]{64}", record["unlock_context"])):
            raise ValueError
        if type(record["version"]) is not int or record["version"] != 1 or record["scheme"] != SCHEME:
            raise ValueError
        if _validate_profile(record["profile"]) != profile_id and profile_id is not None:
            raise ValueError
        if record["model"] != MODEL_ID:
            raise ValueError
        if not isinstance(record["context"], str) or not re.fullmatch(r"[0-9a-f]{64}", record["context"]):
            raise ValueError
        _validate_id(record["id"])
        _decode_variable(record["template"], minimum=64, maximum=64 * 1024, label="template")
        _decode_variable(record["protected_secret"], minimum=32, maximum=8192, label="key")
        _decode_exact(record["nonce"], 12, "nonce")
        _decode_exact(record["ciphertext"], 48, "vault key")
        return record
    except (OSError, ValueError, TypeError, KeyError, FaceError) as exc:
        if isinstance(exc, FaceError):
            raise
        raise FaceError(
            "Camera verification is not set up for this profile, or its local encrypted setup is damaged. "
            "Use your master password and open Settings › Unlocking."
        ) from exc


def _effective_context(record: dict[str, Any]) -> str:
    return str(record.get("unlock_context") or record["context"])


def _check_vault_context(path: Path, record: dict[str, Any]) -> None:
    header, _source = _read_vault_header(path)
    current = unlock_context_for_header(header)
    if not secrets.compare_digest(current, _effective_context(record)):
        raise FaceError(STALE_MESSAGE)


def upgrade_envelope_context(path: Path, old_context: str, new_context: str) -> bool:
    """Carry the camera sidecar across a vault format upgrade that kept the data key."""
    try:
        record = _load_record(path, None)
        if not secrets.compare_digest(_effective_context(record), old_context):
            return False
        record["unlock_context"] = new_context
        atomic_write_json(envelope_path(path), record)
        return True
    except (OSError, ValueError, TypeError, KeyError, FaceError, VaultError):
        return False


def has_envelope(path: Path, profile_id: str) -> bool:
    try:
        record = _load_record(path, profile_id)
        _check_vault_context(path, record)
        return True
    except (FaceError, VaultError):
        return False


@dataclass(repr=False)
class PreparedFaceEnrollment:
    record: dict[str, Any]
    secret: bytearray = field(repr=False)
    committed: bool = False

    def discard(self) -> None:
        wipe(self.secret)


@dataclass(repr=False)
class FaceMaterial:
    path: Path
    profile_id: str
    record: dict[str, Any]
    templates: list[list[float]] = field(repr=False)
    threshold: float

    @property
    def record_id(self) -> str:
        return str(self.record["id"])

    def discard(self) -> None:
        for template in self.templates:
            for index in range(len(template)):
                template[index] = 0.0
        self.templates.clear()


def prepare_enrollment(profile_id: str, context: str, embeddings: Sequence[Sequence[float]], *,
                       threshold: float = DEFAULT_MATCH_THRESHOLD,
                       protector_factory: Callable[[], Any] = DPAPIProtector) -> PreparedFaceEnrollment:
    _validate_profile(profile_id)
    if not isinstance(context, str) or not re.fullmatch(r"[0-9a-f]{64}", context):
        raise FaceError("The vault changed before camera enrollment could start.")
    record = {
        "version": 1,
        "scheme": SCHEME,
        "profile": profile_id,
        "context": context,
        "id": uuid.uuid4().hex,
        "model": MODEL_ID,
    }
    template_plain = _encode_templates(embeddings, threshold)
    secret = bytearray(os.urandom(32))
    try:
        protector = protector_factory()
        entropy = _entropy(record)
        record["template"] = _encode(protector.protect(template_plain, entropy, "LocalGateKeys face template"))
        record["protected_secret"] = _encode(protector.protect(secret, entropy, "LocalGateKeys local unlock key"))
        return PreparedFaceEnrollment(record, secret)
    except BaseException:
        wipe(secret)
        raise
    finally:
        wipe(template_plain)


def commit_enrollment(session: VaultSession, prepared: PreparedFaceEnrollment) -> None:
    if session.face_binding():
        raise FaceError("Remove the previous camera-verification setup before enrolling again.")
    if not secrets.compare_digest(session.unlock_context(), prepared.record["context"]):
        raise FaceError("The vault changed during enrollment. No camera setup was enabled.")
    record = dict(prepared.record)
    nonce, wrapped_key = session.wrap_unlock_key(prepared.secret, _context(record))
    record["nonce"], record["ciphertext"] = _encode(nonce), _encode(wrapped_key)
    session.set_face_binding(record["id"])
    try:
        atomic_write_json(envelope_path(session.path), record)
    except BaseException:
        try:
            session.set_face_binding(None)
        finally:
            prepared.discard()
        raise
    prepared.committed = True
    prepared.discard()


def load_face_material(path: Path, profile_id: str, *,
                       protector_factory: Callable[[], Any] = DPAPIProtector) -> FaceMaterial:
    record = _load_record(path, profile_id)
    _check_vault_context(path, record)
    check_attempt(record["id"])
    plain: bytearray | None = None
    try:
        protector = protector_factory()
        plain = protector.unprotect(
            _decode_variable(record["template"], minimum=64, maximum=64 * 1024, label="template"),
            _entropy(record),
        )
        templates, threshold = _decode_templates(plain)
        return FaceMaterial(path, profile_id, record, templates, threshold)
    finally:
        if plain is not None:
            wipe(plain)


def unlock_verified_face(material: FaceMaterial, cancelled: threading.Event | None = None, *,
                         backup_dir: Path | None = None, backup_count: int = 0,
                         protector_factory: Callable[[], Any] = DPAPIProtector) -> VaultSession:
    if cancelled is not None and cancelled.is_set():
        raise FaceCancelled("Camera verification was cancelled. Your vault is still locked.")
    record = material.record
    _check_vault_context(material.path, record)
    secret = key = None
    session = None
    try:
        secret = protector_factory().unprotect(
            _decode_variable(record["protected_secret"], minimum=32, maximum=8192, label="key"),
            _entropy(record),
        )
        if len(secret) != 32:
            raise FaceError("Windows returned invalid protected key material.")
        if cancelled is not None and cancelled.is_set():
            raise FaceCancelled("Camera verification was cancelled. Your vault is still locked.")
        try:
            key = bytearray(AESGCM(secret).decrypt(
                _decode_exact(record["nonce"], 12, "nonce"),
                _decode_exact(record["ciphertext"], 48, "vault key"),
                _context(record),
            ))
        except InvalidTag as exc:
            raise FaceError("The encrypted camera-verification setup could not be authenticated.") from exc
        session = _unlock_vault_with_face_key(
            material.path,
            key,
            expected_context=_effective_context(record),
            expected_binding=record["id"],
            backup_dir=backup_dir,
            backup_count=backup_count,
        )
        key = None
        clear_failures(record["id"])
        return session
    except BaseException:
        if session is not None:
            session.lock()
        raise
    finally:
        if secret is not None:
            wipe(secret)
        if key is not None:
            wipe(key)


def enrollment_present(session: VaultSession) -> bool:
    """Whether camera unlock is (or was left half) set up: a binding or a sidecar exists."""
    try:
        return bool(session.face_binding()) or envelope_path(session.path).exists()
    except OSError:
        return True


def rotation_on_disable(session: VaultSession) -> bool:
    """Whether disabling camera unlock re-encrypts the vault under a new key.

    Only when camera unlock is set up and the vault has no recovery phrase:
    rotating would invalidate the phrase.
    """
    return enrollment_present(session) and not session.has_recovery_phrase()


def disable_enrollment(session: VaultSession, current_password: Any = None) -> dict[str, Any] | None:
    """Revoke camera unlock.

    The sidecar holds the data key under DPAPI only, so any copy of it taken
    while camera unlock was on (backup, shadow copy, undeleted file) would
    keep opening the vault for anyone signed in to this Windows account.
    With ``current_password`` the data key is therefore rotated first
    (``rotate_data_key``), which leaves every old sidecar wrapping a retired
    key; the rotation result is returned.

    A rotation cannot re-wrap the recovery phrase (its words are not
    available), so it is skipped while the vault has one: losing the
    phrase silently is worse than the residual risk, which needs a copy of
    the old sidecar *and* this Windows account (or its password and user
    files).  Without a password, or with a phrase, only the binding and the
    sidecar are removed and ``None`` is returned.
    """
    result = None
    if rotation_on_disable(session) and current_password is not None:
        result = session.rotate_data_key(current_password)
    if session.face_binding():
        session.set_face_binding(None)
    try:
        envelope_path(session.path).unlink(missing_ok=True)
    except OSError as exc:
        raise FaceError(
            "Camera verification was revoked in the encrypted vault, but its encrypted sidecar could not be removed."
        ) from exc
    return result


def cleanup_after_password_change(path: Path) -> bool:
    try:
        envelope_path(path).unlink(missing_ok=True)
        return True
    except OSError:
        return False


def _failure_state_path() -> Path:
    return data_dir() / _FAILURE_FILE_NAME


def _load_persisted_failures() -> dict[str, tuple[int, float]]:
    try:
        with _failure_state_path().open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    result: dict[str, tuple[int, float]] = {}
    for record_id, value in list(raw.items())[:256]:
        if not isinstance(record_id, str) or not (1 <= len(record_id) <= 256):
            continue
        if not isinstance(value, dict):
            continue
        count, blocked_until = value.get("count"), value.get("blocked_until")
        if type(count) is not int or not 0 <= count <= 1000:
            continue
        if isinstance(blocked_until, bool):
            continue
        try:
            blocked_until = float(blocked_until)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(blocked_until) or blocked_until < 0:
            continue
        result[record_id] = (count, blocked_until)
    return result


def _persist_failures(state: dict[str, tuple[int, float]]) -> None:
    payload = {
        record_id: {"count": count, "blocked_until": blocked_until}
        for record_id, (count, blocked_until) in list(state.items())[:256]
        if 0 <= count <= 1000 and math.isfinite(blocked_until)
    }
    try:
        atomic_write_json(_failure_state_path(), payload)
    except (OSError, ValueError, TypeError):
        # Throttling remains enforced in memory if the local state file cannot
        # be written; the failure is not allowed to break face unlock.
        pass


def _merge_persisted_failures() -> None:
    for record_id, persisted in _load_persisted_failures().items():
        current = _FAILURES.get(record_id)
        if current is None or persisted[0] > current[0] or persisted[1] > current[1]:
            _FAILURES[record_id] = persisted


def check_attempt(record_id: str, *, now: float | None = None) -> None:
    persistent = now is None
    now = time.time() if persistent else float(now)
    with _FAILURE_LOCK:
        if persistent:
            _merge_persisted_failures()
        count, blocked_until = _FAILURES.get(record_id, (0, 0.0))
    if blocked_until > now:
        wait = max(1, int(math.ceil(blocked_until - now)))
        raise FaceError(f"Too many unsuccessful camera checks. Try again in {wait} seconds or use your master password.")


def record_failure(record_id: str, *, now: float | None = None) -> None:
    persistent = now is None
    now = time.time() if persistent else float(now)
    with _FAILURE_LOCK:
        if persistent:
            _merge_persisted_failures()
        count, blocked_until = _FAILURES.get(record_id, (0, 0.0))
        if blocked_until <= now:
            count += 1
        delay = 0.0 if count < 3 else min(120.0, 15.0 * (2 ** min(count - 3, 3)))
        _FAILURES[record_id] = (count, now + delay)
        if persistent:
            _persist_failures(_FAILURES)


def clear_failures(record_id: str) -> None:
    with _FAILURE_LOCK:
        _FAILURES.pop(record_id, None)
        try:
            if _failure_state_path().exists():
                _persist_failures(_FAILURES)
        except OSError:
            pass
