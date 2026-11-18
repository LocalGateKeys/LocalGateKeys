"""Per-profile security key (FIDO2 hmac-secret) unlock envelope and its enrollment lifecycle.

An alternative to typing the master password, like Windows Hello; not a second
factor.  The master password and the recovery phrase keep opening the vault, so
a lost key only costs this shortcut (remove it in Settings > Unlocking).

The sidecar ``<vault>.fido.json`` holds the vault data key encrypted with
AES-256-GCM under ``HKDF-SHA256(hmac-secret output, salt, info)``.  The
hmac-secret output is computed on the security key from the record's random
salt, after its PIN (or on-key biometrics) and a touch; it never leaves the key
otherwise.  ``info`` and the AES-GCM associated data are the canonical public
record, which includes the vault unlock context, so a sidecar copied from
another vault, or left over from an older master password, cannot be decrypted
into this vault's key; the record id must also match ``fido_binding`` inside
the encrypted payload, so a planted or resurrected sidecar is refused.
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import atomic_write_json
from .i18n import t
from .security_key import (
    MAX_CREDENTIAL_ID_BYTES,
    MIN_API_VERSION,
    RP_ID,
    SECRET_BYTES,
    SecurityKeyCancelled,
    SecurityKeyError,
    SecurityKeyUnavailable,
    WebAuthn,
    native_operation,
    wipe,
)
from .vault import (
    VaultSession,
    _read_vault_header,
    _unlock_vault_with_security_key,
    unlock_context_for_header,
)

SCHEME = "fido2-hmac-secret-hkdf-sha256-aes256gcm-v1"
MAX_RECORD_BYTES = 8192
FIELDS = {"version", "scheme", "profile", "context", "id", "rp_id", "credential_id", "salt", "nonce", "ciphertext"}
# Written when a vault upgrade (KDF parameters, envelope format) changed the unlock
# context but kept the data key: the authenticated ``context`` stays as it was.
OPTIONAL_FIELDS = {"unlock_context"}
STALE_MESSAGE_KEY = "securityKey.error.stale"


def envelope_path(vault_path: Path) -> Path:
    return vault_path.with_name(vault_path.stem + ".fido.json")


def _cancel_check(event: threading.Event) -> None:
    if event.is_set():
        raise SecurityKeyCancelled(t("securityKey.error.cancelledNoUnlock"))


def _encode(value: bytes | bytearray) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: Any, size: int | None = None, *, maximum: int = 2048) -> bytes:
    try:
        if not isinstance(value, str) or len(value) > 2048:
            raise ValueError
        decoded = base64.b64decode(value, validate=True)
        if (size is not None and len(decoded) != size) or not 1 <= len(decoded) <= maximum:
            raise ValueError
        return decoded
    except (ValueError, TypeError) as exc:
        raise SecurityKeyError(t("securityKey.error.localDamaged")) from exc


def _context(record: dict[str, Any]) -> bytes:
    public = {name: record[name] for name in ("version", "scheme", "profile", "context", "id", "rp_id",
                                              "credential_id", "salt")}
    return b"LocalGateKeys|fido-unlock|v1|" + json.dumps(
        public, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _wrapping_key(secret: bytearray, record: dict[str, Any]) -> bytearray:
    """HKDF-SHA256 over the key's hmac-secret output, bound to this record and vault context."""
    if len(secret) != SECRET_BYTES:
        raise SecurityKeyError(t("securityKey.error.invalidKeyMaterial"))
    # The buffer is passed as is: no immutable copy of the secret is made here.
    return bytearray(HKDF(algorithm=hashes.SHA256(), length=32, salt=_decode(record["salt"], SECRET_BYTES),
                          info=_context(record)).derive(secret))


def _effective_context(record: dict[str, Any]) -> str:
    """The vault unlock context this record is valid for (moved by a vault upgrade)."""
    return str(record.get("unlock_context") or record["context"])


def _validate_record_id(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise SecurityKeyError(t("securityKey.error.invalidSetup"))
    return value


def _read_record(path: Path) -> dict[str, Any]:
    with envelope_path(path).open("rb") as handle:
        raw = handle.read(MAX_RECORD_BYTES + 1)
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError
    record = json.loads(raw)
    if not isinstance(record, dict) or not FIELDS <= set(record) or set(record) - FIELDS - OPTIONAL_FIELDS:
        raise ValueError
    if type(record["version"]) is not int or record["version"] != 1 or record["scheme"] != SCHEME:
        raise ValueError
    if not isinstance(record["profile"], str) or record["rp_id"] != RP_ID:
        raise ValueError
    for name in ("context", "unlock_context"):
        if name in record and (not isinstance(record[name], str) or not re.fullmatch(r"[0-9a-f]{64}", record[name])):
            raise ValueError
    _validate_record_id(record["id"])
    _decode(record["credential_id"], maximum=MAX_CREDENTIAL_ID_BYTES)
    for name, size in (("salt", SECRET_BYTES), ("nonce", 12), ("ciphertext", 48)):
        _decode(record[name], size)
    return record


def upgrade_envelope_context(path: Path, old_context: str, new_context: str) -> bool:
    """Carry a sidecar across a vault upgrade that kept the data key.

    Returns False when the sidecar is missing, damaged, or bound to a different
    vault state; the caller then revokes the grant or retries later.
    """
    try:
        record = _read_record(path)
        if not secrets.compare_digest(_effective_context(record), old_context):
            return False
        record["unlock_context"] = new_context
        atomic_write_json(envelope_path(path), record)
        return True
    except (OSError, ValueError, TypeError, KeyError, SecurityKeyError):
        return False


def _load(path: Path, profile_id: str) -> dict[str, Any]:
    try:
        record = _read_record(path)
        if record["profile"] != profile_id:
            raise ValueError
        return record
    except (OSError, ValueError, TypeError, KeyError, SecurityKeyError) as exc:
        raise SecurityKeyError(t("securityKey.error.notSetUp")) from exc


def has_envelope(path: Path, profile_id: str) -> bool:
    try:
        _load(path, profile_id)
        return True
    except SecurityKeyError:
        return False


@dataclass(repr=False)
class PreparedEnrollment:
    record: dict[str, Any]
    wrapping_key: bytearray = field(repr=False)
    committed: bool = False

    def discard(self) -> None:
        # The credential lives only on the key (non-resident): nothing else to delete.
        wipe(self.wrapping_key)


def prepare_enrollment(profile_id: str, context: str, hwnd: int, cancelled: threading.Event,
                       *, provider_factory: Callable[[], Any] = WebAuthn) -> PreparedEnrollment:
    """Register the key and read one hmac-secret, without touching a live VaultSession on a worker.

    The read proves, before opt-in, that this key really returns hmac-secret
    output for the new credential with user verification.
    """
    _cancel_check(cancelled)
    with native_operation():
        provider = provider_factory()
        version = int(provider.api_version())
        if version < MIN_API_VERSION:
            raise SecurityKeyUnavailable(t("securityKey.error.apiTooOld", version=version))
        credential_id = bytes(provider.make_credential(hwnd, RP_ID, os.urandom(16)))
        if not 1 <= len(credential_id) <= MAX_CREDENTIAL_ID_BYTES:
            raise SecurityKeyError(t("securityKey.error.invalidResponse"))
        _cancel_check(cancelled)
        salt = os.urandom(SECRET_BYTES)
        secret = provider.hmac_secret(hwnd, RP_ID, credential_id, salt)
        try:
            _cancel_check(cancelled)
            record = {"version": 1, "scheme": SCHEME, "profile": profile_id, "context": context,
                      "id": uuid.uuid4().hex, "rp_id": RP_ID, "credential_id": _encode(credential_id),
                      "salt": _encode(salt)}
            return PreparedEnrollment(record, _wrapping_key(secret, record))
        finally:
            wipe(secret)


def commit_enrollment(session: VaultSession, prepared: PreparedEnrollment) -> None:
    """UI-thread commit after master-password reauthentication and lease checks."""
    if session.fido_binding():
        raise SecurityKeyError(t("securityKey.error.removeFirst"))
    if not secrets.compare_digest(session.unlock_context(), prepared.record["context"]):
        raise SecurityKeyError(t("securityKey.error.changedDuringEnroll"))
    record = dict(prepared.record)
    nonce, wrapped_key = session.wrap_unlock_key(prepared.wrapping_key, _context(record))
    record["nonce"], record["ciphertext"] = _encode(nonce), _encode(wrapped_key)
    # Save encrypted authorization first. A crash here leaves password unlock
    # working and no usable key envelope; there is no partially enabled shortcut.
    session.set_fido_binding(record["id"])
    try:
        atomic_write_json(envelope_path(session.path), record)
    except BaseException:
        try:
            session.set_fido_binding(None)
        finally:
            prepared.discard()
        raise
    prepared.committed = True
    wipe(prepared.wrapping_key)


def unlock_with_security_key(path: Path, profile_id: str, hwnd: int, cancelled: threading.Event,
                             *, backup_dir: Path | None = None, backup_count: int = 0,
                             provider_factory: Callable[[], Any] = WebAuthn) -> VaultSession:
    _cancel_check(cancelled)
    record = _load(path, profile_id)
    # Reject a changed master password/header before showing the Windows Security dialog.
    header, _source = _read_vault_header(path)
    expected_context = _effective_context(record)
    if not secrets.compare_digest(unlock_context_for_header(header), expected_context):
        raise SecurityKeyError(t(STALE_MESSAGE_KEY))
    secret = wrapping_key = key = None
    session = None
    try:
        with native_operation():
            _cancel_check(cancelled)
            provider = provider_factory()
            version = int(provider.api_version())
            if version < MIN_API_VERSION:
                raise SecurityKeyUnavailable(t("securityKey.error.apiTooOld", version=version))
            secret = provider.hmac_secret(hwnd, RP_ID, _decode(record["credential_id"], maximum=MAX_CREDENTIAL_ID_BYTES),
                                          _decode(record["salt"], SECRET_BYTES))
        _cancel_check(cancelled)
        wrapping_key = _wrapping_key(secret, record)
        try:
            key = bytearray(AESGCM(bytes(wrapping_key)).decrypt(_decode(record["nonce"], 12),
                                                             _decode(record["ciphertext"], 48), _context(record)))
        except InvalidTag as exc:
            # Another key, or a key that answered without the same PIN verification.
            raise SecurityKeyError(t("securityKey.error.authFailed")) from exc
        _cancel_check(cancelled)
        session = _unlock_vault_with_security_key(path, key, expected_context=expected_context,
                                                  expected_binding=record["id"], backup_dir=backup_dir,
                                                  backup_count=backup_count)
        key = None  # Session now owns these mutable key bytes.
        _cancel_check(cancelled)
        return session
    except BaseException:
        if session is not None:
            session.lock()
        raise
    finally:
        for value in (secret, wrapping_key, key):
            if value is not None:
                wipe(value)


def disable_enrollment(session: VaultSession) -> None:
    """Revoke inside the vault first, then remove the sidecar.

    The credential itself stays on the security key (it is not stored there as
    a passkey and holds nothing of the vault); without the sidecar and the
    binding it opens nothing.
    """
    session.set_fido_binding(None)
    envelope_path(session.path).unlink(missing_ok=True)


def cleanup_after_password_change(path: Path) -> bool:
    """A rotated data key already invalidates the envelope; remove the stale file."""
    try:
        envelope_path(path).unlink(missing_ok=True)
        return True
    except OSError:
        return False
