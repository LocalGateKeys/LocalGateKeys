"""Per-profile encrypted local unlock envelope and explicit enrollment lifecycle."""
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import atomic_write_json
from .vault import (
    VaultSession,
    _read_vault_header,
    _unlock_vault_with_key,
    unlock_context_for_header,
)
from .windows_hello import (
    HelloCancelled,
    HelloError,
    WindowsHello,
    native_operation,
    validate_record_id,
    wipe,
)

SCHEME = "windows-hello-rsa-oaep-sha256-aes256gcm-v1"
MAX_RECORD_BYTES = 8192
FIELDS = {"version", "scheme", "profile", "context", "id", "wrapped_secret", "nonce", "ciphertext"}
# Added when a v2 vault was upgraded to format v3: the sidecar keeps its
# original authenticated ``context`` (part of the AEAD) and additionally
# records the v3 unlock context it is valid for.
OPTIONAL_FIELDS = {"unlock_context"}
STALE_MESSAGE = ("The vault password or header changed (or the vault format was upgraded without this setup). "
                 "Use your master password and set up Hello again.")


def envelope_path(vault_path: Path) -> Path:
    return vault_path.with_name(vault_path.stem + ".hello.json")


def _cancel_check(event: threading.Event) -> None:
    if event.is_set():
        raise HelloCancelled("Windows Hello was cancelled. No unlock was accepted.")


def _encode(value: bytes | bytearray) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: Any, size: int) -> bytes:
    try:
        if not isinstance(value, str) or len(value) > 2048:
            raise ValueError
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) != size:
            raise ValueError
        return decoded
    except (ValueError, TypeError) as exc:
        raise HelloError("The local Windows Hello setup is damaged. Use your master password.") from exc


def _context(record: dict[str, Any]) -> bytes:
    public = {name: record[name] for name in ("version", "scheme", "profile", "context", "id")}
    return b"LocalGateKeys|local-unlock|v1|" + json.dumps(
        public, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _effective_context(record: dict[str, Any]) -> str:
    """The vault unlock context this record is valid for (v3 context after an upgrade)."""
    return str(record.get("unlock_context") or record["context"])


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
    for name in ("context", "unlock_context"):
        if name in record and (not isinstance(record[name], str) or not re.fullmatch(r"[0-9a-f]{64}", record[name])):
            raise ValueError
    validate_record_id(record["id"])
    for name, size in (("wrapped_secret", 256), ("nonce", 12), ("ciphertext", 48)):
        _decode(record[name], size)
    return record


def upgrade_envelope_context(path: Path, old_context: str, new_context: str) -> bool:
    """Carry a sidecar across a vault format upgrade that kept the data key.

    Returns False when the sidecar is missing, damaged, or bound to a different
    vault state; the caller then revokes the grant and asks for re-enrollment.
    """
    try:
        record = _read_record(path)
        if not secrets.compare_digest(_effective_context(record), old_context):
            return False
        record["unlock_context"] = new_context
        atomic_write_json(envelope_path(path), record)
        return True
    except (OSError, ValueError, TypeError, KeyError, HelloError):
        return False


def _load(path: Path, profile_id: str) -> dict[str, Any]:
    try:
        record = _read_record(path)
        if record["profile"] != profile_id:
            raise ValueError
        return record
    except (OSError, ValueError, TypeError, KeyError, HelloError) as exc:
        raise HelloError("Windows Hello is not set up for this profile, or its local setup is damaged. "
                         "Unlock with your master password and open Security settings.") from exc


def has_envelope(path: Path, profile_id: str) -> bool:
    try:
        _load(path, profile_id)
        return True
    except HelloError:
        return False


@dataclass(repr=False)
class PreparedEnrollment:
    record: dict[str, Any]
    secret: bytearray = field(repr=False)
    provider: Any = field(repr=False)
    committed: bool = False

    def discard(self) -> None:
        wipe(self.secret)
        if not self.committed:
            try:
                self.provider.delete(self.record["id"])
            except Exception:
                # Before commit no vault key has been persisted under this key.
                # Failure can leave an unused OS key, not an unlocked vault.
                pass


def prepare_enrollment(profile_id: str, context: str, hwnd: int, cancelled: threading.Event,
                       *, provider_factory: Callable[[], Any] = WindowsHello) -> PreparedEnrollment:
    """Perform native enrollment without touching a live VaultSession on a worker."""
    _cancel_check(cancelled)
    with native_operation():
        provider = provider_factory()
        record_id = uuid.uuid4().hex
        secret = bytearray(os.urandom(32))
        created = False
        try:
            provider.create(record_id, hwnd)
            created = True
            _cancel_check(cancelled)
            wrapped = provider.wrap(record_id, secret)
            # Exercise a real, freshly verified private-key operation before opt-in.
            recovered = provider.unwrap(record_id, wrapped, hwnd)
            try:
                _cancel_check(cancelled)
                if not secrets.compare_digest(secret, recovered):
                    raise HelloError("Windows Hello key verification failed. Setup was not enabled.")
            finally:
                wipe(recovered)
            record = {"version": 1, "scheme": SCHEME, "profile": profile_id,
                      "context": context, "id": record_id, "wrapped_secret": _encode(wrapped)}
            return PreparedEnrollment(record, secret, provider)
        except BaseException:
            wipe(secret)
            if created:
                try:
                    provider.delete(record_id)
                except Exception:
                    pass
            raise


def commit_enrollment(session: VaultSession, prepared: PreparedEnrollment) -> None:
    """UI-thread commit after master-password reauthentication and lease checks."""
    if session.hello_binding():
        raise HelloError("Remove the previous Windows Hello setup before enrolling again.")
    if not secrets.compare_digest(session.unlock_context(), prepared.record["context"]):
        raise HelloError("The vault changed during enrollment. No setup was enabled.")
    record = dict(prepared.record)
    nonce, wrapped_key = session.wrap_unlock_key(prepared.secret, _context(record))
    record["nonce"], record["ciphertext"] = _encode(nonce), _encode(wrapped_key)
    # Save encrypted authorization first. A crash here leaves password unlock
    # working and no usable key envelope; there is no partially enabled shortcut.
    session.set_hello_binding(record["id"])
    try:
        atomic_write_json(envelope_path(session.path), record)
    except BaseException:
        try:
            session.set_hello_binding(None)
        finally:
            prepared.discard()
        raise
    prepared.committed = True
    wipe(prepared.secret)


def unlock_with_hello(path: Path, profile_id: str, hwnd: int, cancelled: threading.Event,
                      *, backup_dir: Path | None = None, backup_count: int = 0,
                      provider_factory: Callable[[], Any] = WindowsHello) -> VaultSession:
    _cancel_check(cancelled)
    record = _load(path, profile_id)
    # Reject a changed master password/header before showing a native prompt.
    header, _source = _read_vault_header(path)
    expected_context = _effective_context(record)
    if not secrets.compare_digest(unlock_context_for_header(header), expected_context):
        raise HelloError(STALE_MESSAGE)
    secret = key = None
    session = None
    try:
        with native_operation():
            _cancel_check(cancelled)
            secret = provider_factory().unwrap(record["id"], _decode(record["wrapped_secret"], 256), hwnd)
        _cancel_check(cancelled)
        if len(secret) != 32:
            raise HelloError("Windows Hello returned invalid key material.")
        try:
            key = bytearray(AESGCM(bytes(secret)).decrypt(_decode(record["nonce"], 12),
                                                       _decode(record["ciphertext"], 48), _context(record)))
        except InvalidTag as exc:
            raise HelloError("Windows Hello setup could not be authenticated. Use your master password.") from exc
        _cancel_check(cancelled)
        session = _unlock_vault_with_key(path, key, expected_context=expected_context,
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
        if secret is not None:
            wipe(secret)
        if key is not None:
            wipe(key)


def disable_enrollment(session: VaultSession, *, provider_factory: Callable[[], Any] = WindowsHello) -> None:
    record_id = session.hello_binding()
    if record_id:
        # Real revocation is key deletion, not just hiding a button/setting.
        provider_factory().delete(record_id)
    session.set_hello_binding(None)
    envelope_path(session.path).unlink(missing_ok=True)


def cleanup_after_password_change(path: Path, record_id: str) -> bool:
    """A changed salt/key already invalidates the old envelope for the live vault."""
    ok = True
    if record_id:
        try:
            WindowsHello().delete(record_id)
        except HelloError:
            ok = False
    try:
        envelope_path(path).unlink(missing_ok=True)
    except OSError:
        ok = False
    return ok
