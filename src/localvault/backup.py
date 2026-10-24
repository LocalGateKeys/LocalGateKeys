from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import shutil
import tempfile
import time
import uuid
import warnings
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import atomic_write_json, read_json
from .secret_text import SecretText, argon2id_raw, as_secret
from .vault import DEFAULT_KDF, MAX_KDF_MEMORY_KIB, MIN_KDF_MEMORY_KIB

# Vault-only .lgk envelope.  v2 authenticates the header (format, version, KDF
# parameters, cipher name and nonce) as associated data; v1 used a constant
# AAD and remains readable.
BACKUP_VERSION = 2
BACKUP_AAD = b"localgatekeys|encrypted-profile-backup|v1"
BACKUP_AAD_V2 = b"localgatekeys|encrypted-profile-backup|v2|"
SUPPORTED_BACKUP_VERSIONS = frozenset({1, 2})
# The encrypted inner payload layout did not change between envelope v1 and v2.
BACKUP_PAYLOAD_VERSION = 1

# Argon2id parameters for new backup/transfer writes mirror the vault default.
# Readers accept any header inside the vault's bounded range instead of a
# single hard-coded tuple so older and tuned files stay restorable.
BACKUP_KDF = {
    "name": "argon2id",
    "time_cost": int(DEFAULT_KDF["time_cost"]),
    "memory_cost_kib": int(DEFAULT_KDF["memory_cost_kib"]),
    "parallelism": int(DEFAULT_KDF["parallelism"]),
}
MIN_BACKUP_KDF_TIME_COST, MAX_BACKUP_KDF_TIME_COST = 1, 10
MIN_BACKUP_KDF_PARALLELISM, MAX_BACKUP_KDF_PARALLELISM = 1, 16
_KDF_FIELDS = ("time_cost", "memory_cost_kib", "parallelism")


class BackupError(Exception):
    pass


PRIVATE_TEMP_FOLDER = "tmp"


def private_temp_root() -> Path:
    """An owner-only ``tmp`` folder inside the data folder for scratch directories.

    ``tempfile.TemporaryDirectory`` in the shared system temp folder has a
    cleanup race on Windows (another process can swap the directory for a
    junction before rmtree runs).  Scratch directories are therefore created
    in a folder only the current user and SYSTEM can write to.  A link or
    junction in its place is refused rather than followed.
    """
    from .config import apply_owner_only_acl, data_dir, has_owner_only_acl
    root = data_dir() / PRIVATE_TEMP_FOLDER
    if root.is_symlink() or root.is_junction():
        raise OSError("The private temporary folder is a link")
    created = False
    if not root.is_dir():
        root.mkdir(mode=0o700)
        created = True
    if os.name == "nt":
        try:
            if created or not has_owner_only_acl(root):
                apply_owner_only_acl(root)
        except Exception:  # noqa: BLE001 - best-effort, like the data folder ACL
            import logging
            logging.getLogger(__name__).warning("Could not apply the owner-only ACL to the private temporary folder.")
    else:
        try:
            root.chmod(0o700)
        except OSError:
            pass
    return root


def private_temporary_directory(prefix: str) -> tempfile.TemporaryDirectory[str]:
    """``TemporaryDirectory`` created inside ``private_temp_root()`` (still removed on exit)."""
    return tempfile.TemporaryDirectory(prefix=prefix, dir=private_temp_root())


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise BackupError("Backup contains invalid encoded data") from exc


def _canonical(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _kdf_parameters(kdf: Any) -> dict[str, int | str]:
    """Bound Argon2id parameters before any derivation runs (fail closed)."""
    if not isinstance(kdf, dict) or kdf.get("name") != "argon2id":
        raise BackupError("Unsupported backup encryption parameters")
    values: dict[str, int | str] = {"name": "argon2id"}
    for field in _KDF_FIELDS:
        value = kdf.get(field)
        if type(value) is not int:
            raise BackupError("Unsupported backup encryption parameters")
        values[field] = value
    if not (MIN_BACKUP_KDF_TIME_COST <= int(values["time_cost"]) <= MAX_BACKUP_KDF_TIME_COST
            and MIN_KDF_MEMORY_KIB <= int(values["memory_cost_kib"]) <= MAX_KDF_MEMORY_KIB
            and MIN_BACKUP_KDF_PARALLELISM <= int(values["parallelism"]) <= MAX_BACKUP_KDF_PARALLELISM):
        raise BackupError("Unsupported backup encryption parameters")
    if "hash_len" in kdf and kdf.get("hash_len") != 32:
        raise BackupError("Unsupported backup encryption parameters")
    return values


def _new_kdf(kdf_overrides: dict[str, int] | None) -> dict[str, int | str]:
    kdf: dict[str, Any] = dict(BACKUP_KDF)
    if kdf_overrides:
        for field in _KDF_FIELDS:
            if field in kdf_overrides:
                kdf[field] = kdf_overrides[field]
    return _kdf_parameters(kdf)


def _derive(password: str | SecretText, salt: bytes, kdf: dict[str, Any]) -> bytes:
    """The backup key. A ``SecretText`` password is hashed straight from its wipeable buffer."""
    if isinstance(password, SecretText):
        try:
            length = password.char_count
        except ValueError:
            raise BackupError("Backup password must contain at least 12 characters") from None
    elif isinstance(password, str):
        length = len(password)
    else:
        length = 0
    if not 12 <= length <= 4096:
        raise BackupError("Backup password must contain at least 12 characters")
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise BackupError("Malformed encryption header")
    parameters = _kdf_parameters(kdf)
    if isinstance(password, SecretText):
        key = argon2id_raw(password.buffer, salt, time_cost=int(parameters["time_cost"]),
                           memory_cost=int(parameters["memory_cost_kib"]),
                           parallelism=int(parameters["parallelism"]), hash_len=32)
        try:
            return bytes(key)
        finally:
            key[:] = b"\0" * len(key)
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=int(parameters["time_cost"]),
        memory_cost=int(parameters["memory_cost_kib"]),
        parallelism=int(parameters["parallelism"]),
        hash_len=32,
        type=Type.ID,
    )


def _backup_header_aad(envelope: dict[str, Any]) -> bytes:
    return BACKUP_AAD_V2 + _canonical({
        "format": envelope["format"],
        "version": envelope["version"],
        "kdf": envelope["kdf"],
        "cipher": {"name": envelope["cipher"]["name"], "nonce": envelope["cipher"]["nonce"]},
    })


def export_encrypted_backup(
    destination: Path,
    *,
    vault_file: Path,
    settings_file: Path | None,
    profile_name: str,
    backup_password: str,
    kdf_overrides: dict[str, int] | None = None,
) -> None:
    if not vault_file.exists():
        raise BackupError("There is no vault to back up yet")
    kdf = _new_kdf(kdf_overrides)
    payload: dict[str, Any] = {
        "version": BACKUP_PAYLOAD_VERSION,
        "exported_at": int(time.time()),
        "profile_name": profile_name,
        "vault": read_json(vault_file),
        "settings": read_json(settings_file) if settings_file and settings_file.exists() else None,
    }
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    salt = os.urandom(16)
    key = _derive(backup_password, salt, kdf)
    nonce = os.urandom(12)
    envelope: dict[str, Any] = {
        "format": "localgatekeys-backup",
        "version": BACKUP_VERSION,
        "kdf": {**kdf, "salt": _b64e(salt)},
        "cipher": {"name": "aes-256-gcm", "nonce": _b64e(nonce)},
    }
    envelope["cipher"]["ciphertext"] = _b64e(AESGCM(key).encrypt(nonce, plaintext, _backup_header_aad(envelope)))
    atomic_write_json(destination, envelope)


def restore_encrypted_backup(
    source: Path,
    *,
    vault_file: Path,
    settings_file: Path | None,
    backup_password: str,
) -> str:
    warnings.warn(
        "restore_encrypted_backup is retained for compatibility; use restore_verified_backup for new restores",
        DeprecationWarning,
        stacklevel=2,
    )
    # Keep this compatibility API on the same bounded envelope parser as the
    # verified restore path. It still cannot verify the vault master password
    # because that password is intentionally not part of this API.
    payload = _read_backup_payload(source, backup_password)

    atomic_write_json(vault_file, payload["vault"])
    # The rollback anchor is deliberately left alone: this API cannot open the
    # vault, so it cannot mint an authenticated anchor, and resetting it would
    # silently accept an older vault.  An older restored copy therefore fails
    # the rollback check at the next unlock until the user confirms a rollback
    # through the verified restore path.
    if settings_file is not None and isinstance(payload.get("settings"), dict):
        atomic_write_json(settings_file, payload["settings"])
    return str(payload.get("profile_name") or "Restored profile")


MAX_BACKUP_BYTES = 32 * 1024 * 1024


def _read_backup_payload(source: Path, backup_password: str) -> dict[str, Any]:
    """Validate bounds before decryption; never create a plaintext temporary file."""
    try:
        if source.stat().st_size > MAX_BACKUP_BYTES:
            raise BackupError("Backup is too large")
        with source.open("rb") as handle:
            blob = handle.read(MAX_BACKUP_BYTES + 1)
        if len(blob) > MAX_BACKUP_BYTES:
            raise BackupError("Backup is too large")
        envelope = json.loads(blob)
        if not isinstance(envelope, dict):
            raise BackupError("Backup header must be an object")
        version = envelope.get("version")
        if envelope.get("format") != "localgatekeys-backup" or version not in SUPPORTED_BACKUP_VERSIONS:
            raise BackupError("Unsupported backup format")
        kdf, cipher = envelope["kdf"], envelope["cipher"]
        if not isinstance(kdf, dict) or not isinstance(cipher, dict) or cipher.get("name") != "aes-256-gcm":
            raise BackupError("Unsupported backup encryption parameters")
        _kdf_parameters(kdf)
        salt, nonce = _b64d(kdf["salt"]), _b64d(cipher["nonce"])
        if len(salt) != 16 or len(nonce) != 12:
            raise BackupError("Malformed encryption header")
        aad = BACKUP_AAD if version == 1 else _backup_header_aad(envelope)
        raw = AESGCM(_derive(backup_password, salt, kdf)).decrypt(nonce, _b64d(cipher["ciphertext"]), aad)
        payload = json.loads(raw)
        if (not isinstance(payload, dict) or payload.get("version") != BACKUP_PAYLOAD_VERSION or
                not isinstance(payload.get("vault"), dict)):
            raise BackupError("Malformed encrypted backup payload")
        return payload
    except InvalidTag:
        raise BackupError("Wrong backup password or modified backup") from None
    except (OSError, KeyError, TypeError, ValueError, RecursionError):
        raise BackupError("Could not read this backup") from None


def _vault_secret(value: Any, message: str) -> tuple[SecretText, bool]:
    """Convert the vault (master) password once at a public entry: ``(secret, owned)``."""
    if not isinstance(value, (str, SecretText)):
        raise BackupError(message)
    try:
        return as_secret(value)
    except ValueError:
        raise BackupError(message) from None


_VERIFY_FAILED = ("Backup opened, but its vault could not be unlocked/validated. "
                  "Use the vault master password from when this backup was made.")


def verify_encrypted_backup(source: Path, *, backup_password: str,
                            vault_password: str | SecretText) -> dict[str, Any]:
    """Verify BOTH layers of encryption and schema without touching a live vault.

    Existing .lgk exports wrap an already-encrypted vault. Consequently full
    recovery requires the backup password AND that vault's master password at
    the time the backup was made. The temporary file below is encrypted only.
    """
    payload = _read_backup_payload(source, backup_password)
    secret, owned = _vault_secret(vault_password, _VERIFY_FAILED)
    try:
        return _verify_payload(payload, secret)
    finally:
        if owned:
            secret.wipe()


def _verify_payload(payload: dict[str, Any], vault_password: SecretText) -> dict[str, Any]:
    from .vault import VaultError, unlock_vault
    try:
        # A private directory holds the encrypted copy and the anchor the
        # probe unlock writes; nothing is left behind in the system temp.  The
        # probe never upgrades a v1/v2 envelope, which would otherwise write a
        # migration journal and pre-migration snapshot beside the copy.
        with private_temporary_directory("lgk-verify-") as directory:
            encrypted_path = Path(directory) / "vault.json"
            atomic_write_json(encrypted_path, payload["vault"])
            session = unlock_vault(encrypted_path, vault_password, upgrade_envelope=False)
            try:
                return {"verified": True, "profile_name": str(payload.get("profile_name", "Restored profile")),
                        "entries": len(session.summaries()), "deleted_entries": len(session.trash_summaries()),
                        "exported_at": int(payload.get("exported_at", 0))}
            finally:
                session.lock()
    except (VaultError, OSError, ValueError, TypeError, OverflowError):
        raise BackupError("Backup opened, but its vault could not be unlocked/validated. Use the vault master password from when this backup was made.") from None


def _check_restore_rollback(session: Any, vault_file: Path, *, allow_rollback: bool) -> None:
    """Raise RollbackRequiresConfirmation when the destination already moved further ahead.

    The anchor is authenticated with the restored vault's data key.  An anchor
    that does not authenticate belongs to a different key lineage, which is
    also treated as a rollback that needs explicit confirmation.
    """
    from .vault import RollbackRequiresConfirmation, VaultError, _read_generation_anchor

    restored_generation = int(session._payload.get("generation", 0))
    try:
        current = session.rollback_anchor_generation(vault_file)
        foreign = False
    except VaultError:
        current, _upgrade = _read_generation_anchor(vault_file)
        foreign = True
    if current is None:
        return
    if (foreign or current > restored_generation) and not allow_rollback:
        raise RollbackRequiresConfirmation(current_generation=int(current), restored_generation=restored_generation)


def _sanitize_restored_settings(settings: dict[str, Any]) -> None:
    """Autostart, external requests and automatic sign-in are OFF for a restored profile."""
    settings.update(start_with_windows=False, fill_and_sign_in=False, breach_check_enabled=False)


def _sanitize_restored_session(session: Any) -> None:
    """Restored credentials must not silently retain automatic sign-in or desktop-fill approvals."""
    from .access_policy import normalized_policy
    with session.transaction():
        session.set_fill_and_sign_in_enabled(False)
        for entry in session.all_entries():
            policy = normalized_policy(entry.get("policy"))
            policy["sign_in"] = "never"
            session.set_entry_extras(entry["id"], policy=policy)
            if entry["kind"] == "desktop":
                session.set_desktop_embedded_fill_approval(entry["id"], False)
            entry.clear()


def restore_verified_backup(source: Path, *, vault_file: Path, settings_file: Path | None,
                            backup_password: str, vault_password: str | SecretText,
                            replace: bool = False, allow_rollback: bool = False) -> dict[str, Any]:
    """Restore into a new profile by default; caller must explicitly request replacement.

    Restoring a copy that is older than the rollback anchor beside ``vault_file``
    raises ``RollbackRequiresConfirmation`` before anything is written unless
    ``allow_rollback`` is set.
    """
    payload = _read_backup_payload(source, backup_password)
    secret, owned = _vault_secret(vault_password, _VERIFY_FAILED)
    try:
        return _restore_verified(payload, secret, vault_file=vault_file, settings_file=settings_file,
                                 replace=replace, allow_rollback=allow_rollback)
    finally:
        if owned:
            secret.wipe()


def _restore_verified(payload: dict[str, Any], vault_password: SecretText, *, vault_file: Path,
                      settings_file: Path | None, replace: bool, allow_rollback: bool) -> dict[str, Any]:
    from .settings import AppSettings
    from .vault import unlock_vault
    info = _verify_payload(payload, vault_password)
    if vault_file.exists() and not replace:
        raise BackupError("Destination already has a vault. Restore as a new profile instead.")
    with private_temporary_directory("lgk-restore-check-") as directory:
        probe_path = Path(directory) / "vault.json"
        atomic_write_json(probe_path, payload["vault"])
        probe = unlock_vault(probe_path, vault_password, upgrade_envelope=False)
        try:
            _check_restore_rollback(probe, vault_file, allow_rollback=allow_rollback)
        finally:
            probe.lock()
    if replace and vault_file.exists():
        # Preserve the old encrypted file before replacement, never a plaintext copy.
        previous = vault_file.parent / "Backups" / (f"before-restore-{time.time_ns()}.json")
        atomic_write_json(previous, read_json(vault_file))
    # Profile-specific settings are restored through their normal validation.
    # Autostart/external requests/automatic sign-in are OFF for a restored profile.
    if settings_file is not None:
        raw = payload.get("settings")
        if isinstance(raw, dict):
            _sanitize_restored_settings(raw)
            atomic_write_json(settings_file, raw)
            AppSettings.load(settings_file).save(settings_file)
    # Restored credentials must not silently retain per-entry automatic sign-in approvals.
    # Re-encrypt the sanitized payload in an encrypted-only temporary file.
    with private_temporary_directory("lgk-restore-") as directory:
        temporary = Path(directory) / "vault.json"
        atomic_write_json(temporary, payload["vault"])
        session = unlock_vault(temporary, vault_password)
        try:
            _sanitize_restored_session(session)
            atomic_write_json(vault_file, read_json(temporary))
            # Mint the anchor with the restored vault's own data key; a confirmed
            # rollback replaces the newer anchor instead of resetting it to zero.
            session.write_rollback_anchor(vault_file)
        finally:
            session.lock()
    return info


# Full profile backups are deliberately a separate format.  The v1 limit above
# is part of the compatibility contract and must not be raised for old .lgk
# envelopes.
FULL_BACKUP_VERSION = 2
FULL_BACKUP_FORMAT = "localgatekeys-full-backup"
FULL_BACKUP_AAD = b"localgatekeys|encrypted-full-profile-backup|v2"
FULL_BACKUP_KDF = dict(BACKUP_KDF)
MAX_FULL_BACKUP_BYTES = 2 * 1024 * 1024 * 1024
MAX_FULL_BACKUP_ENTRIES = 20_005  # catalog attachment bound plus vault/settings metadata
MAX_FULL_BACKUP_MEMBER_BYTES = 32 * 1024 * 1024
MAX_FULL_BACKUP_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_FULL_BACKUP_HEADER_BYTES = 64 * 1024
MAX_FULL_BACKUP_SETTINGS_BYTES = 1 * 1024 * 1024

# Names used by callers that adopted the M3 terminology before the final
# constants were chosen.  Keeping these aliases costs nothing and makes the
# size/entry bounds straightforward to discover.
MAX_BACKUP_V2_BYTES = MAX_FULL_BACKUP_BYTES
MAX_FULL_ARCHIVE_BYTES = MAX_FULL_BACKUP_BYTES
MAX_BACKUP_V2_ENTRIES = MAX_FULL_BACKUP_ENTRIES


class BackupCancelled(BackupError):
    """A full backup operation was cancelled before publication."""


def _full_cancelled(cancel: Callable[[], bool] | Any | None) -> None:
    if cancel is None:
        return
    try:
        value = cancel.is_set() if hasattr(cancel, "is_set") else bool(cancel())
    except Exception as exc:  # noqa: BLE001
        raise BackupCancelled("Backup operation was cancelled") from exc
    if value:
        raise BackupCancelled("Backup operation was cancelled")


def _full_progress(
    callback: Callable[..., Any] | None,
    phase: str,
    completed: int,
    total: int,
) -> None:
    """Call progress hooks with metadata only; never pass names or data."""
    if callback is None:
        return
    event = {"phase": phase, "completed": int(completed), "total": int(total)}
    try:
        callback(phase, int(completed), int(total))
    except TypeError:
        try:
            callback(event)
        except TypeError:
            callback(int(completed), int(total))


def _full_regular_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise BackupError(f"{label} must be a regular non-symlink file")


def _full_bounded_read(
    path: Path,
    limit: int,
    *,
    label: str,
    cancel: Callable[[], bool] | Any | None = None,
    progress: Callable[..., Any] | None = None,
    phase: str = "read",
) -> bytes:
    path = Path(path)
    _full_regular_file(path, label)
    try:
        size = path.stat().st_size
        if size > limit:
            raise BackupError(f"{label} is too large")
        chunks: list[bytes] = []
        total = 0
        with path.open("rb") as handle:
            while True:
                _full_cancelled(cancel)
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise BackupError(f"{label} is too large")
                _full_progress(progress, phase, total, max(size, total))
        if path.stat().st_size != size:
            raise BackupError(f"{label} changed while it was being read")
        return b"".join(chunks)
    except BackupError:
        raise
    except OSError as exc:
        raise BackupError(f"Could not read {label}") from exc


def _full_atomic_bytes(path: Path, data: bytes) -> None:
    """Write bounded binary data atomically, with no destination plaintext temp."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".lgk-full-", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _full_temp_dir(parent: Path, prefix: str) -> Path:
    """Create a random working directory usable by the current Windows user."""
    parent = Path(parent)
    try:
        parent.mkdir(parents=True, exist_ok=True)
        for _ in range(16):
            candidate = parent / f"{prefix}{uuid.uuid4().hex}"
            try:
                candidate.mkdir()
                return candidate
            except FileExistsError:
                continue
    except OSError as exc:
        raise BackupError("Could not create full backup staging directory") from exc
    raise BackupError("Could not create a unique full backup staging directory")


def _full_canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _full_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _full_validate_settings(value: Any) -> dict[str, Any]:
    """Normalize settings through the same bounds used by AppSettings.save."""
    from .hotkey import normalize_hotkey
    from .settings import (
        LOADABLE_SETTINGS_VERSIONS,
        SETTINGS_VERSION,
        AppSettings,
        _bounded,
        _validated_backup_count,
        _validated_clipboard_timeout,
        _validated_timeout,
    )

    if not isinstance(value, dict):
        raise BackupError("Backup settings must be an object")
    version = value.get("version", 1)
    if version not in LOADABLE_SETTINGS_VERSIONS:
        raise BackupError("Unsupported backup settings version")
    defaults = AppSettings()
    args: dict[str, Any] = {}
    for field in dataclasses.fields(defaults):
        name = field.name
        default = getattr(defaults, name)
        raw = value.get(name, default)
        if isinstance(default, bool):
            args[name] = raw if type(raw) is bool else default
    # The same migrations as AppSettings.load: neither stored "on" was ever chosen.
    if version < 7:
        args["website_icons"] = defaults.website_icons
    if version < 8:
        args["legacy_gesture_compat"] = defaults.legacy_gesture_compat
    args.update(
        auto_lock_seconds=_validated_timeout(value.get("auto_lock_seconds", defaults.auto_lock_seconds)),
        max_session_seconds=_validated_timeout(value.get("max_session_seconds", defaults.max_session_seconds),
                                                default=defaults.max_session_seconds),
        idle_source=value.get("idle_source") if value.get("idle_source") in ("computer", "vault") else defaults.idle_source,
        clipboard_clear_seconds=_validated_clipboard_timeout(
            value.get("clipboard_clear_seconds", defaults.clipboard_clear_seconds)
        ),
        automatic_backup_count=_validated_backup_count(
            value.get("automatic_backup_count", defaults.automatic_backup_count)
        ),
        trash_retention_days=_bounded(value.get("trash_retention_days", defaults.trash_retention_days), 1, 365, 30),
    )
    try:
        args["quick_access_hotkey"] = normalize_hotkey(
            value.get("quick_access_hotkey", defaults.quick_access_hotkey)
        )
    except ValueError:
        args["quick_access_hotkey"] = defaults.quick_access_hotkey
    return {"version": SETTINGS_VERSION, **dataclasses.asdict(AppSettings(**args))}


def _full_read_settings(path: Path | None) -> dict[str, Any]:
    if path is None or not Path(path).exists():
        return _full_validate_settings({})
    try:
        raw = read_json(Path(path))
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise BackupError("Could not read profile settings") from exc
    return _full_validate_settings(raw)


def _full_validate_json_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise BackupError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise BackupError(f"{label} must be a JSON object")
    return value


def _full_validate_generation(data: bytes) -> None:
    value = _full_validate_json_object(data, "Vault generation metadata")
    generation = value.get("generation")
    if value.get("version") != 1 or type(generation) is not int or not 0 <= generation <= 2**63 - 1:
        raise BackupError("Vault generation metadata is malformed")


def _full_validate_sidecar_header(data: bytes, *, expected_id: str | None = None) -> dict[str, Any]:
    """Validate the unauthenticated sidecar framing before any publication."""
    from .attachments import ATTACHMENT_MAGIC, MAX_ATTACHMENT_SIZE, SUPPORTED_ATTACHMENT_VERSIONS

    if len(data) > MAX_ATTACHMENT_SIZE + 64 * 1024:
        raise BackupError("Attachment sidecar is too large")
    if not data.startswith(ATTACHMENT_MAGIC) or len(data) < len(ATTACHMENT_MAGIC) + 4:
        raise BackupError("Attachment sidecar has an invalid header")
    offset = len(ATTACHMENT_MAGIC)
    header_length = int.from_bytes(data[offset:offset + 4], "big")
    if not 1 <= header_length <= 8 * 1024:
        raise BackupError("Attachment sidecar header is malformed")
    start = offset + 4
    end = start + header_length
    if end + 12 > len(data):
        raise BackupError("Attachment sidecar is truncated")
    header = _full_validate_json_object(data[start:end], "Attachment sidecar header")
    if (header.get("format") != "localgatekeys-attachment"
            or header.get("version") not in SUPPORTED_ATTACHMENT_VERSIONS):
        raise BackupError("Unsupported attachment sidecar format")
    attachment_id = str(header.get("id", ""))
    try:
        parsed_id = str(uuid.UUID(attachment_id))
    except (ValueError, TypeError, AttributeError):
        raise BackupError("Attachment sidecar ID is malformed") from None
    if expected_id is not None and parsed_id != expected_id:
        raise BackupError("Attachment sidecar ID does not match its manifest")
    ciphertext_length = len(data) - (end + 12)
    if ciphertext_length < 16 or ciphertext_length - 16 > MAX_ATTACHMENT_SIZE:
        raise BackupError("Attachment sidecar length is out of bounds")
    if header.get("version") == 1:
        size = header.get("size")
        digest = header.get("sha256")
        if type(size) is not int or not 0 <= size <= MAX_ATTACHMENT_SIZE:
            raise BackupError("Attachment sidecar size is malformed")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(char not in "0123456789abcdefABCDEF" for char in digest)):
            raise BackupError("Attachment sidecar digest is malformed")
        if ciphertext_length != size + 16:
            raise BackupError("Attachment sidecar length does not match its header")
        digest = digest.lower()
    else:
        # v2 headers carry identity only; the plaintext size follows from the
        # AES-GCM body and the digest is verified from the encrypted catalog.
        if set(header) != {"format", "version", "id", "store_id"}:
            raise BackupError("Attachment sidecar header is malformed")
        size = ciphertext_length - 16
        digest = None
    return {"id": parsed_id, "store_id": header.get("store_id"), "size": size,
            "sha256": digest, "header": header}


def _full_resolve_paths(
    *,
    profile_dir: Path | None,
    vault_file: Path | None,
    settings_file: Path | None,
    attachment_store_dir: Path | None,
    attachment_store: Path | None,
) -> tuple[Path, Path, Path | None, Path, Path]:
    if attachment_store_dir is not None and attachment_store is not None:
        if Path(attachment_store_dir) != Path(attachment_store):
            raise BackupError("Attachment store paths disagree")
    attachment_store_dir = attachment_store_dir or attachment_store
    if profile_dir is not None:
        root = Path(profile_dir)
        expected_vault = root / "vault.json"
        expected_settings = root / "settings.json"
        expected_attachments = root / "Attachments"
        if vault_file is not None and Path(vault_file) != expected_vault:
            raise BackupError("Explicit vault path does not belong to profile_dir")
        if settings_file is not None and Path(settings_file) != expected_settings:
            raise BackupError("Explicit settings path does not belong to profile_dir")
        if attachment_store_dir is not None and Path(attachment_store_dir) != expected_attachments:
            raise BackupError("Explicit attachment path does not belong to profile_dir")
        vault_file = expected_vault
        settings_file = expected_settings
        attachment_store_dir = expected_attachments
    elif vault_file is None:
        raise BackupError("A profile_dir or vault_file is required")
    else:
        vault_file = Path(vault_file)
        if attachment_store_dir is None:
            attachment_store_dir = vault_file.parent / "Attachments"
    vault_file = Path(vault_file)
    root = Path(profile_dir) if profile_dir is not None else vault_file.parent
    anchor = vault_file.with_name(vault_file.stem + ".generation.json")
    return root, vault_file, Path(settings_file) if settings_file is not None else None, Path(attachment_store_dir), anchor


def _full_source_sidecars(
    attachment_store_dir: Path,
    *,
    cancel: Callable[[], bool] | Any | None,
    progress: Callable[..., Any] | None,
) -> list[dict[str, Any]]:
    if not attachment_store_dir.exists():
        return []
    if attachment_store_dir.is_symlink() or not attachment_store_dir.is_dir():
        raise BackupError("Attachment store must be a regular directory")
    result: list[dict[str, Any]] = []
    try:
        paths = sorted(attachment_store_dir.glob("*.blob"), key=lambda item: item.name)
    except OSError as exc:
        raise BackupError("Could not enumerate attachment store") from exc
    for index, path in enumerate(paths, start=1):
        _full_cancelled(cancel)
        if path.is_symlink() or not path.is_file():
            continue
        try:
            attachment_id = str(uuid.UUID(path.stem))
        except (ValueError, TypeError, AttributeError):
            # Temporary/unrelated files are not part of the attachment store.
            continue
        data = _full_bounded_read(
            path,
            MAX_FULL_BACKUP_MEMBER_BYTES,
            label="Attachment sidecar",
            cancel=cancel,
            progress=progress,
            phase="scan-attachments",
        )
        parsed = _full_validate_sidecar_header(data, expected_id=attachment_id)
        result.append({
            "kind": "attachment",
            "target": f"{attachment_id}.blob",
            "attachment_id": attachment_id,
            "source": path,
            "size": len(data),
            "sha256": _full_sha256(data),
            "sidecar_size": parsed["size"],
        })
        _full_progress(progress, "scan-attachments", index, max(index, len(paths)))
        if len(result) + 3 > MAX_FULL_BACKUP_ENTRIES:
            raise BackupError("Full backup contains too many entries")
    return result


def _full_entry_bytes(entry: dict[str, Any], *, cancel: Callable[[], bool] | Any | None,
                      progress: Callable[..., Any] | None) -> bytes:
    _full_cancelled(cancel)
    if "data" in entry:
        data = entry["data"]
    else:
        data = _full_bounded_read(
            Path(entry["source"]),
            MAX_FULL_BACKUP_MEMBER_BYTES,
            label="Attachment sidecar",
            cancel=cancel,
            progress=progress,
            phase="read-attachment",
        )
    if len(data) != entry["size"] or _full_sha256(data) != entry["sha256"]:
        raise BackupError("A source changed while the full backup was being written")
    return data


def _full_zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 0
    info.external_attr = 0o600 << 16
    return info


def _full_encrypt(data: bytes, *, key: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def export_full_backup(
    destination: Path,
    *,
    profile_dir: Path | None = None,
    vault_file: Path | None = None,
    settings_file: Path | None = None,
    attachment_store_dir: Path | None = None,
    attachment_store: Path | None = None,
    profile_name: str | None = None,
    backup_password: str,
    cancel: Callable[[], bool] | Any | None = None,
    progress: Callable[..., Any] | None = None,
    kdf_overrides: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Export a complete profile into an authenticated, encrypted v2 container.

    ZIP member names are fixed safe tokens.  The manifest, vault JSON, settings
    and opaque encrypted sidecars are all authenticated with the backup key;
    only the version/KDF header is visible without the password.
    """
    root, vault_file, settings_file, attachment_dir, anchor = _full_resolve_paths(
        profile_dir=profile_dir,
        vault_file=vault_file,
        settings_file=settings_file,
        attachment_store_dir=attachment_store_dir,
        attachment_store=attachment_store,
    )
    _full_cancelled(cancel)
    vault_data = _full_bounded_read(vault_file, MAX_FULL_BACKUP_MEMBER_BYTES, label="Vault", cancel=cancel,
                                    progress=progress, phase="read-vault")
    _full_validate_json_object(vault_data, "Vault")
    settings = _full_read_settings(settings_file)
    settings_data = _full_canonical(settings)
    if len(settings_data) > MAX_FULL_BACKUP_SETTINGS_BYTES:
        raise BackupError("Profile settings are too large")
    entries: list[dict[str, Any]] = [
        {"kind": "vault", "target": "vault.json", "data": vault_data,
         "size": len(vault_data), "sha256": _full_sha256(vault_data)},
        {"kind": "settings", "target": "settings.json", "data": settings_data,
         "size": len(settings_data), "sha256": _full_sha256(settings_data)},
    ]
    if anchor.exists():
        anchor_data = _full_bounded_read(anchor, 64 * 1024, label="Vault generation metadata", cancel=cancel,
                                         progress=progress, phase="read-vault")
        _full_validate_generation(anchor_data)
        entries.append({"kind": "generation", "target": "generation.json", "data": anchor_data,
                        "size": len(anchor_data), "sha256": _full_sha256(anchor_data)})
    entries.extend(_full_source_sidecars(attachment_dir, cancel=cancel, progress=progress))
    if len(entries) > MAX_FULL_BACKUP_ENTRIES:
        raise BackupError("Full backup contains too many entries")
    if profile_name is None:
        profile_name = root.name or "Restored profile"
    if not isinstance(profile_name, str) or not 1 <= len(profile_name) <= 256 or "\x00" in profile_name:
        raise BackupError("Profile name is malformed")

    salt = os.urandom(16)
    kdf = _new_kdf(kdf_overrides)
    key = _derive(backup_password, salt, kdf)
    header = {
        "format": FULL_BACKUP_FORMAT,
        "version": FULL_BACKUP_VERSION,
        "kdf": {**kdf, "salt": _b64e(salt)},
        "cipher": {"name": "aes-256-gcm", "nonce_bytes": 12, "tag_bytes": 16},
        "entry_count": len(entries),
    }
    header_data = _full_canonical(header)
    if len(header_data) > MAX_FULL_BACKUP_HEADER_BYTES:
        raise BackupError("Full backup header is too large")
    manifest_entries: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        member = f"data/{index:08d}.bin"
        entry["member"] = member
        record = {key: entry[key] for key in ("kind", "target", "size", "sha256")}
        if entry["kind"] == "attachment":
            record["attachment_id"] = entry["attachment_id"]
            record["sidecar_size"] = entry["sidecar_size"]
        record["member"] = member
        manifest_entries.append(record)
    manifest = {
        "version": FULL_BACKUP_VERSION,
        "profile_name": profile_name,
        "entries": manifest_entries,
        "created_at": int(time.time()),
    }
    manifest_data = _full_canonical(manifest)
    if len(manifest_data) > MAX_FULL_BACKUP_MANIFEST_BYTES:
        raise BackupError("Full backup manifest is too large")
    manifest_digest = hashlib.sha256(manifest_data).digest()
    manifest_blob = _full_encrypt(manifest_data, key=key, aad=FULL_BACKUP_AAD + header_data)

    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_dir():
        raise BackupError("Backup destination must be a file")
    fd, name = tempfile.mkstemp(prefix=".lgk-full-backup-", suffix=".tmp", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w+b") as handle:
            with zipfile.ZipFile(handle, mode="w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                archive.writestr(_full_zip_info("header.json"), header_data)
                archive.writestr(_full_zip_info("manifest.bin"), manifest_blob)
                total = len(entries)
                for index, entry in enumerate(entries, start=1):
                    _full_cancelled(cancel)
                    data = _full_entry_bytes(entry, cancel=cancel, progress=progress)
                    aad = FULL_BACKUP_AAD + header_data + manifest_digest + entry["member"].encode("ascii")
                    blob = _full_encrypt(data, key=key, aad=aad)
                    archive.writestr(_full_zip_info(entry["member"]), blob)
                    _full_progress(progress, "export", index, total)
            handle.flush()
            os.fsync(handle.fileno())
        if temporary.stat().st_size > MAX_FULL_BACKUP_BYTES:
            raise BackupError("Full backup is too large")
        _full_cancelled(cancel)
        os.replace(temporary, destination)
    except BackupError:
        temporary.unlink(missing_ok=True)
        raise
    except (OSError, zipfile.BadZipFile, ValueError) as exc:
        temporary.unlink(missing_ok=True)
        raise BackupError("Could not write full backup") from exc
    return {
        "version": FULL_BACKUP_VERSION,
        "profile_name": profile_name,
        "entries": len(entries),
        "attachments": sum(entry["kind"] == "attachment" for entry in entries),
        "bytes": destination.stat().st_size,
    }


def _full_zip_read(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int,
                   *, cancel: Callable[[], bool] | Any | None = None) -> bytes:
    if info.file_size > limit:
        raise BackupError("Full backup member is too large")
    chunks: list[bytes] = []
    total = 0
    try:
        with archive.open(info, "r") as handle:
            while True:
                _full_cancelled(cancel)
                chunk = handle.read(min(1024 * 1024, limit - total + 1))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise BackupError("Full backup member is too large")
    except BackupError:
        raise
    except (OSError, EOFError, RuntimeError, zipfile.BadZipFile) as exc:
        raise BackupError("Full backup is truncated or unreadable") from exc
    if total != info.file_size:
        raise BackupError("Full backup member length is inconsistent")
    return b"".join(chunks)


def _full_manifest_entries(manifest: dict[str, Any], header: dict[str, Any]) -> list[dict[str, Any]]:
    entries = manifest.get("entries")
    if manifest.get("version") != FULL_BACKUP_VERSION or not isinstance(entries, list):
        raise BackupError("Full backup manifest is malformed")
    if len(entries) != header.get("entry_count") or not 2 <= len(entries) <= MAX_FULL_BACKUP_ENTRIES:
        raise BackupError("Full backup entry count is invalid")
    profile_name = manifest.get("profile_name")
    if not isinstance(profile_name, str) or not 1 <= len(profile_name) <= 256 or "\x00" in profile_name:
        raise BackupError("Full backup profile name is malformed")
    result: list[dict[str, Any]] = []
    seen_members: set[str] = set()
    seen_targets: set[str] = set()
    kinds: set[str] = set()
    for index, raw in enumerate(entries):
        if not isinstance(raw, dict):
            raise BackupError("Full backup manifest entry is malformed")
        allowed = {"kind", "target", "size", "sha256", "member", "attachment_id", "sidecar_size"}
        if set(raw) - allowed:
            raise BackupError("Full backup manifest contains unsupported fields")
        kind, target, member = raw.get("kind"), raw.get("target"), raw.get("member")
        if kind not in {"vault", "settings", "generation", "attachment"} or not isinstance(target, str):
            raise BackupError("Full backup manifest entry type is invalid")
        expected_member = f"data/{index:08d}.bin"
        if member != expected_member or member in seen_members:
            raise BackupError("Full backup data member name is invalid")
        if kind == "vault" and target != "vault.json":
            raise BackupError("Full backup vault target is invalid")
        if kind == "settings" and target != "settings.json":
            raise BackupError("Full backup settings target is invalid")
        if kind == "generation" and target != "generation.json":
            raise BackupError("Full backup generation target is invalid")
        if kind == "attachment":
            attachment_id = raw.get("attachment_id")
            try:
                attachment_id = str(uuid.UUID(str(attachment_id)))
            except (ValueError, TypeError, AttributeError):
                raise BackupError("Full backup attachment ID is invalid") from None
            if target != f"{attachment_id}.blob" or raw.get("sidecar_size") is None:
                raise BackupError("Full backup attachment target is invalid")
            raw = {**raw, "attachment_id": attachment_id}
        if target in seen_targets:
            raise BackupError("Full backup contains duplicate targets")
        size = raw.get("size")
        digest = raw.get("sha256")
        if type(size) is not int or not 0 <= size <= MAX_FULL_BACKUP_MEMBER_BYTES:
            raise BackupError("Full backup member size is invalid")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(char not in "0123456789abcdefABCDEF" for char in digest)):
            raise BackupError("Full backup member digest is invalid")
        if kind == "attachment" and (type(raw.get("sidecar_size")) is not int or raw["sidecar_size"] < 0):
            raise BackupError("Full backup sidecar size is invalid")
        seen_members.add(member)
        seen_targets.add(target)
        kinds.add(kind)
        result.append({**raw, "sha256": digest.lower()})
    if kinds & {"vault"} == set() or "settings" not in kinds:
        raise BackupError("Full backup is missing vault or settings")
    if sum(raw["kind"] == "vault" for raw in result) != 1 or sum(raw["kind"] == "settings" for raw in result) != 1:
        raise BackupError("Full backup contains duplicate vault or settings entries")
    if sum(raw["kind"] == "generation" for raw in result) > 1:
        raise BackupError("Full backup contains duplicate generation metadata")
    return result


def _full_read_container(
    source: Path,
    backup_password: str,
    *,
    on_entry: Callable[[dict[str, Any], bytes], None],
    cancel: Callable[[], bool] | Any | None = None,
    progress: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    source = Path(source)
    _full_regular_file(source, "Full backup")
    try:
        if source.stat().st_size > MAX_FULL_BACKUP_BYTES:
            raise BackupError("Full backup is too large")
        with zipfile.ZipFile(source, "r") as archive:
            infos = archive.infolist()
            if len(infos) < 4 or len(infos) > MAX_FULL_BACKUP_ENTRIES + 2:
                raise BackupError("Full backup has too many archive members")
            info_by_name: dict[str, zipfile.ZipInfo] = {}
            for info in infos:
                name = info.filename
                if name in info_by_name or name not in {"header.json", "manifest.bin"} and not (
                    isinstance(name, str) and name.startswith("data/") and name.endswith(".bin")
                ):
                    raise BackupError("Full backup contains an unsafe archive member")
                if not isinstance(name, str) or "\x00" in name or name.startswith(("/", "\\")) or ".." in name.split("/"):
                    raise BackupError("Full backup contains an unsafe archive member")
                if info.flag_bits & 0x1 or info.compress_type != zipfile.ZIP_STORED:
                    raise BackupError("Full backup compression or ZIP encryption is unsupported")
                if info.file_size > MAX_FULL_BACKUP_MEMBER_BYTES + 64 * 1024:
                    raise BackupError("Full backup member is too large")
                info_by_name[name] = info
            if set(info_by_name) - {"header.json", "manifest.bin"} and any(
                not name.startswith("data/") for name in info_by_name if name not in {"header.json", "manifest.bin"}
            ):
                raise BackupError("Full backup contains an unsafe archive member")
            header_data = _full_zip_read(archive, info_by_name.get("header.json") or (_ for _ in ()).throw(BackupError("Missing full backup header")),
                                         MAX_FULL_BACKUP_HEADER_BYTES, cancel=cancel)
            header = _full_validate_json_object(header_data, "Full backup header")
            if header.get("format") != FULL_BACKUP_FORMAT or header.get("version") != FULL_BACKUP_VERSION:
                raise BackupError("Unsupported full backup format")
            kdf = header.get("kdf")
            cipher = header.get("cipher")
            if (not isinstance(kdf, dict) or not isinstance(cipher, dict)
                    or cipher.get("name") != "aes-256-gcm" or cipher.get("nonce_bytes") != 12
                    or cipher.get("tag_bytes") != 16):
                raise BackupError("Unsupported full backup encryption parameters")
            _kdf_parameters(kdf)
            salt = _b64d(kdf.get("salt", ""))
            if len(salt) != 16:
                raise BackupError("Malformed full backup KDF salt")
            entry_count = header.get("entry_count")
            if type(entry_count) is not int or not 2 <= entry_count <= MAX_FULL_BACKUP_ENTRIES:
                raise BackupError("Full backup entry count is invalid")
            manifest_info = info_by_name.get("manifest.bin")
            if manifest_info is None:
                raise BackupError("Missing full backup manifest")
            manifest_blob = _full_zip_read(archive, manifest_info, MAX_FULL_BACKUP_MANIFEST_BYTES + 64, cancel=cancel)
            if len(manifest_blob) < 12 + 16:
                raise BackupError("Full backup manifest is truncated")
            key = _derive(backup_password, salt, kdf)
            try:
                manifest_data = AESGCM(key).decrypt(
                    manifest_blob[:12], manifest_blob[12:], FULL_BACKUP_AAD + header_data
                )
            except InvalidTag:
                raise BackupError("Wrong backup password or modified full backup") from None
            if len(manifest_data) > MAX_FULL_BACKUP_MANIFEST_BYTES:
                raise BackupError("Full backup manifest is too large")
            manifest = _full_validate_json_object(manifest_data, "Full backup manifest")
            entries = _full_manifest_entries(manifest, header)
            expected_names = {"header.json", "manifest.bin"} | {entry["member"] for entry in entries}
            if set(info_by_name) != expected_names:
                raise BackupError("Full backup members do not match its manifest")
            manifest_digest = hashlib.sha256(manifest_data).digest()
            for index, entry in enumerate(entries, start=1):
                _full_cancelled(cancel)
                info = info_by_name[entry["member"]]
                if info.file_size != entry["size"] + 12 + 16:
                    raise BackupError("Full backup member size does not match its manifest")
                blob = _full_zip_read(archive, info, MAX_FULL_BACKUP_MEMBER_BYTES + 64 * 1024, cancel=cancel)
                aad = FULL_BACKUP_AAD + header_data + manifest_digest + entry["member"].encode("ascii")
                try:
                    data = AESGCM(key).decrypt(blob[:12], blob[12:], aad)
                except InvalidTag:
                    raise BackupError("Wrong backup password or modified full backup") from None
                if len(data) != entry["size"] or _full_sha256(data) != entry["sha256"]:
                    raise BackupError("Full backup member authentication failed")
                on_entry(entry, data)
                _full_progress(progress, "import", index, len(entries))
            return {"manifest": manifest, "header": header, "entries": entries}
    except BackupError:
        raise
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, zipfile.BadZipFile, RecursionError) as exc:
        raise BackupError("Could not read full backup") from exc


def _full_validate_staged_vault(
    vault_path: Path,
    attachment_dir: Path,
    *,
    vault_password: SecretText | None,
    attachment_quota_bytes: int,
    cancel: Callable[[], bool] | Any | None = None,
    progress: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    from .vault import VaultError, _read_vault_header, unlock_vault

    try:
        _read_vault_header(vault_path)
    except (VaultError, OSError, ValueError, TypeError) as exc:
        raise BackupError("Full backup contains an invalid encrypted vault") from exc
    if not 1 <= int(attachment_quota_bytes) <= 1024 * 1024 * 1024:
        raise BackupError("Attachment quota is outside the accepted bound")
    if vault_password is None:
        return {"verified": False, "entries": None, "attachments": None}
    try:
        session = unlock_vault(vault_path, vault_password)
    except Exception as exc:  # noqa: BLE001 - do not leak vault parser details
        raise BackupError("Backup vault could not be unlocked with the supplied master password") from exc
    try:
        from .attachments import AttachmentStore
        store = AttachmentStore(session, quota_bytes=int(attachment_quota_bytes))
        store.root = Path(attachment_dir)
        records = list(session._payload.get("attachments", []))
        for index, record in enumerate(records, start=1):
            _full_cancelled(cancel)
            store.read_bytes(record["id"], cancel=cancel)
            _full_progress(progress, "validate-attachments", index, len(records))
        if store.usage_bytes() > int(attachment_quota_bytes):
            raise BackupError("Restored attachments exceed the attachment quota")
        return {
            "verified": True,
            "entries": len(session.summaries()),
            "deleted_entries": len(session.trash_summaries()),
            "attachments": len(records),
        }
    except BackupError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize catalog/sidecar failures
        from .attachments import AttachmentError
        # Attachment/vault errors carry fixed, secret-free messages; surface
        # them so a failed check names the actual problem.
        detail = f": {exc}" if isinstance(exc, (AttachmentError, VaultError)) else f" ({type(exc).__name__})"
        raise BackupError(f"Backup catalog or attachment sidecar validation failed{detail}") from exc
    finally:
        session.lock()


def _full_sanitize_staged_vault(staged_vault: Path, vault_password: SecretText, *, destination_vault: Path,
                                allow_rollback: bool) -> None:
    """Apply the restore rollback check and sanitising to the staged copy before publication."""
    from .vault import unlock_vault

    try:
        session = unlock_vault(staged_vault, vault_password)
    except Exception as exc:  # noqa: BLE001 - do not leak vault parser details
        raise BackupError("Backup vault could not be unlocked with the supplied master password") from exc
    try:
        # Raises RollbackRequiresConfirmation before anything is written.
        _check_restore_rollback(session, destination_vault, allow_rollback=allow_rollback)
        with session.transaction():
            _sanitize_restored_session(session)
            session.set_hello_binding(None)
            session.set_face_binding(None)
    finally:
        session.lock()


def _full_profile_nonempty(path: Path) -> bool:
    if not path.exists():
        return False
    if path.is_symlink() or not path.is_dir():
        return True
    try:
        return any(path.iterdir())
    except OSError:
        return True


def _full_existing(path: Path) -> bool:
    return path.is_symlink() or path.exists()


def _full_make_pre_restore_backup(
    *,
    destination_root: Path,
    vault_file: Path,
    settings_file: Path | None,
    attachment_dir: Path,
    backup_password: str,
) -> Path:
    if not _full_existing(vault_file):
        raise BackupError("Replacement requires an existing vault to back up first")
    backup_dir = destination_root / "Backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    candidate = backup_dir / f"before-restore-{time.time_ns()}-{os.getpid()}.lgk"
    export_full_backup(
        candidate,
        vault_file=vault_file,
        settings_file=settings_file,
        attachment_store_dir=attachment_dir,
        profile_name=destination_root.name or "Previous profile",
        backup_password=backup_password,
    )
    return candidate


def _full_publish(
    stage_root: Path,
    *,
    profile_dir: Path | None,
    vault_file: Path,
    settings_file: Path | None,
    attachment_dir: Path,
    anchor: Path,
    replace: bool,
) -> None:
    targets: list[tuple[Path, Path, bool]] = [
        (stage_root / vault_file.name, vault_file, True),
        (stage_root / attachment_dir.name, attachment_dir, True),
    ]
    if settings_file is not None:
        targets.append((stage_root / settings_file.name, settings_file, True))
    stage_anchor = stage_root / anchor.name
    if stage_anchor.exists() or replace:
        targets.append((stage_anchor, anchor, stage_anchor.exists()))
    rollback_parent = vault_file.parent if vault_file.parent.exists() else stage_root.parent
    rollback_dir = _full_temp_dir(rollback_parent, ".lgk-full-rollback-")
    moved_old: list[tuple[Path, Path]] = []
    moved_new: list[Path] = []
    created_parents: list[Path] = []
    try:
        for index, (_stage, target, _required) in enumerate(targets):
            if _full_existing(target):
                if not replace:
                    raise BackupError("Destination already contains a profile component")
                old = rollback_dir / f"{index}-{target.name}"
                os.replace(target, old)
                moved_old.append((old, target))
        for stage, target, required in targets:
            if not stage.exists():
                if required:
                    raise BackupError("Full backup staging data is incomplete")
                continue
            if not target.parent.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                created_parents.append(target.parent)
            os.replace(stage, target)
            moved_new.append(target)
    except BaseException as exc:
        for target in reversed(moved_new):
            try:
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                else:
                    target.unlink(missing_ok=True)
            except OSError:
                pass
        for old, target in reversed(moved_old):
            try:
                os.replace(old, target)
            except OSError:
                pass
        if isinstance(exc, BackupError):
            raise
        raise BackupError("Could not publish restored profile") from exc
    finally:
        shutil.rmtree(rollback_dir, ignore_errors=True)
        for parent in reversed(created_parents):
            try:
                parent.rmdir()
            except OSError:
                pass


def restore_full_backup(source: Path, **kwargs: Any) -> dict[str, Any]:
    """Preflight and atomically restore a complete v2 profile (see ``_restore_full_backup``).

    ``vault_password`` may be a ``str`` or a ``SecretText``; it is converted once here and the
    same buffer is used for every unlock.  A ``str`` copy is wiped before return, a ``SecretText``
    stays the caller's.
    """
    vault_password = kwargs.pop("vault_password", None)
    if vault_password is None:
        return _restore_full_backup(source, vault_password=None, **kwargs)
    secret, owned = _vault_secret(vault_password,
                                  "Backup vault could not be unlocked with the supplied master password")
    try:
        return _restore_full_backup(source, vault_password=secret, **kwargs)
    finally:
        if owned:
            secret.wipe()


def _restore_full_backup(
    source: Path,
    *,
    profile_dir: Path | None = None,
    vault_file: Path | None = None,
    settings_file: Path | None = None,
    attachment_store_dir: Path | None = None,
    attachment_store: Path | None = None,
    backup_password: str,
    vault_password: SecretText | None = None,
    validate_vault_password: bool = False,
    validate_master_password: bool = False,
    replace: bool = False,
    allow_rollback: bool = False,
    dry_run: bool = False,
    attachment_quota_bytes: int = 1024 * 1024 * 1024,
    cancel: Callable[[], bool] | Any | None = None,
    progress: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Preflight and atomically restore a complete v2 profile.

    ``vault_password`` is already a ``SecretText`` here; the caller owns it.

    The only temporary files are encrypted vault JSON and already encrypted
    attachment sidecars.  Settings stay in memory until the destination commit.

    Like ``restore_verified_backup``, the restored profile has autostart,
    external requests and automatic sign-in switched off, and (when the vault
    master password is supplied) every credential's automatic sign-in and
    desktop-fill approval and the Windows Hello / camera bindings revoked.
    Replacing an existing vault requires the master password, and replacing
    one that is newer than the backup (or belongs to another key lineage)
    raises ``RollbackRequiresConfirmation`` before anything is written unless
    ``allow_rollback`` is set.
    """
    if (validate_vault_password or validate_master_password) and vault_password is None:
        raise BackupError("A vault master password is required for requested validation")
    root, vault_file, settings_file, attachment_dir, anchor = _full_resolve_paths(
        profile_dir=profile_dir,
        vault_file=vault_file,
        settings_file=settings_file,
        attachment_store_dir=attachment_store_dir,
        attachment_store=attachment_store,
    )
    if profile_dir is not None and _full_existing(root) and not replace and _full_profile_nonempty(root):
        raise BackupError("Destination profile already exists")
    if not replace:
        for target in (vault_file, settings_file, attachment_dir, anchor):
            if target is not None and _full_existing(target):
                raise BackupError("Destination already contains a profile component")
    elif not dry_run and vault_password is None and (_full_existing(vault_file) or _full_existing(anchor)):
        raise BackupError("Replacing an existing vault requires the backup's vault master password")
    # Stage beside the source until every authenticated member and the vault
    # have passed validation.  This keeps dry-run and failed restores from
    # creating destination directories as a side effect.
    stage_root = _full_temp_dir(Path(source).parent, ".lgk-full-restore-")
    stage_attachment_dir = stage_root / attachment_dir.name
    stage_attachment_dir.mkdir(parents=True, exist_ok=True)
    settings_holder: dict[str, Any] = {}
    counts = {"attachments": 0, "attachment_bytes": 0}

    def on_entry(entry: dict[str, Any], data: bytes) -> None:
        kind = entry["kind"]
        if kind == "vault":
            _full_atomic_bytes(stage_root / vault_file.name, data)
        elif kind == "settings":
            if len(data) > MAX_FULL_BACKUP_SETTINGS_BYTES:
                raise BackupError("Restored settings are too large")
            settings_holder["value"] = _full_validate_settings(_full_validate_json_object(data, "Restored settings"))
        elif kind == "generation":
            _full_validate_generation(data)
            _full_atomic_bytes(stage_root / anchor.name, data)
        elif kind == "attachment":
            attachment_id = entry["attachment_id"]
            parsed = _full_validate_sidecar_header(data, expected_id=attachment_id)
            if parsed["size"] != entry["sidecar_size"]:
                raise BackupError("Attachment sidecar metadata does not match its manifest")
            if counts["attachment_bytes"] + len(data) > int(attachment_quota_bytes) + 64 * 1024 * max(1, counts["attachments"] + 1):
                raise BackupError("Restored attachments exceed the attachment quota")
            _full_atomic_bytes(stage_attachment_dir / f"{attachment_id}.blob", data)
            counts["attachments"] += 1
            counts["attachment_bytes"] += parsed["size"]
        else:
            raise BackupError("Unsupported full backup entry")

    pre_restore_backup: Path | None = None
    pre_restore_backup_dir = root / "Backups"
    pre_restore_backup_dir_existed = _full_existing(pre_restore_backup_dir)
    published = False
    try:
        container_info = _full_read_container(
            source,
            backup_password,
            on_entry=on_entry,
            cancel=cancel,
            progress=progress,
        )
        if not settings_holder or not (stage_root / vault_file.name).exists():
            raise BackupError("Full backup is missing required profile data")
        validation = _full_validate_staged_vault(
            stage_root / vault_file.name,
            stage_attachment_dir,
            vault_password=vault_password,
            attachment_quota_bytes=int(attachment_quota_bytes),
        )
        # Quota is measured against the real sidecar ciphertext store as the
        # attachment service does, not only against plaintext record sizes.
        if sum(path.stat().st_size for path in stage_attachment_dir.glob("*.blob")) > int(attachment_quota_bytes):
            raise BackupError("Restored attachments exceed the attachment quota")
        info = {
            "version": FULL_BACKUP_VERSION,
            "profile_name": container_info["manifest"]["profile_name"],
            "entries": len(container_info["entries"]),
            "attachments": counts["attachments"],
            "attachment_bytes": counts["attachment_bytes"],
            "verified_vault": bool(validation.get("verified")),
            "dry_run": bool(dry_run),
        }
        if validation.get("entries") is not None:
            info.update({"vault_entries": validation["entries"], "deleted_entries": validation["deleted_entries"]})
        if dry_run:
            return info
        _full_cancelled(cancel)
        _sanitize_restored_settings(settings_holder["value"])
        if vault_password is not None:
            _full_sanitize_staged_vault(stage_root / vault_file.name, vault_password,
                                        destination_vault=vault_file, allow_rollback=allow_rollback)
        _full_cancelled(cancel)
        # The destination parent is created by _full_publish only when the
        # final commit starts, and its rollback cleanup removes an empty one
        # if publication fails.
        if replace and (_full_existing(vault_file) or (profile_dir is not None and _full_profile_nonempty(root))):
            pre_restore_backup = _full_make_pre_restore_backup(
                destination_root=root,
                vault_file=vault_file,
                settings_file=settings_file,
                attachment_dir=attachment_dir,
                backup_password=backup_password,
            )
        if settings_file is not None:
            _full_atomic_bytes(stage_root / settings_file.name, _full_canonical(settings_holder["value"]))
        _full_publish(
            stage_root,
            profile_dir=profile_dir,
            vault_file=vault_file,
            settings_file=settings_file,
            attachment_dir=attachment_dir,
            anchor=anchor,
            replace=replace,
        )
        published = True
        return info
    except BackupError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise BackupError("Full backup restore failed") from exc
    finally:
        if not published:
            if pre_restore_backup is not None:
                pre_restore_backup.unlink(missing_ok=True)
            if not pre_restore_backup_dir_existed and pre_restore_backup_dir.is_dir():
                try:
                    next(pre_restore_backup_dir.iterdir())
                except StopIteration:
                    pre_restore_backup_dir.rmdir()
                except OSError:
                    pass
        shutil.rmtree(stage_root, ignore_errors=True)


def preflight_full_backup(source: Path, **kwargs: Any) -> dict[str, Any]:
    """Run full-backup restore validation without touching the destination."""
    kwargs["dry_run"] = True
    return restore_full_backup(source, **kwargs)


# Explicit aliases make the v2 API discoverable while retaining the shorter
# names used by early M3 callers.
export_encrypted_full_backup = export_full_backup
restore_encrypted_full_backup = restore_full_backup
verify_full_backup = preflight_full_backup
