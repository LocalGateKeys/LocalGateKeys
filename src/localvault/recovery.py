"""Offline recovery workflow built on the authenticated full-backup v2 API.

This module is intentionally an orchestration boundary.  :mod:`localvault.backup`
owns the encrypted container format, bounds, authentication, staging, and
atomic profile publication.  The recovery layer adds the user-facing contract:
preview before restore, independent passwords, checksum inventories, safe
restore-as-new-profile, and non-secret recovery-kit material.

No function in this module performs discovery, opens a browser, contacts a
network, or writes to a profile until the caller explicitly confirms a restore.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .backup import (
    FULL_BACKUP_FORMAT,
    FULL_BACKUP_VERSION,
    BackupCancelled,
    BackupError,
    export_full_backup,
    preflight_full_backup,
    restore_full_backup,
)
from .config import atomic_write_json
from .secret_text import SecretText, secrets_match
from .session_guard import StaleSession
from .version import APP_VERSION
from .i18n import t

RECOVERY_KIT_FORMAT = "localgatekeys-recovery-kit"
RECOVERY_KIT_VERSION = 1
CHECKSUM_MANIFEST_FORMAT = "localgatekeys-sha256-manifest"
CHECKSUM_MANIFEST_VERSION = 1
CHECKSUM_SUFFIX = ".sha256.json"
DEFAULT_ROTATION_COUNT = 3
_HASH_CHUNK = 1024 * 1024


class RecoveryError(BackupError):
    """A recovery request was rejected without changing live profile state."""


class RecoveryCancelled(RecoveryError):
    """A user-cancelled recovery operation did not publish partial state."""


def _local_path(value: Path | str, *, label: str) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise RecoveryError(t("recovery.mustBeALocalPath", label=label)) from exc
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise RecoveryError(t("recovery.mustBeALocalPath", label=label))
    if raw.startswith(("\\\\", "//")) or "://" in raw:
        raise RecoveryError(t("recovery.mustBeALocalNon", label=label))
    try:
        return Path(raw).expanduser().absolute()
    except (OSError, RuntimeError, ValueError) as exc:
        raise RecoveryError(t("recovery.isNotAUsableLocal", label=label)) from exc


def _existing_parent(path: Path) -> Path:
    candidate = path.parent
    while not candidate.exists():
        if candidate == candidate.parent:
            raise RecoveryError(t("recovery.couldNotFindALocal"))
        candidate = candidate.parent
    if candidate.is_symlink() or not candidate.is_dir():
        raise RecoveryError(t("recovery.recoveryDestinationMustUseA"))
    return candidate


def _regular_source(value: Path | str, *, label: str) -> Path:
    path = _local_path(value, label=label)
    if path.is_symlink() or not path.is_file():
        raise RecoveryError(t("recovery.mustBeARegularNon", label=label))
    return path


def _destination_file(value: Path | str, *, label: str, overwrite: bool = False) -> Path:
    path = _local_path(value, label=label)
    _existing_parent(path)
    if path.exists() and (path.is_symlink() or path.is_dir()):
        raise RecoveryError(t("recovery.mustBeARegularFile", label=label))
    if path.exists() and not overwrite:
        raise RecoveryError(t("recovery.alreadyExistsChooseANew", label=label))
    return path


def _destination_profile(value: Path | str) -> Path:
    path = _local_path(value, label=t("recovery.restoreDestination"))
    if path.name in {"", ".", ".."}:
        raise RecoveryError(t("recovery.restoreDestinationMustNameA"))
    _existing_parent(path)
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise RecoveryError(t("recovery.restoreDestinationMustBeA"))
        try:
            if any(path.iterdir()):
                raise RecoveryError(t("recovery.restoreDestinationAlreadyExistsAnd"))
        except OSError as exc:
            raise RecoveryError(t("recovery.couldNotInspectTheRestore")) from exc
        raise RecoveryError(t("recoveryCenter.restoreDestinationMustNotAlready"))
    return path


def _password(value: str | SecretText, *, label: str) -> str | SecretText:
    """A backup or vault master password, as ``str`` or the caller's ``SecretText`` (never converted to ``str``)."""
    count = value.char_count if isinstance(value, SecretText) else len(value) if isinstance(value, str) else -1
    if not 12 <= count <= 4096:
        raise RecoveryError(t("recovery.mustContainAtLeast12", label=label))
    return value


def _independent_passwords(backup_password: str | SecretText, vault_password: str | SecretText | None = None) -> None:
    if vault_password is not None and secrets_match(backup_password, vault_password):
        raise RecoveryError(t("recovery.useAnIndependentBackupPassword"))


def sha256_file(path: Path | str) -> str:
    """Return a bounded-stream SHA-256 digest for a local regular file."""
    source = _regular_source(path, label=t("recovery.checksumSource"))
    digest = hashlib.sha256()
    try:
        with source.open("rb") as handle:
            while True:
                chunk = handle.read(_HASH_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise RecoveryError(t("recovery.couldNotCalculateTheRecovery")) from exc
    return digest.hexdigest()


def _same_disk(first: Path, second: Path) -> bool:
    try:
        first_drive = os.path.splitdrive(str(first.absolute()))[0].casefold()
        second_drive = os.path.splitdrive(str(second.absolute()))[0].casefold()
        if first_drive or second_drive:
            return first_drive == second_drive
        return first.stat().st_dev == second.stat().st_dev
    except OSError:
        return False


def check_disk_space(path: Path | str, *, required_bytes: int = 0, reserve_bytes: int = 0) -> dict[str, int | str]:
    """Check local free space without creating a destination or profile."""
    if type(required_bytes) is not int or required_bytes < 0:
        raise RecoveryError(t("recovery.requiredDiskSpaceMustBe"))
    if type(reserve_bytes) is not int or reserve_bytes < 0:
        raise RecoveryError(t("recovery.reservedDiskSpaceMustBe"))
    target = _local_path(path, label=t("recovery.diskSpacePath"))
    parent = _existing_parent(target if target.exists() and target.is_dir() else target)
    try:
        usage = shutil.disk_usage(parent)
    except OSError as exc:
        raise RecoveryError(t("recovery.couldNotInspectFreeSpace")) from exc
    needed = required_bytes + reserve_bytes
    if usage.free < needed:
        raise RecoveryError(t("recovery.theSelectedRecoveryDestinationDoes"))
    return {
        "path": str(parent),
        "free_bytes": int(usage.free),
        "required_bytes": int(needed),
        "sufficient": True,
    }


def _manifest_path(backup: Path) -> Path:
    return backup.with_name(backup.name + CHECKSUM_SUFFIX)


def _manifest_payload(backup: Path, *, inventory: Mapping[str, Any] | None = None) -> dict[str, Any]:
    stat = backup.stat()
    payload: dict[str, Any] = {
        "format": CHECKSUM_MANIFEST_FORMAT,
        "version": CHECKSUM_MANIFEST_VERSION,
        "algorithm": "sha256",
        "generated_at": int(time.time()),
        "backup": {
            "name": backup.name,
            "size": int(stat.st_size),
            "sha256": sha256_file(backup),
        },
    }
    if inventory is not None:
        safe = _safe_inventory(inventory)
        safe.pop("backup_sha256", None)
        safe.pop("backup_bytes", None)
        payload["inventory"] = safe
    return payload


def _validate_digest(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdefABCDEF" for char in value):
        raise RecoveryError(t("recovery.recoveryChecksumIsMalformed"))
    return value.lower()


def verify_sha256_manifest(
    backup: Path | str,
    manifest: Path | str | None = None,
) -> dict[str, Any]:
    """Verify a sidecar checksum manifest without decrypting the backup."""
    source = _regular_source(backup, label="Backup")
    manifest_path = _regular_source(manifest or _manifest_path(source), label=t("recovery.checksumManifest"))
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RecoveryError(t("recovery.theRecoveryChecksumManifestIs")) from exc
    if not isinstance(raw, dict) or raw.get("format") != CHECKSUM_MANIFEST_FORMAT or raw.get("version") != CHECKSUM_MANIFEST_VERSION:
        raise RecoveryError(t("recovery.unsupportedRecoveryChecksumManifest"))
    record = raw.get("backup")
    if not isinstance(record, dict) or record.get("name") != source.name:
        raise RecoveryError(t("recovery.recoveryChecksumManifestDoesNot"))
    try:
        expected_size = int(record["size"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RecoveryError(t("recovery.recoveryChecksumManifestIsMalformed")) from exc
    if expected_size != source.stat().st_size:
        raise RecoveryError(t("recovery.theRecoveryBackupChecksumManifest"))
    expected_digest = _validate_digest(record.get("sha256"))
    actual_digest = sha256_file(source)
    if actual_digest != expected_digest:
        raise RecoveryError(t("recovery.theRecoveryBackupChecksumDoes"))
    return {
        "verified": True,
        "backup": source.name,
        "size": expected_size,
        "sha256": actual_digest,
        "manifest": str(manifest_path),
    }


@dataclass(frozen=True)
class BackupInventory:
    """Safe metadata suitable for a Recovery Center or recovery kit."""

    version: int
    path: str
    profile_name: str | None
    entries: int
    attachment_count: int
    attachment_bytes: int
    backup_bytes: int
    backup_sha256: str
    created_at: int
    verified: bool = False
    verified_at: int | None = None
    same_disk: bool = False
    warnings: tuple[str, ...] = ()
    manifest_path: str | None = None
    # Whether the backed-up vault had a recovery phrase enrolled.  The phrase
    # itself is never part of any backup, manifest, inventory or kit.
    recovery_phrase_enrolled: bool | None = None

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["warnings"] = list(self.warnings)
        return result

    to_dict = as_dict


def _safe_inventory(value: BackupInventory | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(value, BackupInventory):
        result = value.as_dict()
    elif isinstance(value, Mapping):
        allowed = {
            "version", "path", "profile_name", "entries", "attachment_count", "attachment_bytes",
            "backup_bytes", "backup_sha256", "created_at", "verified", "verified_at", "same_disk",
            "warnings", "manifest_path", "recovery_phrase_enrolled",
        }
        result = {key: value[key] for key in allowed if key in value}
    else:
        raise RecoveryError(t("recovery.backupInventoryIsMalformed"))
    if result.get("recovery_phrase_enrolled") is not None and not isinstance(result["recovery_phrase_enrolled"], bool):
        raise RecoveryError(t("recovery.backupInventoryRecoveryPhraseFlag"))
    if "backup_sha256" in result:
        result["backup_sha256"] = _validate_digest(result["backup_sha256"])
    if "warnings" in result:
        warnings = result["warnings"]
        if not isinstance(warnings, (list, tuple)) or not all(isinstance(item, str) for item in warnings):
            raise RecoveryError(t("recovery.backupInventoryWarningsAreMalformed"))
        result["warnings"] = list(warnings)
    return result


def _inventory_from_info(
    backup: Path,
    info: Mapping[str, Any],
    *,
    source_root: Path | None = None,
    verified: bool = False,
    verified_at: int | None = None,
    manifest_path: Path | None = None,
) -> BackupInventory:
    warnings: list[str] = []
    same_disk = bool(source_root and _same_disk(source_root, backup.parent))
    if same_disk:
        warnings.append(t("recovery.theBackupDestinationAppearsTo"))
    return BackupInventory(
        version=int(info.get("version", FULL_BACKUP_VERSION)),
        path=str(backup),
        profile_name=str(info.get("profile_name")) if info.get("profile_name") is not None else None,
        entries=int(info.get("entries", 0)),
        attachment_count=int(info.get("attachments", 0)),
        attachment_bytes=int(info.get("attachment_bytes", 0)),
        backup_bytes=int(backup.stat().st_size),
        backup_sha256=sha256_file(backup),
        created_at=int(backup.stat().st_mtime),
        verified=verified,
        verified_at=verified_at,
        same_disk=same_disk,
        warnings=tuple(warnings),
        manifest_path=str(manifest_path) if manifest_path is not None else None,
        recovery_phrase_enrolled=(bool(info["recovery_phrase_enrolled"])
                                  if isinstance(info.get("recovery_phrase_enrolled"), bool) else None),
    )


def _preflight(
    source: Path,
    *,
    backup_password: str | SecretText,
    vault_password: str | None = None,
    attachment_quota_bytes: int = 1024 * 1024 * 1024,
    cancel: Any = None,
    progress: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    # The backup API needs a profile-shaped destination even for dry-run. It
    # removes its own staging directory and never creates this probe path.
    # Use best-effort manual cleanup because some Windows workspaces have
    # restrictive inherited ACLs that make TemporaryDirectory.__exit__ fail
    # after an otherwise successful read-only preflight.
    directory = Path(tempfile.mkdtemp(prefix=".lgk-recovery-probe-", dir=str(source.parent)))
    try:
        probe = directory / "profile"
        return preflight_full_backup(
            source,
            profile_dir=probe,
            backup_password=backup_password,
            vault_password=vault_password,
            validate_vault_password=vault_password is not None,
            validate_master_password=vault_password is not None,
            attachment_quota_bytes=attachment_quota_bytes,
            cancel=cancel,
            progress=progress,
        )
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def create_recovery_backup(
    destination: Path | str,
    *,
    profile_dir: Path | None = None,
    vault_file: Path | None = None,
    settings_file: Path | None = None,
    attachment_store_dir: Path | None = None,
    profile_name: str | None = None,
    backup_password: str | SecretText,
    backup_password_confirmation: str | None = None,
    confirm_backup_password: str | None = None,
    vault_password: str | None = None,
    master_password: str | None = None,
    manifest_path: Path | str | None = None,
    overwrite: bool = False,
    cancel: Any = None,
    progress: Callable[..., Any] | None = None,
    reserve_bytes: int = 0,
) -> dict[str, Any]:
    """Create and immediately authenticate a full encrypted v2 recovery backup."""
    backup_password = _password(backup_password, label=t("backupPasswordSheet.title"))
    confirmation = backup_password_confirmation if backup_password_confirmation is not None else confirm_backup_password
    if confirmation is not None and not secrets_match(confirmation, backup_password):
        raise RecoveryError(t("recovery.theBackupPasswordConfirmationDid"))
    if master_password is not None:
        vault_password = master_password if vault_password is None else vault_password
    if vault_password is not None:
        _password(vault_password, label=t("recovery.vaultMasterPassword"))
    _independent_passwords(backup_password, vault_password)
    destination_path = _destination_file(destination, label=t("recovery.recoveryBackupDestination"), overwrite=overwrite)
    source_root = _local_path(profile_dir or (Path(vault_file).parent if vault_file is not None else destination_path.parent), label=t("recovery.profileSource"))
    if source_root == destination_path.parent:
        # This is allowed, but the Recovery Center must make the weak
        # availability property visible to the user.
        pass
    source_vault = Path(vault_file) if vault_file is not None else source_root / "vault.json"
    try:
        estimated = source_vault.stat().st_size + 1024 * 1024
    except OSError:
        estimated = 0
    disk = check_disk_space(destination_path, required_bytes=estimated, reserve_bytes=reserve_bytes)
    sidecar = _destination_file(
        manifest_path or _manifest_path(destination_path),
        label=t("recovery.checksumManifestDestination"),
        overwrite=True,
    )
    if sidecar == destination_path:
        raise RecoveryError(t("recovery.checksumManifestDestinationMustBe"))
    # Keep any existing good backup in place until the new archive has passed
    # authenticated preflight. export_full_backup publishes atomically to its
    # destination, so target a sibling staging file rather than the user's
    # selected path.
    descriptor, staging_name = tempfile.mkstemp(
        prefix=f".{destination_path.name}.", suffix=".staging", dir=str(destination_path.parent),
    )
    os.close(descriptor)
    staging_path = Path(staging_name)
    try:
        info = export_full_backup(
            staging_path,
            profile_dir=profile_dir,
            vault_file=vault_file,
            settings_file=settings_file,
            attachment_store_dir=attachment_store_dir,
            profile_name=profile_name,
            backup_password=backup_password,
            cancel=cancel,
            progress=progress,
        )
        # Authenticate every encrypted member before reporting success.  If a
        # master password was supplied, validate that layer too.
        checked = _preflight(
            staging_path,
            backup_password=backup_password,
            vault_password=vault_password,
            cancel=cancel,
            progress=progress,
        )
        from .vault import recovery_phrase_enrolled
        inventory = _inventory_from_info(
            staging_path,
            {**info, **checked, "recovery_phrase_enrolled": recovery_phrase_enrolled(source_vault)},
            source_root=source_root,
        )
        # Report the selected final path even though the verified artifact is
        # still staged while its inventory is assembled.
        inventory = BackupInventory(**{
            **inventory.as_dict(),
            "path": str(destination_path),
            "manifest_path": str(sidecar),
            "warnings": tuple(inventory.warnings),
        })
        os.replace(staging_path, destination_path)
        atomic_write_json(sidecar, _manifest_payload(destination_path, inventory=inventory.as_dict()))
        result = inventory.as_dict()
        result.update({
            "operation": "create", "committed": True, "disk": disk, "manifest": str(sidecar),
            "attachments": inventory.attachment_count, "sha256": inventory.backup_sha256,
        })
        return result
    except BackupCancelled as exc:
        raise RecoveryCancelled(str(exc)) from exc
    except RecoveryError:
        raise
    except BackupError as exc:
        raise RecoveryError(str(exc)) from exc
    except (OSError, ValueError, TypeError) as exc:
        raise RecoveryError(t("recovery.couldNotCreateTheRecovery")) from exc
    finally:
        staging_path.unlink(missing_ok=True)


def inspect_recovery_backup(
    source: Path | str,
    *,
    backup_password: str | SecretText,
    vault_password: str | None = None,
    manifest_path: Path | str | None = None,
    attachment_quota_bytes: int = 1024 * 1024 * 1024,
    cancel: Any = None,
    progress: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Return safe inventory metadata after authenticating the v2 container."""
    backup = _regular_source(source, label=t("recovery.recoveryBackup"))
    backup_password = _password(backup_password, label=t("backupPasswordSheet.title"))
    if vault_password is not None:
        _password(vault_password, label=t("recovery.vaultMasterPassword"))
    _independent_passwords(backup_password, vault_password)
    chosen_manifest = _manifest_path(backup) if manifest_path is None and _manifest_path(backup).exists() else manifest_path
    if chosen_manifest is not None:
        verify_sha256_manifest(backup, chosen_manifest)
    try:
        info = _preflight(
            backup,
            backup_password=backup_password,
            vault_password=vault_password,
            attachment_quota_bytes=attachment_quota_bytes,
            cancel=cancel,
            progress=progress,
        )
    except BackupCancelled as exc:
        raise RecoveryCancelled(str(exc)) from exc
    except BackupError as exc:
        raise RecoveryError(str(exc)) from exc
    inventory = _inventory_from_info(
        backup,
        info,
        verified=vault_password is not None and bool(info.get("verified_vault")),
        verified_at=int(time.time()) if vault_password is not None else None,
        manifest_path=Path(chosen_manifest) if chosen_manifest is not None else None,
    )
    result = inventory.as_dict()
    result.update({
        "operation": "inspect", "verified": inventory.verified, "dry_run": True,
        "attachments": inventory.attachment_count, "sha256": inventory.backup_sha256,
    })
    return result


def verify_recovery_backup(
    source: Path | str,
    *,
    backup_password: str | SecretText,
    vault_password: str | SecretText,
    expected_sha256: str | None = None,
    manifest_path: Path | str | None = None,
    attachment_quota_bytes: int = 1024 * 1024 * 1024,
    cancel: Any = None,
    progress: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Verify checksum, backup password, vault master password, and sidecars.

    Only temporary encrypted staging data is used; the live profile is not
    opened, rewritten, or replaced.
    """
    backup = _regular_source(source, label=t("recovery.recoveryBackup"))
    backup_password = _password(backup_password, label=t("backupPasswordSheet.title"))
    vault_password = _password(vault_password, label=t("recovery.vaultMasterPassword"))
    _independent_passwords(backup_password, vault_password)
    if expected_sha256 is not None:
        expected = _validate_digest(expected_sha256)
        actual = sha256_file(backup)
        if actual != expected:
            raise RecoveryError(t("recovery.theRecoveryBackupSha256"))
    result = inspect_recovery_backup(
        backup,
        backup_password=backup_password,
        vault_password=vault_password,
        manifest_path=manifest_path,
        attachment_quota_bytes=attachment_quota_bytes,
        cancel=cancel,
        progress=progress,
    )
    result.update({"operation": "verify", "verified": True, "verified_at": int(time.time()), "dry_run": True})
    return result


def plan_restore_as_new_profile(
    source: Path | str,
    destination: Path | str,
    *,
    backup_password: str | SecretText,
    vault_password: str | SecretText,
    expected_sha256: str | None = None,
    manifest_path: Path | str | None = None,
    attachment_quota_bytes: int = 1024 * 1024 * 1024,
    cancel: Any = None,
    progress: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Authenticate and stage a restore preview without touching destination."""
    backup = _regular_source(source, label=t("recovery.recoveryBackup"))
    destination_path = _destination_profile(destination)
    backup_password = _password(backup_password, label=t("backupPasswordSheet.title"))
    vault_password = _password(vault_password, label=t("recovery.vaultMasterPassword"))
    _independent_passwords(backup_password, vault_password)
    backup_sha256 = sha256_file(backup)
    if expected_sha256 is not None and backup_sha256 != _validate_digest(expected_sha256):
        raise RecoveryError(t("recovery.theRecoveryBackupSha256"))
    chosen_manifest = manifest_path
    if chosen_manifest is None and _manifest_path(backup).exists():
        chosen_manifest = _manifest_path(backup)
    if chosen_manifest is not None:
        verify_sha256_manifest(backup, chosen_manifest)
    try:
        estimated = backup.stat().st_size * 2 + 1024 * 1024
        disk = check_disk_space(destination_path, required_bytes=estimated)
        info = _preflight(
            backup,
            backup_password=backup_password,
            vault_password=vault_password,
            attachment_quota_bytes=attachment_quota_bytes,
            cancel=cancel,
            progress=progress,
        )
    except BackupCancelled as exc:
        raise RecoveryCancelled(str(exc)) from exc
    except BackupError as exc:
        raise RecoveryError(str(exc)) from exc
    warnings = [
        t("recovery.restoreCreatesANewProfile"),
        t("recovery.automaticSignInExternalChecks"),
    ]
    return {
        "operation": "restore",
        "source": str(backup),
        "destination": str(destination_path),
        "backup_sha256": backup_sha256,
        "backup_bytes": int(backup.stat().st_size),
        "format": FULL_BACKUP_FORMAT,
        "version": FULL_BACKUP_VERSION,
        "profile_name": info.get("profile_name"),
        "entries": int(info.get("entries", 0)),
        "attachments": int(info.get("attachments", 0)),
        "attachment_bytes": int(info.get("attachment_bytes", 0)),
        "verified_vault": bool(info.get("verified_vault")),
        "dry_run": True,
        "requires_confirmation": True,
        "committed": False,
        "safety": {
            "automatic_sign_in_disabled": True,
            "external_checks_disabled": True,
            "trust_bindings_disabled": True,
            "overwrites_existing": False,
        },
        "warnings": warnings,
        "disk": disk,
    }


def _sanitize_restored_profile(profile: Path, vault_password: str | SecretText) -> None:
    """Disable machine-specific release/trust state in an isolated restored copy."""
    from .access_policy import normalized_policy
    from .settings import AppSettings
    from .vault import unlock_vault

    settings_path = profile / "settings.json"
    settings = AppSettings.load(settings_path)
    settings.start_with_windows = False
    settings.fill_and_sign_in = False
    settings.breach_check_enabled = False
    settings.strict_offline_mode = True
    settings.save(settings_path)

    session = unlock_vault(profile / "vault.json", vault_password)
    try:
        with session.transaction():
            session.set_fill_and_sign_in_enabled(False)
            session.set_hello_binding(None)
            session.set_face_binding(None)
            for entry in session.all_entries():
                policy = normalized_policy(entry.get("policy"))
                policy["sign_in"] = "never"
                session.set_entry_extras(entry["id"], policy=policy)
                if entry.get("kind") == "desktop":
                    session.set_desktop_embedded_fill_approval(entry["id"], False)
    finally:
        session.lock()


def restore_as_new_profile(
    source: Path | str,
    destination: Path | str,
    *,
    backup_password: str | SecretText,
    vault_password: str | SecretText,
    confirm: bool = False,
    expected_sha256: str | None = None,
    manifest_path: Path | str | None = None,
    attachment_quota_bytes: int = 1024 * 1024 * 1024,
    cancel: Any = None,
    progress: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Return a preview unless ``confirm=True``; then publish a safe new profile."""
    plan = plan_restore_as_new_profile(
        source,
        destination,
        backup_password=backup_password,
        vault_password=vault_password,
        expected_sha256=expected_sha256,
        manifest_path=manifest_path,
        attachment_quota_bytes=attachment_quota_bytes,
        cancel=cancel,
        progress=progress,
    )
    if not confirm:
        return plan
    backup = Path(plan["source"])
    destination_path = Path(plan["destination"])
    parent = destination_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    # restore_full_backup owns creation of the profile root and rejects a
    # pre-existing non-empty destination, so reserve only a unique pathname.
    stage = parent / f".lgk-recovery-restore-{uuid.uuid4().hex}"
    published = False
    try:
        try:
            info = restore_full_backup(
                backup,
                profile_dir=stage,
                backup_password=_password(backup_password, label=t("backupPasswordSheet.title")),
                vault_password=_password(vault_password, label=t("recovery.vaultMasterPassword")),
                validate_vault_password=True,
                validate_master_password=True,
                replace=False,
                attachment_quota_bytes=attachment_quota_bytes,
                cancel=cancel,
                progress=progress,
            )
        except BackupCancelled as exc:
            raise RecoveryCancelled(str(exc)) from exc
        except BackupError as exc:
            raise RecoveryError(str(exc)) from exc
        _sanitize_restored_profile(stage, vault_password)
        if destination_path.exists():
            raise RecoveryError(t("recovery.restoreDestinationAppearedWhileThe"))
        os.rename(stage, destination_path)
        published = True
        result = dict(info)
        result.update({
            "operation": "restore",
            "source": str(backup),
            "destination": str(destination_path),
            "dry_run": False,
            "requires_confirmation": False,
            "committed": True,
            "safety": plan["safety"],
            "warnings": plan["warnings"],
        })
        return result
    except RecoveryError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize isolated restore failures
        # The stage is disposable, so parser/schema/sanitization failures must
        # never escape as a successful restore or expose implementation detail.
        raise RecoveryError(t("recovery.couldNotFinalizeTheRestored")) from exc
    finally:
        if not published:
            shutil.rmtree(stage, ignore_errors=True)


def _file_descriptor(value: Path | str | Mapping[str, Any] | None, *, label: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        result = {key: value[key] for key in ("name", "size", "sha256", "version") if key in value}
        if "sha256" in result:
            result["sha256"] = _validate_digest(result["sha256"])
        return result
    path = _regular_source(value, label=label)
    return {"name": path.name, "size": int(path.stat().st_size), "sha256": sha256_file(path)}


def _default_restore_guide() -> str:
    return (
        "Keep the encrypted backup and its checksum manifest on separate protected media. "
        "Install the matching LocalGateKeys package offline, verify the SHA-256 checksum, "
        "then use Verify recovery backup with both the independent backup password and the "
        "vault master password from backup time. Restore as a new profile first. "
        "Store both passwords separately from the backup media; losing the vault master "
        "password from backup time makes the encrypted backup unrecoverable. "
        "If the vault had a 24-word recovery phrase, that phrase can replace a forgotten master "
        "password for the restored vault only when the phrase is still in its sealed, "
        "separately stored record; the phrase is never written into a backup or this kit."
    )


def write_recovery_kit(
    destination: Path | str,
    *,
    backup: Path | str,
    inventory: BackupInventory | Mapping[str, Any] | None = None,
    manifest_path: Path | str | None = None,
    app_version: str = APP_VERSION,
    extension_package: Path | str | Mapping[str, Any] | None = None,
    installer_package: Path | str | Mapping[str, Any] | None = None,
    restore_guide: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Write a non-secret JSON recovery kit; passwords are never accepted or stored."""
    backup_path = _regular_source(backup, label=t("recovery.recoveryBackup"))
    destination_path = _destination_file(destination, label=t("recovery.recoveryKitDestination"), overwrite=overwrite)
    if not isinstance(app_version, str) or not app_version.strip() or len(app_version) > 80:
        raise RecoveryError(t("recovery.applicationVersionIsMalformed"))
    if restore_guide is not None and (not isinstance(restore_guide, str) or len(restore_guide) > 20_000):
        raise RecoveryError(t("recovery.recoveryGuideIsMalformed"))
    kit_inventory = _safe_inventory(inventory) if inventory is not None else {
        "version": FULL_BACKUP_VERSION,
        "path": backup_path.name,
        "backup_bytes": int(backup_path.stat().st_size),
        "backup_sha256": sha256_file(backup_path),
        "verified": False,
    }
    kit_manifest = manifest_path or (_manifest_path(backup_path) if _manifest_path(backup_path).exists() else None)
    files: list[dict[str, Any]] = [{
        "name": backup_path.name,
        "size": int(backup_path.stat().st_size),
        "sha256": sha256_file(backup_path),
        "role": "encrypted-full-backup-v2",
    }]
    if kit_manifest is not None:
        descriptor = _file_descriptor(kit_manifest, label=t("recovery.checksumManifest"))
        if descriptor is not None:
            descriptor["role"] = "sha256-manifest"
            files.append(descriptor)
    for value, label, role in (
        (extension_package, t("recovery.extensionPackage"), "browser-extension-package"),
        (installer_package, t("recovery.installerPackage"), "installer-package"),
    ):
        descriptor = _file_descriptor(value, label=label)
        if descriptor is not None:
            descriptor["role"] = role
            files.append(descriptor)
    payload = {
        "format": RECOVERY_KIT_FORMAT,
        "version": RECOVERY_KIT_VERSION,
        "generated_at": int(time.time()),
        "app_version": app_version,
        "restore_guide": restore_guide or _default_restore_guide(),
        "inventory": kit_inventory,
        "files": files,
        "safety": {
            "contains_passwords": False,
            "contains_recovery_phrase": False,
            "contains_vault_data": False,
            "restore_mode": "new-profile-only-by-default",
        },
    }
    try:
        atomic_write_json(destination_path, payload)
    except (OSError, TypeError, ValueError) as exc:
        raise RecoveryError(t("recovery.couldNotWriteTheRecovery")) from exc
    return {"operation": "recovery-kit", "path": str(destination_path), "files": files, "committed": True}


def plan_backup_rotation(directory: Path | str, *, keep: int = DEFAULT_ROTATION_COUNT) -> dict[str, Any]:
    """Return a non-mutating plan for retaining recent backups and orphan manifests."""
    root = _local_path(directory, label=t("recovery.backupDirectory"))
    if root.is_symlink() or not root.is_dir():
        raise RecoveryError(t("recovery.backupDirectoryMustBeA"))
    if type(keep) is not int or not 1 <= keep <= 100:
        raise RecoveryError(t("recovery.backupRotationCountMustBe"))
    backups = sorted((path for path in root.glob("*.lgk") if path.is_file() and not path.is_symlink()), key=lambda path: path.stat().st_mtime, reverse=True)
    retained = backups[:keep]
    remove = backups[keep:]
    backup_names = {path.name for path in backups}
    orphan_manifests = [
        path for path in root.glob(f"*{CHECKSUM_SUFFIX}")
        if path.is_file() and not path.is_symlink() and path.name[: -len(CHECKSUM_SUFFIX)] not in backup_names
    ]
    return {
        "operation": "rotate",
        "directory": str(root),
        "keep": keep,
        "retained": [path.name for path in retained],
        "remove": [path.name for path in remove],
        "orphan_manifests": [path.name for path in orphan_manifests],
        "requires_confirmation": bool(remove or orphan_manifests),
        "dry_run": True,
    }


def cleanup_recovery_artifacts(
    directory: Path | str,
    *,
    keep: int = DEFAULT_ROTATION_COUNT,
    confirm: bool = False,
) -> dict[str, Any]:
    plan = plan_backup_rotation(directory, keep=keep)
    if not confirm:
        return plan
    root = Path(plan["directory"])
    removed: list[str] = []
    for name in [*plan["remove"], *plan["orphan_manifests"]]:
        path = root / name
        if path.is_symlink() or not path.is_file():
            continue
        path.unlink()
        removed.append(name)
    return {**plan, "dry_run": False, "committed": True, "removed": removed, "requires_confirmation": False}


class RecoveryService:
    """Profile-scoped facade used by the Recovery Center and tests."""

    def __init__(self, profile_dir: Path | str, *, profile_name: str | None = None) -> None:
        self.profile_dir = _local_path(profile_dir, label=t("recovery.profileSource"))
        self.profile_name = profile_name or self.profile_dir.name
        self.last_backup: dict[str, Any] | None = None

    def create_backup(self, destination: Path | str, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("profile_dir", self.profile_dir)
        kwargs.setdefault("profile_name", self.profile_name)
        result = create_recovery_backup(destination, **kwargs)
        self.last_backup = result
        return result

    def inspect_backup(self, source: Path | str, **kwargs: Any) -> dict[str, Any]:
        return inspect_recovery_backup(source, **kwargs)

    def verify_backup(self, source: Path | str, **kwargs: Any) -> dict[str, Any]:
        result = verify_recovery_backup(source, **kwargs)
        self.last_backup = result
        return result

    def plan_restore(self, source: Path | str, destination: Path | str, **kwargs: Any) -> dict[str, Any]:
        return plan_restore_as_new_profile(source, destination, **kwargs)

    def restore(self, source: Path | str, destination: Path | str, **kwargs: Any) -> dict[str, Any]:
        return restore_as_new_profile(source, destination, **kwargs)

    def recovery_kit(self, destination: Path | str, *, backup: Path | str, **kwargs: Any) -> dict[str, Any]:
        return write_recovery_kit(destination, backup=backup, inventory=self.last_backup, **kwargs)

    def rotation_plan(self, directory: Path | str, *, keep: int = DEFAULT_ROTATION_COUNT) -> dict[str, Any]:
        return plan_backup_rotation(directory, keep=keep)


class RecoverySessionBinding:
    """Keep UI actions bound to one unlocked profile and optional lease."""

    def __init__(self, session: Any, *, lease: Any = None, guard: Any = None,
                 require_lease: Callable[[Any], Any] | None = None,
                 session_provider: Callable[[], Any] | None = None) -> None:
        if session is None:
            raise RecoveryError(t("recovery.anUnlockedVaultSessionIs"))
        self._session = session
        self._session_provider = session_provider
        self._guard = guard
        self._require_lease_callback = require_lease
        self.lease = lease if lease is not None else (guard.lease() if guard is not None and callable(getattr(guard, "lease", None)) else None)
        self._path = self._path_of(session)

    @staticmethod
    def _path_of(session: Any) -> str | None:
        value = getattr(session, "path", None)
        if value is None:
            return None
        return os.path.normcase(os.path.abspath(os.fspath(value)))

    def current(self) -> Any:
        current = self._session_provider() if self._session_provider is not None else self._session
        if current is not self._session or self._path_of(current) != self._path or not bool(getattr(current, "is_unlocked", False)):
            raise StaleSession(t("recovery.vaultIsLockedOrThe"))
        if self._guard is not None:
            if self.lease is None or not callable(getattr(self._guard, "require", None)):
                raise StaleSession(t("recovery.theRecoveryActionHasNo"))
            self._guard.require(self.lease)
        if self._require_lease_callback is not None:
            if self.lease is None:
                raise StaleSession(t("recovery.theRecoveryActionHasNo"))
            self._require_lease_callback(self.lease)
        return current


class RecoveryController:
    """Session-bound controller with preview/confirm semantics for the UI."""

    def __init__(self, session: Any, *, profile_name: str | None = None, lease: Any = None,
                 guard: Any = None, require_lease: Callable[[Any], Any] | None = None,
                 session_provider: Callable[[], Any] | None = None) -> None:
        self.binding = RecoverySessionBinding(session, lease=lease, guard=guard,
                                              require_lease=require_lease, session_provider=session_provider)
        profile_dir = Path(session.path).parent
        self.service = RecoveryService(profile_dir, profile_name=profile_name)

    def create_backup(self, destination: Path | str, **kwargs: Any) -> dict[str, Any]:
        self.binding.current()
        result = self.service.create_backup(destination, **kwargs)
        self.binding.current()
        return result

    def verify_backup(self, source: Path | str, **kwargs: Any) -> dict[str, Any]:
        # Verification is deliberately independent of the live session.  The
        # caller supplies the master password from backup time and the result
        # is safe to display without touching the active profile.
        return self.service.verify_backup(source, **kwargs)

    def plan_restore(self, source: Path | str, destination: Path | str, **kwargs: Any) -> dict[str, Any]:
        return self.service.plan_restore(source, destination, **kwargs)

    def restore(self, source: Path | str, destination: Path | str, **kwargs: Any) -> dict[str, Any]:
        if kwargs.get("confirm"):
            # Reject a stale/locked session before the core publishes any data.
            self.binding.current()
        result = self.service.restore(source, destination, **kwargs)
        if kwargs.get("confirm"):
            self.binding.current()
        return result


create_backup = create_recovery_backup
inspect_backup = inspect_recovery_backup
verify_backup = verify_recovery_backup
restore_backup_as_new_profile = restore_as_new_profile


__all__ = [
    "BackupInventory", "RecoveryCancelled", "RecoveryController", "RecoveryError",
    "RecoveryService", "RecoverySessionBinding", "CHECKSUM_MANIFEST_FORMAT",
    "CHECKSUM_MANIFEST_VERSION", "FULL_BACKUP_FORMAT", "FULL_BACKUP_VERSION",
    "check_disk_space", "cleanup_recovery_artifacts", "create_backup",
    "create_recovery_backup", "inspect_backup", "inspect_recovery_backup",
    "plan_backup_rotation", "plan_restore_as_new_profile", "restore_as_new_profile",
    "restore_backup_as_new_profile", "sha256_file", "verify_backup",
    "verify_recovery_backup", "verify_sha256_manifest", "write_recovery_kit",
]
