"""Backup and recovery controller, phrase recovery and result summaries (no UI toolkit)."""
from __future__ import annotations

import os
import secrets
import shutil
import tempfile
import unicodedata
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..backup import (
    BackupError,
    export_encrypted_backup,
    restore_verified_backup,
    verify_encrypted_backup,
)
from ..config import BRAND_NAME
from ..profiles import ProfileError, ProfileManager, ProfileRecord
from ..recovery import (
    BackupInventory,
    RecoveryController,
    RecoveryError,
    RecoveryService,
    cleanup_recovery_artifacts,
    inspect_recovery_backup,
    plan_restore_as_new_profile,
    restore_as_new_profile,
    sha256_file,
    verify_recovery_backup,
    write_recovery_kit,
)
from ..secret_text import SecretText, is_blank_secret, secrets_match
from ..vault import (
    VaultError,
    VaultSession,
    unlock_with_recovery_phrase,
)


def summarize_recovery(result: Mapping[str, Any] | BackupInventory) -> dict[str, Any]:
    """Return only non-secret fields suitable for a status card or dialog."""
    if isinstance(result, BackupInventory):
        raw = result.as_dict()
    elif isinstance(result, Mapping):
        raw = dict(result)
    else:
        raise RecoveryError("Recovery result is malformed")
    allowed = {
        "operation", "path", "source", "destination", "profile_name", "version", "entries",
        "attachments", "attachment_count", "attachment_bytes", "backup_bytes", "backup_sha256",
        "format", "format_kind", "new_profile_name", "deleted_entries",
        "created_at", "verified", "verified_at", "same_disk", "warnings", "safety", "dry_run",
        "requires_confirmation", "committed", "disk", "manifest", "manifest_path", "remove",
        "retained", "orphan_manifests", "keep", "recovery_phrase_enrolled",
    }
    safe = {key: raw[key] for key in allowed if key in raw}
    if "warnings" in safe:
        warnings = safe["warnings"]
        if not isinstance(warnings, (list, tuple)) or not all(isinstance(value, str) for value in warnings):
            raise RecoveryError("Recovery warnings are malformed")
        safe["warnings"] = list(warnings)
    # Passwords and vault payloads are intentionally not copied even if a
    # caller passes an over-rich result mapping.
    safe.pop("backup_password", None)
    safe.pop("vault_password", None)
    safe.pop("master_password", None)
    return safe


def recovery_phrase_change_warnings(change: Mapping[str, Any]) -> list[str]:
    """Plain-language notes after a recovery phrase was replaced (a data-key rotation)."""
    if change.get("operation") not in {"replace", "remove"}:
        return []
    notes = ["The previous recovery phrase no longer opens this vault. Backup files you exported or copied "
             "elsewhere earlier still open with the old phrase or the master password of that time: delete "
             "them if the old phrase may be known to someone else."]
    reenroll = [name for name in change.get("reenroll_required", ()) if name in {"hello", "face"}]
    if reenroll:
        names = " and ".join({"hello": "Windows Hello", "face": "camera verification"}[name] for name in reenroll)
        notes.append(f"Set up {names} again; the vault was re-encrypted under a new key.")
    retained = int(change.get("retained_old_copies", 0) or 0)
    if retained:
        notes.append(f"{retained} older safety cop{'y' if retained == 1 else 'ies'} (before a restore or a format "
                     "upgrade) in this profile's Backups folder still open with the old phrase or password. "
                     "Delete them if you no longer need them.")
    return notes


class RecoveryPhraseChallenge:
    """Three random word positions the user must retype before the show-once card closes.

    The challenge keeps the words only for the lifetime of the card; nothing is
    written to disk and the comparison is constant-time per word.
    """

    WORDS_TO_CONFIRM = 3

    def __init__(self, phrase: str, *, count: int = WORDS_TO_CONFIRM) -> None:
        words = phrase.split() if isinstance(phrase, str) else []
        if len(words) != 24:
            raise RecoveryError("A recovery phrase has exactly 24 words")
        remaining = list(range(1, len(words) + 1))
        picks: list[int] = []
        for _ in range(max(1, min(int(count), len(words)))):
            picks.append(remaining.pop(secrets.randbelow(len(remaining))))
        self.positions: tuple[int, ...] = tuple(sorted(picks))
        # Only the challenged words are kept; the rest of the phrase is never held here.
        self._expected = tuple(self._normalize(words[position - 1]) for position in self.positions)

    @staticmethod
    def _normalize(value: Any) -> str:
        return unicodedata.normalize("NFKD", str(value)).casefold().strip()

    def verify(self, answers: Any) -> bool:
        try:
            given = [self._normalize(answer) for answer in answers]
        except TypeError:
            return False
        if len(given) != len(self.positions):
            return False
        matched = True
        for expected, answer in zip(self._expected, given, strict=True):
            if not secrets.compare_digest(answer.encode("utf-8"), expected.encode("utf-8")):
                matched = False
        return matched


def recover_with_phrase(path: Path | str, phrase: str, new_password: str | SecretText, *,
                        backup_dir: Path | None = None, backup_count: int = 0,
                        report: dict[str, Any] | None = None) -> VaultSession:
    """Open the vault with its recovery phrase and immediately set a new master password.

    The returned session is an ordinary unlocked session.  The new master
    password rotates the data key (as a password change does): the catalog is
    re-encrypted, rolling backups under the old key are purged and the same
    recovery phrase is re-wrapped under the new key.  Windows Hello and camera
    grants are revoked: their bindings leave the payload and, like
    ``MasterService.change``, their sidecar envelopes and the Windows Hello OS
    key are deleted.  A ``report`` dict, when given, receives non-secret
    results; ``unlock_cleanup_complete`` is False when some stale key material
    could not be removed (it only wraps the retired data key).  A ``SecretText``
    new password stays the caller's to wipe.
    """
    from ..face_unlock import cleanup_after_password_change as cleanup_face
    from ..hello_unlock import cleanup_after_password_change as cleanup_hello

    session = unlock_with_recovery_phrase(Path(path), phrase, backup_dir=backup_dir, backup_count=backup_count)
    try:
        record_id = session.hello_binding()
        vault_path = session.path
        result = session.set_master_password_after_recovery(new_password)
    except BaseException:
        session.lock()
        raise
    # The envelopes are removed even without a binding: after the rotation a
    # leftover sidecar can only hold the retired data key.
    try:
        hello_cleaned = cleanup_hello(vault_path, record_id)
    except Exception:  # noqa: BLE001 - the reset is committed; a cleanup failure is only reported
        hello_cleaned = False
    try:
        face_cleaned = cleanup_face(vault_path)
    except Exception:  # noqa: BLE001
        face_cleaned = False
    if report is not None:
        report.update({
            "key_generation": result.get("key_generation"),
            "recovery_phrase_invalidated": bool(result.get("recovery_phrase_invalidated")),
            "reenroll_required": list(result.get("reenroll_required", [])),
            "purged_backups": int(result.get("purged_backups", 0)),
            "unlock_cleanup_complete": bool(hello_cleaned and face_cleaned),
        })
    return session


class RecoveryCenter:
    """UI-facing view model; every mutating operation remains explicit."""

    def __init__(self, controller: RecoveryController | None = None, *, service: RecoveryService | None = None,
                 drill: Any | None = None, profiles: ProfileManager | None = None,
                 active_profile_id: str | None = None,
                 current_check: Callable[[], Any] | None = None,
                 save_current: Callable[[], Any] | None = None,
                 can_create: bool = True) -> None:
        if controller is None and service is None:
            raise RecoveryError("A recovery controller or service is required")
        self.controller = controller
        self.service = service or controller.service  # type: ignore[union-attr]
        # ``GuidedRecoveryDrill`` is imported by the application layer to
        # avoid a recovery/core/UI import cycle.  The presentation only
        # requires the small stage-shaped method surface and keeps this seam
        # optional for existing callers.
        self.drill = drill
        self.profiles = profiles
        self.active_profile_id = active_profile_id
        self.current_check = current_check
        self.save_current = save_current
        self.can_create = bool(can_create)
        self.last_result: dict[str, Any] | None = None

    @staticmethod
    def backup_format(source: Path | str) -> str:
        """Identify the two supported .lgk containers without decrypting them."""
        path = Path(source)
        try:
            if path.is_symlink() or not path.is_file():
                raise RecoveryError("Select a regular backup file")
            with path.open("rb") as handle:
                prefix = handle.read(4)
        except OSError as exc:
            raise RecoveryError("Could not read the selected backup") from exc
        if prefix.startswith(b"PK\x03\x04"):
            return "full"
        if prefix.startswith(b"{") or prefix.startswith(b"\xef\xbb\xbf{"):
            return "catalog"
        raise RecoveryError("This file is not a supported LocalGateKeys backup")

    def _require_current(self) -> None:
        if self.current_check is not None:
            self.current_check()
        if self.controller is not None:
            self.controller.binding.current()

    def _require_create(self) -> None:
        if not self.can_create:
            raise RecoveryError("Unlock this profile to create a backup")
        self._require_current()

    def _save_current(self) -> None:
        self._require_create()
        if self.save_current is not None:
            self.save_current()
        self._require_current()

    def allocate_restore_profile(self, name: str) -> ProfileRecord:
        if self.profiles is None:
            raise RecoveryError("Profile storage is unavailable")
        try:
            return self.profiles.allocate_restore_profile(name)
        except ProfileError as exc:
            raise RecoveryError(str(exc)) from exc

    def _restore_path(self, record: ProfileRecord) -> Path:
        if self.profiles is None:
            raise RecoveryError("Profile storage is unavailable")
        try:
            return self.profiles.restore_profile_path(record)
        except ProfileError as exc:
            raise RecoveryError(str(exc)) from exc

    def _register_restored_profile(self, record: ProfileRecord, destination: Path) -> None:
        if self.profiles is None:
            raise RecoveryError("Profile storage is unavailable")
        # A successfully published directory is deliberately kept if the
        # session changed or the index write fails; it remains recoverable.
        try:
            self._require_current()
            self.profiles.register_restored_profile(record)
        except Exception as exc:
            raise RecoveryError(
                f"The backup was restored, but {BRAND_NAME} could not add {record.name} to your profiles. "
                f"Your restored data is still saved at {destination}. Resolve the profile-list issue and "
                "contact support if it continues."
            ) from exc

    def status(self) -> dict[str, Any]:
        return summarize_recovery(self.last_result or {"operation": "status", "verified": False})

    # -- recovery phrase ------------------------------------------------------
    def _session(self) -> Any:
        if self.controller is None:
            raise RecoveryError("Unlock this profile to manage its recovery phrase")
        return self.controller.binding.current()

    def recovery_phrase_status(self) -> dict[str, Any]:
        """Non-secret: whether a phrase is enrolled.  The phrase itself is never retained."""
        enrolled = False
        if self.controller is not None:
            try:
                enrolled = bool(self._session().has_recovery_phrase())
            except Exception:  # noqa: BLE001 - a stale/locked session simply reports "none"
                enrolled = False
        return {"operation": "recovery-phrase", "recovery_phrase_enrolled": enrolled}

    def create_recovery_phrase(self, vault_password: str | SecretText) -> str:
        """Create or replace the 24-word phrase; the previous phrase stops working.

        The phrase is returned exactly once for the show-once card and is not
        stored in ``last_result`` or anywhere else.
        """
        session = self._session()
        if is_blank_secret(vault_password):
            raise RecoveryError("Enter the vault password")
        try:
            record_id = session.hello_binding()
            phrase = session.create_recovery_phrase(vault_password)
        except VaultError as exc:
            raise RecoveryError(str(exc)) from exc
        change = getattr(session, "last_recovery_phrase_change", None) or {}
        warnings = recovery_phrase_change_warnings(change)
        if "hello" in change.get("reenroll_required", ()):
            # Replacing a phrase rotates the data key: the Windows Hello OS key
            # only wraps the retired key now (its sidecar is already removed).
            from ..hello_unlock import cleanup_after_password_change as cleanup_hello

            try:
                cleanup_hello(session.path, record_id)
            except Exception:  # noqa: BLE001, S110 - the rotation is committed; cleanup is best effort
                pass
        self._require_current()
        summary: dict[str, Any] = {"operation": "recovery-phrase", "committed": True, "recovery_phrase_enrolled": True}
        if warnings:
            summary["warnings"] = warnings
        self.last_result = summarize_recovery(summary)
        return phrase

    def create_backup(self, destination: Path | str, **kwargs: Any) -> dict[str, Any]:
        self._save_current()
        result = (self.drill.create(destination, **kwargs) if self.drill is not None else
                  self.controller.create_backup(destination, **kwargs) if self.controller is not None
                  else self.service.create_backup(destination, **kwargs))
        self._require_current()
        self.last_result = summarize_recovery(result)
        return self.last_result

    def inspect_backup(self, source: Path | str, **kwargs: Any) -> dict[str, Any]:
        result = (self.drill.inspect(source, **kwargs) if self.drill is not None else
                  self.controller.verify_backup(source, **kwargs) if self.controller is not None
                  else inspect_recovery_backup(source, **kwargs))
        self.last_result = summarize_recovery(result)
        return self.last_result

    def verify_backup(self, source: Path | str, **kwargs: Any) -> dict[str, Any]:
        self._require_current()
        if self.backup_format(source) == "catalog":
            result = verify_encrypted_backup(Path(source), **kwargs)
            result = {"operation": "verify", "format_kind": "catalog", **result}
        else:
            result = (self.drill.verify(source, **kwargs) if self.drill is not None else
                      self.controller.verify_backup(source, **kwargs) if self.controller is not None
                      else verify_recovery_backup(source, **kwargs))
        self._require_current()
        self.last_result = summarize_recovery(result)
        return self.last_result

    def preview_restore(self, source: Path | str, destination: Path | str | None = None, **kwargs: Any) -> dict[str, Any]:
        self._require_current()
        record = kwargs.pop("profile_record", None)
        # Callers sometimes forward the same option set to preview and commit.
        # ``confirm`` belongs only to restore(), never to preview services.
        kwargs.pop("confirm", None)
        if record is not None:
            destination = self._restore_path(record)
        if destination is None:
            raise RecoveryError("Choose a profile for the restore")
        backup_kind = self.backup_format(source)
        if backup_kind == "catalog":
            source_path = Path(source)
            digest = sha256_file(source_path)
            expected = kwargs.pop("expected_sha256", None)
            if expected is not None and digest != expected:
                raise RecoveryError("This backup changed after it was selected. Select it again to preview a new restore.")
            info = verify_encrypted_backup(source_path, **kwargs)
            if sha256_file(source_path) != digest:
                raise RecoveryError("This backup changed while it was being checked. Select it again to preview a new restore.")
            result = {
                "operation": "restore", "source": str(source_path.absolute()),
                "destination": str(Path(destination).absolute()), "backup_sha256": digest,
                "backup_bytes": source_path.stat().st_size, "format_kind": "catalog",
                "profile_name": record.name if isinstance(record, ProfileRecord) else info.get("profile_name"),
                "entries": int(info.get("entries", 0)), "deleted_entries": int(info.get("deleted_entries", 0)),
                "attachments": 0, "dry_run": True, "requires_confirmation": True,
                "committed": False,
            }
        else:
            result = (self.drill.plan(source, destination, **kwargs) if self.drill is not None else
                      self.controller.plan_restore(source, destination, **kwargs) if self.controller is not None
                      else plan_restore_as_new_profile(source, destination, **kwargs))
            result = {**result, "format_kind": "full"}
            if isinstance(record, ProfileRecord):
                result["profile_name"] = record.name
        expected_digest = result.get("backup_sha256")
        if isinstance(expected_digest, str) and sha256_file(source) != expected_digest:
            raise RecoveryError("This backup changed while it was being checked. Select it again to preview a new restore.")
        self._require_current()
        self.last_result = summarize_recovery(result)
        return self.last_result

    def restore(self, source: Path | str, destination: Path | str | None = None, **kwargs: Any) -> dict[str, Any]:
        self._require_current()
        record = kwargs.pop("profile_record", None)
        if record is not None:
            destination = self._restore_path(record)
        confirmed = kwargs.pop("confirm", False) is True
        allow_rollback = kwargs.pop("allow_rollback", False) is True
        if not confirmed:
            # A UI caller must use preview_restore and then explicitly pass
            # confirm=True.  The core function also returns a preview, but the
            # guard here makes the presentation contract obvious.
            return self.preview_restore(source, destination, profile_record=record, **kwargs)
        expected_sha256 = kwargs.get("expected_sha256")
        if not isinstance(expected_sha256, str):
            raise RecoveryError("Restore confirmation is out of date. Preview the backup again.")
        if sha256_file(source) != expected_sha256:
            raise RecoveryError("This backup changed after preview. Nothing was restored; preview it again.")
        # The UI has consumed its confirmation; forward it to the core service
        # as well as retaining the fingerprint for its independent validation.
        kwargs["confirm"] = True
        backup_kind = self.backup_format(source)
        if record is not None:
            destination = self._restore_path(record)
        if destination is None:
            raise RecoveryError("Choose a profile for the restore")
        destination = Path(destination)
        if record is None and destination.exists():
            raise RecoveryError("Restore destination must not already exist")

        # Restore from a private snapshot, so the bytes authenticated at preview
        # are the same bytes consumed by the mutating restore operation.
        with _backup_snapshot(Path(source), destination.parent, expected_sha256) as snapshot:
            self._require_current()
            if backup_kind == "catalog":
                try:
                    result = restore_verified_backup(
                        snapshot,
                        vault_file=destination / "vault.json",
                        settings_file=destination / "settings.json",
                        backup_password=kwargs["backup_password"],
                        vault_password=kwargs["vault_password"],
                        replace=False,
                        allow_rollback=allow_rollback,
                    )
                except (BackupError, OSError, ValueError) as exc:
                    if record is not None and destination.exists():
                        raise RecoveryError(
                            f"Restore did not finish. Any encrypted data left at {destination} is kept for recovery."
                        ) from exc
                    raise
                result = {**result, "operation": "restore", "destination": str(destination),
                          "format_kind": "catalog", "backup_sha256": expected_sha256, "committed": True}
            else:
                try:
                    result = (self.drill.test_restore(snapshot, destination, **kwargs) if self.drill is not None else
                              self.controller.restore(snapshot, destination, **kwargs) if self.controller is not None
                              else restore_as_new_profile(snapshot, destination, **kwargs))
                except Exception as exc:
                    if record is not None and destination.exists():
                        raise RecoveryError(
                            f"The backup data was restored, but it could not be added to your profiles. "
                            f"Your data is still saved at {destination}."
                        ) from exc
                    raise
        result = {**result, "source": str(Path(source).absolute())}
        if record is not None:
            self._register_restored_profile(record, destination)
            result = {**result, "profile_name": record.name, "format_kind": backup_kind,
                      "backup_sha256": expected_sha256}
        self._require_current()
        self.last_result = summarize_recovery(result)
        return self.last_result

    def create_catalog_backup(self, destination: Path | str, *, backup_password: str | SecretText,
                              backup_password_confirmation: str | SecretText,
                              vault_password: str | SecretText) -> dict[str, Any]:
        if self.profiles is None:
            raise RecoveryError("Profile storage is unavailable")
        if not secrets_match(backup_password, backup_password_confirmation):
            raise RecoveryError("Backup passwords do not match")
        if secrets_match(backup_password, vault_password):
            raise RecoveryError("Choose a backup password different from your vault password")
        length = (backup_password.char_count if isinstance(backup_password, SecretText)
                  else len(backup_password) if isinstance(backup_password, str) else 0)
        if length < 12:
            raise RecoveryError("Backup password must contain at least 12 characters")
        self._save_current()
        active = next((item for item in self.profiles.list_profiles()
                       if item.id == self.active_profile_id), None)
        if active is None:
            active = self.profiles.active_profile()
        if active is None:
            raise RecoveryError("There is no profile to back up")
        try:
            profile_dir = self.profiles.restore_profile_path(active, require_absent=False)
        except ProfileError as exc:
            raise RecoveryError(str(exc)) from exc
        if not profile_dir.is_dir():
            raise RecoveryError("The profile to back up is unavailable")
        from ..vault import unlock_vault
        checked_session = unlock_vault(profile_dir / "vault.json", vault_password)
        try:
            self._require_current()
            export_encrypted_backup(
                Path(destination), vault_file=profile_dir / "vault.json",
                settings_file=profile_dir / "settings.json", profile_name=active.name,
                backup_password=backup_password,
            )
        except (BackupError, OSError, ValueError) as exc:
            raise RecoveryError(str(exc)) from exc
        finally:
            checked_session.lock()
        self._require_current()
        result = {"operation": "create", "path": str(destination), "format_kind": "catalog",
                  "profile_name": active.name, "committed": True}
        self.last_result = summarize_recovery(result)
        return self.last_result

    def recovery_kit(self, destination: Path | str, *, backup: Path | str, **kwargs: Any) -> dict[str, Any]:
        result = (self.drill.kit(destination, backup=backup, **kwargs) if self.drill is not None else
                  write_recovery_kit(destination, backup=backup, inventory=self.last_result, **kwargs))
        self.last_result = summarize_recovery(result)
        return self.last_result

    def verify_restored_catalog(self, trial_profile: Path | str, **kwargs: Any) -> dict[str, Any]:
        if self.drill is None:
            raise RecoveryError("The guided recovery drill is not configured")
        result = self.drill.verify_restored_catalog(trial_profile, **kwargs)
        self.last_result = summarize_recovery(result)
        return self.last_result

    def cleanup(self, directory: Path | str, *, keep: int = 3, confirm: bool = False) -> dict[str, Any]:
        result = cleanup_recovery_artifacts(directory, keep=keep, confirm=confirm)
        self.last_result = summarize_recovery(result)
        return self.last_result


@contextmanager
def _backup_snapshot(source: Path, destination_parent: Path, expected_sha256: str) -> Iterator[Path]:
    """Copy an authenticated backup to a private writable scratch directory."""
    last_error: OSError | None = None
    parents = dict.fromkeys((destination_parent, source.parent, Path(tempfile.gettempdir())))
    for parent in parents:
        snapshot: Path | None = None
        descriptor: int | None = None
        try:
            descriptor, name = tempfile.mkstemp(prefix=".lgk-restore-source-", suffix=".lgk", dir=parent)
            snapshot = Path(name)
            with source.open("rb") as original, os.fdopen(descriptor, "wb") as copy:
                descriptor = None
                shutil.copyfileobj(original, copy)
            if sha256_file(snapshot) != expected_sha256:
                snapshot.unlink(missing_ok=True)
                raise RecoveryError("This backup changed while restore was starting. Nothing was restored.")
        except OSError as exc:
            last_error = exc
            if descriptor is not None:
                os.close(descriptor)
            if snapshot is not None:
                snapshot.unlink(missing_ok=True)
            continue
        try:
            yield snapshot
        finally:
            snapshot.unlink(missing_ok=True)
        return
    raise RecoveryError("Could not prepare the selected backup") from last_error
