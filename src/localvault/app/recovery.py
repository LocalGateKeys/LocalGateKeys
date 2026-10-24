"""Backup & restore and the recovery phrase for the WebView UI.

Follows ``recovery_ui.RecoveryWindow``: every file comes from a Python
dialog, each multi-field form arrives in one call, and confirmations go
through ``UiPort.confirm`` with the Tk texts. Restores always create a new
profile; the backup's sha256 is pinned between preview and commit by
``RecoveryCenter.restore(expected_sha256=...)``. The recovery phrase is
returned once; only its word challenge is kept, until confirmed or locked.
"""
from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any, Mapping

from ..api.result import ApiError
from ..backup import private_temporary_directory
from ..secret_text import SecretText, is_blank_secret, secrets_match

INTRO = ("Backups are encrypted files saved on this computer or a location you choose. To restore one, you need "
         "its backup password and the vault password in use when it was created.")
PHRASE_INTRO = ("A 24-word recovery phrase can replace a forgotten vault password. It is shown once, never stored "
                "by LocalGateKeys, and replaces any earlier phrase.")
CARD_INTRO = ("Write these 24 words down in order and keep them sealed, away from this computer and your backups. "
              "Anyone with the phrase can open the vault. It is shown only now; LocalGateKeys does not store it and "
              "cannot show it again.")
PHRASE_MISMATCH = ("Those words do not match the phrase in that order. Check your written copy and try again, or go "
                   "back to the phrase.")
PHRASE_CONFIRMED = ("Recovery phrase confirmed. Keep the written copy sealed and separate from your backups; it is "
                    "not stored anywhere by LocalGateKeys.")
NOT_RESTORED = "Nothing was restored as a new profile. Your existing profiles and current vault are unchanged."


def result_message(result: Mapping[str, Any]) -> str:
    """``RecoveryWindow.show_result``'s text for a summarised result."""
    from .recovery_center import summarize_recovery

    safe = summarize_recovery(result)
    operation, kind = safe.get("operation"), safe.get("format_kind")
    if operation == "create" and kind == "catalog":
        return "Older backup created. It contains saved items and settings, but not attachment files."
    if operation == "create":
        return "Encrypted backup created. Your vault password was not stored in the backup."
    if operation == "verify":
        return "Backup verified. No profile data was changed."
    if operation == "restore" and safe.get("committed") and safe.get("profile_name"):
        return f"“{safe['profile_name']}” was restored as a new profile. Your existing vault is unchanged."
    if operation == "restore" and safe.get("committed"):
        return "The temporary restore test completed. Your profiles and current vault are unchanged."
    if operation == "recovery-kit":
        return "Recovery kit saved. Keep it with your encrypted backup."
    if safe.get("catalog_verified"):
        return "Test profile opened successfully."
    return "Backup details checked. No profile data was changed."


def restore_confirmation(name: str, planned: Mapping[str, Any]) -> str:
    kind, entries = planned.get("format_kind"), planned.get("entries")
    item_copy = f"{entries} saved items" if type(entries) is int else "saved items"
    if kind == "catalog":
        contents = f"This older backup includes {item_copy} and settings. It does not include attachment files."
    else:
        attachments = planned.get("attachments")
        attachment_copy = (f" and {attachments} attachment files" if type(attachments) is int
                           else " and attachment files")
        contents = f"This full backup includes {item_copy}, settings{attachment_copy}."
    return (f"{contents}\n\nA new profile named “{name}” will be created. "
            "Your existing profiles and current vault will stay unchanged. "
            "Sign-in and device trust settings in the restored profile will be turned off.")


def rollback_confirmation(rollback: Any) -> str:
    return (f"This backup is older than the vault that is currently on disk "
            f"(backup generation {rollback.restored_generation}, current generation "
            f"{rollback.current_generation}).\n\nRestoring it rolls the vault back and replaces the "
            "rollback-protection anchor with the older generation. Changes made after this backup "
            "was created will not be in the restored profile.\n\nRoll back to this older backup?")


class RecoveryWebService:
    def __init__(self, controller: Any, port: Any, dialogs: Any) -> None:
        self._controller = controller
        self._port = port
        self._dialogs = dialogs
        self._challenges: dict[str, Any] = {}
        self._trial: dict[str, Any] = {}
        # Set once a backup was verified (or test-restored) in this unlock; the setup guide asks for it.
        self.verified_backup = False
        controller.on_lock.append(self._on_lock)

    def _on_lock(self) -> None:
        self.verified_backup = False
        self._challenges.clear()
        self.cancel_trial()

    # --------------------------------------------------------------- center
    def _center(self) -> Any:
        from ..recovery import RecoveryController, RecoveryService
        from ..session_guard import StaleSession
        from .recovery_center import RecoveryCenter

        controller = self._controller
        profiles = controller.profiles
        record = profiles.active_profile()
        if record is None:
            raise ApiError("no_profile", "Choose a profile first.")
        stamp = controller.guard.stamp()

        def selected_profile_current() -> None:
            if controller.guard.stamp() != stamp:
                raise StaleSession("The profile or session changed. Open Backup & restore again.")
            if not any(item.id == record.id for item in profiles.list_profiles()):
                raise StaleSession("The selected profile is no longer available.")

        if not controller.is_unlocked():
            selected_profile_current()
            return RecoveryCenter(service=RecoveryService(profiles.profile_dir(record.id), profile_name=record.name),
                                  profiles=profiles, active_profile_id=record.id,
                                  current_check=selected_profile_current, can_create=False)
        from ..next_release_ui import GuidedRecoveryDrill

        session = controller.session
        lease = controller.guard.lease()
        controller.require_lease(lease)

        def current_check() -> None:
            selected_profile_current()
            if controller.session is not session:
                raise StaleSession("The active profile changed. Open Backup & restore again.")
            controller.require_lease(lease)

        recovery = RecoveryController(session, profile_name=record.name, lease=lease, guard=controller.guard,
                                      require_lease=controller.require_lease,
                                      session_provider=lambda: controller.session)
        drill = self._trial.get("drill") or GuidedRecoveryDrill(recovery, session_checker=current_check)
        return RecoveryCenter(recovery, drill=drill, profiles=profiles, active_profile_id=record.id,
                              current_check=current_check, save_current=session.save, can_create=True)

    def _run(self, fn: Any) -> Any:
        from ..recovery import RecoveryError
        from ..session_guard import StaleSession
        from ..vault import VaultError

        try:
            return fn()
        except ApiError:
            raise
        except StaleSession as exc:
            raise ApiError("session_changed", str(exc) or "The vault locked or changed. Try again.") from None
        except (RecoveryError, VaultError, OSError, ValueError) as exc:
            raise ApiError("invalid", str(exc) or "The backup operation failed.") from None

    def _open(self, title: str) -> Path:
        source = self._dialogs.open_file(title)
        if not source:
            raise ApiError("cancelled", "No file was chosen.")
        return Path(source)

    # ---------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        from ..vault import recovery_phrase_enrolled

        controller = self._controller
        record = controller.profiles.active_profile()
        unlocked = controller.is_unlocked()
        try:
            if unlocked:
                enrolled = bool(controller.session.has_recovery_phrase())
            else:
                enrolled = bool(record and recovery_phrase_enrolled(controller.profiles.vault_path(record.id)))
        except Exception:  # noqa: BLE001 - a status row only
            enrolled = False
        return {"can_create": unlocked, "phrase_enrolled": enrolled, "intro": INTRO, "phrase_intro": PHRASE_INTRO,
                "trial": bool(self._trial.get("profile")), "kit_ready": self._kit_ready()}

    # --------------------------------------------------------------- backups
    # The vault (master) password arrives as a SecretText the bridge owns and wipes after the call;
    # the closures below use it while the call runs and never keep it.
    def create_backup(self, backup_password: str | SecretText, confirmation: str | SecretText,
                      vault_password: str | SecretText) -> dict[str, Any]:
        from ..backup_filename import BackupFilenameError, backup_save_as_options, normalize_backup_filename

        if not self._controller.is_unlocked():
            raise ApiError("locked", "Unlock this profile to create a backup.")
        if is_blank_secret(backup_password) or is_blank_secret(confirmation) or is_blank_secret(vault_password):
            raise ApiError("invalid", "Enter both passwords and confirm the backup password.")
        if not secrets_match(confirmation, backup_password):
            raise ApiError("invalid", "Backup passwords do not match.")
        center = self._run(self._center)
        selected = self._dialogs.save_file("Create backup (.lgk)", backup_save_as_options()["initialfile"])
        if not selected:
            raise ApiError("cancelled", "No file was chosen.")
        try:
            destination = normalize_backup_filename(selected).expanduser().absolute()
        except BackupFilenameError as exc:
            raise ApiError("invalid", str(exc)) from None
        overwrite = False
        if destination.exists():
            if not self._port.confirm("Replace this backup?", f"{destination.name} already exists. Replace it?"):
                raise ApiError("cancelled", "Cancelled.")
            overwrite = True
        result = self._run(lambda: center.create_backup(
            destination, backup_password=backup_password, backup_password_confirmation=confirmation,
            vault_password=vault_password, overwrite=overwrite))
        return {"message": result_message(result)}

    def verify(self, backup_password: str | SecretText, vault_password: str | SecretText) -> dict[str, Any]:
        if is_blank_secret(backup_password) or is_blank_secret(vault_password):
            raise ApiError("invalid", "Enter both passwords.")
        center = self._run(self._center)
        source = self._open("Choose backup to verify")
        result = self._run(lambda: center.verify_backup(source, backup_password=backup_password,
                                                        vault_password=vault_password))
        self.verified_backup = True
        return {"message": result_message(result)}

    def restore(self, profile_name: str, backup_password: str | SecretText, vault_password: str | SecretText) -> dict[str, Any]:
        from ..vault import RollbackRequiresConfirmation

        if not str(profile_name).strip() or is_blank_secret(backup_password) or is_blank_secret(vault_password):
            raise ApiError("invalid", "Enter a profile name and both passwords.")
        center = self._run(self._center)
        source = self._open("Choose backup to restore")

        def run() -> dict[str, Any]:
            from ..recovery import RecoveryError

            record = center.allocate_restore_profile(str(profile_name).strip())
            planned = center.preview_restore(source, profile_record=record, backup_password=backup_password,
                                             vault_password=vault_password)
            if not planned.get("requires_confirmation"):
                raise RecoveryError("This backup could not be previewed for restore")
            if not self._port.confirm("Restore as a new profile?", restore_confirmation(record.name, planned)):
                return {"message": NOT_RESTORED, "restored": False}
            kwargs = dict(profile_record=record, confirm=True, expected_sha256=planned.get("backup_sha256"),
                          backup_password=backup_password, vault_password=vault_password)
            try:
                result = center.restore(source, **kwargs)
            except RollbackRequiresConfirmation as rollback:
                if not self._port.confirm("Roll back to an older backup?", rollback_confirmation(rollback)):
                    return {"message": "Nothing was restored. The newer vault on disk and your rollback protection "
                                       "are unchanged.", "restored": False}
                result = center.restore(source, allow_rollback=True, **kwargs)
            return {"message": result_message(result), "restored": True}

        return self._run(run)

    # ------------------------------------------------------ guided drill
    def _kit_ready(self) -> bool:
        drill = self._trial.get("drill")
        return bool(self._trial.get("backup") and getattr(getattr(drill, "state", None), "verified_catalog", False))

    def cancel_trial(self) -> dict[str, Any]:
        directory = self._trial.get("directory")
        if directory is not None:
            try:
                directory.cleanup()
            except OSError:
                pass
        self._trial = {}
        return {"message": "Test cancelled. Existing profiles and backup files are unchanged."}

    def test_restore(self, backup_password: str | SecretText, vault_password: str | SecretText) -> dict[str, Any]:
        if not self._controller.is_unlocked():
            raise ApiError("locked", "Unlock this profile to test a restore.")
        if is_blank_secret(backup_password) or is_blank_secret(vault_password):
            raise ApiError("invalid", "Enter both passwords.")
        self.cancel_trial()
        center = self._run(self._center)
        source = self._open("Choose backup to test")
        try:
            # Inside the owner-only data folder, not the shared system temp (cleanup junction race).
            directory = private_temporary_directory("localgatekeys-restore-test-")
        except OSError:
            raise ApiError("invalid", "Could not prepare a private folder for the test restore.") from None
        destination = Path(directory.name) / "profile"

        def run() -> dict[str, Any]:
            from ..recovery import RecoveryError

            planned = center.preview_restore(source, destination, backup_password=backup_password,
                                             vault_password=vault_password)
            if not planned.get("requires_confirmation"):
                raise RecoveryError("This backup could not be previewed for a test restore")
            if not self._port.confirm("Test this restore?", (
                    "A temporary copy will be opened in an isolated location. Your profiles and current vault will "
                    "stay unchanged. The test copy is removed when this window closes.")):
                raise ApiError("cancelled", "Cancelled.")
            return center.restore(source, destination, confirm=True, expected_sha256=planned.get("backup_sha256"),
                                  backup_password=backup_password, vault_password=vault_password)

        try:
            result = self._run(run)
        except ApiError:
            directory.cleanup()
            raise
        self._trial = {"directory": directory, "profile": destination, "backup": source, "drill": center.drill}
        self.verified_backup = True
        return {"message": result_message(result)}

    def verify_trial(self, vault_password: str | SecretText) -> dict[str, Any]:
        if not self._trial.get("profile"):
            raise ApiError("invalid", "Test a restore first.")
        if is_blank_secret(vault_password):
            raise ApiError("invalid", "Enter the vault password.")
        center = self._run(self._center)
        result = self._run(lambda: center.verify_restored_catalog(self._trial["profile"],
                                                                  vault_password=vault_password))
        return {"message": result_message(result)}

    def write_kit(self) -> dict[str, Any]:
        if not self._kit_ready():
            raise ApiError("invalid", "Verify the test profile before writing a recovery kit.")
        center = self._run(self._center)
        target = self._dialogs.save_file("Write recovery kit (.json)", "recovery-kit.json")
        if not target:
            raise ApiError("cancelled", "No file was chosen.")
        result = self._run(lambda: center.recovery_kit(Path(target), backup=self._trial["backup"], overwrite=False))
        return {"message": result_message(result)}

    # -------------------------------------------------------- recovery phrase
    def phrase_create(self, vault_password: str | SecretText) -> dict[str, Any]:
        if not self._controller.is_unlocked():
            raise ApiError("locked", "Unlock this profile to manage its recovery phrase.")
        center = self._run(self._center)
        phrase = self._run(lambda: center.create_recovery_phrase(vault_password))
        # Replacing a phrase rotates the data key; the notes say what that changed.
        notes = list((getattr(center, "last_result", None) or {}).get("warnings", []))
        return self.phrase_card(phrase, notes)

    def phrase_card(self, phrase: str, notes: list[str] | None = None) -> dict[str, Any]:
        """The show-once card for a phrase just issued (here, or by removing camera verification)."""
        from .recovery_center import RecoveryPhraseChallenge

        try:
            challenge = RecoveryPhraseChallenge(phrase)
            words = phrase.split()
        finally:
            phrase = ""
        self._challenges.clear()
        token = secrets.token_urlsafe(12)
        self._challenges[token] = challenge
        return {"token": token, "words": words, "positions": list(challenge.positions), "intro": CARD_INTRO,
                "notes": [note for note in (notes or []) if isinstance(note, str) and note]}

    def phrase_confirm(self, token: str, answers: list[str]) -> dict[str, Any]:
        challenge = self._challenges.get(str(token))
        if challenge is None:
            raise ApiError("expired", "This recovery phrase card is closed. Create a new phrase to try again.")
        if not challenge.verify(list(answers or [])):
            return {"confirmed": False, "message": PHRASE_MISMATCH}
        self._challenges.pop(str(token), None)
        return {"confirmed": True, "message": PHRASE_CONFIRMED}

    def phrase_close(self, token: str) -> dict[str, Any]:
        self._challenges.pop(str(token), None)
        return {"message": "A recovery phrase is active, but you did not confirm it. If you did not write it down, "
                           "open Recovery phrase again to replace it."}
