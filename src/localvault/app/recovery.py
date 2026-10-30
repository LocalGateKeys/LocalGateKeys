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
from ..i18n import t

INTRO = ("recovery.backupsAreEncryptedFilesSaved")
PHRASE_INTRO = ("recovery.a24WordRecoveryPhrase")
CARD_INTRO = ("recovery.writeThese24WordsDown")
PHRASE_MISMATCH = ("recovery.thoseWordsDoNotMatch")
PHRASE_CONFIRMED = ("recovery.recoveryPhraseConfirmedKeepThe")
NOT_RESTORED = "recovery.nothingWasRestoredAsA"


def result_message(result: Mapping[str, Any]) -> str:
    """``RecoveryWindow.show_result``'s text for a summarised result."""
    from .recovery_center import summarize_recovery

    safe = summarize_recovery(result)
    operation, kind = safe.get("operation"), safe.get("format_kind")
    if operation == "create" and kind == "catalog":
        return t("recovery.olderBackupCreatedItContains")
    if operation == "create":
        return t("recovery.encryptedBackupCreatedYourVault")
    if operation == "verify":
        return t("recovery.backupVerifiedNoProfileData")
    if operation == "restore" and safe.get("committed") and safe.get("profile_name"):
        return t("recovery.restoredAsNewProfile", name=safe['profile_name'])
    if operation == "restore" and safe.get("committed"):
        return t("recovery.theTemporaryRestoreTestCompleted")
    if operation == "recovery-kit":
        return t("recovery.recoveryKitSavedKeepIt")
    if safe.get("catalog_verified"):
        return t("recovery.testProfileOpenedSuccessfully")
    return t("recovery.backupDetailsCheckedNoProfile")


def restore_confirmation(name: str, planned: Mapping[str, Any]) -> str:
    kind, entries = planned.get("format_kind"), planned.get("entries")
    item_copy = t("recovery.savedItemsCount", count=entries) if type(entries) is int else t("recovery.savedItems")
    if kind == "catalog":
        contents = t("recovery.thisOlderBackupIncludesAnd", item_copy=item_copy)
    else:
        attachments = planned.get("attachments")
        attachment_copy = (t("recovery.attachmentFilesCount", count=attachments) if type(attachments) is int
                           else t("recovery.attachmentFiles"))
        contents = t("recovery.fullBackupIncludes", items=item_copy, attachments=attachment_copy)
    return (t("recovery.aNewProfileNamedWill", contents=contents, name=name))


def rollback_confirmation(rollback: Any) -> str:
    return (t("recovery.thisBackupIsOlderThan", restored_generation=rollback.restored_generation, current_generation=rollback.current_generation))


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
            raise ApiError("no_profile", t("recovery.chooseAProfileFirst"))
        stamp = controller.guard.stamp()

        def selected_profile_current() -> None:
            if controller.guard.stamp() != stamp:
                raise StaleSession(t("recovery.theProfileOrSessionChanged"))
            if not any(item.id == record.id for item in profiles.list_profiles()):
                raise StaleSession(t("recovery.theSelectedProfileIsNo"))

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
                raise StaleSession(t("recovery.theActiveProfileChangedOpen"))
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
            raise ApiError("session_changed", str(exc) or t("recovery.theVaultLockedOrChanged")) from None
        except (RecoveryError, VaultError, OSError, ValueError) as exc:
            raise ApiError("invalid", str(exc) or t("recovery.theBackupOperationFailed")) from None

    def _open(self, title: str) -> Path:
        source = self._dialogs.open_file(title)
        if not source:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
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
        return {"can_create": unlocked, "phrase_enrolled": enrolled, "intro": t(INTRO), "phrase_intro": t(PHRASE_INTRO),
                "trial": bool(self._trial.get("profile")), "kit_ready": self._kit_ready()}

    # --------------------------------------------------------------- backups
    # The vault (master) password arrives as a SecretText the bridge owns and wipes after the call;
    # the closures below use it while the call runs and never keep it.
    def create_backup(self, backup_password: str | SecretText, confirmation: str | SecretText,
                      vault_password: str | SecretText) -> dict[str, Any]:
        from ..backup_filename import BackupFilenameError, backup_save_as_options, normalize_backup_filename

        if not self._controller.is_unlocked():
            raise ApiError("locked", t("recovery.unlockThisProfileToCreate"))
        if is_blank_secret(backup_password) or is_blank_secret(confirmation) or is_blank_secret(vault_password):
            raise ApiError("invalid", t("recovery.enterBothPasswordsAndConfirm"))
        if not secrets_match(confirmation, backup_password):
            raise ApiError("invalid", t("recovery.backupPasswordsDoNotMatch"))
        center = self._run(self._center)
        selected = self._dialogs.save_file(t("recovery.createBackupLgk"), backup_save_as_options()["initialfile"])
        if not selected:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        try:
            destination = normalize_backup_filename(selected).expanduser().absolute()
        except BackupFilenameError as exc:
            raise ApiError("invalid", str(exc)) from None
        overwrite = False
        if destination.exists():
            if not self._port.confirm(t("recovery.replaceThisBackup"), t("recovery.alreadyExistsReplaceIt", name=destination.name)):
                raise ApiError("cancelled", t("error.cancelled"))
            overwrite = True
        result = self._run(lambda: center.create_backup(
            destination, backup_password=backup_password, backup_password_confirmation=confirmation,
            vault_password=vault_password, overwrite=overwrite))
        return {"message": result_message(result)}

    def verify(self, backup_password: str | SecretText, vault_password: str | SecretText) -> dict[str, Any]:
        if is_blank_secret(backup_password) or is_blank_secret(vault_password):
            raise ApiError("invalid", t("recovery.enterBothPasswords"))
        center = self._run(self._center)
        source = self._open(t("recovery.chooseBackupToVerify"))
        result = self._run(lambda: center.verify_backup(source, backup_password=backup_password,
                                                        vault_password=vault_password))
        self.verified_backup = True
        return {"message": result_message(result)}

    def restore(self, profile_name: str, backup_password: str | SecretText, vault_password: str | SecretText) -> dict[str, Any]:
        from ..vault import RollbackRequiresConfirmation

        if not str(profile_name).strip() or is_blank_secret(backup_password) or is_blank_secret(vault_password):
            raise ApiError("invalid", t("recovery.enterAProfileNameAnd"))
        center = self._run(self._center)
        source = self._open(t("recovery.chooseBackupToRestore"))

        def run() -> dict[str, Any]:
            from ..recovery import RecoveryError

            record = center.allocate_restore_profile(str(profile_name).strip())
            planned = center.preview_restore(source, profile_record=record, backup_password=backup_password,
                                             vault_password=vault_password)
            if not planned.get("requires_confirmation"):
                raise RecoveryError(t("recovery.thisBackupCouldNotBe"))
            if not self._port.confirm(t("recovery.restoreAsANewProfile"), restore_confirmation(record.name, planned)):
                return {"message": t(NOT_RESTORED), "restored": False}
            kwargs = dict(profile_record=record, confirm=True, expected_sha256=planned.get("backup_sha256"),
                          backup_password=backup_password, vault_password=vault_password)
            try:
                result = center.restore(source, **kwargs)
            except RollbackRequiresConfirmation as rollback:
                if not self._port.confirm(t("recovery.rollBackToAnOlder"), rollback_confirmation(rollback)):
                    return {"message": t("recovery.nothingWasRestoredTheNewer"), "restored": False}
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
        return {"message": t("recovery.testCancelledExistingProfilesAnd")}

    def test_restore(self, backup_password: str | SecretText, vault_password: str | SecretText) -> dict[str, Any]:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("recovery.unlockThisProfileToTest"))
        if is_blank_secret(backup_password) or is_blank_secret(vault_password):
            raise ApiError("invalid", t("recovery.enterBothPasswords"))
        self.cancel_trial()
        center = self._run(self._center)
        source = self._open(t("recovery.chooseBackupToTest"))
        try:
            # Inside the owner-only data folder, not the shared system temp (cleanup junction race).
            directory = private_temporary_directory("localgatekeys-restore-test-")
        except OSError:
            raise ApiError("invalid", t("recovery.couldNotPrepareAPrivate")) from None
        destination = Path(directory.name) / "profile"

        def run() -> dict[str, Any]:
            from ..recovery import RecoveryError

            planned = center.preview_restore(source, destination, backup_password=backup_password,
                                             vault_password=vault_password)
            if not planned.get("requires_confirmation"):
                raise RecoveryError(t("recovery.thisBackupCouldNotBe2"))
            if not self._port.confirm(t("recovery.testThisRestore"), (
                    t("recovery.aTemporaryCopyWillBe"))):
                raise ApiError("cancelled", t("error.cancelled"))
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
            raise ApiError("invalid", t("recovery.testARestoreFirst"))
        if is_blank_secret(vault_password):
            raise ApiError("invalid", t("recovery.enterTheVaultPassword"))
        center = self._run(self._center)
        result = self._run(lambda: center.verify_restored_catalog(self._trial["profile"],
                                                                  vault_password=vault_password))
        return {"message": result_message(result)}

    def write_kit(self) -> dict[str, Any]:
        if not self._kit_ready():
            raise ApiError("invalid", t("recovery.verifyTheTestProfileBefore"))
        center = self._run(self._center)
        target = self._dialogs.save_file(t("recovery.writeRecoveryKitJson"), "recovery-kit.json")
        if not target:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        result = self._run(lambda: center.recovery_kit(Path(target), backup=self._trial["backup"], overwrite=False))
        return {"message": result_message(result)}

    # -------------------------------------------------------- recovery phrase
    def phrase_create(self, vault_password: str | SecretText) -> dict[str, Any]:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("recovery.unlockThisProfileToManage"))
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
        return {"token": token, "words": words, "positions": list(challenge.positions), "intro": t(CARD_INTRO),
                "notes": [note for note in (notes or []) if isinstance(note, str) and note]}

    def phrase_confirm(self, token: str, answers: list[str]) -> dict[str, Any]:
        challenge = self._challenges.get(str(token))
        if challenge is None:
            raise ApiError("expired", t("recovery.thisRecoveryPhraseCardIs"))
        if not challenge.verify(list(answers or [])):
            return {"confirmed": False, "message": t(PHRASE_MISMATCH)}
        self._challenges.pop(str(token), None)
        return {"confirmed": True, "message": t(PHRASE_CONFIRMED)}

    def phrase_close(self, token: str) -> dict[str, Any]:
        self._challenges.pop(str(token), None)
        return {"message": t("recovery.aRecoveryPhraseIsActive")}
