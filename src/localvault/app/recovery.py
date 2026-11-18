"""Backup & restore and the recovery phrase for the WebView UI.

Follows ``recovery_ui.RecoveryWindow``: every file comes from a Python
dialog, each multi-field form arrives in one call, and confirmations go
through ``UiPort.confirm`` with the Tk texts. Restores always create a new
profile; the backup's sha256 is pinned between preview and commit by
``RecoveryCenter.restore(expected_sha256=...)``. The recovery phrase is
returned once; only its word challenge is kept, until confirmed or locked.

A backup whose vault has a key file / YubiKey (vault v4) raises
``FactorRequired`` before the vault's Argon2 runs; the page then asks for them
(``factors`` / ``choose_keyfile``) or offers ``restore_with_phrase``.  The key
file's bytes are held only until the flow succeeds, another backup is chosen or
the vault locks.
"""
from __future__ import annotations

import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any, Mapping

from ..api.result import ApiError
from ..composite_key import YUBIKEY_HMAC
from ..backup import private_temporary_directory
from ..secret_text import SecretText, is_blank_secret, secrets_match
from ..i18n import t

INTRO = ("recovery.backupsAreEncryptedFilesSaved")
PHRASE_INTRO = ("recovery.a24WordRecoveryPhrase")
CARD_INTRO = ("recovery.writeThese24WordsDown")
PHRASE_MISMATCH = ("recovery.thoseWordsDoNotMatch")
PHRASE_CONFIRMED = ("recovery.recoveryPhraseConfirmedKeepThe")
NOT_RESTORED = "recovery.nothingWasRestoredAsA"
FACTORS_REMOVED = "recovery.factorsRemoved"


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
    removed = f" {t(FACTORS_REMOVED)}" if safe.get("factors_removed") else ""
    if operation == "restore" and safe.get("committed") and safe.get("profile_name"):
        return t("recovery.restoredAsNewProfile", name=safe['profile_name']) + removed
    if operation == "restore" and safe.get("committed"):
        return t("recovery.theTemporaryRestoreTestCompleted") + removed
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
    # Shared collections are never restored from a backup (sub-plan 07, ruling F3), as on the Mac and the phones.
    shared = t("recovery.sharedNotRestored")
    return t("recovery.aNewProfileNamedWill", contents=contents, name=name) + "\n\n" + shared


# The file dialog titles of the three flows that read a backup the user picks first (design section 8).
CHOOSE_TITLES = {"verify": "recovery.chooseBackupToVerify", "restore": "recovery.chooseBackupToRestore",
                 "test": "recovery.chooseBackupToTest"}


def key_line_text(info: Mapping[str, Any]) -> str:
    """Section 8: which backup password opens this file (from ``backup.describe_backup``), then the master password."""
    from .backup_keys import short_date

    line = info.get("key_line")
    when = short_date(info.get("key_set_at"))
    if line == "current":
        text = t("backupKey.restore.current", date=when)
    elif line == "earlier_changed":
        text = t("backupKey.restore.changed", date=when, changed=short_date(info.get("replaced_at")))
    elif line == "earlier_reset":
        text = t("backupKey.restore.reset", date=when, reset=short_date(info.get("reset_at")))
    elif line == "other_device":
        text = t("backupKey.restore.otherDevice", date=when)
    else:
        text = t("backupKey.restore.oldFormat", date=short_date(info.get("date")))
    return f"{text} {t('backupKey.restore.master')}"


def rollback_confirmation(rollback: Any) -> str:
    return (t("recovery.thisBackupIsOlderThan", restored_generation=rollback.restored_generation, current_generation=rollback.current_generation))


class RecoveryWebService:
    def __init__(self, controller: Any, port: Any, dialogs: Any, *,
                 yubikey: Callable[[int], Callable[[bytes], bytes]] | None = None) -> None:
        self._controller = controller
        self._port = port
        self._dialogs = dialogs
        # ``yubikey(slot)`` returns the challenge-response callable for a YubiKey slot (the HID transport);
        # without it a backup that needs a YubiKey opens only with its recovery phrase.
        self._yubikey = yubikey
        # The factors the page supplied for the chosen backup: the key file's bytes and name, and what the
        # last ``FactorRequired`` asked for ({"kinds", "yubikey_slot"}).
        self._keyfile: bytearray | None = None
        self._keyfile_name: str | None = None
        self._factor_need: dict[str, Any] | None = None
        self._challenges: dict[str, Any] = {}
        self._trial: dict[str, Any] = {}
        # The backup chosen (and described) before its passwords are typed: {"kind", "path"}.
        self._picked: dict[str, Any] | None = None
        # Set once a backup was verified (or test-restored) in this unlock; the setup guide asks for it.
        self.verified_backup = False
        controller.on_lock.append(self._on_lock)

    def _on_lock(self) -> None:
        self._picked = None
        self.verified_backup = False
        self.clear_factors()
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
        from ..vault import FactorMismatch, FactorRequired, VaultError

        try:
            return fn()
        except ApiError:
            raise
        except StaleSession as exc:
            raise ApiError("session_changed", str(exc) or t("recovery.theVaultLockedOrChanged")) from None
        except FactorRequired as exc:
            # The backup's vault has a key file / YubiKey: the page asks for them (``factors``).
            slot = next((spec.slot for spec in getattr(exc, "specs", []) if spec.slot), None)
            self._factor_need = {"kinds": list(exc.kinds), "yubikey_slot": slot or
                                 (self._factor_need or {}).get("yubikey_slot")}
            raise ApiError("factor_required", str(exc)) from None
        except FactorMismatch as exc:
            raise ApiError("factor_mismatch", str(exc)) from None
        except (RecoveryError, VaultError, OSError, ValueError) as exc:
            raise ApiError("invalid", str(exc) or t("recovery.theBackupOperationFailed")) from None

    def _open(self, title: str, kind: str | None = None) -> Path:
        # The file chosen with ``choose`` stays chosen for retries (a mistyped password) until the flow
        # succeeds, another file is chosen or the vault locks.
        picked = self._picked
        if picked is not None and kind is not None and picked.get("kind") == kind:
            return picked["path"]
        self._picked = None
        source = self._dialogs.open_file(title)
        if not source:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        return Path(source)

    def choose(self, kind: str) -> dict[str, Any]:
        """Pick the backup for ``verify``, ``restore`` or ``test`` and say which passwords open it (section 8).

        Only the cleartext header is read.  The next call of that flow uses this file instead of asking again.
        """
        from ..backup import BackupError, describe_backup
        from ..backup_key import DamagedRecordError

        if kind not in CHOOSE_TITLES:
            raise ApiError("invalid", t("bridge.invalid", name="kind"))
        if kind == "test" and not self._controller.is_unlocked():
            raise ApiError("locked", t("recovery.unlockThisProfileToTest"))
        self._picked = None
        self.clear_factors()
        path = self._open(t(CHOOSE_TITLES[kind]))
        record = None
        if self._controller.is_unlocked():
            try:
                record = self._controller.session.scheduled_backup_key()
            except DamagedRecordError:
                record = None
        try:
            info = describe_backup(path, record=record)
        except BackupError as exc:
            raise ApiError("invalid", str(exc) or t("recovery.theBackupOperationFailed")) from None
        self._picked = {"kind": kind, "path": path}
        return {"name": path.name, "key_line": key_line_text(info), "format_kind": info.get("format_kind"),
                "version": info.get("version")}

    # ---------------------------------------------------------------- factors
    def factors(self) -> dict[str, Any]:
        """What the factor prompt shows: the kinds still asked for, the YubiKey slot, the key file chosen."""
        need = self._factor_need or {}
        return {"kinds": list(need.get("kinds", [])), "yubikey_slot": need.get("yubikey_slot"),
                "keyfile": self._keyfile_name, "yubikey_ready": self._yubikey is not None,
                "phrase_allowed": bool(self._picked and self._picked.get("kind") == "restore")}

    def choose_keyfile(self) -> dict[str, Any]:
        """Pick the key file in a Windows dialog; its bytes are held for the next try of the current flow."""
        selected = self._dialogs.open_file(t("recovery.chooseKeyFile"))
        if not selected:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        from .factors import read_keyfile

        path = Path(selected)
        try:
            data = read_keyfile(path)  # at most factors.MAX_KEYFILE_BYTES + 1, from one open handle
        except ApiError as exc:
            raise ApiError("invalid", t("recovery.keyFileTooLarge") if exc.code == "keyfile_too_large"
                           else t("recovery.couldNotReadKeyFile")) from None
        self._wipe_keyfile()
        self._keyfile, self._keyfile_name = data, path.name
        return self.factors()

    def clear_factors(self) -> dict[str, Any]:
        self._wipe_keyfile()
        self._factor_need = None
        return {"cleared": True}

    def _wipe_keyfile(self) -> None:
        if self._keyfile is not None:
            self._keyfile[:] = b"\0" * len(self._keyfile)
        self._keyfile, self._keyfile_name = None, None

    def _factors(self, *, session_fallback: bool = False) -> Any:
        """``FactorSecrets`` from what the page supplied (``None`` when nothing was).

        ``session_fallback`` (backups of the unlocked vault itself) also uses the factors this
        session was unlocked with: the key file's 32-byte key is a valid KeePass key file of its own.
        """
        from ..vault import FactorSecrets

        keyfile = bytes(self._keyfile) if self._keyfile is not None else None
        need = self._factor_need or {}
        slot = need.get("yubikey_slot")
        if not slot and YUBIKEY_HMAC in need.get("kinds", []):
            slot = 2  # FactorRequired without the factor list: the default slot
        responder = self._yubikey(int(slot)) if self._yubikey is not None and slot else None
        if session_fallback and self._controller.is_unlocked():
            held = self._controller.session.held_factor_secrets()
            if held is not None:
                if keyfile is None:
                    keyfile = held.keyfile
                if responder is None:
                    responder = held.yubikey_response
        if keyfile is None and responder is None:
            return None
        return FactorSecrets(keyfile=keyfile, yubikey_response=responder)

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
            vault_password=vault_password, overwrite=overwrite, factors=self._factors(session_fallback=True)))
        self.clear_factors()
        return {"message": result_message(result)}

    def verify(self, backup_password: str | SecretText, vault_password: str | SecretText) -> dict[str, Any]:
        if is_blank_secret(backup_password) or is_blank_secret(vault_password):
            raise ApiError("invalid", t("recovery.enterBothPasswords"))
        center = self._run(self._center)
        source = self._open(t("recovery.chooseBackupToVerify"), "verify")
        result = self._run(lambda: center.verify_backup(source, backup_password=backup_password,
                                                        vault_password=vault_password, factors=self._factors()))
        self.verified_backup = True
        self._picked = None
        self.clear_factors()
        return {"message": result_message(result)}

    def restore(self, profile_name: str, backup_password: str | SecretText, vault_password: str | SecretText) -> dict[str, Any]:
        if not str(profile_name).strip() or is_blank_secret(backup_password) or is_blank_secret(vault_password):
            raise ApiError("invalid", t("recovery.enterAProfileNameAnd"))
        return self._restore(profile_name, backup_password, vault_password, factors=self._factors())

    def restore_with_phrase(self, profile_name: str, backup_password: str | SecretText, phrase: str,
                            new_password: str | SecretText, confirm: str | SecretText) -> dict[str, Any]:
        """Restore with the backup vault's recovery phrase instead of its master password and factors.

        ``new_password`` becomes the restored profile's master password; a key file / YubiKey is removed
        (the message says to add them again).
        """
        if (not str(profile_name).strip() or is_blank_secret(backup_password) or not str(phrase).strip()
                or is_blank_secret(new_password)):
            raise ApiError("invalid", t("recovery.enterPhraseAndPasswords"))
        if not secrets_match(new_password, confirm):
            raise ApiError("invalid", t("masterSheet.mismatch"))
        return self._restore(profile_name, backup_password, new_password, recovery_phrase=str(phrase).strip())

    def _restore(self, profile_name: str, backup_password: str | SecretText, vault_password: str | SecretText,
                 **unlock: Any) -> dict[str, Any]:
        from ..vault import RollbackRequiresConfirmation

        center = self._run(self._center)
        source = self._open(t("recovery.chooseBackupToRestore"), "restore")

        def run() -> dict[str, Any]:
            from ..recovery import RecoveryError

            record = center.allocate_restore_profile(str(profile_name).strip())
            planned = center.preview_restore(source, profile_record=record, backup_password=backup_password,
                                             vault_password=vault_password, **unlock)
            if not planned.get("requires_confirmation"):
                raise RecoveryError(t("recovery.thisBackupCouldNotBe"))
            if not self._port.confirm(t("recovery.restoreAsANewProfile"), restore_confirmation(record.name, planned)):
                return {"message": t(NOT_RESTORED), "restored": False}
            kwargs = dict(profile_record=record, confirm=True, expected_sha256=planned.get("backup_sha256"),
                          backup_password=backup_password, vault_password=vault_password, **unlock)
            try:
                result = center.restore(source, **kwargs)
            except RollbackRequiresConfirmation as rollback:
                if not self._port.confirm(t("recovery.rollBackToAnOlder"), rollback_confirmation(rollback)):
                    return {"message": t("recovery.nothingWasRestoredTheNewer"), "restored": False}
                result = center.restore(source, allow_rollback=True, **kwargs)
            return {"message": result_message(result), "restored": True}

        result = self._run(run)
        self._picked = None
        self.clear_factors()
        return result

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
        self.clear_factors()
        return {"message": t("recovery.testCancelledExistingProfilesAnd")}

    def test_restore(self, backup_password: str | SecretText, vault_password: str | SecretText) -> dict[str, Any]:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("recovery.unlockThisProfileToTest"))
        if is_blank_secret(backup_password) or is_blank_secret(vault_password):
            raise ApiError("invalid", t("recovery.enterBothPasswords"))
        self.cancel_trial()
        center = self._run(self._center)
        source = self._open(t("recovery.chooseBackupToTest"), "test")
        try:
            # Inside the owner-only data folder, not the shared system temp (cleanup junction race).
            directory = private_temporary_directory("localgatekeys-restore-test-")
        except OSError:
            raise ApiError("invalid", t("recovery.couldNotPrepareAPrivate")) from None
        destination = Path(directory.name) / "profile"

        def run() -> dict[str, Any]:
            from ..recovery import RecoveryError

            factors = self._factors()
            planned = center.preview_restore(source, destination, backup_password=backup_password,
                                             vault_password=vault_password, factors=factors)
            if not planned.get("requires_confirmation"):
                raise RecoveryError(t("recovery.thisBackupCouldNotBe2"))
            if not self._port.confirm(t("recovery.testThisRestore"), (
                    t("recovery.aTemporaryCopyWillBe"))):
                raise ApiError("cancelled", t("error.cancelled"))
            # The test profile keeps the factors; they stay held for "Verify the test profile".  A throwaway
            # copy: no rollback marks are set for it (``mark=False``).
            return center.restore(source, destination, confirm=True, expected_sha256=planned.get("backup_sha256"),
                                  backup_password=backup_password, vault_password=vault_password, factors=factors,
                                  mark=False)

        try:
            result = self._run(run)
        except ApiError:
            directory.cleanup()
            raise
        self._trial = {"directory": directory, "profile": destination, "backup": source, "drill": center.drill}
        self._picked = None
        self.verified_backup = True
        return {"message": result_message(result)}

    def verify_trial(self, vault_password: str | SecretText) -> dict[str, Any]:
        if not self._trial.get("profile"):
            raise ApiError("invalid", t("recovery.testARestoreFirst"))
        if is_blank_secret(vault_password):
            raise ApiError("invalid", t("recovery.enterTheVaultPassword"))
        center = self._run(self._center)
        result = self._run(lambda: center.verify_restored_catalog(self._trial["profile"],
                                                                  vault_password=vault_password,
                                                                  factors=self._factors()))
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

    # --------------------------------------------------------- emergency kit
    def kit_facts(self) -> dict[str, Any]:
        """The non-secret facts printed on the emergency kit; the phrase and passwords never pass through here."""
        from datetime import date

        from .. import heir
        from ..backup_schedule import SCHEDULED_DIR_NAME
        from ..version import APP_VERSION

        controller = self._controller
        record = controller.profiles.active_profile()
        if record is None:
            raise ApiError("no_profile", t("recovery.chooseAProfileFirst"))
        from ..duress import shown_path

        # Display text only: inside a duress session the paths read as the profile's own (review R1).
        folders = [str(shown_path(controller.profiles.backups_dir(record.id) / SCHEDULED_DIR_NAME))]
        mirror = str(getattr(controller.settings, "backup_mirror_dir", "") or "")
        if mirror:
            folders.append(mirror)
        # Emergency access (sub-plan 08): the shard holders by nickname only, for the kit's holder page.
        holders = heir.holder_nicknames(getattr(controller, "session", None)) if controller.is_unlocked() else []
        return {"profile": record.name, "vault_path": str(shown_path(controller.profiles.vault_path(record.id))),
                "backup_folders": folders, "created": date.today().isoformat(), "app_version": APP_VERSION,
                "heir_holders": holders}

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
