"""The scheduled-backup key for the WebView UI (``docs/design/backup-public-key-2026-10-31.md``).

Scheduled backups lock to a public key whose record lives in the vault (``VaultSession.scheduled_backup_key``);
the backup password is never stored.  This service:

* migrates a stored backup password on the first unlock after the update (section 5), on a worker thread;
* sets, changes (with an optional re-lock of version 3 files), resets with the recovery phrase (owner Q2:
  strict), re-binds after a phrase replacement, confirms after a rollback and removes the key.  Every
  operation that replaces or removes an existing key needs proof: the current backup password or the
  recovery phrase bound in the record.  The master password alone never does;
* after a rollback, a missing or a damaged record (section 16c) checks every proof against the record last
  seen on this device (``seen_record``), never against the record in the vault: the rolled-back record's own
  password confirms, changes, sets and removes nothing;
* tells the scheduler which record to use, or why there is none (``schedule_record``);
* reports the Backups page state (``status``).

Old-format backups (full backup v2, ``.lgk`` v1/v2) are never opened, rewritten, renamed, moved or deleted
here (hard rule 1.1); the re-lock and the migration only read their cleartext header.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any

from .. import backup_key_state as device
from ..api.result import ApiError
from ..i18n import t
from ..secret_text import SecretText, as_secret, secrets_match

MIN_PASSWORD_CHARS = 12
MAX_PASSWORD_CHARS = 4096
# A change waits this long for a scheduled backup in flight before it re-locks (review L6).
RUN_WAIT_SECONDS = 300.0


def _thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True, name="lgk-backup-key-migration").start()


def short_date(seconds: int | None) -> str:
    """Local short date of integer Unix seconds (section 8: formatted only for display)."""
    if seconds is None:
        return ""
    try:
        return datetime.fromtimestamp(int(seconds)).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return ""


def _log(where: str, exc: BaseException) -> None:
    try:
        from ..error_log import log_exception

        log_exception(where, exc)
    except Exception:  # noqa: BLE001, S110 - logging never raises
        pass


@dataclass(frozen=True)
class KeyView:
    """What the vault and this device say about the key, and which record a proof must match.

    ``kind``: ``ok``, ``none``, ``damaged``, ``paused``, ``migrating`` or ``failed``.  ``reason`` (paused only):
    ``rollback``, ``missing``, ``damaged`` (16c, checked against ``seen_record``) or ``legacy`` (a pre-16c device
    file without the public key: the vault record is checked, as before 16c).  ``base`` is the record every
    proof is checked against and every new record descends from.
    """
    kind: str
    record: dict[str, Any] | None
    damaged: bool
    state: device.DeviceKeyState
    base: dict[str, Any] | None
    reason: str = ""
    pending: bool = False

    @property
    def seen_paused(self) -> bool:
        """Paused under 16c: only ``seen_record``'s password or the phrase bound in it goes on."""
        return self.kind == "paused" and self.reason != "legacy"

    @property
    def predecessor(self) -> dict[str, Any] | None:
        return self.base if self.seen_paused else None


class BackupKeyService:
    def __init__(self, controller: Any, *, clock: Callable[[], float] = time.time,
                 spawn: Callable[[Callable[[], None]], None] = _thread) -> None:
        self._controller = controller
        self._clock = clock
        self._spawn = spawn
        self._guard = threading.Lock()
        self._migrating: Any = None  # the session a migration runs for
        self._failed: Any = None  # the session whose migration failed (retried on the next unlock)
        # Held by a scheduled run from its start to its end, and by a change around its store and re-lock, so a
        # re-lock never races a run that prunes or publishes (review L6).
        self.files_lock = threading.Lock()
        self.on_change: list[Callable[[], None]] = []
        hooks = getattr(controller, "on_unlock", None)
        if isinstance(hooks, list):
            hooks.append(self._after_unlock)

    # ------------------------------------------------------------ helpers
    def _now(self) -> int:
        return int(self._clock())

    def _profile(self) -> Any:
        profile = self._controller.profiles.active_profile()
        if profile is None:
            raise ApiError("no_profile", t("recovery.chooseAProfileFirst"))
        return profile

    def _profile_dir(self, profile: Any) -> Path:
        return Path(self._controller.profiles.profile_dir(profile.id))

    def _folders(self, profile: Any) -> list[Path]:
        """This profile's own scheduled-backup folder and, if set and present, the mirror folder."""
        from ..backup_schedule import SCHEDULED_DIR_NAME

        folders = [Path(self._controller.profiles.backups_dir(profile.id)) / SCHEDULED_DIR_NAME]
        mirror = str(getattr(self._controller.settings, "backup_mirror_dir", "") or "").strip()
        if mirror:
            try:
                path = Path(mirror)
                if path.is_dir() and path.resolve() != folders[0].resolve():
                    folders.append(path)
            except OSError:
                # Best-effort file/OS step: failure is harmless here, so it is ignored.
                pass
        return folders

    def _lease(self) -> Any:
        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        lease = controller.guard.lease()
        controller.require_lease(lease)
        return lease

    def _changed(self) -> None:
        for listener in list(self.on_change):
            try:
                listener()
            except Exception:  # noqa: BLE001, S110 - a listener never undoes a saved key
                pass

    def _new_password(self, first: str | SecretText, second: str | SecretText) -> tuple[SecretText, bool]:
        """The checks of section 4 "Set": twice the same, 12-4096 characters, not the master password."""
        if not secrets_match(first, second):
            raise ApiError("invalid", t("settings.backupPassword.mismatch"))
        secret, owned = as_secret(first)
        try:
            if secret.char_count < MIN_PASSWORD_CHARS:
                raise ApiError("invalid", t("settings.backupPassword.tooShort"))
            if secret.char_count > MAX_PASSWORD_CHARS or 0 in secret.buffer:
                raise ApiError("invalid", t("backupKey.tooLong"))
            if self._matches_master(secret):
                raise ApiError("invalid", t("recoveryCenter.chooseABackupPasswordDifferent"))
        except BaseException:
            if owned:
                secret.wipe()
            raise
        return secret, owned

    def _derive_new(self, first: str | SecretText, second: str | SecretText,
                    old: str | SecretText | None = None) -> Any:
        from .. import backup
        from ..backup_key import derive_backup_key, new_kdf

        secret, owned = self._new_password(first, second)
        try:
            if old is not None and secrets_match(secret, old):
                raise ApiError("invalid", t("backupKey.sameAsOld"))
            return derive_backup_key(secret, new_kdf(parameters=backup.BACKUP_KDF))
        finally:
            if owned:
                secret.wipe()

    def _matches_master(self, secret: SecretText) -> bool:
        session = self._controller.session
        check = getattr(session, "_password_wrapper_matches", None)
        if check is None:
            return False
        try:
            return bool(check(secret))
        except Exception:  # noqa: BLE001 - the check is advisory; a malformed wrapper fails elsewhere
            return False

    def _save_seen(self, profile: Any, record: dict[str, Any]) -> None:
        try:
            device.update(self._profile_dir(profile), lambda state: device.seen(state, record))
        except OSError as exc:
            _log("backup-key-seen", exc)

    def _store(self, lease: Any, record: Any, *, predecessor: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """Save ``record`` (or a builder that gets the phrase snapshot under the session lock); returns it."""
        from ..vault import VaultError

        self._controller.require_lease(lease)
        try:
            return self._controller.session.set_scheduled_backup_key(record, predecessor=predecessor)
        except VaultError as exc:
            raise ApiError("invalid", str(exc) or t("settings.error.notSaved")) from None

    def _proof_key(self, record: dict[str, Any], password: str | SecretText) -> Any:
        """Proof (a): derive the private key with the record's parameters and match the public key."""
        import base64
        import hmac

        from ..backup_key import BackupKeyError, derive_backup_key

        try:
            key = derive_backup_key(password, record["kdf"])
        except BackupKeyError:
            raise ApiError("invalid", t("backupKey.notCurrent")) from None
        except Exception:  # noqa: BLE001 - e.g. an empty or oversized password
            raise ApiError("invalid", t("backupKey.notCurrent")) from None
        if not hmac.compare_digest(key.public_key, base64.b64decode(record["public_key"])):
            key.wipe()
            raise ApiError("invalid", t("backupKey.notCurrent"))
        return key

    # -------------------------------------------------------------- the view
    def view(self, session: Any = None) -> KeyView:
        """The key situation for ``session`` (default: the open one), sections 2.3, 5 and 16c."""
        from ..backup_key import DamagedRecordError

        session = self._controller.session if session is None else session
        empty = device.DeviceKeyState()
        try:
            pending = bool(session.scheduled_backup_migration_pending())
        except Exception:  # noqa: BLE001 - locked meanwhile
            return KeyView("none", None, False, empty, None)
        try:
            record, damaged = session.scheduled_backup_key(), False
        except DamagedRecordError:
            record, damaged = None, True
        try:
            directory = self._profile_dir(self._profile())
        except ApiError:
            directory = None
        state = device.load(directory) if directory is not None else empty
        if directory is not None and state.legacy_seen and record is not None \
                and (record["key_id"], record["set_at"]) == (state.seen_key_id, state.seen_set_at):
            # A pre-16c file that names this very record: keep its full public data from now on.
            try:
                state = device.update(directory, lambda current: device.seen(current, record)
                                      if current.legacy_seen and current.seen_key_id == record["key_id"]
                                      else current)
            except OSError as exc:
                _log("backup-key-seen", exc)
        with self._guard:
            running = self._migrating is session
            failed = self._failed is session
        seen = state.seen_record
        if seen is not None:
            if damaged:
                view = KeyView("paused", None, True, state, seen, "damaged", pending)
            elif record is None:
                view = KeyView("paused", None, False, state, seen, "missing", pending)
            elif device.is_paused(record, state):
                view = KeyView("paused", record, False, state, seen, "rollback", pending)
            else:
                view = KeyView("ok", record, False, state, record, "", pending)
        elif damaged:
            view = KeyView("damaged", None, True, state, None, "", pending)
        elif record is None:
            view = KeyView("none", None, False, state, None, "", pending)
        elif device.is_paused(record, state):
            view = KeyView("paused", record, False, state, record, "legacy", pending)
        else:
            view = KeyView("ok", record, False, state, record, "", pending)
        if running or pending:
            view = replace(view, kind="failed" if failed and pending and not running else "migrating")
        return view

    # ---------------------------------------------------------- migration
    def _after_unlock(self) -> None:
        session = self._controller.session
        try:
            pending = session is not None and session.scheduled_backup_migration_pending()
        except Exception:  # noqa: BLE001 - checked again by the scheduler
            pending = False
        if not pending:
            return
        self._start_migration(session)

    def _start_migration(self, session: Any) -> None:
        with self._guard:
            if self._migrating is session:
                return
            self._migrating = session
            if self._failed is session:
                self._failed = None
        try:
            self._spawn(lambda: self.migrate(session))
        except Exception as exc:  # noqa: BLE001 - e.g. no thread could be started
            _log("backup-key-migration-start", exc)
            with self._guard:
                self._migrating = None
                self._failed = session

    def _newest_old_format(self, folder: Path, tag: str) -> str:
        """Owner Q3: the newest scheduled backup in ``folder`` that is not version 3 (its header only is read)."""
        from ..backup import is_version3_backup
        from ..backup_schedule import owned_backups

        for path in owned_backups(folder, tag):
            if not is_version3_backup(path):
                return path.name
        return ""

    def migrate(self, session: Any) -> dict[str, Any] | None:
        """Section 5 for ``session``.  Touches no backup file: it lists the folders and reads headers only (Q3)."""
        try:
            if self._controller.session is not session or not session.scheduled_backup_migration_pending():
                return None
            profile = self._profile()
            directory = self._profile_dir(profile)
            # Q3, written before the vault save: keep the newest old-format scheduled backup and its mirror copy
            # out of pruning (never a version 3 file, also when a pre-migration vault comes back later).
            from ..backup_schedule import profile_tag

            names = [name for folder in self._folders(profile)
                     if (name := self._newest_old_format(folder, profile_tag(profile.id)))]
            if names:
                device.update(directory, lambda state: device.protect(state, names))
            record = session.migrate_scheduled_backup_password(self._now())
            if record is not None:
                def after(state: device.DeviceKeyState) -> device.DeviceKeyState:
                    if state.seen_key_id:
                        # A key was seen on this device: this vault came back from before the migration (16c).
                        return replace(state, confirm_key_id=record["key_id"])
                    return device.seen(state, record)

                try:
                    device.update(directory, after)
                except OSError as exc:
                    _log("backup-key-seen", exc)
                self._changed()
            return record
        except Exception as exc:  # noqa: BLE001 - retried on the next unlock; scheduled backups skip
            _log("backup-key-migration", exc)
            with self._guard:
                self._failed = session
            return None
        finally:
            with self._guard:
                if self._migrating is session:
                    self._migrating = None

    # ---------------------------------------------------------- scheduler
    def schedule_record(self) -> tuple[str, dict[str, Any] | None]:
        """``("ok", record)`` or why there is none: ``migrating``, ``failed``, ``none``, ``damaged``, ``paused``."""
        view = self.view()
        return (view.kind, view.record) if view.kind == "ok" else (view.kind, None)

    def protected_names(self) -> tuple[str, ...] | None:
        """Q3 names for ``prune``; ``None`` when unknown (prune then keeps every old-format file: fail closed)."""
        try:
            return device.protection(device.load(self._profile_dir(self._profile())))
        except ApiError:
            return None

    # -------------------------------------------------------------- state
    def status(self) -> dict[str, Any]:
        """The Backups page facts (no secret)."""
        controller = self._controller
        out: dict[str, Any] = {"has_key": False, "damaged": False, "set_at": None, "set_by": "", "reset_at": None,
                               "can_reset": False, "has_authority": False, "has_phrase": False,
                               "rebind_needed": False, "paused": False, "paused_reason": "", "seen_set_at": None,
                               "notice": "", "migrating": False}
        if not controller.is_unlocked():
            return out
        session = controller.session
        try:
            view = self.view(session)
        except Exception:  # noqa: BLE001 - a status only
            return out
        out["migrating"] = view.kind == "migrating"
        try:
            out["has_phrase"] = bool(session.has_recovery_phrase())
        except Exception:  # noqa: BLE001
            out["has_phrase"] = False
        out["damaged"] = view.damaged
        out["has_key"] = view.damaged or view.record is not None
        out["seen_set_at"] = view.state.seen_set_at
        if view.seen_paused:
            base = view.base
            out.update(paused=True, paused_reason=view.reason,
                       set_at=None if view.record is None else view.record["set_at"],
                       has_authority=base["reset_authority"] is not None,
                       can_reset=base["reset_authority"] is not None and out["has_phrase"])
            return out
        record = view.record
        if record is None:
            return out
        flagged = bool(session.scheduled_backup_key_rebind_needed())
        authority = record["reset_authority"] is not None
        out.update(
            set_at=record["set_at"], set_by=record["set_by"], reset_at=record["reset_at"],
            has_authority=authority,
            rebind_needed=out["has_phrase"] and (flagged or not authority),
            can_reset=authority and out["has_phrase"] and not flagged,
            paused=view.kind == "paused", paused_reason=view.reason,
            notice=device.upgrade_notice(record, view.state, self._now()),
        )
        return out

    # --------------------------------------------------------- operations
    def _settled(self, session: Any) -> KeyView:
        """The view for an operation: refused while a stored password still waits to migrate (L2), which then
        starts again if it failed."""
        view = self.view(session)
        if view.kind in ("migrating", "failed") or view.pending:
            if view.pending:
                self._start_migration(session)
            raise ApiError("invalid", t("backupKey.migrationPending"))
        return view

    def _refuse_while_paused(self, view: KeyView) -> None:
        if view.seen_paused:
            raise ApiError("invalid", t("backupKey.pausedRefused"))

    def _base(self, view: KeyView) -> dict[str, Any]:
        """The record a proof must match: ``seen_record`` while paused under 16c, else the vault's."""
        if view.base is not None:
            return view.base
        if view.damaged:
            raise ApiError("invalid", t("backupKey.damaged"))
        raise ApiError("invalid", t("backupKey.noKey"))

    def set_password(self, first: str | SecretText, second: str | SecretText) -> dict[str, Any]:
        """Section 4 "Set": only when there is no record and nothing proves one (16c), never while migrating (L2)."""
        from ..backup_key import build_record

        lease = self._lease()
        # A stored password waiting to migrate is in effect the current key: it is migrated first (L2).
        view = self._settled(self._controller.session)
        self._refuse_while_paused(view)
        if view.record is not None:
            raise ApiError("invalid", t("backupKey.alreadySet"))
        profile = self._profile()
        key = self._derive_new(first, second)
        try:
            if view.damaged:
                # A device that never saw a record (16c: as before): nothing can prove the damaged one.
                _log("backup-key-damaged-replaced", RuntimeError("a damaged backup key record was replaced by Set"))
            now = self._now()
            stored = self._store(lease, lambda snapshot: build_record(key, now=now, set_by="set",
                                                                      reset_authority=snapshot))
        finally:
            key.wipe()
        self._save_seen(profile, stored)
        self._changed()
        self._controller.touch()
        return {"message": t("backupKey.saved")}

    def change_password(self, old: str | SecretText, first: str | SecretText, second: str | SecretText, *,
                        relock: bool = True) -> dict[str, Any]:
        """Section 7: the old password proves the key; the new record goes to the vault; then the optional re-lock.

        While paused (16c) the old password must be ``seen_record``'s.  A scheduled run in flight finishes first
        and none starts until the re-lock ends (L6).  Once the new record is saved this never reports failure:
        each file's re-lock result is in the message (L4).
        """
        from ..backup_key import build_record

        lease = self._lease()
        view = self._settled(self._controller.session)
        base = self._base(view)
        profile = self._profile()
        old_key = self._proof_key(base, old)
        try:
            new_key = self._derive_new(first, second, old)
            try:
                if not self.files_lock.acquire(timeout=RUN_WAIT_SECONDS):
                    raise ApiError("busy", t("backupKey.busy"))
                try:
                    now = self._now()
                    stored = self._store(lease, lambda snapshot: build_record(
                        new_key, now=now, set_by="changed", reset_authority=snapshot, previous=base),
                        predecessor=view.predecessor)
                    self._save_seen(profile, stored)
                    self._changed()
                    message = t("backupKey.changed")
                    if relock:
                        message = self._relock(profile, old_key, stored)
                finally:
                    self.files_lock.release()
            finally:
                new_key.wipe()
        finally:
            old_key.wipe()
        self._controller.touch()
        return {"message": message}

    def _relock(self, profile: Any, old_key: Any, new_record: dict[str, Any]) -> str:
        """Section 7.2 after the new record is stored (files listed now, under ``files_lock``)."""
        from ..backup import relock_full_backups, sweep_relock_leftovers
        from ..backup_schedule import owned_backups, profile_tag

        try:
            folders = self._folders(profile)
            for folder in folders:
                sweep_relock_leftovers(folder)
            files = [path for folder in folders for path in owned_backups(folder, profile_tag(profile.id))]
            summary = relock_full_backups(files, old_key=old_key, new_record=new_record)
        except Exception as exc:  # noqa: BLE001 - the new password is saved; the files keep the old one
            _log("backup-key-relock", exc)
            return t("backupKey.changed") + " " + t("backupKey.relockFailed", count=1)
        message = t("backupKey.relocked", count=len(summary["relocked"]), left=len(summary["left"]))
        if summary["failed"]:
            for _path, error in summary["failed"]:
                _log("backup-key-relock", RuntimeError(str(error)))
            message += " " + t("backupKey.relockFailed", count=len(summary["failed"]))
        return message

    def reset_password(self, phrase: str, first: str | SecretText, second: str | SecretText) -> dict[str, Any]:
        """Section 6 with owner decision Q2: the phrase must be the bound one AND the vault's current one.

        While paused (16c) the phrase must be the one bound in ``seen_record``.
        """
        from ..backup_key import build_record, verify_reset_phrase
        from ..vault import RecoveryPhraseError, entropy_from_phrase

        lease = self._lease()
        session = self._controller.session
        view = self._settled(session)
        base = self._base(view)
        if base["reset_authority"] is None:
            raise ApiError("invalid", t("backupKey.cannotReset"))
        profile = self._profile()
        wrong = t("backupKey.wrongPhrase", date=short_date(base["set_at"]))
        try:
            entropy = bytearray(entropy_from_phrase(str(phrase or "")))
        except (RecoveryPhraseError, ValueError):
            raise ApiError("invalid", wrong) from None
        try:
            current = session.recovery_wrapper_snapshot()
            if not verify_reset_phrase(base, entropy, current):
                raise ApiError("invalid", wrong)
        finally:
            entropy[:] = bytes(len(entropy))
            phrase = ""
        new_key = self._derive_new(first, second)
        now = self._now()

        def build(snapshot: dict[str, str] | None) -> dict[str, Any]:
            if snapshot != current:  # the phrase was replaced after it was checked
                raise ApiError("invalid", wrong)
            return build_record(new_key, now=now, set_by="reset", reset_authority=snapshot, previous=base)

        try:
            stored = self._store(lease, build, predecessor=view.predecessor)
        finally:
            new_key.wipe()
        self._save_seen(profile, stored)
        self._changed()
        self._controller.touch()
        return {"message": t("backupKey.resetDone", date=short_date(now))}

    def rebind(self, password: str | SecretText) -> dict[str, Any]:
        """Owner decision Q2: bind the reset authority to the current phrase; needs the backup password."""
        from ..backup_key import validate_record

        lease = self._lease()
        view = self._settled(self._controller.session)
        self._refuse_while_paused(view)
        record = self._base(view)
        profile = self._profile()
        self._proof_key(record, password).wipe()
        stored = self._store(lease, lambda snapshot: validate_record(dict(record, reset_authority=snapshot)))
        self._save_seen(profile, stored)
        self._changed()
        self._controller.touch()
        return {"message": t("backupKey.rebound")}

    def confirm(self, password: str | SecretText) -> dict[str, Any]:
        """Lift a rollback pause (2.3, 16c).  Under 16c the password must be ``seen_record``'s, which is then
        written back into the vault; a pre-16c device file (no public key) checks the vault's record."""
        lease = self._lease()
        view = self._settled(self._controller.session)
        base = self._base(view)
        profile = self._profile()
        self._proof_key(base, password).wipe()
        if view.seen_paused:
            stored = self._store(lease, base, predecessor=base)
        else:
            self._controller.require_lease(lease)
            stored = base
        try:
            device.update(self._profile_dir(profile), lambda state: device.seen(state, stored))
        except OSError:
            raise ApiError("invalid", t("settings.error.notSaved")) from None
        self._changed()
        self._controller.touch()
        return {"message": t("backupKey.confirmed")}

    def remove(self, password: str | SecretText | None = None, phrase: str | None = None) -> dict[str, Any]:
        """Section 4 "Remove": proof (a) or (b), so that "remove, then set" can never replace "change"."""
        from ..backup_key import verify_reset_phrase
        from ..vault import RecoveryPhraseError, entropy_from_phrase

        lease = self._lease()
        session = self._controller.session
        view = self._settled(session)
        self._refuse_while_paused(view)
        if view.damaged:
            raise ApiError("invalid", t("backupKey.damaged"))
        record = self._base(view)
        if password:
            self._proof_key(record, password).wipe()
        elif phrase:
            try:
                entropy = bytearray(entropy_from_phrase(str(phrase)))
            except (RecoveryPhraseError, ValueError):
                raise ApiError("invalid", t("backupKey.wrongPhrase", date=short_date(record["set_at"]))) from None
            try:
                if not verify_reset_phrase(record, entropy, session.recovery_wrapper_snapshot()):
                    raise ApiError("invalid", t("backupKey.wrongPhrase", date=short_date(record["set_at"])))
            finally:
                entropy[:] = bytes(len(entropy))
        else:
            raise ApiError("invalid", t("backupKey.proofNeeded"))
        # A removal proved like this is deliberate: this device forgets the record, so a later Set is not taken
        # for a missing record (16c).  Forgotten first, so a failed write never leaves Set refused.
        directory = self._profile_dir(self._profile())
        try:
            device.update(directory, device.without_seen)
        except OSError:
            raise ApiError("invalid", t("settings.error.notSaved")) from None
        try:
            self._store(lease, None)
        except BaseException:
            self._save_seen(self._profile(), record)
            raise
        self._changed()
        self._controller.touch()
        return {"message": t("backupKey.removed")}

    def dismiss_notice(self) -> dict[str, Any]:
        """Owner decision Q1: hide the upgrade notice (the migration itself stays done)."""
        self._lease()
        record = self.view().record
        directory = self._profile_dir(self._profile())
        now = self._now()

        def change(state: device.DeviceKeyState) -> device.DeviceKeyState:
            kind = device.upgrade_notice(record, state, now)
            return device.dismiss(state, kind, now) if kind else state

        try:
            device.update(directory, change)
        except OSError:
            raise ApiError("invalid", t("settings.error.notSaved")) from None
        return {"message": ""}
