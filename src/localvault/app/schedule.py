"""Scheduled backups for the WebView UI, following ``RuntimeActions._scheduled_backup_check``.

Checked every 60 s and 3 s after each unlock. The public backup key record is
read from the vault just before the run (``BackupKeyService.schedule_record``)
and handed to a worker thread; no password is involved. Results reach the page
as ``toast`` events.
"""
from __future__ import annotations

import threading
from datetime import datetime
from typing import Any, Callable

from .setting_links import open_settings
from ..i18n import t

SKIPPED = "schedule.scheduledBackupSkippedSetA"
SKIPPED_ACTION = open_settings("backups")
# Why a due backup did not run (``BackupKeyService.schedule_record``), said once until settings change.
SKIPPED_BY_KIND = {"none": SKIPPED, "damaged": "schedule.skippedDamagedKey",
                   "paused": "schedule.skippedPaused", "failed": "schedule.skippedMigration"}
FAILED = "schedule.scheduledBackupFailedThePrevious"
INTERVAL = 60
AFTER_UNLOCK = 3


def _thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True, name="lgk-scheduled-backup").start()


def _run_backup(*, profile_dir: Any, profile_name: str, record: dict[str, Any], directory: Any, tag: str,
                keep: int, when: datetime, mirror_dir: str, protect_old: tuple[str, ...] | None = (),
                current_record: Callable[[], Any] | None = None,
                vault_filter: Callable[[dict[str, Any]], dict[str, Any]] | None = None) -> Any:
    from ..backup_schedule import full_backup_functions, run_scheduled_backup
    from ..error_log import log_exception

    def log(where: str, exc: BaseException) -> None:
        log_exception(where, exc)

    make, verify = full_backup_functions(profile_dir=profile_dir, profile_name=profile_name, record=record,
                                         current_record=current_record, vault_filter=vault_filter)
    try:
        return run_scheduled_backup(directory=directory, tag=tag, keep=keep, when=when, make_backup=make,
                                    verify=verify, mirror_dir=mirror_dir, log=log, protect_old=protect_old)
    except Exception as exc:
        log("scheduled-backup", exc)
        raise
    finally:
        make.discard()  # type: ignore[attr-defined]


class ScheduleRunner:
    def __init__(self, controller: Any, bus: Any, *, spawn: Callable[[Callable[[], None]], None] = _thread,
                 run_backup: Callable[..., Any] = _run_backup, now: Callable[[], datetime] = datetime.now,
                 keys: Any = None) -> None:
        if keys is None:
            from .backup_keys import BackupKeyService

            keys = BackupKeyService(controller)
        self.keys = keys
        keys.on_change.append(self.settings_changed)
        self._controller = controller
        self._bus = bus
        self._spawn = spawn
        self._run_backup = run_backup
        self._now = now
        self._running = False
        # check() runs from the 60 s timer and 3 s after each unlock: claim the run atomically.
        self._claim = threading.Lock()
        self._failed_at: datetime | None = None
        self._warned = False
        self._timer: Any = None
        # The emergency access service (HeirService), set by the bridge; its backup check runs on this timer.
        self.heir: Any = None
        # The duress service (DuressService), set by the bridge: it looks for other devices' duress markers.
        self.duress: Any = None
        controller.on_unlock.append(lambda: controller._scheduler.call_later(AFTER_UNLOCK, self._safe_check))

    def _toast(self, message: str, kind: str = "info", action: dict[str, Any] | None = None) -> None:
        self._bus.emit("toast", {"kind": kind, "message": message, **({"action": action} if action else {})})

    def _safe_check(self) -> None:
        try:
            self.check()
        except Exception:  # noqa: BLE001, S110 - a background check never takes the app down
            pass

    def start(self) -> None:
        def loop() -> None:
            self._safe_check()
            self._timer = self._controller._scheduler.call_later(INTERVAL, loop)

        self._timer = self._controller._scheduler.call_later(INTERVAL, loop)

    def settings_changed(self) -> None:
        self._warned = False

    def check(self) -> bool:
        from ..duress import is_decoy

        controller = self._controller
        if controller.is_unlocked() and is_decoy(controller.session):
            return False  # a duress session: no scheduled or heir backup, no emergency access look (sub-plan 08)
        self._heir_check()
        self._duress_check()
        with self._claim:
            return self._check()

    def _duress_check(self) -> None:
        """Duress markers of the owner's other devices in the sync folder (sub-plan 08), shown once per run."""
        watch = self.duress
        if watch is None:
            return
        try:
            watch.timer_check()
        except Exception:  # noqa: BLE001, S110 - a background check never takes the app down
            pass

    def _heir_check(self) -> None:
        """Emergency access (sub-plan 08): requests and missing denies on every owner device, and the heir
        folder's own daily backup on the device that made the plan, whatever the backup schedule."""
        heir = self.heir
        if heir is None:
            return
        try:
            heir.timer_check()
        except Exception:  # noqa: BLE001, S110 - a background check never takes the app down
            pass

    def _check(self) -> bool:
        from ..backup import without_share_records
        from ..backup_schedule import RETRY_AFTER, SCHEDULED_DIR_NAME, is_due, profile_tag, read_last_success

        controller = self._controller
        settings = controller.settings
        if settings.scheduled_backup_frequency == "off" or self._running or not controller.is_unlocked():
            return False
        session = controller.session
        profile = controller.profiles.active_profile()
        if session is None or profile is None:
            return False
        directory = controller.profiles.backups_dir(profile.id) / SCHEDULED_DIR_NAME
        now = self._now()
        if not is_due(now, read_last_success(directory), settings.scheduled_backup_frequency,
                      settings.scheduled_backup_time, settings.scheduled_backup_weekday):
            return False
        if self._failed_at is not None and now - self._failed_at < RETRY_AFTER:
            return False
        kind, record = self.keys.schedule_record()
        if kind == "migrating":
            return False  # the first unlock after the update is moving the stored password to a public key
        if record is None:
            if not self._warned:
                self._warned = True
                self._toast(t(SKIPPED_BY_KIND.get(kind, SKIPPED)), "warning", SKIPPED_ACTION)
            return False

        def current_record() -> Any:
            """The record as stored when the file is verified (9.1); the captured one once the vault locked."""
            if controller.session is session and controller.is_unlocked():
                try:
                    return session.scheduled_backup_key()
                except Exception:  # noqa: BLE001 - locked meanwhile, or damaged: verify against what was used
                    return record if not controller.is_unlocked() else None
            return record

        job = {"profile_dir": controller.profiles.profile_dir(profile.id), "profile_name": profile.name,
               "record": record, "directory": directory, "tag": profile_tag(profile.id),
               "keep": settings.scheduled_backup_keep, "when": now, "mirror_dir": settings.backup_mirror_dir,
               "protect_old": self.keys.protected_names(), "current_record": current_record,
               # Share keys never go into a backup (sub-plan 07, ruling F3): the vault file is sealed again
               # without its share records, with this unlocked session's key.
               "vault_filter": without_share_records(session)}
        # A backup-password change re-locks the same folders: never run beside it (review L6).
        files_lock = getattr(self.keys, "files_lock", None)
        if files_lock is not None and not files_lock.acquire(blocking=False):
            job.clear()
            return False
        self._running = True

        def release() -> None:
            if files_lock is not None:
                files_lock.release()

        def work() -> None:
            try:
                result = self._run_backup(**job)
            except Exception:  # noqa: BLE001 - reported to the page; logged by the runner
                result = None
            finally:
                job.clear()
                release()
            self._finished(result)

        try:
            self._spawn(work)
        except Exception as exc:  # noqa: BLE001 - e.g. no thread could be started
            job.clear()
            release()
            self._log_spawn_failure(exc)
            self._finished(None)  # resets _running, sets _failed_at, sends FAILED
            return False
        return True

    def _record_restore_test(self, result: Any) -> None:
        """Sub-plan 12: a verified scheduled backup passed the full restore dry run (with the writer's in-memory
        data key, design 9.1); record it as the weekly restore test. No password is stored or needed."""
        try:
            if not getattr(self._controller.settings, "restore_test_weekly", True):
                return
            from .. import restore_test

            profile = self._controller.profiles.active_profile()
            if profile is None:
                return
            restore_test.record_scheduled(restore_test.state_path(self._controller.profiles.profile_dir(profile.id)),
                                          getattr(result, "path", None), int(self._now().timestamp()))
        except Exception as exc:  # noqa: BLE001 - the backup itself succeeded; never fail it over the record
            self._log_spawn_failure(exc)

    @staticmethod
    def _log_spawn_failure(exc: BaseException) -> None:
        try:
            from ..error_log import log_exception

            log_exception("scheduled-backup-start", exc)
        except Exception:  # noqa: BLE001, S110 - logging never hides the toast
            pass

    def _finished(self, result: Any) -> None:
        self._running = False
        if result is None:
            self._failed_at = self._now()
            self._toast(t(FAILED), "error")
            return
        self._failed_at = None
        self._record_restore_test(result)
        if result.mirror_warning:
            self._toast(t("schedule.scheduledBackupSavedMirrorCopy", mirror_warning=result.mirror_warning), "warning")
        elif result.mirrored is not None:
            self._toast(t("schedule.scheduledBackupSavedAndCopied"))
        else:
            self._toast(t("schedule.scheduledBackupSaved"))
