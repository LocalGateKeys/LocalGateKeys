"""Scheduled backups for the WebView UI, following ``RuntimeActions._scheduled_backup_check``.

Checked every 60 s and 3 s after each unlock. The backup password is read
from the vault just before the run and handed to a worker thread that drops
it when done; results reach the page as ``toast`` events.
"""
from __future__ import annotations

import threading
from datetime import datetime
from typing import Any, Callable

from .setting_links import open_settings

SKIPPED = "Scheduled backup skipped: set a backup password first."
SKIPPED_ACTION = open_settings("backups")
FAILED = "Scheduled backup failed; the previous backup was kept. See the error log."
INTERVAL = 60
AFTER_UNLOCK = 3


def _thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True, name="lgk-scheduled-backup").start()


def _run_backup(*, profile_dir: Any, profile_name: str, password: str, directory: Any, tag: str, keep: int,
                when: datetime, mirror_dir: str) -> Any:
    from ..backup_schedule import full_backup_functions, run_scheduled_backup
    from ..error_log import log_exception

    secret = [password]

    def log(where: str, exc: BaseException) -> None:
        log_exception(where, exc, secrets=secret)

    try:
        make, verify = full_backup_functions(profile_dir=profile_dir, profile_name=profile_name,
                                             backup_password=secret[0])
        return run_scheduled_backup(directory=directory, tag=tag, keep=keep, when=when, make_backup=make,
                                    verify=verify, mirror_dir=mirror_dir, log=log)
    except Exception as exc:
        log("scheduled-backup", exc)
        raise
    finally:
        secret.clear()


class ScheduleRunner:
    def __init__(self, controller: Any, bus: Any, *, spawn: Callable[[Callable[[], None]], None] = _thread,
                 run_backup: Callable[..., Any] = _run_backup, now: Callable[[], datetime] = datetime.now) -> None:
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
        with self._claim:
            return self._check()

    def _check(self) -> bool:
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
        password = session.scheduled_backup_password()
        if not password:
            if not self._warned:
                self._warned = True
                self._toast(SKIPPED, "warning", SKIPPED_ACTION)
            return False
        self._running = True
        job = {"profile_dir": controller.profiles.profile_dir(profile.id), "profile_name": profile.name,
               "password": password, "directory": directory, "tag": profile_tag(profile.id),
               "keep": settings.scheduled_backup_keep, "when": now, "mirror_dir": settings.backup_mirror_dir}
        password = ""

        def work() -> None:
            try:
                result = self._run_backup(**job)
            except Exception:  # noqa: BLE001 - reported to the page; logged by the runner
                result = None
            finally:
                job.clear()
            self._finished(result)

        try:
            self._spawn(work)
        except Exception as exc:  # noqa: BLE001 - e.g. no thread could be started
            job.clear()
            self._log_spawn_failure(exc)
            self._finished(None)  # resets _running, sets _failed_at, sends FAILED
            return False
        return True

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
            self._toast(FAILED, "error")
            return
        self._failed_at = None
        if result.mirror_warning:
            self._toast(f"Scheduled backup saved. Mirror copy failed: {result.mirror_warning}", "warning")
        elif result.mirrored is not None:
            self._toast("Scheduled backup saved and copied to the mirror folder.")
        else:
            self._toast("Scheduled backup saved.")
