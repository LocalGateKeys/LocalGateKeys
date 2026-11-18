"""Erase this PC's copy of a vault after another device removed it from sync (WP-A).

``RemovalGuard.check`` reads each profile's sync watch file (``sync.removal``), and erases a profile
only when a removal notice signed by a member it trusted verifies (``removal.check``) and the setting
"Erase this device if it is removed from sync" (``erase_on_sync_removal``) is on.  It runs at start,
every ``CHECK_INTERVAL_SECONDS`` while the app runs (locked or not), and soon after a folder run
reports ``removal-notice``.  The ambiguous sync issues (``removed-or-conflict``...) never get here.

The erase itself is ``device_erase.erase_profile``; the vault is locked first when it is open.  The
next screen (and the next start) shows a plain notice until it is dismissed.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

CHECK_INTERVAL_SECONDS = 300.0


def _install_id() -> str:
    from ..sync.install import load_or_create_install_id

    return load_or_create_install_id()


class RemovalGuard:
    def __init__(self, controller: Any, *, install_id: Callable[[], str] = _install_id,
                 erase: Callable[..., list[str]] | None = None,
                 interval: float = CHECK_INTERVAL_SECONDS) -> None:
        from ..device_erase import erase_profile

        self._controller = controller
        self._install_id = install_id
        self._erase = erase or erase_profile
        self._interval = interval
        self._mu = threading.Lock()
        self._timer: threading.Timer | None = None
        self._stopped = False

    # ------------------------------------------------------------ schedule
    def start(self) -> None:
        """Check now (off the caller's thread), then every ``interval`` seconds until ``stop``."""
        self._stopped = False
        self.check_soon()

    def stop(self) -> None:
        self._stopped = True
        timer, self._timer = self._timer, None
        if timer is not None:
            timer.cancel()

    def check_soon(self) -> None:
        threading.Thread(target=self._run, name="lgk-removal-check", daemon=True).start()

    def _run(self) -> None:
        try:
            self.check()
        except Exception as exc:  # noqa: BLE001 - logged; the next check retries
            from ..error_log import log_exception

            log_exception("sync-removal", exc)
        finally:
            if not self._stopped and self._interval > 0:
                timer = threading.Timer(self._interval, self._run)
                timer.daemon = True
                old, self._timer = self._timer, timer
                if old is not None:
                    old.cancel()
                timer.start()

    # --------------------------------------------------------------- check
    def check(self) -> list[str]:
        """Erase every profile with a verified removal notice (setting on); returns their ids."""
        from ..sync import removal

        if not self._mu.acquire(blocking=False):
            return []  # a check is already running
        try:
            if not bool(getattr(self._controller.settings, "erase_on_sync_removal", True)):
                return []
            profiles = self._controller.profiles
            install = self._install_id()
            erased: list[str] = []
            for profile in profiles.list_profiles():
                vault = profiles.root / "Profiles" / profile.id / "vault.json"
                if removal.check_file(removal.watch_path(vault), install_id=install) is None:
                    continue
                if self._erase_profile(profile.id):
                    erased.append(profile.id)
            return erased
        finally:
            self._mu.release()

    def _erase_profile(self, profile_id: str) -> bool:
        controller = self._controller
        active = controller.profiles.active_profile()
        if active is not None and active.id == profile_id and controller.is_unlocked():
            controller.lock()
        with controller._lock:  # no unlock can start while the files go
            if active is not None and active.id == profile_id and (controller.is_unlocked() or controller._unlocking):
                return False  # unlocked again meanwhile: the next check erases it
            left = self._erase(controller.profiles, profile_id)
        if left:
            from ..error_log import log_exception

            # The profile row and its watch file stay: the next check tries again.
            log_exception("sync-removal", OSError(f"{len(left)} file(s) of an erased vault could not be removed"))
            return False
        now_active = controller.profiles.active_profile()
        controller.guard.invalidate(now_active.id if now_active is not None else "")
        controller._extras_cache = None
        controller._publish()
        return True
