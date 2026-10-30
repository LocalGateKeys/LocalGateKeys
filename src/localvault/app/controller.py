"""The WebView UI's controller: profiles, unlock/create, lock and auto-lock (no UI toolkit).

Behaviour mirrors the Tk app's ``RuntimeActions`` (``ensure_unlocked``, ``lock``,
``require_lease``, ``_auto_lock_tick``); Windows Hello, camera unlock, the recovery
phrase and scheduled backups join in later stages.
"""
from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from typing import Any

from .. import licensing
from ..api.result import ApiError
from ..clipboard_guard import ClipboardGuard
from ..profiles import ProfileManager, ProfileRecord
from ..secret_text import SecretText, secrets_match
from ..session_guard import SessionGuard, StaleSession
from ..session_monitor import windows_idle_seconds
from ..settings import AppSettings
from ..unlock_policy import clear_master_unlock_requirement, master_unlock_required
from .unlock_backoff import UnlockBackoff, backoff_seconds_from_error, locked_subtitle, profile_chips
from ..i18n import t
from ..vault import (
    InvalidMasterPassword,
    UnlockThrottled,
    VaultError,
    VaultSession,
    create_vault,
    recovery_phrase_enrolled,
    unlock_vault,
)

LOCKED_STATUS = "palette.vaultLocked"
RECOVERY_RESET_TITLE = "controller.vaultReEncryptedWithA"
RECOVERY_RESET_TEXT = ("controller.yourNewMasterPasswordIs")
RECOVERY_PHRASE_LOST_TEXT = "controller.yourPreviousRecoveryPhraseNo"
RECOVERY_CLEANUP_TEXT = ("controller.theVaultHasBeenRe")


def _marker_stamp(profile_id: str) -> Any:
    """When the master-password marker last changed (another process may write it)."""
    from ..unlock_policy import _marker_path

    try:
        return _marker_path(profile_id).stat().st_mtime_ns
    except OSError:
        return None


def _os_error_message(exc: OSError) -> str:
    """A file-system failure without the path (it names the user and data folder)."""
    try:
        from .. import error_log

        error_log.log_exception("vault-file", exc)
    except Exception:  # noqa: BLE001, S110 - logging must not hide the real failure
        pass
    return t("controller.localgatekeysCouldNotReadOr")


class _DaemonScheduler:
    def call_later(self, delay: float, fn: Callable[[], None]) -> threading.Timer:
        timer = threading.Timer(max(0.0, delay), fn)
        timer.daemon = True
        timer.name = "localgatekeys-controller-tick"
        timer.start()
        return timer

    def cancel(self, handle: Any) -> None:
        if isinstance(handle, threading.Timer):
            handle.cancel()


class WebController:
    def __init__(self, *, profiles: ProfileManager, settings: AppSettings, bus: Any,
                 clock: Callable[[], float] = time.monotonic, scheduler: Any = None,
                 create_kwargs: dict[str, Any] | None = None) -> None:
        self.profiles = profiles
        self.settings = settings
        self._bus = bus
        self._clock = clock
        self._scheduler = scheduler or _DaemonScheduler()
        self._create_kwargs = dict(create_kwargs or {})
        self._lock = threading.RLock()
        # Every page call that reads or writes the vault, and every sync hold, takes this
        # lock, so a sync merge and a user save never interleave (the classic window got
        # the same exclusion by parking its single UI thread).
        self.vault_lock = threading.Lock()
        self._unlocking = False
        self._ticking = False
        self.session: VaultSession | None = None
        self.status = ""
        self.handover = False
        self.locked_at: float | None = None
        self.backoff = UnlockBackoff(clock)
        self.on_unlock: list[Callable[[], None]] = []
        self._extras_cache: tuple[Any, dict[str, Any]] | None = None
        # Alternative unlock methods register here ("hello", "camera" -> offered()).
        self.offers: dict[str, Callable[[], bool]] = {}
        # Windows Hello for routine re-authentication: (title, lease) -> verified.
        self.hello_reauth: Callable[[str, Any], bool] | None = None
        # The startup decision (legacy data) that must be made before any profile exists.
        self.startup: Any = None
        self.last_secret_use = 0.0
        active = profiles.active_profile()
        self.guard = SessionGuard(active.id if active else "", monotonic=clock)
        self.on_lock: list[Callable[[], None]] = []
        self.clipboard: Any = ClipboardGuard(timeout_seconds=settings.clipboard_clear_seconds)
        self.routine_reauth: tuple[Any, float] = (None, 0.0)

    # ---------------------------------------------------------------- state
    def _active(self) -> ProfileRecord | None:
        return self.profiles.active_profile()

    def is_unlocked(self) -> bool:
        return bool(self.session is not None and self.session.is_unlocked)

    def state(self) -> dict[str, Any]:
        startup = self.startup
        if startup is not None and startup.pending:
            return {"state": "legacy", "profile": None, "vault_exists": False, "legacy": startup.legacy_state(),
                    "autolock_seconds": int(self.settings.auto_lock_seconds or 0)}
        profile = self._active()
        if profile is None:
            return {"state": "no_profile", "profile": None, "vault_exists": False,
                    "autolock_seconds": int(self.settings.auto_lock_seconds or 0)}
        unlocked = self.is_unlocked()
        extras: dict[str, Any] = {}
        if not unlocked:
            extras = self._locked_extras(profile)
        return {
            **extras,
            "choose_profile": self.handover,
            "state": "unlocked" if unlocked else "locked",
            "profile": {"id": profile.id, "name": profile.name, "color": profile.color},
            "vault_exists": self.profiles.vault_path(profile.id).exists(),
            "autolock_seconds": int(self.settings.auto_lock_seconds or 0),
            "status": self.status,
            "appearance": str(getattr(self.settings, "appearance", "system") or "system"),
        }

    def _locked_extras(self, profile: ProfileRecord) -> dict[str, Any]:
        """Unlock-screen data: profile chips, "Locked … ago", backoff and the phrase link."""
        chips = profile_chips([(p.id, p.name) for p in self.profiles.list_profiles()], profile.id)
        phrase, required, offered = self._file_flags(profile)
        return {
            **offered,
            "hello_auto": bool(getattr(self.settings, "hello_auto_start", False)),
            "chips": [{"id": c.profile_id, "name": c.name, "initial": c.initial, "active": c.active} for c in chips],
            "subtitle": locked_subtitle(self.locked_at),
            "recovery_phrase": phrase,
            "backoff": math.ceil(self.backoff.remaining()),
            "backoff_message": self.backoff.message(),
            "master_required": required,
        }

    def _file_flags(self, profile: ProfileRecord) -> tuple[bool, bool, dict[str, bool]]:
        """Recovery-phrase enrolment and the master-required marker, re-read only when the vault file changes."""
        path = self.profiles.vault_path(profile.id)
        try:
            stamp = path.stat().st_mtime_ns
        except OSError:
            stamp = None
        key = (profile.id, stamp, self.status, _marker_stamp(profile.id))
        cached = self._extras_cache
        if cached is not None and cached[0] == key:
            return cached[1]["phrase"], cached[1]["required"], dict(cached[1]["offered"])
        try:
            phrase = bool(recovery_phrase_enrolled(path))
        except Exception:  # noqa: BLE001 - only decides whether a link is shown
            phrase = False
        try:
            required = bool(master_unlock_required(profile.id))
        except Exception:  # noqa: BLE001
            required = False
        offered = {"hello": False, "camera": False}
        for name, check in self.offers.items():
            try:
                offered[name] = bool(check()) and not required
            except Exception:  # noqa: BLE001 - an unavailable method is simply not offered
                offered[name] = False
        self._extras_cache = (key, {"phrase": phrase, "required": required, "offered": offered})
        return phrase, required, dict(offered)

    def _publish(self) -> dict[str, Any]:
        state = self.state()
        self._bus.emit("vault.state", state)
        return state

    def list_profiles(self) -> list[dict[str, Any]]:
        active = self._active()
        return [{"id": p.id, "name": p.name, "color": p.color, "active": bool(active and p.id == active.id)}
                for p in self.profiles.list_profiles()]

    def select_profile(self, profile_id: str) -> dict[str, Any]:
        with self._lock:
            if not any(p.id == profile_id for p in self.profiles.list_profiles()):
                raise ApiError("not_found", t("controller.thatProfileNoLongerExists"))
            hooks = self._lock_session() if self.is_unlocked() else []
            self.profiles.set_active(profile_id)
            self.guard.invalidate(profile_id)
            if self.handover:
                self.handover = False
                self.status = t("controller.profileSelectedVaultIsLocked")
        self._run_hooks(hooks)
        return self._publish()

    # --------------------------------------------------------- unlock/create
    def _begin(self) -> ProfileRecord:
        with self._lock:
            if self._unlocking:
                raise ApiError("busy", t("controller.unlockIsAlreadyInProgress"))
            profile = self._active()
            if profile is None:
                raise ApiError("no_profile", t("recovery.chooseAProfileFirst"))
            if self.guard.profile_id != profile.id:
                # Profile created or switched outside select_profile (first run).
                self.guard.invalidate(profile.id)
            self._unlocking = True
            return profile

    def _finish(self, profile: ProfileRecord, candidate: VaultSession, stamp: tuple[str, int], *,
                clear_marker: bool = True) -> dict[str, Any]:
        with self._lock:
            active = self._active()
            if self.guard.stamp() != stamp or active is None or active.id != profile.id:
                candidate.lock()
                raise ApiError("session_changed", t("controller.theProfileChangedWhileUnlocking"))
            candidate.trash_retention_days = self.settings.trash_retention_days
            candidate.trash_auto_purge = self.settings.trash_auto_purge
            # The free plan's item limit is in place before the session is published;
            # licensing.item_limit fails closed, and the unlock hooks only refine it.
            candidate.item_limit = licensing.item_limit()
            candidate.pro_features = licensing.pro_features()
            self.settings.fill_and_sign_in = candidate.fill_and_sign_in_enabled()
            # Open the lease before publishing the session: a tick in between
            # must never see an unlocked session with a closed guard.
            self.guard.open(self.settings.max_session_seconds)
            self.last_secret_use = self._clock()
            self.session = candidate
            self.status = ""
            if clear_marker:
                # Only a master-password (or recovery-phrase) unlock lifts an emergency lock.
                clear_master_unlock_requirement(profile.id)
            self.handover = False
            hooks = list(self.on_unlock)
        self._run_hooks(hooks)
        if getattr(candidate, "rollback_anchor_missing", False) is True:
            # The anti-rollback record was missing: say so (every unlock path finishes here).
            self._bus.emit("notice", {"kind": "error", "title": t("controller.rollbackProtectionWasReset"), "message": (
                t("controller.theVaultSLocalRollback"))})
        return self._publish()

    def unlock(self, password: str | SecretText) -> dict[str, Any]:
        """Unlock with the master password; a ``SecretText`` stays the caller's to wipe."""
        profile = self._begin()
        try:
            stamp = self.guard.stamp()
            path = self.profiles.vault_path(profile.id)
            if not path.exists():
                raise ApiError("no_vault", t("controller.thisProfileHasNoVault"))
            try:
                candidate = unlock_vault(path, password, backup_dir=self.profiles.backups_dir(profile.id),
                                         backup_count=self.settings.automatic_backup_count)
            except UnlockThrottled as exc:
                self.backoff.start(backoff_seconds_from_error(exc))
                raise ApiError("throttled", str(exc)) from None
            except InvalidMasterPassword as exc:
                raise ApiError("wrong_password", str(exc)) from None
            except VaultError as exc:
                raise ApiError("vault_error", str(exc)) from None
            except OSError as exc:
                raise ApiError("vault_error", _os_error_message(exc)) from None
            return self._finish(profile, candidate, stamp)
        finally:
            with self._lock:
                self._unlocking = False

    def create(self, password: str | SecretText, confirm: str | SecretText) -> dict[str, Any]:
        profile = self._begin()
        try:
            stamp = self.guard.stamp()
            if not secrets_match(password, confirm):
                raise ApiError("mismatch", t("controller.theMasterPasswordsDoNot"))
            try:
                candidate = create_vault(self.profiles.vault_path(profile.id), password,
                                         backup_dir=self.profiles.backups_dir(profile.id),
                                         backup_count=self.settings.automatic_backup_count,
                                         **self._create_kwargs)
            except VaultError as exc:
                raise ApiError("vault_error", str(exc)) from None
            except OSError as exc:
                raise ApiError("vault_error", _os_error_message(exc)) from None
            return self._finish(profile, candidate, stamp)
        finally:
            with self._lock:
                self._unlocking = False

    def unlock_alternative(self, build: Callable[[Any, Any, int], VaultSession]) -> dict[str, Any]:
        """Unlock with Windows Hello or the camera: ``build(path, backup_dir, backup_count)`` returns the session.

        Refused while a master-password unlock is required, and never clears that requirement.
        """
        profile = self._begin()
        try:
            if master_unlock_required(profile.id):
                raise ApiError("master_required", t("unlockMethods.useYourMasterPasswordThis"))
            stamp = self.guard.stamp()
            path = self.profiles.vault_path(profile.id)
            try:
                candidate = build(path, self.profiles.backups_dir(profile.id), self.settings.automatic_backup_count)
            except ApiError:
                raise
            except VaultError as exc:
                raise ApiError("vault_error", str(exc)) from None
            except OSError as exc:
                raise ApiError("vault_error", _os_error_message(exc)) from None
            return self._finish(profile, candidate, stamp, clear_marker=False)
        finally:
            with self._lock:
                self._unlocking = False

    def recover(self, phrase: str, new_password: str | SecretText, confirm: str | SecretText) -> dict[str, Any]:
        """Unlock with the recovery phrase and set a new master password at once.

        The reset rotates the data key and removes the Windows Hello and camera
        envelopes (see ``recover_with_phrase``); a notice tells the user so.
        """
        from .recovery_center import recover_with_phrase

        if not secrets_match(new_password, confirm):
            raise ApiError("mismatch", t("masterSheet.mismatch"))
        profile = self._begin()
        try:
            stamp = self.guard.stamp()
            report: dict[str, Any] = {}
            try:
                candidate = recover_with_phrase(self.profiles.vault_path(profile.id), str(phrase).strip(),
                                                new_password, backup_dir=self.profiles.backups_dir(profile.id),
                                                backup_count=self.settings.automatic_backup_count, report=report)
            except UnlockThrottled as exc:
                self.backoff.start(backoff_seconds_from_error(exc))
                raise ApiError("throttled", str(exc)) from None
            except VaultError as exc:
                raise ApiError("vault_error", str(exc)) from None
            except OSError as exc:
                raise ApiError("vault_error", _os_error_message(exc)) from None
            published = self._finish(profile, candidate, stamp)
        finally:
            with self._lock:
                self._unlocking = False
        self._recovery_notices(report)
        return published

    def _recovery_notices(self, report: dict[str, Any]) -> None:
        if report.get("recovery_phrase_invalidated"):
            self._bus.emit("notice", {"kind": "error", "title": t("controller.createANewRecoveryPhrase"),
                                      "message": t(RECOVERY_PHRASE_LOST_TEXT)})
        else:
            self._bus.emit("notice", {"kind": "info", "title": t(RECOVERY_RESET_TITLE), "message": t(RECOVERY_RESET_TEXT)})
        if report and not report.get("unlock_cleanup_complete", True):
            self._bus.emit("notice", {"kind": "error", "title": t("controller.oldLocalUnlockCleanupIncomplete"),
                                      "message": t(RECOVERY_CLEANUP_TEXT)})

    # ------------------------------------------------------------------ lock
    def _lock_session(self) -> list[Callable[[], None]]:
        """Lock under ``_lock``; returns the hooks to run once the lock is released."""
        self.guard.invalidate()
        if self.session is not None:
            self.session.lock()
        self.session = None
        self.last_secret_use = 0.0
        self.routine_reauth = (None, 0.0)
        try:
            self.clipboard.clear()
        except Exception:  # noqa: BLE001, S110 - a busy clipboard must not block the lock
            pass
        return list(self.on_lock)

    @staticmethod
    def _run_hooks(hooks: list[Callable[[], None]]) -> None:
        for callback in hooks:
            try:
                callback()
            except Exception:  # noqa: BLE001, S110 - every lock hook runs; one failure must not skip the rest
                pass

    def lock(self, reason: str = LOCKED_STATUS) -> dict[str, Any]:
        with self._lock:
            was_unlocked = self.is_unlocked()
            hooks = self._lock_session()
            self.status = "" if reason == LOCKED_STATUS else t(str(reason))
            if was_unlocked:
                self.locked_at = time.time()
        self._run_hooks(hooks)
        return self._publish()

    # ------------------------------------------------------------- auto-lock
    def touch(self) -> None:
        """Vault use (a secret revealed or copied): restarts the inactivity timer."""
        self.last_secret_use = self._clock()

    def _idle_seconds(self) -> float:
        idle = windows_idle_seconds() if self.settings.idle_source == "computer" else None
        if idle is None:
            idle = max(0.0, self._clock() - self.last_secret_use) if self.last_secret_use else 0.0
        return idle

    def require_lease(self, lease: Any) -> None:
        self.guard.require(lease)
        if not self.is_unlocked():
            raise StaleSession(t("controller.vaultIsLocked"))
        timeout = self.settings.auto_lock_seconds
        if timeout and self._idle_seconds() >= timeout:
            raise StaleSession(t("controller.inactivityTimeoutReached"))

    def idle_lock_remaining(self) -> int | None:
        if not self.is_unlocked():
            return None
        timeout = self.settings.auto_lock_seconds
        if not timeout:
            return None
        return max(0, math.ceil(timeout - self._idle_seconds()))

    def tick(self) -> None:
        with self._lock:
            if not self.is_unlocked():
                return
            try:
                self.require_lease(self.guard.lease())
            except StaleSession:
                stale = True
            else:
                stale = False
            remaining = self.idle_lock_remaining()
        if stale:
            reason = t("controller.maximumUnlockedSession") if self.guard.expired() else t("controller.inactivityTimeout")
            self.lock(t("controller.vaultLockedReached", reason=reason))
            return
        self._bus.emit("autolock.tick", {"remaining": remaining})

    def start(self) -> None:
        """Tick once a second until :meth:`stop`."""
        self._ticking = True

        def loop() -> None:
            if not self._ticking:
                return
            try:
                self.tick()
            except Exception as exc:  # noqa: BLE001 - logged; the next tick retries
                from .. import error_log

                error_log.log_exception("auto-lock", exc)
            finally:
                if self._ticking:
                    self._scheduler.call_later(1.0, loop)

        self._scheduler.call_later(1.0, loop)

    def stop(self) -> None:
        self._ticking = False
