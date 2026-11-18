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
from pathlib import Path
from typing import Any

from .. import duress, licensing
from ..api.result import ApiError
from ..clipboard_guard import ClipboardGuard
from ..profiles import ProfileManager, ProfileRecord
from ..secret_text import SecretText, secrets_match
from ..session_guard import SessionGuard, StaleSession
from ..session_monitor import windows_idle_seconds
from ..settings import AppSettings
from ..unlock_policy import clear_master_unlock_requirement, master_unlock_required
from .factors import (
    YubiKeyFailure,
    make_responder,
    remember_keyfile,
    safe_specs,
    safe_vault_id,
    unlock_factors,
)
from .unlock_backoff import UnlockBackoff, backoff_seconds_from_error, locked_subtitle, profile_chips
from ..i18n import t
from ..vault import (
    FactorMismatch,
    FactorRequired,
    FactorSecrets,
    InvalidMasterPassword,
    UnlockThrottled,
    VaultError,
    VaultSession,
    create_vault,
    recovery_phrase_enrolled,
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


def _spawn(work: Callable[[], None]) -> None:
    threading.Thread(target=work, name="localgatekeys-controller-job", daemon=True).start()


def _log(where: str, exc: BaseException) -> None:
    try:
        from .. import error_log

        error_log.log_exception(where, exc)
    except Exception:  # noqa: BLE001, S110 - logging never takes the app down
        pass


class _SessionProfiles:
    """The profile manager as the app sees it.

    While a duress session is open, the active profile's folder is the second vault's own folder
    (``duress.decoy_dir``): its documents, backups, open copies, onboarding and trusted-app files, and every
    ``vault_path`` a service asks for, resolve there, so nothing done in that session reads or writes the real
    vault's files.  Otherwise (and for any other profile) it is the plain ``ProfileManager``.
    """

    def __init__(self, manager: ProfileManager, controller: WebController) -> None:
        self._manager = manager
        self._controller = controller

    def __getattr__(self, name: str) -> Any:
        return getattr(self._manager, name)

    def _own_folder(self, profile_id: str | None) -> Path | None:
        session = self._controller.session
        if session is None or not duress.is_decoy(session) or not session.is_unlocked:
            return None
        active = self._manager.active_profile()
        if active is None or (profile_id is not None and profile_id != active.id):
            return None
        folder = Path(session.path).parent
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def profile_dir(self, profile_id: str | None = None) -> Path:
        return self._own_folder(profile_id) or self._manager.profile_dir(profile_id)

    def vault_path(self, profile_id: str | None = None) -> Path:
        folder = self._own_folder(profile_id)
        return folder / "vault.json" if folder is not None else self._manager.vault_path(profile_id)

    def settings_path(self, profile_id: str | None = None) -> Path:
        folder = self._own_folder(profile_id)
        return folder / "settings.json" if folder is not None else self._manager.settings_path(profile_id)

    def backups_dir(self, profile_id: str | None = None) -> Path:
        folder = self._own_folder(profile_id)
        if folder is None:
            return self._manager.backups_dir(profile_id)
        path = folder / "Backups"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def trusted_apps_path(self, profile_id: str | None = None) -> Path:
        folder = self._own_folder(profile_id)
        return folder / "trusted-apps.json" if folder is not None else self._manager.trusted_apps_path(profile_id)

    def restore_profile_path(self, record: ProfileRecord, *, require_absent: bool = True) -> Path:
        folder = None if require_absent else self._own_folder(record.id)
        return folder if folder is not None else self._manager.restore_profile_path(record,
                                                                                   require_absent=require_absent)


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
                 create_kwargs: dict[str, Any] | None = None, now: Callable[[], float] = time.time) -> None:
        # Per-profile paths follow the open session (a duress session's own folder, see _SessionProfiles).
        self.profiles: Any = _SessionProfiles(profiles, self)
        self.settings = settings
        self._bus = bus
        self._clock = clock
        # Wall-clock time (the duress hold, sub-plan 08); tests inject it.
        self._wall = now
        # Runs a background job off the unlock path (the duress marker write to a cloud folder).
        self.spawn: Callable[[Callable[[], None]], None] = _spawn
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
        # Alternative unlock methods register here ("hello", "camera", "security_key" -> offered()).
        self.offers: dict[str, Callable[[], bool]] = {}
        # Key file / YubiKey (app.factors.FactorService): ``yubikey_responder(slot)`` answers challenges,
        # ``factor_provider(kinds)`` supplies factors to a session that holds none (Hello, security key,
        # camera), and ``keyfile_used`` is (vault_id, path) of the key file used since the last unlock.
        self.yubikey_responder: Callable[[int], Callable[[bytes], bytes]] | None = None
        self.factor_provider: Callable[[Any], FactorSecrets | None] | None = None
        self.keyfile_used: tuple[str, str] | None = None
        # Windows Hello for routine re-authentication: (title, lease) -> verified.
        self.hello_reauth: Callable[[str, Any], bool] | None = None
        # The startup decision (legacy data) that must be made before any profile exists.
        self.startup: Any = None
        self.last_secret_use = 0.0
        active = profiles.active_profile()
        self.guard = SessionGuard(active.id if active else "", monotonic=clock)
        self.on_lock: list[Callable[[], None]] = []
        # Run before every lock takes ``_lock`` (FactorService cancels a pending YubiKey touch here, so a
        # factor change waiting inside the vault's session lock gives way at once).
        self.before_lock: list[Callable[[], None]] = []
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
        from ..device_erase import erased_notice

        # A vault erased after a sync removal (app.device_removal): said on the next screen until dismissed.
        erased = erased_notice()
        profile = self._active()
        if profile is None:
            return {"state": "no_profile", "profile": None, "vault_exists": False,
                    "autolock_seconds": int(self.settings.auto_lock_seconds or 0), "erased": erased}
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
            "erased": erased,
        }

    def _locked_extras(self, profile: ProfileRecord) -> dict[str, Any]:
        """Unlock-screen data: profile chips, "Locked … ago", backoff and the phrase link."""
        chips = profile_chips([(p.id, p.name) for p in self.profiles.list_profiles()], profile.id)
        phrase, required, offered = self._file_flags(profile)
        if self._held(profile):
            # The real vault is held after a duress unlock: no shortcut is offered (as if none were set up).
            offered = {name: False for name in offered}
        factors, vault_id = self._factor_flags()
        entry = (getattr(self.settings, "unlock_keyfile_paths", None) or {}).get(vault_id) if vault_id else None
        return {
            **offered,
            # The unlock screen's key-file row and YubiKey note (names only; the path stays in Python).
            "factors": factors,
            "keyfile_name": Path(entry).name if entry else None,
            "keyfile_remember": entry != "",
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
        key = (profile.id, stamp, self.status, _marker_stamp(profile.id),
               bool(getattr(self.settings, "unlock_factors_always_ask", False)))
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
        specs = safe_specs(path)
        offered = {"hello": False, "camera": False, "security_key": False}
        # "Always ask for the key file / YubiKey": no shortcut is offered for a vault with factors.
        blocked = bool(specs) and bool(getattr(self.settings, "unlock_factors_always_ask", False))
        for name, check in self.offers.items():
            try:
                offered[name] = bool(check()) and not required and not blocked
            except Exception:  # noqa: BLE001 - an unavailable method is simply not offered
                offered[name] = False
        factors = [{"kind": spec.kind, "slot": spec.slot} for spec in specs]
        self._extras_cache = (key, {"phrase": phrase, "required": required, "offered": offered,
                                    "factors": factors, "vault_id": safe_vault_id(path) if specs else ""})
        return phrase, required, dict(offered)

    def _held(self, profile: ProfileRecord) -> bool:
        """Whether the profile's real vault is held after a duress unlock (sub-plan 08)."""
        try:
            return duress.real_held(self.profiles.vault_path(profile.id), self._wall())
        except Exception:  # noqa: BLE001 - fail closed
            return True

    def _factor_flags(self) -> tuple[list[dict[str, Any]], str]:
        """The vault's factor list (kind, slot) and its vault_id, from the cache ``_file_flags`` filled."""
        cached = self._extras_cache
        if cached is None:
            return [], ""
        return [dict(item) for item in cached[1].get("factors", [])], str(cached[1].get("vault_id", ""))

    def shortcuts_blocked(self) -> bool:
        """Whether "Always ask" is on and the active vault has a key file / YubiKey (no Hello, key, camera)."""
        profile = self._active()
        if profile is None or not getattr(self.settings, "unlock_factors_always_ask", False):
            return False
        return bool(safe_specs(self.profiles.vault_path(profile.id)))

    def _publish(self) -> dict[str, Any]:
        state = self.state()
        self._bus.emit("vault.state", state)
        return state

    def list_profiles(self) -> list[dict[str, Any]]:
        active = self._active()
        return [{"id": p.id, "name": p.name, "color": p.color, "active": bool(active and p.id == active.id)}
                for p in self.profiles.list_profiles()]

    def select_profile(self, profile_id: str) -> dict[str, Any]:
        self._run_hooks(list(self.before_lock))
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

    def _apply_vault_item_counts(self, profile: ProfileRecord, candidate: Any) -> None:
        """Free plan: items in the other vaults count too; record this vault's count for them (sub-plan 12)."""
        try:
            # A duress session never writes the real profile's plaintext count (it would reveal the decoy).
            if not duress.is_decoy(candidate):
                self.profiles.record_item_count(profile.id, candidate.live_item_count())
            candidate.item_limit_offset = self.profiles.items_in_other_vaults(profile.id)
        except (AttributeError, OSError, ValueError, TypeError):
            candidate.item_limit_offset = 0

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
            self._apply_vault_item_counts(profile, candidate)
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

    def unlock(self, password: str | SecretText, factors: FactorSecrets | None = None, *,
               keyfile_path: str | None = None) -> dict[str, Any]:
        """Unlock with the master password (+ the key file / YubiKey of a v4 vault).

        Without ``factors`` they are built here: the key file at ``keyfile_path`` (picked on the unlock
        screen, then remembered unless "Don't remember") or the remembered one, and the YubiKey through
        ``yubikey_responder``.  A ``SecretText`` stays the caller's to wipe; the session holds the
        factors until it locks.
        """
        profile = self._begin()
        try:
            stamp = self.guard.stamp()
            path = self.profiles.vault_path(profile.id)
            if not path.exists():
                raise ApiError("no_vault", t("controller.thisProfileHasNoVault"))
            chosen = None
            if factors is None:
                factors, chosen = unlock_factors(self.settings, path, keyfile_path,
                                                 self.yubikey_responder or make_responder)
            try:
                # The real vault first, then the duress vault, with the same Argon2id work either way.
                candidate = duress.open_vault(path, password, factors=factors,
                                              backup_dir=self.profiles.backups_dir(profile.id),
                                              backup_count=self.settings.automatic_backup_count, upgrade_kdf=True,
                                              now=self._wall())
            except UnlockThrottled as exc:
                self.backoff.start(backoff_seconds_from_error(exc))
                raise ApiError("throttled", str(exc)) from None
            except InvalidMasterPassword as exc:
                raise ApiError("wrong_password", str(exc)) from None
            except FactorRequired as exc:
                raise ApiError("factor_required", str(exc)) from None
            except FactorMismatch as exc:
                raise ApiError("factor_mismatch", str(exc)) from None
            except YubiKeyFailure as exc:
                # Not a password attempt: never throttled, each with its own message (a cancel says nothing).
                raise exc.api_error() from None
            except VaultError as exc:
                raise ApiError("vault_error", str(exc)) from None
            except OSError as exc:
                raise ApiError("vault_error", _os_error_message(exc)) from None
            if chosen:
                vault_id = safe_vault_id(path)
                self.keyfile_used = (vault_id, str(chosen))
                if keyfile_path:
                    remember_keyfile(self.settings, vault_id, keyfile_path)
            if duress.is_decoy(candidate):
                return self._finish_duress(profile, candidate, stamp, path)
            published = self._finish(profile, candidate, stamp)
        finally:
            with self._lock:
                self._unlocking = False
        self._duress_notice(path)
        self._restore_test_at_unlock(profile, candidate)
        return published

    def _restore_test_at_unlock(self, profile: ProfileRecord, session: VaultSession) -> None:
        """Sub-plan 12: when the weekly restore test is due (no verified scheduled backup this week), open the
        newest rolling backup with the unlocked key. Best effort; never blocks or fails the unlock."""
        try:
            from .. import restore_test

            restore_test.run_at_unlock(session, restore_test.state_path(self.profiles.profile_dir(profile.id)),
                                       int(self._wall()), enabled=self.settings.restore_test_weekly)
        except Exception as exc:  # noqa: BLE001
            _log("restore-test", exc)

    def _finish_duress(self, profile: ProfileRecord, candidate: VaultSession, stamp: tuple[str, int],
                       path: Path) -> dict[str, Any]:
        """A duress unlock: hold the real vault, publish the session like any other, then sign the marker.

        Nothing here reaches the page: the published state is the same as for the real vault.
        """
        try:
            duress.trip(path, candidate, now=self._wall())
        except OSError as exc:
            _log("unlock-post", exc)  # a neutral tag: the error log can be opened from this session
        identity = duress.marker_identity(candidate)
        published = self._finish(profile, candidate, stamp, clear_marker=False)
        if identity is not None:
            when = self._wall()

            def write() -> None:
                try:
                    duress.mark_tripped(identity.folder, identity, now=when)
                except Exception as exc:  # noqa: BLE001 - logged; never shown in the duress session
                    _log("unlock-post", exc)

            try:
                self.spawn(write)
            except Exception as exc:  # noqa: BLE001
                _log("unlock-post", exc)
        return published

    def _duress_notice(self, path: Path) -> None:
        """After a real unlock: a finished hold is removed and the owner told when the duress password was used."""
        try:
            since = duress.release(path, now=self._wall())
        except Exception as exc:  # noqa: BLE001
            _log("duress-release", exc)
            return
        if since is None:
            return
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(since)) if since else "?"
        self._bus.emit("notice", {"kind": "error", "title": t("duress.usedHereTitle"),
                                  "message": t("duress.usedHere", time=when)})

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
            # A brand-new vault has no backup key: a record seen here before belongs to the old one (16c).
            from .. import backup_key_state

            try:
                backup_key_state.forget_seen(self.profiles.profile_dir(profile.id))
            except OSError:
                pass  # a newer-release or unwritable file: the old record then still needs its proof
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
            if master_unlock_required(profile.id) or self._held(profile):
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
                if self._held(profile):
                    # Held after a duress unlock: the phrase gets the same checks and work, then "wrong phrase".
                    duress.refuse_recovery(self.profiles.vault_path(profile.id), str(phrase).strip())
                candidate = recover_with_phrase(self.profiles.vault_path(profile.id), str(phrase).strip(),
                                                new_password, backup_dir=self.profiles.backups_dir(profile.id),
                                                backup_count=self.settings.automatic_backup_count, report=report,
                                                check_new=lambda opened: duress.check_new_master(opened,
                                                                                                 new_password))
            except duress.DuressError as exc:
                raise ApiError(exc.code, str(exc)) from None
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
        if report.get("factors_removed"):
            # The reset dropped the vault's key file / YubiKey (the phrase is the lost-factor way in).
            self._bus.emit("notice", {"kind": "info", "title": t("recovery.factorsRemovedTitle"),
                                      "message": t("recovery.factorsRemoved")})
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
        self.keyfile_used = None
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

    def dismiss_erased_notice(self) -> dict[str, Any]:
        from ..device_erase import dismiss_erased_notice

        dismiss_erased_notice()
        return self._publish()

    def lock(self, reason: str = LOCKED_STATUS) -> dict[str, Any]:
        # Every lock path (Lock, auto-lock, emergency lock, profile switch, session lock / RDP) comes here.
        self._run_hooks(list(self.before_lock))
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
