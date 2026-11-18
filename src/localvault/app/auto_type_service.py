"""Auto-type for the WebView UI (feature C4): type a login into the window the user used last.

The target is the window that was in front before LocalGateKeys took focus.  The app reports it with
``note_foreground`` (call it when the app window activates, passing the window that lost focus when
known); at run time a foreground window that is not ours is used directly.  The remembered window is
used only while its handle is valid and it still belongs to the same process.  LocalGateKeys is never
minimised to find a window.

Order: setting on -> unlocked -> a login -> not hidden by travel mode -> access rules allow fill ->
a window that is allowed (not ours, not elevated, not a secure desktop) -> re-authentication -> confirm
(optional, but always for a web browser) -> bring the window to the front -> type, re-checking the window
before every short batch of keys.

The two switches live in the vault's encrypted per-device preferences (``PREF_KEY``), so a same-user process
cannot turn auto-type on or the confirm step off by editing ``device-settings.json`` (scan 2026-11-15 W-L10).
That file only keeps a copy shown while the vault is locked (nothing can be typed then); an unlocked vault that
never stored the preference reads the safe defaults, off and confirm on, never the file (finding L6), so a
choice made in another profile does not carry over. Turning auto-type on or the confirm step off needs
re-authentication.
Python strings holding the username and password cannot be wiped (documented limit, W-L11).
"""
from __future__ import annotations

import os
from types import SimpleNamespace
from typing import Any

from .. import auto_type
from ..access_policy import enforced_policy
from ..api.result import ApiError
from ..device_settings import DeviceSettingsStore
from ..i18n import t
from ..session_guard import StaleSession
from ..vault import VaultError
from .secrets import SESSION_CHANGED, SecretService, _copy_once_used

# auto_type.AutoTypeError code -> i18n key of the refusal shown to the user
_REFUSALS = {
    "disabled": "autoType.disabled",
    "no_window": "autoType.noWindow",
    "own_window": "autoType.ownWindow",
    "elevated": "autoType.elevated",
    "secure_desktop": "autoType.secureDesktop",
    "foreground_changed": "autoType.changed",
    "send_failed": "autoType.changed",
    "unknown_key": "autoType.changed",
    "declined": "autoType.declined",
    "not_allowed": "autoType.notAllowed",
    "web_only": "autoType.webOnly",
}


def _refuse(code: str) -> ApiError:
    key = _REFUSALS.get(code, "autoType.changed")
    return ApiError(key.split(".", 1)[1], t(key))


def _default_platform() -> Any:
    if os.name != "nt":
        return None
    from ..auto_type_win import WindowsPlatform

    return WindowsPlatform()


PREF_KEY = "auto_type"  # encrypted per-device preference: {"enabled": bool, "confirm": bool}


class AutoTypeService:
    def __init__(self, controller: Any, port: Any, platform: Any = None, store: DeviceSettingsStore | None = None,
                 *, own_pid: int | None = None) -> None:
        self._controller = controller
        self._port = port
        self._platform = platform
        self._store = store if store is not None else DeviceSettingsStore()
        self._own_pid = os.getpid() if own_pid is None else int(own_pid)
        self._remembered: auto_type.Target | None = None

    @property
    def platform(self) -> Any:
        if self._platform is None:
            self._platform = _default_platform()
        return self._platform

    # ---------------------------------------------------------------- settings
    def _vault_session(self) -> Any:
        """The unlocked session when it keeps encrypted per-device preferences, else None."""
        try:
            if not self._controller.is_unlocked():
                return None
            session = self._controller.session
        except Exception:  # noqa: BLE001 - no session: the file copy is used
            return None
        if not callable(getattr(session, "_read_prefs", None)) or not callable(getattr(session, "_commit_prefs", None)):
            return None
        return session

    def _vault_value(self) -> dict[str, bool] | None:
        session = self._vault_session()
        if session is None:
            return None
        try:
            value = session._read_prefs().get(PREF_KEY)
        except Exception:  # noqa: BLE001 - unreadable: safe defaults below
            return {"enabled": False, "confirm": True}
        if not isinstance(value, dict):  # never stored here (None) or unreadable: the safe defaults
            return {"enabled": False, "confirm": True}
        return {"enabled": value.get("enabled") is True, "confirm": value.get("confirm") is not False}

    def settings_get(self) -> dict[str, bool]:
        stored = self._vault_value()
        if stored is not None:
            return stored
        current = self._store.load()
        return {"enabled": current.auto_type_enabled, "confirm": current.auto_type_confirm_window}

    def settings_set(self, enabled: bool, confirm: bool) -> dict[str, bool]:
        enabled, confirm = enabled is True, confirm is not False
        current = self.settings_get()
        turning_on = enabled and not current["enabled"]
        loosening = turning_on or (current["confirm"] and not confirm)
        if turning_on and not self._port.confirm(t("autoType.title"), t("autoType.enableHint")):
            raise ApiError("cancelled", t("error.cancelled"))
        if loosening:
            # Typing secrets into other windows, or without asking first: the master password, not Hello or the
            # recent-unlock grace (W-M4).
            _session, lease = self._session_and_lease()
            SecretService(self._controller, self._port).reauthenticate(t("autoType.title"), lease, allow_hello=False)
            self._require(lease)
        session = self._vault_session()
        if session is not None:
            try:
                session._commit_prefs({PREF_KEY: {"enabled": enabled, "confirm": confirm}})
            except VaultError as exc:
                raise ApiError("vault_error", str(exc)) from None
        self._store.update(auto_type_enabled=enabled, auto_type_confirm_window=confirm)
        if not enabled:
            self._remembered = None
        return self.settings_get()

    # ------------------------------------------------------------------ target
    def note_foreground(self, hwnd: int | None = None) -> None:
        """Remember ``hwnd`` (or the current foreground window) as the target, unless it is ours."""
        platform = self.platform
        if platform is None:
            return
        try:
            hwnd = int(hwnd) if hwnd else platform.foreground()
            target = platform.describe(hwnd) if hwnd else None
        except Exception:  # noqa: BLE001 - a failed lookup just remembers nothing
            return
        if target is not None and target.hwnd and target.pid != self._own_pid:
            self._remembered = target

    def _current(self, target: auto_type.Target) -> auto_type.Target | None:
        """``target`` as it is now, if the handle is valid and still the same process."""
        now = self.platform.describe(target.hwnd)
        if now is None or (now.pid, now.process) != (target.pid, target.process):
            return None
        return now

    def _resolve_target(self) -> auto_type.Target:
        platform = self.platform
        if platform is None:
            raise _refuse("no_window")
        hwnd = platform.foreground()
        target = platform.describe(hwnd) if hwnd else None
        if target is None or target.pid == self._own_pid:
            remembered = self._remembered
            target = self._current(remembered) if remembered is not None else None
            if target is None:
                self._remembered = None
                raise _refuse("no_window")
        self._check(target)
        return target

    def _check(self, target: auto_type.Target) -> None:
        try:
            auto_type._check_allowed(self.platform, target, self._own_pid)
        except auto_type.AutoTypeError as exc:
            raise _refuse(exc.code) from None

    # --------------------------------------------------------------------- run
    def _session_and_lease(self) -> tuple[Any, Any]:
        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        try:
            lease = controller.guard.lease()
            controller.require_lease(lease)
        except StaleSession:
            raise ApiError("session_changed", t(SESSION_CHANGED)) from None
        return controller.session, lease

    def _require(self, lease: Any) -> None:
        try:
            self._controller.require_lease(lease)
        except StaleSession:
            raise ApiError("session_changed", t(SESSION_CHANGED)) from None

    def run(self, ref: dict[str, Any]) -> dict[str, str]:
        if not self.settings_get()["enabled"]:
            raise _refuse("disabled")
        session, lease = self._session_and_lease()
        if not isinstance(ref, dict) or ref.get("source") != "credential":
            raise _refuse("web_only")
        item_id = str(ref.get("id") or "")
        from .. import travel

        if item_id in travel.hidden_id_set(session):
            raise _refuse("not_allowed")
        detail = session.credential_detail(item_id)
        if detail is None:
            raise ApiError("not_found", t("share.thisItemNoLongerExists"))
        try:
            revision = detail.get("revision")
            policy = enforced_policy(detail)
            username = str(detail.get("username") or "")
            scope = detail.get("scope")
            site = str(scope.get("origin") or "") if detail.get("kind") == "web" and isinstance(scope, dict) else ""
        finally:
            detail.clear()
        if not isinstance(revision, int):
            raise ApiError("changed", t("secrets.thisCredentialCannotBeVerified"))
        if policy.get("fill") == "never":
            raise _refuse("not_allowed")

        target = self._resolve_target()
        strict = bool(policy.get("require_master_password"))
        # Access rule "copy once": typing releases the password like a copy does, so a release after the first in
        # this unlock session needs the master password, and this one counts as the first (finding L4).
        once = policy.get("copy_once") is True
        secrets = SecretService(self._controller, self._port)
        if once and item_id in _copy_once_used(self._controller):
            secrets.reauthenticate(t("access.copyAgain"), lease, allow_hello=False)
        elif strict:
            secrets.reauthenticate(t("loginExtras.openSensitiveCredential"), lease, allow_hello=False)
        else:  # routine: Windows Hello or the recent-unlock grace, like copying a password
            secrets.reauthenticate(t("autoType.run"), lease, allow_hello=True)
        self._require(lease)
        now = self._current(target)  # the prompts took time: the window must still be there
        if now is None:
            raise _refuse("foreground_changed")
        target = now
        self._check(target)
        browser = auto_type.is_browser(target.process)
        # A browser window is always confirmed, whatever the setting (W-M4): its title is the page's, and nothing
        # here checks that the open site is the login's. The extension's fill is the origin-checked way.
        if browser or self.settings_get()["confirm"]:
            body = t("autoType.confirmBody", window=target.title or target.process, process=target.process)
            if browser:
                body += "\n\n" + (t("autoType.browserWarning", site=site) if site else t("autoType.browserWarningAny"))
            if not self._port.confirm(t("autoType.confirmTitle"), body):
                raise _refuse("declined")
        self._require(lease)
        if item_id in travel.hidden_id_set(session):
            raise _refuse("not_allowed")
        try:
            password = session.credential_secret(item_id, expected_revision=revision)
        except VaultError:
            raise ApiError("changed", t("secrets.thisCredentialChangedSelectIt")) from None
        steps = auto_type.sequence(username, password)
        del password
        if once:
            _copy_once_used(self._controller).add(item_id)
        try:
            platform = self.platform
            now = self._current(target)
            if now is None or not platform.activate(now.hwnd):
                raise _refuse("foreground_changed")
            now = self._current(now)
            if now is None:
                raise _refuse("foreground_changed")
            target = now
            self._require(lease)
            try:
                auto_type.run(platform, target, steps,
                              settings=SimpleNamespace(auto_type_enabled=True, auto_type_confirm_window=False),
                              countdown=0, own_pid=self._own_pid)
            except auto_type.AutoTypeError as exc:
                raise _refuse(exc.code) from None
        finally:
            steps.clear()
        self._remembered = target
        self._controller.touch()
        return {"message": t("autoType.typed", window=target.title or target.process)}


__all__ = ["AutoTypeService"]
