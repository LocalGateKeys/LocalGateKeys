"""Desktop app fill and binding for the WebView UI.

Ports ``RuntimeActions._desktop_field_icon_clicked`` / ``_fill_entry`` /
``bind_desktop_clicked`` and ``AgentApp._handle_desktop_icon_snapshot`` /
``_complete_desktop_binding`` / ``_complete_desktop_rebind``. Windows UI
Automation work runs off the vault lock on a COM-initialised thread; every
vault read or write runs through ``serialise`` (the agent host's
``run_on_ui``), so it never interleaves with page calls or sync. Choices go
through the page (``UiPort``); binding forms are a page sheet that receives a
single-use snapshot token. No field value is ever read from the target app.
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ..api.result import ApiError
from ..session_guard import StaleSession
from .setting_links import open_settings
from ..i18n import t

SCAN_MAX_AGE = 120.0  # seconds a scanned window may wait for the binding sheet

BROWSER_EXECUTABLE_NAMES = {"brave.exe", "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "vivaldi.exe"}
EMBEDDED_TOKENS = ("cef", "chrome", "chromium", "webview")
FAILED = ("desktop.desktopVerificationInputFailedThe")


def _safe(value: Any, limit: int = 160) -> str:
    text = "".join(ch for ch in str(value) if ch.isprintable())
    return text[:limit] + ("…" if len(text) > limit else "")


def _embedded(selector: dict[str, Any] | None) -> bool:
    if not isinstance(selector, dict):
        return False
    combined = f"{selector.get('framework_id', '')} {selector.get('class_name', '')}".casefold()
    return any(token in combined for token in EMBEDDED_TOKENS)


def _with_com(fn: Callable[[], Any]) -> Any:
    com = False
    try:
        if os.name == "nt":
            import pythoncom

            pythoncom.CoInitialize()
            com = True
        return fn()
    finally:
        if com:
            import pythoncom

            pythoncom.CoUninitialize()


class DesktopService:
    def __init__(self, controller: Any, port: Any, bus: Any, *, serialise: Callable[[Callable[[], Any]], Any],
                 ensure_unlocked: Callable[[], bool], reauthenticate: Callable[[str, Any], bool],
                 raise_window: Callable[[], None] = lambda: None, uia: Any = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        if uia is None:
            from .. import uia
        self._controller = controller
        self._port = port
        self._bus = bus
        self._serialise = serialise
        self._ensure_unlocked = ensure_unlocked
        self._reauthenticate = reauthenticate
        self._raise_window = raise_window
        self._uia = uia
        self._sleep = sleep
        self._clock = time.monotonic
        self._busy = threading.Lock()
        self._snapshots: dict[str, dict[str, Any]] = {}
        controller.on_lock.append(self._snapshots.clear)

    # ---------------------------------------------------------------- helpers
    def _status(self, text: str, kind: str = "info") -> None:
        self._bus.emit("toast", {"kind": kind, "message": text})

    @property
    def _session(self) -> Any:
        session = self._controller.session
        if session is None:
            raise ApiError("locked", t("desktop.theVaultLockedNothingWas"))
        return session

    def _lease(self) -> Any:
        lease = self._controller.guard.lease()
        self._controller.require_lease(lease)
        return lease

    def _uia_job(self, fn: Callable[[], Any]) -> Any:
        try:
            return _with_com(fn)
        except Exception:  # noqa: BLE001 - the app changed or refused input
            raise ApiError("desktop_failed", t(FAILED)) from None

    # -------------------------------------------------------------------- fill
    def fill_foreground(self) -> None:
        """The desktop-fill hotkey: fill the app in front (classic Ctrl+Shift+Space)."""
        hwnd = self._uia.foreground_hwnd() if hasattr(self._uia, "foreground_hwnd") else 0
        if not hwnd and os.name == "nt":
            import ctypes

            hwnd = int(ctypes.windll.user32.GetForegroundWindow())
        self.fill_window(hwnd)

    def fill_window(self, hwnd: int) -> None:
        """Fill one app window (the hotkey's foreground window, or the window the field button sat beside)."""
        if not self._busy.acquire(blocking=False):
            self._status(t("desktop.aDesktopOperationIsAlready"), "warning")
            return
        try:
            self._fill_window(hwnd)
        except ApiError as exc:
            if exc.code != "cancelled":
                self._status(exc.message, "error")
        except StaleSession:
            self._status(t("desktop.theVaultLockedNothingWas"), "warning")
        finally:
            self._busy.release()

    def _fill_window(self, hwnd: int) -> None:
        uia = self._uia
        snapshot = self._uia_job(lambda: uia.scan_window(hwnd))
        if Path(snapshot.exe_path).name.casefold() in BROWSER_EXECUTABLE_NAMES:
            self._status(t("desktop.useTheBrowserFieldIcon"))
            return
        if not any(c.enabled and c.visible and c.is_password for c in snapshot.controls):
            self._status(t("desktop.theDesktopPasswordFieldIs"))
            return
        was_locked = not self._controller.is_unlocked()
        if was_locked:
            self._raise_window()
        if not self._ensure_unlocked():
            return
        if was_locked:
            # The unlock took a while: match the binding against the window as it is now.
            snapshot = self._uia_job(lambda: uia.scan_window(hwnd))
            if not any(c.enabled and c.visible and c.is_password for c in snapshot.controls):
                self._status(t("desktop.theDesktopPasswordFieldIs"))
                return
        lease = self._lease()  # every prompt below is followed by a lease check: a lock or switch ends the fill
        entries = self._serialise(lambda: self._session.find_desktop(snapshot.exe_path))
        try:
            if not entries:
                self._offer_add(snapshot)
                return
            entry = entries[0]
            if len(entries) > 1:
                self._raise_window()
                options = [{"id": str(e.get("id", "")), "label": _safe(e.get("label", "")),
                            "detail": _safe(e.get("username", ""))} for e in entries]
                chosen = self._port.choose(t("desktop.chooseAccountForThisApp"), "", options)
                self._controller.require_lease(lease)
                entry = next((e for e in entries if str(e.get("id", "")) == chosen), None)
                if entry is None:
                    self._status(t("desktop.desktopFillCancelled"))
                    return
            if uia.desktop_entry_matches_snapshot(entry, snapshot):
                self._fill_entry(str(entry.get("id", "")), snapshot)
                return
            if self._updated_app(entry, snapshot, lease):
                return
            self._offer_rebind(entry, snapshot)
        finally:
            for item in entries or []:
                item.clear()

    def _updated_app(self, entry: dict[str, Any], snapshot: Any, lease: Any) -> bool:
        update = self._uia.updated_binary_binding(entry, snapshot)
        if update is None:
            return False
        updated, signer_verified = update
        try:
            approved = signer_verified
            scope = entry.get("scope")
            saved_title = str(scope.get("window_title", "")) if isinstance(scope, dict) else ""
            saved_layout = scope.get("control_fingerprint") if isinstance(scope, dict) else None
            layout_changed = saved_layout != snapshot.control_fingerprint()
            if signer_verified and (saved_title != snapshot.title or layout_changed):
                # Same (or same-signer) program, another window or other login fields: never adopt
                # its title or layout silently, it may be a different login screen of the same app.
                self._raise_window()
                approved = self._port.confirm(t("desktop.appWindowChanged"), t(
                    "desktop.windowAndFieldsChanged" if layout_changed else "desktop.windowChanged",
                    app=_safe(Path(snapshot.exe_path).name), exe_path=_safe(snapshot.exe_path),
                    saved_title=_safe(saved_title), title=_safe(snapshot.title)))
            if not signer_verified:
                self._raise_window()
                approved = self._port.confirm(t("desktop.appWasUpdated"), (
                    t("desktop.changedSinceThisLoginWas", app=_safe(Path(snapshot.exe_path).name), exe_path=_safe(snapshot.exe_path), title=_safe(snapshot.title))))
            self._controller.require_lease(lease)
            if not approved:
                self._status(t("desktop.updatedAppWasNotTrusted"))
                return True
            entry_id = str(entry.get("id", ""))
            self._serialise(lambda: self._controller.require_lease(lease) or self._session.accept_desktop_update(
                entry_id, exe_sha256=snapshot.exe_sha256, window_title=snapshot.title,
                control_fingerprint=snapshot.control_fingerprint()))
            self._fill_entry(entry_id, snapshot)
            return True
        finally:
            updated.clear()

    def _offer_rebind(self, entry: dict[str, Any], snapshot: Any) -> None:
        self._raise_window()
        label, username = _safe(entry.get("label", "")), _safe(entry.get("username", ""))
        account = t("desktop.theSelectedLocalgatekeysAccount") + (f" ({label})" if label else "") + (f" — {username}" if username else "")
        approved = self._port.confirm(t("desktop.refreshSavedDesktopBinding"), t(
            "desktop.accountSavedChanged", account=account, app=_safe(Path(snapshot.exe_path).name),
            title=_safe(snapshot.title)))
        if not approved:
            self._status(t("desktop.savedDesktopBindingWasNot"))
            return
        token = self._remember(snapshot, entry_id=str(entry.get("id", "")), fill_after=True, dynamic=True)
        self._bus.emit("navigate", {"route": "desktop-bind", "params": {"token": token}})

    def _offer_add(self, snapshot: Any) -> None:
        self._raise_window()
        approved = self._port.confirm(t("desktop.addDesktopLogin"), (
            t("desktop.noSavedLoginExistsFor", app=_safe(Path(snapshot.exe_path).name), title=_safe(snapshot.title))))
        if not approved:
            self._status(t("desktop.desktopLoginWasNotAdded"))
            return
        token = self._remember(snapshot, fill_after=True)
        self._bus.emit("navigate", {"route": "desktop-bind", "params": {"token": token}})

    def _fill_entry(self, entry_id: str, snapshot: Any) -> None:
        from ..access_policy import may_sign_in, normalized_policy

        uia = self._uia
        lease = self._lease()
        entry = self._serialise(lambda: self._session.get_entry(entry_id))
        if not entry:
            self._status(t("desktop.theEntryWasRemoved"), "error")
            return
        try:
            if not uia.desktop_entry_matches_snapshot(entry, snapshot):
                self._status(t("desktop.appBindingChangedRebindExplicitly"), "warning")
                return
            policy = normalized_policy(entry.get("policy"))
            if policy["fill"] == "never":
                self._status(t("desktop.fillingIsDisabledForThis"))
                return
            if policy["require_master_password"] and not self._reauthenticate(t("desktop.authorizeDesktopFill"), lease):
                return
            scope = entry.get("scope", {})
            selector = scope.get("password_selector") or {}
            warnings = []
            if not selector.get("is_password"):
                warnings.append(t("desktop.thisFieldIsNotMarked"))
            embedded = _embedded(selector)
            if embedded and not scope.get("embedded_web_fill_approved"):
                warnings.append(t("desktop.thisAppDisplaysEmbeddedWeb"))
            if warnings:
                self._raise_window()
                answer = self._port.confirm_remember(
                    t("desktop.confirmDesktopFill"),
                    t("desktop.localgatekeysFoundASavedCredential")
                    + "\n".join(warnings)
                    + t("desktop.appWindow", app=_safe(Path(snapshot.exe_path).name), title=_safe(snapshot.title)),
                    t("desktop.rememberApprovalForThisSaved") if embedded else "")
                self._controller.require_lease(lease)
                if not answer.get("approved"):
                    return
                if answer.get("remember") and embedded:
                    self._serialise(lambda: self._session.set_desktop_embedded_fill_approval(entry_id, True))
            self._controller.require_lease(lease)
            do_sign_in = may_sign_in(entry, self._controller.settings.fill_and_sign_in) and isinstance(
                scope.get("sign_in_selector"), dict)
            submitted = self._uia_job(lambda: uia.fill_desktop_entry(
                entry, snapshot, guard=lambda: self._controller.require_lease(lease), sign_in=do_sign_in))
            self._controller.touch()
            self._status(t("desktop.credentialsFilledSignInInvoked") if submitted
                         else t("desktop.credentialsFilledSignInManually"))
        finally:
            entry.clear()

    def fill_entry_now(self, entry_id: str) -> dict[str, Any]:
        """The Fill button on a desktop login: switch to the app; checked after 3 seconds."""
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", t("desktop.aDesktopOperationIsAlready"))
        try:
            self._sleep(3)
            snapshot = self._uia_job(self._uia.scan_foreground_window)
            self._fill_entry(entry_id, snapshot)
        finally:
            self._busy.release()
        return {}

    # ----------------------------------------------------------------- binding
    def _remember(self, snapshot: Any, *, entry_id: str | None = None, fill_after: bool = False,
                  dynamic: bool = False) -> str:
        token = secrets.token_urlsafe(12)
        self._snapshots.clear()  # one binding at a time
        self._snapshots[token] = {"snapshot": snapshot, "entry_id": entry_id, "fill_after": fill_after,
                                  "dynamic": dynamic, "at": self._clock()}
        return token

    def _held(self, token: str, *, sign_in: bool = False) -> dict[str, Any]:
        """A remembered scan, for two minutes: an older one may no longer describe the app's window."""
        held = self._snapshots.get(str(token))
        if held is not None and self._clock() - held["at"] > SCAN_MAX_AGE:
            self._snapshots.pop(str(token), None)
            held = None
        if held is None or bool(held.get("sign_in")) != sign_in:  # a button scan never rebinds, and back
            raise ApiError("expired", t("desktop.inspectTheAppAgain"))
        return held

    # ------------------------------------------------------ sign-in button
    def sign_in_buttons(self, entry_id: str) -> dict[str, Any]:
        """Find the saved app's login window and list its buttons (classic "Map sign-in button")."""
        import copy

        from ..uia import scan_bound_window

        lease = self._lease()

        def binding() -> dict[str, Any]:
            entry = self._session.get_entry(entry_id)
            if not entry or entry.get("kind") != "desktop":
                if entry:
                    entry.clear()
                raise ApiError("invalid", t("desktop.selectADesktopLoginFirst"))
            try:  # only non-secret binding metadata leaves the vault call
                return {"kind": "desktop", "scope": copy.deepcopy(entry.get("scope", {}))}
            finally:
                entry.clear()
        bound = self._serialise(binding)
        scan = getattr(self._uia, "scan_bound_window", scan_bound_window)
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", t("desktop.aDesktopOperationIsAlready"))
        try:
            snapshot = self._uia_job(lambda: scan(bound, include_buttons=True, include_all_buttons=True))
        finally:
            self._busy.release()
        self._controller.require_lease(lease)
        buttons = [b for b in snapshot.buttons if b.visible and b.enabled]
        if not buttons:
            raise ApiError("refused", t("desktop.noVisibleUiAutomationButtons"))
        token = self._remember(snapshot, entry_id=entry_id)
        self._snapshots[token]["sign_in"] = True
        self._snapshots[token]["lease"] = lease  # the save belongs to this session only
        current = (bound["scope"].get("sign_in_selector") or {}).get("name") or t("desktop.notMapped")
        return {"token": token, "app": _safe(Path(snapshot.exe_path).name), "title": _safe(snapshot.title),
                "current": _safe(str(current)),
                "buttons": [{"index": b.index, "name": _safe(b.name)} for b in buttons]}

    def map_sign_in(self, token: str, index: int) -> dict[str, Any]:
        held = self._held(token, sign_in=True)
        lease = held["lease"]
        self._controller.require_lease(lease)
        snapshot, entry_id = held["snapshot"], held["entry_id"]
        visible = [b for b in snapshot.buttons if b.visible and b.enabled]
        control = next((b for b in visible if b.index == index), None)
        if control is None:
            raise ApiError("invalid", t("desktop.chooseOneOfTheListed"))
        selector = control.selector()
        selector["explicit_user_mapping"] = True
        stable = bool(selector.get("automation_id") or selector.get("class_name"))
        selector["identity_mode"] = "exact_metadata" if stable else "unique_name"
        if not stable and sum(1 for b in visible if b.name == control.name) != 1:
            raise ApiError("refused", t("desktop.thisLoginActionExposesOnly"))
        note = (t("desktop.thisButtonExposesAStable") if stable else
                t("desktop.thisAppDoesNotExpose"))
        if not self._port.confirm(t("desktop.trustThisLoginAction"), (
                t("desktop.actionWindowTheVerifiedApplication", name=_safe(control.name), title=_safe(snapshot.title), note=note))):
            raise ApiError("cancelled", t("error.cancelled"))
        self._controller.require_lease(lease)  # a lock or switch during the prompt ends it here
        if self._snapshots.pop(str(token), None) is None:
            raise ApiError("expired", t("desktop.inspectTheAppAgain"))
        from ..vault import VaultError

        try:
            self._serialise(lambda: self._controller.require_lease(lease)
                            or self._session.bind_sign_in(entry_id, selector))
        except VaultError as exc:
            raise ApiError("invalid", str(exc)) from None
        self._controller.touch()
        self._bus.emit("items.changed", {})
        return {"message": t("desktop.signInButtonSavedIt", name=_safe(control.name)),
                "action": open_settings("autofill")}

    def require_web_warning(self, entry_id: str) -> dict[str, Any]:
        """Ask before filling embedded web content in this app again."""
        lease = self._lease()
        self._serialise(lambda: self._controller.require_lease(lease)
                        or self._session.set_desktop_embedded_fill_approval(entry_id, False))
        return {"message": t("desktop.localgatekeysWillWarnBeforeFilling")}

    def scan_for_binding(self, entry_id: str | None = None) -> dict[str, Any]:
        """Bind (or rebind) a desktop login: the user switches to the app; it is inspected after 3 seconds."""
        if os.name != "nt":
            raise ApiError("unsupported", t("desktop.desktopBindingIsAvailableOnly"))
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", t("desktop.aDesktopOperationIsAlready"))
        try:
            self._sleep(3)
            snapshot = self._uia_job(self._uia.scan_foreground_window)
        finally:
            self._busy.release()
        return {"token": self._remember(snapshot, entry_id=entry_id), **self.binding_form_for(snapshot)}

    def binding_form(self, token: str) -> dict[str, Any]:
        held = self._held(token)
        return {"token": token, "rebind": bool(held["entry_id"]), **self.binding_form_for(held["snapshot"])}

    def binding_form_for(self, snapshot: Any) -> dict[str, Any]:
        if not snapshot.title.strip():
            raise ApiError("refused", t("desktop.unsupportedUntitledWindowTheForeground"))
        if Path(snapshot.exe_path).name.casefold() in BROWSER_EXECUTABLE_NAMES:
            raise ApiError("refused", t("desktop.useTheBrowserExtensionLocalgatekeys"))
        if not snapshot.controls:
            raise ApiError("refused", t("desktop.unsupportedLoginUiThisWindow"))
        default_user, default_password = self._uia.choose_default_selectors(snapshot.controls)
        return {
            "title": _safe(snapshot.title), "app": _safe(snapshot.exe_path),
            "intro": t("desktop.selectTheUsernameAndPassword"),
            "controls": [{"index": c.index, "password": bool(c.is_password),
                          "label": f"#{c.index}  {'PASSWORD' if c.is_password else 'text'}  "
                                   f"name={_safe(c.name or '-', 80)}  id={_safe(c.automation_id or '-', 80)}"}
                         for c in snapshot.controls],
            "user_index": (default_user or {}).get("index"), "password_index": (default_password or {}).get("index"),
            "label": _safe(snapshot.title or Path(snapshot.exe_path).stem),
        }

    def save_binding(self, token: str, user_index: int | None, password_index: int, label: str = "",
                     username: str = "", password: str = "") -> dict[str, Any]:
        from ..vault import ItemLimitReached, VaultError

        held = self._held(token)
        snapshot, entry_id = held["snapshot"], held["entry_id"]
        if not entry_id:
            # Checked before the scan is used up, so a typo does not mean inspecting the app again.
            if not str(label).strip():
                raise ApiError("invalid", t("desktop.enterALabel"))
            if not password:
                raise ApiError("invalid", t("desktop.enterThePasswordIntoLocalgatekeys"))
        self._snapshots.pop(str(token), None)
        by_index = {c.index: c for c in snapshot.controls}
        password_control = by_index.get(password_index)
        if password_control is None:
            raise ApiError("invalid", t("desktop.chooseThePasswordControl"))
        user_control = by_index.get(user_index) if user_index is not None else None
        if not password_control.is_password and not self._port.confirm(
                t("desktop.unprotectedUiaField"), t("desktop.theSelectedFieldIsNot")):
            raise ApiError("cancelled", t("error.cancelled"))
        password_selector = password_control.selector()
        if _embedded(password_selector) and not self._port.confirm(
                t("desktop.embeddedWebContent"), t("desktop.thisFieldAppearsToBe")):
            raise ApiError("cancelled", t("error.cancelled"))
        signer = snapshot.signer
        signer_valid = (isinstance(signer, dict) and str(signer.get("status", "")).casefold() == "valid"
                        and bool(signer.get("thumbprint")))
        discord = self._uia._is_discord_executable(snapshot.exe_path)
        mode = ("discord_stable" if discord else "dynamic_layout" if held["dynamic"]
                else "embedded_web_volatile" if _embedded(password_selector) else "strict")
        common = dict(exe_path=snapshot.exe_path, exe_sha256=snapshot.exe_sha256, window_title=snapshot.title,
                      control_fingerprint=snapshot.control_fingerprint(),
                      username_selector=user_control.selector() if user_control is not None else None,
                      password_selector=password_selector, signer=signer if signer_valid else None,
                      binding_mode=mode)
        lease = self._lease()
        try:
            if entry_id:
                self._serialise(lambda: self._session.update_desktop_binding(entry_id, **common))
                message = (t("desktop.dynamicDesktopBindingRefreshedStable") if held["dynamic"] else
                           t("desktop.embeddedWebBindingRefreshedVolatile")
                           if mode == "embedded_web_volatile" else
                           t("desktop.desktopCredentialReboundWithStrict"))
            else:
                entry_id = self._serialise(lambda: self._session.add_desktop(
                    label=str(label).strip(), username=str(username), password=password, **common))
                signer_text = (signer or {}).get("subject") if signer_valid else t("desktop.noValidSignerPin")
                message = t("desktop.boundTo", label=label, exe_path=snapshot.exe_path, signer_text=_safe(str(signer_text)))
        except ItemLimitReached as exc:
            self._port.show_upgrade(limit=exc.limit, message=str(exc), on_enter=lambda: None)
            raise ApiError("item_limit", str(exc)) from None
        except VaultError as exc:
            raise ApiError("invalid", str(exc)) from None
        finally:
            password = ""
        self._controller.require_lease(lease)
        self._controller.touch()
        self._bus.emit("items.changed", {})
        if held["fill_after"] and self._port.confirm(
                t("desktop.fillTheAppNow"), t("desktop.fillIntoNow", label=_safe(str(label or t("desktop.thisLogin"))), title=_safe(snapshot.title))):
            try:
                self._fill_entry(entry_id, snapshot)
            except ApiError as exc:
                self._status(exc.message, "error")
        return {"message": message, "entry_id": entry_id}
