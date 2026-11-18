"""The agent host for the WebView UI: the classic browser broker and native integrations, without Tk.

``BrowserBroker`` (and its passkey mixin), the named-pipe server, the tray,
the global hotkeys and the Windows session monitor are already Tk-free. They
expect "the app" to provide a handful of things that the classic ``AgentApp``
implemented on the Tk thread; this class provides those on top of
``WebController`` and the page's ``WebUiPort``.

``run_on_ui`` — the classic "do this on the UI thread" — becomes "do this
while holding ``controller.vault_lock``": the lock every vault-touching page
call and every sync hold also takes, so a browser request never interleaves
with them, exactly as the single Tk thread serialised them.
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any, Callable, TypeVar

from ..browser_broker import BrowserBroker
from ..i18n import t

T = TypeVar("T")
_log = logging.getLogger(__name__)
UNLOCK_TOAST = "host.localgatekeysIsLockedUnlockIt"


class _ReleasingPort:
    """The UI port as the broker sees it: while a prompt waits for the user, the vault lock is free."""

    def __init__(self, host: "WebAgentHost", port: Any) -> None:
        self._host = host
        self._port = port

    def __getattr__(self, name: str) -> Any:
        value = getattr(self._port, name)
        if not callable(value):
            return value

        def call(*args: Any, **kwargs: Any) -> Any:
            return self._host.released_while_waiting(lambda: value(*args, **kwargs))
        return call


class WebAgentHost(BrowserBroker):
    def __init__(self, controller: Any, port: Any, bus: Any, *, window: Any = None,
                 unlock_timeout: float = 90.0, popup: Any = None) -> None:
        self._controller = controller
        self._port = port
        # Fills started outside the app (field button, hotkey, browser) ask in the small popup window,
        # as the classic compact dialogs did, instead of bringing the whole app to the front.
        self._popup = popup
        self._popup_lock = threading.Lock()
        self._unlock_waits = 0
        self._popup_cancelled = threading.Event()
        view = port
        if popup is not None and hasattr(port, "popup_view"):
            view = port.popup_view(on_show=self.show_popup, on_idle=self._popup_idle)
        self.popup_port = view
        if popup is not None:
            hooks = getattr(popup, "on_disable", None)
            if isinstance(hooks, list):
                hooks.append(self._popup_disabled)
            if getattr(popup, "disabled", False):
                self._popup_disabled()
        self.ui = _ReleasingPort(self, view)
        self._holding = threading.local()  # does this thread hold the vault lock through run_on_ui?
        self._bus = bus
        self._window = window
        self._unlock_timeout = unlock_timeout
        self._remote_busy = False
        self.last_extension_seen = 0.0
        self.last_extension_version = ""
        self.last_secret_use = 0.0
        self._closing = False
        self._posted: queue.Queue[Callable[[], None] | None] = queue.Queue()
        self._poster: threading.Thread | None = None
        self.integrations: list[Any] = []
        self.cli_service: Any = None
        self.agent_gate_service: Any = None  # AI agents through `lgk mcp` (app/agent_gate_service.py)
        self.ssh_agent_server: Any = None
        self._ssh_agent_factory: Callable[[WebAgentHost], Any] | None = None
        self._ssh_agent_lock = threading.Lock()
        # The quick-search palette window (``PaletteWindow``); None keeps the app's Quick access page.
        self.palette: Any = None

    # ------------------------------------------------- what the broker expects
    def duress_session(self) -> bool:
        """Whether the open session is a duress session (sub-plan 08): no browser extension, Windows passkey
        provider, command line or SSH agent request is served from it, as if the vault were locked."""
        from ..duress import is_decoy

        return self._controller.is_unlocked() and is_decoy(self._controller.session)

    @property
    def session(self) -> Any:
        if not self._controller.is_unlocked() or self.duress_session():
            return None
        return self._controller.session

    def _session_available(self) -> bool:
        return not self.duress_session() and super()._session_available()

    def dispatch_remote(self, request: dict[str, Any]) -> dict[str, Any]:
        if self.duress_session() and not (isinstance(request, dict) and request.get("action") == "ping"):
            return {"ok": False, "error": "integration_disabled"}
        return super().dispatch_remote(request)

    @property
    def guard(self) -> Any:
        return self._controller.guard

    @property
    def settings(self) -> Any:
        return self._controller.settings

    @property
    def active_profile(self) -> Any:
        return self._controller.profiles.active_profile()

    def require_lease(self, lease: Any) -> None:
        self._controller.require_lease(lease)

    def _touch_secret(self) -> None:
        self.last_secret_use = time.monotonic()
        self._controller.touch()

    def refresh_entries(self) -> None:
        self._bus.emit("items.changed", {})

    @staticmethod
    def _validate_remote_text(value: Any, field: str, max_len: int, allow_empty: bool) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{field} must be text")
        if not allow_empty and not value:
            raise ValueError(f"{field} cannot be empty")
        if len(value) > max_len or "\x00" in value:
            raise ValueError(f"{field} is invalid")
        return value

    def run_on_ui(self, function: Callable[[], T], timeout: float = 90.0) -> T:
        """Run ``function`` serialised with page calls and sync (the classic UI-thread contract).

        Re-entrant on the thread that already holds the vault lock through ``run_on_ui`` (as a call made on the UI
        thread runs at once): the broker's handlers run under the lock, and a nested call from them (the agent
        gate's activity record when an agent-approved fill releases the password) must not wait on its own lock.
        """
        if getattr(self._holding, "held", False):
            return function()
        lock = self._controller.vault_lock
        if not lock.acquire(timeout=max(0.0, float(timeout))):
            raise TimeoutError("Interaction timed out; retry with a new explicit action")
        self._holding.held = True
        try:
            return function()
        finally:
            self._holding.held = False
            lock.release()

    def released_while_waiting(self, wait: Callable[[], T]) -> T:
        """Run a wait for the user (a prompt, an unlock) with the vault lock released, as the classic modal
        dialogs let the rest of the UI run. The broker re-checks its lease after every prompt."""
        if not getattr(self._holding, "held", False):
            return wait()
        lock = self._controller.vault_lock
        self._holding.held = False
        lock.release()
        try:
            return wait()
        finally:
            lock.acquire()
            self._holding.held = True

    def approve_local_client(self, request: Any) -> bool:
        """Ask in the popup whether a local client (SSH agent, CLI) may have an item; remembered for 10 minutes.

        Not the browser broker's path: it never touches ``_remote_busy`` and holds no vault lock while the user decides.
        """
        return self.approve_local_clients([request])

    def approve_local_clients(self, requests: list[Any]) -> bool:
        """One popup for several items of one client (``lgk run``/``inject``); each approval is remembered alone."""
        from ..local_clients.approvals import default_approvals

        def ask(pending: list[Any]) -> tuple[bool, bool]:
            first = pending[0]
            client = first.client
            key = "local_clients.prompt.ssh" if first.kind == "ssh_sign" else "local_clients.prompt.cli"
            if key == "local_clients.prompt.cli" and len(pending) > 1:
                key = "local_clients.prompt.cliMany"
            message = t(key, program=client.label, host=client.host_name, count=len(pending),
                        item=", ".join(req.item_title for req in pending), detail=first.detail)
            answer = self.ui.confirm_remember("LocalGateKeys", message, t("local_clients.remember"))
            return answer.get("approved") is True, answer.get("remember") is True
        return default_approvals().check_or_ask_many(list(requests), ask, time.monotonic())

    def ensure_unlocked(self, stop: Callable[[], bool] | None = None) -> bool:
        """Unlocked now, or after the user unlocks in the window (raised for them) within the timeout.

        ``stop`` (polled with the wait) ends the wait early with False, e.g. when the Windows passkey request
        was cancelled or ran past its deadline; the popup is then hidden like any finished unlock wait.
        """
        controller = self._controller
        if self.duress_session():
            return False  # never served from a duress session, and no window is raised for it
        if controller.is_unlocked():
            return True
        startup = getattr(controller, "startup", None)
        if startup is not None and startup.pending:
            return False
        if self._popup is None:
            self.raise_window()
            self._bus.emit("toast", {"kind": "info", "message": t(UNLOCK_TOAST)})
        else:
            with self._popup_lock:
                if self._unlock_waits == 0:
                    self._popup_cancelled.clear()
                self._unlock_waits += 1
            self.show_popup()  # the compact unlock (profile chips, password, Hello, camera)
        deadline = time.monotonic() + self._unlock_timeout

        def wait() -> bool:
            while time.monotonic() < deadline and not self._closing and not self._popup_cancelled.is_set():
                if stop is not None and stop():
                    return False
                if controller.is_unlocked():
                    return True
                time.sleep(0.1)
            if stop is not None and stop():
                return False
            return controller.is_unlocked()
        try:
            return self.released_while_waiting(wait)
        finally:
            if self._popup is not None:
                with self._popup_lock:
                    self._unlock_waits -= 1
                self._popup_idle()

    # ------------------------------------------------------------ the popup
    def show_popup(self) -> None:
        popup = self._popup
        self.hide_palette()  # an approval in the popup is never covered by the on-top palette
        if popup is None:
            self.raise_window()
            return
        try:
            shown = popup.show()
        except Exception:  # noqa: BLE001 - fall back to the main window
            _log.debug("Popup could not be shown", exc_info=True)
            shown = False
        if shown is False:
            # A disabled popup (R-9): never let a prompt wait on a window that cannot appear.
            self.raise_window()

    def _popup_disabled(self) -> None:
        """The popup can never be shown: its prompts go to the main window, which shows them (R-9)."""
        view = self.popup_port
        if view is not self._port and hasattr(view, "_surface"):
            view._surface = None
            view._on_show = self.raise_window
            view._on_idle = None

    def _popup_idle(self) -> None:
        """Hide the popup once no fill waits for an unlock or an answer in it."""
        popup = self._popup
        if popup is None:
            return
        with self._popup_lock:
            busy = self._unlock_waits > 0
        pending = getattr(self._port, "pending_on", lambda _s: 0)("popup")
        if not busy and not pending:
            try:
                popup.hide()
            except Exception:  # noqa: BLE001
                _log.debug("Popup could not be hidden", exc_info=True)

    def popup_closed(self) -> None:
        """The user closed the popup: the waiting fill and its prompts are cancelled."""
        self._popup_cancelled.set()
        cancel = getattr(self._port, "cancel_surface", None)
        if cancel is not None:
            cancel("popup")
        if self._popup is not None:
            try:
                self._popup.hide()
            except Exception:  # noqa: BLE001
                pass

    def reauthenticate(self, title: str, lease: Any, *, allow_hello: bool = False, fresh: bool = False) -> bool:
        from ..api.result import ApiError
        from ..app.secrets import SecretService

        try:
            native = getattr(self._controller, "hello_reauth", None)
            hello = None if native is None else (
                lambda t, l: self.released_while_waiting(lambda: native(t, l)))
            SecretService(self._controller, self.ui, hello=hello).reauthenticate(
                title, lease, allow_hello=allow_hello, fresh=fresh)
            return True
        except ApiError:
            return False
        except Exception:  # noqa: BLE001 - a failed check is a refusal, never a crash on the pipe thread
            _log.warning("Re-authentication failed", exc_info=True)
            return False

    # ----------------------------------------------------- window and status
    def raise_window(self) -> None:
        window = self._window
        if window is not None and hasattr(window, "raise_window"):
            try:
                window.raise_window()
            except Exception:  # noqa: BLE001 - best effort
                _log.debug("Window could not be raised", exc_info=True)

    def show_main_window(self) -> None:
        if self._window is not None and hasattr(self._window, "show"):
            self._window.show()

    def hide_main_window(self) -> None:
        if self._window is not None and hasattr(self._window, "hide"):
            self._window.hide()

    def set_status(self, text: str, kind: str = "info") -> None:
        self._bus.emit("toast", {"kind": kind, "message": str(text)})

    # -------------------------------------------------------------- locking
    def lock(self, reason: str = "palette.vaultLocked") -> None:
        self.hide_palette()  # the palette never outlives the vault it searched
        self._controller.lock(t(reason))

    def emergency_lock(self) -> None:
        from ..app.lockmodes import LockModes

        self._overlay_off()
        self.hide_palette()
        LockModes(self._controller).emergency_lock()

    def lock_and_switch_person(self) -> None:
        from ..app.lockmodes import LockModes

        self._overlay_off()
        LockModes(self._controller).lock_and_switch()
        self.show_main_window()

    # ------------------------------------------------- posting off a thread
    def post(self, fn: Callable[[], None]) -> None:
        """Run ``fn`` on the host's own worker (hotkey, tray and monitor callbacks arrive on their threads)."""
        if self._poster is None or not self._poster.is_alive():
            self._poster = threading.Thread(target=self._drain, name="lgk-host-post", daemon=True)
            self._poster.start()
        self._posted.put(fn)

    def _drain(self) -> None:
        while True:
            fn = self._posted.get()
            if fn is None:
                return
            try:
                fn()
            except Exception:  # noqa: BLE001 - one failed callback must not stop the worker
                _log.exception("Host callback failed")

    _post_to_ui = post


    # ------------------------------------------------------- native integrations
    on_exit: Callable[[], None] | None = None
    desktop_fill: Callable[[], None] | None = None

    def start_integrations(self, *, pipe: Any = None, hotkey: Any = None, monitor: Any = None,
                           tray: Any = None, overlay: Any = None, ssh_agent: Any = None) -> None:
        """Start the pipe server, global hotkeys, session monitor, tray, field button and, when it is on in
        Settings › Developer, the SSH agent (the real app only)."""
        if overlay is None:
            from ..desktop_overlay import DesktopFieldOverlay as overlay
        if pipe is None:
            from ..pipe_transport import NamedPipeAgentServer as pipe
        if hotkey is None:
            from ..hotkey import HotkeyListener as hotkey
        if monitor is None:
            from ..session_monitor import WindowsSessionMonitor as monitor
        if tray is None:
            from ..tray import TrayController as tray
        controller = self._controller
        from ..cli_service import CliService

        # Requests from the installed lgk.exe (pipe scope "cli") go to the CLI service, never the broker.
        self.cli_service = CliService(self)
        from ..app.agent_gate_service import AgentGateService

        self.agent_gate_service = AgentGateService(self)
        # Requests from the Windows passkey provider (pipe scope "system_passkey") reach only dispatch_system.
        self.server = pipe(self.dispatch_remote, cli_dispatcher=self.cli_service.dispatch_from_pid,
                           system_dispatcher=self.dispatch_system)
        # The fill waits on page prompts, so it gets its own thread: lock hotkeys and the tray never queue behind it.
        self._hotkey_factory = hotkey
        self.hotkey = self._make_hotkey(self._quick_hotkey())
        self.session_monitor = monitor(self._session_lock_requested)
        self.tray = tray(
            on_open=lambda: self.post(self._open_window),
            on_lock=lambda: self.post(self.lock),
            on_unlock=lambda: self.post(self._open_window),
            on_toggle_browser=lambda: self.post(self._toggle_browser),
            on_toggle_desktop=lambda: self.post(self._toggle_desktop),
            on_exit=lambda: self.post(self._exit),
            state=self._tray_state,
            on_switch=lambda: self.post(self.lock_and_switch_person),
            on_quick_access=lambda: self.post(self.quick_access),
            on_check_updates=lambda: self.post(lambda: self._navigate("updates")))
        from ..app.desktop import BROWSER_EXECUTABLE_NAMES

        self.overlay = overlay(on_click=self._overlay_clicked,
                               ignored_executables=set(BROWSER_EXECUTABLE_NAMES) | {"localgatekeys.exe"})
        for name in ("server", "hotkey", "session_monitor", "tray", "overlay"):
            component = getattr(self, name)
            try:
                component.start()
            except Exception as exc:  # noqa: BLE001 - one unavailable integration must not stop the app
                _log.warning("%s could not start: %s", name, exc)
                if name == "hotkey":
                    self.set_status(t("host.agentRunningHotkeyUnavailable2", exc=exc), "warning")
            else:
                if name == "hotkey":  # Windows refused some keys without raising (emergency lock first: it matters most)
                    problems = [getattr(component, attr, None) for attr in ("emergency_error", "error", "quick_error")]
                    problem = "; ".join(p for p in problems if isinstance(p, str) and p)
                    if problem:
                        self.set_status(t("host.agentRunningHotkeyUnavailable", problem=problem), "warning")
            self.integrations.append(component)
        controller.on_lock.append(self._refresh_tray)
        controller.on_lock.append(self._forget_site_verdicts)  # phishing shield: no saved origin outlives the vault
        # Passkeys a page never confirmed receiving go before the lock, and at the next unlock after a crash.
        controller.before_lock.append(self._passkey_before_lock)
        controller.on_unlock.append(self._passkey_after_unlock)
        controller.on_unlock.append(self._refresh_tray)
        controller.on_unlock.append(self.apply_overlay)  # back on after an emergency lock or a switch
        self.apply_overlay()
        self._ssh_agent_factory = ssh_agent
        self.apply_ssh_agent()
        # A duress session stops the SSH agent pipe; the next lock starts it again (when it is on).
        controller.on_unlock.append(self.apply_ssh_agent)
        controller.on_lock.append(self.apply_ssh_agent)

    # ------------------------------------------------------ SSH agent
    @staticmethod
    def _default_ssh_agent(host: WebAgentHost) -> Any:
        from ..ssh_agent import SshAgentServer, SshAgentService, default_pipe_name

        return SshAgentServer(default_pipe_name(), SshAgentService(host))

    # Told every status apply_ssh_agent ends in (the developer service removes / restores SSH_AUTH_SOCK).
    on_ssh_agent_status: Callable[[str], None] | None = None

    def apply_ssh_agent(self) -> str:
        """Start or stop the SSH agent pipe to match ``settings.developer_ssh_agent``; returns its status."""
        status = self._apply_ssh_agent()
        listener = self.on_ssh_agent_status
        if listener is not None:
            try:
                listener(status)
            except Exception:  # noqa: BLE001 - never stop the app over the agent
                _log.warning("SSH agent status listener failed", exc_info=True)
        return status

    def _apply_ssh_agent(self) -> str:
        with self._ssh_agent_lock:
            enabled = (bool(getattr(self.settings, "developer_ssh_agent", False)) and not self._closing
                       and not self.duress_session())
            server = self.ssh_agent_server
            if enabled and (server is None or server.status != "running"):
                if server is not None:
                    server.stop()  # an earlier start found the name taken: try again
                try:
                    server = (self._ssh_agent_factory or self._default_ssh_agent)(self)
                    server.start()
                except Exception as exc:  # noqa: BLE001 - never stop the app over the agent
                    _log.warning("SSH agent could not start: %s", type(exc).__name__)
                    server = None
                    self.ssh_agent_server = None
                    return "unavailable"
                self.ssh_agent_server = server
            elif not enabled and server is not None:
                self.ssh_agent_server = None
                try:
                    server.stop()
                except Exception:  # noqa: BLE001
                    _log.warning("SSH agent did not stop cleanly", exc_info=True)
            return self.ssh_agent_status()

    def ssh_agent_status(self) -> str:
        """"off", "running", "unavailable" (this user's process holds the pipe name), "taken" (another account's
        process holds it) or "stopped"."""
        server = self.ssh_agent_server
        return "off" if server is None else str(server.status)

    # ------------------------------------------------------ field button
    desktop_fill_window: Callable[[int], None] | None = None

    def apply_overlay(self) -> None:
        """Show the button beside desktop password fields when "Desktop app autofill" is on."""
        overlay = getattr(self, "overlay", None)
        if overlay is not None:
            overlay.set_enabled(bool(self.settings.desktop_overlay_enabled))

    def _overlay_off(self) -> None:
        overlay = getattr(self, "overlay", None)
        if overlay is not None:
            overlay.set_enabled(False)

    def _overlay_clicked(self, hwnd: int) -> None:
        """The field button: fill that window through the verified desktop path, on its own thread."""
        fill = self.desktop_fill_window
        if fill is None:
            return

        def run() -> None:
            try:
                fill(int(hwnd))
            except Exception:  # noqa: BLE001 - logged; the button must keep working
                _log.exception("Desktop fill from the field button failed")
        threading.Thread(target=run, name="lgk-desktop-fill", daemon=True).start()

    def stop_integrations(self) -> None:
        self._closing = True
        self.apply_ssh_agent()  # off while closing
        for component in reversed(self.integrations):
            try:
                component.stop()
            except Exception:  # noqa: BLE001 - keep stopping the rest
                _log.warning("Integration did not stop cleanly", exc_info=True)
        self.integrations.clear()
        self._posted.put(None)

    def _quick_hotkey(self) -> str:
        return getattr(self.settings, "quick_access_hotkey", "Ctrl+Alt+K") or "Ctrl+Alt+K"

    def _make_hotkey(self, quick: str) -> Any:
        # The fill waits on page prompts, so it gets its own thread: lock hotkeys and the tray never queue behind it.
        return self._hotkey_factory(self._spawn_desktop_fill, lambda: self.post(self.emergency_lock),
                                    lambda: self.post(self.quick_access), quick_hotkey=quick)

    def restart_hotkeys(self) -> None:
        """The quick-access shortcut changed in Settings: register the new one, or keep the old one if it fails."""
        old = getattr(self, "hotkey", None)
        if old is None:
            return
        previous = old.kwargs.get("quick_hotkey") if hasattr(old, "kwargs") else getattr(old, "quick_hotkey", None)
        try:
            old.stop()  # Windows refuses a second registration of the same keys, so the old one goes first
        except Exception:  # noqa: BLE001
            _log.debug("Old hotkey listener did not stop cleanly", exc_info=True)
        replacement = self._make_hotkey(self._quick_hotkey())
        try:
            replacement.start()
            problem = getattr(replacement, "quick_error", None)  # Windows refused the keys without raising
        except Exception as exc:  # noqa: BLE001
            problem = str(exc)
        if problem:  # fall back to the shortcut that worked
            self.set_status(t("host.agentRunningHotkeyUnavailable", problem=problem), "warning")
            try:
                replacement.stop()
            except Exception:  # noqa: BLE001
                pass
            replacement = self._make_hotkey(previous or "Ctrl+Alt+K")
            try:
                replacement.start()
            except Exception:  # noqa: BLE001
                _log.warning("Hotkeys could not be restored", exc_info=True)
        self.hotkey = replacement
        self.integrations = [replacement if c is old else c for c in self.integrations]

    def _refresh_tray(self) -> None:
        tray = getattr(self, "tray", None)
        if tray is not None:
            try:
                tray.refresh()
            except Exception:  # noqa: BLE001 - cosmetic
                pass

    def _tray_state(self) -> dict[str, bool]:
        return {"unlocked": self._controller.is_unlocked(),
                "browser_enabled": bool(self.settings.browser_enabled),
                "desktop_enabled": bool(self.settings.desktop_overlay_enabled)}

    def _save_settings(self) -> None:
        try:
            self.settings.save()
        except OSError:
            self.set_status(t("settings.error.notSaved"), "error")

    def _toggle_browser(self) -> None:
        self.settings.browser_enabled = not self.settings.browser_enabled
        self._save_settings()
        self._refresh_tray()
        self.set_status(t("host.browserIntegration", v1='enabled' if self.settings.browser_enabled else 'paused'))

    def _toggle_desktop(self) -> None:
        self.settings.desktop_overlay_enabled = not self.settings.desktop_overlay_enabled
        self._save_settings()
        self.apply_overlay()
        self._refresh_tray()

    def _session_lock_requested(self, reason: str) -> None:
        lower = reason.lower()
        if "sleep" in lower or "suspend" in lower:
            if not self.settings.lock_on_sleep:
                return
        elif not self.settings.lock_on_session_lock:
            return
        # Revoke capabilities on the notification thread at once, then lock.
        self.guard.invalidate()
        self.post(lambda: self.lock(t("host.vaultLocked", reason=reason)))

    def _navigate(self, route: str) -> None:
        self._open_window()
        self._bus.emit("navigate", {"route": route})

    def _open_window(self) -> None:
        self.show_main_window()
        self.raise_window()

    def quick_access(self) -> None:
        if getattr(self.settings, "quick_access_palette", True) is not False and self.show_palette():
            return
        self._navigate("quick-access")

    def show_palette(self) -> bool:
        """Show the quick-search palette over the app in front; False when it cannot be shown."""
        palette = getattr(self, "palette", None)
        if palette is None or getattr(palette, "disabled", False):
            return False
        try:
            shown = palette.show_centered()
        except Exception:  # noqa: BLE001 - logged; the app's Quick access page opens instead
            _log.warning("The quick-search palette could not be shown", exc_info=True)
            return False
        if shown:
            self._bus.emit("palette.show", {})
        return bool(shown)

    def hide_palette(self) -> None:
        palette = getattr(self, "palette", None)
        if palette is None:
            return
        self._bus.emit("palette.hide", {})
        # A prompt the palette was showing is cancelled: its copy stops waiting and frees the vault lock.
        cancel = getattr(self._port, "cancel_surface", None)
        if cancel is not None:
            cancel("palette")
        try:
            palette.hide()
        except Exception:  # noqa: BLE001, S110 - already hidden or gone
            pass

    def _spawn_desktop_fill(self) -> None:
        threading.Thread(target=self._run_desktop_fill, name="lgk-desktop-fill", daemon=True).start()

    def _run_desktop_fill(self) -> None:
        try:
            self._desktop_fill_hotkey()
        except Exception:  # noqa: BLE001 - logged; the hotkey must keep working
            _log.exception("Desktop fill failed")

    def _desktop_fill_hotkey(self) -> None:
        if self.desktop_fill is not None:
            self.desktop_fill()

    def close_requested(self) -> bool:
        """Window close: hide to the tray when asked to keep running, else exit. True means exit."""
        tray = getattr(self, "tray", None)
        if self.settings.minimize_to_tray and tray is not None and getattr(tray, "available", False):
            self.hide_main_window()
            self.set_status(t("host.localgatekeysIsStillRunningIn"))
            return False
        return True

    def _exit(self) -> None:
        if self.on_exit is not None:
            self.on_exit()
