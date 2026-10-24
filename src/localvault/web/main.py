"""The LocalGateKeys window: builds the controller, services, bridge and host, then runs the WebView2 page."""
from __future__ import annotations

import logging
from typing import Any

_log = logging.getLogger(__name__)
# How long a page may take to load before the window is closed rather than run unlocked.
_LOAD_TIMEOUT = 60


def run() -> None:
    import webview  # type: ignore[import-not-found]

    from ..api.bridge import PAGE_CALLS, Api, page_api
    from ..app.controller import WebController
    from ..config import BRAND_NAME
    from ..profiles import ProfileManager
    from ..settings import AppSettings
    from .bus import EventBus, QueuedSink
    from .ui_port import WebUiPort
    from .window import (FileDialogs, PopupWindow, WindowOps, apply_glass, block_foreign_navigation,
                         install_call_guard, native_handle, origin_of, ui_index_path)

    index = ui_index_path()
    from ..app.startup import prepare_startup

    # The legacy-data decision comes first: nothing is written to the data folder before it.
    startup, profiles = prepare_startup()

    def clean_open_copies() -> None:
        # Decrypted copies left by a crash or a file that was still open at exit.
        from ..attachments import cleanup_open_copies

        try:
            if profiles.active_profile() is not None:
                cleanup_open_copies(profiles.profile_dir())
        except OSError:
            pass

    if not startup.pending:
        clean_open_copies()
    startup.on_ready.append(clean_open_copies)
    import sys

    def repair_start_with_windows() -> None:
        if getattr(sys, "frozen", False):
            # Repair Run entries written by older builds (console window, no --background).
            from ..startup import sync_start_with_windows

            try:
                sync_start_with_windows(bool(AppSettings.load().start_with_windows))
            except OSError:
                pass

    if startup.pending:
        startup.on_ready.append(repair_start_with_windows)
    else:
        repair_start_with_windows()
    bus = EventBus()
    port = WebUiPort(bus)
    controller = WebController(profiles=profiles, settings=AppSettings.load(), bus=bus)
    controller.on_lock.append(port.cancel_all)
    controller.startup = startup
    startup.on_ready.append(controller._publish)
    ops: dict[str, Any] = {}

    class _LateOps:
        def minimize(self) -> None:
            ops["ops"].minimize()

        def toggle_maximize(self) -> None:
            ops["ops"].toggle_maximize()

        def close(self) -> None:
            ops["ops"].close()

        def hwnd(self) -> int | None:
            return ops["ops"].hwnd() if "ops" in ops else None

        def set_theme(self, appearance: str) -> None:
            if "ops" in ops:
                ops["ops"].set_theme(appearance)

        def show(self) -> None:
            if "ops" in ops:
                ops["ops"].show()

        def hide(self) -> None:
            if "ops" in ops:
                ops["ops"].hide()

        def raise_window(self) -> None:
            if "ops" in ops:
                ops["ops"].raise_window()

    class _LateDialogs:
        def open_file(self, title: str, file_types: tuple[str, ...] | None = None) -> Any:
            if file_types:
                return ops["dialogs"].open_file(title, file_types)
            return ops["dialogs"].open_file(title)

        def save_file(self, title: str, name: str) -> Any:
            return ops["dialogs"].save_file(title, name)

        def choose_folder(self, title: str) -> Any:
            return ops["dialogs"].choose_folder(title)

    import sys

    from .host import WebAgentHost

    background = "--background" in sys.argv
    late_ops = _LateOps()
    api = Api(controller, port, late_ops, dialogs=_LateDialogs())
    # Both pages reach only the public calls: a facade object, and a guard that drops any other name
    # (pywebview would otherwise walk dotted names like "_controller.lock" from the js_api object).
    js_api = page_api(api)
    install_call_guard(PAGE_CALLS)
    # Links leave only through system_open_url's web-link check, never pywebview's new-window handler.
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = False
    # No --allow-file-access-from-files: the pages are served over the local http server.
    webview.settings["ALLOW_FILE_URLS"] = False
    # The small popup a fill started outside the app uses (classic compact unlock and account choice).
    popup_window = webview.create_window(
        "Unlock LocalGateKeys", url=str(index.with_name("popup.html")), js_api=js_api, width=460, height=620,
        resizable=False, on_top=True, hidden=True, background_color="#0C1424",
        text_select=False,
    )
    popup = PopupWindow(popup_window)
    host = WebAgentHost(controller, port, bus, window=late_ops, popup=popup)
    api._connections._extension = lambda: (host.last_extension_version, host.last_extension_seen)
    from ..app.icons import IconProvider

    # Item icons (memory only): app icons for desktop logins; website icons only while
    # "Show website icons" is on (off by default) and strict offline mode is off.
    icons = IconProvider(offline=lambda: getattr(controller.settings, "strict_offline_mode", True) is not False,
                         on_ready=lambda: bus.emit("items.changed", {}),
                         website_icons=lambda: getattr(controller.settings, "website_icons", False) is True)
    api._home.icons = icons
    controller.on_lock.append(icons.clear)

    def settings_changed(key: str) -> None:
        if key == "quick_access_hotkey":
            host.restart_hotkeys()
            return
        if key in ("strict_offline_mode", "website_icons"):
            icons.clear()  # a policy change never carries icons fetched under the old one
        host.apply_overlay()
        host._refresh_tray()

    api._settings.on_change.append(settings_changed)
    window = webview.create_window(
        BRAND_NAME, url=str(index), js_api=js_api, width=1180, height=760, min_size=(900, 600),
        background_color="#0C1424", text_select=False, hidden=background,
    )
    exiting = {"value": False}

    def exit_app() -> None:
        exiting["value"] = True
        try:
            popup_window.destroy()
        except Exception:  # noqa: BLE001 - already gone
            pass
        window.destroy()

    host.on_exit = exit_app
    from ..app.desktop import DesktopService

    # Desktop fills ask in the popup; it shows itself for each question, so nothing raises the main window.
    desktop = DesktopService(controller, host.popup_port, bus, serialise=lambda fn: host.run_on_ui(fn, timeout=90),
                             ensure_unlocked=host.ensure_unlocked, reauthenticate=host.reauthenticate,
                             raise_window=lambda: None)
    api._desktop = desktop
    host.desktop_fill = desktop.fill_foreground
    host.desktop_fill_window = desktop.fill_window
    ops["ops"] = WindowOps(window)
    ops["dialogs"] = FileDialogs(window)

    def on_closing() -> Any:
        if not exiting["value"] and not host.close_requested():
            return False  # hidden to the tray; keep running
        # Runs on the WinForms UI thread: evaluate_js there would deadlock, so
        # the page is detached before anything below emits.
        bus.attach(lambda _js: None)
        bus.attach(lambda _js: None, key="popup")
        # Revoke leases first: a desktop fill or browser request still running stops before its next write.
        controller.guard.invalidate()
        port.cancel_all()  # wake prompts first: their threads must not hold up stopping the pipe server
        host.stop_integrations()
        controller.stop()
        # Locking sweeps decrypted document copies no app holds; finish_at_exit below takes care of the rest.
        controller.lock("App closed.")
        try:
            # A copied secret the lock could not clear (another app held the clipboard) is retried here:
            # the background retries end with the process.
            controller.clipboard.finish()
        except Exception:  # noqa: BLE001 - best-effort at exit
            _log.warning("Clipboard not cleared at exit", exc_info=True)
        # Copies no app holds are deleted now; one still open is deleted by a detached helper once its app closes.
        from ..open_copy_watch import finish_at_exit

        try:
            finish_at_exit(controller.profiles.profile_dir() if controller.profiles.active_profile() else None)
        except Exception:  # noqa: BLE001 - the next launch still sweeps
            _log.warning("Open documents could not be handed over at exit", exc_info=True)
        port.cancel_all()

    window.events.closing += on_closing

    def on_popup_closing() -> Any:
        if exiting["value"]:
            return True
        host.popup_closed()  # closing the popup cancels that fill; the window is kept for the next one
        return False

    popup_window.events.closing += on_popup_closing

    def attach_popup(app_origin: str) -> None:
        # Fail closed: a popup whose navigation lock is missing is never shown or attached.
        if not popup_window.events.loaded.wait(_LOAD_TIMEOUT):
            _log.error("The popup page did not load; desktop and browser prompts are disabled")
            popup.disable()
            return
        try:
            block_foreign_navigation(popup_window, app_origin)
        except Exception:  # noqa: BLE001 - logged; the popup stays hidden for good
            _log.error("Navigation lock not installed on the popup; it is disabled", exc_info=True)
            popup.disable()
            return
        bus.attach(QueuedSink(popup_window.evaluate_js), key="popup")

    def on_start(win: Any) -> None:
        # pywebview calls this before the native form exists; glass and the
        # navigation lock need the shown window and its WebView2 core.
        install_call_guard(PAGE_CALLS)  # again: covers a platform module that imported js_bridge_call meanwhile
        win.events.shown.wait(15)
        if not win.events.loaded.wait(_LOAD_TIMEOUT):
            _log.error("The app page did not load; closing instead of running without the navigation lock")
            exit_app()
            return
        app_origin = origin_of(win.get_current_url() or "")
        try:
            block_foreign_navigation(win, app_origin)
        except Exception:  # noqa: BLE001 - logged; never run the bridge without the lock
            _log.error("Navigation lock not installed; closing the window", exc_info=True)
            exit_app()
            return
        bus.attach(QueuedSink(win.evaluate_js))
        ops["ops"].handle = native_handle(win)
        glass = apply_glass(win)
        ops["ops"].set_theme(controller.settings.appearance)
        api._glass = glass
        if not glass:
            win.evaluate_js('document.documentElement.dataset.glass = "off"')
        import threading

        threading.Thread(target=attach_popup, args=(app_origin,), name="lgk-popup-attach", daemon=True).start()
        controller.start()
        api._schedule.start()
        api._sync.enable()  # background sync while unlocked (never in tests)
        api._licence.on_plan_change.append(api._sync.plan_changed)  # Pro-only: follow licence changes
        try:
            from ..browser_bridge import ensure_packaged_registration

            ensure_packaged_registration()
        except Exception:  # noqa: BLE001 - logged; the Connections page can repair it
            _log.warning("Browser bridge registration failed", exc_info=True)
        host.start_integrations()
        tray = getattr(host, "tray", None)
        if background and not getattr(tray, "available", False):
            host.show_main_window()  # no tray to come back from: never stay invisible

    webview.start(on_start, window, gui="edgechromium", debug=False, private_mode=True, http_server=True)
