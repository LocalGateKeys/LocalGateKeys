"""The WebView2 window: built UI location, glass backdrop, navigation lock, window controls.

Only the helpers at the top are toolkit-free; the rest touch pywebview's
WinForms/WebView2 objects and run on its UI thread.
"""
from __future__ import annotations

import ctypes
import logging
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_log = logging.getLogger(__name__)

UI_DIR = Path(__file__).resolve().parent.parent / "assets" / "ui"
BUILD_HINT = "The new UI is not built. Run: cd webui && npm ci && npm run build"

_DWMWA_USE_IMMERSIVE_DARK_MODE = 20
_DWMWA_SYSTEMBACKDROP_TYPE = 38
_DWMSBT_MAINWINDOW = 2  # Mica
_BACKDROP_MIN_BUILD = 22621
_WDA_NONE = 0x0
_WDA_MONITOR = 0x1  # shows black in captures; every Windows 10 build
_WDA_EXCLUDEFROMCAPTURE = 0x11  # the window is simply absent from captures; Windows 10 2004 and later


# ------------------------------------------------------------ pure helpers
def ui_index_path() -> Path:
    index = UI_DIR / "index.html"
    if not index.is_file():
        raise FileNotFoundError(BUILD_HINT)
    return index


def origin_of(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def is_app_url(url: str, app_origin: str) -> bool:
    """True only for pages served from the app's own local origin."""
    return bool(app_origin) and origin_of(url) == app_origin


# pywebview's own messages, answered inside js_bridge_call before any js_api lookup.
PYWEBVIEW_CALLS = frozenset({
    "pywebviewMoveWindow", "pywebviewEventHandler", "pywebviewAsyncCallback", "pywebviewStateUpdate",
    "pywebviewStateDelete",
})


def page_call_allowed(func_name: Any, page_calls: frozenset[str]) -> bool:
    """Only exact, flat, public names reach pywebview's lookup; no dotted or underscore path."""
    if not isinstance(func_name, str):
        return False
    if func_name in PYWEBVIEW_CALLS:
        return True
    return func_name in page_calls and "." not in func_name and not func_name.startswith("_")


def guard_js_bridge_call(original: Any, page_calls: Any) -> Any:
    """Wrap pywebview's js_bridge_call so a name outside the allowlist is dropped before it is resolved."""
    allowed = frozenset(page_calls)

    def js_bridge_call(window: Any, func_name: Any, param: Any, value_id: Any) -> None:
        if not page_call_allowed(func_name, allowed):
            _log.warning("Refused a page call to an unknown name: %r", str(func_name)[:80])
            return None
        return original(window, func_name, param, value_id)

    js_bridge_call.lgk_original = original  # type: ignore[attr-defined]
    return js_bridge_call


def install_call_guard(page_calls: Any) -> None:
    """Patch js_bridge_call in pywebview and in every platform module that imported it by name.

    Call before webview.start (the WebView2 platform imports it while starting) and
    again once started, so a platform module loaded meanwhile is covered too.
    """
    import webview.util as util  # type: ignore[import-not-found]

    current = util.js_bridge_call
    original = getattr(current, "lgk_original", current)
    guarded = guard_js_bridge_call(original, page_calls)
    util.js_bridge_call = guarded
    for name, module in list(sys.modules.items()):
        if name.startswith("webview.platforms") and module is not None:
            found = getattr(module, "js_bridge_call", None)
            if found is original or getattr(found, "lgk_original", None) is original:
                module.js_bridge_call = guarded  # type: ignore[attr-defined]


def system_prefers_dark() -> bool:
    if os.name != "nt":
        return True
    try:
        import winreg

        key = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
            value, _kind = winreg.QueryValueEx(handle, "AppsUseLightTheme")
        return int(value) == 0
    except Exception:  # noqa: BLE001 - unknown means the dark default
        return True


def backdrop_supported() -> bool:
    if os.name != "nt":
        return False
    try:
        return sys.getwindowsversion().build >= _BACKDROP_MIN_BUILD
    except Exception:  # noqa: BLE001
        return False


# ------------------------------------------------------- WinForms / WebView2
def _on_ui_thread(window: Any, fn: Any) -> None:
    import System  # type: ignore[import-not-found]

    window.native.Invoke(System.Action(fn))


def theme_is_dark(appearance: str) -> bool:
    """The in-app theme choice; "system" follows Windows."""
    if appearance == "dark":
        return True
    if appearance == "light":
        return False
    return system_prefers_dark()


def set_title_bar_dark(window: Any, dark: bool) -> bool:
    """Match the native title bar and Mica tint to the page theme. Best-effort."""
    done = {"ok": False}

    def run() -> None:
        from ctypes import wintypes

        hwnd = wintypes.HWND(int(window.native.Handle.ToInt64()))
        set_attribute = ctypes.WinDLL("dwmapi").DwmSetWindowAttribute
        set_attribute.argtypes = (wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD)
        value = wintypes.BOOL(bool(dark))
        done["ok"] = set_attribute(hwnd, _DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(value),
                                   ctypes.sizeof(value)) == 0

    try:
        _on_ui_thread(window, run)
    except Exception:  # noqa: BLE001 - cosmetic only
        return False
    return done["ok"]


def native_handle(window: Any) -> int | None:
    """The top-level window handle (owner of Windows Security prompts), read on the UI thread."""
    found: dict[str, int] = {}

    def run() -> None:
        found["hwnd"] = int(window.native.Handle.ToInt64())

    try:
        _on_ui_thread(window, run)
    except Exception:  # noqa: BLE001 - no handle means Windows Hello is refused, nothing else
        return None
    return found.get("hwnd") or None


def set_display_affinity(hwnd: int | None, hide: bool) -> bool:
    """Hide a window from screenshots and screen sharing (or show it again). Best-effort; False when not applied.

    Falls back to WDA_MONITOR where WDA_EXCLUDEFROMCAPTURE is refused (older Windows). This only stops other
    programs from capturing the window; LocalGateKeys itself never captures the screen.
    """
    if os.name != "nt" or not hwnd:
        return False
    try:
        from ctypes import wintypes

        set_affinity = ctypes.windll.user32.SetWindowDisplayAffinity
        set_affinity.argtypes = (wintypes.HWND, wintypes.DWORD)
        set_affinity.restype = wintypes.BOOL
        target = wintypes.HWND(int(hwnd))
        if not hide:
            return bool(set_affinity(target, _WDA_NONE))
        return bool(set_affinity(target, _WDA_EXCLUDEFROMCAPTURE)) or bool(set_affinity(target, _WDA_MONITOR))
    except Exception:  # noqa: BLE001 - best effort
        return False


def apply_capture_protection(window: Any, hide: bool) -> bool:
    """set_display_affinity for a pywebview window's top-level form."""
    return set_display_affinity(native_handle(window), hide)


def apply_glass(window: Any) -> bool:
    """The recipe from the spec's feasibility check. Best-effort; False when not applied."""
    if not backdrop_supported():
        return False
    applied = {"ok": False}

    def run() -> None:
        from ctypes import wintypes

        from System.Drawing import Color  # type: ignore[import-not-found]

        form = window.native
        form.BackColor = Color.Black
        form.browser.webview.DefaultBackgroundColor = Color.Transparent
        hwnd = wintypes.HWND(int(form.Handle.ToInt64()))
        dwmapi = ctypes.WinDLL("dwmapi")
        set_attribute = dwmapi.DwmSetWindowAttribute
        set_attribute.argtypes = (wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD)
        dark = wintypes.BOOL(system_prefers_dark())
        set_attribute(hwnd, _DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(dark), ctypes.sizeof(dark))
        backdrop = wintypes.DWORD(_DWMSBT_MAINWINDOW)
        if set_attribute(hwnd, _DWMWA_SYSTEMBACKDROP_TYPE, ctypes.byref(backdrop), ctypes.sizeof(backdrop)) != 0:
            return

        class MARGINS(ctypes.Structure):
            _fields_ = [("left", ctypes.c_int), ("right", ctypes.c_int),
                        ("top", ctypes.c_int), ("bottom", ctypes.c_int)]

        if dwmapi.DwmExtendFrameIntoClientArea(hwnd, ctypes.byref(MARGINS(-1, -1, -1, -1))) == 0:
            applied["ok"] = True

    try:
        _on_ui_thread(window, run)
    except Exception:  # noqa: BLE001 - the opaque wash is the fallback
        _log.warning("Glass backdrop not applied", exc_info=True)
        return False
    return applied["ok"]


def guard_script_notify(original: Any, app_origin: str) -> Any:
    """Wrap pywebview's WebMessageReceived handler: a message from any other origin is dropped.

    Only the app's own page may reach the bridge; a frame or a page that slipped
    past the navigation lock never does.
    """

    def on_script_notify(sender: Any, args: Any) -> Any:
        try:
            source = str(args.Source)
        except Exception:  # noqa: BLE001 - no source means not ours
            source = ""
        if not is_app_url(source, app_origin):
            _log.warning("Dropped a page message from a foreign origin")
            return None
        return original(sender, args)

    on_script_notify.lgk_original = original  # type: ignore[attr-defined]
    return on_script_notify


def block_foreign_navigation(window: Any, app_origin: str) -> None:
    """Cancel any top-level navigation or new window outside the app's origin.

    Raises when the lock could not be installed in full, so the caller can
    close the window instead of running it unprotected.
    """
    if not app_origin:
        raise RuntimeError("The app origin is unknown")
    done = {"ok": False}

    def run() -> None:
        browser = window.native.browser
        control = browser.webview
        core = control.CoreWebView2

        def on_navigation(_sender: Any, args: Any) -> None:
            if not is_app_url(str(args.Uri), app_origin):
                args.Cancel = True

        def on_new_window(_sender: Any, args: Any) -> None:
            args.Handled = True  # never open a second browser window

        core.NavigationStarting += on_navigation
        try:
            # pywebview's own handler opens the link in a browser or loads it here; links leave only by
            # system_open_url. OPEN_EXTERNAL_LINKS_IN_BROWSER is off too, so a handler left attached
            # loads the link, which on_navigation cancels.
            core.NewWindowRequested -= window.native.browser.on_new_window_request
        except Exception:  # noqa: BLE001 - logged; the setting and on_navigation still hold
            _log.warning("pywebview's new-window handler not detached", exc_info=True)
        core.NewWindowRequested += on_new_window
        settings = core.Settings
        settings.AreDefaultContextMenusEnabled = False
        settings.IsZoomControlEnabled = False
        settings.AreBrowserAcceleratorKeysEnabled = False
        settings.IsStatusBarEnabled = False
        # Edge must never offer to save or autofill the master password.
        settings.IsPasswordAutosaveEnabled = False
        settings.IsGeneralAutofillEnabled = False
        # Bridge messages only from the app's own origin (pywebview checks none).
        original = browser.on_script_notify
        control.WebMessageReceived -= original
        control.WebMessageReceived += guard_script_notify(original, app_origin)
        done["ok"] = True

    _on_ui_thread(window, run)
    if not done["ok"]:
        raise RuntimeError("The navigation lock was not installed")


class WindowOps:
    def __init__(self, window: Any) -> None:
        self._window = window
        self._maximized = False
        self.handle: int | None = None

    def hwnd(self) -> int | None:
        return self.handle

    def set_theme(self, appearance: str) -> None:
        set_title_bar_dark(self._window, theme_is_dark(appearance))

    def set_capture_protection(self, hide: bool) -> bool:
        return apply_capture_protection(self._window, hide)

    def show(self) -> None:
        self._window.show()

    def hide(self) -> None:
        self._window.hide()

    def raise_window(self) -> None:
        """Bring the window to the front for a prompt (restore, show, activate)."""
        window = self._window
        try:
            window.restore()
        except Exception:  # noqa: BLE001 - not minimized
            pass
        window.show()

        def run() -> None:
            form = window.native
            form.TopMost = True
            form.Activate()
            form.TopMost = False

        try:
            _on_ui_thread(window, run)
        except Exception:  # noqa: BLE001 - focus is a courtesy
            pass

    def minimize(self) -> None:
        self._window.minimize()

    def toggle_maximize(self) -> None:
        if self._maximized:
            self._window.restore()
        else:
            self._window.maximize()
        self._maximized = not self._maximized

    def close(self) -> None:
        self._window.destroy()


class FileDialogs:
    """Native open/save dialogs through pywebview (called from bridge worker threads)."""

    def __init__(self, window: Any) -> None:
        self._window = window

    def open_file(self, title: str, file_types: tuple[str, ...] | None = None) -> Path | None:
        import webview  # type: ignore[import-not-found]

        extra = {"file_types": file_types} if file_types else {}
        result = self._window.create_file_dialog(webview.FileDialog.OPEN, allow_multiple=False, **extra)
        if not result:
            return None
        return Path(result[0] if isinstance(result, (list, tuple)) else result)

    def choose_folder(self, title: str) -> Path | None:
        import webview  # type: ignore[import-not-found]

        result = self._window.create_file_dialog(webview.FileDialog.FOLDER)
        if not result:
            return None
        return Path(result[0] if isinstance(result, (list, tuple)) else result)

    def save_file(self, title: str, name: str) -> Path | None:
        import webview  # type: ignore[import-not-found]

        result = self._window.create_file_dialog(webview.FileDialog.SAVE, save_filename=name)
        if not result:
            return None
        return Path(result[0] if isinstance(result, (list, tuple)) else result)


class PopupWindow:
    """The small always-on-top window a fill uses (unlock with profile chips, choose an account, confirm)."""

    def __init__(self, window: Any) -> None:
        self._window = window
        self.disabled = False
        # Run once when the popup is disabled: the host moves its prompts to the main window.
        self.on_disable: list[Any] = []
        self.hide_from_capture = False

    def set_capture_protection(self, hide: bool) -> bool:
        """Remember the choice (applied again each time the popup is shown) and apply it now."""
        self.hide_from_capture = hide
        return apply_capture_protection(self._window, hide)

    def disable(self) -> None:
        """Never show this window again (its navigation lock could not be installed)."""
        self.disabled = True
        try:
            self._window.hide()
        except Exception:  # noqa: BLE001, S110 - already hidden or gone
            pass
        for hook in list(self.on_disable):
            try:
                hook()
            except Exception:  # noqa: BLE001 - every hook runs
                logging.getLogger(__name__).warning("Popup disable hook failed", exc_info=True)

    def show(self) -> bool:
        """Show and focus the popup; False when it is disabled (the caller raises the main window instead)."""
        if self.disabled:
            return False
        window = self._window
        window.show()
        if self.hide_from_capture:
            apply_capture_protection(window, True)

        def run() -> None:
            form = window.native
            form.TopMost = True
            form.Activate()

        try:
            _on_ui_thread(window, run)
        except Exception:  # noqa: BLE001 - focus is a courtesy
            pass
        return True

    def hide(self) -> None:
        self._window.hide()
