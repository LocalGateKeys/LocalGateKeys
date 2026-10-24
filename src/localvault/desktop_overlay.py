"""The LocalGateKeys button beside protected desktop password fields (Win32, no Tk).

Discovery reads only UI Automation metadata (never field values). Once a protected
password field is found in the foreground app, a small owned, non-activating,
per-pixel-alpha window follows it. A click only asks the agent to start its normal,
separately verified desktop fill for that window; no secret is ever released here.
"""
from __future__ import annotations

import math
import os
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .uia import ControlDescriptor, WindowSnapshot, scan_foreground_window


def _asset_path(name: str) -> Path:
    # A PyInstaller build keeps assets below ``sys._MEIPASS``; a checkout keeps them in ``<root>/assets``.
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        return Path(frozen_root) / "assets" / name
    return Path(__file__).resolve().parents[2] / "assets" / name


OVERLAY_BASE_DPI = 96.0
OVERLAY_LOGICAL_SIZE = 32
OVERLAY_LOGICAL_LOGO_SIZE = 24
OVERLAY_LOGICAL_GAP = 5
OVERLAY_LOGO_SIZES = (24, 30, 36, 42, 48, 64, 96, 128)

# Colours of the rounded square behind the logo (rest, hover, pressed): the classic button's.
_BACKGROUND = {"rest": ((0x17, 0x21, 0x30), (0x7C, 0x8C, 0xFF)),
               "hover": ((0x7C, 0x8C, 0xFF), (0xDC, 0xE0, 0xFF)),
               "pressed": ((0x66, 0x76, 0xE8), (0xB8, 0xC1, 0xFF))}


def overlay_dpi_scale(dpi: float | None) -> float:
    """Return the physical scale used by the overlay for a Windows DPI."""
    try:
        value = float(dpi) if dpi is not None else OVERLAY_BASE_DPI
    except (TypeError, ValueError):
        value = OVERLAY_BASE_DPI
    if not math.isfinite(value) or value <= 0:
        value = OVERLAY_BASE_DPI
    # Keep malformed or legacy DPI reports from shrinking the hit target.
    return max(1.0, value / OVERLAY_BASE_DPI)


def overlay_render_metrics(dpi: float | None) -> tuple[int, int, int]:
    """Return physical button, logo, and gap sizes for logical 32/24/5 px."""
    scale = overlay_dpi_scale(dpi)
    return (max(1, round(OVERLAY_LOGICAL_SIZE * scale)), max(1, round(OVERLAY_LOGICAL_LOGO_SIZE * scale)),
            max(1, round(OVERLAY_LOGICAL_GAP * scale)))


def overlay_logo_asset_size(dpi: float | None) -> int:
    """Choose the nearest generated source without enlarging a tiny raster."""
    target = overlay_render_metrics(dpi)[1]
    return min(OVERLAY_LOGO_SIZES, key=lambda size: (abs(size - target), size < target))


def window_dpi(hwnd: int) -> float | None:
    """Read a target window's effective per-monitor DPI on Windows."""
    if os.name != "nt" or not hwnd:
        return None
    try:
        import ctypes

        getter = getattr(_user32(), "GetDpiForWindow", None)
        if getter is not None:
            getter.argtypes = [ctypes.c_void_p]
            value = int(getter(_hwnd(hwnd)))
            if value > 0:
                return float(value)
    except Exception:  # noqa: BLE001
        pass
    return None


def render_overlay_image(size: int, logo_size: int, state: str = "rest", busy: bool = False) -> Any:
    """The button as a premultiplication-ready RGBA Pillow image (rounded square + field_fill logo)."""
    from PIL import Image, ImageDraw

    scale = 4  # draw large, then downsample: smooth rounded corners
    big = Image.new("RGBA", (size * scale, size * scale), (0, 0, 0, 0))
    draw = ImageDraw.Draw(big)
    fill, border = _BACKGROUND.get(state, _BACKGROUND["rest"])
    radius = max(1, round(8 * size / OVERLAY_LOGICAL_SIZE)) * scale
    width = max(1, round(size / OVERLAY_LOGICAL_SIZE)) * scale
    draw.rounded_rectangle((0, 0, size * scale - 1, size * scale - 1), radius=radius, fill=fill + (255,),
                           outline=border + (255,), width=width)
    if busy:
        inset = max(1, round(8 * size / OVERLAY_LOGICAL_SIZE)) * scale
        draw.ellipse((inset, inset, size * scale - inset, size * scale - inset), outline=(0x26, 0xD4, 0xF2, 255),
                     width=max(1, round(2 * size / OVERLAY_LOGICAL_SIZE)) * scale)
    image = big.resize((size, size), Image.LANCZOS)
    if not busy:
        asset = min(OVERLAY_LOGO_SIZES, key=lambda s: (abs(s - logo_size), s < logo_size))
        try:
            logo = Image.open(_asset_path(f"icons/field_fill_{asset}.png")).convert("RGBA")
            if logo.size != (logo_size, logo_size):
                logo = logo.resize((logo_size, logo_size), Image.LANCZOS)
            offset = ((size - logo_size) // 2, (size - logo_size) // 2)
            image.alpha_composite(logo, offset)
        except OSError:
            pass  # the coloured square alone still works as the button
    return image


class DesktopFieldOverlay:
    """Small LocalGateKeys button beside protected desktop password fields."""

    DISCOVERY_POLL_MS = 300
    TRACK_MS = 6
    SIZE = OVERLAY_LOGICAL_SIZE
    GAP = OVERLAY_LOGICAL_GAP

    def __init__(self, *, on_click: Callable[[int], None], ignored_executables: set[str] | None = None,
                 scan: Callable[..., WindowSnapshot] = scan_foreground_window) -> None:
        self.on_click = on_click
        self.ignored_executables = {value.casefold() for value in (ignored_executables or set())}
        self._scan = scan
        self.enabled = False
        self.stopped = False
        self._busy = False
        self._state = "rest"
        self._lock = threading.Lock()
        self.target_hwnd: int | None = None
        self.target_window_rect: tuple[int, int, int, int] | None = None
        self.target_control_offset: tuple[int, int, int, int] | None = None
        self.last_position: tuple[int, int] | None = None
        self.overlay_hwnd = 0
        self.native_hidden = True
        self._overlay_size, self._overlay_logo_size, self._overlay_gap = overlay_render_metrics(None)
        self._rendered: tuple[int, str, bool] | None = None
        self._thread: threading.Thread | None = None
        self._thread_id = 0
        self._probe_thread: threading.Thread | None = None
        self._probe_running = False
        self._last_probe = 0.0
        self._ready = threading.Event()
        self._wndproc: Any = None  # keep the ctypes callback alive

    # ----------------------------------------------------------- public api
    def start(self) -> None:
        if os.name != "nt" or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="localgatekeys-overlay", daemon=True)
        self._thread.start()
        self._ready.wait(3)

    def stop(self) -> None:
        self.stopped = True
        self.enabled = False
        if os.name == "nt" and self._thread_id:
            import ctypes

            ctypes.windll.user32.PostThreadMessageW(self._thread_id, 0x0012, 0, 0)  # WM_QUIT
        for thread in (self._thread, self._probe_thread):
            if thread is not None and thread is not threading.current_thread() and thread.is_alive():
                thread.join(timeout=1.5)
        self._thread = None
        self._probe_thread = None

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = bool(enabled) and os.name == "nt"
        if not self.enabled:
            self.hide()

    def set_busy(self, busy: bool) -> None:
        self._busy = bool(busy)

    def hide(self) -> None:
        with self._lock:
            self.target_hwnd = None
            self.target_window_rect = None
            self.target_control_offset = None
            self.last_position = None
        if not self.native_hidden and self.overlay_hwnd:
            hide_overlay_window(self.overlay_hwnd)
        self.native_hidden = True

    # ------------------------------------------------------------ discovery
    def _maybe_probe(self) -> None:
        if not self.enabled or self._probe_running or self.stopped:
            return
        now = time.monotonic()
        if now - self._last_probe < self.DISCOVERY_POLL_MS / 1000.0:
            return
        self._last_probe = now
        self._probe_running = True
        self._probe_thread = threading.Thread(target=self._probe_worker, name="localgatekeys-overlay-probe",
                                              daemon=True)
        self._probe_thread.start()

    def _probe_worker(self) -> None:
        snapshot: WindowSnapshot | None = None
        try:
            # Discovery is non-secret: no executable hashing or signature check just to show a button.
            snapshot = self._scan(include_identity=False)
        except Exception:  # noqa: BLE001
            snapshot = None
        try:
            self.finish_probe(snapshot)
        finally:
            self._probe_running = False

    def finish_probe(self, snapshot: WindowSnapshot | None) -> None:
        """Adopt (or drop) the foreground window as the overlay target."""
        if self.stopped or not self.enabled or snapshot is None or snapshot.pid == os.getpid() \
                or Path(snapshot.exe_path).name.casefold() in self.ignored_executables:
            self.hide()
            return
        control = choose_overlay_password_control(snapshot.controls)
        if control is None:
            self.hide()
            return
        left, top, right, bottom = control.rectangle
        if right <= left or bottom <= top:
            self.hide()
            return
        target = resolve_native_toplevel_hwnd(snapshot.hwnd)
        foreground = resolve_native_toplevel_hwnd(get_foreground_hwnd())
        window_rect = get_window_rect(target)
        if not foreground_belongs_to_target(foreground, target, self.overlay_hwnd) or window_rect is None:
            self.hide()
            return
        with self._lock:
            # Keep the verified relative anchor while the same window stays active: Chromium/CEF providers
            # can report a stale absolute rectangle during a drag.
            if self.target_hwnd != target or self.target_control_offset is None:
                self.target_control_offset = control_rect_relative_to_window(control.rectangle, window_rect)
            self.target_hwnd = target
            self.target_window_rect = window_rect
        dpi = window_dpi(target)
        self._overlay_size, self._overlay_logo_size, self._overlay_gap = overlay_render_metrics(dpi)

    # --------------------------------------------------------------- window
    def _track(self) -> None:
        with self._lock:
            target, offset = self.target_hwnd, self.target_control_offset
        if not self.enabled or target is None or offset is None or not self.overlay_hwnd:
            if not self.native_hidden and self.overlay_hwnd:
                hide_overlay_window(self.overlay_hwnd)
                self.native_hidden = True
            return
        if not foreground_belongs_to_target(get_foreground_hwnd(), target, self.overlay_hwnd):
            if not self.native_hidden:
                hide_overlay_window(self.overlay_hwnd)
                self.native_hidden = True
            return
        rect = get_window_rect(target)
        if rect is None:
            self.hide()
            return
        x, y = calculate_overlay_position_from_offset(offset, rect, size=self._overlay_size, gap=self._overlay_gap)
        with self._lock:
            if not self.enabled or self.target_hwnd != target:  # hidden meanwhile (lock, setting, click)
                return
        self._paint()
        if self.native_hidden:
            set_overlay_owner(self.overlay_hwnd, target)
        position_overlay_window(self.overlay_hwnd, x, y, self._overlay_size, topmost=window_is_topmost(target))
        self.last_position = (x, y)
        self.native_hidden = False

    def _paint(self) -> None:
        key = (self._overlay_size, self._state, self._busy)
        if key == self._rendered or not self.overlay_hwnd:
            return
        try:
            image = render_overlay_image(self._overlay_size, self._overlay_logo_size, self._state, self._busy)
            update_layered_window(self.overlay_hwnd, image)
            self._rendered = key
        except Exception:  # noqa: BLE001 - never let drawing stop the tracker
            self._rendered = None

    def _clicked(self) -> None:
        if self._busy:
            return
        with self._lock:
            hwnd = self.target_hwnd
        self.hide()
        if hwnd:
            self.on_click(hwnd)

    def _run(self) -> None:  # pragma: no cover - needs a Windows desktop
        import ctypes
        from ctypes import wintypes

        # Private DLL handles: the type declarations below must not change ctypes.windll for other code.
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._thread_id = int(kernel32.GetCurrentThreadId())
        WM_TIMER, WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_LBUTTONUP = 0x0113, 0x0200, 0x0201, 0x0202
        WM_MOUSELEAVE, WM_MOUSEACTIVATE, WM_DESTROY, MA_NOACTIVATE = 0x02A3, 0x0021, 0x0002, 3
        LRESULT = ctypes.c_ssize_t
        WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
        user32.DefWindowProcW.restype = LRESULT
        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]

        class TRACKMOUSEEVENT(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("dwFlags", wintypes.DWORD), ("hwndTrack", wintypes.HWND),
                        ("dwHoverTime", wintypes.DWORD)]

        pressed = {"value": False}

        def proc(hwnd: Any, msg: int, wparam: int, lparam: int) -> int:
            try:
                if msg == WM_MOUSEACTIVATE:
                    return MA_NOACTIVATE  # clicking never takes focus from the app being filled
                if msg == WM_TIMER:
                    self._track()
                    self._maybe_probe()
                    return 0
                if msg == WM_MOUSEMOVE:
                    if self._state == "rest":
                        event = TRACKMOUSEEVENT(ctypes.sizeof(TRACKMOUSEEVENT), 0x00000002, hwnd, 0)  # TME_LEAVE
                        user32.TrackMouseEvent(ctypes.byref(event))
                    self._state = "pressed" if pressed["value"] else "hover"
                    self._paint()
                    return 0
                if msg == WM_MOUSELEAVE:
                    pressed["value"] = False
                    self._state = "rest"
                    self._paint()
                    return 0
                if msg == WM_LBUTTONDOWN:
                    pressed["value"] = True
                    self._state = "pressed"
                    self._paint()
                    return 0
                if msg == WM_LBUTTONUP:
                    was = pressed["value"]
                    pressed["value"] = False
                    self._state = "hover"
                    self._paint()
                    x, y = ctypes.c_short(lparam & 0xFFFF).value, ctypes.c_short((lparam >> 16) & 0xFFFF).value
                    if was and 0 <= x < self._overlay_size and 0 <= y < self._overlay_size:
                        self._clicked()
                    return 0
                if msg == WM_DESTROY:
                    user32.PostQuitMessage(0)
                    return 0
            except Exception:  # noqa: BLE001 - a window procedure must never raise
                return 0
            return int(user32.DefWindowProcW(hwnd, msg, wparam, lparam))

        self._wndproc = WNDPROC(proc)

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                        ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
                        ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                        ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]

        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        user32.LoadCursorW.restype = wintypes.HANDLE
        user32.LoadCursorW.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
        user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        user32.SetTimer.argtypes = [wintypes.HWND, ctypes.c_size_t, wintypes.UINT, ctypes.c_void_p]
        user32.KillTimer.argtypes = [wintypes.HWND, ctypes.c_size_t]
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.TrackMouseEvent.argtypes = [ctypes.POINTER(TRACKMOUSEEVENT)]
        user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.DispatchMessageW.restype = LRESULT
        instance = kernel32.GetModuleHandleW(None)
        cls = WNDCLASSW(0, self._wndproc, 0, 0, instance, None, user32.LoadCursorW(None, ctypes.c_void_p(32649)),
                        None, None, "LocalGateKeysFieldButton")
        user32.RegisterClassW(ctypes.byref(cls))
        WS_POPUP = 0x80000000
        WS_EX_LAYERED, WS_EX_TOOLWINDOW, WS_EX_NOACTIVATE = 0x00080000, 0x00000080, 0x08000000
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                           ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND,
                                           wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
        hwnd = user32.CreateWindowExW(WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                                      "LocalGateKeysFieldButton", "LocalGateKeys", WS_POPUP, 0, 0,
                                      self._overlay_size, self._overlay_size, None, None, instance, None)
        self.overlay_hwnd = int(hwnd or 0)
        if self.overlay_hwnd:
            user32.SetTimer(hwnd, 1, self.TRACK_MS, None)
        self._ready.set()
        if not self.overlay_hwnd:
            return
        message = wintypes.MSG()
        try:
            while not self.stopped and user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(message))
                user32.DispatchMessageW(ctypes.byref(message))
        finally:
            user32.KillTimer(hwnd, 1)
            user32.DestroyWindow(hwnd)
            self.overlay_hwnd = 0


def update_layered_window(hwnd: int, image: Any) -> None:  # pragma: no cover - Windows only
    """Show a Pillow RGBA image as the window's per-pixel-alpha surface."""
    import ctypes
    from ctypes import wintypes

    width, height = image.size
    r, g, b, a = image.split()
    from PIL import Image, ImageChops

    # Premultiplied BGRA, bottom-up rows are avoided with a negative height (top-down DIB).
    premultiplied = Image.merge("RGBA", (ImageChops.multiply(b, a), ImageChops.multiply(g, a),
                                         ImageChops.multiply(r, a), a))
    pixels = premultiplied.tobytes("raw", "RGBA")

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [("biSize", wintypes.DWORD), ("biWidth", ctypes.c_long), ("biHeight", ctypes.c_long),
                    ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", ctypes.c_long),
                    ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wintypes.DWORD),
                    ("biClrImportant", wintypes.DWORD)]

    class BLENDFUNCTION(ctypes.Structure):
        _fields_ = [("BlendOp", ctypes.c_ubyte), ("BlendFlags", ctypes.c_ubyte),
                    ("SourceConstantAlpha", ctypes.c_ubyte), ("AlphaFormat", ctypes.c_ubyte)]

    user32, gdi32 = ctypes.WinDLL("user32"), ctypes.WinDLL("gdi32")  # private: declarations stay local
    gdi32.CreateDIBSection.restype = wintypes.HBITMAP
    gdi32.CreateDIBSection.argtypes = [wintypes.HDC, ctypes.c_void_p, wintypes.UINT, ctypes.POINTER(ctypes.c_void_p),
                                       wintypes.HANDLE, wintypes.DWORD]
    gdi32.CreateCompatibleDC.restype = wintypes.HDC
    gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
    gdi32.SelectObject.restype = wintypes.HGDIOBJ
    gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
    gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    gdi32.DeleteDC.argtypes = [wintypes.HDC]
    user32.GetDC.restype = wintypes.HDC
    user32.GetDC.argtypes = [wintypes.HWND]
    user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    user32.UpdateLayeredWindow.argtypes = [wintypes.HWND, wintypes.HDC, ctypes.c_void_p, ctypes.c_void_p,
                                           wintypes.HDC, ctypes.c_void_p, wintypes.COLORREF, ctypes.c_void_p,
                                           wintypes.DWORD]
    screen = user32.GetDC(None)
    memory = gdi32.CreateCompatibleDC(screen)
    header = BITMAPINFOHEADER(ctypes.sizeof(BITMAPINFOHEADER), width, -height, 1, 32, 0, 0, 0, 0, 0, 0)
    bits = ctypes.c_void_p()
    bitmap = gdi32.CreateDIBSection(memory, ctypes.byref(header), 0, ctypes.byref(bits), None, 0)
    if not bitmap or not bits.value:
        gdi32.DeleteDC(memory)
        user32.ReleaseDC(None, screen)
        raise OSError("The field button could not be drawn")
    try:
        ctypes.memmove(bits, pixels, len(pixels))
        old = gdi32.SelectObject(memory, bitmap)
        size = wintypes.SIZE(width, height)
        source = wintypes.POINT(0, 0)
        blend = BLENDFUNCTION(0, 0, 255, 1)  # AC_SRC_OVER, AC_SRC_ALPHA
        user32.UpdateLayeredWindow(int(hwnd), screen, None, ctypes.byref(size), memory, ctypes.byref(source), 0,
                                   ctypes.byref(blend), 2)  # ULW_ALPHA
        gdi32.SelectObject(memory, old)
    finally:
        gdi32.DeleteObject(bitmap)
        gdi32.DeleteDC(memory)
        user32.ReleaseDC(None, screen)


def choose_overlay_password_control(controls: list[ControlDescriptor]) -> ControlDescriptor | None:
    """Pick the first visible, enabled, protected password control."""
    return next((c for c in controls if c.enabled and c.visible and c.is_password), None)


def control_rect_relative_to_window(control_rect: tuple[int, int, int, int],
                                    window_rect: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Convert an absolute UIA control rectangle to one relative to its top-level window."""
    left, top, right, bottom = control_rect
    window_left, window_top, _, _ = window_rect
    return (int(left - window_left), int(top - window_top), int(right - window_left), int(bottom - window_top))


def calculate_overlay_position_from_offset(relative_control_rect: tuple[int, int, int, int],
                                           current_window_rect: tuple[int, int, int, int], *, size: int = 28,
                                           gap: int = 4) -> tuple[int, int]:
    """Place the overlay from a stable window-relative control anchor."""
    left, top, right, bottom = relative_control_rect
    window_left, window_top, _, _ = current_window_rect
    return int(window_left + right + gap), int(window_top + top + max(0, ((bottom - top) - size) // 2))


def calculate_overlay_position(control_rect: tuple[int, int, int, int], anchor_window_rect: tuple[int, int, int, int],
                               current_window_rect: tuple[int, int, int, int], *, size: int = 28,
                               gap: int = 4) -> tuple[int, int]:
    """Return the overlay position after a top-level window move."""
    relative = control_rect_relative_to_window(control_rect, anchor_window_rect)
    return calculate_overlay_position_from_offset(relative, current_window_rect, size=size, gap=gap)


def foreground_belongs_to_target(foreground_hwnd: int, target_hwnd: int, overlay_hwnd: int = 0) -> bool:
    """Accept only the target (or the overlay itself during a click race)."""
    return bool(foreground_hwnd and target_hwnd and foreground_hwnd in {int(target_hwnd), int(overlay_hwnd or 0)})


_USER32: Any = None


def _user32() -> Any:
    """A private user32 with full 64-bit signatures (ctypes.windll stays untouched for other code)."""
    global _USER32
    if _USER32 is None:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32")
        user32.GetForegroundWindow.restype = wintypes.HWND
        user32.GetForegroundWindow.argtypes = []
        user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
        user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.GetAncestor.restype = wintypes.HWND
        user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
        user32.SetWindowLongPtrW.restype = ctypes.c_ssize_t
        user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t]
        user32.GetWindowLongPtrW.restype = ctypes.c_ssize_t
        user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                        ctypes.c_int, wintypes.UINT]
        _USER32 = user32
    return _USER32


def _hwnd(value: int) -> Any:
    import ctypes

    return ctypes.c_void_p(int(value))  # keeps negative markers (HWND_TOPMOST = -1) and 64-bit handles intact


def get_foreground_hwnd() -> int:
    if os.name != "nt":
        return 0
    return int(_user32().GetForegroundWindow() or 0)


def get_window_rect(hwnd: int) -> tuple[int, int, int, int] | None:
    """Return a top-level window rectangle without invoking UI Automation."""
    if os.name != "nt" or not hwnd:
        return None
    import ctypes
    from ctypes import wintypes

    rect = wintypes.RECT()
    if not _user32().GetWindowRect(_hwnd(hwnd), ctypes.byref(rect)):
        return None
    return int(rect.left), int(rect.top), int(rect.right), int(rect.bottom)


def hide_overlay_window(hwnd: int) -> None:
    if os.name != "nt" or not hwnd:
        return
    _user32().ShowWindow(_hwnd(hwnd), 0)  # SW_HIDE


def resolve_native_toplevel_hwnd(hwnd: int) -> int:
    """Resolve a child HWND to its native top-level window."""
    if os.name != "nt" or not hwnd:
        return int(hwnd or 0)
    root = _user32().GetAncestor(_hwnd(hwnd), 2)  # GA_ROOT
    return int(root or 0) or int(hwnd)


def set_overlay_owner(overlay_hwnd: int, target_hwnd: int) -> None:
    """Own the popup by the target window: above it, but never above unrelated apps (not TOPMOST)."""
    if os.name != "nt" or not overlay_hwnd:
        return
    _user32().SetWindowLongPtrW(_hwnd(overlay_hwnd), -8, int(target_hwnd or 0))  # GWLP_HWNDPARENT


def window_is_topmost(hwnd: int) -> bool:
    """An always-on-top app window: its button must be always-on-top too, or it hides behind the app."""
    if os.name != "nt" or not hwnd:
        return False
    return bool(int(_user32().GetWindowLongPtrW(_hwnd(hwnd), -20)) & 0x00000008)  # GWL_EXSTYLE, WS_EX_TOPMOST


def position_overlay_window(hwnd: int, x: int, y: int, size: int, *, topmost: bool = False) -> None:
    """Move/show the owned overlay without activating it, above its app (always-on-top only if the app is)."""
    if os.name != "nt" or not hwnd:
        return
    after = -1 if topmost else -2  # HWND_TOPMOST / HWND_NOTOPMOST (top of the normal windows)
    _user32().SetWindowPos(_hwnd(hwnd), _hwnd(after), int(x), int(y), int(size), int(size), 0x0010 | 0x0040)
