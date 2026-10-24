from __future__ import annotations

import os
import threading
from collections.abc import Callable


class WindowsSessionMonitor:
    """Receive Windows lock/logoff/suspend notifications on a hidden message window."""

    def __init__(self, on_lock_required: Callable[[str], None]) -> None:
        self.on_lock_required = on_lock_required
        self.thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._hwnd: int | None = None
        # More than one monitor can briefly coexist while a profile chooser
        # replaces an older window.  Win32 class names are process-global, so
        # a PID-only name races with the previous monitor's registration.
        self._class_name = f"LocalGateKeysSessionMonitor-{os.getpid()}-{id(self):x}"

    def start(self) -> None:
        if os.name != "nt" or self.thread is not None:
            return
        self.thread = threading.Thread(target=self._run, name="localvault-session-monitor", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        if os.name == "nt" and self._hwnd:
            try:
                import win32api
                import win32con

                win32api.PostMessage(self._hwnd, win32con.WM_CLOSE, 0, 0)
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.5)
        self.thread = None

    def _run(self) -> None:
        try:
            import win32con
            import win32gui
            import win32ts
        except Exception:
            return

        WM_WTSSESSION_CHANGE = 0x02B1
        WTS_SESSION_LOCK = 0x7
        WTS_SESSION_LOGOFF = 0x6
        PBT_APMSUSPEND = 0x0004

        def wndproc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
            if msg == WM_WTSSESSION_CHANGE and wparam in (WTS_SESSION_LOCK, WTS_SESSION_LOGOFF):
                reason = "Windows session locked" if wparam == WTS_SESSION_LOCK else "Windows signed out"
                self.on_lock_required(reason)
                return 0
            if msg == win32con.WM_POWERBROADCAST and wparam == PBT_APMSUSPEND:
                self.on_lock_required("Windows is sleeping")
                return 1
            if msg == win32con.WM_CLOSE:
                win32gui.DestroyWindow(hwnd)
                return 0
            if msg == win32con.WM_DESTROY:
                win32gui.PostQuitMessage(0)
                return 0
            return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

        class_name = self._class_name
        wc = win32gui.WNDCLASS()
        wc.lpfnWndProc = wndproc
        wc.lpszClassName = class_name
        atom = win32gui.RegisterClass(wc)
        try:
            hwnd = win32gui.CreateWindow(class_name, class_name, 0, 0, 0, 0, 0, 0, 0, 0, None)
            self._hwnd = int(hwnd)
            try:
                win32ts.WTSRegisterSessionNotification(hwnd, win32ts.NOTIFY_FOR_THIS_SESSION)
            except Exception:
                pass
            while not self._stop.is_set():
                if not win32gui.PumpWaitingMessages():
                    self._stop.wait(0.05)
        finally:
            if self._hwnd:
                try:
                    win32ts.WTSUnRegisterSessionNotification(self._hwnd)
                except Exception:
                    pass
            self._hwnd = None
            try:
                win32gui.UnregisterClass(class_name, None)
            except Exception:
                pass


def windows_idle_seconds() -> float | None:
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]

        info = LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(info)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
            return None
        now = ctypes.windll.kernel32.GetTickCount()
        elapsed_ms = (int(now) - int(info.dwTime)) & 0xFFFFFFFF
        return elapsed_ms / 1000.0
    except Exception:
        return None
