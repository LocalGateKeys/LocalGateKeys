"""Windows ``auto_type.Platform``: window facts, elevation, secure desktop and ``SendInput`` keys.

No clipboard, no keyboard hook, no hotkey.  Import-safe on every OS: the DLLs are loaded only when a
``WindowsPlatform`` is created.  Anything that cannot be checked counts as unsafe (an unreadable process
token is "elevated", an unreadable input desktop is "secure").
"""
from __future__ import annotations

import ctypes
import os
import time
from dataclasses import dataclass
from typing import Any, Protocol

from .auto_type import AutoTypeError, Target

# --- SendInput structures (winuser.h), laid out for 32- and 64-bit -------------------------------
ULONG_PTR = ctypes.c_size_t
INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
VK = {"tab": 0x09, "enter": 0x0D}
VK_SHIFT, VK_CONTROL, VK_MENU, VK_CAPITAL = 0x10, 0x11, 0x12, 0x14
VK_LSHIFT, VK_LWIN, VK_RWIN = 0xA0, 0x5B, 0x5C
SHIFT_SCAN = 0x2A  # left Shift, the same on every layout
# Seconds after a key goes up and after Shift changes.
CHAR_DELAY = 0.02
# Seconds a key stays down before its key up, with nothing else sent meanwhile (see "Why real keys" below).
KEY_HOLD = 0.25
# How long typing waits for the user to let go of Shift, Ctrl, Alt or Win before it stops.
# Keyboard layouts whose input usually runs through an IME (Chinese, Japanese, Korean): a real "k" key could start
# a composition, so every character is sent as a unicode key there.
IME_LANGUAGES = frozenset({0x04, 0x11, 0x12})
WM_NULL, SMTO_ABORTIFHUNG = 0x0000, 0x0002
SETTLE_TIMEOUT_MS = 2000  # a target that reads no messages for this long is busy or hung: typing stops
TOUNICODE_KEEP_STATE = 0x4  # ToUnicodeEx: do not change the keyboard (dead key) state (Windows 10 1607+)


# --- Why real keys, held down (live check 2026-11-15) ---------------------------------------------
# Windows 11 Notepad sometimes handles a key late (most often the key after a ".") and then reads the keyboard
# state of that later moment, not of the key's own message:
# * a KEYEVENTF_UNICODE key (WM_KEYDOWN VK_PACKET) does not carry its character; Windows keeps the last one per
#   thread, so a later unicode key overwrote it: "test.example" arrived as "test.xxample" (up to 16 of 50 lines);
# * a real key carries its own code, but Shift released 20-100 ms after "S" gave "Alice.smith", and a key already
#   released by then could be lost ("mail.test" arrived as "mail.est").
# So characters the target's layout types with no modifier or with Shift alone (checked with ToUnicodeEx, so Caps
# Lock and dead keys are accounted for) go as real keys, with Shift pressed once for a run of shifted characters;
# anything else (AltGr, dead keys, characters not on the layout, emoji, IME languages) stays a unicode key; and
# every key stays down ``KEY_HOLD`` with nothing else sent, so a late reader still sees the key, its Shift and its
# character. Typing is slower (about 0.3 s a character) but every line came out right; see
# docs/reports/2026-11-15-verify-desktop-extension.md for the measurements.
@dataclass(frozen=True)
class KeyPlan:
    """How one character is typed: a real key (``vk``/``scan``, Shift held or not) or a unicode key."""

    char: str
    vk: int = 0
    scan: int = 0
    shift: bool = False

    @property
    def unicode(self) -> bool:
        return not self.vk


class LayoutApi(Protocol):
    """The keyboard layout of the window being typed into (a fake in tests)."""

    def language(self) -> int: ...
    def vk_scan(self, char: str) -> int: ...  # VkKeyScanExW: low byte vk, high byte shift state; -1 = none
    def scan_code(self, vk: int) -> int: ...  # MapVirtualKeyExW(MAPVK_VK_TO_VSC)
    def to_unicode(self, vk: int, scan: int, shift: bool, caps: bool) -> str | None: ...  # None for a dead key
    def caps_lock(self) -> bool: ...


def plan_char(char: str, layout: LayoutApi, caps: bool) -> KeyPlan:
    """A real key only when that key, with Shift or without, produces exactly ``char`` on ``layout``."""
    code = ord(char) if len(char) == 1 else -1
    if code < 0x20 or code == 0x7F or 0xD800 <= code <= 0xDFFF or code > 0xFFFF:
        return KeyPlan(char)  # control characters, surrogates and emoji stay unicode
    if (layout.language() & 0x3FF) in IME_LANGUAGES:
        return KeyPlan(char)
    found = layout.vk_scan(char)
    if found is None or found < 0 or (found & 0xFFFF) == 0xFFFF:
        return KeyPlan(char)
    vk, mods = found & 0xFF, (found >> 8) & 0xFF
    if not vk or vk == 0xFF or mods & ~0x1:  # Ctrl, Alt (AltGr) or other shift states: unicode
        return KeyPlan(char)
    scan = layout.scan_code(vk)
    if not scan:
        return KeyPlan(char)
    shifted = bool(mods & 0x1)
    for shift in (shifted, not shifted):  # Caps Lock can flip which one is right
        if layout.to_unicode(vk, scan, shift, caps) == char:
            return KeyPlan(char, vk=vk, scan=scan, shift=shift)
    return KeyPlan(char)


def plan_text(text: str, layout: LayoutApi) -> list[KeyPlan]:
    caps = layout.caps_lock()
    plans: list[KeyPlan] = []
    for char in _chars(text):
        plans.append(plan_char(char, layout, caps))
    return plans


def _chars(text: str) -> list[str]:
    """Characters of ``text``; a surrogate pair (as Python sees it from some sources) stays one item."""
    out: list[str] = []
    for char in text:
        if out and 0xDC00 <= ord(char) <= 0xDFFF and len(out[-1]) == 1 and 0xD800 <= ord(out[-1]) <= 0xDBFF:
            out[-1] += char
        else:
            out.append(char)
    return out


def vk_input(vk: int, scan: int, up: bool) -> Any:
    """One real key event as a one-item ``INPUT`` array."""
    array = (INPUT * 1)()
    array[0].type = INPUT_KEYBOARD
    array[0].ki.wVk = vk
    array[0].ki.wScan = scan
    array[0].ki.dwFlags = KEYEVENTF_KEYUP if up else 0
    return array


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", ctypes.c_long), ("dy", ctypes.c_long), ("mouseData", ctypes.c_uint32),
                ("dwFlags", ctypes.c_uint32), ("time", ctypes.c_uint32), ("dwExtraInfo", ULONG_PTR)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", ctypes.c_uint16), ("wScan", ctypes.c_uint16), ("dwFlags", ctypes.c_uint32),
                ("time", ctypes.c_uint32), ("dwExtraInfo", ULONG_PTR)]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", ctypes.c_uint32), ("wParamL", ctypes.c_uint16), ("wParamH", ctypes.c_uint16)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", ctypes.c_uint32), ("u", _INPUTUNION)]


def utf16_units(text: str) -> list[int]:
    """UTF-16 code units of ``text`` (a character outside the BMP becomes its surrogate pair)."""
    data = text.encode("utf-16-le", "surrogatepass")
    return [int.from_bytes(data[i:i + 2], "little") for i in range(0, len(data), 2)]


def unicode_inputs(text: str) -> Any:
    """Key down + key up per UTF-16 code unit, as one ``INPUT`` array."""
    units = utf16_units(text)
    array = (INPUT * (2 * len(units)))()
    for i, unit in enumerate(units):
        for j, flags in enumerate((KEYEVENTF_UNICODE, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)):
            item = array[2 * i + j]
            item.type = INPUT_KEYBOARD
            item.ki.wVk = 0
            item.ki.wScan = unit
            item.ki.dwFlags = flags
    units.clear()
    return array


def unicode_presses(char: str) -> tuple[Any, Any]:
    """``(key downs, key ups)`` for one character, as two ``INPUT`` arrays (a surrogate pair stays together)."""
    both = unicode_inputs(char)
    count = len(both) // 2
    down, up = (INPUT * count)(), (INPUT * count)()
    for i in range(count):
        ctypes.memmove(ctypes.byref(down, i * ctypes.sizeof(INPUT)), ctypes.byref(both[2 * i]), ctypes.sizeof(INPUT))
        ctypes.memmove(ctypes.byref(up, i * ctypes.sizeof(INPUT)), ctypes.byref(both[2 * i + 1]), ctypes.sizeof(INPUT))
    ctypes.memset(ctypes.addressof(both), 0, ctypes.sizeof(both))
    return down, up


def key_inputs(key: str) -> Any:
    vk = VK.get(key)
    if vk is None:
        raise AutoTypeError("unknown_key")
    array = (INPUT * 2)()
    for j, flags in enumerate((0, KEYEVENTF_KEYUP)):
        array[j].type = INPUT_KEYBOARD
        array[j].ki.wVk = vk
        array[j].ki.dwFlags = flags
    return array


class RECT(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long), ("right", ctypes.c_long), ("bottom", ctypes.c_long)]


class GUITHREADINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint32), ("flags", ctypes.c_uint32), ("hwndActive", ctypes.c_void_p),
                ("hwndFocus", ctypes.c_void_p), ("hwndCapture", ctypes.c_void_p),
                ("hwndMenuOwner", ctypes.c_void_p), ("hwndMoveSize", ctypes.c_void_p),
                ("hwndCaret", ctypes.c_void_p), ("rcCaret", RECT)]


class WindowsLayout:
    """``LayoutApi`` for one keyboard layout handle (the target thread's), through the platform's bound calls."""

    def __init__(self, platform: WindowsPlatform, hkl: int) -> None:
        self._p, self._hkl = platform, hkl

    def language(self) -> int:
        return int(self._hkl or 0) & 0xFFFF

    def vk_scan(self, char: str) -> int:
        return int(self._p._VkKeyScanExW(char, self._hkl))

    def scan_code(self, vk: int) -> int:
        return int(self._p._MapVirtualKeyExW(vk, 0, self._hkl))  # MAPVK_VK_TO_VSC

    def to_unicode(self, vk: int, scan: int, shift: bool, caps: bool) -> str | None:
        state = (ctypes.c_ubyte * 256)()
        if shift:
            state[VK_SHIFT] = state[VK_LSHIFT] = 0x80
        if caps:
            state[VK_CAPITAL] = 0x01
        buffer = ctypes.create_unicode_buffer(8)
        try:
            count = int(self._p._ToUnicodeEx(vk, scan, state, buffer, 8, TOUNICODE_KEEP_STATE, self._hkl))
            return buffer.value[:count] if count > 0 else None
        finally:
            ctypes.memset(buffer, 0, ctypes.sizeof(buffer))

    def caps_lock(self) -> bool:
        return bool(self._p._GetKeyState(VK_CAPITAL) & 1)


# --- Win32 constants ------------------------------------------------------------------------------
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TOKEN_ELEVATION_CLASS = 20  # TokenElevation
DESKTOP_READOBJECTS = 0x0001
UOI_NAME = 2
SW_RESTORE = 9


class WindowsPlatform:
    """The real input layer.  Create only on Windows."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("auto-type needs Windows")
        from ctypes import wintypes as w

        self._w = w
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        HWND, HANDLE, BOOL, DWORD = w.HWND, w.HANDLE, w.BOOL, w.DWORD

        def bind(dll: Any, name: str, restype: Any, *argtypes: Any) -> Any:
            fn = getattr(dll, name)
            fn.restype, fn.argtypes = restype, list(argtypes)
            return fn

        self._GetForegroundWindow = bind(user32, "GetForegroundWindow", HWND)
        self._IsWindow = bind(user32, "IsWindow", BOOL, HWND)
        self._IsIconic = bind(user32, "IsIconic", BOOL, HWND)
        self._GetWindowTextLengthW = bind(user32, "GetWindowTextLengthW", ctypes.c_int, HWND)
        self._GetWindowTextW = bind(user32, "GetWindowTextW", ctypes.c_int, HWND, w.LPWSTR, ctypes.c_int)
        self._GetWindowThreadProcessId = bind(user32, "GetWindowThreadProcessId", DWORD, HWND,
                                              ctypes.POINTER(DWORD))
        self._SetForegroundWindow = bind(user32, "SetForegroundWindow", BOOL, HWND)
        self._ShowWindow = bind(user32, "ShowWindow", BOOL, HWND, ctypes.c_int)
        self._SendInput = bind(user32, "SendInput", ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(INPUT),
                               ctypes.c_int)
        self._OpenInputDesktop = bind(user32, "OpenInputDesktop", HANDLE, DWORD, BOOL, DWORD)
        self._CloseDesktop = bind(user32, "CloseDesktop", BOOL, HANDLE)
        self._GetUserObjectInformationW = bind(user32, "GetUserObjectInformationW", BOOL, HANDLE, ctypes.c_int,
                                               ctypes.c_void_p, DWORD, ctypes.POINTER(DWORD))
        self._OpenProcess = bind(kernel32, "OpenProcess", HANDLE, DWORD, BOOL, DWORD)
        self._CloseHandle = bind(kernel32, "CloseHandle", BOOL, HANDLE)
        self._QueryFullProcessImageNameW = bind(kernel32, "QueryFullProcessImageNameW", BOOL, HANDLE, DWORD,
                                                w.LPWSTR, ctypes.POINTER(DWORD))
        self._OpenProcessToken = bind(advapi32, "OpenProcessToken", BOOL, HANDLE, DWORD, ctypes.POINTER(HANDLE))
        self._GetTokenInformation = bind(advapi32, "GetTokenInformation", BOOL, HANDLE, ctypes.c_int,
                                         ctypes.c_void_p, DWORD, ctypes.POINTER(DWORD))
        HKL = ctypes.c_void_p
        self._GetKeyboardLayout = bind(user32, "GetKeyboardLayout", HKL, DWORD)
        self._VkKeyScanExW = bind(user32, "VkKeyScanExW", ctypes.c_short, ctypes.c_wchar, HKL)
        self._MapVirtualKeyExW = bind(user32, "MapVirtualKeyExW", ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, HKL)
        self._ToUnicodeEx = bind(user32, "ToUnicodeEx", ctypes.c_int, ctypes.c_uint, ctypes.c_uint,
                                 ctypes.POINTER(ctypes.c_ubyte), w.LPWSTR, ctypes.c_int, ctypes.c_uint, HKL)
        self._GetKeyState = bind(user32, "GetKeyState", ctypes.c_short, ctypes.c_int)
        self._GetGUIThreadInfo = bind(user32, "GetGUIThreadInfo", BOOL, DWORD, ctypes.POINTER(GUITHREADINFO))
        self._SendMessageTimeoutW = bind(user32, "SendMessageTimeoutW", ctypes.c_size_t, HWND, ctypes.c_uint,
                                         ctypes.c_size_t, ctypes.c_ssize_t, ctypes.c_uint, ctypes.c_uint,
                                         ctypes.POINTER(ctypes.c_size_t))
        self._settle_hwnd = 0

    # ------------------------------------------------------------------ windows
    def foreground(self) -> int:
        return int(self._GetForegroundWindow() or 0)

    def _pid(self, hwnd: int) -> int:
        pid = self._w.DWORD(0)
        self._GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return int(pid.value)

    def _image(self, pid: int) -> str:
        handle = self._OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return ""
        try:
            size = self._w.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if not self._QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                return ""
            return os.path.basename(buffer.value)
        finally:
            self._CloseHandle(handle)

    def describe(self, hwnd: int) -> Target | None:
        if not hwnd or not self._IsWindow(hwnd):
            return None
        pid = self._pid(hwnd)
        if not pid:
            return None
        length = max(0, int(self._GetWindowTextLengthW(hwnd)))
        buffer = ctypes.create_unicode_buffer(length + 1)
        self._GetWindowTextW(hwnd, buffer, length + 1)
        return Target(hwnd=int(hwnd), title=buffer.value, process=self._image(pid), pid=pid)

    def is_elevated(self, hwnd: int) -> bool:
        """True when the window's process token is elevated, or when that cannot be read."""
        pid = self._pid(hwnd) if hwnd else 0
        if not pid:
            return True
        process = self._OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not process:
            return True
        try:
            token = self._w.HANDLE()
            if not self._OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
                return True
            try:
                elevation = self._w.DWORD(0)
                size = self._w.DWORD(0)
                if not self._GetTokenInformation(token, TOKEN_ELEVATION_CLASS, ctypes.byref(elevation),
                                                 ctypes.sizeof(elevation), ctypes.byref(size)):
                    return True
                return elevation.value != 0
            finally:
                self._CloseHandle(token)
        finally:
            self._CloseHandle(process)

    def secure_desktop(self) -> bool:
        """True unless the input desktop can be opened and is named ``Default``."""
        desktop = self._OpenInputDesktop(0, False, DESKTOP_READOBJECTS)
        if not desktop:
            return True
        try:
            buffer = ctypes.create_unicode_buffer(256)
            needed = self._w.DWORD(0)
            if not self._GetUserObjectInformationW(desktop, UOI_NAME, buffer, ctypes.sizeof(buffer),
                                                   ctypes.byref(needed)):
                return True
            return buffer.value.casefold() != "default"
        finally:
            self._CloseDesktop(desktop)

    def activate(self, hwnd: int) -> bool:
        if not hwnd or not self._IsWindow(hwnd):
            return False
        if self._IsIconic(hwnd):
            self._ShowWindow(hwnd, SW_RESTORE)
        self._SetForegroundWindow(hwnd)
        for _ in range(25):  # up to about half a second for the switch to land
            if self.foreground() == hwnd:
                return True
            time.sleep(0.02)
        return False

    # -------------------------------------------------------------------- input
    def _send(self, array: Any) -> None:
        count = len(array)
        try:
            sent = int(self._SendInput(count, array, ctypes.sizeof(INPUT))) if count else 0
        finally:
            ctypes.memset(ctypes.addressof(array), 0, ctypes.sizeof(array))  # no key codes left behind
        if sent != count:
            raise AutoTypeError("send_failed")

    def _settle(self) -> None:
        """Wait until the target window's thread is reading messages again before the next key event."""
        hwnd = self._settle_hwnd
        if not hwnd:
            return
        result = ctypes.c_size_t(0)
        if not self._SendMessageTimeoutW(hwnd, WM_NULL, 0, 0, SMTO_ABORTIFHUNG, SETTLE_TIMEOUT_MS,
                                         ctypes.byref(result)):
            raise AutoTypeError("target_busy")

    def _event(self, array: Any) -> None:
        try:
            self._settle()
        except AutoTypeError:
            ctypes.memset(ctypes.addressof(array), 0, ctypes.sizeof(array))
            raise
        self._send(array)

    def _press(self, down: Any, up: Any) -> None:
        """Key down, ``KEY_HOLD``, key up; once the key is down, the key up is always sent."""
        try:
            self._event(down)
        except AutoTypeError:
            ctypes.memset(ctypes.addressof(up), 0, ctypes.sizeof(up))
            raise
        try:
            self.sleep(KEY_HOLD)
        finally:
            self._send(up)
        self.sleep(CHAR_DELAY)

    def layout_for(self, hwnd: int) -> LayoutApi:
        """The keyboard layout of the thread that owns the focus in ``hwnd``'s thread (else ``hwnd``'s own)."""
        thread = int(self._GetWindowThreadProcessId(hwnd, None)) if hwnd else 0
        if thread:
            info = GUITHREADINFO()
            info.cbSize = ctypes.sizeof(GUITHREADINFO)
            if self._GetGUIThreadInfo(thread, ctypes.byref(info)) and info.hwndFocus:
                thread = int(self._GetWindowThreadProcessId(info.hwndFocus, None)) or thread
        return WindowsLayout(self, int(self._GetKeyboardLayout(thread) or 0))

    def _set_shift(self, down: bool) -> None:
        self._event(vk_input(VK_SHIFT, SHIFT_SCAN, not down))
        self.sleep(CHAR_DELAY)

    def _release_shift(self) -> None:
        """Shift up on the way out, also when the target is busy or the window changed (no settle check)."""
        self._send(vk_input(VK_SHIFT, SHIFT_SCAN, True))
        self.sleep(CHAR_DELAY)

    def send_text(self, text: str) -> None:
        """Each character as its own key events, one per ``SendInput`` call, each key held ``KEY_HOLD``.

        Characters the target's keyboard layout types with no modifier or Shift alone go as real keys; the rest as
        unicode keys (see "Why real keys" above). Typing stops if the foreground window changes, and Shift is
        never left down.
        """
        if not text:
            return
        start = self.foreground()
        plans = plan_text(text, self.layout_for(start))
        self._settle_hwnd = start
        shift = False
        try:
            for index, plan in enumerate(plans):
                if index and self.foreground() != start:
                    raise AutoTypeError("foreground_changed")
                if plan.unicode:
                    if shift:
                        self._set_shift(False)
                        shift = False
                    self._press(*unicode_presses(plan.char))
                    continue
                if plan.shift != shift:
                    self._set_shift(plan.shift)
                    shift = plan.shift
                self._press(vk_input(plan.vk, plan.scan, False), vk_input(plan.vk, plan.scan, True))
        finally:
            try:
                if shift:
                    self._release_shift()
            finally:
                plans.clear()
                self._settle_hwnd = 0

    def send_key(self, key: str) -> None:
        both = key_inputs(key)
        down, up = (INPUT * 1)(), (INPUT * 1)()
        ctypes.memmove(ctypes.byref(down), ctypes.byref(both[0]), ctypes.sizeof(INPUT))
        ctypes.memmove(ctypes.byref(up), ctypes.byref(both[1]), ctypes.sizeof(INPUT))
        self._settle_hwnd = self.foreground()
        try:
            self._press(down, up)
        finally:
            self._settle_hwnd = 0

    def sleep(self, seconds: float) -> None:
        time.sleep(max(0.0, float(seconds)))


__all__ = ["HARDWAREINPUT", "INPUT", "KEYBDINPUT", "MOUSEINPUT", "KeyPlan", "LayoutApi", "WindowsLayout",
           "WindowsPlatform", "key_inputs", "plan_char", "plan_text", "unicode_inputs", "unicode_presses",
           "utf16_units", "vk_input"]
