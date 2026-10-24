from __future__ import annotations

import ctypes
import os
import time
from collections.abc import Callable
from ctypes import wintypes


class InputError(RuntimeError):
    pass


if os.name == "nt":
    ULONG_PTR = wintypes.WPARAM

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [
            ("wVk", wintypes.WORD),
            ("wScan", wintypes.WORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ULONG_PTR),
        ]

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ULONG_PTR)]

    class INPUT_UNION(ctypes.Union):
        _fields_ = [("ki", KEYBDINPUT), ("mi", MOUSEINPUT)]

    class INPUT(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("union", INPUT_UNION)]

    INPUT_KEYBOARD = 1
    KEYEVENTF_KEYUP = 0x0002
    KEYEVENTF_UNICODE = 0x0004
    VK_CONTROL = 0x11
    VK_A = 0x41
    VK_BACK = 0x08

_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_TOKEN_QUERY = 0x0008
_TOKEN_INTEGRITY_LEVEL = 25  # TOKEN_INFORMATION_CLASS.TokenIntegrityLevel


def _send(inputs: list[INPUT]) -> None:
    if os.name != "nt":
        raise InputError("Windows input is available only on Windows")
    array_type = INPUT * len(inputs)
    array = array_type(*inputs)
    sent = ctypes.windll.user32.SendInput(len(inputs), ctypes.byref(array), ctypes.sizeof(INPUT))
    if sent != len(inputs):
        raise InputError(f"SendInput sent {sent} of {len(inputs)} keyboard events")


def _integrity_level(process: int) -> int | None:
    """The mandatory integrity RID of a process handle's token, or None when unreadable."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD))
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetSidSubAuthorityCount.argtypes = (ctypes.c_void_p,)
    advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    advapi32.GetSidSubAuthority.argtypes = (ctypes.c_void_p, wintypes.DWORD)
    advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(process, _TOKEN_QUERY, ctypes.byref(token)):
        return None
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, _TOKEN_INTEGRITY_LEVEL, None, 0, ctypes.byref(needed))
        if not needed.value:
            return None
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, _TOKEN_INTEGRITY_LEVEL, buffer, needed, ctypes.byref(needed)):
            return None
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]  # TOKEN_MANDATORY_LABEL.Label.Sid
        count = advapi32.GetSidSubAuthorityCount(sid)[0]
        if not count:
            return None
        return int(advapi32.GetSidSubAuthority(sid, count - 1)[0])
    finally:
        kernel32.CloseHandle(token)


def _window_integrity_level(hwnd: int) -> int | None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(wintypes.HWND(int(hwnd)), ctypes.byref(pid))
    if not pid.value:
        return None
    process = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    if not process:
        return None
    try:
        return _integrity_level(process)
    finally:
        kernel32.CloseHandle(process)


def _own_integrity_level() -> int | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    return _integrity_level(kernel32.GetCurrentProcess())


def input_blocked_by_uipi(hwnd: int) -> bool:
    """True when Windows would silently drop SendInput aimed at this window.

    UIPI discards synthesized input to a process at a higher integrity level
    (an elevated app) while SendInput still reports every event as sent, so a
    fill would look successful. Unknown levels count as blocked (fail closed).
    """
    if os.name != "nt":
        return True
    try:
        target = _window_integrity_level(hwnd)
        own = _own_integrity_level()
    except Exception:  # noqa: BLE001 - unknown: refuse rather than report a false success
        return True
    if target is None or own is None:
        return True
    return target > own


def _virtual_key(vk: int, *, key_up: bool = False) -> INPUT:
    flags = KEYEVENTF_KEYUP if key_up else 0
    return INPUT(type=INPUT_KEYBOARD, union=INPUT_UNION(ki=KEYBDINPUT(vk, 0, flags, 0, 0)))


def clear_focused_control() -> None:
    """Select all and delete in the currently focused control."""

    _send(
        [
            _virtual_key(VK_CONTROL),
            _virtual_key(VK_A),
            _virtual_key(VK_A, key_up=True),
            _virtual_key(VK_CONTROL, key_up=True),
            _virtual_key(VK_BACK),
            _virtual_key(VK_BACK, key_up=True),
        ]
    )


def type_unicode(text: str, *, inter_key_delay: float = 0.0, guard: Callable[[], None] | None = None) -> None:
    """Send Unicode text to the focused control without using the clipboard."""

    if os.name != "nt":
        raise InputError("Windows input is available only on Windows")
    if "\x00" in text:
        raise InputError("Cannot type a null character")
    encoded = text.encode("utf-16-le")
    units = [
        int.from_bytes(encoded[index : index + 2], "little")
        for index in range(0, len(encoded), 2)
    ]
    for unit in units:
        if guard: guard()
        down = INPUT(
            type=INPUT_KEYBOARD,
            union=INPUT_UNION(ki=KEYBDINPUT(0, unit, KEYEVENTF_UNICODE, 0, 0)),
        )
        up = INPUT(
            type=INPUT_KEYBOARD,
            union=INPUT_UNION(
                ki=KEYBDINPUT(0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, 0, 0)
            ),
        )
        _send([down, up])
        if inter_key_delay:
            time.sleep(inter_key_delay)
