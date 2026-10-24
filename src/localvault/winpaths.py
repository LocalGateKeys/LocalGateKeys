"""Planting-safe Windows tool paths and current-account identity.

``subprocess`` on Windows resolves a bare executable name through the
application directory, the current directory and ``PATH`` before System32, so a
binary dropped next to the app (or in the working directory) would run instead
of the real tool. Every Windows tool LocalGateKeys launches goes through
:func:`system32`. ACL grants use :func:`current_user_sid` rather than an
environment-derived user name, which ``icacls`` may also resolve ambiguously.
"""
from __future__ import annotations

import os


def system32(executable: str) -> str:
    """Absolute path of a System32 tool so search-path entries cannot shadow it."""

    root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    if not os.path.isabs(root):
        root = r"C:\Windows"
    return os.path.join(root, "System32", executable)


def windows_powershell() -> str:
    """Absolute path of the in-box Windows PowerShell 5.1 executable."""

    return system32(os.path.join("WindowsPowerShell", "v1.0", "powershell.exe"))


def current_user_sid() -> str | None:
    """Return the current process token's user SID (``S-1-5-21-...``), or ``None``."""

    if os.name != "nt":
        return None
    try:
        import ctypes
        import ctypes.wintypes as wintypes

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                                 ctypes.POINTER(wintypes.DWORD)]
        advapi32.GetTokenInformation.restype = wintypes.BOOL
        advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
            return None
        try:
            size = wintypes.DWORD()
            advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
            if not size.value:
                return None
            buffer = ctypes.create_string_buffer(size.value)
            if not advapi32.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
                return None
            sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
            text = ctypes.c_wchar_p()
            if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(sid_pointer), ctypes.byref(text)):
                return None
            try:
                value = text.value
            finally:
                kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
            return value if value and value.startswith("S-1-") else None
        finally:
            kernel32.CloseHandle(token)
    except (OSError, AttributeError, ValueError):
        return None
