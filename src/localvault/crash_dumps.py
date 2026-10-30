"""Keep Windows Error Reporting from writing a memory dump of the running app.

A crash dump of this process would hold the decrypted vault and its keys.  Both calls are best effort,
never raise and do nothing off Windows.
"""
from __future__ import annotations

import ctypes
import logging
import os
import sys

_log = logging.getLogger(__name__)

SEM_FAILCRITICALERRORS = 0x0001
SEM_NOGPFAULTERRORBOX = 0x0002


def exe_name() -> str:
    """The running program's file name: the frozen app, or the interpreter when run from source."""
    return os.path.basename(sys.executable)


def exclude_from_error_reporting(name: str | None = None) -> bool:
    """Ask WER to skip this program (per user, no admin rights): wer.dll WerAddExcludedApplication."""
    if os.name != "nt":
        return False
    try:
        add = ctypes.WinDLL("wer").WerAddExcludedApplication
        add.restype = ctypes.c_long
        add.argtypes = (ctypes.c_wchar_p, ctypes.c_int)
        return add(name or exe_name(), 0) >= 0  # S_OK; FALSE = this user only
    except Exception:  # noqa: BLE001 - hardening only; the app starts without it
        _log.debug("WerAddExcludedApplication failed", exc_info=True)
        return False


def suppress_fault_dialogs() -> bool:
    """SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX), keeping the flags already set."""
    if os.name != "nt":
        return False
    try:
        set_mode = ctypes.windll.kernel32.SetErrorMode
        set_mode.restype = ctypes.c_uint
        set_mode.argtypes = (ctypes.c_uint,)
        previous = int(set_mode(0))
        set_mode(previous | SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX)
        return True
    except Exception:  # noqa: BLE001 - hardening only
        _log.debug("SetErrorMode failed", exc_info=True)
        return False


def disable_crash_dumps() -> None:
    """Run both at startup.  Never raises."""
    try:
        exclude_from_error_reporting()
        suppress_fault_dialogs()
    except Exception:  # noqa: BLE001 - never fail startup
        pass
