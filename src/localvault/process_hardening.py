"""Process-wide DLL-loading hardening for the frozen Windows executables.

Called first thing by both PyInstaller entry points (build-personal/
lgk_agent_entry.py and lgk_native_entry.py), before the GUI, camera, crypto or
pywin32 stacks load their DLLs. Standard library only, and never raises: a
failed step is reported in the returned :class:`HardeningResult` so the caller
can log it, and the process carries on as before.

What it does:

* ``SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)``: later
  ``LoadLibrary`` calls search only the application directory, directories
  added with ``AddDllDirectory``/``SetDllDirectory`` (PyInstaller's
  ``_internal`` folder, pywin32's ``os.add_dll_directory``) and System32, no
  longer the current directory or ``PATH``.
* ``SetProcessMitigationPolicy(ProcessImageLoadPolicy)`` with
  ``NoRemoteImages`` (no DLLs from network shares) and
  ``NoLowMandatoryLabelImages`` (no DLLs a low-integrity process could have
  written).

``PreferSystem32Images`` is deliberately NOT set. It makes the loader take a
System32 copy over the bundled one for every later load by name. The bundle
ships ``VCRUNTIME140.dll``, ``VCRUNTIME140_1.dll``, ``ucrtbase.dll``,
``libcrypto-3.dll``/``libssl-3.dll`` and ``python3.dll``; the bootloader has
already loaded ``VCRUNTIME140.dll`` from ``_internal`` before this code runs,
so the extension modules loaded afterwards would get ``VCRUNTIME140_1.dll``
from whatever Visual C++ redistributable the machine has (possibly older than
the one the bundle was built with, or a different build of OpenSSL/Python if
some installer dropped one into System32), mixing runtime versions inside one
process. The planting risk it would close is small here: the application folder
is per-user under ``%LOCALAPPDATA%\\Programs`` (the installer refuses any other
location), and anyone who can write a DLL there can replace the executables.
"""

from __future__ import annotations

import sys

# winbase.h / winnt.h
LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000
PROCESS_IMAGE_LOAD_POLICY = 10  # PROCESS_MITIGATION_POLICY::ProcessImageLoadPolicy
IMAGE_LOAD_NO_REMOTE_IMAGES = 0x1
IMAGE_LOAD_NO_LOW_MANDATORY_LABEL_IMAGES = 0x2
IMAGE_LOAD_PREFER_SYSTEM32_IMAGES = 0x4
IMAGE_LOAD_FLAGS = IMAGE_LOAD_NO_REMOTE_IMAGES | IMAGE_LOAD_NO_LOW_MANDATORY_LABEL_IMAGES


class HardeningResult:
    # A plain class, not a dataclass: the native host starts for every browser
    # message and should not pay for importing dataclasses/inspect.
    def __init__(self, applied: list[str] | None = None, failed: list[tuple[str, int]] | None = None) -> None:
        self.applied: list[str] = list(applied or [])
        # (step, Windows error code) pairs; codes only, never paths or messages.
        self.failed: list[tuple[str, int]] = list(failed or [])

    def __repr__(self) -> str:
        return f"HardeningResult(applied={self.applied!r}, failed={self.failed!r})"

    @property
    def ok(self) -> bool:
        return not self.failed

    def describe(self) -> str:
        return " ".join(f"{step}:winerror={code}" for step, code in self.failed)


def _kernel32():
    import ctypes

    return ctypes.WinDLL("kernel32", use_last_error=True)


def _last_error() -> int:
    import ctypes

    return int(ctypes.get_last_error())


def harden_process(*, platform: str | None = None) -> HardeningResult:
    """Apply the DLL search and image-load policies; Windows only, never raises."""

    result = HardeningResult()
    if (platform or sys.platform) != "win32":
        return result
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = _kernel32()
    except Exception:
        result.failed.append(("kernel32", 0))
        return result

    try:
        set_default = kernel32.SetDefaultDllDirectories
        set_default.argtypes = [wintypes.DWORD]
        set_default.restype = wintypes.BOOL
        if set_default(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS):
            result.applied.append("SetDefaultDllDirectories")
        else:
            result.failed.append(("SetDefaultDllDirectories", _last_error()))
    except Exception:
        result.failed.append(("SetDefaultDllDirectories", 0))

    try:
        flags = wintypes.DWORD(IMAGE_LOAD_FLAGS)
        set_policy = kernel32.SetProcessMitigationPolicy
        set_policy.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        set_policy.restype = wintypes.BOOL
        if set_policy(PROCESS_IMAGE_LOAD_POLICY, ctypes.byref(flags), ctypes.sizeof(flags)):
            result.applied.append("ProcessImageLoadPolicy")
        else:
            result.failed.append(("ProcessImageLoadPolicy", _last_error()))
    except Exception:
        result.failed.append(("ProcessImageLoadPolicy", 0))
    return result


def image_load_policy(*, platform: str | None = None) -> int | None:
    """Current ProcessImageLoadPolicy flags of this process (None if unavailable)."""

    if (platform or sys.platform) != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = _kernel32()
        get_policy = kernel32.GetProcessMitigationPolicy
        get_policy.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        get_policy.restype = wintypes.BOOL
        get_current = kernel32.GetCurrentProcess
        get_current.argtypes = []
        get_current.restype = wintypes.HANDLE
        flags = wintypes.DWORD(0)
        if not get_policy(get_current(), PROCESS_IMAGE_LOAD_POLICY, ctypes.byref(flags), ctypes.sizeof(flags)):
            return None
        return int(flags.value)
    except Exception:
        return None


def check_hardened(result: HardeningResult, *, platform: str | None = None) -> str | None:
    """Error text for a build self-check when the policies are not in force, else None."""

    if (platform or sys.platform) != "win32":
        return None
    if not result.ok:
        return f"process hardening failed: {result.describe()}"
    flags = image_load_policy(platform=platform)
    if flags is None or flags & IMAGE_LOAD_FLAGS != IMAGE_LOAD_FLAGS:
        return f"image load policy not in force (flags={flags})"
    return None
