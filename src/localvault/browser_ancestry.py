"""Verify that a native-host process was launched by a real, signed browser.

Browsers start the registered native-messaging host themselves: Chromium
browsers on Windows normally go through ``cmd.exe /d /s /c "host" ...`` (or
launch the ``.exe`` directly when the ``NativeHostsExecutablesLaunchDirectly``
policy is set), Firefox launches it directly.  Any other same-user program can
also start the registered host and speak native messaging on its stdin, so
the host's argv (the extension origin) proves nothing about the caller.

:func:`verify_browser_ancestry` walks the parent chain of a process:

1. skip at most :data:`MAX_SELF_HOPS` ancestors whose image is one of the
   caller-supplied *self images* (the native host launcher, a venv redirector,
   the Python interpreter);
2. allow at most one ``cmd.exe`` from the Windows system directory
   (``System32``, or ``SysWOW64`` for a 32-bit browser);
3. require the next ancestor to be an allow-listed browser image
   (:data:`BROWSER_SIGNERS`) whose file carries a valid Authenticode signature
   (``WinVerifyTrust``) from that browser's vendor.

Every hop requires the parent to have been created before the child, so a
recycled parent PID never counts as the launcher.  Everything fails closed.

This is defense in depth, not a same-user malware boundary: a same-user
process can still drive a real browser (remote debugging, a sideloaded copy of
the extension) or start the host with a spoofed parent process attribute.

Standard library only (ctypes): the native host imports this before any
third-party package.
"""
from __future__ import annotations

import os
import sys
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass

# Browser image name -> Authenticode signer organisations accepted for it.
BROWSER_SIGNERS: dict[str, frozenset[str]] = {
    "chrome.exe": frozenset({"Google LLC"}),
    "msedge.exe": frozenset({"Microsoft Corporation"}),
    "brave.exe": frozenset({"Brave Software, Inc."}),
    "firefox.exe": frozenset({"Mozilla Corporation"}),
    "vivaldi.exe": frozenset({"Vivaldi Technologies AS"}),
    "opera.exe": frozenset({"Opera Norway AS"}),
}
MAX_SELF_HOPS = 4

# Error code/message shared by the native host and the agent.
BROWSER_UNVERIFIED_CODE = "caller_not_browser"
BROWSER_UNVERIFIED_MESSAGE = (
    "LocalGateKeys accepts browser requests only from a native host started by a "
    "signed Chrome, Edge, Brave, Firefox, Vivaldi or Opera. Restart the browser; "
    "if this repeats, repair the browser bridge from Connections."
)


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    parent_pid: int
    image: str
    created: int  # FILETIME ticks (100 ns since 1601)


@dataclass(frozen=True)
class AncestryDecision:
    ok: bool
    code: str = "ok"
    browser: str = ""

    def __bool__(self) -> bool:
        return self.ok


ProcessLookup = Callable[[int], "ProcessInfo | None"]
SignerLookup = Callable[[str], "str | None"]


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path)) if path else ""


# ---------------------------------------------------------------------------
# Windows primitives (ctypes)
# ---------------------------------------------------------------------------

def _system_directories() -> tuple[str, ...]:
    """``<Windows>\\System32`` and ``SysWOW64`` from the API, never from %SystemRoot%."""
    from .winpaths import system_windows_directory

    root = system_windows_directory()
    if not root:
        return ()
    return (os.path.join(root, "System32"), os.path.join(root, "SysWOW64"))


def _is_system_cmd(image: str) -> bool:
    if os.path.basename(image).lower() != "cmd.exe":
        return False
    return any(_norm(image) == _norm(os.path.join(directory, "cmd.exe"))
               for directory in _system_directories())


def _parent_pid_map() -> dict[int, int]:
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snapshot_fn = kernel32.CreateToolhelp32Snapshot
    snapshot_fn.argtypes = [wintypes.DWORD, wintypes.DWORD]
    snapshot_fn.restype = wintypes.HANDLE
    first, following = kernel32.Process32FirstW, kernel32.Process32NextW
    for function in (first, following):
        function.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        function.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    snapshot = snapshot_fn(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if not snapshot or snapshot == wintypes.HANDLE(-1).value:
        return {}
    parents: dict[int, int] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        more = first(snapshot, ctypes.byref(entry))
        while more:
            parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            more = following(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return parents


def _open_process_info(pid: int, parents: dict[int, int]) -> ProcessInfo | None:
    import ctypes
    from ctypes import wintypes

    if pid <= 4 or pid not in parents:
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                    ctypes.POINTER(wintypes.DWORD)]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return None
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
            return None
        created = (int(times[0].dwHighDateTime) << 32) | int(times[0].dwLowDateTime)
        return ProcessInfo(pid=pid, parent_pid=parents[pid], image=buffer.value, created=created)
    finally:
        kernel32.CloseHandle(handle)


def windows_process_lookup() -> ProcessLookup:
    """A lookup over one Toolhelp snapshot (parent PIDs) plus live handles."""
    parents = _parent_pid_map()
    return lambda pid: _open_process_info(pid, parents)


def process_image(pid: int) -> str:
    """Full image path of ``pid`` or "" (best effort)."""
    if os.name != "nt":
        return ""
    try:
        info = _open_process_info(pid, {pid: 0})
    except Exception:
        return ""
    return info.image if info else ""


def _authenticode_organisation(path: str) -> str | None:
    """Organisation (O=, else CN=) of a file's valid Authenticode signer, or None.

    ``WinVerifyTrust`` with the generic verify policy, no UI and no network
    revocation retrieval; the signer certificate comes from the verified state.
    """
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8)]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.POINTER(GUID))]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPWSTR),
                    ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    class CRYPT_PROVIDER_CERT_HEAD(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.c_void_p)]

    wintrust = ctypes.WinDLL("wintrust")
    crypt32 = ctypes.WinDLL("crypt32")
    verify = wintrust.WinVerifyTrust
    verify.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
    verify.restype = wintypes.LONG
    from_state = wintrust.WTHelperProvDataFromStateData
    from_state.argtypes = [wintypes.HANDLE]
    from_state.restype = ctypes.c_void_p
    signer_fn = wintrust.WTHelperGetProvSignerFromChain
    signer_fn.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    signer_fn.restype = ctypes.c_void_p
    cert_fn = wintrust.WTHelperGetProvCertFromChain
    cert_fn.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    cert_fn.restype = ctypes.POINTER(CRYPT_PROVIDER_CERT_HEAD)
    name_fn = crypt32.CertGetNameStringW
    name_fn.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                        wintypes.LPWSTR, wintypes.DWORD]
    name_fn.restype = wintypes.DWORD

    # WINTRUST_ACTION_GENERIC_VERIFY_V2 {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    action = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = 2  # WTD_UI_NONE
    data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
    data.dwUnionChoice = 1  # WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
    data.dwProvFlags = 0x00001000 | 0x00000010  # WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
    status = verify(None, ctypes.byref(action), ctypes.byref(data))
    try:
        if status != 0:
            return None
        provider = from_state(data.hWVTStateData)
        signer = signer_fn(provider, 0, False, 0) if provider else None
        cert = cert_fn(signer, 0) if signer else None
        if not cert or not cert.contents.pCert:
            return None
        for oid in (b"2.5.4.10", b"2.5.4.3"):  # organisationName, commonName
            buffer = ctypes.create_unicode_buffer(512)
            oid_buffer = ctypes.create_string_buffer(oid)
            length = name_fn(cert.contents.pCert, 3, 0, ctypes.cast(oid_buffer, ctypes.c_void_p),
                             buffer, 512)  # CERT_NAME_ATTR_TYPE
            if length > 1 and buffer.value:
                return buffer.value
        return None
    finally:
        data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
        verify(None, ctypes.byref(action), ctypes.byref(data))


_SIGNER_CACHE: dict[tuple[str, int, int], str | None] = {}
_SIGNER_LOCK = threading.Lock()


def authenticode_organisation(path: str) -> str | None:
    """Cached by (path, size, mtime): the agent checks on every pipe connection."""
    if os.name != "nt":
        return None
    try:
        stat = os.stat(path)
        key = (_norm(path), int(stat.st_size), int(stat.st_mtime_ns))
    except OSError:
        return None
    with _SIGNER_LOCK:
        if key in _SIGNER_CACHE:
            return _SIGNER_CACHE[key]
    try:
        organisation = _authenticode_organisation(path)
    except Exception:
        organisation = None
    with _SIGNER_LOCK:
        if len(_SIGNER_CACHE) > 64:
            _SIGNER_CACHE.clear()
        _SIGNER_CACHE[key] = organisation
    return organisation


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

def verify_browser_ancestry(pid: int, *, self_images: Iterable[str] = (),
                            lookup: ProcessLookup | None = None,
                            signer: SignerLookup | None = None,
                            is_system_cmd: Callable[[str], bool] | None = None) -> AncestryDecision:
    """Decide whether ``pid`` descends from an allow-listed signed browser.

    ``lookup``, ``signer`` and ``is_system_cmd`` default to the real Windows
    implementations; tests inject fakes.  Any error fails closed.
    """
    try:
        if lookup is None:
            if os.name != "nt" or sys.platform != "win32":
                return AncestryDecision(False, "ancestry_unavailable")
            lookup = windows_process_lookup()
        signer = signer or authenticode_organisation
        is_system_cmd = is_system_cmd or _is_system_cmd
        own = {_norm(path) for path in self_images if isinstance(path, str) and path}

        def parent_of(child: ProcessInfo) -> ProcessInfo | None:
            if child.parent_pid <= 0 or child.parent_pid == child.pid:
                return None
            parent = lookup(child.parent_pid)
            # A parent created after the child is a recycled PID, not the launcher.
            if parent is None or parent.created <= 0 or parent.created >= child.created:
                return None
            return parent

        current = lookup(int(pid))
        if current is None:
            return AncestryDecision(False, "ancestry_unavailable")
        parent = parent_of(current)
        hops = 0
        while parent is not None and _norm(parent.image) in own:
            hops += 1
            if hops > MAX_SELF_HOPS:
                return AncestryDecision(False, "browser_parent_unverified")
            current, parent = parent, parent_of(parent)
        if parent is not None and is_system_cmd(parent.image):
            current, parent = parent, parent_of(parent)
        if parent is None:
            return AncestryDecision(False, "browser_parent_unverified")
        name = os.path.basename(parent.image).lower()
        vendors = BROWSER_SIGNERS.get(name)
        if not vendors:
            return AncestryDecision(False, "browser_parent_unverified")
        if signer(parent.image) not in vendors:
            return AncestryDecision(False, "browser_signer_mismatch")
        return AncestryDecision(True, "ok", name)
    except Exception:
        return AncestryDecision(False, "ancestry_unavailable")


__all__ = [
    "AncestryDecision",
    "BROWSER_SIGNERS",
    "BROWSER_UNVERIFIED_CODE",
    "BROWSER_UNVERIFIED_MESSAGE",
    "ProcessInfo",
    "authenticode_organisation",
    "process_image",
    "verify_browser_ancestry",
    "windows_process_lookup",
]
