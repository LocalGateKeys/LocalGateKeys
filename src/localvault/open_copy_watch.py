"""Delete a decrypted document copy as soon as the app it was opened in is done with it.

Opening a document writes a decrypted copy to the profile's opened-copies folder and hands it to
the Windows default app. A watcher per copy then deletes it when:

* the app process Windows reports for the launch has exited and nothing holds the file, or
* the file was seen in use (Restart Manager lists a process holding it) and no longer is, or
* nothing ever held it (the app read it and let go, as many viewers do) for ``GRACE_SECONDS``.

If LocalGateKeys exits while a copy is still open, :func:`spawn_exit_sweeper` starts a small
detached process (``--sweep-open-copies``) that keeps checking until the copies are gone. The
startup sweep in ``web/main.py`` stays as the last resort after a crash or power loss.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

POLL_SECONDS = 2.0
GRACE_SECONDS = 45.0
HANDOFF_SECONDS = 5.0  # a launch process gone this fast handed the file to an app already running
SWEEPER_MAX_SECONDS = 24 * 3600


# ------------------------------------------------------------------ Windows checks
def file_in_use(path: Path) -> bool:
    """True when the Restart Manager lists a process holding ``path`` open (or the check itself fails)."""
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes

    rm = ctypes.WinDLL("rstrtmgr")
    session = wintypes.DWORD()
    key = ctypes.create_unicode_buffer(33)  # CCH_RM_SESSION_KEY + 1
    rm.RmStartSession.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, wintypes.LPWSTR]
    rm.RmRegisterResources.argtypes = [wintypes.DWORD, wintypes.UINT, ctypes.POINTER(wintypes.LPCWSTR),
                                       wintypes.UINT, ctypes.c_void_p, wintypes.UINT, ctypes.c_void_p]
    rm.RmGetList.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.UINT), ctypes.POINTER(wintypes.UINT),
                             ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    rm.RmEndSession.argtypes = [wintypes.DWORD]
    if rm.RmStartSession(ctypes.byref(session), 0, key) != 0:
        return True  # unknown: keep the copy for now
    try:
        files = (wintypes.LPCWSTR * 1)(str(path))
        if rm.RmRegisterResources(session, 1, files, 0, None, 0, None) != 0:
            return True
        needed, count, reasons = wintypes.UINT(0), wintypes.UINT(0), wintypes.DWORD(0)
        result = rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count), None, ctypes.byref(reasons))
        if result == 234:  # ERROR_MORE_DATA: at least one process holds it
            return True
        return result != 0 or needed.value > 0
    finally:
        rm.RmEndSession(session)


class _Process:
    """A process handle from ShellExecuteEx (closed when the watcher ends)."""

    def __init__(self, handle: int) -> None:
        self.handle = handle

    def running(self) -> bool:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        return kernel32.WaitForSingleObject(ctypes.c_void_p(self.handle), 0) == 0x102  # WAIT_TIMEOUT

    def close(self) -> None:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle(ctypes.c_void_p(self.handle))


def shell_open(path: Path) -> _Process | None:
    """Open ``path`` in its default app; return the app process when Windows reports one.

    Only allow-listed viewer types are handed to Windows (checked again here, after
    ``write_open_copy``), so a caller can never launch a program or script this way.
    """
    from .attachments import can_open_externally

    if not can_open_externally(Path(path).name):
        raise PermissionError("This file type is not opened in other apps")
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE),
                    ("hProcess", wintypes.HANDLE)]

    ole32 = ctypes.WinDLL("ole32")
    ole32.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    ole32.CoInitializeEx(None, 0x2 | 0x4)  # apartment-threaded, no OLE1 DDE; some handlers need COM
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
    info.fMask = 0x00000040 | 0x00000400  # SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI
    info.lpVerb = "open"
    info.lpFile = str(path)
    info.nShow = 1  # SW_SHOWNORMAL
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        raise OSError(ctypes.get_last_error(), "Windows could not open the file")
    return _Process(int(info.hProcess)) if info.hProcess else None


# ---------------------------------------------------------------------- the watcher
def remove_copy(path: Path) -> bool:
    """Delete one copy and its random folder; False when Windows refuses (still open)."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        return False
    try:
        path.parent.rmdir()
    except OSError:
        pass
    return True


class CopyWatcher:
    """Decide when one opened copy can go. ``step`` is one check; ``run`` loops it on a thread."""

    def __init__(self, path: Path, process: Any = None, *, in_use: Callable[[Path], bool] = file_in_use,
                 clock: Callable[[], float] = time.monotonic, grace: float = GRACE_SECONDS) -> None:
        self.path = Path(path)
        self.process = process
        self._in_use = in_use
        self._clock = clock
        self._grace = grace
        self._started = clock()
        self._seen_in_use = False
        self.done = False

    def step(self) -> bool:
        """Check once; delete when the app is done with the copy. Returns True when the copy is gone."""
        if self.done:
            return True
        if not self.path.exists():
            self.done = True
            return True
        running = False
        if self.process is not None:
            running = self.process.running()
            if not running and self._clock() - self._started < HANDOFF_SECONDS:
                self.close()  # a hand-off stub, not the app: judge by who holds the file from now on
        try:
            busy = self._in_use(self.path)
        except Exception:  # noqa: BLE001 - unknown: keep the copy and look again
            busy = True
        if busy:
            self._seen_in_use = True
            return False
        if running:
            # The app is still open: the copy goes once the app has held it and let go (document closed).
            if self._seen_in_use:
                self.done = remove_copy(self.path)
            return self.done
        app_closed = self.process is not None  # its process existed and has exited
        if app_closed or self._seen_in_use or self._clock() - self._started >= self._grace:
            self.done = remove_copy(self.path)
        return self.done

    def close(self) -> None:
        if self.process is not None:
            try:
                self.process.close()
            except Exception:  # noqa: BLE001
                pass
            self.process = None


class OpenCopyWatchers:
    """All watchers of this run; :meth:`remaining` is what an exit sweeper must take over."""

    def __init__(self, *, poll: float = POLL_SECONDS) -> None:
        self._poll = poll
        self._lock = threading.Lock()
        self._watchers: list[CopyWatcher] = []
        self._stop = threading.Event()

    def watch(self, watcher: CopyWatcher) -> None:
        with self._lock:
            self._watchers.append(watcher)
        threading.Thread(target=self._run, args=(watcher,), name="lgk-open-copy", daemon=True).start()

    def _run(self, watcher: CopyWatcher) -> None:
        try:
            while not self._stop.is_set():
                if watcher.step():
                    break
                self._stop.wait(self._poll)
        finally:
            watcher.close()
            with self._lock:
                if watcher.done and watcher in self._watchers:
                    self._watchers.remove(watcher)

    def remaining(self) -> list[Path]:
        with self._lock:
            return [w.path for w in self._watchers if not w.done and w.path.exists()]

    def stop(self) -> None:
        self._stop.set()


WATCHERS = OpenCopyWatchers()


def open_and_watch(path: Path) -> None:
    """The launcher for :meth:`DocumentService.open_externally`: open the copy and delete it when done."""
    process = shell_open(path)
    WATCHERS.watch(CopyWatcher(path, process))


# ------------------------------------------------------------------------ at exit
def spawn_exit_sweeper(profile_dir: Path) -> bool:
    """LocalGateKeys is exiting with copies still open: a detached helper deletes them once closed."""
    if os.name != "nt":
        return False
    if getattr(sys, "frozen", False):
        command = [sys.executable, "--sweep-open-copies", str(profile_dir)]
    else:
        command = [sys.executable, "-m", "localvault.agent", "--sweep-open-copies", str(profile_dir)]
    flags = 0x00000008 | 0x00000200 | 0x08000000  # DETACHED_PROCESS | NEW_PROCESS_GROUP | NO_WINDOW
    try:
        subprocess.Popen(command, creationflags=flags, close_fds=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError:
        _log.warning("The open-document sweeper could not start", exc_info=True)
        return False


def is_plain_dir(path: Path) -> bool:
    """A real directory: not a symlink, junction or any other reparse point (never followed)."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    import stat

    if not stat.S_ISDIR(info.st_mode):
        return False
    return not (getattr(info, "st_file_attributes", 0) & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def _copies(root: Path) -> list[Path]:
    """Regular files one level below plain folders of ``root`` (the only shape copies have)."""
    if not is_plain_dir(root):
        return []
    found = []
    for folder in root.iterdir():
        if not is_plain_dir(folder):
            continue
        for path in folder.iterdir():
            try:
                if not path.is_symlink() and path.is_file():
                    found.append(path)
            except OSError:
                pass
    return found


def run_exit_sweeper(profile_dir: Path, *, poll: float = 3.0, max_seconds: float = SWEEPER_MAX_SECONDS,
                     sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> int:
    """The ``--sweep-open-copies`` helper: delete the copies left at exit as their apps let go; 0 when all are gone.

    Only copies that existed when the helper started are touched (a relaunched app may open new ones), and
    deleting is the in-use test: Windows refuses to delete a file an app still holds.
    """
    from .attachments import open_copies_dir

    deadline = clock() + max_seconds
    root = open_copies_dir(profile_dir)
    pending = set(_copies(root))
    while pending and clock() < deadline:
        for path in list(pending):
            if not path.exists() or remove_copy(path):
                pending.discard(path)
        if pending:
            sleep(poll)
    try:
        root.rmdir()  # only when empty
    except OSError:
        pass
    return 0 if not pending else 1

def finish_at_exit(profile_dir: Path | None) -> bool:
    """App exit: delete every copy no app holds now; hand the rest to a detached sweeper. True if one started."""
    from .attachments import cleanup_open_copies

    WATCHERS.stop()
    if profile_dir is None:
        return False
    try:
        left = cleanup_open_copies(profile_dir)
    except OSError:
        left = [Path(profile_dir)]
    return bool(left) and spawn_exit_sweeper(Path(profile_dir))
