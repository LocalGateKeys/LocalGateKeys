"""Double-clicked ``.lgkshare`` files: Windows starts ``LocalGateKeys.exe <path>``.

The starting process only notes the path in the data folder and, when the app is already
running, tells it through a named event. The running app takes each noted file into the
share inbox (``ShareService.receive_file``) once the vault is unlocked and shows the incoming
sheet, where the six-word code is still needed. Nothing in the file is trusted here: it is
read only by the share inbox, which checks it like a file chosen in the open dialog.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Callable
from pathlib import Path

from . import config

_log = logging.getLogger(__name__)

SUFFIX = ".lgkshare"
EVENT_NAME = "Local\\LocalGateKeys.ShareOpened"
PENDING_NAME = "share-open.json"
#: Most noted files kept; older ones are dropped (a double-click again notes it again).
MAX_PENDING = 8
_lock = threading.Lock()


def find_share_file(args: list[str]) -> Path | None:
    """The first argument that names an existing ``.lgkshare`` file, if any."""
    for arg in args:
        if isinstance(arg, str) and arg.lower().endswith(SUFFIX):
            path = Path(arg)
            if path.is_file():
                return path.resolve()
    return None


def _pending_path() -> Path:
    return config.data_dir() / PENDING_NAME


def _read() -> list[str]:
    try:
        rows = json.loads(_pending_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [r for r in rows if isinstance(r, str)] if isinstance(rows, list) else []


def _write(rows: list[str]) -> None:
    path = _pending_path()
    if not rows:
        path.unlink(missing_ok=True)
        return
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(rows), encoding="utf-8")
    os.replace(tmp, path)


def note(path: Path) -> None:
    """Remember ``path`` for the running (or next) app."""
    with _lock:
        rows = [r for r in _read() if r != str(path)]
        rows.append(str(path))
        _write(rows[-MAX_PENDING:])


def has_pending() -> bool:
    with _lock:
        return bool(_read())


def take() -> list[Path]:
    """The noted files that still exist, oldest first; the list is cleared."""
    with _lock:
        rows = _read()
        _write([])
    return [Path(r) for r in rows if Path(r).is_file()]


def signal_running_app() -> None:
    """Tell an already-running LocalGateKeys that a shared file was opened (no-op if none listens)."""
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    kernel32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.OpenEventW.restype = wintypes.HANDLE
    kernel32.SetEvent.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    event_modify_state = 0x0002
    handle = kernel32.OpenEventW(event_modify_state, False, EVENT_NAME)
    if handle:
        kernel32.SetEvent(handle)
        kernel32.CloseHandle(handle)


def watch(on_open: Callable[[], None]) -> None:
    """Start a daemon thread that calls ``on_open`` each time another process notes a shared file."""
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    handle = kernel32.CreateEventW(None, False, False, EVENT_NAME)  # auto-reset
    if not handle:
        _log.warning("Shared file signal not available")
        return

    def loop() -> None:
        infinite, signalled = 0xFFFFFFFF, 0
        while kernel32.WaitForSingleObject(handle, infinite) == signalled:
            try:
                on_open()
            except Exception:  # noqa: BLE001 - one failed open never stops the watcher
                _log.warning("Opening a shared file failed", exc_info=True)

    threading.Thread(target=loop, name="share-open-watch", daemon=True).start()


def receive_pending(is_unlocked: Callable[[], bool], receive: Callable[[str], object]) -> tuple[int, str]:
    """Take every noted file into the share inbox while unlocked: (how many arrived, last refusal message).

    While locked nothing is taken, so the files wait for the unlock. A file the inbox refuses
    (damaged, already opened) is dropped; its message is returned for the status line.
    """
    if not is_unlocked():
        return 0, ""
    arrived, refused = 0, ""
    for path in take():
        try:
            receive(str(path))
            arrived += 1
        except Exception as exc:  # noqa: BLE001 - ApiError carries the user-facing message
            _log.warning("A double-clicked shared file was not taken: %s", type(exc).__name__)
            refused = getattr(exc, "message", "") or "This shared item could not be opened."
    return arrived, refused
