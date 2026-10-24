from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
from collections.abc import Callable
from typing import Any


class _ThreadScheduler:
    """Default clear timer: a daemon ``threading.Timer`` (no UI toolkit needed)."""

    def call_later(self, delay: float, fn: Callable[[], None]) -> threading.Timer:
        timer = threading.Timer(max(0.0, delay), fn)
        timer.daemon = True
        timer.name = "localgatekeys-clipboard-clear"
        timer.start()
        return timer

    def cancel(self, handle: Any) -> None:
        if isinstance(handle, threading.Timer):
            handle.cancel()


class _RootScheduler:
    """Compatibility: run the clear on a Tk root's event loop, as before."""

    def __init__(self, root: Any) -> None:
        self._root = root

    def call_later(self, delay: float, fn: Callable[[], None]) -> Any:
        return self._root.after(int(delay * 1000), fn)

    def cancel(self, handle: Any) -> None:
        pass


def _unavailable(*_args: Any) -> Any:
    raise RuntimeError("Clipboard unavailable")


def _clipboard_sequence() -> int:
    # Use the documented Win32 API rather than a pywin32-version-specific wrapper.
    import ctypes
    from ctypes import wintypes
    fn = ctypes.windll.user32.GetClipboardSequenceNumber
    fn.argtypes = []
    fn.restype = wintypes.DWORD
    return int(fn())


class ClipboardGuard:
    """Clear only our own copy, on timeout/lock/switch; never erase unrelated data.

    Windows uses the clipboard sequence number plus documented history/cloud
    exclusion formats. Non-Windows tests use a digest of the exact owned value.
    This is not a guarantee against third-party clipboard readers or malware.
    """
    def __init__(self, root: Any = None, timeout_seconds: int = 30, *, scheduler: Any = None,
                 set_text: Callable[[str], None] | None = None,
                 get_text: Callable[[], str] | None = None,
                 clear_text: Callable[[], None] | None = None) -> None:
        # ``root`` is the legacy Tk form: its event loop and clipboard are used
        # unless explicit functions are given. Without a root, clearing runs on
        # a daemon timer thread and off-Windows clipboard access is injected.
        self.root = root
        self._scheduler = scheduler or (_RootScheduler(root) if root is not None else _ThreadScheduler())
        self._set_text = set_text or (root.clipboard_append if root is not None else _unavailable)
        self._get_text = get_text or (root.clipboard_get if root is not None else _unavailable)
        self._clear_text = clear_text or (root.clipboard_clear if root is not None else _unavailable)
        # copy() and a timer-thread clear must never interleave (no Tk thread serialises them).
        self._lock = threading.RLock()
        self.timeout_seconds = max(0, int(timeout_seconds))
        self._generation = 0
        self._digest: bytes | None = None
        self._sequence: int | None = None
        self._expires = 0.0

    def copy(self, text: str) -> None:
        with self._lock:
            self._copy_locked(text)

    def _copy_locked(self, text: str) -> None:
        self.clear()
        self._generation += 1
        generation = self._generation
        if os.name == "nt":
            import win32clipboard as cb
            import win32con
            cb.OpenClipboard()
            try:
                cb.EmptyClipboard()
                # Set exclusion formats BEFORE exposing any plaintext.
                for name in ("CanIncludeInClipboardHistory", "CanUploadToCloudClipboard",
                             "ExcludeClipboardContentFromMonitorProcessing"):
                    cb.SetClipboardData(cb.RegisterClipboardFormat(name), b"\x00\x00\x00\x00")
                # Pass NUL-terminated UTF-16 bytes, never a str: pywin32 312 on
                # Python 3.14 corrupts the heap converting a str here and the app dies.
                cb.SetClipboardData(win32con.CF_UNICODETEXT, (text + "\0").encode("utf-16-le"))
                # Capture while OpenClipboard still excludes other writers. A
                # competing copy immediately after CloseClipboard must not be
                # mistaken for the value we own.
                self._sequence = _clipboard_sequence()
                if self._sequence == 0:
                    raise RuntimeError("Clipboard ownership could not be checked")
            except Exception:
                cb.EmptyClipboard()
                raise RuntimeError("Could not copy securely. Clipboard was left empty.") from None
            finally:
                cb.CloseClipboard()
            self._adopt_synthesized_sequence(cb, win32con)
        else:
            self._clear_text()
            self._set_text(text)
        self._digest = hashlib.sha256(text.encode("utf-8")).digest()
        self._expires = time.monotonic() + self.timeout_seconds if self.timeout_seconds else 0.0
        if self.timeout_seconds:
            self._scheduler.call_later(self.timeout_seconds, lambda: self._clear_if_owned(generation))

    def _adopt_synthesized_sequence(self, cb: Any, win32con: Any) -> None:
        """Follow the sequence bump Windows makes when it synthesizes text formats on close.

        CloseClipboard adds CF_TEXT, CF_OEMTEXT and CF_LOCALE, each bumping the
        sequence number, so the number captured while the clipboard was open
        would never match again and the timed clear would never run. The new
        number is adopted only when the format list proves nothing else wrote:
        our exclusion formats and text are all still present, nothing but the
        standard synthesized formats was added, and the sequence moved by
        exactly their count. The clipboard's contents are never read.
        """
        try:
            after = _clipboard_sequence()
            if self._sequence is None or after == self._sequence:
                return
            ours = {cb.RegisterClipboardFormat(name) for name in (
                "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard",
                "ExcludeClipboardContentFromMonitorProcessing")} | {win32con.CF_UNICODETEXT}
            synthesized_kinds = {win32con.CF_TEXT, win32con.CF_OEMTEXT, win32con.CF_LOCALE}
            cb.OpenClipboard()
            try:
                formats: set[int] = set()
                fmt = cb.EnumClipboardFormats(0)
                while fmt:
                    formats.add(fmt)
                    fmt = cb.EnumClipboardFormats(fmt)
                check = _clipboard_sequence()
            finally:
                cb.CloseClipboard()
            synthesized = formats & synthesized_kinds
            if (check == after and ours <= formats and formats <= ours | synthesized_kinds
                    and after - self._sequence == len(synthesized)):
                self._sequence = after
        except Exception:  # noqa: BLE001, S110 - keep the strict sequence (no clear) when unsure
            pass

    def remaining(self) -> int | None:
        if self._digest is None or not self._expires:
            return None
        return max(0, int(self._expires - time.monotonic()))

    def clear(self) -> None:
        with self._lock:
            self._clear_locked()

    def _clear_locked(self) -> None:
        # Move to a fresh generation first so a pending timer for the old one
        # stops, but keep tracking the owned value under the new generation:
        # a busy clipboard on lock or exit is retried instead of forgotten.
        self._generation += 1
        self._clear_if_owned_locked(self._generation)

    def _clear_if_owned(self, generation: int, deadline: float | None = None) -> None:
        with self._lock:
            self._clear_if_owned_locked(generation, deadline)

    # Another app can hold the clipboard open for a moment (clipboard managers,
    # remote desktop). Retry briefly, then keep rescheduling for about a minute
    # while the value we copied is still the clipboard's current content.
    _OPEN_ATTEMPTS = 20
    _OPEN_RETRY_SECONDS = 0.05
    _RESCHEDULE_SECONDS = 1.5
    _GIVE_UP_SECONDS = 60.0

    def _open_clipboard(self, cb: Any) -> bool:
        for attempt in range(self._OPEN_ATTEMPTS):
            try:
                cb.OpenClipboard()
                return True
            except Exception:  # noqa: BLE001 - busy: another process holds the clipboard
                if attempt + 1 < self._OPEN_ATTEMPTS:
                    time.sleep(self._OPEN_RETRY_SECONDS)
        return False

    def _clear_if_owned_locked(self, generation: int, deadline: float | None = None) -> None:
        if generation != self._generation or self._digest is None:
            return
        if self._attempt_clear_locked() and self._reschedule(generation, deadline):
            return  # still tracking: the scheduled retry owns the cleanup
        self._forget_locked()

    def _attempt_clear_locked(self) -> bool:
        """Clear the clipboard if it still holds our copy. True only when it was busy (try again later)."""
        try:
            if os.name == "nt":
                import win32clipboard as cb
                if self._sequence is None or self._sequence != _clipboard_sequence():
                    return False  # someone else wrote since: never ours to clear
                if not self._open_clipboard(cb):
                    return True
                try:
                    if self._sequence == _clipboard_sequence():
                        cb.EmptyClipboard()
                finally:
                    cb.CloseClipboard()
            else:
                value = self._get_text()
                if isinstance(value, str) and secrets.compare_digest(
                        hashlib.sha256(value.encode("utf-8")).digest(), self._digest or b""):
                    self._clear_text()
        except Exception:  # noqa: BLE001, S110 - fail quietly; the caller stops tracking
            pass
        return False

    def _forget_locked(self) -> None:
        self._digest = None
        self._sequence = None
        self._expires = 0.0

    def finish(self, timeout: float = 3.0) -> None:
        """At exit: retry a pending clear in this thread, since scheduled retries die with the process."""
        end = time.monotonic() + max(0.0, timeout)
        while True:
            with self._lock:
                self._generation += 1  # retire any scheduled retry; this loop owns the clear now
                if self._digest is None:
                    return
                if not self._attempt_clear_locked() or time.monotonic() >= end:
                    self._forget_locked()
                    return
            time.sleep(self._OPEN_RETRY_SECONDS)

    def _reschedule(self, generation: int, deadline: float | None) -> bool:
        now = time.monotonic()
        if deadline is None:
            deadline = now + self._GIVE_UP_SECONDS
        if now >= deadline:
            return False
        try:
            self._scheduler.call_later(self._RESCHEDULE_SECONDS,
                                       lambda: self._clear_if_owned(generation, deadline))
        except Exception:  # noqa: BLE001 - no scheduler (shutting down): give up
            return False
        return True
