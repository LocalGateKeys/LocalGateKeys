"""Stage 0: ClipboardGuard works without a Tk root (scheduler and clipboard functions injected)."""
from __future__ import annotations

from types import SimpleNamespace as NS

import localvault.clipboard_guard as clip


class FakeScheduler:
    def __init__(self) -> None:
        self.jobs: list = []

    def call_later(self, delay, fn):
        self.jobs.append((delay, fn))
        return fn

    def cancel(self, handle) -> None:
        pass


class Board:
    def __init__(self) -> None:
        self.text, self.clears = "", 0

    def set(self, value: str) -> None:
        self.text = value

    def get(self) -> str:
        return self.text

    def clear(self) -> None:
        self.text, self.clears = "", self.clears + 1


def _guard(monkeypatch, timeout=30):
    monkeypatch.setattr(clip, "os", NS(name="posix"))
    sched, board = FakeScheduler(), Board()
    guard = clip.ClipboardGuard(timeout_seconds=timeout, scheduler=sched,
                                set_text=board.set, get_text=board.get, clear_text=board.clear)
    return guard, sched, board


def test_clear_fires_via_scheduler(monkeypatch):
    guard, sched, board = _guard(monkeypatch)
    guard.copy("a")
    assert board.text == "a" and sched.jobs[0][0] == 30
    before = board.clears  # copy() empties the clipboard before writing, as before
    sched.jobs[0][1]()
    assert board.text == "" and board.clears == before + 1


def test_stale_timer_does_not_clear_newer_copy(monkeypatch):
    guard, sched, board = _guard(monkeypatch)
    guard.copy("a")
    guard.copy("b")
    sched.jobs[0][1]()
    assert board.text == "b"


def test_guard_without_root_needs_no_tk(monkeypatch):
    guard, _sched, _board = _guard(monkeypatch)
    assert getattr(guard, "root", None) is None


def test_default_scheduler_is_a_daemon_thread_timer():
    guard = clip.ClipboardGuard(timeout_seconds=1)
    handle = guard._scheduler.call_later(60, lambda: None)
    try:
        assert handle.daemon
    finally:
        guard._scheduler.cancel(handle)


def test_copy_during_timer_clear_keeps_the_new_secret_guarded(monkeypatch):
    """A timer-thread clear racing a new copy must not drop the new copy's auto-clear."""
    import threading

    monkeypatch.setattr(clip, "os", NS(name="posix"))
    sched, board = FakeScheduler(), Board()
    holder: dict = {}

    def clear_and_race():
        board.clear()
        if "racer" not in holder:  # only during the timer's clear
            racer = threading.Thread(target=lambda: holder["guard"].copy("b"))
            holder["racer"] = racer
            racer.start()
            racer.join(0.3)  # with a lock the racer waits for this clear to finish

    guard = clip.ClipboardGuard(timeout_seconds=30, scheduler=sched, set_text=board.set,
                                get_text=board.get, clear_text=lambda: None)
    holder["guard"] = guard
    guard.copy("a")
    guard._clear_text = clear_and_race
    sched.jobs[0][1]()  # timer for "a" fires
    holder["racer"].join(2)
    assert board.text == "b"
    assert guard.remaining() is not None  # "b" still has its auto-clear


def test_windows_clear_works_when_close_synthesizes_formats(monkeypatch):
    """CloseClipboard synthesizes CF_TEXT/CF_OEMTEXT/CF_LOCALE and bumps the sequence number;
    our own unchanged text must still be cleared on timeout."""
    import sys

    monkeypatch.setattr(clip, "os", NS(name="nt"))
    state = {"seq": 10, "text": None, "open": False}

    def open_():
        state["open"] = True

    def close():
        state["open"] = False
        if state["text"] is not None and state.get("fresh"):
            state["seq"] += 3  # synthesized formats on close
            state["fresh"] = False

    def empty():
        state["seq"] += 1
        state["text"] = None

    def set_(fmt, value):
        state["seq"] += 1
        if fmt == 13:
            state["text"] = value
            state["fresh"] = True

    names = {"CanIncludeInClipboardHistory": 0xC001, "CanUploadToCloudClipboard": 0xC002,
             "ExcludeClipboardContentFromMonitorProcessing": 0xC003}

    def enum(previous):
        present = sorted([*names.values(), 13, 1, 7, 16]) if state["text"] is not None else []
        later = [f for f in present if f > previous]
        return later[0] if later else 0

    cb = NS(OpenClipboard=open_, CloseClipboard=close, EmptyClipboard=empty, SetClipboardData=set_,
            RegisterClipboardFormat=names.__getitem__, EnumClipboardFormats=enum)
    monkeypatch.setitem(sys.modules, "win32clipboard", cb)
    monkeypatch.setitem(sys.modules, "win32con", NS(CF_UNICODETEXT=13, CF_TEXT=1, CF_OEMTEXT=7, CF_LOCALE=16))
    monkeypatch.setattr(clip, "_clipboard_sequence", lambda: state["seq"])
    sched = FakeScheduler()
    guard = clip.ClipboardGuard(timeout_seconds=30, scheduler=sched)
    guard.copy("secret-value")
    sched.jobs[-1][1]()
    assert state["text"] is None


def test_windows_copy_passes_utf16_bytes_not_str(monkeypatch):
    # pywin32 312 / Python 3.14 crashes the process when SetClipboardData gets a str.
    import sys

    monkeypatch.setattr(clip, "os", NS(name="nt"))
    written = {}

    def set_(fmt, value):
        written[fmt] = value

    cb = NS(OpenClipboard=lambda: None, CloseClipboard=lambda: None, EmptyClipboard=lambda: None,
            SetClipboardData=set_, RegisterClipboardFormat=lambda name: name,
            EnumClipboardFormats=lambda previous: 0)
    monkeypatch.setitem(sys.modules, "win32clipboard", cb)
    monkeypatch.setitem(sys.modules, "win32con", NS(CF_UNICODETEXT=13, CF_TEXT=1, CF_OEMTEXT=7, CF_LOCALE=16))
    monkeypatch.setattr(clip, "_clipboard_sequence", lambda: 1)
    clip.ClipboardGuard(timeout_seconds=0, scheduler=FakeScheduler()).copy("123 456 é")
    assert written[13] == "123 456 é\0".encode("utf-16-le")


def test_windows_clear_spares_another_apps_copy(monkeypatch):
    import sys

    monkeypatch.setattr(clip, "os", NS(name="nt"))
    state = {"seq": 10, "text": None}

    def set_(fmt, value):
        state["seq"] += 1
        if fmt == 13:
            state["text"] = value

    def empty():
        state["seq"] += 1
        state["text"] = None

    cb = NS(OpenClipboard=lambda: None, CloseClipboard=lambda: None, EmptyClipboard=empty, SetClipboardData=set_,
            RegisterClipboardFormat=lambda name: name, EnumClipboardFormats=lambda previous: 0)
    monkeypatch.setitem(sys.modules, "win32clipboard", cb)
    monkeypatch.setitem(sys.modules, "win32con", NS(CF_UNICODETEXT=13, CF_TEXT=1, CF_OEMTEXT=7, CF_LOCALE=16))
    monkeypatch.setattr(clip, "_clipboard_sequence", lambda: state["seq"])
    sched = FakeScheduler()
    guard = clip.ClipboardGuard(timeout_seconds=30, scheduler=sched)
    guard.copy("secret-value")
    state["text"], state["seq"] = "someone else's text", state["seq"] + 5
    sched.jobs[-1][1]()
    assert state["text"] == "someone else's text"
