"""Auto-type fallback (Windows): type a login into the window the user chose, for apps no other fill reaches.

Rules (feature C4):

* Off unless ``settings.auto_type_enabled``; it runs only from an explicit command or hotkey, never on its own.
* The target (window handle, title, process name) is captured when the user picks the item. Before every keystroke
  batch the foreground window must still be that exact target, else the run stops (``foreground_changed``).
* A visible countdown runs first; with ``settings.auto_type_confirm_window`` (on by default) the user also confirms
  the window title and process before anything is typed.
* Never the app's own windows, never an elevated window (SendInput would be dropped or need the same rights), never
  a secure desktop (UAC, Ctrl+Alt+Del, lock screen). No clipboard and no keyboard hook: only SendInput keys
  (real keys for characters on the target's keyboard layout, unicode keys for the rest).

The platform layer (``Platform``) is injected so all of the matching and abort logic is tested with a fake.
"""
from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class Target:
    hwnd: int
    title: str
    process: str
    pid: int


class AutoTypeError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Platform(Protocol):
    def foreground(self) -> int: ...
    def describe(self, hwnd: int) -> Target | None: ...
    def is_elevated(self, hwnd: int) -> bool: ...
    def secure_desktop(self) -> bool: ...
    def send_text(self, text: str) -> None: ...
    def send_key(self, key: str) -> None: ...
    def sleep(self, seconds: float) -> None: ...
    # Bring ``hwnd`` to the foreground; True only when it then is the foreground window.
    def activate(self, hwnd: int) -> bool: ...


def capture(platform: Platform, own_pid: int | None = None) -> Target:
    """The current foreground window as the target; refused for this app, elevated windows and secure desktops."""
    hwnd = platform.foreground()
    target = platform.describe(hwnd) if hwnd else None
    _check_allowed(platform, target, os.getpid() if own_pid is None else own_pid)
    if target is None:  # _check_allowed already refused; keeps type checkers honest
        raise AutoTypeError("no_window")
    return target


def _check_allowed(platform: Platform, target: Target | None, own_pid: int) -> None:
    if platform.secure_desktop():
        raise AutoTypeError("secure_desktop")
    if target is None or not target.hwnd:
        raise AutoTypeError("no_window")
    if target.pid == own_pid:
        raise AutoTypeError("own_window")
    if platform.is_elevated(target.hwnd):
        raise AutoTypeError("elevated")


_UNSAVED_MARKS = ("*", "●", "•")


def _without_unsaved_mark(title: str) -> str:
    """``title`` without an editor's "unsaved changes" mark: the first typed key adds one ("*file.txt - Notepad",
    "● file - Code", "file *"), and that must not count as a window change (live check 2026-11-15)."""
    text = str(title or "").strip()
    if text[:1] in _UNSAVED_MARKS:
        text = text[1:].lstrip()
    if text.endswith(" *"):
        text = text[:-2].rstrip()
    return text


def _named_from_typed(before: str, after: str, typed: str) -> bool:
    """True when ``after`` is ``before`` with the document name replaced by the start of the first line typed so far:
    Windows 11 Notepad names an untitled tab after its first line, and renames it as the line grows ("Untitled -
    Notepad" -> "bob - Notepad" -> "bob<TAB>pw - Notepad"), live check 2026-11-18. The app part after the last " - " must stay the same; another tab's name is not typed text."""
    if not typed or " - " not in before or " - " not in after:
        return False
    old_doc, old_app = before.rsplit(" - ", 1)
    new_doc, new_app = after.rsplit(" - ", 1)
    return new_app == old_app and bool(new_doc.strip()) and new_doc != old_doc and typed.startswith(new_doc)


def still_target(platform: Platform, target: Target, typed: str = "") -> bool:
    """True only while the foreground is the same window with the same title and process as captured; a title
    that differs only by an unsaved-changes mark is the same, and so is an untitled document renamed after the
    first field's text ``typed`` so far (never for a browser, whose title is the page's)."""
    if platform.secure_desktop():
        return False
    hwnd = platform.foreground()
    if hwnd != target.hwnd:
        return False
    now = platform.describe(hwnd)
    if now is None or (now.process, now.pid) != (target.process, target.pid):
        return False
    before, after = _without_unsaved_mark(target.title), _without_unsaved_mark(now.title)
    return after == before or (not is_browser(target.process) and _named_from_typed(before, after, typed))


# Web browsers (and hosts of embedded web pages): the page decides the window title and LocalGateKeys cannot
# see which site is open, so typing into one is always confirmed by the user, whatever the confirm setting
# (scan 2026-11-15 W-M4). An unreadable process name counts as a browser.
BROWSER_PROCESSES = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "opera_gx.exe", "vivaldi.exe",
    "iexplore.exe", "arc.exe", "chromium.exe", "librewolf.exe", "waterfox.exe", "floorp.exe", "zen.exe",
    "thorium.exe", "browser.exe", "whale.exe", "maxthon.exe", "palemoon.exe", "seamonkey.exe",
    "msedgewebview2.exe",
})


def is_browser(process: str) -> bool:
    name = str(process or "").strip().lower()
    return not name or name in BROWSER_PROCESSES


# Text is sent in small batches with the target re-checked before each (W-L11): a focus change can still let
# the rest of one batch reach the new window, so the batch is kept short.
TEXT_BATCH = 4


def sequence(username: str, password: str) -> list[tuple[str, str]]:
    """Username, Tab, password, Enter (an empty username types the password only)."""
    steps: list[tuple[str, str]] = []
    if username:
        steps += [("text", username), ("key", "tab")]
    return steps + [("text", password), ("key", "enter")]


def run(platform: Platform, target: Target, steps: list[tuple[str, str]], *, settings: Any,
        countdown: int = 3, on_tick: Callable[[int], None] = lambda left: None,
        confirm: Callable[[Target], bool] = lambda target: False, own_pid: int | None = None) -> dict[str, Any]:
    """Count down, (optionally) confirm the window, then type ``steps``; abort the moment the window changes."""
    if getattr(settings, "auto_type_enabled", False) is not True:
        raise AutoTypeError("disabled")
    _check_allowed(platform, target, os.getpid() if own_pid is None else own_pid)
    if getattr(settings, "auto_type_confirm_window", True) is not False and not confirm(target):
        raise AutoTypeError("declined")
    for left in range(max(0, int(countdown)), 0, -1):
        on_tick(left)
        platform.sleep(1)
        if not still_target(platform, target):
            raise AutoTypeError("foreground_changed")
    typed = 0
    first = ""  # the first line typed so far (an untitled editor tab takes its name from it, tab included)
    first_done = False
    for kind, value in steps:
        if kind != "text":
            if not still_target(platform, target, first):
                raise AutoTypeError("foreground_changed")
            platform.send_key(value)
            if value == "tab" and not first_done:
                first += "\t"
            else:
                first_done = True
        else:
            for start in range(0, len(value), TEXT_BATCH):
                if not still_target(platform, target, first):
                    raise AutoTypeError("foreground_changed")
                platform.send_text(value[start:start + TEXT_BATCH])
                if not first_done:
                    first += value[start:start + TEXT_BATCH]
        typed += 1
    return {"typed": typed}


__all__ = ["BROWSER_PROCESSES", "TEXT_BATCH", "AutoTypeError", "Platform", "Target", "capture", "is_browser", "run",
           "sequence", "still_target"]
