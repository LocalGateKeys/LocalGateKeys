"""Auto-type on Windows: which characters go as real keys, and the key events ``send_text`` sends (fake API layer).

Live check 2026-11-15: unicode (VK_PACKET) keys reached Windows 11 Notepad with one character replaced by its
neighbour ("test.example" -> "test.xxample"), and a real Shift released too soon gave "Alice.smith". No real key
events are sent here: ``SendInput`` and the other user32 calls are fakes.
"""
from __future__ import annotations

import ctypes
import sys

import pytest

from localvault import auto_type_win as w
from localvault.auto_type import AutoTypeError

US_ROWS = {  # char -> (vk, shift) on a US-like layout
    **{c: (ord(c.upper()), False) for c in "abcdefghijklmnopqrstuvwxyz"},
    **{c: (ord(c), True) for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
    **{c: (ord(c), False) for c in "0123456789"},
    "!": (0x31, True), "@": (0x32, True), ".": (0xBE, False), "_": (0xBD, True), " ": (0x20, False),
    "^": (0x36, True),
}


class FakeLayout:
    """A US-like layout; ``altgr`` chars need Ctrl+Alt, ``dead`` keys type nothing on their own."""

    def __init__(self, language=0x0409, caps=False, altgr=("€",), dead=(), scanless=(), lies=()):
        self.lang, self.caps, self.altgr, self.dead = language, caps, set(altgr), set(dead)
        self.scanless, self.lies = set(scanless), set(lies)
        self.by_key = {(vk, shift): c for c, (vk, shift) in US_ROWS.items()}

    def language(self):
        return self.lang

    def vk_scan(self, char):
        if char in self.altgr:
            return (0x6 << 8) | 0x45  # Ctrl+Alt+E
        if char not in US_ROWS:
            return -1
        vk, shift = US_ROWS[char]
        return (0x1 << 8 if shift else 0) | vk

    def scan_code(self, vk):
        return 0 if vk in self.scanless else vk % 0x60 + 1

    def to_unicode(self, vk, scan, shift, caps):
        if caps and 0x41 <= vk <= 0x5A:
            shift = not shift  # Caps Lock flips letters only
        char = self.by_key.get((vk, shift))
        if char in self.dead:
            return None
        if char in self.lies:
            return "?"
        return char

    def caps_lock(self):
        return self.caps


def kinds(plans):
    return [("uni", p.char) if p.unicode else (hex(p.vk), p.shift) for p in plans]


# ------------------------------------------------------------------------------------------- mapping
def test_layout_characters_become_real_keys_with_the_right_shift():
    plans = w.plan_text("aZ.@_ 9", FakeLayout())
    assert kinds(plans) == [("0x41", False), ("0x5a", True), ("0xbe", False), ("0x32", True), ("0xbd", True),
                            ("0x20", False), ("0x39", False)]
    assert all(p.scan for p in plans)


def test_caps_lock_flips_shift_for_letters_only():
    plans = w.plan_text("aA1!", FakeLayout(caps=True))
    assert kinds(plans) == [("0x41", True), ("0x41", False), ("0x31", False), ("0x31", True)]


@pytest.mark.parametrize("char", ["€", "é", "ß", "α", "Ω", "\U0001F511", "\t", "\n", "\x7f", "\x00"])
def test_characters_off_the_layout_or_needing_altgr_stay_unicode(char):
    assert w.plan_text(char, FakeLayout()) == [w.KeyPlan(char)]


def test_dead_keys_missing_scan_codes_and_mismatches_stay_unicode():
    assert w.plan_char("^", FakeLayout(dead={"^"}), False).unicode
    assert w.plan_char("a", FakeLayout(scanless={0x41}), False).unicode
    assert w.plan_char("b", FakeLayout(lies={"b"}), False).unicode  # ToUnicodeEx disagrees: never guess
    assert not w.plan_char("c", FakeLayout(), False).unicode


@pytest.mark.parametrize("language", [0x0404, 0x0804, 0x0411, 0x0412])
def test_ime_languages_type_everything_as_unicode(language):
    assert all(p.unicode for p in w.plan_text("abcXYZ", FakeLayout(language=language)))


def test_vk_scan_with_other_shift_states_or_no_key_is_unicode():
    class Odd(FakeLayout):
        def vk_scan(self, char):
            return {"x": (0x2 << 8) | 0x58, "y": (0x4 << 8) | 0x59, "z": 0xFFFF, "q": 0x00FF}.get(char, -1)

    assert all(p.unicode for p in w.plan_text("xyzq", Odd()))


def test_surrogate_pair_stays_one_character():
    text = "a🔑b"  # as some sources hand over an emoji
    assert [p.char for p in w.plan_text(text, FakeLayout())] == ["a", "🔑", "b"]


# ------------------------------------------------------------------------------------------- sending
class Api:
    """Fake user32 for ``WindowsPlatform``: records every SendInput event (one per call) and every sleep."""

    def __init__(self, layout=None, foregrounds=None, fail_at=None, busy=False, held=()):
        self.layout = layout or FakeLayout()
        self.fg = iter(foregrounds) if foregrounds is not None else None
        self.fail_at, self.busy, self.held = fail_at, busy, set(held)
        self.events, self.log = [], []

    def platform(self):
        p = object.__new__(w.WindowsPlatform)
        p._settle_hwnd = 0
        p._SendInput = self.send_input
        p._SendMessageTimeoutW = self.send_message
        p.layout_for = lambda hwnd: self.layout
        p.foreground = (lambda: next(self.fg)) if self.fg else (lambda: 7)
        p.sleep = lambda s: self.log.append(("sleep", s))
        return p

    def send_input(self, count, array, size):
        assert count == 1 and size == ctypes.sizeof(w.INPUT)
        ki = array[0].ki
        unicode = bool(ki.dwFlags & w.KEYEVENTF_UNICODE)
        event = ("up" if ki.dwFlags & w.KEYEVENTF_KEYUP else "down", chr(ki.wScan) if unicode else hex(ki.wVk))
        if self.fail_at is not None and len(self.events) == self.fail_at:
            self.fail_at = None
            return 0
        self.events.append(event)
        self.log.append(event)
        return 1

    def send_message(self, hwnd, msg, wparam, lparam, flags, timeout, result):
        assert hwnd == 7 and msg == w.WM_NULL and flags & w.SMTO_ABORTIFHUNG
        self.log.append(("settle",))
        return 0 if self.busy else 1


SHIFT_DOWN, SHIFT_UP = ("down", "0x10"), ("up", "0x10")


def test_send_text_uses_real_keys_and_one_shift_press_per_run_of_capitals():
    api = Api()
    api.platform().send_text("aBC.d")
    assert api.events == [("down", "0x41"), ("up", "0x41"),
                          SHIFT_DOWN, ("down", "0x42"), ("up", "0x42"), ("down", "0x43"), ("up", "0x43"), SHIFT_UP,
                          ("down", "0xbe"), ("up", "0xbe"), ("down", "0x44"), ("up", "0x44")]


def test_every_key_stays_down_key_hold_with_nothing_else_sent():
    """A late reader (Windows 11 Notepad) must still see the key, its Shift and its unicode character."""
    api = Api()
    api.platform().send_text("aB€é")
    log = api.log
    assert w.KEY_HOLD >= 0.25
    for char in ("0x41", "0x42", "€", "é"):
        at = log.index(("down", char))
        assert log[at + 1:at + 3] == [("sleep", w.KEY_HOLD), ("up", char)], char
    assert api.events == [("down", "0x41"), ("up", "0x41"), SHIFT_DOWN, ("down", "0x42"), ("up", "0x42"), SHIFT_UP,
                          ("down", "€"), ("up", "€"), ("down", "é"), ("up", "é")]


def test_every_key_down_and_shift_change_is_preceded_by_a_settle_check():
    api = Api()
    api.platform().send_text("Ab€")
    events = [i for i, entry in enumerate(api.log) if entry[0] == "down" or entry == SHIFT_UP]
    assert len(events) == 5 and all(api.log[i - 1] == ("settle",) for i in events)


def test_shift_is_released_when_the_window_changes_mid_run():
    api = Api(foregrounds=[7, 7, 9])  # start, before "B", before "C"
    with pytest.raises(AutoTypeError) as caught:
        api.platform().send_text("ABC")
    assert caught.value.code == "foreground_changed"
    assert api.events == [SHIFT_DOWN, ("down", "0x41"), ("up", "0x41"), ("down", "0x42"), ("up", "0x42"), SHIFT_UP]


def test_shift_is_released_when_a_key_cannot_be_sent():
    api = Api(fail_at=1)  # Shift goes down, the "A" key down is refused
    with pytest.raises(AutoTypeError) as caught:
        api.platform().send_text("Ab")
    assert caught.value.code == "send_failed"
    assert api.events == [SHIFT_DOWN, SHIFT_UP]


def test_busy_target_stops_typing_and_never_leaves_shift_down():
    api = Api()
    p = api.platform()
    calls = {"n": 0}

    def flaky(*args):
        calls["n"] += 1
        api.log.append(("settle",))
        return 1 if calls["n"] <= 2 else 0  # Shift down and "A" settle; then the target hangs

    p._SendMessageTimeoutW = flaky
    with pytest.raises(AutoTypeError) as caught:
        p.send_text("AB")
    assert caught.value.code == "target_busy"
    assert api.events == [SHIFT_DOWN, ("down", "0x41"), ("up", "0x41"), SHIFT_UP]
    assert p._settle_hwnd == 0


def test_send_key_settles_on_the_foreground_window():
    api = Api()
    p = api.platform()
    p.send_key("tab")
    assert api.log == [("settle",), ("down", "0x9"), ("sleep", w.KEY_HOLD), ("up", "0x9"), ("sleep", w.CHAR_DELAY)]
    assert p._settle_hwnd == 0


def test_sent_inputs_are_zeroed():
    seen = []
    p = Api().platform()
    p._SendInput = lambda count, array, size: seen.append(array) or 1
    p.send_text("aZ")
    assert len(seen) == 6  # a down and up, Shift down, Z down and up, Shift up; each zeroed after the call
    assert all(ctypes.string_at(ctypes.addressof(a), ctypes.sizeof(a)) == bytes(ctypes.sizeof(a)) for a in seen)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_real_layout_calls_round_trip_without_typing():
    """The ctypes bindings for the layout calls, against this thread's own keyboard layout; nothing is sent."""
    platform = w.WindowsPlatform()
    layout = platform.layout_for(0)
    assert isinstance(layout.caps_lock(), bool)
    plans = w.plan_text("".join(chr(c) for c in range(0x20, 0x7F)) + "€\U0001F511", layout)
    assert plans[-1].unicode
    for plan in plans:
        if not plan.unicode:
            assert layout.to_unicode(plan.vk, plan.scan, plan.shift, layout.caps_lock()) == plan.char
