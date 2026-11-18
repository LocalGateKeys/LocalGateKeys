"""Auto-type fallback (C4): window match and abort logic with a fake input layer."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from localvault.auto_type import AutoTypeError, Target, capture, run, sequence, still_target

OWN = 1000
NOTEPAD = Target(hwnd=11, title="Login - App", process="app.exe", pid=42)


@pytest.fixture(autouse=True)
def _data(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))


class FakePlatform:
    def __init__(self, windows=None, fg=11):
        self.windows = dict(windows or {11: NOTEPAD})
        self.fg = fg
        self.elevated = set()
        self.secure = False
        self.sent = []
        self.on_sleep = None

    def foreground(self):
        return self.fg

    def describe(self, hwnd):
        return self.windows.get(hwnd)

    def is_elevated(self, hwnd):
        return hwnd in self.elevated

    def secure_desktop(self):
        return self.secure

    def send_text(self, text):
        self.sent.append(("text", text))

    def send_key(self, key):
        self.sent.append(("key", key))
        if self.on_key:
            self.on_key(self)

    on_key = None

    def sleep(self, seconds):
        if self.on_sleep:
            self.on_sleep(self)


ON = SimpleNamespace(auto_type_enabled=True, auto_type_confirm_window=False)


def test_missing_settings_mean_off_with_confirm_on():
    p = FakePlatform()
    with pytest.raises(AutoTypeError) as err:  # no auto_type_enabled at all: off
        run(p, NOTEPAD, sequence("a", "b"), settings=SimpleNamespace(), own_pid=OWN)
    assert err.value.code == "disabled"
    with pytest.raises(AutoTypeError) as err:  # enabled, confirm setting missing: the confirm step runs
        run(p, NOTEPAD, sequence("a", "b"), settings=SimpleNamespace(auto_type_enabled=True), own_pid=OWN)
    assert err.value.code == "declined" and p.sent == []


def test_capture_and_refusals():
    p = FakePlatform()
    assert capture(p, own_pid=OWN) == NOTEPAD
    assert pytest.raises(AutoTypeError, capture, p, own_pid=42).value.code == "own_window"
    p.elevated.add(11)
    assert pytest.raises(AutoTypeError, capture, p, own_pid=OWN).value.code == "elevated"
    p.elevated.clear()
    p.secure = True
    assert pytest.raises(AutoTypeError, capture, p, own_pid=OWN).value.code == "secure_desktop"
    p.secure, p.fg = False, 0
    assert pytest.raises(AutoTypeError, capture, p, own_pid=OWN).value.code == "no_window"


def test_still_target_needs_same_window_title_and_process():
    p = FakePlatform({11: NOTEPAD, 12: Target(12, "Other", "x.exe", 7)})
    assert still_target(p, NOTEPAD)
    p.windows[11] = Target(11, "Changed title", "app.exe", 42)
    assert not still_target(p, NOTEPAD)
    p.windows[11] = NOTEPAD
    p.fg = 12
    assert not still_target(p, NOTEPAD)


def test_unsaved_changes_mark_is_not_a_window_change():
    """Live check 2026-11-15: Notepad's title became "*file - Notepad" after the first batch and typing stopped."""
    doc = Target(11, "notes.txt - Notepad", "notepad.exe", 42)
    p = FakePlatform({11: doc})
    for title in ("*notes.txt - Notepad", "* notes.txt - Notepad", "● notes.txt - Notepad", "notes.txt - Notepad *"):
        p.windows[11] = Target(11, title, "notepad.exe", 42)
        assert still_target(p, doc), title
    for title in ("*other.txt - Notepad", "notes.txt - Notepad 2", ""):  # another tab or document is still a change
        p.windows[11] = Target(11, title, "notepad.exe", 42)
        assert not still_target(p, doc), title
    p.windows[11] = Target(11, "*notes.txt - Notepad", "notepad.exe", 43)  # same title, other process
    assert not still_target(p, doc)
    p.windows[11] = doc  # a full run where the first batch marks the document unsaved
    p.send_text = lambda text, _p=p: (_p.sent.append(("text", text)),
                                      _p.windows.__setitem__(11, Target(11, "*notes.txt - Notepad", "notepad.exe", 42)))
    assert run(p, doc, sequence("bob@test.example", "pw-long-1234"), settings=ON, countdown=0, own_pid=OWN) == {"typed": 4}
    assert "".join(v for k, v in p.sent if k == "text") == "bob@test.examplepw-long-1234"


def test_untitled_tab_named_after_typed_text_is_not_a_window_change():
    """Live check 2026-11-18: Windows 11 Notepad renamed "Untitled - Notepad" to "test - Notepad" after the first
    batch and typing stopped."""
    doc = Target(11, "Untitled - Notepad", "notepad.exe", 42)
    p = FakePlatform({11: doc})
    assert still_target(p, doc, "test")
    p.windows[11] = Target(11, "test - Notepad", "notepad.exe", 42)
    assert still_target(p, doc, "testuser") and still_target(p, doc, "test")
    assert not still_target(p, doc, "")  # nothing typed yet: a rename is a change
    assert not still_target(p, doc, "bob")  # a name that is not the typed text (another tab)
    p.windows[11] = Target(11, "test - Other", "notepad.exe", 42)  # the app part changed
    assert not still_target(p, doc, "testuser")
    page = Target(11, "Untitled - Browser", "chrome.exe", 42)  # never for a browser
    p.windows[11] = Target(11, "test - Browser", "chrome.exe", 42)
    assert not still_target(p, page, "testuser")
    p.windows[11] = doc  # a full run: every batch renames the tab after the whole first line, tab included

    line = []

    def rename():
        p.windows[11] = Target(11, "*" + "".join(line) + " - Notepad", "notepad.exe", 42)

    def send_text(text):
        p.sent.append(("text", text))
        line.append(text)
        rename()

    def send_key(key):
        p.sent.append(("key", key))
        if key == "tab":
            line.append("\t")
            rename()
    p.send_text, p.send_key = send_text, send_key
    assert run(p, doc, sequence("testuser", "pw-long-1234"), settings=ON, countdown=0, own_pid=OWN) == {"typed": 4}
    assert "".join(v for k, v in p.sent if k == "text") == "testuserpw-long-1234"


def test_types_after_countdown():
    p, ticks = FakePlatform(), []
    assert run(p, NOTEPAD, sequence("ada", "pw"), settings=ON, on_tick=ticks.append, own_pid=OWN) == {"typed": 4}
    assert ticks == [3, 2, 1]
    assert p.sent == [("text", "ada"), ("key", "tab"), ("text", "pw"), ("key", "enter")]


def test_disabled_types_nothing():
    p = FakePlatform()
    with pytest.raises(AutoTypeError) as err:
        run(p, NOTEPAD, sequence("a", "b"), settings=SimpleNamespace(), own_pid=OWN)
    assert err.value.code == "disabled" and p.sent == []


def test_confirm_window_step():
    p, asked = FakePlatform(), []
    on = SimpleNamespace(auto_type_enabled=True, auto_type_confirm_window=True)
    with pytest.raises(AutoTypeError) as err:
        run(p, NOTEPAD, sequence("a", "b"), settings=on, confirm=lambda t: asked.append(t) or False, own_pid=OWN)
    assert err.value.code == "declined" and asked == [NOTEPAD] and p.sent == []
    assert run(p, NOTEPAD, sequence("", "b"), settings=on, confirm=lambda t: True, own_pid=OWN) == {"typed": 2}


def test_focus_change_during_countdown_aborts():
    p = FakePlatform({11: NOTEPAD, 12: Target(12, "Chat", "chat.exe", 9)})
    p.on_sleep = lambda plat: setattr(plat, "fg", 12)
    with pytest.raises(AutoTypeError) as err:
        run(p, NOTEPAD, sequence("a", "b"), settings=ON, own_pid=OWN)
    assert err.value.code == "foreground_changed" and p.sent == []


def test_focus_change_mid_typing_stops_before_the_password():
    p = FakePlatform({11: NOTEPAD, 12: Target(12, "Chat", "chat.exe", 9)})
    p.on_key = lambda plat: setattr(plat, "fg", 12)  # after Tab the focus moves away
    with pytest.raises(AutoTypeError) as err:
        run(p, NOTEPAD, sequence("ada", "secret"), settings=ON, own_pid=OWN)
    assert err.value.code == "foreground_changed"
    assert ("text", "secret") not in p.sent


def test_secure_desktop_mid_run_aborts():
    p = FakePlatform()
    p.on_sleep = lambda plat: setattr(plat, "secure", True)
    with pytest.raises(AutoTypeError) as err:
        run(p, NOTEPAD, sequence("a", "b"), settings=ON, own_pid=OWN)
    assert err.value.code in {"foreground_changed", "secure_desktop"} and p.sent == []


def test_never_into_own_or_elevated_window_at_run_time():
    p = FakePlatform()
    with pytest.raises(AutoTypeError):
        run(p, NOTEPAD, sequence("a", "b"), settings=ON, own_pid=42)
    p.elevated.add(11)
    with pytest.raises(AutoTypeError):
        run(p, NOTEPAD, sequence("a", "b"), settings=ON, own_pid=OWN)
    assert p.sent == []
