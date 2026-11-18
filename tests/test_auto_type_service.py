"""Auto-type service (C4): settings stored on this device, refusals, target window and typing with a fake input layer."""
from __future__ import annotations

import ctypes
import json
import os
import sys

import pytest

from localvault.api.result import ApiError
from localvault.app import auto_type_service as svc_mod
from localvault.app.auto_type_service import AutoTypeService
from localvault.auto_type import Target
from localvault.device_settings import FILENAME, DeviceSettingsStore
from localvault.session_guard import StaleSession

OWN = 1000
APP = Target(hwnd=11, title="Login - App", process="app.exe", pid=42)
OURS = Target(hwnd=5, title="LocalGateKeys", process="LocalGateKeys.exe", pid=OWN)


@pytest.fixture(autouse=True)
def _data(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr("localvault.travel.hidden_id_set", lambda session: session.hidden)


class FakePlatform:
    def __init__(self, fg=5):
        self.windows = {5: OURS, 11: APP}
        self.fg = fg
        self.elevated: set[int] = set()
        self.secure = False
        self.sent: list = []
        self.on_send = None
        self.activate_ok = True

    def foreground(self):
        return self.fg

    def describe(self, hwnd):
        return self.windows.get(hwnd)

    def is_elevated(self, hwnd):
        return hwnd in self.elevated

    def secure_desktop(self):
        return self.secure

    def activate(self, hwnd):
        if self.activate_ok and hwnd in self.windows:
            self.fg = hwnd
            return True
        return False

    def _record(self, step):
        self.sent.append(step)
        if self.on_send:
            self.on_send(self)

    def send_text(self, text):
        self._record(("text", text))

    def send_key(self, key):
        self._record(("key", key))

    def sleep(self, seconds):
        pass


class Session:
    def __init__(self, detail=None):
        self.detail = {"id": "c1", "username": "alice", "revision": 7} if detail is None else detail
        self.hidden: frozenset[str] = frozenset()
        self.secret_calls = 0

    def credential_detail(self, item_id):
        return dict(self.detail) if item_id == self.detail.get("id") else None

    def credential_secret(self, item_id, expected_revision=None):
        self.secret_calls += 1
        assert expected_revision == 7
        return "s3cr\U0001F511t"


class Guard:
    def lease(self):
        return "lease"


class Controller:
    def __init__(self, session=None, unlocked=True):
        self.session = session or Session()
        self.unlocked = unlocked
        self.guard = Guard()
        self.stale = False
        self.touched = 0

    def is_unlocked(self):
        return self.unlocked

    def require_lease(self, lease):
        if self.stale:
            raise StaleSession("stale")

    def touch(self):
        self.touched += 1


class Port:
    def __init__(self, answers=()):
        self.answers = list(answers)
        self.confirms: list = []

    def confirm(self, title, message):
        self.confirms.append((title, message))
        return self.answers.pop(0) if self.answers else False


@pytest.fixture
def reauth(monkeypatch):
    calls: list = []
    monkeypatch.setattr(svc_mod.SecretService, "reauthenticate",
                        lambda self, title, lease, allow_hello=False, fresh=False: calls.append(allow_hello))
    return calls


def make(*, enabled=True, confirm=False, answers=(), platform=None, session=None, fg=11):
    store = DeviceSettingsStore()
    store.update(auto_type_enabled=enabled, auto_type_confirm_window=confirm)
    platform = platform or FakePlatform(fg=fg)
    controller = Controller(session)
    port = Port(answers)
    return AutoTypeService(controller, port, platform, store, own_pid=OWN), platform, controller, port


def code(fn, *args):
    with pytest.raises(ApiError) as err:
        fn(*args)
    return err.value.code


REF = {"source": "credential", "id": "c1"}


def typed(platform):
    """``platform.sent`` with the short text batches (auto_type.TEXT_BATCH) joined back into whole steps."""
    steps: list = []
    for kind, value in platform.sent:
        if kind == "text" and steps and steps[-1][0] == "text":
            steps[-1] = ("text", steps[-1][1] + value)
        else:
            steps.append((kind, value))
    return steps


# ------------------------------------------------------------------------------------- settings
def test_settings_default_off_confirm_on_and_persist(tmp_path, reauth):
    service = AutoTypeService(Controller(), Port(answers=[True]), FakePlatform(), own_pid=OWN)
    assert service.settings_get() == {"enabled": False, "confirm": True}
    assert service.settings_set(True, False) == {"enabled": True, "confirm": False}
    again = AutoTypeService(Controller(), Port(), FakePlatform(), own_pid=OWN)
    assert again.settings_get() == {"enabled": True, "confirm": False}
    stored = json.loads((tmp_path / "data" / FILENAME).read_text("utf-8"))
    assert stored["auto_type"] == {"enabled": True, "confirm": False}
    # Already on: no new question; off again needs none either.
    port = Port()
    third = AutoTypeService(Controller(), port, FakePlatform(), own_pid=OWN)
    assert third.settings_set(True, True) == {"enabled": True, "confirm": True}
    assert third.settings_set(False, True)["enabled"] is False and port.confirms == []
    assert reauth == [False]  # only turning it on (with the confirm step off) asked for the master password


def test_turning_on_asks_once_and_a_no_keeps_it_off():
    port = Port(answers=[False])
    service = AutoTypeService(Controller(), port, FakePlatform(), own_pid=OWN)
    assert code(service.settings_set, True, True) == "cancelled"
    assert service.settings_get()["enabled"] is False and len(port.confirms) == 1


def test_damaged_file_reads_as_safe_defaults(tmp_path):
    path = tmp_path / "data"
    path.mkdir(parents=True, exist_ok=True)
    (path / FILENAME).write_text('{"auto_type": {"enabled": "yes", "confirm": 0}}', "utf-8")
    assert DeviceSettingsStore().load().auto_type_enabled is False
    assert DeviceSettingsStore().load().auto_type_confirm_window is True
    (path / FILENAME).write_text("not json", "utf-8")
    assert DeviceSettingsStore().load().auto_type_enabled is False


def test_settings_are_not_appsettings_fields():
    from localvault.settings import AppSettings

    names = set(AppSettings.__dataclass_fields__)
    assert not {"auto_type_enabled", "auto_type_confirm_window"} & names


# ------------------------------------------------------------------------------------- happy path
def test_happy_path_types_username_tab_password_enter(reauth):
    service, platform, controller, _port = make()
    result = service.run(REF)
    assert typed(platform) == [("text", "alice"), ("key", "tab"), ("text", "s3cr\U0001F511t"), ("key", "enter")]
    assert all(len(value) <= 4 for kind, value in platform.sent if kind == "text")
    assert result == {"message": result["message"]} and "Login - App" in result["message"]
    assert reauth == [True] and controller.touched == 1


def test_remembered_window_used_when_our_window_is_in_front(reauth):
    service, platform, _c, port = make(confirm=True, answers=[True], fg=5)
    assert code(service.run, REF) == "noWindow" and platform.sent == []
    platform.fg = 11
    service.note_foreground()
    platform.fg = 5
    service.note_foreground()  # our own window is never remembered
    service.run(REF)
    assert platform.fg == 11 and len(typed(platform)) == 4
    assert len(port.confirms) == 1 and "app.exe" in port.confirms[0][1]


def test_remembered_window_must_still_be_the_same_process(reauth):
    service, platform, _c, _p = make(fg=5)
    service.note_foreground(11)
    platform.windows[11] = Target(hwnd=11, title="Other", process="other.exe", pid=99)
    assert code(service.run, REF) == "noWindow" and platform.sent == []
    service.note_foreground(11)
    del platform.windows[11]  # the window closed
    assert code(service.run, REF) == "noWindow"


def test_strict_login_asks_master_password_without_hello(reauth):
    session = Session({"id": "c1", "username": "a", "revision": 7, "policy": {"require_master_password": True}})
    service, platform, _c, _p = make(session=session)
    service.run(REF)
    assert reauth == [False] and len(typed(platform)) == 4


# ------------------------------------------------------------------------------------- refusals
def test_refused_when_disabled_locked_or_not_a_login(reauth):
    service, platform, controller, _p = make(enabled=False)
    assert code(service.run, REF) == "disabled"
    service, platform, controller, _p = make()
    assert code(service.run, {"source": "typed", "id": "c1"}) == "webOnly"
    controller.unlocked = False
    assert code(service.run, REF) == "locked"
    assert platform.sent == [] and reauth == []


def test_own_window_never_a_target(reauth):
    service, platform, _c, _p = make(fg=5)
    service.note_foreground(5)  # ignored: it is ours
    assert code(service.run, REF) == "noWindow"  # ours in front and nothing remembered
    assert code(service._check, OURS) == "ownWindow"  # the same refusal auto_type.capture gives
    assert platform.sent == [] and reauth == []


@pytest.mark.parametrize("setup, expected", [
    (lambda p: p.elevated.add(11), "elevated"),
    (lambda p: setattr(p, "secure", True), "secureDesktop"),
])
def test_window_refusals(reauth, setup, expected):
    service, platform, _c, _p = make()
    setup(platform)
    assert code(service.run, REF) == expected
    assert platform.sent == [] and reauth == []


def test_remembered_window_that_became_elevated_is_refused(reauth):
    service, platform, _c, _p = make(fg=5)
    service.note_foreground(11)
    platform.elevated.add(11)
    assert code(service.run, REF) == "elevated" and platform.sent == []


@pytest.mark.parametrize("detail", [
    {"id": "c1", "username": "a", "revision": 7, "policy": {"fill": "never"}},
    {"id": "c1", "username": "a", "revision": 7, "scope": {"access": {"expires": "2000-01-01"}}},
    {"id": "c1", "username": "a", "revision": 7, "scope": {"access": "from-a-newer-version"}},
])
def test_access_rules_refuse(reauth, detail):
    session = Session(detail)
    service, platform, _c, _p = make(session=session)
    assert code(service.run, REF) == "notAllowed"
    assert platform.sent == [] and session.secret_calls == 0 and reauth == []


def test_travel_hidden_login_refused(reauth):
    session = Session()
    session.hidden = frozenset({"c1"})
    service, platform, _c, _p = make(session=session)
    assert code(service.run, REF) == "notAllowed" and platform.sent == [] and session.secret_calls == 0


def test_declined_confirm_types_nothing(reauth):
    session = Session()
    service, platform, _c, port = make(confirm=True, answers=[False], session=session)
    assert code(service.run, REF) == "declined"
    assert platform.sent == [] and session.secret_calls == 0 and len(port.confirms) == 1


def test_window_that_will_not_come_forward_is_refused(reauth):
    service, platform, _c, _p = make(fg=5)
    service.note_foreground(11)
    platform.activate_ok = False
    assert code(service.run, REF) == "changed" and platform.sent == []


def test_target_change_mid_typing_stops(reauth):
    service, platform, _c, _p = make()

    def switch_after_username(p):
        if len(p.sent) == 1:
            p.fg = 5  # the user clicked another window
    platform.on_send = switch_after_username
    assert code(service.run, REF) == "changed"
    assert platform.sent == [("text", "alic")]  # stopped after the first short batch


def test_title_change_mid_typing_stops(reauth):
    service, platform, _c, _p = make()

    def retitle(p):
        p.windows[11] = Target(hwnd=11, title="Pay now", process="app.exe", pid=42)
    platform.on_send = retitle
    assert code(service.run, REF) == "changed" and platform.sent == [("text", "alic")]


def test_session_lost_during_prompts_types_nothing(monkeypatch):
    service, platform, controller, _p = make()
    monkeypatch.setattr(svc_mod.SecretService, "reauthenticate",
                        lambda self, *a, **k: setattr(controller, "stale", True))
    assert code(service.run, REF) == "session_changed" and platform.sent == []


# ------------------------------------------------------------------------------------- Windows layer
def test_windows_module_imports_and_encodes_without_sending():
    from localvault import auto_type_win as w

    assert w.utf16_units("a\U0001F511") == [0x61, 0xD83D, 0xDD11]
    array = w.unicode_inputs("a\U0001F511")
    assert len(array) == 6
    assert [(i.type, i.ki.wVk, i.ki.wScan, i.ki.dwFlags) for i in array[:2]] == [
        (1, 0, 0x61, w.KEYEVENTF_UNICODE), (1, 0, 0x61, w.KEYEVENTF_UNICODE | w.KEYEVENTF_KEYUP)]
    assert [i.ki.wScan for i in array[2::2]] == [0xD83D, 0xDD11]
    keys = w.key_inputs("tab")
    assert [(k.ki.wVk, k.ki.dwFlags) for k in keys] == [(0x09, 0), (0x09, w.KEYEVENTF_KEYUP)]


def test_input_struct_layout():
    from localvault import auto_type_win as w

    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert ctypes.sizeof(w.MOUSEINPUT) == 32
        assert ctypes.sizeof(w.KEYBDINPUT) == 24
        assert ctypes.sizeof(w.HARDWAREINPUT) == 8
        assert ctypes.sizeof(w.INPUT) == 40
        assert w.INPUT.u.offset == 8
    else:
        assert ctypes.sizeof(w.INPUT) == 28


def _fake_windows_platform(foregrounds):
    """A ``WindowsPlatform`` without DLLs: records each ``SendInput`` batch as its UTF-16 units."""
    from localvault import auto_type_win as w

    platform = object.__new__(w.WindowsPlatform)
    batches, sleeps, fg = [], [], iter(foregrounds)

    def send(array):
        ups = {bool(array[i].ki.dwFlags & w.KEYEVENTF_KEYUP) for i in range(len(array))}
        assert len(ups) == 1, "a SendInput call is all key downs or all key ups"
        batches.append(("up" if ups.pop() else "down", [array[i].ki.wScan or array[i].ki.wVk for i in range(len(array))]))

    class NoLayout:  # no character on the layout: every character is a unicode key
        def language(self):
            return 0x0409

        def vk_scan(self, char):
            return -1

        def caps_lock(self):
            return False

    platform._send = send
    platform._settle_hwnd = 0
    platform._SendMessageTimeoutW = lambda *args: 1
    platform.layout_for = lambda hwnd: NoLayout()
    platform.foreground = lambda: next(fg)
    platform.sleep = sleeps.append
    return platform, batches, sleeps


def test_send_text_types_one_key_event_per_sendinput():
    """Live check 2026-11-15: one SendInput for the whole string reached Windows 11 Notepad as a later character
    repeated ("alice@test.zzzzzzz" and a password of only "z"). Each key down and key up now goes alone, the key
    held KEY_HOLD (real keys for layout characters: tests/test_auto_type_win.py)."""
    from localvault import auto_type_win as w

    platform, batches, sleeps = _fake_windows_platform([7] * 10)
    platform.send_text("ab\U0001F511")
    assert batches == [("down", [0x61]), ("up", [0x61]), ("down", [0x62]), ("up", [0x62]),
                       ("down", [0xD83D, 0xDD11]), ("up", [0xD83D, 0xDD11])]  # a surrogate pair stays together
    assert sleeps == [w.KEY_HOLD, w.CHAR_DELAY] * 3 and w.CHAR_DELAY > 0
    platform.send_text("")
    assert len(batches) == 6
    platform.send_key("tab")
    assert batches[6:] == [("down", [0x09]), ("up", [0x09])]


def test_send_text_stops_when_the_window_changes_mid_text():
    from localvault import auto_type as at

    platform, batches, _ = _fake_windows_platform([7, 7, 9, 9])
    with pytest.raises(at.AutoTypeError) as caught:
        platform.send_text("secret")
    assert caught.value.code == "foreground_changed"
    assert batches == [("down", [ord("s")]), ("up", [ord("s")]), ("down", [ord("e")]), ("up", [ord("e")])]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_windows_platform_reads_without_typing():
    """Read-only calls against the real desktop; nothing is sent or activated."""
    from localvault.auto_type_win import WindowsPlatform

    platform = WindowsPlatform()
    assert isinstance(platform.secure_desktop(), bool)
    hwnd = platform.foreground()
    if hwnd:
        target = platform.describe(hwnd)
        assert target is None or target.pid > 0
        assert isinstance(platform.is_elevated(hwnd), bool)
    assert platform.describe(0) is None and platform.is_elevated(0) is True
    assert os.getpid() > 0


# ------------------------------------------------------------------------- scan 2026-11-15 W-M4, W-L10, W-L11
BROWSER = Target(hwnd=11, title="Your Bank - Sign in", process="chrome.exe", pid=42)
WEB = {"id": "c1", "kind": "web", "username": "alice", "revision": 7, "scope": {"origin": "https://bank.test"}}


@pytest.mark.parametrize("process", ["chrome.exe", "MSEDGE.EXE", "firefox.exe", ""])
def test_browser_window_is_always_confirmed_even_with_confirm_off(reauth, process):
    service, platform, _c, port = make(confirm=False, answers=[False], session=Session(dict(WEB)))
    platform.windows[11] = Target(hwnd=11, title=BROWSER.title, process=process, pid=42)
    assert code(service.run, REF) == "declined"
    assert platform.sent == [] and len(port.confirms) == 1
    assert "https://bank.test" in port.confirms[0][1]  # check the address bar shows the login's site


def test_browser_window_types_after_the_user_confirms_it_each_time(reauth):
    service, platform, _c, port = make(confirm=False, answers=[True, True], session=Session(dict(WEB)))
    platform.windows[11] = BROWSER
    service.run(REF)
    service.run(REF)
    assert len(port.confirms) == 2 and len(typed(platform)) == 8


def test_non_browser_window_keeps_the_confirm_setting(reauth):
    service, platform, _c, port = make(confirm=False, session=Session(dict(WEB)))
    service.run(REF)
    assert port.confirms == [] and len(typed(platform)) == 4


def test_desktop_login_into_a_browser_gets_the_general_warning(reauth):
    service, platform, _c, port = make(confirm=False, answers=[False])
    platform.windows[11] = BROWSER
    assert code(service.run, REF) == "declined"
    assert "https://" not in port.confirms[0][1] and len(port.confirms[0][1]) > len("LocalGateKeys will type")


class PrefsSession(Session):
    def __init__(self):
        super().__init__()
        self.prefs: dict = {}

    def _read_prefs(self):
        return self.prefs

    def _commit_prefs(self, changes):
        for key, value in changes.items():
            if value is None:
                self.prefs.pop(key, None)
            else:
                self.prefs[key] = json.loads(json.dumps(value))


def test_settings_live_in_the_encrypted_prefs_and_the_file_cannot_loosen_them(tmp_path, reauth):
    session = PrefsSession()
    controller = Controller(session)
    service = AutoTypeService(controller, Port(answers=[True]), FakePlatform(), own_pid=OWN)
    assert service.settings_set(True, True) == {"enabled": True, "confirm": True}
    assert session.prefs[svc_mod.PREF_KEY] == {"enabled": True, "confirm": True}
    # Another process edits device-settings.json: no effect while the vault holds the preference.
    DeviceSettingsStore().update(auto_type_enabled=True, auto_type_confirm_window=False)
    assert service.settings_get() == {"enabled": True, "confirm": True}
    service.settings_set(False, True)
    DeviceSettingsStore().update(auto_type_enabled=True, auto_type_confirm_window=False)
    assert service.settings_get()["enabled"] is False
    assert code(service.run, REF) == "disabled"
    session.prefs[svc_mod.PREF_KEY] = "damaged"
    assert service.settings_get() == {"enabled": False, "confirm": True}


def test_loosening_needs_the_master_password_and_an_unlocked_vault(monkeypatch):
    calls = []

    def refuse(self, title, lease, allow_hello=False, fresh=False):
        calls.append(allow_hello)
        raise ApiError("cancelled", "no")

    monkeypatch.setattr(svc_mod.SecretService, "reauthenticate", refuse)
    session = PrefsSession()
    controller = Controller(session)
    service = AutoTypeService(controller, Port(answers=[True, True]), FakePlatform(), own_pid=OWN)
    assert code(service.settings_set, True, True) == "cancelled"
    assert service.settings_get()["enabled"] is False and calls == [False]
    session.prefs[svc_mod.PREF_KEY] = {"enabled": True, "confirm": True}
    assert code(service.settings_set, True, False) == "cancelled"  # turning the confirm step off
    assert service.settings_get() == {"enabled": True, "confirm": True}
    controller.unlocked = False
    assert code(service.settings_set, True, False) == "locked"
    # Tightening needs nothing.
    controller.unlocked = True
    assert service.settings_set(False, True)["enabled"] is False and calls == [False, False]


def test_text_goes_in_short_batches_with_the_window_checked_before_each():
    from localvault import auto_type as at

    platform = FakePlatform(fg=11)
    checks = []
    real = at.still_target
    at_run_steps = [("text", "abcdefghij"), ("key", "enter")]

    def counting(p, target, *typed):
        checks.append(1)
        return real(p, target, *typed)

    import unittest.mock as mock

    with mock.patch.object(at, "still_target", counting):
        at.run(platform, APP, at_run_steps, settings=type("S", (), {"auto_type_enabled": True,
                                                                     "auto_type_confirm_window": False})(),
               countdown=0, own_pid=OWN)
    assert platform.sent == [("text", "abcd"), ("text", "efgh"), ("text", "ij"), ("key", "enter")]
    assert len(checks) == 4


def test_unlocked_vault_that_never_stored_the_preference_reads_safe_defaults():
    """Final review L6: the file copy (written by another profile, or edited) is used only while locked."""
    DeviceSettingsStore().update(auto_type_enabled=True, auto_type_confirm_window=False)
    session = PrefsSession()
    controller = Controller(session)
    service = AutoTypeService(controller, Port(), FakePlatform(), own_pid=OWN)
    assert service.settings_get() == {"enabled": False, "confirm": True}
    assert code(service.run, REF) == "disabled"
    controller.unlocked = False
    assert service.settings_get() == {"enabled": True, "confirm": False}


def test_copy_once_login_types_once_then_needs_the_master_password(reauth):
    """Final review L4: typing releases the password like a copy, so the copy-once rule applies."""
    detail = {"id": "c1", "username": "alice", "revision": 7, "kind": "desktop",
              "scope": {"access": {"copy": "once"}}}
    service, platform, _controller, _port = make(session=Session(detail))
    service.run(REF)
    assert reauth == [True]
    service.run(REF)
    assert reauth == [True, False]
