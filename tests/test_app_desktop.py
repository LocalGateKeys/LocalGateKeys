"""Stage 7: desktop app fill and binding for the WebView UI (real vault; UI Automation faked)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from localvault import uia as real_uia
from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.desktop import DesktopService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from localvault.uia import ControlDescriptor, WindowSnapshot

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
EXE = r"C:\Program Files\Example\example.exe"


class Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append((name, detail))


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Port:
    def __init__(self):
        self.asked, self.answers, self.choice, self.remember = [], [], None, {"approved": True, "remember": False}

    def confirm(self, title, message):
        self.asked.append(title)
        return self.answers.pop(0) if self.answers else True

    def choose(self, title, message, options):
        self.asked.append(title)
        return self.choice

    def confirm_remember(self, title, message, remember_label):
        self.asked.append(title)
        return self.remember

    def show_upgrade(self, **kw):
        self.asked.append("upgrade")


def control(index, *, password, framework="Win32"):
    return ControlDescriptor(index=index, name="Password" if password else "User", automation_id=f"f{index}",
                             class_name="Edit", framework_id=framework, is_password=password, enabled=True,
                             visible=True, rectangle=(0, 0, 10, 10))


def snapshot(*, title="Example sign in", exe=EXE, framework="Win32"):
    return WindowSnapshot(hwnd=1, pid=2, title=title, exe_path=exe, exe_sha256="a" * 64,
                          controls=[control(0, password=False), control(1, password=True, framework=framework)],
                          signer=None)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = Bus()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    filled = []
    state = SimpleNamespace(snap=snapshot())
    fake = SimpleNamespace(
        foreground_hwnd=lambda: 1,
        scan_window=lambda hwnd: state.snap,
        scan_foreground_window=lambda: state.snap,
        choose_default_selectors=real_uia.choose_default_selectors,
        desktop_entry_matches_snapshot=real_uia.desktop_entry_matches_snapshot,
        updated_binary_binding=lambda entry, snap: None,
        fill_desktop_entry=lambda entry, snap, guard, sign_in: filled.append(entry["username"]) or False,
        _is_discord_executable=lambda path: False,
    )
    port = Port()
    service = DesktopService(controller, port, bus, serialise=lambda fn: fn(), ensure_unlocked=lambda: True,
                             reauthenticate=lambda title, lease: True, uia=fake, sleep=lambda s: None)
    return SimpleNamespace(controller=controller, port=port, bus=bus, service=service, filled=filled, state=state)


def _bind(env, *, username="ann", label="Example"):
    form = env.service.scan_for_binding()
    assert form["password_index"] == 1 and form["user_index"] == 0
    return env.service.save_binding(form["token"], form["user_index"], form["password_index"], label, username,
                                    "pw-desktop-12345")


def test_bind_then_fill_with_the_hotkey(env):
    result = _bind(env)
    assert result["message"].startswith("Bound Example to ")
    env.service.fill_foreground()
    assert env.filled == ["ann"]
    assert ("toast", {"kind": "info", "message": "Credentials filled. Sign in manually (or bind a supported Sign in "
                                                  "button)."}) in env.bus.events


def test_several_accounts_ask_which_one(env):
    _bind(env, username="ann")
    _bind(env, username="bob", label="Example 2")
    entries = env.controller.session.find_desktop(EXE)
    bob = next(e for e in entries if e["username"] == "bob")["id"]
    env.port.choice = bob
    env.service.fill_foreground()
    assert env.port.asked[-1] == "Choose account for this app" and env.filled == ["bob"]
    env.port.choice = None
    env.service.fill_foreground()
    assert env.filled == ["bob"]


def test_no_saved_login_offers_to_add_one(env):
    env.service.fill_foreground()
    assert "Add desktop login?" in env.port.asked
    navigate = [d for n, d in env.bus.events if n == "navigate"]
    assert navigate and navigate[0]["route"] == "desktop-bind"
    form = env.service.binding_form(navigate[0]["params"]["token"])
    assert form["rebind"] is False


def test_browsers_and_untitled_windows_are_refused(env):
    env.state.snap = snapshot(exe=r"C:\Program Files\Google\Chrome\chrome.exe")
    env.service.fill_foreground()
    assert ("toast", {"kind": "info", "message": "Use the browser field icon for normal browser logins."}) in env.bus.events
    env.state.snap = snapshot(title="  ")
    with pytest.raises(ApiError) as untitled:
        env.service.scan_for_binding()
    assert untitled.value.message.startswith("Unsupported untitled window")


def test_embedded_web_fill_asks_and_can_remember(env):
    env.state.snap = snapshot(framework="Chrome")
    _bind(env)
    env.port.remember = {"approved": True, "remember": True}
    env.service.fill_foreground()
    assert "Confirm desktop fill" in env.port.asked and env.filled == ["ann"]
    entry = env.controller.session.find_desktop(EXE)[0]
    assert entry["scope"].get("embedded_web_fill_approved") is True


def test_bind_needs_a_password_and_cleans_up(env):
    form = env.service.scan_for_binding()
    with pytest.raises(ApiError):
        env.service.save_binding(form["token"], 0, 1, "Example", "ann", "")
    env.service.save_binding(form["token"], 0, 1, "Example", "ann", "pw-desktop-12345")  # the scan survived the typo
    with pytest.raises(ApiError) as gone:
        env.service.save_binding(form["token"], 0, 1, "Example", "ann", "pw-desktop-12345")
    assert gone.value.code == "expired"  # a token is single-use


def test_lock_during_the_updated_app_prompt_writes_nothing(env):
    _bind(env)
    class Held(dict):
        def clear(self):
            pass
    env.service._uia.desktop_entry_matches_snapshot = lambda entry, snap: False
    env.service._uia.updated_binary_binding = lambda entry, snap: (Held(), False)

    def confirm(title, message):
        env.port.asked.append(title)
        env.controller.lock("test")
        return True
    env.port.confirm = confirm
    env.service.fill_foreground()  # must not raise AttributeError on the cleared session
    assert "App was updated" in env.port.asked and env.filled == []


def test_an_old_binding_scan_expires_and_fill_after_asks_first(env):
    clock = [1000.0]
    env.service._clock = lambda: clock[0]
    env.service.fill_foreground()  # no saved login: offers to add, remembers the scan with fill-after
    token = [d for n, d in env.bus.events if n == "navigate"][0]["params"]["token"]
    clock[0] += 121
    with pytest.raises(ApiError):
        env.service.save_binding(token, 0, 1, "Example", "ann", "pw-desktop-12345")
    env.service.fill_foreground()
    token = [d for n, d in env.bus.events if n == "navigate"][-1]["params"]["token"]
    env.port.answers = [False]  # "Fill now?" declined
    env.service.save_binding(token, 0, 1, "Example", "ann", "pw-desktop-12345")
    assert env.port.asked[-1] == "Fill the app now?" and env.filled == []


def test_a_locked_vault_rescans_the_window_after_unlock(env):
    _bind(env)
    env.controller.lock("test")
    scans = []
    real_scan = env.service._uia.scan_window
    env.service._uia.scan_window = lambda hwnd: scans.append(hwnd) or real_scan(hwnd)

    def unlock_then_true():
        env.controller.unlock(MASTER)
        return True
    env.service._ensure_unlocked = unlock_then_true
    env.service.fill_foreground()
    assert len(scans) == 2 and env.filled == ["ann"]


def test_binding_a_new_app_at_the_item_limit_offers_the_upgrade(env):
    env.controller.session.item_limit = 0
    form = env.service.scan_for_binding()
    with pytest.raises(ApiError) as full:
        env.service.save_binding(form["token"], form["user_index"], form["password_index"], "Example", "ann",
                                 "pw-desktop-12345")
    assert full.value.code == "item_limit" and "upgrade" in env.port.asked
    assert env.controller.session.find_desktop(EXE) == []


def button(index, name, *, automation_id="", class_name=""):
    return ControlDescriptor(index=index, name=name, automation_id=automation_id, class_name=class_name,
                             framework_id="Win32", is_password=False, enabled=True, visible=True,
                             rectangle=(0, 0, 10, 10))


def _with_buttons(env, buttons):
    snap = snapshot()
    snap.buttons = buttons
    env.service._uia.scan_bound_window = lambda binding, include_buttons, include_all_buttons: snap
    entry_id = _bind(env)["entry_id"]
    return entry_id


def test_map_the_sign_in_button_after_a_confirm(env):
    entry_id = _with_buttons(env, [button(5, "Sign in", automation_id="login"), button(6, "Cancel", automation_id="c")])
    form = env.service.sign_in_buttons(entry_id)
    assert [b["name"] for b in form["buttons"]] == ["Sign in", "Cancel"] and form["current"] == "Not mapped"
    result = env.service.map_sign_in(form["token"], 5)
    assert env.port.asked[-1] == "Trust this login action?" and "Sign in" in result["message"]
    scope = env.controller.session.get_entry(entry_id)["scope"]
    assert scope["sign_in_selector"]["name"] == "Sign in"
    assert scope["sign_in_selector"]["identity_mode"] == "exact_metadata"
    assert env.service.sign_in_buttons(entry_id)["current"] == "Sign in"


def test_a_name_only_button_must_be_unique(env):
    entry_id = _with_buttons(env, [button(5, "Sign in"), button(6, "Sign in")])
    form = env.service.sign_in_buttons(entry_id)
    asked = len(env.port.asked)
    with pytest.raises(ApiError):
        env.service.map_sign_in(form["token"], 5)
    assert len(env.port.asked) == asked  # refused before any confirm
    assert "sign_in_selector" not in env.controller.session.get_entry(entry_id)["scope"]


def test_declining_the_confirm_saves_nothing(env):
    entry_id = _with_buttons(env, [button(5, "Sign in")])
    form = env.service.sign_in_buttons(entry_id)
    env.port.answers = [False]
    with pytest.raises(ApiError) as cancelled:
        env.service.map_sign_in(form["token"], 5)
    assert cancelled.value.code == "cancelled"
    assert "sign_in_selector" not in env.controller.session.get_entry(entry_id)["scope"]


def test_require_the_embedded_web_warning_again(env):
    entry_id = _bind(env)["entry_id"]
    env.controller.session.set_desktop_embedded_fill_approval(entry_id, True)
    env.service.require_web_warning(entry_id)
    assert not env.controller.session.get_entry(entry_id)["scope"].get("embedded_web_fill_approved")


def test_the_field_button_fills_the_window_it_was_shown_for(env):
    _bind(env)
    scanned = []
    real = env.service._uia.scan_window
    env.service._uia.scan_window = lambda hwnd: scanned.append(hwnd) or real(hwnd)
    env.service.fill_window(77)
    assert scanned == [77] and env.filled == ["ann"]


def test_a_lock_during_the_trust_prompt_saves_no_sign_in_button(env):
    entry_id = _with_buttons(env, [button(5, "Sign in", automation_id="login")])
    form = env.service.sign_in_buttons(entry_id)

    def confirm(title, message):
        env.port.asked.append(title)
        env.controller.lock("test")
        env.controller.unlock(MASTER)  # same profile again, a new session
        return True
    env.port.confirm = confirm
    with pytest.raises(Exception):
        env.service.map_sign_in(form["token"], 5)
    assert "sign_in_selector" not in env.controller.session.get_entry(entry_id)["scope"]


def test_a_sign_in_scan_cannot_be_used_to_rebind(env):
    entry_id = _with_buttons(env, [button(5, "Sign in", automation_id="login")])
    form = env.service.sign_in_buttons(entry_id)
    with pytest.raises(ApiError):
        env.service.binding_form(form["token"])
    with pytest.raises(ApiError):
        env.service.save_binding(form["token"], 0, 1)
