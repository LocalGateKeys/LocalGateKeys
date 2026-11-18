"""Stage 7: the WebView agent host that runs the classic browser broker and native integrations."""
from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace

import pytest

from localvault.app.controller import WebController
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings
from localvault.web.host import WebAgentHost

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
ORIGIN = "https://login.example.test"
CONTEXT = json.dumps([17, "document-redacted", ORIGIN, "operation-redacted"])


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
        self.asked, self.answers, self.passwords = [], [], []

    def confirm(self, title, message):
        self.asked.append((title, message))
        return self.answers.pop(0) if self.answers else True

    def notify(self, kind, title, message):
        self.asked.append((title, message))

    def ask_password(self, title, message):
        self.asked.append((title, message))
        answer = self.passwords.pop(0) if self.passwords else None
        return None if answer is None else SecretText.from_str(answer)

    def ask_passkey(self, mode, **kw):
        return ("cancel", None)

    def show_upgrade(self, **kw):
        pass


class Window:
    def __init__(self):
        self.calls = []

    def raise_window(self):
        self.calls.append("raise")

    def show(self):
        self.calls.append("show")

    def hide(self):
        self.calls.append("hide")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = Bus()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault", browser_enabled=True),
                               bus=bus, scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    port, window = Port(), Window()
    host = WebAgentHost(controller, port, bus, window=window, unlock_timeout=0.5)
    return SimpleNamespace(controller=controller, port=port, bus=bus, window=window, host=host)


def request(host, action, **payload):
    return host.dispatch_remote({"action": action, "protocol": 2, "extension_version": "0.4.0", "origin": ORIGIN,
                                 "context": CONTEXT, **payload})


def test_ping_reports_lock_state(env):
    assert request(env.host, "ping")["locked"] is False
    env.controller.lock()
    assert request(env.host, "ping")["locked"] is True


def test_browser_save_goes_through_the_page_confirm(env):
    nonce = request(env.host, "begin_gesture_browser", user_gesture=True)["gesture_nonce"]
    reply = request(env.host, "save_browser", username="ann", password="pw-from-browser-1", gesture_nonce=nonce)
    assert reply["ok"] is True
    assert env.port.asked[0][0] == "Save new login?"
    assert env.controller.session.live_item_count() == 1
    assert ("items.changed", {}) in env.bus.events


def test_run_on_ui_is_serialised_with_page_calls(env):
    lock = env.controller.vault_lock
    lock.acquire()  # a page call is in progress
    done = threading.Event()
    threading.Thread(target=lambda: (env.host.run_on_ui(lambda: None, timeout=2), done.set()), daemon=True).start()
    assert not done.wait(0.3)
    lock.release()
    assert done.wait(2)


def test_run_on_ui_times_out(env):
    env.controller.vault_lock.acquire()
    try:
        with pytest.raises(TimeoutError):
            env.host.run_on_ui(lambda: None, timeout=0.2)
    finally:
        env.controller.vault_lock.release()


def test_ensure_unlocked_raises_the_window_and_waits(env):
    env.controller.lock()
    threading.Timer(0.2, lambda: env.controller.unlock(MASTER)).start()
    assert env.host.ensure_unlocked() is True
    assert "raise" in env.window.calls
    assert any(name == "toast" for name, _ in env.bus.events)


def test_ensure_unlocked_gives_up(env):
    env.controller.lock()
    started = time.monotonic()
    assert env.host.ensure_unlocked() is False
    assert time.monotonic() - started < 2


def test_reauthenticate_maps_to_bool(env):
    lease = env.controller.guard.lease()
    env.port.passwords = [MASTER]
    assert env.host.reauthenticate("Confirm master password for this credential", lease) is True
    env.controller.routine_reauth = (None, 0.0)
    env.port.passwords = []
    assert env.host.reauthenticate("Confirm master password for this credential", lease) is False


def test_browser_disabled_refuses(env):
    env.controller.settings.browser_enabled = False
    assert request(env.host, "begin_gesture_browser", user_gesture=True)["error"] == "integration_disabled"


def test_emergency_lock_marks_master_required(env, monkeypatch):
    marks = []
    monkeypatch.setattr("localvault.app.lockmodes.require_master_unlock", lambda pid: marks.append(pid) or True)
    env.host.emergency_lock()
    assert not env.controller.is_unlocked() and marks


# ------------------------------------------------------------- integrations
class Fake:
    def __init__(self, *args, **kwargs):
        self.args, self.kwargs = args, kwargs
        self.started = self.stopped = False
        self.available = True
        self.refreshed = 0

    def start(self):
        self.started = True

    def stop(self, *a, **k):
        self.stopped = True

    def set_enabled(self, value):
        self.enabled = value

    def refresh(self):
        self.refreshed += 1


def _start(env):
    made = {}

    def factory(name):
        def make(*args, **kwargs):
            made[name] = Fake(*args, **kwargs)
            return made[name]
        return make

    env.host.post = lambda fn: fn()  # run callbacks inline for the test
    env.host.start_integrations(pipe=factory("pipe"), hotkey=factory("hotkey"), monitor=factory("monitor"),
                                tray=factory("tray"), overlay=factory("overlay"))
    return made


def test_integrations_start_and_stop(env):
    made = _start(env)
    assert all(made[name].started for name in ("pipe", "hotkey", "monitor", "tray"))
    env.host.stop_integrations()
    assert all(made[name].stopped for name in ("pipe", "hotkey", "monitor", "tray"))


class FakeAgent:
    def __init__(self, host, status_after_start="running"):
        self.host, self.status, self._after = host, "stopped", status_after_start
        self.starts = self.stops = 0

    def start(self):
        self.starts += 1
        self.status = self._after

    def stop(self):
        self.stops += 1
        if self.status == "running":
            self.status = "stopped"


def test_ssh_agent_follows_the_developer_setting(env):
    made = []
    env.host.post = lambda fn: fn()
    factory = lambda name: Fake  # noqa: E731
    env.host.start_integrations(pipe=factory("pipe"), hotkey=factory("hotkey"), monitor=factory("monitor"),
                                tray=factory("tray"), overlay=factory("overlay"),
                                ssh_agent=lambda host: made.append(FakeAgent(host)) or made[-1])
    assert made == [] and env.host.ssh_agent_status() == "off"  # off by default
    env.host.settings.developer_ssh_agent = True
    assert env.host.apply_ssh_agent() == "running"
    assert made[0].host is env.host and made[0].starts == 1
    assert env.host.apply_ssh_agent() == "running" and len(made) == 1  # already running: unchanged
    env.host.settings.developer_ssh_agent = False
    assert env.host.apply_ssh_agent() == "off" and made[0].stops == 1
    env.host.settings.developer_ssh_agent = True
    env.host.apply_ssh_agent()
    env.host.stop_integrations()
    assert made[1].stops == 1 and env.host.ssh_agent_status() == "off"


def test_ssh_agent_name_taken_is_reported_and_retried(env):
    made = []
    env.host.settings.developer_ssh_agent = True
    env.host.post = lambda fn: fn()
    factory = lambda name: Fake  # noqa: E731
    env.host.start_integrations(pipe=factory("pipe"), hotkey=factory("hotkey"), monitor=factory("monitor"),
                                tray=factory("tray"), overlay=factory("overlay"),
                                ssh_agent=lambda host: made.append(FakeAgent(host, "unavailable")) or made[-1])
    assert env.host.ssh_agent_status() == "unavailable"
    assert env.host.apply_ssh_agent() == "unavailable" and len(made) == 2  # tried again
    env.host._ssh_agent_factory = lambda host: (_ for _ in ()).throw(OSError("no pywin32"))
    assert env.host.apply_ssh_agent() == "unavailable" and env.host.ssh_agent_status() == "off"
    env.host.stop_integrations()


def test_hotkey_callbacks(env, monkeypatch):
    marks = []
    monkeypatch.setattr("localvault.app.lockmodes.require_master_unlock", lambda pid: marks.append(pid) or True)
    made = _start(env)
    _fill, emergency, quick = made["hotkey"].args
    quick()
    assert ("navigate", {"route": "quick-access"}) in env.bus.events and "raise" in env.window.calls
    emergency()
    assert not env.controller.is_unlocked() and marks


def test_session_monitor_respects_the_settings(env):
    made = _start(env)
    on_lock = made["monitor"].args[0]
    env.controller.settings.lock_on_sleep = False
    on_lock("Windows is sleeping")
    assert env.controller.is_unlocked()
    env.controller.settings.lock_on_session_lock = True
    on_lock("Windows session locked")
    assert not env.controller.is_unlocked()
    assert env.controller.state()["status"] == "Vault locked: Windows session locked."


def test_tray_menu_actions(env, monkeypatch):
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)
    made = _start(env)
    tray = made["tray"].kwargs
    assert tray["state"]() == {"unlocked": True, "browser_enabled": True,
                               "desktop_enabled": bool(env.controller.settings.desktop_overlay_enabled)}
    tray["on_toggle_browser"]()
    assert env.controller.settings.browser_enabled is False
    assert ("toast", {"kind": "info", "message": "Browser integration paused."}) in env.bus.events
    tray["on_lock"]()
    assert not env.controller.is_unlocked() and made["tray"].refreshed
    tray["on_open"]()
    assert "show" in env.window.calls


def test_close_hides_to_tray_or_exits(env):
    _start(env)
    exits = []
    env.host.on_exit = lambda: exits.append(1)
    env.controller.settings.minimize_to_tray = True
    assert env.host.close_requested() is False and "hide" in env.window.calls and exits == []
    env.controller.settings.minimize_to_tray = False
    assert env.host.close_requested() is True


def test_emergency_lock_does_not_wait_behind_a_fill_prompt(env, monkeypatch):
    import threading
    import time as _time

    monkeypatch.setattr("localvault.app.lockmodes.require_master_unlock", lambda pid: True)
    release = threading.Event()
    env.host.desktop_fill = lambda: release.wait(5)  # a fill sitting on a page prompt
    made = {}

    def factory(name):
        def make(*args, **kwargs):
            made[name] = Fake(*args, **kwargs)
            return made[name]
        return make

    env.host.start_integrations(pipe=factory("pipe"), hotkey=factory("hotkey"), monitor=factory("monitor"),
                                tray=factory("tray"), overlay=factory("overlay"))
    fill, emergency, _quick = made["hotkey"].args
    fill()
    _time.sleep(0.1)
    emergency()
    deadline = _time.monotonic() + 2
    while env.controller.is_unlocked() and _time.monotonic() < deadline:
        _time.sleep(0.02)
    unlocked = env.controller.is_unlocked()
    release.set()
    env.host.stop_integrations()
    assert not unlocked


def test_page_calls_are_not_blocked_while_a_browser_prompt_waits(env):
    lock = env.controller.vault_lock
    seen = {}

    def confirm(title, message):
        seen["free"] = lock.acquire(blocking=False)  # what a page call would try during the prompt
        if seen["free"]:
            lock.release()
        return True
    env.port.confirm = confirm
    assert env.host.run_on_ui(lambda: env.host.ui.confirm("Save new login?", "m")) is True
    assert seen["free"] is True
    assert lock.acquire(blocking=False)  # handed back afterwards and released at the end
    lock.release()


def test_waiting_for_unlock_releases_the_vault_lock(env):
    import threading
    env.controller.lock()
    lock = env.controller.vault_lock
    result = {}
    worker = threading.Thread(target=lambda: result.setdefault("r", env.host.run_on_ui(env.host.ensure_unlocked)))
    worker.start()
    import time as _time
    _time.sleep(0.15)
    got = lock.acquire(timeout=10)  # the page's unlock (or any page call) is not stuck behind the request
    if got:
        lock.release()
    env.controller.unlock(MASTER)
    worker.join(30)
    assert got and result["r"] is True


def test_changing_the_quick_shortcut_keeps_fill_off_the_shared_worker(env):
    made = _start(env)
    old = made["hotkey"]
    env.controller.settings.quick_access_hotkey = "Ctrl+Alt+J"
    env.host.restart_hotkeys()
    new = env.host.hotkey
    assert old.stopped and new.started and new is not old and new.kwargs["quick_hotkey"] == "Ctrl+Alt+J"
    assert new.args[0] == env.host._spawn_desktop_fill  # its own thread, as at startup
    assert new in env.host.integrations and old not in env.host.integrations


def test_a_shortcut_that_fails_to_start_brings_back_the_old_one(env):
    made = _start(env)

    class Broken(Fake):
        def start(self):
            raise OSError("in use")
    built = []

    def factory(*a, **k):
        listener = (Broken if not built else Fake)(*a, **k)  # the new shortcut fails, the old one comes back
        built.append(listener)
        return listener
    env.host._hotkey_factory = factory
    env.controller.settings.quick_access_hotkey = "Ctrl+Alt+J"
    env.host.restart_hotkeys()
    assert env.host.hotkey.started and env.host.hotkey.kwargs["quick_hotkey"] == made["hotkey"].kwargs["quick_hotkey"]
    assert any("Hotkey unavailable" in str(d) for _n, d in env.bus.events)


def test_a_shortcut_windows_refuses_brings_back_the_old_one(env):
    made = _start(env)
    built = []

    def factory(*a, **k):
        listener = Fake(*a, **k)
        listener.quick_error = None if built else "Ctrl+Alt+J is already registered by another application"
        built.append(listener)
        return listener
    env.host._hotkey_factory = factory
    env.controller.settings.quick_access_hotkey = "Ctrl+Alt+J"
    env.host.restart_hotkeys()
    assert built[0].stopped and env.host.hotkey is built[1]
    assert env.host.hotkey.kwargs["quick_hotkey"] == made["hotkey"].kwargs["quick_hotkey"]


def test_an_emergency_lock_hotkey_windows_refuses_is_shown(env):
    class Refused(Fake):
        def start(self):
            super().start()
            self.emergency_error = "Ctrl+Alt+L is already registered by another application"

    env.host.post = lambda fn: fn()
    env.host.start_integrations(pipe=Fake, hotkey=Refused, monitor=Fake, tray=Fake, overlay=Fake)
    assert any("Ctrl+Alt+L is already registered" in str(d) for _n, d in env.bus.events)


class OverlayFake(Fake):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.enabled = None

    def set_enabled(self, value):
        self.enabled = value


def _start_with_overlay(env):
    made = {}

    def factory(name, cls=Fake):
        def make(*args, **kwargs):
            made[name] = cls(*args, **kwargs)
            return made[name]
        return make
    env.host.post = lambda fn: fn()
    env.host.start_integrations(pipe=factory("pipe"), hotkey=factory("hotkey"), monitor=factory("monitor"),
                                tray=factory("tray"), overlay=factory("overlay", OverlayFake))
    return made


def test_the_field_button_follows_the_setting_and_lock_modes(env, monkeypatch):
    monkeypatch.setattr("localvault.app.lockmodes.require_master_unlock", lambda pid: True)
    env.controller.settings.desktop_overlay_enabled = True
    made = _start_with_overlay(env)
    overlay = made["overlay"]
    assert overlay.started and overlay.enabled is True
    env.host._toggle_desktop()
    assert overlay.enabled is False
    env.host._toggle_desktop()
    assert overlay.enabled is True
    env.host.emergency_lock()
    assert overlay.enabled is False  # until the next unlock
    env.controller.unlock(MASTER)
    assert overlay.enabled is True
    env.host.stop_integrations()
    assert overlay.stopped


def test_clicking_the_field_button_fills_that_window(env):
    filled = []
    env.host.desktop_fill_window = lambda hwnd: filled.append(hwnd)
    made = _start_with_overlay(env)
    on_click = made["overlay"].kwargs["on_click"]
    on_click(4242)
    import time as _time
    deadline = _time.monotonic() + 2
    while not filled and _time.monotonic() < deadline:
        _time.sleep(0.02)
    assert filled == [4242]


def test_windows_hello_reauth_does_not_hold_the_vault_lock(env):
    lock = env.controller.vault_lock
    seen = {}

    def hello(title, lease):
        seen["free"] = lock.acquire(blocking=False)
        if seen["free"]:
            lock.release()
        return True
    env.controller.hello_reauth = hello
    lease = env.controller.guard.lease()
    assert env.host.run_on_ui(lambda: env.host.reauthenticate("Use passkey", lease, allow_hello=True)) is True
    assert seen["free"] is True


class Popup:
    def __init__(self):
        self.calls = []

    def show(self):
        self.calls.append("show")

    def hide(self):
        self.calls.append("hide")


def _popup_host(env):
    from localvault.web.ui_port import WebUiPort

    port = WebUiPort(env.bus, timeout=5)
    popup = Popup()
    host = WebAgentHost(env.controller, port, env.bus, window=env.window, unlock_timeout=2, popup=popup)
    return host, port, popup


def test_a_fill_on_a_locked_vault_shows_the_small_popup_not_the_app(env):
    import threading
    host, _port, popup = _popup_host(env)
    env.controller.lock()
    result = {}
    worker = threading.Thread(target=lambda: result.setdefault("r", host.ensure_unlocked()))
    worker.start()
    import time as _time
    _time.sleep(0.2)
    assert popup.calls == ["show"] and "raise" not in env.window.calls
    env.controller.unlock(MASTER)
    worker.join(3)
    assert result["r"] is True and popup.calls[-1] == "hide"


def test_closing_the_popup_cancels_the_waiting_fill(env):
    import threading
    host, _port, popup = _popup_host(env)
    env.controller.lock()
    result = {}
    worker = threading.Thread(target=lambda: result.setdefault("r", host.ensure_unlocked()))
    worker.start()
    import time as _time
    _time.sleep(0.2)
    host.popup_closed()
    worker.join(1)
    assert result["r"] is False and not env.controller.is_unlocked()


def test_fill_prompts_go_to_the_popup_and_it_hides_when_answered(env):
    import threading
    host, port, popup = _popup_host(env)
    box = {}
    worker = threading.Thread(target=lambda: box.setdefault("r", host.ui.choose("Choose account", "", [{"id": "a", "label": "ann"}])))
    worker.start()
    import time as _time
    deadline = _time.monotonic() + 2
    while not any(n == "modal.request" for n, _ in env.bus.events) and _time.monotonic() < deadline:
        _time.sleep(0.01)
    request = [d for n, d in env.bus.events if n == "modal.request"][-1]
    assert request["surface"] == "popup" and popup.calls == ["show"]
    port.answer(request["id"], "a")
    worker.join(2)
    assert box["r"] == "a" and popup.calls == ["show", "hide"]


class Palette:
    def __init__(self):
        self.calls = []
        self.disabled = False

    def show_centered(self):
        self.calls.append("show")
        return True

    def hide(self):
        self.calls.append("hide")


def test_quick_access_opens_the_palette_when_the_setting_is_on(env):
    env.host.palette = palette = Palette()
    env.controller.settings.quick_access_palette = True
    env.host.quick_access()
    assert palette.calls == ["show"]
    assert ("palette.show", {}) in env.bus.events
    assert ("navigate", {"route": "quick-access"}) not in env.bus.events


def test_quick_access_opens_the_app_page_when_the_setting_is_off(env):
    env.host.palette = palette = Palette()
    env.controller.settings.quick_access_palette = False
    env.host.quick_access()
    assert palette.calls == []
    assert ("navigate", {"route": "quick-access"}) in env.bus.events


def test_quick_access_falls_back_to_the_app_page_without_a_palette(env):
    env.host.palette = palette = Palette()
    palette.disabled = True
    env.host.quick_access()
    assert ("navigate", {"route": "quick-access"}) in env.bus.events


def test_hide_palette_tells_the_page_and_hides_the_window(env):
    env.host.palette = palette = Palette()
    env.host.hide_palette()
    assert palette.calls == ["hide"] and ("palette.hide", {}) in env.bus.events


def test_hiding_the_palette_cancels_its_prompts(env):
    cancelled = []
    env.host.palette = Palette()
    env.host._port = SimpleNamespace(cancel_surface=cancelled.append)
    env.host.hide_palette()
    assert cancelled == ["palette"]


def test_lock_hides_palette(env):
    env.host.palette = palette = Palette()
    env.host.lock()
    assert not env.controller.is_unlocked()
    assert palette.calls == ["hide"] and ("palette.hide", {}) in env.bus.events


def test_emergency_lock_hides_palette(env, monkeypatch):
    monkeypatch.setattr("localvault.app.lockmodes.require_master_unlock", lambda pid: True)
    env.host.palette = palette = Palette()
    env.host.emergency_lock()
    assert "hide" in palette.calls


def test_a_popup_question_hides_the_palette(env):
    host, _port, popup = _popup_host(env)
    host.palette = palette = Palette()
    host.show_popup()
    assert palette.calls == ["hide"]


# ------------------------------------------------------------- duress session (sub-plan 08, Task 4)
DURESS = "orange tractor sunset"


def _duress_session(env):
    from localvault import duress

    env.controller.session.item_service.create_ssh_key("deploy", private_key="", public_key="")
    duress.setup(env.controller.session, DURESS, lock_hours=6, master_password=MASTER)
    env.controller.lock()
    env.controller.unlock(DURESS)
    assert duress.is_decoy(env.controller.session) and env.controller.is_unlocked()


def test_a_duress_session_serves_no_browser_or_cli_request(env):
    from localvault.cli_service import CliService

    _duress_session(env)
    assert env.host.session is None
    assert request(env.host, "ping")["locked"] is True
    assert request(env.host, "begin_browser") == {"ok": False, "error": "integration_disabled"}
    assert env.host.ensure_unlocked() is False and env.window.calls == []  # no window raised, no wait
    env.host.settings.developer_cli = True
    assert CliService(env.host).dispatch({"action": "list"}, None)["error"] == "locked"
    env.controller.lock()
    assert request(env.host, "ping")["locked"] is True  # locked again: the ordinary locked answer


def test_a_duress_session_stops_the_ssh_agent(env):
    from localvault.ssh_agent import SshAgentService

    made = []
    env.host.post = lambda fn: fn()
    factory = lambda name: Fake  # noqa: E731
    env.host.settings.developer_ssh_agent = True
    env.host.start_integrations(pipe=factory("pipe"), hotkey=factory("hotkey"), monitor=factory("monitor"),
                                tray=factory("tray"), overlay=factory("overlay"),
                                ssh_agent=lambda host: made.append(FakeAgent(host)) or made[-1])
    assert env.host.ssh_agent_status() == "running"
    _duress_session(env)
    assert env.host.ssh_agent_status() == "off" and made[0].stops == 1
    assert SshAgentService(env.host).identities() == []
    env.controller.lock()
    assert env.host.ssh_agent_status() == "running" and len(made) == 2  # back once the duress session ends
    env.host.stop_integrations()
