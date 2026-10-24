"""Stage 1: the Tk-free controller behind the WebView UI â€” profiles, unlock, create, lock, auto-lock."""
from __future__ import annotations

import json
import threading

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
PASSWORD = "correct horse battery"


class RecordingBus:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def emit(self, name, detail):
        self.events.append((name, json.loads(json.dumps(detail))))

    def states(self) -> list[str]:
        return [d["state"] for n, d in self.events if n == "vault.state"]


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class ManualScheduler:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    bus, clock = RecordingBus(), Clock()
    settings = AppSettings(auto_lock_seconds=300, idle_source="vault")
    controller = WebController(profiles=profiles, settings=settings, bus=bus, clock=clock,
                               scheduler=ManualScheduler(), create_kwargs={"kdf_overrides": KDF})
    return controller, profiles, bus, clock


def test_no_profile_state(env):
    controller, _profiles, _bus, _clock = env
    state = controller.state()
    assert state["state"] == "no_profile" and state["profile"] is None


def test_create_then_unlock_then_lock(env):
    controller, profiles, bus, _clock = env
    profiles.ensure_profile()
    assert controller.state()["vault_exists"] is False
    assert controller.create(PASSWORD, PASSWORD)["state"] == "unlocked"
    assert controller.lock()["state"] == "locked"
    assert controller.unlock(PASSWORD)["state"] == "unlocked"
    assert bus.states()[-3:] == ["unlocked", "locked", "unlocked"]
    session = controller.session
    controller.lock()
    assert not session.is_unlocked


def test_create_mismatch_and_short(env):
    controller, profiles, _bus, _clock = env
    profiles.ensure_profile()
    with pytest.raises(ApiError) as mismatch:
        controller.create(PASSWORD, PASSWORD + "x")
    assert (mismatch.value.code, mismatch.value.message) == ("mismatch", "The master passwords do not match.")
    with pytest.raises(ApiError) as short:
        controller.create("short", "short")
    assert short.value.code == "vault_error" and "12 characters" in short.value.message


def test_wrong_password_is_apierror_with_vault_message(env):
    controller, profiles, _bus, _clock = env
    profiles.ensure_profile()
    controller.create(PASSWORD, PASSWORD)
    controller.lock()
    with pytest.raises(ApiError) as wrong:
        controller.unlock("not the password!!")
    assert wrong.value.code in {"wrong_password", "throttled"}
    assert controller.state()["state"] == "locked"


def test_concurrent_unlock_second_is_busy(env, monkeypatch):
    controller, profiles, _bus, _clock = env
    profiles.ensure_profile()
    controller.create(PASSWORD, PASSWORD)
    controller.lock()
    release, entered = threading.Event(), threading.Event()
    real_unlock = __import__("localvault.app.controller", fromlist=["unlock_vault"]).unlock_vault

    def slow_unlock(*args, **kwargs):
        entered.set()
        release.wait(5)
        return real_unlock(*args, **kwargs)

    monkeypatch.setattr("localvault.app.controller.unlock_vault", slow_unlock)
    first = threading.Thread(target=lambda: controller.unlock(PASSWORD))
    first.start()
    assert entered.wait(5)
    with pytest.raises(ApiError) as busy:
        controller.unlock(PASSWORD)
    assert busy.value.code == "busy"
    release.set()
    first.join(10)
    assert controller.state()["state"] == "unlocked"


def test_idle_autolock_locks_and_emits(env):
    controller, profiles, bus, clock = env
    profiles.ensure_profile()
    controller.create(PASSWORD, PASSWORD)
    controller.touch()
    clock.now += 100
    controller.tick()
    assert controller.state()["state"] == "unlocked"
    assert any(n == "autolock.tick" and d["remaining"] == 200 for n, d in bus.events)
    clock.now += 250
    controller.tick()
    assert controller.state()["state"] == "locked"
    assert bus.states()[-1] == "locked"


def test_select_profile_while_unlocked_locks_first(env):
    controller, profiles, _bus, _clock = env
    first = profiles.ensure_profile()
    controller.create(PASSWORD, PASSWORD)
    session = controller.session
    second = profiles.create_profile("Second")
    state = controller.select_profile(second.id)
    assert not session.is_unlocked
    assert state["state"] == "locked" and state["profile"]["id"] == second.id
    assert {p["id"]: p["active"] for p in controller.list_profiles()} == {first.id: False, second.id: True}


def test_select_unknown_profile_is_apierror(env):
    controller, profiles, _bus, _clock = env
    profiles.ensure_profile()
    with pytest.raises(ApiError) as missing:
        controller.select_profile("nope")
    assert missing.value.code == "not_found"


def test_state_never_contains_password(env):
    controller, profiles, bus, clock = env
    profiles.ensure_profile()
    controller.create(PASSWORD, PASSWORD)
    controller.lock()
    controller.unlock(PASSWORD)
    clock.now += 1000
    controller.tick()
    assert PASSWORD not in json.dumps(bus.events)
    assert PASSWORD not in json.dumps(controller.state())


def test_lock_hooks_run_after_the_controller_lock_is_released(env):
    controller, profiles, _bus, _clock = env
    profiles.ensure_profile()
    controller.create(PASSWORD, PASSWORD)
    acquired = []

    def hook():
        box = {}
        probe = threading.Thread(target=lambda: box.update(got=controller._lock.acquire(timeout=1)))
        probe.start()
        probe.join(2)
        acquired.append(box.get("got"))
        if box.get("got"):
            controller._lock.release()

    controller.on_lock.append(hook)
    controller.lock()
    assert acquired == [True]


def test_tick_during_unlock_cannot_lock_the_new_session(env, monkeypatch):
    controller, profiles, _bus, _clock = env
    profiles.ensure_profile()
    controller.create(PASSWORD, PASSWORD)
    controller.lock()
    real_open = controller.guard.open

    def open_then_tick(seconds):
        controller.tick()  # a timer tick landing in the middle of _finish, before the guard opens
        return real_open(seconds)

    monkeypatch.setattr(controller.guard, "open", open_then_tick)
    assert controller.unlock(PASSWORD)["state"] == "unlocked"
    assert controller.state()["state"] == "unlocked"


def test_os_errors_do_not_reach_the_page_with_paths(env, monkeypatch):
    controller, profiles, _bus, _clock = env
    profiles.ensure_profile()

    def denied(*_a, **_k):
        raise PermissionError(13, "Access is denied", r"C:\Users\someone\AppData\Local\LocalGateKeys\vault.json")

    monkeypatch.setattr("localvault.app.controller.create_vault", denied)
    with pytest.raises(ApiError) as failure:
        controller.create(PASSWORD, PASSWORD)
    assert failure.value.code == "vault_error"
    assert "Users" not in failure.value.message and "AppData" not in failure.value.message


def test_unlock_warns_when_rollback_protection_was_reset(env, monkeypatch):
    controller, profiles, bus, _clock = env
    profiles.ensure_profile()
    controller.create(PASSWORD, PASSWORD)
    controller.lock()
    import localvault.app.controller as controller_module
    real = controller_module.unlock_vault

    def unlock_without_anchor(*args, **kwargs):
        session = real(*args, **kwargs)
        session.rollback_anchor_missing = True
        return session
    monkeypatch.setattr(controller_module, "unlock_vault", unlock_without_anchor)
    controller.unlock(PASSWORD)
    notices = [d for n, d in bus.events if n == "notice"]
    assert notices and notices[-1]["title"] == "Rollback protection was reset"
    assert "newest copy of the vault" in notices[-1]["message"]
