"""Stage 4a: scheduled backups, emergency lock, lock & switch person, unlock-screen extras."""
from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.lockmodes import LockModes
from localvault.app.schedule import ScheduleRunner
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from localvault.vault import UnlockThrottled

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"


class Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, detail):
        self.events.append((name, detail))


class Sched:
    def __init__(self):
        self.calls = []

    def call_later(self, delay, fn):
        self.calls.append((delay, fn))
        return fn

    def cancel(self, handle):
        pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    marks = []
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: marks.append(("clear", pid)))
    monkeypatch.setattr("localvault.app.lockmodes.require_master_unlock", lambda pid: marks.append(("require", pid)) or True)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus, sched = Bus(), Sched()
    settings = AppSettings(idle_source="vault", scheduled_backup_frequency="daily", scheduled_backup_time="00:00")
    controller = WebController(profiles=profiles, settings=settings, bus=bus, scheduler=sched,
                               create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    return controller, bus, sched, marks


def _toasts(bus):
    return [d["message"] for n, d in bus.events if n == "toast"]


def test_schedule_skips_without_a_backup_password(env):
    controller, bus, _s, _m = env
    ran = []
    runner = ScheduleRunner(controller, bus, spawn=lambda fn: fn(), run_backup=lambda **kw: ran.append(kw))
    assert runner.check() is False and ran == []
    assert _toasts(bus) == ["Scheduled backup skipped: set a backup password first."]
    runner.check()
    assert len(_toasts(bus)) == 1


def test_schedule_runs_when_due_and_reports(env, monkeypatch):
    controller, bus, _s, _m = env
    monkeypatch.setattr(controller.session, "scheduled_backup_password", lambda: "backup-secret-pw", raising=False)
    seen = []

    def run_backup(**job):
        seen.append(job)
        return SimpleNamespace(path=None, mirrored=None, mirror_warning="")

    runner = ScheduleRunner(controller, bus, spawn=lambda fn: fn(), run_backup=run_backup)
    assert runner.check() is True
    assert seen[0]["password"] == "backup-secret-pw"
    assert _toasts(bus) == ["Scheduled backup saved."]
    assert "backup-secret-pw" not in repr(bus.events)


def test_schedule_failure_waits_before_retry(env, monkeypatch):
    controller, bus, _s, _m = env
    monkeypatch.setattr(controller.session, "scheduled_backup_password", lambda: "pw", raising=False)
    clock = [datetime(2026, 10, 17, 12, 0)]

    def boom(**job):
        raise OSError("disk")

    runner = ScheduleRunner(controller, bus, spawn=lambda fn: fn(), run_backup=boom, now=lambda: clock[0])
    assert runner.check() is True
    assert _toasts(bus)[-1] == "Scheduled backup failed; the previous backup was kept. See the error log."
    clock[0] += timedelta(minutes=10)
    assert runner.check() is False
    clock[0] += timedelta(minutes=25)
    assert runner.check() is True


def test_schedule_off_or_locked_does_nothing(env):
    controller, bus, _s, _m = env
    runner = ScheduleRunner(controller, bus, spawn=lambda fn: fn(), run_backup=lambda **kw: None)
    controller.lock()
    assert runner.check() is False
    controller.unlock(MASTER)
    controller.settings.scheduled_backup_frequency = "off"
    assert runner.check() is False


def test_unlock_schedules_a_check_after_three_seconds(env):
    controller, bus, sched, _m = env
    ScheduleRunner(controller, bus, spawn=lambda fn: fn(), run_backup=lambda **kw: None)
    controller.lock()
    sched.calls.clear()
    controller.unlock(MASTER)
    assert 3 in [delay for delay, _fn in sched.calls]


def test_emergency_lock_marks_master_required(env):
    controller, _b, _s, marks = env
    pid = controller.profiles.active_profile().id
    LockModes(controller).emergency_lock()
    assert not controller.is_unlocked() and ("require", pid) in marks
    assert controller.state()["status"] == ("Emergency lock. Master password required; signed-in websites/apps "
                                            "remain signed in.")


def test_lock_and_switch_asks_for_a_profile(env):
    controller, _b, _s, _m = env
    LockModes(controller).lock_and_switch()
    state = controller.state()
    assert state["choose_profile"] is True and state["status"].startswith("Handover:")
    controller.select_profile(controller.profiles.active_profile().id)
    state = controller.state()
    assert state["choose_profile"] is False
    assert state["status"] == "Profile selected; vault is locked. Websites/apps are not signed out by LocalGateKeys."


def test_locked_state_has_chips_subtitle_and_phrase(env):
    controller, _b, _s, _m = env
    controller.lock()
    state = controller.state()
    assert state["chips"][0]["active"] is True and state["chips"][0]["initial"]
    assert state["subtitle"].startswith("Locked ")
    assert state["recovery_phrase"] is False
    assert state["backoff"] == 0


def test_throttle_starts_the_backoff(env, monkeypatch):
    controller, _b, _s, _m = env
    controller.lock()

    def throttled(*a, **k):
        raise UnlockThrottled(30)

    monkeypatch.setattr("localvault.app.controller.unlock_vault", throttled)
    with pytest.raises(ApiError):
        controller.unlock("wrong")
    state = controller.state()
    assert 29 <= state["backoff"] <= 30
    assert state["backoff_message"].startswith("Too many incorrect attempts. Try again in ")


def test_locked_state_caches_file_reads(env, monkeypatch):
    controller, _b, _s, _m = env
    controller.lock()
    calls = []
    monkeypatch.setattr("localvault.app.controller.recovery_phrase_enrolled", lambda p: calls.append(p) or False)
    controller._extras_cache = None
    controller.state()
    controller.state()
    assert len(calls) == 1


def test_recover_throttle_starts_the_backoff(env, monkeypatch):
    controller, _b, _s, _m = env
    controller.lock()

    def throttled(*a, **k):
        raise UnlockThrottled(20)

    monkeypatch.setattr("localvault.app.recovery_center.recover_with_phrase", throttled)
    with pytest.raises(ApiError):
        controller.recover("x " * 24, "new password 12", "new password 12")
    assert controller.state()["backoff"] >= 19


def test_failed_lock_does_not_leave_handover(env, monkeypatch):
    controller, _b, _s, _m = env

    def boom(reason=""):
        raise RuntimeError("lock failed")

    monkeypatch.setattr(controller, "lock", boom)
    with pytest.raises(RuntimeError):
        LockModes(controller).lock_and_switch()
    assert controller.handover is False


def test_schedule_check_runs_once_when_called_concurrently(env, monkeypatch):
    import threading
    controller, bus, _s, _m = env
    monkeypatch.setattr(controller.session, "scheduled_backup_password", lambda: "pw", raising=False)
    started, release = [], threading.Event()
    runner = ScheduleRunner(controller, bus, spawn=lambda fn: threading.Thread(target=fn).start(),
                            run_backup=lambda **job: (started.append(1), release.wait(5),
                                                      SimpleNamespace(path=None, mirrored=None, mirror_warning=""))[-1])
    results = []
    threads = [threading.Thread(target=lambda: results.append(runner.check())) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    release.set()
    assert results.count(True) == 1
