"""Sub-plan 12 page layer: restore test, change-password page, health report, estate pack, weekly switch."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from localvault import restore_test
from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.power_user import PowerUserService
from localvault.backup import export_encrypted_backup
from localvault.profiles import ProfileManager
from localvault.secret_text import SecretText
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
CHEAP = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
MASTER = "correct horse battery"
NOW = 1_800_000_000


class Bus:
    def emit(self, name, detail):
        pass


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


class Dialogs:
    def __init__(self, path):
        self.path = path
        self.calls = []

    def open_file(self, title, file_types=None):
        self.calls.append(file_types)
        return self.path

    def save_file(self, title, name):
        return self.path


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    entry = controller.session.create_web_login(urls=[{"url": "https://github.com", "match": "exact_origin"}],
                                                username="ann", password="pw-123456789012", label="GitHub")
    opened = []
    dialogs = Dialogs(tmp_path / "out.pdf")
    service = PowerUserService(controller, SimpleNamespace(), dialogs, clock=lambda: NOW, open_url=opened.append)
    return SimpleNamespace(controller=controller, profiles=profiles, service=service, dialogs=dialogs,
                           opened=opened, entry=entry, tmp=tmp_path)


def test_restore_status_starts_due_and_a_run_records_the_result(env):
    status = env.service.restore_status()
    assert status["due"] is True and status["ok"] is False
    profile = env.profiles.active_profile()
    backup = env.tmp / "b.lgk"
    export_encrypted_backup(backup, vault_file=env.profiles.vault_path(profile.id), settings_file=None,
                            profile_name="P", backup_password=MASTER, kdf_overrides=CHEAP)
    env.dialogs.path = backup
    picked = env.service.restore_pick()
    assert picked["name"] == "b.lgk" and "*.lgk" in env.dialogs.calls[-1][0]
    result = env.service.restore_run(picked["path"], SecretText.from_str(MASTER))
    assert result["passed"] is True and result["due"] is False
    wrong = env.service.restore_run(picked["path"], SecretText.from_str("not the password 01"))
    assert wrong["passed"] is False


def test_restore_run_refuses_other_files(env):
    other = env.tmp / "notes.txt"
    other.write_text("x", encoding="utf-8")
    with pytest.raises(ApiError):
        env.service.restore_run(str(other), SecretText.from_str(MASTER))


def test_change_password_opens_a_page(env):
    result = env.service.change_password_open(env.entry)
    assert env.opened == [result["url"]] and result["url"].startswith("https://github.com/")


def test_health_report_is_saved(env):
    result = env.service.health_print("letter")
    data = (env.tmp / "out.pdf").read_bytes()
    assert data.startswith(b"%PDF") and result["path"].endswith("out.pdf")
    assert b"pw-123456789012" not in data


def test_estate_pack_creates_a_note(env):
    before = env.controller.session.live_item_count()
    result = env.service.estate_create()
    assert result["id"] and env.controller.session.live_item_count() == before + 1


def test_locked_vault_is_refused(env):
    env.controller.lock("test")
    with pytest.raises(ApiError) as exc:
        env.service.restore_status()
    assert exc.value.code == "locked"


def test_weekly_setting_is_optional_when_reading(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{}", encoding="utf-8")
    assert AppSettings.load(path).restore_test_weekly is True
    settings = AppSettings.load(path)
    settings.restore_test_weekly = False
    settings.save(path)
    assert AppSettings.load(path).restore_test_weekly is False


def test_unlock_runs_the_weekly_test_on_rolling_backups(env):
    env.controller.settings.automatic_backup_count = 3
    profile = env.profiles.active_profile()
    state = restore_test.state_path(env.profiles.profile_dir(profile.id))
    env.controller.lock("test")
    env.controller.unlock(MASTER)
    env.controller.session.create_web_login(urls=[{"url": "https://b.test", "match": "exact_origin"}],
                                            username="bo", password="pw-223456789012", label="Beta")
    env.controller.lock("test")
    env.controller.unlock(MASTER)
    last = restore_test.load(state)
    assert last is not None and last.ok


def test_a_verified_scheduled_backup_records_the_weekly_test(tmp_path):
    from datetime import datetime

    from localvault.app.schedule import ScheduleRunner

    profile = SimpleNamespace(id="p1")
    profiles = SimpleNamespace(active_profile=lambda: profile, profile_dir=lambda pid: tmp_path)
    settings = SimpleNamespace(restore_test_weekly=True)
    controller = SimpleNamespace(settings=settings, profiles=profiles, on_unlock=[], on_lock=[])
    runner = ScheduleRunner(controller, Bus(), keys=SimpleNamespace(on_change=[]),
                            now=lambda: datetime.fromtimestamp(NOW))
    runner._record_restore_test(SimpleNamespace(path=tmp_path / "s.lgkfull"))
    last = restore_test.load(restore_test.state_path(tmp_path))
    assert last is not None and last.ok and last.tested_at == NOW
    settings.restore_test_weekly = False
    restore_test.state_path(tmp_path).unlink()
    runner._record_restore_test(SimpleNamespace(path=tmp_path / "s.lgkfull"))
    assert restore_test.load(restore_test.state_path(tmp_path)) is None
