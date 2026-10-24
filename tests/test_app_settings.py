"""Stage 5a: the Settings page model and applying preferences from the WebView UI."""
from __future__ import annotations

import json

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.settings import SettingsService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"


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
        self.asked, self.answers = [], []

    def confirm(self, title, message):
        self.asked.append(title)
        return self.answers.pop(0) if self.answers else True


@pytest.fixture
def env(tmp_path, monkeypatch):
    saved = []
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: saved.append(self))
    startup = []
    monkeypatch.setattr("localvault.app.settings.set_start_with_windows", lambda value: startup.append(value))
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    bus = Bus()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=bus,
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    port = Port()
    return SettingsService(controller, port, bus), controller, port, bus, saved, startup


def test_page_has_every_section_in_classic_order(env):
    service, *_ = env
    page = service.page()
    assert [s["key"] for s in page["sections"]] == ["locking", "unlocking", "privacy", "autofill", "appearance",
                                                    "backups", "plan", "help"]
    locking = page["sections"][0]
    first = locking["rows"][0]
    assert first["type"] == "choice" and first["key"] == "auto_lock_seconds"
    assert first["title"] == "Lock after inactivity"
    assert {"label": "15 minutes", "value": 900} in first["options"]


def test_buttons_are_routes_not_commands(env):
    service, *_ = env
    rows = [r for s in service.page()["sections"] for r in s["rows"] if r["type"] == "button"]
    routes = {r["title"]: r["route"] for r in rows}
    assert routes["Master password"] == "master"
    assert routes["Updates"] == "updates"
    assert routes["Backup password"] == "backup_password"
    assert routes["Licence"] == "licence"
    assert routes["Devices & connections"] == "connections"
    assert "<function" not in json.dumps(rows)


def test_apply_validates_and_saves(env):
    service, controller, _port, _bus, saved, _ = env
    result = service.apply("clipboard_clear_seconds", 15)
    assert controller.settings.clipboard_clear_seconds == 15 and saved
    assert controller.clipboard.timeout_seconds == 15
    assert result["message"] == "Settings saved."
    saved.clear()
    with pytest.raises(ApiError):
        service.apply("clipboard_clear_seconds", "15")
    with pytest.raises(ApiError):
        service.apply("not_a_setting", True)
    assert saved == []


def test_sign_in_after_filling_needs_a_confirm(env):
    service, controller, port, _bus, saved, _ = env
    port.answers = [False]
    with pytest.raises(ApiError) as declined:
        service.apply("fill_and_sign_in", True)
    assert declined.value.code == "cancelled" and port.asked == ["Enable Fill & sign in?"]
    assert controller.settings.fill_and_sign_in is False and saved == []
    service.apply("fill_and_sign_in", True)
    assert controller.session.fill_and_sign_in_enabled() is True


def test_start_with_windows_and_appearance_side_effects(env):
    service, controller, _port, bus, _saved, startup = env
    service.apply("start_with_windows", True)
    assert startup == [True]
    target = "dark" if controller.settings.appearance != "dark" else "light"
    service.apply("appearance", target)
    assert ("appearance", {"appearance": target}) in bus.events


def test_backup_password_set_and_clear(env):
    service, controller, port, _bus, _saved, _ = env
    with pytest.raises(ApiError) as short:
        service.backup_password("short", "short")
    assert short.value.message == "The backup password must contain at least 12 characters."
    with pytest.raises(ApiError) as mismatch:
        service.backup_password("long enough pw 1", "long enough pw 2")
    assert mismatch.value.message == "The backup passwords do not match."
    assert service.backup_password("long enough pw 1", "long enough pw 1")["message"] == \
        "Backup password saved inside the encrypted vault."
    assert controller.session.has_scheduled_backup_password()
    page = json.dumps(service.page())
    assert "long enough pw 1" not in page
    assert service.clear_backup_password()["message"] == "Backup password cleared. Scheduled backups are off."
    assert port.asked == ["Clear backup password?"]
    assert not controller.session.has_scheduled_backup_password()


def test_a_failed_save_is_an_error_not_a_crash(env, monkeypatch):
    service, controller, *_ = env

    def boom(self, path=None):
        raise OSError("disk full")

    monkeypatch.setattr(AppSettings, "save", boom)
    with pytest.raises(ApiError) as failed:
        service.apply("clipboard_clear_seconds", 15)
    assert failed.value.message == "The setting could not be saved."
    assert controller.settings.clipboard_clear_seconds != 15
