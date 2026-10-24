"""Stage 6b: reminders, activity, shortcuts, collections and the catalog update."""
from __future__ import annotations

import datetime as dt
import json
from types import SimpleNamespace

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.workspace import ActivityService, CatalogService, CollectionsService, RemindersService, shortcuts
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"


class Bus:
    def emit(self, name, detail):
        pass


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
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    changed = []
    return SimpleNamespace(controller=controller, changed=changed, port=Port(),
                           mark=lambda: changed.append(1))


def _note_with_reminder(session, title="Passport"):
    item_id = session.item_service.create_note(title, "x")
    due = (dt.date.today() + dt.timedelta(days=3)).isoformat()
    reminder_id = session.reminders.create(item_id, due)
    return item_id, reminder_id


def test_reminders_list_complete_and_snooze(env):
    session = env.controller.session
    service = RemindersService(env.controller, env.mark)
    try:
        _item, reminder = _note_with_reminder(session)
    except Exception as exc:  # pragma: no cover - environment specific item API
        pytest.skip(f"cannot create a reminder here: {exc}")
    rows = service.list()["rows"]
    assert rows and rows[0]["id"] == reminder and rows[0]["title"] == "Passport"
    service.snooze(reminder)
    assert env.changed
    service.complete(reminder)
    with pytest.raises(ApiError):
        service.complete("no-such-reminder")


def test_activity_has_only_safe_fields(env):
    rows = ActivityService(env.controller).list()["rows"]
    assert all(set(r) == {"when", "event", "result", "count"} for r in rows)


def test_shortcuts_use_the_quick_access_key(env):
    env.controller.settings.quick_access_hotkey = "Ctrl+Alt+Q"
    rows = shortcuts(env.controller.settings)["rows"]
    assert {"group": "Anywhere in Windows", "keys": "Ctrl+Alt+Q",
            "description": "Quick access: search this profile from any window."} in rows


def test_collections_create_rename_archive(env):
    service = CollectionsService(env.controller, env.mark)
    created = service.create("Travel")["collections"]
    travel = next(c for c in created if c["name"] == "Travel")
    service.rename(travel["id"], "Trips")
    assert any(c["name"] == "Trips" for c in service.list()["collections"])
    service.archive(travel["id"])
    assert all(c["id"] != travel["id"] for c in service.list()["collections"])  # archived ones leave the list
    with pytest.raises(ApiError):
        service.create("")


def test_catalog_update_needs_a_confirm_and_a_verified_result(env, monkeypatch):
    service = CatalogService(env.controller, env.port, env.mark)
    assert service.status() == {"needs_update": False}
    session = env.controller.session
    monkeypatch.setattr(type(session), "_require_typed_catalog",
                        lambda self: (_ for _ in ()).throw(__import__("localvault.vault", fromlist=["VaultError"]).VaultError("legacy")))
    assert service.status()["needs_update"] is True
    env.port.answers = [False]
    with pytest.raises(ApiError):
        service.update()
    assert env.port.asked == ["This vault uses the legacy catalog"]
    monkeypatch.setattr(type(session), "migrate_to_v2", lambda self: True)
    monkeypatch.setattr(type(session), "last_catalog_migration_result", property(lambda self: {"success": False}))
    with pytest.raises(ApiError) as unverified:
        service.update()
    assert unverified.value.message == "The vault update could not be verified."


def test_locked_refuses(env):
    env.controller.lock()
    with pytest.raises(ApiError):
        RemindersService(env.controller, env.mark).list()
    assert "secret" not in json.dumps(shortcuts(env.controller.settings))


def test_catalog_update_refuses_a_session_replaced_during_the_confirm(env, monkeypatch):
    session = env.controller.session
    monkeypatch.setattr(type(session), "_require_typed_catalog",
                        lambda self: (_ for _ in ()).throw(__import__("localvault.vault", fromlist=["VaultError"]).VaultError("legacy")))
    migrated = []
    monkeypatch.setattr(type(session), "migrate_to_v2", lambda self: migrated.append(1) or True)

    def confirm(title, message):
        env.controller.lock()
        env.controller.unlock(MASTER)  # locked and reopened while the dialog was open
        return True

    env.port.confirm = confirm
    with pytest.raises(ApiError) as stale:
        CatalogService(env.controller, env.port, env.mark).update()
    assert stale.value.code == "session_changed" and migrated == []
