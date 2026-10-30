"""Stage 3: Recently deleted (trash) in the WebView UI."""
from __future__ import annotations

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.trash import TrashService
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
        self.asked, self.answers, self.upgrades = [], [], []

    def confirm(self, title, message):
        self.asked.append((title, message))
        return self.answers.pop(0) if self.answers else True

    def notify(self, kind, title, message):
        self.asked.append((title, message))

    def show_upgrade(self, *, limit, message, on_enter):
        self.upgrades.append(limit)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    session = controller.session
    login = session.create_web_login(urls=[{"url": "https://a.test", "match": "exact_origin"}], username="ann",
                                     password="pw-alpha-1234567", label="Alpha")
    note = session.item_service.create_note("Router", "codes")
    session.delete(login)
    session.item_service.delete_item(note)
    port = Port()
    return TrashService(controller, port), controller, port, login, note


def test_list_both_sources_and_retention_text(env):
    service, controller, _port, login, note = env
    listed = service.list()
    rows = {r["id"]: r for r in listed["rows"]}
    assert rows[login]["source"] == "credential" and rows[login]["kind_label"] == "Login"
    assert rows[note]["source"] == "typed" and rows[note]["kind_label"] == "Note"
    assert listed["retention_text"] == ("Entries stay encrypted for 30 days. Expired entries are purged on the next "
                                        "vault write. Older backups may retain copies.")
    controller.settings.trash_auto_purge = False
    assert service.list()["retention_text"].startswith("Automatic emptying is off")


def test_restore_both(env):
    service, controller, _port, login, note = env
    result = service.restore([login, note])
    assert result == {"message": "Restored 2 items.", "failed": []}
    assert service.list()["rows"] == []


def test_restore_stops_at_the_item_limit(env):
    service, controller, port, login, note = env
    controller.session.item_limit = 0
    result = service.restore([login, note])
    assert port.upgrades == [0] and "Restored 0 items." in result["message"]
    assert len(service.list()["rows"]) == 2


def test_purge_confirm_texts_and_cancel(env):
    service, _controller, port, login, note = env
    port.answers = [False]
    with pytest.raises(ApiError) as cancelled:
        service.purge([login])
    assert cancelled.value.code == "cancelled"
    assert port.asked[-1] == ("Permanently delete?",
                              "Permanently delete 'Alpha'? This cannot be undone. Previous backups can still contain it.")
    port.answers = [True]
    assert service.purge([login, note]) == {"message": "Permanently deleted 2 items."}
    assert port.asked[-1][1] == ("Permanently delete 2 items? This cannot be undone. Previous backups can still "
                                 "contain them.")
    assert service.list()["rows"] == []


def test_empty_trash(env):
    service, _controller, port, _login, _note = env
    port.answers = [True]
    assert service.empty() == {"message": "Permanently deleted 2 items."}


def test_unknown_ids_are_ignored(env):
    service, _controller, _port, _login, _note = env
    assert service.restore(["nope"])["message"] == "Restored 0 items."
