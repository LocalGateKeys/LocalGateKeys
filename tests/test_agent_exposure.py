"""Exposure to AI agents: derived from the activity and run logs, shown in health and the item view (Stream D)."""
from __future__ import annotations

import json
import time

import pytest

from localvault import agent_exposure as ax
from localvault.agent_run_log import AgentRunLog
from localvault.app.controller import WebController
from localvault.app.health import HealthService
from localvault.app.home import HomeService
from localvault.backup import DEVICE_ONLY_SETTINGS, RESET_ON_RESTORE
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"
L1, L2, S1 = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", \
    "33333333-3333-4333-8333-333333333333"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))


def _ev(event_type, item_id, at, result="ok"):
    return {"event_type": event_type, "item_id": item_id, "timestamp": at, "result": result}


# ---------------------------------------------------------------- derivation
def test_password_fill_and_run_release_count_until_changed():
    events = [_ev("agent.fill", L1, 100), _ev("agent.fill", L2, 100), _ev("agent.read", S1, 200)]
    runs = [{"stage": "filled", "agent": "Claude Code", "at": 101, "items": [{"item_id": L1}]},
            {"stage": "released", "agent": "Cursor", "at": 199, "items": [{"item_id": S1, "field": "key"}]}]
    found = ax.exposures(events, runs, {L1: 0, L2: 150}, {S1: 50})
    assert set(found) == {L1, S1}  # L2's password changed after the fill
    assert found[L1] == ax.Exposure(L1, "login", 100, "Claude Code")
    assert found[S1].agent == "Cursor" and found[S1].kind == "secret"
    assert ax.exposures(events, runs, {L1: 0}, {S1: 201}).keys() == {L1}  # the secret item was saved since


def test_events_without_id_or_not_ok_never_count():
    events = [_ev("agent.fill", None, 100), _ev("agent.fill", L1, 100, "denied"), _ev("agent.request", L1, 100),
              _ev("agent.read", S1, 100, "not_found"), _ev("agent.complete", S1, 100)]
    assert ax.exposures(events, [], {L1: 0}, {S1: 0}) == {}


def test_kind_must_match_and_deleted_items_never_count():
    events = [_ev("agent.fill", S1, 100), _ev("agent.read", L1, 100), _ev("agent.fill", L2, 100)]
    assert ax.exposures(events, [], {L1: 0}, {S1: 0}) == {}


def test_agent_name_needs_a_nearby_run_row():
    runs = [{"stage": "filled", "agent": "Old", "at": 100 + ax.NAME_WINDOW + 1, "items": [{"item_id": L1}]},
            {"stage": "approved", "agent": "Approved only", "at": 100, "items": [{"item_id": L1}]}]
    assert ax.exposures([_ev("agent.fill", L1, 100)], runs, {L1: 0}, {})[L1].agent == ""


def test_dismissal_hides_until_a_later_release():
    dismissed = ax.dismiss(["x@1"], L1, 150)
    assert dismissed == ["x@1", f"{L1}@150"]
    assert ax.exposures([_ev("agent.fill", L1, 100)], [], {L1: 0}, {}, dismissed) == {}
    assert L1 in ax.exposures([_ev("agent.fill", L1, 160)], [], {L1: 0}, {}, dismissed)
    assert ax.dismiss(dismissed, L1, 170) == ["x@1", f"{L1}@170"]


def test_login_changed_at_reads_history_times_only():
    assert ax.login_changed_at({"password_history": [{"password": "p", "changed_at": 5}, {"changed_at": 9}]}) == 9
    assert ax.login_changed_at({}) == 0


# ---------------------------------------------------------------- settings and backup
def test_dismissals_are_device_only_and_reset_on_restore(tmp_path):
    assert "agent_exposure_dismissed" in DEVICE_ONLY_SETTINGS
    assert RESET_ON_RESTORE["agent_exposure_dismissed"] == []
    path = tmp_path / "settings.json"
    AppSettings(agent_exposure_dismissed=[f"{L1}@5", 7, "bad\n@1"]).save(path)
    assert AppSettings.load(path).agent_exposure_dismissed == [f"{L1}@5"]


# ---------------------------------------------------------------- health service
class _Bus:
    def emit(self, name, detail):
        pass


class _Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda _pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=_Bus(),
                               scheduler=_Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    session = controller.session
    login = session.create_web_login(urls=[{"url": "https://ok.test", "match": "exact_origin"}], username="b",
                                     password="Xq7!vR2#mP9$wL4@", label="Shop")
    secret_id = session.item_service.create_typed("api_key", "Stripe", {"service": "stripe", "key": "sk_live_x"})
    runs = AgentRunLog(None, crypto=False)
    health = HealthService(controller, None, HomeService(controller), _Bus(), check=lambda *a, **k: 0,
                           spawn=lambda fn: fn(), sleep=lambda s: None, run_log=runs)
    return {"controller": controller, "session": session, "login": login, "secret": secret_id, "runs": runs,
            "health": health}


def _expose(env, *, at=None):
    session = env["session"]
    kwargs = {} if at is None else {"timestamp": at}
    session.activity.record("agent.fill", result="ok", item_id=env["login"], **kwargs)
    session.activity.record("agent.read", result="ok", item_id=env["secret"], **kwargs)
    env["runs"].append({"stage": "filled", "agent": "Claude Code", "items": [{"item_id": env["login"]}]})
    env["runs"].append({"stage": "released", "agent": "Claude Code",
                        "items": [{"item_id": env["secret"], "field": "key", "variable": "K"}]})


def test_health_lists_exposed_logins_and_secrets_with_agent_and_date(env):
    assert env["health"].report("agent")["rows"] == []
    _expose(env)
    report = env["health"].report("agent")
    rows = {row["id"]: row for row in report["rows"]}
    assert set(rows) == {env["login"], env["secret"]}
    assert rows[env["login"]]["kind"] == "web" and rows[env["secret"]]["kind"] == "api_key"
    assert "Claude Code" in rows[env["login"]]["agent_exposure"]
    assert rows[env["secret"]]["label"] == "Stripe"
    assert any(f["key"] == "agent" for f in report["filters"])
    assert "sk_live_x" not in json.dumps(report) and "Xq7!" not in json.dumps(report)
    # The full list marks the login too, and the existing score is unchanged.
    full = {row["id"]: row for row in env["health"].report(None)["rows"]}
    assert full[env["login"]]["agent_exposure"] and env["secret"] not in full


def test_changing_the_password_clears_the_login(env):
    _expose(env, at=int(time.time()) - 10)
    env["session"].update_entry_fields(env["login"], password="An0ther!Strong#Pass")
    ids = {row["id"] for row in env["health"].report("agent")["rows"]}
    assert env["login"] not in ids


def test_item_notice_and_dismiss(env):
    health = env["health"]
    assert health.agent_exposure(env["login"]) == {"exposed": False}
    _expose(env)
    state = health.agent_exposure(env["login"])
    assert state["exposed"] is True and state["kind"] == "login" and "Claude Code" in state["text"]
    health.dismiss_agent_exposure(env["login"])
    assert health.agent_exposure(env["login"]) == {"exposed": False}
    assert env["controller"].settings.agent_exposure_dismissed[0].startswith(env["login"] + "@")
    assert health.agent_exposure(env["secret"])["exposed"] is True
