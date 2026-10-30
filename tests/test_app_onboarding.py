"""UX plan workstream 4: the five-step, skippable setup guide and its vault card."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from localvault.app.controller import WebController
from localvault.app.onboarding import OnboardingWebService
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


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    controller.create(MASTER, MASTER)
    recovery = SimpleNamespace(verified_backup=False)
    report = {"connection": {"status": "unavailable"}}
    phrase = {"enrolled": False}
    service = OnboardingWebService(controller, recovery, diagnostics=lambda: report,
                                   phrase_enrolled=lambda path: phrase["enrolled"])
    return SimpleNamespace(controller=controller, recovery=recovery, report=report, service=service, phrase=phrase)


def _setup_file(env):
    from pathlib import Path

    return Path(env.controller.session.path).parent / "setup.json"


def test_first_screen_lists_five_steps_with_the_vault_already_done(env):
    view = env.service.view()
    assert [s["key"] for s in view["steps"]] == ["vault", "unlock", "import", "phrase", "browser"]
    assert view["steps"][0]["state"] == "done" and view["current"] == "unlock"
    assert view["progress"] == "1 of 5" and view["card"] is True


def test_skip_all_leaves_the_card_with_every_step_left(env):
    view = env.service.skip_all()
    assert view["current"] is None and view["card"] is True and view["progress"] == "1 of 5"
    assert {s["state"] for s in view["steps"][1:]} == {"skipped"}
    assert env.service.card() == {"card": True, "progress": "1 of 5", "done": 1, "total": 5}


def test_each_step_routes_or_confirms(env):
    s = env.service
    assert s.perform("unlock")["open"] == {"route": "hello", "params": {"startHello": True}}
    s.skip("unlock")
    opened = s.perform("import")
    assert opened["open"] == {"route": "import"} and opened["steps"][2]["state"] == "done"
    phrase = s.perform("phrase")
    assert phrase["open"]["route"] == "recovery" and phrase["steps"][3]["state"] != "done"
    env.phrase["enrolled"] = True  # created and confirmed on the recovery page
    assert s.view()["steps"][3]["state"] == "done"
    blocked = s.perform("browser")
    assert "did not answer" in blocked["message"] and blocked["steps"][4]["state"] == "current"
    env.report["connection"]["status"] = "connected"
    assert s.perform("browser")["steps"][4]["state"] == "done"
    view = s.view()
    assert view["progress"] == "4 of 5" and view["card"] is True  # Windows Hello was skipped


def test_finishing_every_step_removes_the_card(env):
    s = env.service
    env.controller.offers["hello"] = lambda: True
    env.phrase["enrolled"] = True
    env.report["connection"]["status"] = "connected"
    s.perform("import")
    view = s.perform("browser")
    assert view["complete"] is True and view["card"] is False and view["progress"] == "5 of 5"


def test_hide_keeps_the_card_hidden_until_show_again(env):
    s = env.service
    s.skip_all()
    assert s.hide()["card"] is False
    assert s.card()["card"] is False
    again = s.show_again()
    assert again["card"] is True and again["current"] == "unlock"
    assert not any(step["state"] == "skipped" for step in again["steps"])


def test_progress_is_a_local_file_without_secrets(env):
    env.service.skip("unlock")
    data = json.loads(_setup_file(env).read_text(encoding="utf-8"))
    assert data == {"format": "localgatekeys-setup-v1", "done": ["vault"], "skipped": ["unlock"], "hidden": False}
    _setup_file(env).write_text("not json", encoding="utf-8")
    assert env.service.view()["current"] == "unlock"  # a damaged file only restarts the guide


def test_unknown_step_and_locked_vault_are_refused(env):
    from localvault.api.result import ApiError

    with pytest.raises(ApiError):
        env.service.perform("nope")
    env.controller.lock()
    with pytest.raises(ApiError):
        env.service.view()
