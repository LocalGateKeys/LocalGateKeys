"""Stage 6b: the Getting started guide for the WebView UI."""
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
    service = OnboardingWebService(controller, recovery, diagnostics=lambda: report)
    return SimpleNamespace(controller=controller, recovery=recovery, report=report, service=service)


def test_walks_every_stage_with_the_classic_rules(env):
    s = env.service
    assert s.view()["heading"] == "Stage 1 of 7 · Welcome"
    s.perform(False)
    assert env.controller.settings.strict_offline_mode is False
    assert s.perform()["open"] == {"route": "security"}
    assert "open" not in s.perform(False)  # demo declined
    blocked = s.perform()
    assert blocked["stage"] == "bridge_diagnostic"
    assert blocked["status"] == "Connection unavailable. Retry or open Connections for help."
    env.report["connection"]["status"] = "connected"
    first = s.perform()
    assert first["stage"] == "first_item"
    opened = s.perform()
    assert opened["open"] == {"route": "new-item"} and opened["primary"] == "Confirm saved item"
    assert s.perform()["status"] == "No saved item yet. Save one in Add item, then confirm below."
    env.controller.session.item_service.create_note("First", "x")
    backup = s.perform()
    assert backup["stage"] == "backup"
    assert s.perform()["open"] == {"route": "recovery", "params": {"initial": "verify"}}
    env.recovery.verified_backup = True
    done = s.perform()
    assert done["stage"] == "complete"
    assert s.perform()["done"] is True


def test_skip_keeps_the_stage_skipped(env):
    s = env.service
    view = s.skip()
    assert view["stage"] == "security"
    assert next(st for st in view["stages"] if st["key"] == "welcome")["state"] == "skipped"


def test_progress_is_saved_without_secrets(env):
    env.service.perform(True)
    path = env.controller.profiles.vault_path(env.controller.profiles.active_profile().id).parent / "onboarding.json"
    text = path.read_text(encoding="utf-8")
    assert "security" in json.loads(text)["profiles"][env.controller.profiles.active_profile().id]["stage"]
    assert MASTER not in text


def test_offline_choice_goes_through_settings(env):
    applied = []
    env.service._apply_setting = lambda key, value: applied.append((key, value))
    env.service.perform(False)
    assert applied == [("strict_offline_mode", False)]


def test_connection_test_is_separate_from_perform(env):
    s = env.service
    for _ in range(3):
        s.perform(True if s.view()["stage"] == "welcome" else False)
    assert s.view()["stage"] == "bridge_diagnostic"
    env.report["connection"]["status"] = "connected"
    calls = []
    s._diagnostics = lambda: calls.append(1) or env.report
    s.test_connection()
    assert calls == [1]
    view = s.perform()
    assert view["stage"] == "first_item" and calls == [1]  # perform used the stored result


def test_skip_is_saved_once_and_stays_skipped(env, monkeypatch):
    s = env.service
    s.view()
    saves = []
    flow = s._flow
    original = flow._save
    monkeypatch.setattr(flow, "_save", lambda: saves.append(1) or original())
    view = s.skip()
    assert len(saves) == 1 and view["stage"] == "security"
    assert next(st for st in view["stages"] if st["key"] == "welcome")["state"] == "skipped"
