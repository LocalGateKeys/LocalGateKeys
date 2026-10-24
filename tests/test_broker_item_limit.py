"""Browser save on a full free vault: a structured ``item_limit`` reply, no silent failure."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from localvault.browser_broker import BrowserBroker
from broker_host import BrokerHostBase as RuntimeActions
from localvault.session_guard import SessionGuard
from localvault.settings import AppSettings
from localvault.vault import ItemLimitReached, create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
ORIGIN = "https://example.test"
LIMIT_REPLY = {"ok": False, "error": "item_limit", "limit": 4,
               "message": "Your free LocalGateKeys holds 4 items. Upgrade to Pro for unlimited."}


class _Broker(RuntimeActions, BrowserBroker):
    def __init__(self, session) -> None:
        self.session = session
        self.guard = SessionGuard("redacted-profile")
        self.guard.open(3600)
        self.root = None
        self.settings = AppSettings(auto_lock_seconds=0)
        self.active_profile = SimpleNamespace(id="redacted-profile", name="Redacted", color="#123456")
        self._remote_busy = False
        self.last_extension_seen = 0.0
        self.last_extension_version = ""
        self.last_secret_use = 0.0
        self._closing = False

    def ensure_unlocked(self):
        return self._session_available()

    def run_on_ui(self, function, timeout=0):
        return function()

    def refresh_entries(self):
        return None

    def _touch_secret(self):
        self.last_secret_use = 1.0

    def _validate_remote_text(self, value, *args):
        from localvault.web.host import WebAgentHost
        return WebAgentHost._validate_remote_text(value, *args)

    def request(self, action: str, **payload):
        if action in {"save_browser", "save_pending_browser"} and payload.pop("user_gesture", None) is True:
            # As the extension does: the click mints a broker gesture nonce first.
            payload["gesture_nonce"] = self.request("begin_gesture_browser", user_gesture=True)["gesture_nonce"]
        return self.dispatch_remote({
            "action": action, "protocol": 2, "extension_version": "0.3.3", "origin": ORIGIN,
            "context": json.dumps([17, "document-redacted", ORIGIN, "operation-redacted"]),
            **payload,
        })


@pytest.fixture
def full_vault(tmp_path):
    session = create_vault(tmp_path / "limit.json", "redacted-master", kdf_overrides=KDF)
    for i in range(4):
        session.upsert_web(origin=f"https://site{i}.test", username="u", password=f"pw-{i}")
    session.upsert_web(origin=ORIGIN, username="alice", password="old-pw")
    session.delete(session.find_web("https://site0.test")[0]["id"])  # trash never counts
    session.item_limit = 4
    assert session.live_item_count() == 4
    return session


@pytest.fixture
def confirms(monkeypatch):
    asked = []
    monkeypatch.setattr("broker_host.confirm", lambda *a: asked.append(a[1]) or True)
    return asked


def test_save_new_login_on_full_vault_returns_item_limit(full_vault, confirms):
    reply = _Broker(full_vault).request("save_browser", username="bob", password="pw-new", user_gesture=True)
    assert reply == LIMIT_REPLY
    assert confirms == []  # no desktop confirmation for a save that cannot happen
    assert all(e["username"] != "bob" for e in full_vault.find_web(ORIGIN))


def test_updating_existing_login_on_full_vault_succeeds(full_vault, confirms):
    reply = _Broker(full_vault).request("save_browser", username="alice", password="new-pw", user_gesture=True)
    assert reply == {"ok": True, "status": "updated"}
    assert full_vault.find_web(ORIGIN)[0]["password"] == "new-pw"


def test_save_pending_new_login_on_full_vault_returns_item_limit(full_vault, confirms):
    broker = _Broker(full_vault)
    captured = broker.request("capture_browser", username="carol", password="pw-pending")
    assert captured["ok"] and captured["stored"]
    reply = broker.request("save_pending_browser", pending_token=captured["pending_token"], user_gesture=True)
    assert reply == LIMIT_REPLY
    assert confirms == []


def test_limit_raised_by_vault_maps_to_item_limit_not_invalid_request(full_vault, confirms, monkeypatch):
    full_vault.item_limit = None  # pre-check passes; the vault itself refuses (race)

    def refuse(**_kwargs):
        raise ItemLimitReached(4, 4)

    monkeypatch.setattr(full_vault, "upsert_web", refuse)
    reply = _Broker(full_vault).request("save_browser", username="dave", password="pw", user_gesture=True)
    assert reply == LIMIT_REPLY


def test_save_under_limit_still_creates(full_vault, confirms):
    full_vault.item_limit = 5
    reply = _Broker(full_vault).request("save_browser", username="erin", password="pw", user_gesture=True)
    assert reply == {"ok": True, "status": "created"}


def test_a_save_made_elsewhere_during_the_prompt_is_reported_as_it_is(tmp_path, monkeypatch):
    session = create_vault(tmp_path / "race.json", "redacted-master", kdf_overrides=KDF)
    broker = _Broker(session)
    captured = broker.request("capture_browser", username="dana", password="pw-race")

    def confirm_while_another_tab_saves(_parent, title, message):
        session.upsert_web(origin=ORIGIN, username="dana", password="pw-race")  # the other request won
        return True
    monkeypatch.setattr("broker_host.confirm", confirm_while_another_tab_saves)
    reply = broker.request("save_pending_browser", pending_token=captured["pending_token"], user_gesture=True)
    assert reply == {"ok": True, "status": "existing"}
    assert len([e for e in session.find_web(ORIGIN) if e["username"] == "dana"]) == 1


def test_a_new_login_that_fills_the_vault_during_the_prompt_is_refused(full_vault, monkeypatch):
    full_vault.item_limit = 5  # one free slot when the save starts
    broker = _Broker(full_vault)
    captured = broker.request("capture_browser", username="erin", password="pw-last")

    def confirm_while_the_slot_is_taken(_parent, title, message):
        full_vault.upsert_web(origin="https://other.test", username="x", password="pw-x")
        return True
    monkeypatch.setattr("broker_host.confirm", confirm_while_the_slot_is_taken)
    reply = broker.request("save_pending_browser", pending_token=captured["pending_token"], user_gesture=True)
    assert reply["error"] == "item_limit"
    assert all(e["username"] != "erin" for e in full_vault.find_web(ORIGIN))
