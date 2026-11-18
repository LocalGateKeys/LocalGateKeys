"""Extension protocol additions (2026-11-15): edited username / chosen login on a pending save,
the popup's site login list, and timeout cancels with only the fields the worker forwards."""
from __future__ import annotations

import json

import pytest

from localvault.vault import create_vault
from test_broker_item_limit import KDF, ORIGIN, _Broker

CONTEXT = json.dumps([17, "document-redacted", ORIGIN, "operation-redacted"])


@pytest.fixture
def broker(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    return _Broker(create_vault(tmp_path / "popup.json", "redacted-master", kdf_overrides=KDF))


@pytest.fixture
def confirms(monkeypatch):
    asked = []
    monkeypatch.setattr("broker_host.confirm", lambda *a: asked.append(a) or True)
    return asked


def _capture(broker, username="ada", password="pw-new"):
    captured = broker.request("capture_browser", username=username, password=password)
    assert captured["ok"] and captured["stored"]
    return captured["pending_token"]


def test_edited_username_replaces_the_captured_one(broker, confirms):
    token = _capture(broker)
    reply = broker.request("save_pending_browser", pending_token=token, username="ada@example.test", user_gesture=True)
    assert reply == {"ok": True, "status": "created"}
    assert [e["username"] for e in broker.session.find_web(ORIGIN)] == ["ada@example.test"]
    assert "ada@example.test" in str(confirms[0])


@pytest.mark.parametrize("bad", ["x" * 513, "nul\0", 5])
def test_bad_username_is_refused_and_the_capture_kept(broker, confirms, bad):
    token = _capture(broker)
    reply = broker.request("save_pending_browser", pending_token=token, username=bad, user_gesture=True)
    assert reply == {"ok": False, "error": "invalid_credential"}
    assert broker.request("pending_browser")["pending"] is True


def test_entry_id_updates_that_login(broker, confirms):
    first = broker.session.upsert_web(origin=ORIGIN, username="old-name", password="pw-old")
    broker.session.upsert_web(origin=ORIGIN, username="other", password="pw-other")
    token = _capture(broker, username="new-name")
    reply = broker.request("save_pending_browser", pending_token=token, entry_id=first, user_gesture=True)
    assert reply == {"ok": True, "status": "updated", "entry_id": first}
    entry = broker.session.get_entry(first)
    assert entry["username"] == "new-name" and entry["password"] == "pw-new"
    assert len(broker.session.find_web(ORIGIN)) == 2  # nothing new was created
    assert broker.request("pending_browser")["pending"] is False


def test_entry_id_of_another_site_is_refused(broker, confirms):
    elsewhere = broker.session.upsert_web(origin="https://other.test", username="ada", password="pw")
    token = _capture(broker)
    reply = broker.request("save_pending_browser", pending_token=token, entry_id=elsewhere, user_gesture=True)
    assert reply == {"ok": False, "error": "entry_not_for_site"}
    assert confirms == []
    assert broker.session.get_entry(elsewhere)["password"] == "pw"
    assert broker.request("pending_browser")["pending"] is True


def test_unknown_or_malformed_entry_id(broker, confirms):
    token = _capture(broker)
    assert broker.request("save_pending_browser", pending_token=token, entry_id="nope",
                          user_gesture=True)["error"] == "entry_not_for_site"
    assert broker.request("save_pending_browser", pending_token=token, entry_id="x" * 129,
                          user_gesture=True)["error"] == "invalid_entry_id"


def test_entry_id_save_still_needs_token_and_nonce(broker, confirms):
    first = broker.session.upsert_web(origin=ORIGIN, username="a", password="pw-old")
    token = _capture(broker)
    assert broker.request("save_pending_browser", pending_token="wrong", entry_id=first,
                          user_gesture=True)["error"] == "session_changed"
    no_nonce = broker.request("save_pending_browser", pending_token=token, entry_id=first)
    assert no_nonce["ok"] is False
    assert broker.session.get_entry(first)["password"] == "pw-old"


def test_declined_confirmation_changes_nothing(broker, monkeypatch):
    monkeypatch.setattr("broker_host.confirm", lambda *a: False)
    first = broker.session.upsert_web(origin=ORIGIN, username="a", password="pw-old")
    token = _capture(broker)
    reply = broker.request("save_pending_browser", pending_token=token, entry_id=first, user_gesture=True)
    assert reply == {"ok": False, "error": "user_cancelled"}
    assert broker.session.get_entry(first)["password"] == "pw-old"


def test_site_logins_lists_titles_and_usernames_only(broker):
    broker.session.upsert_web(origin=ORIGIN, username="ada", password="secret-1")
    broker.session.upsert_web(origin="https://other.test", username="bob", password="secret-2")
    reply = broker.request("site_logins_browser")
    assert reply["ok"] is True
    assert [row["username"] for row in reply["logins"]] == ["ada"]
    assert set(reply["logins"][0]) == {"entry_id", "title", "username"}
    assert "secret-1" not in json.dumps(reply)


def test_site_logins_capped_at_twenty(broker):
    broker.session.item_limit = None
    for number in range(25):
        broker.session.upsert_web(origin=ORIGIN, username=f"user{number}", password=f"pw{number}")
    assert len(broker.request("site_logins_browser")["logins"]) == 20


def test_site_logins_locked_never_prompts(broker):
    broker.session.lock()
    assert broker.request("site_logins_browser") == {"ok": False, "error": "locked"}


def test_site_logins_needs_protocol_and_context(broker):
    assert broker.dispatch_remote({"action": "site_logins_browser", "protocol": 1, "origin": ORIGIN,
                                   "context": CONTEXT})["error"] == "version_mismatch"
    assert broker.dispatch_remote({"action": "site_logins_browser", "protocol": 2, "origin": ORIGIN,
                                   "context": "short"})["error"] == "invalid_request"


def _timeout_cancel(broker, action, **extra):
    # Exactly what background.js forwards on a timeout: origin/context/session_id/grant (+ passkey_protocol).
    return broker.dispatch_remote({"action": action, "origin": ORIGIN, "context": CONTEXT, "protocol": 2,
                                   "extension_version": "0.4.9", **extra})


@pytest.mark.parametrize("action", ["cancel_browser", "cancel_identity_browser", "cancel_card_browser"])
def test_timeout_cancels_are_accepted(broker, action):
    assert _timeout_cancel(broker, action, session_id="s" * 32, grant="g" * 32) == {"ok": True}
    assert _timeout_cancel(broker, action) == {"ok": True}


def test_timeout_passkey_discard_is_accepted(broker):
    reply = _timeout_cancel(broker, "passkey_discard_browser", passkey_protocol=1)
    assert reply.get("error") not in {"version_mismatch", "invalid_request", "unsupported_action"}


def test_get_browser_refuses_an_entry_id_of_another_site(broker):
    broker.session.upsert_web(origin=ORIGIN, username="ada", password="pw-here")
    elsewhere = broker.session.upsert_web(origin="https://other.test", username="bob", password="pw-there")
    start = broker.request("begin_browser", user_gesture=True)
    assert start["ok"]
    reply = broker.request("get_browser", grant=start["grant"], entry_id=elsewhere,
                           gesture_nonce=start["gesture_nonce"])
    assert reply["ok"] is False and "pw-there" not in json.dumps(reply)


def test_passkey_hint_reports_directory_and_vault(broker, monkeypatch):
    from localvault import site_features

    monkeypatch.setattr(site_features, "load", lambda: site_features.SiteFeatures({"example.test": ["passkey"]}))
    monkeypatch.setattr(site_features, "passkey_domains", lambda session: frozenset())
    assert broker.request("passkey_hint_browser") == {"ok": True, "supported": True, "has_passkey": False}
    monkeypatch.setattr(site_features, "passkey_domains", lambda session: frozenset({"example.test"}))
    assert broker.request("passkey_hint_browser")["has_passkey"] is True
    monkeypatch.setattr(site_features, "load", lambda: site_features.SiteFeatures({}))
    assert broker.request("passkey_hint_browser")["supported"] is False


def test_passkey_hint_locked_never_prompts(broker):
    broker.session.lock()
    assert broker.request("passkey_hint_browser") == {"ok": False, "error": "locked"}


def test_unknown_action_still_gets_the_normal_error(broker):
    reply = broker.request("no_such_browser")
    assert reply["ok"] is False
