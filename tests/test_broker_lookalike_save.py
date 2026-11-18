"""Review R1: a save on a lookalike site is classified in the app after unlock, never written silently.

A capture made while the vault is locked gets no verdict in the page (the app answers
"locked"), so the extension shows the deferred save prompt with no guard. When the user
clicks Save the app unlocks, then classifies the save origin: a lookalike is refused with
the verdict until the extension has asked the guard question (``lookalike_confirmed``),
and even then the trusted desktop confirmation names the site it imitates.
"""
from __future__ import annotations

import json

import pytest
from test_broker_item_limit import KDF, _Broker

from localvault.vault import create_vault

SAVED = "https://example.com"
LOOKALIKE = "https://examp1e.com"


class _LockableBroker(_Broker):
    """Starts locked; ensure_unlocked() stands in for the user unlocking in the app."""

    def __init__(self, session) -> None:
        super().__init__(session)
        self.locked = True
        self.unlocks = 0

    def _session_available(self) -> bool:
        return not self.locked and super()._session_available()

    def ensure_unlocked(self):
        self.unlocks += 1
        self.locked = False
        return self._session_available()


def _request(broker, action, origin, **payload):
    if action in {"save_browser", "save_pending_browser"}:
        payload["gesture_nonce"] = _request(broker, "begin_gesture_browser", origin, user_gesture=True)["gesture_nonce"]
        payload["user_gesture"] = True
    return broker.dispatch_remote({
        "action": action, "protocol": 2, "extension_version": "0.4.12", "origin": origin,
        "context": json.dumps([17, "document-redacted", origin, "operation-redacted"]), **payload,
    })


@pytest.fixture
def broker(tmp_path):
    session = create_vault(tmp_path / "lookalike-save.json", "redacted-master", kdf_overrides=KDF)
    session.upsert_web(origin=SAVED, username="alice", password="real-pw")
    session.upsert_web(origin="https://www.amazon.com", username="alice", password="shop-pw")
    return _LockableBroker(session)


class _Asked(list):
    answer: dict


@pytest.fixture
def confirms(monkeypatch):
    asked = _Asked()
    answer = {"value": True}
    monkeypatch.setattr("broker_host.confirm", lambda *a: asked.append(a) or answer["value"])
    asked.answer = answer
    return asked


def _locked_capture(broker, origin=LOOKALIKE):
    captured = _request(broker, "capture_browser", origin, username="alice", password="phished-pw")
    assert captured["ok"] and captured["stored"] and captured["status"] == "deferred"
    assert broker.unlocks == 0, "capturing never unlocks"
    return captured["pending_token"]


def _web_origins(broker):
    return sorted({s.scope.get("origin") for s in broker.session.summaries() if s.kind == "web"})


def test_deferred_save_on_a_lookalike_is_refused_with_the_verdict_after_unlock(broker, confirms):
    token = _locked_capture(broker)
    reply = _request(broker, "save_pending_browser", LOOKALIKE, pending_token=token)
    assert broker.unlocks == 1
    assert reply == {"ok": False, "error": "lookalike_site", "kind": "lookalike", "reason": "edit-distance",
                     "matched": "example.com"}
    assert confirms == [], "no save dialog before the guard question"
    assert _web_origins(broker) == ["https://example.com", "https://www.amazon.com"], "nothing written"
    # The capture is kept for the retry after the guard.
    assert _request(broker, "pending_browser", LOOKALIKE)["pending"] is True


def test_confirmed_retry_still_warns_in_the_desktop_dialog(broker, confirms):
    token = _locked_capture(broker)
    _request(broker, "save_pending_browser", LOOKALIKE, pending_token=token)
    reply = _request(broker, "save_pending_browser", LOOKALIKE, pending_token=token, lookalike_confirmed=True)
    assert reply == {"ok": True, "status": "created"}
    title, message = confirms[0][1], confirms[0][2]
    assert "lookalike" in title.lower()
    assert "looks like example.com" in message and LOOKALIKE in message


def test_confirmed_retry_can_still_be_cancelled_in_the_app(broker, confirms):
    token = _locked_capture(broker)
    confirms.answer["value"] = False
    reply = _request(broker, "save_pending_browser", LOOKALIKE, pending_token=token, lookalike_confirmed=True)
    assert reply == {"ok": False, "error": "user_cancelled"}
    assert LOOKALIKE not in _web_origins(broker)


def test_manual_save_on_a_lookalike_is_refused_then_warned(broker, confirms):
    broker.locked = False
    refused = _request(broker, "save_browser", LOOKALIKE, username="alice", password="phished-pw")
    assert refused["error"] == "lookalike_site" and refused["matched"] == "example.com"
    assert confirms == []
    saved = _request(broker, "save_browser", LOOKALIKE, username="alice", password="phished-pw", lookalike_confirmed=True)
    assert saved["ok"]
    assert "looks like example.com" in confirms[0][2]


def test_other_suffix_refusal_carries_the_pair_id(broker, confirms):
    token = _locked_capture(broker, "https://www.amazon.de")
    reply = _request(broker, "save_pending_browser", "https://www.amazon.de", pending_token=token)
    assert reply["error"] == "lookalike_site" and reply["reason"] == "other-suffix"
    assert reply["matched"] == "www.amazon.com" and len(reply["pair"]) == 32


def test_mixed_script_confirmed_save_still_warns(broker, confirms):
    origin = "https://xn--bnk-6cd.test"
    token = _locked_capture(broker, origin)
    assert _request(broker, "save_pending_browser", origin, pending_token=token)["reason"] == "mixed-script"
    assert _request(broker, "save_pending_browser", origin, pending_token=token, lookalike_confirmed=True)["ok"]
    text = confirms[0][2]
    assert f"Warning: {origin} mixes letters from different alphabets, a common phishing trick." in text
    assert "which you saved" not in text and "looks like" not in text


def test_ordinary_sites_save_as_before(broker, confirms):
    token = _locked_capture(broker, "https://new.test")
    reply = _request(broker, "save_pending_browser", "https://new.test", pending_token=token)
    assert reply == {"ok": True, "status": "created"}
    assert confirms[0][1] == "Save new login?"
    assert "looks like" not in confirms[0][2]
