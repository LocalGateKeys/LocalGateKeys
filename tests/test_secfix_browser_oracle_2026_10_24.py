"""Security round 3 (2026-10-24): the save prompt is no password-guessing oracle.

Audit M-3 / review R-5: for a captured login the broker answers only ``new``
or ``exists`` (the Safari model), never whether the password matches; the
comparison runs only in the desktop app after the Save click. CodeQL: the
extension's ``session_id`` is compared with ``hmac.compare_digest`` and an
empty or missing value never passes a check a real one would fail.
"""
from __future__ import annotations

import json
from types import SimpleNamespace as NS

import pytest

from localvault.browser_broker import BrowserBroker
from localvault.vault import create_vault
from test_phase2c_identity_broker import _Broker as CardBroker
from test_phase2c_identity_broker import _card_session
from test_security_audit_ipc import KDF, MASTER, SITE, _Broker

RIGHT, WRONG = "pw-right-guess", "pw-wrong-guess"


@pytest.fixture
def session(tmp_path):
    s = create_vault(tmp_path / "oracle.json", MASTER, kdf_overrides=KDF)
    s.upsert_web(origin=SITE, username="alice", password=RIGHT)
    yield s
    if s.is_unlocked:
        s.lock()


@pytest.fixture
def prompts(monkeypatch):
    asked: list[tuple[str, str]] = []
    told: list[tuple[str, str]] = []
    monkeypatch.setattr("broker_host.confirm", lambda _p, title, message: asked.append((title, message)) or True)
    monkeypatch.setattr("broker_host.show_info", lambda _p, title, message: told.append((title, message)))
    return NS(asked=asked, told=told)


def _shape(reply: dict) -> dict:
    """The reply with the random pending token replaced; everything a page could ever see."""
    out = dict(reply)
    for key in ("pending_token", "token"):
        if key in out:
            assert isinstance(out[key], str) and out[key]
            out[key] = "<token>"
    return out


def test_capture_replies_identically_for_a_right_and_a_wrong_password(session):
    right = _Broker(session).request("capture_browser", username="alice", password=RIGHT)
    wrong = _Broker(session).request("capture_browser", username="alice", password=WRONG)
    assert _shape(right) == _shape(wrong) == {"ok": True, "stored": True, "pending_token": "<token>",
                                               "token": "<token>", "status": "exists"}
    new = _Broker(session).request("capture_browser", username="bob", password=RIGHT)
    assert new["stored"] and new["status"] == "new"


def test_pending_replies_identically_for_a_right_and_a_wrong_password(session):
    replies = []
    for password in (RIGHT, WRONG):
        broker = _Broker(session)
        broker.request("capture_browser", username="alice", password=password)
        reply = broker.request("pending_browser")
        reply.pop("age_ms")
        replies.append(_shape(reply))
    assert replies[0] == replies[1]
    assert replies[0]["status"] == "exists" and "match" not in replies[0]


def test_check_replies_identically_for_a_right_and_a_wrong_password(session):
    right = _Broker(session).request("check_browser", username="alice", password=RIGHT)
    wrong = _Broker(session).request("check_browser", username="alice", password=WRONG)
    assert right == wrong == {"ok": True, "locked": False, "match": False, "status": "exists", "prompt": True}
    assert _Broker(session).request("check_browser", username="bob", password=RIGHT)["status"] == "new"


def test_save_prompts_policy_still_suppresses_without_revealing_the_password(session):
    session.create_web_login(urls=[{"url": SITE, "match": "exact_origin"}], username="quiet", password=RIGHT,
                             policy={"fill": "ask", "sign_in": False, "require_master_password": False,
                                     "save_prompts": False})
    right = _Broker(session).request("capture_browser", username="quiet", password=RIGHT)
    wrong = _Broker(session).request("capture_browser", username="quiet", password=WRONG)
    assert right == wrong == {"ok": True, "stored": False, "status": "exists"}


def test_the_comparison_happens_in_the_desktop_app_after_the_click(session, prompts):
    # Unchanged password: the app says "already saved" in its own window and writes nothing.
    broker = _Broker(session)
    token = broker.request("capture_browser", username="alice", password=RIGHT)["pending_token"]
    before = session.find_web(SITE)[0]["updated_at"] if "updated_at" in session.find_web(SITE)[0] else None
    same = broker.request("save_pending_browser", pending_token=token, gesture_nonce=broker.nonce())
    assert same == {"ok": True, "status": "existing"}
    assert prompts.asked == []
    assert [t for t, _ in prompts.told] == ["Already saved"]
    assert "alice" in prompts.told[0][1] and RIGHT not in prompts.told[0][1]
    assert len(session.find_web(SITE)) == 1
    if before is not None:
        assert session.find_web(SITE)[0]["updated_at"] == before
    # Changed password: the desktop asks "Update password?" and replaces it.
    token = broker.request("capture_browser", username="alice", password=WRONG)["pending_token"]
    changed = broker.request("save_pending_browser", pending_token=token, gesture_nonce=broker.nonce())
    assert changed == {"ok": True, "status": "updated"}
    assert [t for t, _ in prompts.asked] == ["Update password?"]
    assert session.find_web(SITE)[0]["password"] == WRONG


def test_manual_save_of_an_unchanged_login_is_reported_in_the_app(session, prompts):
    broker = _Broker(session)
    reply = broker.request("save_browser", username="alice", password=RIGHT, gesture_nonce=broker.nonce())
    assert reply == {"ok": True, "status": "existing"}
    assert prompts.asked == [] and [t for t, _ in prompts.told] == ["Already saved"]


# ---- session_id checks (CodeQL) ------------------------------------------------

class _Lease(NS):
    pass


@pytest.mark.parametrize("supplied", [None, "", 0, b"tok", ["tok"], "tok-other", "tok "])
def test_session_id_mismatch_or_missing_never_matches(supplied):
    assert BrowserBroker._session_id_matches(supplied, _Lease(token="tok")) is False


def test_session_id_matches_only_the_lease_token():
    assert BrowserBroker._session_id_matches("tok", _Lease(token="tok")) is True
    assert BrowserBroker._session_id_matches("", _Lease(token="")) is False


def test_session_id_compare_is_constant_time(monkeypatch):
    calls = []
    import localvault.browser_broker as module
    real = module.hmac.compare_digest
    monkeypatch.setattr(module.hmac, "compare_digest", lambda a, b: calls.append((a, b)) or real(a, b))
    assert BrowserBroker._session_id_matches("tok", _Lease(token="tok"))
    assert calls == [(b"tok", b"tok")]


@pytest.mark.parametrize("session_id", ["", "wrong-session", None])
def test_card_approval_needs_the_current_session_id(tmp_path, monkeypatch, session_id):
    session, card_id = _card_session(tmp_path)
    broker = CardBroker(session)
    start = broker.request("begin_card_browser", user_gesture=True)
    monkeypatch.setattr("broker_host.confirm", lambda *a: True)
    payload = {} if session_id is None else {"session_id": session_id}
    denied = broker.request("approve_card_browser", user_gesture=True, entry_id=card_id, revision=1,
                            fields=["cc-name"], **payload)
    assert denied["ok"] is False and denied["error"] == "session_changed"
    approved = broker.request("approve_card_browser", user_gesture=True, entry_id=card_id, revision=1,
                              fields=["cc-name"], session_id=start["session_id"])
    assert approved["ok"]


@pytest.mark.parametrize("session_id", ["", "wrong-session"])
def test_manual_save_with_an_empty_or_stale_session_id_is_refused(session, prompts, session_id):
    broker = _Broker(session)
    reply = broker.request("save_browser", username="carol", password="pw", session_id=session_id,
                           gesture_nonce=broker.nonce())
    assert reply["ok"] is False and reply["error"] == "session_changed"
    assert prompts.asked == [] and broker.unlock_prompts == 0
    assert not [e for e in session.find_web(SITE) if e["username"] == "carol"]


def test_manual_save_with_the_current_session_id_or_none_proceeds(session, prompts):
    broker = _Broker(session)
    lease = broker.guard.lease().token
    assert broker.request("save_browser", username="carol", password="pw", session_id=lease,
                          gesture_nonce=broker.nonce()) == {"ok": True, "status": "created"}
    # The extension's manual save sends no session_id at all.
    assert broker.request("save_browser", username="dave", password="pw",
                          gesture_nonce=broker.nonce()) == {"ok": True, "status": "created"}
    assert json.dumps(sorted(e["username"] for e in session.find_web(SITE))) == json.dumps(["alice", "carol", "dave"])
