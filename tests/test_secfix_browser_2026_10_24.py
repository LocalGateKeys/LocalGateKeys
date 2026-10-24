"""Extended audit 2026-10-24, stream C: browser broker, grants and passkeys.

I-12 typed grants, L-14 per-site probe budgets, L-15 same-site handoff without
the username, L-16 strict gesture nonces (legacy_gesture_compat off),
L-17 passkey create needs a user activation.
"""
from __future__ import annotations

import json
from types import SimpleNamespace as NS

import pytest

from localvault.identity_fill import CardReleaseManager, IdentityReleaseError, IdentityReleaseManager
from localvault.session_guard import SessionGuard, StaleSession
from test_security_audit_ipc import KDF, MASTER, SITE, _Broker, _ctx
from localvault.vault import create_vault

TOTP = {"secret": "JBSWY3DPEHPK3PXP", "digits": 6, "period": 30, "algorithm": "SHA1"}


@pytest.fixture
def session(tmp_path):
    s = create_vault(tmp_path / "secfix-browser.json", MASTER, kdf_overrides=KDF)
    yield s
    if s.is_unlocked:
        s.lock()


@pytest.fixture
def confirms(monkeypatch):
    asked = []
    monkeypatch.setattr("broker_host.confirm", lambda *a: asked.append(a) or True)
    return asked


@pytest.fixture
def clock(monkeypatch):
    now = [5000.0]
    monkeypatch.setattr("localvault.browser_broker.time.monotonic", lambda: now[0])
    return now


# ---- I-12: grants carry a kind ------------------------------------------------

def test_guard_grant_kind_is_checked_on_use():
    guard = SessionGuard("p")
    guard.open(0)
    login = guard.grant(SITE, "ctx-1", ["e1"])
    totp = guard.grant(SITE, "ctx-1", ["e1"], kind="totp")
    guard.permission(login, SITE, "ctx-1", "e1")
    guard.permission(totp, SITE, "ctx-1", "e1", kind="totp")
    with pytest.raises(StaleSession):
        guard.permission(totp, SITE, "ctx-1", "e1")  # default kind is login
    with pytest.raises(StaleSession):
        guard.permission(login, SITE, "ctx-1", "e1", kind="totp")
    with pytest.raises(ValueError):
        guard.grant(SITE, "ctx-1", ["e1"], kind="vault")


def test_a_2fa_grant_does_not_release_the_password(session):
    entry = session.upsert_web(origin=SITE, username="alice", password="pw-i12-secret")
    session.set_details(entry, totp=dict(TOTP))
    broker = _Broker(session, legacy_gesture_compat=False)
    start = broker.request("begin_totp_browser", user_gesture=True)
    assert start["ok"]
    stolen = broker.request("get_browser", grant=start["grant"], entry_id=entry,
                            gesture_nonce=start["gesture_nonce"])
    assert stolen.get("ok") is not True and "credential" not in stolen
    assert "pw-i12-secret" not in json.dumps(stolen)


def test_a_login_grant_does_not_release_a_2fa_code(session):
    entry = session.upsert_web(origin=SITE, username="alice", password="pw-i12")
    session.set_details(entry, totp=dict(TOTP))
    broker = _Broker(session, legacy_gesture_compat=False)
    start = broker.request("begin_browser", user_gesture=True)
    assert start["ok"]
    code = broker.request("get_totp_browser", grant=start["grant"], entry_id=entry,
                          gesture_nonce=start["gesture_nonce"])
    assert code.get("ok") is not True and "code" not in code


def test_release_approvals_are_tagged_with_their_kind():
    guard = SessionGuard("p")
    guard.open(0)
    context = json.dumps([3, "doc", SITE, "op"])
    identity = IdentityReleaseManager(guard)
    token = identity.issue(identity_id="i1", revision=1, origin=SITE, context=context, fields=["email"])
    assert identity._approvals[token].kind == "identity"
    identity.kind = "card"  # a manager of another kind must not honour it
    with pytest.raises(IdentityReleaseError):
        identity.release(token, identity_id="i1", revision=1, origin=SITE, context=context,
                         fields=["email"], identity={"email": "a@example.test"})
    card = CardReleaseManager(guard)
    card_token = card.issue(identity_id="c1", revision=1, origin=SITE, context=context, fields=["cc-name"])
    assert card._approvals[card_token].kind == "card"


# ---- L-14: one site cannot use up the probe budget ---------------------------

def test_one_site_with_many_subdomains_cannot_exhaust_the_global_budget(session, clock):
    session.upsert_web(origin=SITE, username="alice", password="pw-l14")
    broker = _Broker(session)
    blocked = 0
    for i in range(80):
        reply = broker.request("check_browser", origin=f"https://s{i}.flood.test", username="u", password="p")
        blocked += reply.get("error") == "rate_limited"
    assert blocked == 80 - broker.PROBE_LIMIT_PER_SITE
    # Another site still gets its full per-origin budget.
    for attempt in range(broker.PROBE_LIMIT_PER_ORIGIN):
        assert broker.request("check_browser", username="alice", password=f"g{attempt}")["ok"] is True
    assert broker.request("check_browser", username="alice", password="g")["error"] == "rate_limited"


def test_per_origin_limit_still_applies_within_a_site(session, clock):
    broker = _Broker(session)
    for _ in range(broker.PROBE_LIMIT_PER_ORIGIN):
        assert broker.request("capture_browser", origin="https://a.site.test", username="u", password="p")["ok"]
    assert broker.request("capture_browser", origin="https://a.site.test", username="u",
                          password="p")["error"] == "rate_limited"
    left = broker.PROBE_LIMIT_PER_SITE - broker.PROBE_LIMIT_PER_ORIGIN
    for _ in range(left):
        assert broker.request("capture_browser", origin="https://b.site.test", username="u", password="p")["ok"]
    assert broker.request("capture_browser", origin="https://c.site.test", username="u",
                          password="p")["error"] == "rate_limited"
    clock[0] += broker.PROBE_WINDOW + 1
    assert broker.request("capture_browser", origin="https://a.site.test", username="u", password="p")["ok"]


def test_the_probe_log_has_a_hard_ceiling(session, clock):
    broker = _Broker(session)
    for i in range(broker.PROBE_HARD_LIMIT + 50):
        broker.request("check_browser", origin=f"https://site{i}.test", username="u", password="p")
    assert len(broker._probe_log) <= broker.PROBE_HARD_LIMIT


# ---- L-15: the handoff names the origin, not the username ---------------------

def test_same_site_handoff_hides_the_username_and_the_desktop_shows_it(session, confirms):
    login, landing = "https://login.paddle.com", "https://vendors.paddle.com"
    broker = _Broker(session, legacy_gesture_compat=False)
    captured = broker.request("capture_browser", origin=login, username="ada@example.test",
                              password="pw-l15", context=_ctx(login, document="doc-login"))
    assert captured["stored"]
    there = _ctx(landing, document="doc-landing")
    pending = broker.request("pending_browser", origin=landing, context=there)
    assert pending["pending"] and pending["origin"] == login and pending["handoff"] is True
    assert "username" not in pending and "ada" not in json.dumps(pending)
    nonce = broker.request("begin_gesture_browser", origin=landing, context=there,
                           user_gesture=True)["gesture_nonce"]
    saved = broker.request("save_pending_browser", origin=landing, context=there,
                           pending_token=pending["pending_token"], gesture_nonce=nonce)
    assert saved == {"ok": True, "status": "created"}
    assert "ada@example.test" in str(confirms[0]) and login in str(confirms[0])


def test_own_origin_pending_reply_keeps_the_username(session):
    broker = _Broker(session)
    broker.request("capture_browser", username="ada", password="pw-own")
    pending = broker.request("pending_browser")
    assert pending["username"] == "ada" and "handoff" not in pending


# ---- L-16: strict gesture nonces ---------------------------------------------

def test_without_the_setting_the_broker_requires_a_nonce(session):
    broker = _Broker(session)
    broker.settings = NS(browser_enabled=True, fill_and_sign_in=False)  # no legacy_gesture_compat at all
    reply = broker.request("save_browser", username="u", password="pw", user_gesture=True)
    assert reply["error"] == "gesture_nonce_required"


def test_strict_mode_fill_and_save_flows_work_with_nonces(session, confirms):
    entry = session.upsert_web(origin=SITE, username="alice", password="pw-l16")
    broker = _Broker(session, legacy_gesture_compat=False)
    start = broker.request("begin_browser", user_gesture=True)
    released = broker.request("get_browser", grant=start["grant"], entry_id=entry,
                              gesture_nonce=start["gesture_nonce"])
    assert released["ok"] and released["credential"]["password"] == "pw-l16"
    # save_pending_browser: refused with the bare boolean, accepted with a nonce.
    captured = broker.request("capture_browser", username="bob", password="pw-bob")
    bare = broker.request("save_pending_browser", pending_token=captured["pending_token"], user_gesture=True)
    assert bare["error"] == "gesture_nonce_required"
    nonce = broker.request("begin_gesture_browser", user_gesture=True)["gesture_nonce"]
    saved = broker.request("save_pending_browser", pending_token=captured["pending_token"], gesture_nonce=nonce)
    assert saved == {"ok": True, "status": "created"}
    assert {e["username"] for e in session.find_web(SITE)} == {"alice", "bob"}


# ---- L-17: passkey create needs a user activation ----------------------------

def test_passkey_create_without_activation_falls_back_without_a_prompt(tmp_path):
    from test_passkey_broker import _broker, _create_options
    broker = _broker(tmp_path)
    for activation in (False, None, "yes"):
        reply = broker.request("passkey_create_browser", options=_create_options(), user_activation=activation)
        assert reply == {"ok": False, "error": "fallback"}
    assert broker.prompts == []
    assert broker.request("passkey_create_browser", options=_create_options())["ok"] is True
    assert len(broker.prompts) == 1
