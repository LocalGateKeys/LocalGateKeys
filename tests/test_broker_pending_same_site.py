"""A sign-in that lands on another subdomain of the same site keeps its save prompt.

``login.paddle.com`` posts the login and lands on ``vendors.paddle.com``: the next
document may show and save the capture, which is saved for the origin it was typed
on. Other sites, shared hosting suffixes, other tabs and late documents get nothing.
"""
from __future__ import annotations

import json

import pytest

from localvault.vault import create_vault
from test_broker_item_limit import KDF, _Broker

LOGIN = "https://login.paddle.com"
LANDING = "https://vendors.paddle.com"


def _request(broker, action, origin, tab=17, document="document-login", **payload):
    return broker.dispatch_remote({
        "action": action, "protocol": 2, "extension_version": "0.3.3", "origin": origin,
        "context": json.dumps([tab, document, origin, "operation-redacted"]), **payload,
    })


@pytest.fixture
def broker(tmp_path):
    return _Broker(create_vault(tmp_path / "same-site.json", "redacted-master", kdf_overrides=KDF))


@pytest.fixture
def confirms(monkeypatch):
    asked = []
    monkeypatch.setattr("broker_host.confirm", lambda *a: asked.append(a) or True)
    return asked


def _capture(broker):
    captured = _request(broker, "capture_browser", LOGIN, username="ada", password="pw-paddle")
    assert captured["ok"] and captured["stored"]
    return captured["pending_token"]


def test_landing_subdomain_sees_and_saves_the_capture_for_its_own_origin(broker, confirms):
    token = _capture(broker)
    pending = _request(broker, "pending_browser", LANDING, document="document-landing")
    assert pending["pending"] and pending["pending_token"] == token
    # Audit 2026-10-24 L-15: the other origin learns which origin the login is
    # for, not its username (shown in the trusted desktop confirmation instead).
    assert pending["origin"] == LOGIN and pending["handoff"] is True and "username" not in pending

    nonce = _request(broker, "begin_gesture_browser", LANDING, document="document-landing",
                     user_gesture=True)["gesture_nonce"]
    reply = _request(broker, "save_pending_browser", LANDING, document="document-landing",
                     pending_token=token, user_gesture=True, gesture_nonce=nonce)
    assert reply == {"ok": True, "status": "created"}
    assert LOGIN in str(confirms[0])  # the trusted confirmation names the origin it is saved for
    assert "ada" in str(confirms[0])  # and the username
    assert [e["username"] for e in broker.session.find_web(LOGIN)] == ["ada"]
    assert broker.session.find_web(LANDING) == []
    assert _request(broker, "pending_browser", LANDING, document="document-landing")["pending"] is False


def test_own_origin_reply_carries_no_origin(broker):
    _capture(broker)
    pending = _request(broker, "pending_browser", LOGIN, document="document-login")
    assert pending["pending"] and "origin" not in pending


def test_landing_subdomain_can_discard_it(broker):
    token = _capture(broker)
    _request(broker, "discard_pending_browser", LANDING, document="document-landing", pending_token=token)
    assert _request(broker, "pending_browser", LOGIN)["pending"] is False


@pytest.mark.parametrize("origin", [
    "https://evil.test",                 # another site
    "https://vendors.paddle.com:8443",   # another port
])
def test_other_sites_see_nothing(broker, origin):
    _capture(broker)
    assert _request(broker, "pending_browser", origin, document="document-other")["pending"] is False


def test_shared_hosting_suffix_is_not_one_site(broker):
    captured = _request(broker, "capture_browser", "https://alice.github.io", username="ada", password="pw")
    assert captured["stored"]
    assert _request(broker, "pending_browser", "https://bob.github.io", document="d2")["pending"] is False


def test_another_tab_sees_nothing(broker):
    _capture(broker)
    assert _request(broker, "pending_browser", LANDING, tab=18, document="document-landing")["pending"] is False


def test_handoff_ends_after_the_redirect_grace(broker, monkeypatch):
    _capture(broker)
    import localvault.browser_broker as module
    real = module.time.monotonic
    monkeypatch.setattr(module.time, "monotonic", lambda: real() + broker.PENDING_REDIRECT_GRACE + 1)
    assert _request(broker, "pending_browser", LANDING, document="document-landing")["pending"] is False
