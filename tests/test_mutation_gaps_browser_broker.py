"""Tests that close gaps found by mutation testing of ``localvault.browser_broker`` (2026-10-24)."""
from __future__ import annotations

import time

import pytest
from test_security_audit_ipc import KDF, MASTER, SITE, _Broker, _ctx  # noqa: F401

from localvault import browser_broker as bb
from localvault.vault import create_vault


@pytest.fixture
def session(tmp_path):
    s = create_vault(tmp_path / "mutation-gaps.json", MASTER, kdf_overrides=KDF)
    yield s
    if s.is_unlocked:
        s.lock()


class _QueuedBroker(_Broker):
    """``run_on_ui`` runs ``before`` first, as if the request waited in the UI queue."""

    before = None

    def run_on_ui(self, function, timeout=0):
        if self.before is not None:
            self.before()
        return function()


# --- dispatch_remote ---------------------------------------------------------------------


@pytest.mark.parametrize("request_value", [None, [], "begin_browser", 5, ("action", "ping")])
def test_non_dict_request_is_invalid(session, request_value) -> None:
    broker = _Broker(session)
    assert broker.dispatch_remote(request_value) == {"ok": False, "error": "invalid_request"}


def test_profile_switch_while_queued_is_session_changed(session) -> None:
    broker = _QueuedBroker(session)
    broker.before = lambda: broker.guard.invalidate("other-profile")
    reply = broker.request("begin_gesture_browser", user_gesture=True)
    assert reply == {"ok": False, "error": "session_changed"}


def test_lock_while_queued_is_session_changed(session) -> None:
    broker = _QueuedBroker(session)
    broker.before = lambda: broker.guard.invalidate()
    reply = broker.request("ping")
    assert reply == {"ok": False, "error": "session_changed"}


def test_request_queued_longer_than_90_seconds_is_session_changed(session, monkeypatch) -> None:
    broker = _QueuedBroker(session)
    real = time.monotonic
    offset = {"value": 0.0}
    monkeypatch.setattr(bb.time, "monotonic", lambda: real() + offset["value"])

    def wait() -> None:
        offset["value"] = 91.0

    broker.before = wait
    assert broker.request("ping") == {"ok": False, "error": "session_changed"}
    # 89 s in the queue is still fine.
    offset["value"] = 0.0
    broker.before = lambda: offset.__setitem__("value", 89.0)
    assert broker.request("ping")["ok"] is True


def test_unchanged_stamp_within_90_seconds_runs(session) -> None:
    broker = _QueuedBroker(session)
    broker.before = lambda: None
    assert broker.request("begin_gesture_browser", user_gesture=True)["ok"] is True


@pytest.mark.parametrize("action", ["begin_identity_browser", "approve_identity_browser",
                                    "release_identity_browser", "cancel_identity_browser"])
def test_identity_action_without_identity_protocol_is_version_mismatch(session, action) -> None:
    broker = _Broker(session)
    reply = broker.request(action)
    assert reply["ok"] is False and reply["error"] == "version_mismatch"
    assert "identity-fill" in reply["message"]
    reply = broker.request(action, identity_protocol="0-old")
    assert reply["error"] == "version_mismatch" and "identity-fill" in reply["message"]


@pytest.mark.parametrize("context", ["", "x" * 15, "x" * 8193, 12345, None, ["x" * 20], {"tab": 1}])
def test_context_type_and_length_are_checked(session, context) -> None:
    broker = _Broker(session)
    reply = broker.dispatch_remote({"action": "begin_gesture_browser", "protocol": 2, "extension_version": "t",
                                    "origin": SITE, "context": context, "user_gesture": True})
    assert reply["ok"] is False and reply["error"] == "invalid_request"


@pytest.mark.parametrize("length", [16, 8192])
def test_context_length_bounds_are_inclusive(session, length) -> None:
    broker = _Broker(session)
    reply = broker.dispatch_remote({"action": "begin_gesture_browser", "protocol": 2, "extension_version": "t",
                                    "origin": SITE, "context": "c" * length, "user_gesture": True})
    assert reply["ok"] is True


@pytest.mark.parametrize("action", ["begin_browser", "get_browser", "save_browser", "save_pending_browser",
                                    "begin_identity_browser", "begin_card_browser", "begin_totp_browser",
                                    "get_totp_browser", "passkey_get_browser"])
def test_only_one_interactive_prompt_at_a_time(session, action, monkeypatch) -> None:
    broker = _Broker(session, legacy_gesture_compat=True)
    called = []
    # Any handler that ran would be recorded: the busy check must answer first.
    monkeypatch.setattr(broker, "_check_gesture", lambda *a, **k: None)
    for name in ("_begin_browser", "_release_browser", "_save_browser", "_save_pending_browser",
                 "_begin_identity_browser", "_begin_card_browser", "_begin_totp_browser",
                 "_release_totp_browser", "_passkey_get_browser"):
        monkeypatch.setattr(broker, name, lambda *a, _n=name, **k: called.append(_n) or {"ok": True})
    monkeypatch.setattr(bb, "validate_identity_context", lambda *a, **k: None)
    broker._remote_busy = True
    reply = broker.request(action, user_gesture=True, identity_protocol=bb.IDENTITY_FILL_PROTOCOL,
                           card_protocol=bb.CARD_FILL_PROTOCOL, passkey_protocol=bb.PASSKEY_PROTOCOL)
    assert reply["ok"] is False and reply["error"] == "busy"
    assert called == []
    assert broker._remote_busy is True  # the open prompt still owns the flag
    broker._remote_busy = False
    assert broker.request(action, user_gesture=True, identity_protocol=bb.IDENTITY_FILL_PROTOCOL,
                          card_protocol=bb.CARD_FILL_PROTOCOL, passkey_protocol=bb.PASSKEY_PROTOCOL)["ok"] is True
    assert len(called) == 1
    assert broker._remote_busy is False


def test_non_interactive_actions_are_not_blocked_by_an_open_prompt(session) -> None:
    broker = _Broker(session)
    broker._remote_busy = True
    assert broker.request("begin_gesture_browser", user_gesture=True)["ok"] is True
    assert broker.request("ping")["ok"] is True


# --- begin_gesture_browser ---------------------------------------------------------------


@pytest.mark.parametrize("gesture", [None, False, "true", 1, "yes"])
def test_begin_gesture_browser_requires_a_real_user_gesture(session, gesture) -> None:
    broker = _Broker(session)
    payload = {} if gesture is None else {"user_gesture": gesture}
    reply = broker.request("begin_gesture_browser", **payload)
    assert reply == {"ok": False, "error": "user_gesture_required"}
    assert not getattr(broker, "_gesture_nonces", {})


def test_begin_gesture_browser_with_gesture_mints_a_nonce(session) -> None:
    broker = _Broker(session)
    reply = broker.request("begin_gesture_browser", user_gesture=True)
    assert reply["ok"] is True and len(reply["gesture_nonce"]) == 32


# --- _page_url ----------------------------------------------------------------------------


@pytest.mark.parametrize("url", [5, b"https://example.test/", "", "https://example.test/" + "a" * 4080, ["x"]])
def test_page_url_type_and_length(url) -> None:
    with pytest.raises(ValueError, match="Invalid page URL"):
        bb.BrowserBroker._page_url({"url": url}, SITE)


def test_page_url_accepts_a_url_of_the_origin_and_defaults_to_the_origin() -> None:
    assert bb.BrowserBroker._page_url({}, SITE) == SITE
    assert bb.BrowserBroker._page_url({"url": "https://EXAMPLE.test/a?b=1#frag"}, SITE) == "https://example.test/a?b=1"
    with pytest.raises(ValueError, match="does not belong"):
        bb.BrowserBroker._page_url({"url": "https://other.test/"}, SITE)
