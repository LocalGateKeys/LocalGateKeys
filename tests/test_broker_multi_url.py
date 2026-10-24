"""Multi-URL candidate matching in the browser broker (origin.candidates_for)."""
from __future__ import annotations

import json
from types import SimpleNamespace

from localvault.browser_broker import BrowserBroker
from broker_host import BrokerHostBase as RuntimeActions
from localvault.session_guard import SessionGuard
from localvault.settings import AppSettings
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


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

    def reauthenticate(self, *args):
        return True

    def request(self, action: str, *, origin: str, context=None, **payload):
        return self.dispatch_remote({
            "action": action, "protocol": 2, "extension_version": "0.3.3", "origin": origin,
            "context": context or json.dumps([17, "document-redacted", origin, "operation-redacted"]),
            **payload,
        })


def _vault(tmp_path):
    session = create_vault(tmp_path / "multi.json", "redacted-master", kdf_overrides=KDF)
    exact = session.upsert_web(origin="https://login.example.com", username="exact-user", password="exact-pw")
    wide = session.upsert_web(origin="https://example.com", username="wide-user", password="wide-pw")
    session.items.set_web_urls(wide, [
        {"url": "https://example.com", "match": "exact_origin"},
        {"url": "https://example.com", "match": "base_domain"},
        {"url": "https://portal.example.net/app", "match": "starts_with"},
    ])
    unrelated = session.upsert_web(origin="https://other.test", username="other", password="other-pw")
    return session, exact, wide, unrelated


def test_begin_browser_offers_url_row_matches_exact_origin_first(tmp_path) -> None:
    session, exact, wide, _unrelated = _vault(tmp_path)
    broker = _Broker(session)
    start = broker.request("begin_browser", origin="https://login.example.com", user_gesture=True)
    assert start["ok"]
    assert [row["entry_id"] for row in start["choices"]] == [exact, wide]
    assert [row["match"] for row in start["choices"]] == ["exact_origin", "base_domain"]
    assert "exact-pw" not in json.dumps(start) and "wide-pw" not in json.dumps(start)
    # The grant covers every offered candidate; a base-domain match releases.
    released = broker.request("get_browser", origin="https://login.example.com", grant=start["grant"],
                              entry_id=wide, gesture_nonce=start["gesture_nonce"])
    assert released["ok"] and released["credential"]["password"] == "wide-pw"
    assert released["credential"]["origin"] == "https://login.example.com"


def test_starts_with_rows_need_the_page_url_and_fail_closed_otherwise(tmp_path) -> None:
    session, _exact, wide, _unrelated = _vault(tmp_path)
    broker = _Broker(session)
    origin = "https://portal.example.net"
    # Origin alone does not satisfy a path-scoped row.
    assert broker.request("begin_browser", origin=origin, user_gesture=True) == {"ok": False, "error": "not_found"}
    assert broker.request("begin_browser", origin=origin, user_gesture=True,
                          url="https://portal.example.net/application") == {"ok": False, "error": "not_found"}
    start = broker.request("begin_browser", origin=origin, user_gesture=True,
                           url="https://portal.example.net/app/login?next=1")
    assert [row["entry_id"] for row in start["choices"]] == [wide]
    assert start["choices"][0]["match"] == "starts_with"
    # The release must still match the page; a drifted URL is refused.
    drifted = broker.request("get_browser", origin=origin, grant=start["grant"], entry_id=wide,
                             gesture_nonce=start["gesture_nonce"], url="https://portal.example.net/other")
    assert drifted["ok"] is False and "credential" not in drifted
    start = broker.request("begin_browser", origin=origin, user_gesture=True,
                           url="https://portal.example.net/app/login")
    released = broker.request("get_browser", origin=origin, grant=start["grant"], entry_id=wide,
                              gesture_nonce=start["gesture_nonce"], url="https://portal.example.net/app/login")
    assert released["ok"] and released["credential"]["password"] == "wide-pw"


def test_page_url_must_belong_to_the_request_origin_and_unmatched_hosts_are_not_found(tmp_path) -> None:
    session, _exact, _wide, _unrelated = _vault(tmp_path)
    broker = _Broker(session)
    mismatch = broker.request("begin_browser", origin="https://login.example.com", user_gesture=True,
                              url="https://evil.test/login")
    assert mismatch["error"] == "invalid_request"
    malformed = broker.request("begin_browser", origin="https://login.example.com", user_gesture=True,
                               url="javascript:alert(1)")
    assert malformed["error"] == "invalid_request"
    assert broker.request("begin_browser", origin="https://evil-example.com", user_gesture=True) == {
        "ok": False, "error": "not_found"}
    assert broker.request("begin_browser", origin="https://example.com.evil.test", user_gesture=True) == {
        "ok": False, "error": "not_found"}


def test_fill_never_policy_and_legacy_single_origin_entries_keep_working(tmp_path) -> None:
    session, exact, wide, unrelated = _vault(tmp_path)
    session.set_details(wide, policy={"fill": "never"})
    broker = _Broker(session)
    start = broker.request("begin_browser", origin="https://login.example.com", user_gesture=True)
    assert [row["entry_id"] for row in start["choices"]] == [exact]
    legacy = broker.request("begin_browser", origin="https://other.test", user_gesture=True)
    assert [row["entry_id"] for row in legacy["choices"]] == [unrelated]
    assert legacy["choices"][0]["match"] == "exact_origin"
