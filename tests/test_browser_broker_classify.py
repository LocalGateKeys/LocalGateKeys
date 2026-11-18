"""classify_site_browser: the broker compares the page origin with the saved origins in the app.

The saved origins never leave the app: the reply carries a verdict, and only for a lookalike
the host of the saved site it imitates (shown in the guard panel) plus an opaque pair id.
"""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

from broker_host import BrokerHostBase as RuntimeActions

from localvault import lookalike
from localvault.browser_broker import BrowserBroker
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
        self.unlock_prompts = 0

    def ensure_unlocked(self):
        self.unlock_prompts += 1
        return self._session_available()

    def run_on_ui(self, function, timeout=0):
        return function()

    def refresh_entries(self):
        return None

    def request(self, action: str, *, origin: str, **payload):
        return self.dispatch_remote({
            "action": action, "protocol": 2, "extension_version": "0.4.12", "origin": origin,
            "context": json.dumps([17, "document-redacted", origin, "operation-redacted"]),
            **payload,
        })


def _broker(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    session = create_vault(tmp_path / "classify.json", "redacted-master", kdf_overrides=KDF)
    session.upsert_web(origin="https://example.com", username="alice", password="pw-1")
    session.upsert_web(origin="https://www.amazon.com", username="alice", password="pw-2")
    wide = session.upsert_web(origin="https://portal.example.net", username="bob", password="pw-3")
    session.items.set_web_urls(wide, [
        {"url": "https://portal.example.net", "match": "exact_origin"},
        {"url": "https://paypal.com/signin", "match": "starts_with"},
    ])
    return _Broker(session)


def classify(broker, origin):
    return broker.request("classify_site_browser", origin=origin)


def test_exact_related_and_new_sites(tmp_path) -> None:
    broker = _broker(tmp_path)
    assert classify(broker, "https://example.com") == {"ok": True, "kind": "exact", "reason": "same-origin"}
    assert classify(broker, "https://www.example.com") == {"ok": True, "kind": "related", "reason": "www-host"}
    assert classify(broker, "https://example.com:8443") == {"ok": True, "kind": "related", "reason": "same-host"}
    # Audit 2026-11-10: another host on the saved site's domain gets no "Related site" badge, and the
    # reply names no saved origin (only a lookalike reply does).
    assert classify(broker, "https://accounts.example.com") == {"ok": True, "kind": "unknown", "reason": "same-site"}
    assert classify(broker, "https://unrelated.test") == {"ok": True, "kind": "unknown", "reason": "no-match"}


def test_url_rows_count_as_saved_origins(tmp_path) -> None:
    broker = _broker(tmp_path)
    # The starts_with row on paypal.com is a saved site too.
    assert classify(broker, "https://paypal.com")["kind"] == "exact"
    reply = classify(broker, "https://paypa1.com")
    assert reply["kind"] == "lookalike" and reply["reason"] == "edit-distance"
    assert reply["matched"] == "paypal.com"


def test_lookalike_reply_names_only_the_imitated_host(tmp_path) -> None:
    broker = _broker(tmp_path)
    reply = classify(broker, "https://xn--xample-2of.com")  # Cyrillic "е" in place of "e"
    assert reply["ok"] and reply["kind"] == "lookalike" and reply["reason"] == "homoglyph"
    assert reply["matched"] == "example.com"
    text = json.dumps(reply)
    # No other saved origin, username or password reaches the extension.
    for secret in ("amazon", "portal.example.net", "paypal", "alice", "bob", "pw-"):
        assert secret not in text
    assert set(reply) == {"ok", "kind", "reason", "matched"}


def test_other_suffix_carries_an_opaque_pair_id(tmp_path) -> None:
    broker = _broker(tmp_path)
    reply = classify(broker, "https://www.amazon.de")
    assert reply["kind"] == "lookalike" and reply["reason"] == "other-suffix"
    assert reply["matched"] == "www.amazon.com"
    pair = reply["pair"]
    assert len(pair) == 32 and int(pair, 16) >= 0
    # Keyed with the vault's data key (review finding 6): not the plain hash of the pair.
    assert pair != hashlib.sha256(b"https://www.amazon.de\nhttps://www.amazon.com").hexdigest()[:32]
    # Stable for the same origin pair, different for another page origin.
    assert classify(broker, "https://www.amazon.de")["pair"] == pair
    assert classify(broker, "https://amazon.co.uk")["pair"] != pair


def test_pair_id_differs_between_vaults(tmp_path) -> None:
    one = _broker(tmp_path / "one")
    two = _broker(tmp_path / "two")
    assert classify(one, "https://www.amazon.de")["pair"] != classify(two, "https://www.amazon.de")["pair"]


def test_mixed_script_has_no_match(tmp_path) -> None:
    broker = _broker(tmp_path)
    mixed = classify(broker, "https://xn--bnk-6cd.test")  # Latin "bnk" with a Cyrillic "а"
    assert mixed == {"ok": True, "kind": "lookalike", "reason": "mixed-script", "matched": None}


def test_locked_vault_answers_locked_without_prompting(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.session.lock()
    reply = classify(broker, "https://example.com")
    assert reply == {"ok": True, "locked": True}
    assert broker.unlock_prompts == 0


def test_no_gesture_needed_and_not_interactive(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker._remote_busy = True  # an open desktop prompt does not block a verdict
    assert classify(broker, "https://example.com")["kind"] == "exact"


def test_saved_sites_are_parsed_once(tmp_path, monkeypatch) -> None:
    """Review finding 6: classify does not re-parse every saved origin on every call."""
    broker = _broker(tmp_path)
    lookalike._saved_site.cache_clear()
    calls = []
    real = lookalike._site

    def counting(value, *, bare_host_ok):
        calls.append(value)
        return real(value, bare_host_ok=bare_host_ok)

    monkeypatch.setattr(lookalike, "_site", counting)
    classify(broker, "https://a.example.org")
    first = len(calls)
    classify(broker, "https://b.example.org")
    # Second call parses only the page origin.
    assert len(calls) == first + 1


def test_lock_clears_the_parsed_saved_origins(tmp_path) -> None:
    broker = _broker(tmp_path)
    classify(broker, "https://a.example.org")
    assert lookalike._saved_site.cache_info().currsize > 0
    broker._forget_site_verdicts()  # the host's on_lock hook
    assert lookalike._saved_site.cache_info().currsize == 0
    classify(broker, "https://a.example.org")
    broker.session.lock()
    assert classify(broker, "https://a.example.org") == {"ok": True, "locked": True}
    assert lookalike._saved_site.cache_info().currsize == 0, "a locked answer also drops the cache"


def test_host_registers_the_lock_hook() -> None:
    from pathlib import Path

    host = (Path(__file__).resolve().parents[1] / "src" / "localvault" / "web" / "host.py").read_text(encoding="utf-8")
    assert "controller.on_lock.append(self._forget_site_verdicts)" in host


def test_malformed_origin_is_refused(tmp_path) -> None:
    broker = _broker(tmp_path)
    for bad in ("", "not a url", "https://user:pw@example.com", "javascript:alert(1)", "https://example.com/path"):
        reply = classify(broker, bad)
        assert reply["ok"] is False and reply["error"] == "invalid_request", bad


# ---- Ruling T4b: a never-seen site asking for a saved username.
def new_site(broker, origin, username, **extra):
    return broker.request("new_site_username_browser", origin=origin, username=username, user_gesture=True, **extra)


def test_new_site_username_saved_elsewhere(tmp_path) -> None:
    broker = _broker(tmp_path)
    reply = new_site(broker, "https://secure-login-verify.test", "alice")
    assert reply == {"ok": True, "elsewhere": True}
    # Case and surrounding spaces do not matter; the reply never names a site.
    assert new_site(broker, "https://secure-login-verify.test", " Alice ") == {"ok": True, "elsewhere": True}
    assert new_site(broker, "https://secure-login-verify.test", "carol") == {"ok": True, "elsewhere": False}


def test_new_site_username_only_for_unknown_sites(tmp_path) -> None:
    broker = _broker(tmp_path)
    for origin in ("https://example.com", "https://www.example.com", "https://xn--xample-2of.com"):
        assert new_site(broker, origin, "alice") == {"ok": True, "elsewhere": False}, origin
    # Audit 2026-11-10: another host on a saved site's domain is "unknown" now, so the soft
    # "saved for another site" note can show there (sites.google.com next to accounts.google.com).
    assert new_site(broker, "https://accounts.example.com", "alice") == {"ok": True, "elsewhere": True}


def test_new_site_username_needs_the_gesture_flag_and_a_username(tmp_path) -> None:
    broker = _broker(tmp_path)
    reply = broker.request("new_site_username_browser", origin="https://new.test", username="alice")
    assert reply == {"ok": False, "error": "user_gesture_required"}
    assert new_site(broker, "https://new.test", "")["error"] == "invalid_request"


def test_new_site_username_locked_never_prompts(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.session.lock()
    assert new_site(broker, "https://new.test", "alice") == {"ok": True, "elsewhere": False}
    assert broker.unlock_prompts == 0


def test_new_site_username_is_rate_limited(tmp_path) -> None:
    broker = _broker(tmp_path)
    replies = [new_site(broker, "https://new.test", f"user{i}") for i in range(12)]
    assert replies[-1]["error"] == "rate_limited"
