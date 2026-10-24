"""Extended audit 2026-10-24, integration: a stored origin the stricter rules refuse.

Stream D made ``canonicalize_origin`` stricter (two or more trailing dots,
forbidden host characters, zone ids, mapped IPv6...).  vault.py keeps such a
login loadable; the item service must neither crash on it nor offer it for fill,
and sync must not publish it to other devices.
"""
from __future__ import annotations

import pytest

from localvault.origin import OriginError, canonicalize_origin
from localvault.vault import create_vault, unlock_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "integration master password"
REFUSED = "https://login.example.test.."


@pytest.fixture
def old_vault(tmp_path):
    """A vault holding a login saved before the stricter origin rules."""
    session = create_vault(tmp_path / "old.json", MASTER, kdf_overrides=KDF)
    good = session.upsert_web(origin="https://good.example.test", username="good", password="pw-good")
    bad = session.upsert_web(origin="https://login.example.test", username="old", password="pw-old")
    for entry in session._payload["entries"]:
        if entry["id"] == bad:
            # As an old release stored it: refused origin, plus a host row
            # that on its own would match the login page.
            entry["scope"] = {"origin": REFUSED,
                              "urls": [{"url": "https://login.example.test", "match": "host"}]}
    session.save()
    session.lock()
    reopened = unlock_vault(tmp_path / "old.json", MASTER)
    yield reopened, good, bad
    if reopened.is_unlocked:
        reopened.lock()


def test_the_refused_origin_really_is_refused_now():
    with pytest.raises(OriginError):
        canonicalize_origin(REFUSED)


def test_refused_stored_origin_loads_and_is_never_a_fill_candidate(old_vault):
    session, good, bad = old_vault
    assert session.get_entry(bad)["scope"]["origin"] == REFUSED  # kept as typed
    assert session.items.find_web_candidates("https://login.example.test/signin") == []
    found = session.items.find_web_candidates("https://good.example.test/")
    assert [entry["id"] for entry in found] == [good]


def test_refused_stored_origin_is_shown_as_typed_in_the_editor_rows(old_vault):
    session, _good, bad = old_vault
    rows = session.items.web_urls(bad)
    assert {"url": "https://login.example.test", "match": "host"} in rows
    # Fixing it through the editor path validates and stores a canonical scope.
    assert session.items.set_web_urls(bad, [{"url": "https://login.example.test", "match": "exact_origin"}])
    assert session.get_entry(bad)["scope"]["origin"] == "https://login.example.test"


def test_refused_stored_origin_is_not_offered_by_the_browser_broker(old_vault):
    from test_security_audit_ipc import _Broker

    session, _good, _bad = old_vault
    reply = _Broker(session).request("begin_browser", origin="https://login.example.test", user_gesture=True)
    assert reply == {"ok": False, "error": "not_found"}


def test_refused_stored_origin_is_not_published_by_sync(old_vault):
    import time

    from test_sync_vault_bridge import FakeLease

    from localvault.sync.vault_bridge import local_view

    session, good, bad = old_vault
    view = local_view(session, FakeLease(), device_id="device-a", now=int(time.time()))
    assert bad in view.skipped and bad not in view
    assert good in view
