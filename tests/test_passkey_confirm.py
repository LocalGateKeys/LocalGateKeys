"""Two-step passkey save (known limitation 2): a page confirms or discards its own create.

An extension that announces ``passkey_confirm`` gets its new passkey saved unconfirmed: hidden from
sign-in, from the Windows provider list and from sync. An explicit discard removes it for good; with no
report (window over, lock, a crash before the next unlock) it is kept as an ordinary passkey. An
extension without it keeps the old behaviour.
"""
from __future__ import annotations

import json
import time
from types import SimpleNamespace

from broker_host import BrokerHostBase as RuntimeActions

import localvault.passkey_broker as passkey_broker
from localvault.browser_broker import BrowserBroker
from localvault.passkeys import b64u_encode
from localvault.session_guard import SessionGuard
from localvault.settings import AppSettings
from localvault.sync.vault_bridge import local_view
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
ORIGIN = "https://login.example.test"
CONTEXT = json.dumps([17, "document-redacted", ORIGIN, "pk-op-1"])


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
        self.prompts: list[dict] = []
        self.answer: tuple[str, str | None] = ("approve", None)
        self.scheduled: list[float] = []
        self.refreshes = 0

    def run_on_ui(self, function, timeout=0):
        return function()

    def refresh_entries(self):
        self.refreshes += 1

    def _touch_secret(self):
        self.last_secret_use = 1.0

    def _passkey_schedule(self, delay):  # no real timer threads in tests
        self.scheduled.append(delay)

    def passkey_prompt(self, mode, *, origin, rp_id, accounts, excluded):
        self.prompts.append({"mode": mode, "accounts": accounts})
        return self.answer

    def reauthenticate(self, title, lease, *, allow_hello=False, fresh=False):
        return True

    def request(self, action: str, *, context: str = CONTEXT, origin: str = ORIGIN, **payload):
        return self.dispatch_remote({"action": action, "protocol": 2, "passkey_protocol": 1,
                                     "extension_version": "0.4.0", "origin": origin, "context": context,
                                     **payload})

    def create(self, *, confirm: bool = True, context: str = CONTEXT) -> dict:
        extra = {"passkey_confirm": True} if confirm else {}
        reply = self.request("passkey_create_browser", context=context, user_activation=True,
                             options=_create_options(), **extra)
        assert reply["ok"] is True, reply
        return reply["credential"]

    def items(self) -> list[dict]:
        return [item for item in self.session.item_service._items() if item["kind"] == "passkey"]


def _broker(tmp_path) -> _Broker:
    return _Broker(create_vault(tmp_path / "pk.json", "passkey confirm master", kdf_overrides=KDF))


def _create_options():
    return {"rp": {"id": "example.test", "name": "Example"},
            "user": {"id": b64u_encode(b"user-1"), "name": "ada", "displayName": "Ada"},
            "challenge": b64u_encode(b"c" * 32), "pubKeyCredParams": [{"type": "public-key", "alg": -7}]}


def _get(broker: _Broker) -> dict:
    return broker.request("passkey_get_browser", options={"rpId": "example.test", "challenge": b64u_encode(b"g" * 32)})


def _trash_and_history_ids(broker: _Broker) -> set[str]:
    payload = broker.session._require_typed_catalog()
    ids = {row["entry"]["id"] for row in payload.get("trash", [])}
    return ids | {str(row.get("item_id") or row.get("id")) for row in payload.get("history", []) if isinstance(row, dict)}


def _not_in_file(broker: _Broker, credential_id: str) -> None:
    """The vault on disk no longer holds the passkey (re-read through a fresh unlock)."""
    from localvault.vault import unlock_vault

    copy = unlock_vault(broker.session.path, "passkey confirm master")
    try:
        assert credential_id not in json.dumps(copy._require_typed_catalog())
    finally:
        copy.lock()


def test_capable_create_is_saved_unconfirmed_and_hidden_from_sign_in(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.create()
    [item] = broker.items()
    assert item["payload"]["unconfirmed"] is True
    assert broker.session.item_service.passkey_records("example.test") == []
    assert broker.session.item_service.passkey_metadata() == []
    broker.prompts.clear()
    assert _get(broker) == {"ok": False, "error": "fallback"}
    assert broker.prompts == [], "an unconfirmed passkey is never offered"
    assert broker.scheduled == [passkey_broker.PASSKEY_CONFIRM_WINDOW]


def test_confirm_keeps_the_passkey_and_makes_it_usable(tmp_path) -> None:
    broker = _broker(tmp_path)
    credential = broker.create()
    assert broker.request("passkey_confirm_browser") == {"ok": True}
    [item] = broker.items()
    assert "unconfirmed" not in item["payload"]
    [record] = broker.session.item_service.passkey_records("example.test")
    assert record["credential_id"] == credential["credential_id"]
    broker.answer = ("approve", record["id"])
    assert _get(broker)["ok"] is True
    # Nothing is left to expire, lock or purge.
    broker._passkey_expire(now=time.monotonic() + 3600)
    broker._passkey_before_lock()
    assert broker._passkey_purge_orphans() == 0
    assert len(broker.items()) == 1
    assert broker.request("passkey_discard_browser") == {"ok": False, "error": "not_found"}
    assert len(broker.items()) == 1, "a confirmed passkey is never discarded"


def test_discard_removes_the_passkey_for_good(tmp_path) -> None:
    broker = _broker(tmp_path)
    credential = broker.create()
    item_id = broker.items()[0]["id"]
    assert broker.request("passkey_discard_browser") == {"ok": True}
    assert broker.items() == []
    assert item_id not in _trash_and_history_ids(broker), "no trash row or history snapshot keeps the key"
    _not_in_file(broker, credential["credential_id"])
    assert broker.request("passkey_confirm_browser") == {"ok": False, "error": "not_found"}


def test_no_report_within_the_window_keeps_it_as_an_ordinary_passkey(tmp_path) -> None:
    """Only a discard removes: with no report the page may have received the credential."""
    broker = _broker(tmp_path)
    broker.create()
    broker._passkey_expire(now=time.monotonic() + passkey_broker.PASSKEY_CONFIRM_WINDOW - 1)
    [item] = broker.items()
    assert item["payload"].get("unconfirmed") is True, "still inside the window"
    broker._passkey_expire(now=time.monotonic() + passkey_broker.PASSKEY_CONFIRM_WINDOW + 1)
    [item] = broker.items()
    assert "unconfirmed" not in item["payload"]
    assert broker.request("passkey_discard_browser") == {"ok": False, "error": "not_found"}
    assert len(broker.items()) == 1, "a late discard no longer removes it"


def test_a_confirmation_counts_when_it_arrives_even_if_the_vault_is_busy(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.create()
    # The confirm reaches the broker but cannot run (here: the integration was just switched off).
    broker.settings.browser_enabled = False
    assert broker.request("passkey_confirm_browser")["ok"] is False
    broker._passkey_expire(now=time.monotonic() + passkey_broker.PASSKEY_CONFIRM_WINDOW + 1)
    [item] = broker.items()
    assert "unconfirmed" not in item["payload"], "the noted confirmation is applied, never a removal"


def test_lock_keeps_a_passkey_without_a_report(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.create()
    broker._passkey_before_lock()
    [item] = broker.items()
    assert "unconfirmed" not in item["payload"]
    assert broker.request("passkey_discard_browser") == {"ok": False, "error": "not_found"}


def test_lock_still_applies_a_discard_already_received(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.create()
    broker.settings.browser_enabled = False  # the discard reaches the broker but cannot run
    assert broker.request("passkey_discard_browser")["ok"] is False
    broker._passkey_before_lock()
    assert broker.items() == []


def test_next_unlock_keeps_passkeys_left_unconfirmed_by_a_crash(tmp_path) -> None:
    broker = _broker(tmp_path)
    service = broker.session.item_service
    crashed = service.create_passkey("Left over", relying_party_id="example.test", credential_id="AQ",
                                     unconfirmed=True)
    service.create_passkey("Kept", relying_party_id="example.test", credential_id="Ag")
    broker.create()  # a live create this process still waits on
    assert broker._passkey_purge_orphans() == 1
    by_id = {item["id"]: item for item in broker.items()}
    assert len(by_id) == 3 and "unconfirmed" not in by_id[crashed]["payload"]
    assert sum(1 for item in by_id.values() if item["payload"].get("unconfirmed")) == 1, "the live create still waits"


def test_another_context_or_an_unknown_operation_is_refused_alike_and_changes_nothing(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.create()
    others = [json.dumps([18, "document-redacted", ORIGIN, "pk-op-1"]),       # another tab
              json.dumps([17, "document-other", ORIGIN, "pk-op-1"]),          # another document
              json.dumps([17, "document-redacted", ORIGIN, "pk-op-2"])]       # another operation
    replies = []
    for action in ("passkey_confirm_browser", "passkey_discard_browser"):
        for context in others:
            replies.append(broker.request(action, context=context))
    other_origin = "https://other.example.test"
    replies.append(broker.request("passkey_discard_browser", origin=other_origin,
                                  context=json.dumps([17, "document-redacted", other_origin, "pk-op-1"])))
    assert all(reply == {"ok": False, "error": "not_found"} for reply in replies), replies
    [item] = broker.items()
    assert item["payload"]["unconfirmed"] is True
    # The request's origin must match the context's (as for every passkey action).
    mismatched = broker.request("passkey_confirm_browser", origin="https://other.example.test")
    assert mismatched["error"] == "invalid_request"
    assert broker.items()[0]["payload"]["unconfirmed"] is True
    # The page's own context still confirms.
    assert broker.request("passkey_confirm_browser") == {"ok": True}


def test_outcome_actions_need_the_passkey_protocol(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.create()
    reply = broker.dispatch_remote({"action": "passkey_discard_browser", "protocol": 2, "origin": ORIGIN,
                                    "context": CONTEXT})
    assert reply["error"] == "version_mismatch"


def test_an_extension_without_the_capability_keeps_the_old_behaviour(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.create(confirm=False)
    [item] = broker.items()
    assert "unconfirmed" not in item["payload"]
    assert len(broker.session.item_service.passkey_records("example.test")) == 1
    assert broker.scheduled == []
    broker._passkey_expire(now=time.monotonic() + 3600)
    broker._passkey_before_lock()
    broker._passkey_purge_orphans()
    assert len(broker.items()) == 1
    # A page cannot ask for the two-step save itself: only a literal true from the service worker counts.
    other = json.dumps([17, "document-redacted", ORIGIN, "pk-op-9"])
    broker.request("passkey_create_browser", context=other, user_activation=True, options=_create_options(),
                   passkey_confirm="true")
    assert all("unconfirmed" not in item["payload"] for item in broker.items())


def test_an_unconfirmed_passkey_is_not_synced_until_confirmed(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.create()
    item_id = broker.items()[0]["id"]

    def view():
        return local_view(broker.session, lambda: None, device_id="device-a", now=int(time.time()))

    assert item_id not in view()
    broker.request("passkey_confirm_browser")
    state = view()[item_id]
    assert state.deleted is False
    assert "unconfirmed" not in json.dumps(state.item)


def test_a_discarded_passkey_leaves_no_sync_tombstone(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.create()
    item_id = broker.items()[0]["id"]
    local_view(broker.session, lambda: None, device_id="device-a", now=int(time.time()))
    broker.request("passkey_discard_browser")
    states = local_view(broker.session, lambda: None, device_id="device-a", now=int(time.time()))
    assert item_id not in states


# -- review 2026-11-13: only the broker's own create may set the mark ----------------------------------------------

def test_a_user_update_cannot_set_the_mark(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.create(confirm=False)
    [item] = broker.items()
    assert "unconfirmed" not in item["payload"]
    broker.session.item_service.update_item(item["id"], typed_payload={"unconfirmed": True})
    [item] = broker.items()
    assert "unconfirmed" not in item["payload"], "an update must never hide a passkey from sign-in and sync"


def test_a_user_edit_inside_the_window_confirms_it_so_a_later_discard_keeps_it(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.create()
    [item] = broker.items()
    broker.session.item_service.update_item(item["id"], title="Edited by the user")
    [item] = broker.items()
    assert "unconfirmed" not in item["payload"], "the user's edit makes it an ordinary passkey"
    broker.request("passkey_discard_browser")
    assert [i["title"] for i in broker.items()] == ["Edited by the user"], "the discard no longer removes it"


def test_a_peer_cannot_send_the_mark(tmp_path) -> None:
    import copy

    from localvault.sync.vault_bridge import _Applier

    broker = _broker(tmp_path)
    broker.create(confirm=False)
    [item] = broker.items()
    incoming = copy.deepcopy(item)
    incoming["payload"]["unconfirmed"] = True
    applier = object.__new__(_Applier)
    applier.collections = set()
    applier.scope = None
    merged = applier._with_local_fields("item", incoming, None)
    assert "unconfirmed" not in merged["payload"]


def test_a_confirm_that_fails_to_save_is_tried_again(tmp_path, monkeypatch) -> None:
    from localvault.vault import VaultError

    broker = _broker(tmp_path)
    broker.create()
    service_class = type(broker.session.item_service)  # item_service is a new object on each access
    real = service_class.confirm_passkey
    calls = []

    def flaky(self, item_id):
        calls.append(item_id)
        if len(calls) == 1:
            raise VaultError("disk busy (test)")
        return real(self, item_id)

    monkeypatch.setattr(service_class, "confirm_passkey", flaky)
    broker.request("passkey_confirm_browser")
    [item] = broker.items()
    assert item["payload"].get("unconfirmed") is True, "the first save failed"
    assert broker._passkey_pending(), "the entry waits for another try instead of being forgotten"
    broker._passkey_expire(now=time.monotonic() + 60)
    [item] = broker.items()
    assert "unconfirmed" not in item["payload"]
    assert not broker._passkey_pending()


def test_a_save_that_keeps_failing_is_given_up_and_left_to_the_next_unlock(tmp_path, monkeypatch) -> None:
    from localvault.vault import VaultError

    broker = _broker(tmp_path)
    broker.create()

    def broken(self, item_id):
        raise VaultError("disk gone (test)")

    monkeypatch.setattr(type(broker.session.item_service), "confirm_passkey", broken)
    broker.request("passkey_confirm_browser")
    for _ in range(10):
        broker._passkey_expire(now=time.monotonic() + 600)
    assert not broker._passkey_pending(), "no endless retries"
