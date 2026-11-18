"""Broker side of the Windows passkey provider: the ``*_system`` actions (design note §5.3, §7)."""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import localvault.passkey_system as system_module
from broker_host import BrokerHostBase
from localvault.browser_broker import BrowserBroker
from cryptography.hazmat.primitives import serialization
from localvault.passkeys import b64u_decode, b64u_encode
from localvault.session_guard import SessionGuard
from localvault.settings import AppSettings
from localvault.vault import create_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
RP = "example.test"
ORIGIN = "https://login.example.test"
HASH = hashlib.sha256(b"client data from windows").digest()
CALLER = {"image": "msedge.exe", "title": "Sign in - Example"}


class FakePort:
    """Records every prompt; ``respond(kw)`` answers ask_passkey (default: approve the first account)."""

    def __init__(self) -> None:
        self.prompts: list[dict] = []
        self.upgrades: list[dict] = []
        self.notes: list[tuple] = []
        self.respond = lambda kw: ("approve", kw["accounts"][0].get("id"))

    def ask_passkey(self, mode, **kw):
        self.prompts.append({"mode": mode, **kw})
        return self.respond(kw)

    def show_upgrade(self, *, limit, message, on_enter):
        self.upgrades.append({"limit": limit, "message": message})

    def notify(self, kind, title, message):
        self.notes.append((kind, title, message))

    def confirm(self, title, message):
        return False


class _Broker(BrokerHostBase, BrowserBroker):
    def __init__(self, session) -> None:
        self.session = session
        self.guard = SessionGuard("redacted-profile")
        self.guard.open(3600)
        self.root = None
        self.settings = AppSettings(auto_lock_seconds=0, windows_passkey_provider=True)
        self.active_profile = SimpleNamespace(id="redacted-profile", name="Redacted", color="#123456")
        self._remote_busy = False
        self.last_extension_seen = 0.0
        self.last_extension_version = ""
        self.last_secret_use = 0.0
        self._closing = False
        self.port = FakePort()
        self.ui = self.port
        self.reauths: list[str] = []
        self.reauth_ok = True
        self.locked = False
        self.unlocks: list[int] = []
        self.unlock_ok = True

    def _session_available(self):
        return not self.locked

    def ensure_unlocked(self, stop=None):
        self.unlocks.append(1)
        if self.unlock_ok:
            self.locked = False
        return not self.locked

    def run_on_ui(self, function, timeout=0):
        return function()

    def refresh_entries(self):
        return None

    def _touch_secret(self):
        self.last_secret_use = 1.0

    def _passkey_foreground(self):
        return None

    def reauthenticate(self, title, lease, *, allow_hello=False, fresh=False):
        assert fresh is True  # P-02: a passkey's UV never comes from the routine grace
        self.reauths.append(title)
        return self.reauth_ok

    def system(self, action, **payload):
        request = {"action": action, "system_protocol": 1, "transaction_id": str(uuid.uuid4()), **payload}
        return self.dispatch_system(request, 4321)

    def create(self, **overrides):
        payload = {"rp_id": RP, "rp_name": "Example", "user_id": b64u_encode(b"user-1"), "user_name": "ada",
                   "user_display_name": "Ada", "client_data_hash": b64u_encode(HASH), "algorithms": [-7, -257],
                   "exclude_credentials": [], "resident_key": True, "user_verification": "required",
                   "caller": CALLER}
        payload.update(overrides)
        return self.system("passkey_create_system", **payload)

    def get(self, **overrides):
        payload = {"rp_id": RP, "client_data_hash": b64u_encode(HASH), "allow_credentials": [],
                   "user_verification": "required", "caller": CALLER}
        payload.update(overrides)
        return self.system("passkey_get_system", **payload)

    def browser(self, action, options):
        return self.dispatch_remote({
            "action": action, "protocol": 2, "passkey_protocol": 1, "extension_version": "0.4.0",
            "origin": ORIGIN, "context": json.dumps([17, "document-redacted", ORIGIN, "operation-redacted"]),
            "user_activation": True, "options": options})


def _broker(tmp_path) -> _Broker:
    return _Broker(create_vault(tmp_path / "pk.json", "passkey system master", kdf_overrides=KDF))


def _records(broker):
    return broker.session.items.passkey_records(RP)


def _cose_public_key(auth_data: bytes) -> ec.EllipticCurvePublicKey:
    length = int.from_bytes(auth_data[53:55], "big")
    cose = auth_data[55 + length:]
    assert cose[:10] == bytes.fromhex("a5010203262001215820") and cose[42:45] == bytes.fromhex("225820")
    x, y = int.from_bytes(cose[10:42], "big"), int.from_bytes(cose[45:77], "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _verify(public_key, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _no_key_material(reply) -> None:
    assert "private_key" not in json.dumps(reply)


# -- gating ------------------------------------------------------------------------------

def test_refused_when_setting_off(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.settings.windows_passkey_provider = False
    for action in ("passkey_create_system", "passkey_get_system", "passkey_cancel_system",
                   "passkey_lock_status_system", "passkey_credentials_system"):
        assert broker.system(action) == {"ok": False, "error": "disabled"}, action
    assert AppSettings().windows_passkey_provider is False  # off by default
    broker.settings.windows_passkey_provider = True
    broker.settings.passkeys_enabled = False
    assert broker.create() == {"ok": False, "error": "disabled"}
    assert broker.port.prompts == [] and _records(broker) == []



def test_setting_off_refusal_is_logged(tmp_path, monkeypatch) -> None:
    from localvault import pipe_transport

    lines = []
    monkeypatch.setattr(pipe_transport, "_pipe_log", lambda event, exc=None: lines.append(event))
    broker = _broker(tmp_path)
    broker.settings.windows_passkey_provider = False
    broker.create()
    broker.settings.windows_passkey_provider = True
    broker.settings.passkeys_enabled = False
    broker.create()
    assert lines == ["system_passkey_refused check=setting_off", "system_passkey_refused check=passkeys_off"]

@pytest.mark.parametrize("protocol", [None, 0, 2, "1", True])
def test_refused_without_system_protocol(tmp_path, protocol) -> None:
    broker = _broker(tmp_path)
    request = {"action": "passkey_lock_status_system", "transaction_id": str(uuid.uuid4())}
    if protocol is not None:
        request["system_protocol"] = protocol
    assert broker.dispatch_system(request, 1) == {"ok": False, "error": "invalid_request"}


@pytest.mark.parametrize("txid", [None, "", "x", "FB4D6F45-EF56-470A-87D2-E5F601FB0EBD", "{dc32557f-b614-4511-b703-139f0f20dc9a}", 7])
def test_refused_without_lower_case_transaction_id(tmp_path, txid) -> None:
    broker = _broker(tmp_path)
    reply = broker.dispatch_system({"action": "passkey_lock_status_system", "system_protocol": 1,
                                    "transaction_id": txid}, 1)
    assert reply == {"ok": False, "error": "invalid_request"}


def test_browser_actions_are_unsupported_on_the_system_path(tmp_path) -> None:
    broker = _broker(tmp_path)
    assert broker.system("get_browser")["error"] == "unsupported_action"
    assert broker.system("passkey_get_browser")["error"] == "unsupported_action"
    assert broker.dispatch_system("not a dict", 1)["error"] == "invalid_request"


def test_browser_dispatcher_does_not_serve_system_actions(tmp_path) -> None:
    broker = _broker(tmp_path)
    for action in ("passkey_create_system", "passkey_get_system", "passkey_cancel_system"):
        reply = broker.dispatch_remote({"action": action, "protocol": 2, "passkey_protocol": 1,
                                        "extension_version": "0.4.0", "origin": ORIGIN, "system_protocol": 1,
                                        "context": json.dumps([17, "d", ORIGIN, "o"])})
        assert reply["error"] == "unsupported_action", action


# -- create and get --------------------------------------------------------------------------

def test_create_then_get_round_trip_verifies(tmp_path) -> None:
    broker = _broker(tmp_path)
    created = broker.create()
    assert created["ok"] is True, created
    _no_key_material(created)
    assert created["attestation_format"] == "none"
    prompt = broker.port.prompts[0]
    assert prompt["mode"] == "create" and prompt["surface"] == "system" and prompt["rp_id"] == RP
    assert prompt["caller"] == CALLER and prompt["profile_name"] == "Redacted"
    assert isinstance(prompt["cancel"], threading.Event) and 0 < prompt["timeout"] <= 25
    assert broker.reauths == [f"Confirm passkey for {RP}"]
    auth_data = b64u_decode(created["authenticator_data"], max_bytes=4096)
    assert auth_data[:32] == hashlib.sha256(RP.encode()).digest()
    assert auth_data[32] & 0x45 == 0x45  # UP, UV, AT
    public_key = _cose_public_key(auth_data)
    credential_id = b64u_decode(created["credential_id"], max_bytes=64)
    assert auth_data[55:71] == credential_id
    records = _records(broker)
    assert len(records) == 1 and records[0]["credential_id"] == created["credential_id"]

    asserted = broker.get(allow_credentials=[created["credential_id"]])
    assert asserted["ok"] is True, asserted
    _no_key_material(asserted)
    assert asserted["credential_id"] == created["credential_id"]
    assert asserted["user_handle"] == b64u_encode(b"user-1") and asserted["user_name"] == "ada"
    signed = b64u_decode(asserted["authenticator_data"], max_bytes=4096)
    signature = b64u_decode(asserted["signature"], max_bytes=4096)
    assert signed[:32] == hashlib.sha256(RP.encode()).digest() and signed[32] & 0x05 == 0x05
    assert _verify(public_key, signature, signed + HASH)  # an RP's check over the client data hash
    assert not _verify(public_key, signature, signed + hashlib.sha256(HASH).digest())
    assert broker.port.prompts[1]["mode"] == "get" and broker.port.prompts[1]["surface"] == "system"
    assert broker.last_secret_use == 1.0


def _browser_create_options():
    return {"rp": {"id": RP, "name": "Example"},
            "user": {"id": b64u_encode(b"user-2"), "name": "bob", "displayName": "Bob"},
            "challenge": b64u_encode(b"c" * 32), "pubKeyCredParams": [{"type": "public-key", "alg": -7}]}


def test_system_get_uses_browser_created_passkey(tmp_path) -> None:
    broker = _broker(tmp_path)
    created = broker.browser("passkey_create_browser", _browser_create_options())
    assert created["ok"] is True, created
    credential = created["credential"]
    asserted = broker.get()
    assert asserted["ok"] is True and asserted["credential_id"] == credential["credential_id"]
    public_key = serialization.load_der_public_key(b64u_decode(credential["public_key_spki"], max_bytes=4096))
    assert _verify(public_key, b64u_decode(asserted["signature"], max_bytes=4096),
                   b64u_decode(asserted["authenticator_data"], max_bytes=4096) + HASH)


def test_browser_get_uses_system_created_passkey(tmp_path) -> None:
    broker = _broker(tmp_path)
    created = broker.create()
    public_key = _cose_public_key(b64u_decode(created["authenticator_data"], max_bytes=4096))
    reply = broker.browser("passkey_get_browser", {"rpId": RP, "challenge": b64u_encode(b"g" * 32)})
    assert reply["ok"] is True, reply
    credential = reply["credential"]
    assert credential["credential_id"] == created["credential_id"]
    client_data = b64u_decode(credential["client_data_json"], max_bytes=4096)
    message = b64u_decode(credential["authenticator_data"], max_bytes=4096) + hashlib.sha256(client_data).digest()
    assert _verify(public_key, b64u_decode(credential["signature"], max_bytes=4096), message)


def test_create_over_limit_returns_item_limit_and_shows_upgrade_without_prompt(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.session.item_limit = 0
    assert broker.create() == {"ok": False, "error": "item_limit"}
    assert broker.port.prompts == [] and broker.reauths == [] and _records(broker) == []
    assert len(broker.port.upgrades) == 1 and broker.port.upgrades[0]["limit"] == 0


def test_excluded_credential_returns_invalid_state(tmp_path) -> None:
    broker = _broker(tmp_path)
    first = broker.create()
    broker.port.prompts.clear(); broker.reauths.clear()
    reply = broker.create(exclude_credentials=[b64u_encode(b"other"), first["credential_id"]])
    assert reply == {"ok": False, "error": "invalid_state"}
    assert broker.port.prompts[0]["excluded"] is True and broker.reauths == []
    assert len(_records(broker)) == 1  # no new passkey
    # An exclude list naming nothing in the vault creates as usual.
    broker._system_state().cooldowns.clear()
    assert broker.create(exclude_credentials=[b64u_encode(b"other")])["ok"] is True


def test_get_without_candidate_returns_not_found_without_prompt(tmp_path) -> None:
    broker = _broker(tmp_path)
    assert broker.get() == {"ok": False, "error": "not_found"}
    created = broker.create()
    broker.port.prompts.clear()
    assert broker.get(allow_credentials=[b64u_encode(b"someone-else")])["error"] == "not_found"
    assert broker.get(rp_id="other.test")["error"] == "not_found"
    assert broker.port.prompts == []
    assert broker.get(allow_credentials=[created["credential_id"]])["ok"] is True


def test_empty_allow_list_offers_only_discoverable_passkeys(tmp_path) -> None:
    broker = _broker(tmp_path)
    created = broker.create()
    record = _records(broker)[0]
    # Store a second, non-discoverable copy and drop the discoverable one.
    fields = {key: record[key] for key in ("relying_party_id", "user_handle", "credential_id", "private_key",
                                           "algorithm", "user_name")}
    broker.session.items.create_passkey("Hidden", discoverable=False, **fields)
    assert broker.session.items.delete_item(record["id"])
    assert [r["discoverable"] for r in _records(broker)] == [False]
    broker.port.prompts.clear()
    assert broker.get() == {"ok": False, "error": "not_found"}
    assert broker.port.prompts == []
    assert broker.get(allow_credentials=[created["credential_id"]])["ok"] is True


def test_discouraged_skips_reauth(tmp_path) -> None:
    broker = _broker(tmp_path)
    created = broker.create(user_verification="discouraged")
    assert created["ok"] is True and broker.reauths == []
    assert b64u_decode(created["authenticator_data"], max_bytes=4096)[32] & 0x04 == 0
    asserted = broker.get(user_verification="discouraged")
    assert asserted["ok"] is True and broker.reauths == []
    assert b64u_decode(asserted["authenticator_data"], max_bytes=4096)[32] & 0x04 == 0


def test_required_is_never_signed_without_verification(tmp_path) -> None:
    broker = _broker(tmp_path)
    assert broker.create()["ok"] is True
    broker.reauth_ok = False
    broker._system_state().cooldowns.clear()
    assert broker.get() == {"ok": False, "error": "user_cancelled"}
    broker._system_state().cooldowns.clear()
    assert broker.create(user_name="eve") == {"ok": False, "error": "user_cancelled"}
    assert len(_records(broker)) == 1
    # Even if the verification step reported "no UV" instead of failing, "required" is refused.
    broker.reauth_ok = True
    broker._passkey_verify = lambda rp_id, uv, lease: False
    broker._system_state().cooldowns.clear()
    assert broker.get() == {"ok": False, "error": "user_cancelled"}


def test_declined_prompt_cools_down_the_rp(tmp_path, monkeypatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(system_module.time, "monotonic", lambda: clock[0])
    broker = _broker(tmp_path)
    broker.port.respond = lambda kw: ("cancel", None)
    assert broker.create()["error"] == "user_cancelled"
    assert broker.create()["error"] == "user_cancelled"
    assert len(broker.port.prompts) == 1  # the second answer came without a window
    clock[0] += 10.5
    broker.port.respond = lambda kw: ("browser", None)  # no browser fallback here: a cancel
    assert broker.create()["error"] == "user_cancelled"
    assert len(broker.port.prompts) == 2 and _records(broker) == []


@pytest.mark.parametrize("rp_id", ["com", "github.io", "co.uk", "Example.test", "127.0.0.1", "example.test."])
def test_public_suffix_and_malformed_rp_ids_are_refused(tmp_path, rp_id) -> None:
    broker = _broker(tmp_path)
    assert broker.create(rp_id=rp_id) == {"ok": False, "error": "invalid_request"}
    assert broker.get(rp_id=rp_id) == {"ok": False, "error": "invalid_request"}
    assert broker.port.prompts == []


def test_es256_missing_is_not_supported(tmp_path) -> None:
    broker = _broker(tmp_path)
    assert broker.create(algorithms=[-257]) == {"ok": False, "error": "not_supported"}
    assert broker.port.prompts == []


# -- locked vault ------------------------------------------------------------------------------

def test_locked_vault_decline_returns_locked_declined_and_cools_down(tmp_path, monkeypatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(system_module.time, "monotonic", lambda: clock[0])
    broker = _broker(tmp_path)
    broker.locked, broker.unlock_ok = True, False
    assert broker.get() == {"ok": False, "error": "locked_declined"}
    assert broker.unlocks == [1] and broker.port.prompts == []
    assert broker.create() == {"ok": False, "error": "locked_declined"}
    assert broker.get() == {"ok": False, "error": "locked_declined"}
    assert broker.unlocks == [1]  # no second window during the cooldown
    assert broker.get(rp_id="other.test")["error"] == "locked_declined"
    assert broker.unlocks == [1, 1]  # another RP gets its own single window
    clock[0] += 10.5
    assert broker.create()["error"] == "locked_declined"
    assert broker.unlocks == [1, 1, 1] and _records(broker) == []


def test_locked_vault_unlock_then_prompt(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.locked = True
    created = broker.create()
    assert created["ok"] is True and broker.unlocks == [1] and len(broker.port.prompts) == 1
    broker.locked = True
    assert broker.get()["ok"] is True and broker.unlocks == [1, 1]


def test_lock_status_needs_no_vault_lock(tmp_path) -> None:
    broker = _broker(tmp_path)

    def no_ui(function, timeout=0):
        raise AssertionError("lock status must not wait for the vault lock")
    broker.run_on_ui = no_ui
    broker._remote_busy = True  # an open prompt does not hold it up either
    assert broker.system("passkey_lock_status_system") == {"ok": True, "locked": False}
    broker.locked = True
    assert broker.system("passkey_lock_status_system") == {"ok": True, "locked": True}
    assert broker.unlocks == [] and broker.port.prompts == []


def test_credentials_has_no_key_material(tmp_path) -> None:
    broker = _broker(tmp_path)
    first = broker.create()
    broker.browser("passkey_create_browser", _browser_create_options())
    reply = broker.system("passkey_credentials_system")
    assert reply["ok"] is True and len(reply["credentials"]) == 2
    text = json.dumps(reply)
    assert "private_key" not in text
    for record in _records(broker):
        assert record["private_key"] not in text
    entry = next(e for e in reply["credentials"] if e["credential_id"] == first["credential_id"])
    assert entry == {"credential_id": first["credential_id"], "rp_id": RP, "rp_name": "Example",
                     "user_id": b64u_encode(b"user-1"), "user_name": "ada", "user_display_name": "Ada"}
    assert broker.port.prompts[-1]["mode"] == "create"  # no prompt for the list


def test_credentials_locked_returns_locked(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.create()
    broker.locked = True
    assert broker.system("passkey_credentials_system") == {"ok": False, "error": "locked"}
    assert broker.unlocks == []


# -- concurrency, cancel, deadline --------------------------------------------------------------

def test_second_request_busy(tmp_path) -> None:
    broker = _broker(tmp_path)
    inner = {}

    def respond(kw):
        inner["get"] = broker.get()
        inner["create"] = broker.create(user_name="bob")
        inner["browser"] = broker.browser("passkey_create_browser", _browser_create_options())
        inner["status"] = broker.system("passkey_lock_status_system")
        return ("approve", None)
    broker.port.respond = respond
    assert broker.create()["ok"] is True
    assert inner["get"]["error"] == inner["create"]["error"] == inner["browser"]["error"] == "busy"
    assert inner["status"] == {"ok": True, "locked": False}
    assert len(broker.port.prompts) == 1 and len(_records(broker)) == 1
    assert broker._remote_busy is False


def test_duplicate_open_transaction_is_busy(tmp_path) -> None:
    broker = _broker(tmp_path)
    txid = str(uuid.uuid4())
    inner = {}

    def respond(kw):
        inner["dup"] = broker.dispatch_system({"action": "passkey_get_system", "system_protocol": 1,
                                               "transaction_id": txid, "rp_id": RP,
                                               "client_data_hash": b64u_encode(HASH),
                                               "user_verification": "required"}, 1)
        return ("cancel", None)
    broker.port.respond = respond
    broker.dispatch_system({"action": "passkey_create_system", "system_protocol": 1, "transaction_id": txid,
                            "rp_id": RP, "user_id": b64u_encode(b"u"), "client_data_hash": b64u_encode(HASH),
                            "algorithms": [-7], "user_verification": "required"}, 1)
    assert inner["dup"] == {"ok": False, "error": "busy"}


def test_cancel_answers_while_prompt_is_open_and_nothing_is_stored(tmp_path) -> None:
    broker = _broker(tmp_path)
    txid = str(uuid.uuid4())
    opened = threading.Event()
    seen = {}

    def respond(kw):  # blocks like the real prompt until its cancel Event is set
        opened.set()
        seen["cancelled"] = kw["cancel"].wait(5)
        return ("approve", None)  # a click racing the cancel must still not store anything
    broker.port.respond = respond
    result = {}
    worker = threading.Thread(target=lambda: result.setdefault("reply", broker.dispatch_system(
        {"action": "passkey_create_system", "system_protocol": 1, "transaction_id": txid, "rp_id": RP,
         "user_id": b64u_encode(b"u"), "client_data_hash": b64u_encode(HASH), "algorithms": [-7],
         "user_verification": "required"}, 1)))
    worker.start()
    assert opened.wait(5)
    cancel = {"action": "passkey_cancel_system", "system_protocol": 1, "transaction_id": txid}
    assert broker.dispatch_system(cancel, 1) == {"ok": True}
    worker.join(5)
    assert not worker.is_alive() and seen["cancelled"] is True
    assert result["reply"] == {"ok": False, "error": "user_cancelled"}
    assert _records(broker) == [] and broker.reauths == [] and broker._remote_busy is False
    # An unknown id still answers ok, and a cancel that overtakes its request cancels it.
    early = str(uuid.uuid4())
    assert broker.dispatch_system({**cancel, "transaction_id": early}, 1) == {"ok": True}
    broker._system_state().cooldowns.clear()
    reply = broker.dispatch_system({"action": "passkey_get_system", "system_protocol": 1, "transaction_id": early,
                                    "rp_id": RP, "client_data_hash": b64u_encode(HASH),
                                    "user_verification": "required"}, 1)
    assert reply == {"ok": False, "error": "user_cancelled"}


def test_late_approval_after_deadline_is_dropped(tmp_path, monkeypatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(system_module.time, "monotonic", lambda: clock[0])
    broker = _broker(tmp_path)

    def slow(kw):
        clock[0] += 25.5
        return ("approve", kw["accounts"][0].get("id"))
    broker.port.respond = slow
    assert broker.create() == {"ok": False, "error": "user_cancelled"}
    assert _records(broker) == [] and broker.reauths == []
    # Verification that ends past the deadline drops the signature too.
    broker.port.respond = lambda kw: ("approve", kw["accounts"][0].get("id"))
    clock[0] += 11
    assert broker.create()["ok"] is True
    broker.port.prompts.clear()

    def slow_reauth(title, lease, *, allow_hello=False, fresh=False):
        clock[0] += 26
        return True
    broker.reauthenticate = slow_reauth
    assert broker.get() == {"ok": False, "error": "user_cancelled"}
    assert len(broker.port.prompts) == 1


def test_cancel_during_unlock_wait_ends_it_and_frees_busy(tmp_path) -> None:
    broker = _broker(tmp_path)
    broker.locked = True
    txid = str(uuid.uuid4())
    waiting = threading.Event()
    seen = {}

    def unlock_wait(stop=None):  # polls ``stop`` like WebAgentHost.ensure_unlocked
        waiting.set()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if stop is not None and stop():
                seen["stopped"] = True
                broker.locked = False  # the user unlocks just too late: the request must still not run
                return False
            time.sleep(0.01)
        return False
    broker.ensure_unlocked = unlock_wait
    result = {}
    started = time.monotonic()
    worker = threading.Thread(target=lambda: result.setdefault("reply", broker.dispatch_system(
        {"action": "passkey_get_system", "system_protocol": 1, "transaction_id": txid, "rp_id": RP,
         "client_data_hash": b64u_encode(HASH), "user_verification": "required"}, 1)))
    worker.start()
    assert waiting.wait(5)
    assert broker._remote_busy is True
    assert broker.dispatch_system({"action": "passkey_cancel_system", "system_protocol": 1,
                                   "transaction_id": txid}, 1) == {"ok": True}
    worker.join(5)
    assert not worker.is_alive() and time.monotonic() - started < 3
    assert seen == {"stopped": True} and result["reply"] == {"ok": False, "error": "user_cancelled"}
    assert broker._remote_busy is False and broker.port.prompts == [] and broker.reauths == []
    assert _records(broker) == []


def test_web_host_unlock_wait_honours_stop() -> None:
    from localvault.web.host import WebAgentHost

    host = WebAgentHost.__new__(WebAgentHost)
    host._controller = SimpleNamespace(is_unlocked=lambda: False, startup=None)
    host._popup = None
    host._unlock_timeout = 30.0
    host._closing = False
    host._popup_cancelled = threading.Event()
    host._holding = threading.local()
    host.raise_window = lambda: None
    host._bus = SimpleNamespace(emit=lambda name, detail: None)
    started = time.monotonic()
    assert host.ensure_unlocked(stop=lambda: time.monotonic() - started > 0.2) is False
    assert time.monotonic() - started < 2


def test_late_unlock_is_dropped(tmp_path, monkeypatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(system_module.time, "monotonic", lambda: clock[0])
    broker = _broker(tmp_path)
    broker.locked = True

    def slow_unlock(stop=None):
        clock[0] += 30
        broker.locked = False
        return True
    broker.ensure_unlocked = slow_unlock
    assert broker.create() == {"ok": False, "error": "user_cancelled"}
    assert broker.port.prompts == [] and _records(broker) == []


def test_errors_carry_a_fixed_code_only(tmp_path) -> None:
    broker = _broker(tmp_path)

    def boom(kw):
        raise RuntimeError("secret-material-in-message")
    broker.port.respond = boom
    reply = broker.create()
    assert reply == {"ok": False, "error": "invalid_request"}
    assert broker._remote_busy is False and _records(broker) == []
