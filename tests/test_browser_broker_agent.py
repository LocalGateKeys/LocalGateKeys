"""AI agent fills through the browser broker (fill_grant_browser, agent_gate)."""
from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace

import pytest

from broker_host import BrokerHostBase as RuntimeActions
from localvault.agent_gate import AgentGate, ClientInfo, Refusal
from localvault.browser_broker import BrowserBroker
from localvault.session_guard import SessionGuard
from localvault.settings import AppSettings
from localvault.vault import create_vault
from localvault.web.host import WebAgentHost

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
CLIENT = ClientInfo("pid:session-a", "Claude Code", "claude.exe")
OTHER = ClientInfo("pid:session-b", "Other", "node.exe")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))


class _Ui:
    def confirm_agent(self, request):
        return True


class _GateView:
    """The vault as the gate sees it through AgentGateService (passkey metadata, never key material)."""

    def __init__(self, session) -> None:
        self._session = session

    def __getattr__(self, name):
        return getattr(self._session, name)

    def passkeys(self):
        return self._session.item_service.passkey_metadata()


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
        self.reauths: list[bool] = []
        gate = AgentGate(lambda: _GateView(session), SimpleNamespace(agents_enabled=True), _Ui(), None,
                         is_pro=lambda: True, fill_wait=5.0)
        self.agent_gate_service = SimpleNamespace(gate=gate)

    def ensure_unlocked(self):
        return self._session_available()

    def run_on_ui(self, function, timeout=0):
        return function()

    def refresh_entries(self):
        return None

    def _touch_secret(self):
        self.last_secret_use = 1.0

    def reauthenticate(self, *args, allow_hello=False, fresh=False):
        self.reauths.append(fresh)
        return True

    def passkey_prompt(self, mode, *, origin, rp_id, accounts, excluded):
        self.prompts.append({"mode": mode, "accounts": accounts})
        return "approve", accounts[0]["id"]

    def request(self, action: str, *, origin: str, **payload):
        return self.dispatch_remote({
            "action": action, "protocol": 2, "extension_version": "0.3.3", "origin": origin,
            "context": json.dumps([17, "document-redacted", origin, "operation-redacted"]), **payload})


def _web(session, origin, username, password, *, agents=True):
    entry_id = session.upsert_web(origin=origin, username=username, password=password)
    if agents:
        session.set_ai_agent_use(entry_id, True)  # "AI agents may use this login" (off by default)
    return entry_id


def _vault(tmp_path, *, strict=False, second=False):
    session = create_vault(tmp_path / "agent.json", "redacted-master", kdf_overrides=KDF)
    entry_id = _web(session, "https://login.example.com", "agent-user", "agent-pw")
    if second:
        _web(session, "https://login.example.com", "second-user", "second-pw")
    if strict:
        for row in session._require_payload()["entries"]:
            row["policy"] = {**(row.get("policy") or {}), "require_master_password": True}
    return session, entry_id


def _arm(broker, client=CLIENT, site="example.com"):
    """request_login, then fill_login on a thread (it waits for the page); returns (grant, result holder)."""
    gate = broker.agent_gate_service.gate
    grant = gate.request_login(client, site, "test")
    holder: dict = {}
    thread = threading.Thread(target=lambda: holder.update(result=gate.fill_login(client, grant.id)))
    thread.start()
    for _ in range(200):
        if gate._grants[grant.id].armed_until:
            break
        threading.Event().wait(0.01)
    return grant, holder, thread


def test_grant_fills_on_a_subdomain_of_the_approved_site(tmp_path) -> None:
    session, entry_id = _vault(tmp_path)
    broker = _Broker(session)
    grant, holder, thread = _arm(broker)
    offer = broker.request("fill_grant_browser", origin="https://login.example.com")
    thread.join(5)
    assert offer["ok"] and [c["entry_id"] for c in offer["choices"]] == [entry_id]
    assert "agent-pw" not in json.dumps(offer)
    # The user still picks the login with a click in the picker; the agent learns only that the page took it.
    assert holder["result"]["filled"] is False and "agent-pw" not in json.dumps(holder["result"])
    released = broker.request("get_browser", origin="https://login.example.com", grant=offer["grant"],
                              entry_id=entry_id, gesture_nonce=offer["gesture_nonce"])
    assert released["ok"] and released["credential"]["password"] == "agent-pw"


def test_lookalike_origin_is_refused(tmp_path) -> None:
    session, _entry = _vault(tmp_path)
    broker = _Broker(session)
    _grant, _holder, thread = _arm(broker)
    assert broker.request("fill_grant_browser", origin="https://examp1e.com")["ok"] is False
    assert broker.request("fill_grant_browser", origin="http://login.example.com")["ok"] is False
    assert broker.request("fill_grant_browser", origin="https://login.example.com")["ok"] is True
    thread.join(5)


def test_second_use_is_refused(tmp_path) -> None:
    session, _entry = _vault(tmp_path)
    broker = _Broker(session)
    grant, holder, thread = _arm(broker)
    assert broker.request("fill_grant_browser", origin="https://login.example.com")["ok"] is True
    thread.join(5)
    assert broker.request("fill_grant_browser", origin="https://login.example.com")["ok"] is False
    assert broker.agent_gate_service.gate.fill_login(CLIENT, grant.id) == Refusal("used")


def test_another_clients_grant_is_refused(tmp_path) -> None:
    session, _entry = _vault(tmp_path)
    gate = _Broker(session).agent_gate_service.gate
    grant = gate.request_login(CLIENT, "example.com", "test")
    assert gate.fill_login(OTHER, grant.id) == Refusal("not_yours")


def test_unarmed_grant_never_fills(tmp_path) -> None:
    session, _entry = _vault(tmp_path)
    broker = _Broker(session)
    broker.agent_gate_service.gate.request_login(CLIENT, "example.com", "test")  # approved, never armed
    assert broker.request("fill_grant_browser", origin="https://login.example.com")["ok"] is False


def test_strict_login_is_never_matched(tmp_path) -> None:
    session, _entry = _vault(tmp_path, strict=True)
    broker = _Broker(session)
    assert broker.agent_gate_service.gate.request_login(CLIENT, "example.com", "x") == Refusal("not_found")


def test_several_logins_open_the_picker_for_the_user(tmp_path) -> None:
    session, _entry = _vault(tmp_path, second=True)
    broker = _Broker(session)
    _grant, holder, thread = _arm(broker)
    offer = broker.request("fill_grant_browser", origin="https://login.example.com")
    thread.join(5)
    assert offer["ok"] and len(offer["choices"]) == 2
    assert holder["result"]["filled"] is False  # the user picks; the agent is not told which


def test_grant_offers_only_the_approved_login_on_the_approved_host(tmp_path) -> None:
    session = create_vault(tmp_path / "agent.json", "redacted-master", kdf_overrides=KDF)
    app_id = _web(session, "https://app.example.com", "app-user", "app-pw")
    _web(session, "https://files.example.com", "files-user", "files-pw")
    broker = _Broker(session)
    _grant, _holder, thread = _arm(broker, site="app.example.com")
    assert broker.request("fill_grant_browser", origin="https://files.example.com")["ok"] is False
    offer = broker.request("fill_grant_browser", origin="https://app.example.com")
    thread.join(5)
    assert offer["ok"] and [c["entry_id"] for c in offer["choices"]] == [app_id]


def test_grant_never_offers_a_login_saved_after_the_approval(tmp_path) -> None:
    session, entry_id = _vault(tmp_path)
    broker = _Broker(session)
    _grant, _holder, thread = _arm(broker)
    _web(session, "https://login.example.com", "late-user", "late-pw")
    offer = broker.request("fill_grant_browser", origin="https://login.example.com")
    thread.join(5)
    assert offer["ok"] and [c["entry_id"] for c in offer["choices"]] == [entry_id]


# ---- Opt-in and passkey preference.

def _passkey(broker, user_name="agent-user"):
    """Register a passkey for example.com through the normal broker path (the owner approves it)."""
    from localvault.passkeys import b64u_encode

    options = {"rp": {"id": "example.com", "name": "Example"},
               "user": {"id": b64u_encode(user_name.encode()), "name": user_name, "displayName": user_name},
               "challenge": b64u_encode(b"c" * 32), "pubKeyCredParams": [{"type": "public-key", "alg": -7}]}
    reply = broker.request("passkey_create_browser", origin="https://login.example.com", options=options,
                           passkey_protocol=1, user_activation=True)
    assert reply["ok"] is True, reply
    broker.prompts.clear()
    broker.reauths.clear()
    return reply["credential"]["credential_id"]


def test_a_login_not_opted_in_is_not_found_and_never_asked(tmp_path) -> None:
    session = create_vault(tmp_path / "agent.json", "redacted-master", kdf_overrides=KDF)
    _web(session, "https://login.example.com", "agent-user", "agent-pw", agents=False)
    broker = _Broker(session)
    gate = broker.agent_gate_service.gate
    assert gate.request_login(CLIENT, "example.com", "x") == Refusal("not_found")
    assert gate.request_login(CLIENT, "nowhere.example", "x") == Refusal("not_found")
    assert gate.list_sites(CLIENT) == []


def test_a_login_turned_off_after_the_approval_is_not_offered(tmp_path) -> None:
    session, entry_id = _vault(tmp_path)
    broker = _Broker(session)
    _grant, holder, thread = _arm(broker)
    session.set_ai_agent_use(entry_id, False)
    offer = broker.request("fill_grant_browser", origin="https://login.example.com")
    thread.join(5)
    assert offer == {"ok": False, "error": "not_found"}
    assert holder["result"]["filled"] is False


def test_a_passkey_login_signs_in_with_the_passkey_and_never_fills_the_password(tmp_path) -> None:
    session, _entry_id = _vault(tmp_path)
    broker = _Broker(session)
    credential_id = _passkey(broker)
    gate = broker.agent_gate_service.gate
    grant = gate.request_login(CLIENT, "login.example.com", "x")
    assert grant.method == "passkey" and grant.passkey_ids == {credential_id}
    assert grant.hosts == {"login.example.com"}
    holder: dict = {}
    thread = threading.Thread(target=lambda: holder.update(result=gate.fill_login(CLIENT, grant.id)))
    thread.start()
    offer = broker.request("fill_grant_browser", origin="https://login.example.com")
    assert offer["ok"] is False and offer["error"] == "agent_passkey" and offer["message"]
    assert "agent-pw" not in json.dumps(offer)
    from localvault.passkeys import b64u_encode

    reply = broker.request("passkey_get_browser", origin="https://login.example.com", passkey_protocol=1,
                           user_activation=True, options={"rpId": "example.com", "challenge": b64u_encode(b"g" * 32)})
    thread.join(5)
    assert reply["ok"] is True, reply
    # The owner's passkey dialog and a fresh user verification still ran; the agent approval replaced neither.
    assert [p["mode"] for p in broker.prompts] == ["get"] and broker.reauths == [True]
    assert holder["result"] == {"filled": True, "site": "example.com", "method": "passkey"}
    assert "agent-pw" not in json.dumps(holder["result"])
    # One assertion: the grant is used up.
    assert gate.take_passkey_for_origin("https://login.example.com", [credential_id]) is None


def test_a_password_grant_skips_a_login_that_got_a_passkey_after_the_approval(tmp_path) -> None:
    session, _entry_id = _vault(tmp_path)
    broker = _Broker(session)
    _grant, holder, thread = _arm(broker)
    _passkey(broker)
    offer = broker.request("fill_grant_browser", origin="https://login.example.com")
    thread.join(5)
    assert offer == {"ok": False, "error": "not_found"}
    assert holder["result"]["filled"] is False



# ---- Plain http on loopback (a local dev server) and the app's real vault lock.

class _LockedBroker(_Broker):
    """The app's run_on_ui (web.host): broker requests run under the non-reentrant vault lock, and the gate's
    activity record goes through run_on_ui as AgentGateService._record does."""

    run_on_ui = WebAgentHost.run_on_ui

    def __init__(self, session) -> None:
        super().__init__(session)
        self._controller = SimpleNamespace(vault_lock=threading.Lock())
        self._holding = threading.local()
        self.records: list[tuple] = []
        gate = self.agent_gate_service.gate
        gate._activity = lambda event, result, item_id=None: self.run_on_ui(
            lambda: self.records.append((event, result, item_id)), timeout=5.0)


@pytest.mark.parametrize("site", ["http://127.0.0.1:8765", "127.0.0.1"])
def test_grant_fills_on_a_loopback_http_page_with_a_port_without_waiting_on_the_vault_lock(tmp_path, site) -> None:
    session = create_vault(tmp_path / "agent.json", "redacted-master", kdf_overrides=KDF)
    entry_id = _web(session, "http://127.0.0.1:8765", "local-user", "local-pw")
    broker = _LockedBroker(session)
    grant, holder, thread = _arm(broker, site=site)
    assert not isinstance(grant, Refusal), grant
    assert grant.hosts == {"127.0.0.1"}
    page = "http://127.0.0.1:8765"
    offer = broker.request("fill_grant_browser", origin=page, url=page + "/login")
    thread.join(5)
    assert offer["ok"], offer
    assert [c["entry_id"] for c in offer["choices"]] == [entry_id]
    started = time.monotonic()
    released = broker.request("get_browser", origin=page, url=page + "/login", grant=offer["grant"],
                              entry_id=entry_id, gesture_nonce=offer["gesture_nonce"])
    # The release used to wait out the 5 s lock timeout (its own thread held the lock) and lost the activity row.
    assert time.monotonic() - started < 2
    assert released["ok"] and released["credential"]["password"] == "local-pw", released
    assert ("agent.fill", "ok", entry_id) in broker.records
    assert broker.request("validate_browser", origin=page, grant=offer["grant"], entry_id=entry_id)["ok"] is True
    # Still single use and origin-bound.
    assert broker.request("fill_grant_browser", origin=page)["ok"] is False


def test_loopback_grant_never_fills_another_host_or_scheme(tmp_path) -> None:
    session = create_vault(tmp_path / "agent.json", "redacted-master", kdf_overrides=KDF)
    _web(session, "http://127.0.0.1:8765", "local-user", "local-pw")
    broker = _LockedBroker(session)
    _grant, _holder, thread = _arm(broker, site="http://127.0.0.1:8765")
    assert broker.request("fill_grant_browser", origin="http://localhost:8765")["ok"] is False
    assert broker.request("fill_grant_browser", origin="http://127.0.0.2:8765")["ok"] is False
    assert broker.request("fill_grant_browser", origin="http://127.0.0.1:8765")["ok"] is True
    thread.join(5)


def test_run_on_ui_is_reentrant_only_on_the_thread_holding_the_lock() -> None:
    host = WebAgentHost.__new__(WebAgentHost)
    host._controller = SimpleNamespace(vault_lock=threading.Lock())
    host._holding = threading.local()
    assert host.run_on_ui(lambda: host.run_on_ui(lambda: "inner", timeout=0.5), timeout=1) == "inner"
    errors: list[BaseException] = []

    def other_thread() -> None:
        try:
            host.run_on_ui(lambda: None, timeout=0.2)
        except TimeoutError as exc:
            errors.append(exc)
    worker = threading.Thread(target=other_thread)
    host.run_on_ui(lambda: (worker.start(), worker.join(2)), timeout=1)
    assert len(errors) == 1  # another thread still waits for the lock
