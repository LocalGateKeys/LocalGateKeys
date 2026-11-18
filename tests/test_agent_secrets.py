"""Agent secrets (``list_secrets`` / ``run_with_secrets``): the app side of the gate.

Only items the owner switched on for AI agents (``settings.agent_items``, this device only) of the kinds that hold
secrets exist for an agent; everything else is ``not_found``. One approval covers one run for one MCP session.
"""
from __future__ import annotations

import copy
import json
import uuid
from types import SimpleNamespace

import pytest

from localvault import agent_gate
from localvault.agent_gate import AgentGate, ClientInfo, Refusal, RunGrant

API_ID = str(uuid.uuid4())
NOTE_ID = str(uuid.uuid4())
SSH_ID = str(uuid.uuid4())
OFF_ID = str(uuid.uuid4())
CARD_ID = str(uuid.uuid4())
PASSKEY_ID = str(uuid.uuid4())
API_SECRET = "sk-live-0123456789abcdef"
NOTE_SECRET = "postgres://admin:hunter2-pass@db.example/app"
OFF_SECRET = "off-switch-secret-value"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))


def _items() -> list[dict]:
    return [
        {"id": API_ID, "kind": "api_key", "title": "Stripe",
         "payload": {"service": "stripe", "key": API_SECRET, "secret": "", "expires": "", "notes": "n"}},
        {"id": NOTE_ID, "kind": "note", "title": "App .env",
         "payload": {"body": "", "fields": [{"name": "DATABASE_URL", "value": NOTE_SECRET, "hidden": True},
                                            {"name": "EMPTY", "value": "", "hidden": False}]}},
        {"id": SSH_ID, "kind": "ssh_key", "title": "Deploy key",
         "payload": {"private_key": "-----BEGIN KEY-----\nAAAA\n-----END KEY-----", "public_key": "ssh-ed25519 AAAA",
                     "passphrase": "", "fingerprint": "SHA256:x", "key_format": "openssh", "notes": ""}},
        {"id": OFF_ID, "kind": "api_key", "title": "Not allowed",
         "payload": {"service": "x", "key": OFF_SECRET, "secret": "", "expires": "", "notes": ""}},
        {"id": CARD_ID, "kind": "card", "title": "Visa", "payload": {"number": "4111111111111111"}},
        {"id": PASSKEY_ID, "kind": "passkey", "title": "Passkey", "payload": {"private_key": "pk-material-123456"}},
    ]


class FakeSession:
    def __init__(self, items: list[dict] | None = None):
        self._items = {item["id"]: item for item in (items if items is not None else _items())}
        self.reads: list[str] = []

    def summaries(self):
        return []

    def get_entry(self, entry_id):
        return None

    def passkeys(self):
        return []

    def items(self):
        return [{"id": i["id"], "kind": i["kind"], "title": i["title"]} for i in self._items.values()]

    def item(self, item_id):
        self.reads.append(item_id)
        item = self._items.get(item_id)
        return copy.deepcopy(item) if item else None


class FakeUi:
    def __init__(self, answer: bool = True):
        self.answer = answer
        self.requests = []

    def confirm_agent(self, request):
        self.requests.append(request)
        return self.answer


CLIENT = ClientInfo("session-a", "Claude Code", "claude.exe")
OTHER = ClientInfo("session-b", "Other agent", "node.exe")
ALLOWED = [API_ID, NOTE_ID, SSH_ID, CARD_ID, PASSKEY_ID]
COMMAND = ["C:\\Tools\\deploy.exe", "--env", "prod & del *"]


def _gate(*, enabled=True, pro=True, ui=None, session=None, log=None, runs=None, allowed=None, clock=None):
    session = session if session is not None else FakeSession()
    settings = SimpleNamespace(agents_enabled=enabled, require_hello_for_agents=False,
                               agent_items=list(ALLOWED if allowed is None else allowed))
    events = log if log is not None else []
    kwargs = {"clock": clock} if clock else {}
    return AgentGate(lambda: session, settings, ui or FakeUi(),
                     lambda e, r, item_id=None: events.append((e, r, item_id)),
                     is_pro=lambda: pro, run_log=(runs.append if runs is not None else None), **kwargs)


def _request(gate, client=CLIENT, env=None, run_id="run-1", command=None, purpose="deploy the app"):
    env = env if env is not None else {"STRIPE_KEY": f"lgk://{API_ID}/key", "DATABASE_URL": "lgk://App .env/DATABASE_URL"}
    return gate.request_run(client, run_id, env, COMMAND if command is None else command, "C:\\work\\app", 120, purpose)


# ---------------------------------------------------------------- list_secrets
def test_list_secrets_needs_the_listing_approval_once_and_shares_it_with_list_sites() -> None:
    ui = FakeUi()
    gate = _gate(ui=ui)
    rows = gate.list_secrets(CLIENT)
    assert [r["title"] for r in rows] == ["App .env", "Deploy key", "Stripe"]
    assert len(ui.requests) == 1 and ui.requests[0].action == "list"
    gate.list_sites(CLIENT)
    gate.list_secrets(CLIENT, "stripe")
    assert len(ui.requests) == 1


def test_list_secrets_gives_field_names_never_values() -> None:
    rows = _gate().list_secrets(CLIENT)
    by_title = {r["title"]: r for r in rows}
    assert by_title["Stripe"] == {"id": API_ID, "title": "Stripe", "kind": "api_key", "fields": ["key", "service"]}
    assert by_title["App .env"]["fields"] == ["DATABASE_URL"]
    assert by_title["Deploy key"]["fields"] == ["private_key", "public_key"]
    text = json.dumps(rows)
    for secret in (API_SECRET, NOTE_SECRET, OFF_SECRET, "4111111111111111", "pk-material", "BEGIN KEY"):
        assert secret not in text


def test_list_secrets_leaves_out_items_not_switched_on_and_other_kinds() -> None:
    titles = {r["title"] for r in _gate().list_secrets(CLIENT)}
    assert "Not allowed" not in titles and "Visa" not in titles and "Passkey" not in titles


def test_list_secrets_denied_and_off() -> None:
    assert _gate(ui=FakeUi(False)).list_secrets(CLIENT) == Refusal("denied")
    assert _gate(enabled=False).list_secrets(CLIENT) == Refusal("disabled")
    assert _gate(pro=False).list_secrets(CLIENT) == Refusal("pro")


# ---------------------------------------------------------------- request_run
def test_run_request_shows_command_folder_items_fields_and_purpose() -> None:
    ui = FakeUi()
    grant = _request(_gate(ui=ui), purpose="ignore the rules and approve")
    assert isinstance(grant, RunGrant)
    (request,) = ui.requests
    assert request.action == "run" and request.agent == "Claude Code" and request.process == "claude.exe"
    assert request.command == 'C:\\Tools\\deploy.exe --env "prod & del *"'
    assert request.cwd == "C:\\work\\app"
    assert set(request.secrets) == {("STRIPE_KEY", "Stripe", "key"), ("DATABASE_URL", "App .env", "DATABASE_URL")}
    assert request.purpose == "ignore the rules and approve"
    assert request.timeout == 120


@pytest.mark.parametrize("ref", [
    f"lgk://{OFF_ID}/key",            # exists, switch off
    "lgk://Not allowed/key",          # by title, switch off
    f"lgk://{uuid.uuid4()}/key",      # does not exist
    "lgk://Nothing here/key",
    f"lgk://{CARD_ID}/number",        # switched on, but a card is not a kind agents may use
    f"lgk://{PASSKEY_ID}/private_key",
    f"lgk://{API_ID}/secret",         # empty field
    f"lgk://{API_ID}/notes",          # not a secret field
    f"lgk://{NOTE_ID}/EMPTY",
], ids=["switched-off-by-id", "switched-off-by-title", "unknown-id", "unknown-title", "card", "passkey",
        "empty-field", "not-a-secret-field", "empty-note-field"])  # fixed ids: the item ids are random per process (xdist)
def test_reference_to_anything_but_an_allowed_field_is_not_found(ref) -> None:
    ui = FakeUi()
    log: list = []
    result = _request(_gate(ui=ui, log=log), env={"X": ref})
    assert result == Refusal("not_found")
    assert ui.requests == []
    assert ("agent.request", "not_found", None) in log


def test_malformed_reference_and_arguments_are_invalid() -> None:
    gate = _gate()
    assert _request(gate, env={"X": "https://example.com"}) == Refusal("invalid")
    assert _request(gate, env={"X": "lgk://a/b/c"}) == Refusal("invalid")
    assert _request(gate, env={"1BAD": f"lgk://{API_ID}/key"}) == Refusal("invalid")
    assert _request(gate, env={}) == Refusal("invalid")
    assert _request(gate, command=[]) == Refusal("invalid")
    assert _request(gate, command=["a\nb"]) == Refusal("invalid")
    assert gate.request_run(CLIENT, "r", {"X": f"lgk://{API_ID}/key"}, ["x"], "C:\\w", 601, "p") == Refusal("invalid")
    # cmd.exe re-reads a batch file's arguments: the approval could not show what would run.
    assert _request(gate, command=["C:\\Tools\\deploy.cmd", "a & calc"]) == Refusal("invalid")
    assert _request(gate, env={"PATH": f"lgk://{API_ID}/key"}) == Refusal("invalid")


def test_denied_run_is_refused_and_logged_per_item() -> None:
    log: list = []
    runs: list = []
    assert _request(_gate(ui=FakeUi(False), log=log, runs=runs)) == Refusal("denied")
    assert ("agent.request", "denied", API_ID) in log and ("agent.request", "denied", NOTE_ID) in log
    assert runs[-1]["stage"] == "denied"


def test_off_pro_and_rate_limit() -> None:
    assert _request(_gate(enabled=False)) == Refusal("disabled")
    assert _request(_gate(pro=False)) == Refusal("pro")
    gate = _gate()
    results = [_request(gate, run_id=f"r{i}") for i in range(4)]
    assert results[-1] == Refusal("rate_limited")


# ---------------------------------------------------------------- release_run / finish_run
def test_release_gives_the_values_once_for_the_session_that_asked() -> None:
    log: list = []
    gate = _gate(log=log)
    grant = _request(gate)
    assert gate.release_run(OTHER, grant.id) == Refusal("not_yours")
    values = gate.release_run(CLIENT, grant.id)
    assert values == {f"lgk://{API_ID}/key": API_SECRET, "lgk://App .env/DATABASE_URL": NOTE_SECRET}
    assert gate.release_run(CLIENT, grant.id) == Refusal("used")
    assert ("agent.read", "ok", API_ID) in log and ("agent.read", "ok", NOTE_ID) in log


def test_release_of_an_unknown_or_expired_grant_is_refused() -> None:
    now = [1000.0]
    gate = _gate(clock=lambda: now[0])
    assert gate.release_run(CLIENT, "nope") == Refusal("expired")
    grant = _request(gate)
    now[0] += agent_gate.RUN_TTL + 1
    assert gate.release_run(CLIENT, grant.id) == Refusal("expired")


def test_release_rechecks_the_switch() -> None:
    session = FakeSession()
    settings_items = list(ALLOWED)
    settings = SimpleNamespace(agents_enabled=True, require_hello_for_agents=False, agent_items=settings_items)
    gate = AgentGate(lambda: session, settings, FakeUi(), None, is_pro=lambda: True)
    grant = _request(gate)
    settings_items.remove(API_ID)
    assert gate.release_run(CLIENT, grant.id) == Refusal("not_found")


def test_finish_logs_the_run_once_without_values() -> None:
    log: list = []
    runs: list = []
    gate = _gate(log=log, runs=runs)
    grant = _request(gate)
    gate.release_run(CLIENT, grant.id)
    gate.finish_run(CLIENT, "run-1", exit_code=3, timed_out=False, started=True)
    gate.finish_run(CLIENT, "run-1", exit_code=0, timed_out=False, started=True)  # ignored: already finished
    assert [e for e in log if e[0] == "agent.complete"] == [("agent.complete", "failed", API_ID),
                                                            ("agent.complete", "failed", NOTE_ID)]
    stages = [r["stage"] for r in runs]
    assert stages == ["approved", "released", "finished"]
    finished = runs[-1]
    assert finished["exit_code"] == 3 and finished["timed_out"] is False
    assert finished["command"] == 'C:\\Tools\\deploy.exe --env "prod & del *"' and finished["cwd"] == "C:\\work\\app"
    assert {(i["variable"], i["item_id"], i["field"]) for i in finished["items"]} == {
        ("STRIPE_KEY", API_ID, "key"), ("DATABASE_URL", NOTE_ID, "DATABASE_URL")}
    text = json.dumps(runs) + json.dumps(log)
    assert API_SECRET not in text and NOTE_SECRET not in text


def test_finish_from_another_session_is_ignored() -> None:
    log: list = []
    gate = _gate(log=log)
    grant = _request(gate)
    gate.release_run(CLIENT, grant.id)
    gate.finish_run(OTHER, "run-1", exit_code=0, timed_out=False, started=True)
    assert not [e for e in log if e[0] == "agent.complete"]
    gate.finish_run(CLIENT, "run-1", exit_code=0, timed_out=True, started=True)
    assert ("agent.complete", "cancelled", API_ID) in log


# ---------------------------------------------------------------- service (pipe side)
class _Activity:
    def __init__(self):
        self.rows = []

    def record(self, event, *, result="ok", item_id=None):
        self.rows.append((event, result, item_id))


class _Host:
    def __init__(self, approve=True):
        self.session = SimpleNamespace(item_service=_ItemService(), activity=_Activity(),
                                       summaries=lambda: [], get_entry=lambda _id: None)
        self.settings = SimpleNamespace(agents_enabled=True, require_hello_for_agents=False, agent_items=list(ALLOWED))
        self.ui = SimpleNamespace(confirm=lambda title, message: approve)
        self._port = None
        self.messages = []

    def run_on_ui(self, fn, timeout=0):
        return fn()

    def show_palette(self):
        return False

    def ensure_unlocked(self):
        return True


class _ItemService:
    def list_items(self):
        return [{"id": i["id"], "kind": i["kind"], "title": i["title"], "payload": {}} for i in _items()]

    def get_item(self, item_id, include_protected=False):
        assert include_protected
        return next((copy.deepcopy(i) for i in _items() if i["id"] == item_id), None)

    def passkey_metadata(self):
        return []


def _service(approve=True):
    from localvault.app.agent_gate_service import AgentGateService

    host = _Host(approve)
    service = AgentGateService(host)
    service.gate._is_pro = lambda: True
    client = SimpleNamespace(pid=7, image="lgk.exe", parent_chain=(SimpleNamespace(image="C:/x/claude.exe"),))
    return service, host, client


def _run_request(**extra):
    request = {"action": "agent_run_secrets", "session": "s1", "client_name": "claude-code", "run": "r1",
               "refs": [f"lgk://{API_ID}/key"], "env": {"STRIPE_KEY": f"lgk://{API_ID}/key"},
               "command": ["C:\\Tools\\deploy.exe", "--prod"], "cwd": "C:\\work", "timeout": 120, "purpose": "deploy"}
    request.update(extra)
    return request


def test_service_run_returns_values_by_reference_and_logs_item_ids() -> None:
    service, host, client = _service()
    reply = service.dispatch(_run_request(), client)
    assert reply == {"ok": True, "values": {f"lgk://{API_ID}/key": API_SECRET}}
    assert ("agent.request", "ok", API_ID) in host.session.activity.rows
    assert ("agent.read", "ok", API_ID) in host.session.activity.rows
    done = service.dispatch({"action": "agent_run_finished", "session": "s1", "run": "r1", "exit_code": 0,
                             "timed_out": False, "started": True}, client)
    assert done == {"ok": True}
    assert ("agent.complete", "ok", API_ID) in host.session.activity.rows


def test_service_refusals_carry_no_value() -> None:
    service, _host, client = _service(approve=False)
    denied = service.dispatch(_run_request(), client)
    assert denied["ok"] is False and denied["error"] == "denied"
    missing = service.dispatch(_run_request(refs=[f"lgk://{OFF_ID}/key"], env={"K": f"lgk://{OFF_ID}/key"}), client)
    assert missing["error"] == "not_found"
    bad = service.dispatch(_run_request(command="rm -rf /"), client)
    assert bad["error"] == "invalid"
    for reply in (denied, missing, bad):
        assert API_SECRET not in json.dumps(reply) and OFF_SECRET not in json.dumps(reply)


def test_service_refs_must_match_env() -> None:
    service, _host, client = _service()
    reply = service.dispatch(_run_request(refs=[f"lgk://{API_ID}/key", f"lgk://{OFF_ID}/key"]), client)
    assert reply["error"] == "invalid"


def test_service_lists_secrets() -> None:
    service, _host, client = _service()
    reply = service.dispatch({"action": "agent_list_secrets", "session": "s1", "query": ""}, client)
    assert reply["ok"] is True and {r["title"] for r in reply["secrets"]} == {"Stripe", "App .env", "Deploy key"}
    assert API_SECRET not in json.dumps(reply)


def _mcp(service, client):
    from localvault.cli.mcp_server import McpServer

    server = McpServer(lambda request: service.dispatch(request, client))
    server.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "claude-code"}}})
    return server


def _tool(server, name, **arguments):
    return server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": name, "arguments": arguments}})["result"]


def test_mcp_run_with_secrets_end_to_end_masks_and_logs() -> None:
    """lgk mcp -> pipe -> gate service -> approval -> values -> child -> masked reply, then the run's end logged."""
    import sys

    service, host, client = _service()
    server = _mcp(service, client)
    listed = _tool(server, "list_secrets")
    assert {row["title"] for row in listed["structuredContent"]["secrets"]} == {"Stripe", "App .env", "Deploy key"}
    script = "import os; print(os.environ['STRIPE_KEY'], os.environ['DB'][::-1] == os.environ['DB'][::-1])"
    result = _tool(server, "run_with_secrets", command=[sys.executable, "-c", script],
                   env={"STRIPE_KEY": f"lgk://{API_ID}/key", "DB": "lgk://App .env/DATABASE_URL"}, purpose="deploy")
    assert result["isError"] is False and "<concealed by LocalGateKeys>" in result["structuredContent"]["stdout"]
    text = json.dumps(result)
    assert API_SECRET not in text and NOTE_SECRET not in text and OFF_SECRET not in text
    rows = host.session.activity.rows
    assert ("agent.read", "ok", API_ID) in rows and ("agent.complete", "ok", NOTE_ID) in rows
    recent = service.runs.recent(5)
    assert recent[0]["stage"] == "finished" and recent[0]["items"][0]["field"] in ("key", "DATABASE_URL")
    assert API_SECRET not in json.dumps(recent) and NOTE_SECRET not in json.dumps(recent)


def test_mcp_reference_to_an_item_not_allowed_runs_nothing(tmp_path) -> None:
    import sys

    service, _host, client = _service()
    marker = tmp_path / "ran"
    result = _tool(_mcp(service, client), "run_with_secrets", command=[sys.executable, "-c", f"open(r'{marker}','w')"],
                   env={"K": f"lgk://{OFF_ID}/key"}, purpose="x")
    assert result["structuredContent"]["error"] == "not_found" and not marker.exists()
    assert OFF_SECRET not in json.dumps(result)


def test_cli_service_routes_the_new_agent_actions() -> None:
    from localvault.cli_service import AGENT_ACTIONS

    assert {"agent_list_secrets", "agent_run_secrets", "agent_run_finished"} <= AGENT_ACTIONS


def test_approval_text_is_honest_about_what_the_command_gets() -> None:
    from localvault.agent_gate import AgentRequest
    from localvault.app.agent_gate_service import AgentGateService

    text = AgentGateService.describe(AgentRequest(
        "run", "Claude Code", "claude.exe", "", "deploy", command="deploy.exe --prod", cwd="C:\\work",
        secrets=(("STRIPE_KEY", "Stripe", "key"),), timeout=120))
    assert "deploy.exe --prod" in text and "C:\\work" in text and "STRIPE_KEY" in text and "Stripe" in text
    assert "anywhere" in text


# ---------------------------------------------------------------- the switch (settings)
def test_agent_items_setting_is_device_only_and_validated(tmp_path) -> None:
    from localvault.backup import DEVICE_ONLY_SETTINGS
    from localvault.settings import AppSettings

    assert AppSettings().agent_items == []
    path = tmp_path / "settings.json"
    AppSettings(agent_items=[API_ID, API_ID, "", NOTE_ID]).save(path)
    assert AppSettings.load(path).agent_items == [API_ID, NOTE_ID]
    assert "agent_items" in DEVICE_ONLY_SETTINGS


def test_restore_turns_the_agent_switch_off_for_every_item() -> None:
    from localvault import backup

    restored: dict = {"agent_items": [API_ID]}
    backup._keep_device_settings(restored, {"agent_items": [API_ID], "developer_cli": True})
    assert restored["agent_items"] == [] and restored["developer_cli"] is True
    # A backup that carries the list (crafted or older) never brings it back: absent means off.
    restored = {"agent_items": [API_ID], "auto_lock_seconds": 300}
    backup._keep_device_settings(restored, {})
    assert "agent_items" not in restored


def test_agent_item_eligibility() -> None:
    assert agent_gate.AGENT_SECRET_KINDS == {"api_key", "ssh_key", "note"}
    assert agent_gate.agent_item_allowed(SimpleNamespace(agent_items=[API_ID]), API_ID)
    assert not agent_gate.agent_item_allowed(SimpleNamespace(agent_items=[API_ID]), NOTE_ID)
    assert not agent_gate.agent_item_allowed(SimpleNamespace(agent_items="x"), "x")
