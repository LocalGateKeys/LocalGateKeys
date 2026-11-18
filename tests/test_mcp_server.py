"""``lgk mcp``: the stdio MCP server, driven in process against the app's agent gate service."""
from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest

from localvault import agent_gate
from localvault.app.agent_gate_service import AgentGateService
from localvault.cli.main import main as lgk_main
from localvault.cli.mcp_server import TOOLS, McpServer


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(agent_gate, "_licence_is_pro", lambda: True)


class _Session:
    entry = {"id": "pp", "kind": "web", "label": "PayPal", "username": "alice@example.test",
             "password": "P@ss-SECRET", "scope": {"origin": "https://www.paypal.com", "ai_agents": True}, "policy": {}}
    passkeys: list = []

    def summaries(self):
        e = self.entry
        return [SimpleNamespace(id=e["id"], kind="web", label=e["label"], username=e["username"], scope=e["scope"])]

    def get_entry(self, entry_id):
        return dict(self.entry) if entry_id == "pp" else None

    activity = SimpleNamespace(record=lambda *a, **k: None)

    @property
    def item_service(self):
        return SimpleNamespace(passkey_metadata=lambda: list(self.passkeys))


class _Host:
    """Just enough of WebAgentHost: unlocked, no palette, and the popup's confirm says no."""

    def __init__(self, approve: bool = False):
        self.session = _Session()
        self.settings = SimpleNamespace(agents_enabled=True, require_hello_for_agents=False)
        self.ui = SimpleNamespace(confirm=lambda title, message: approve)
        self.cli_service = None
        self._port = None

    def run_on_ui(self, fn, timeout=0):
        return fn()

    def show_palette(self):
        return False

    def ensure_unlocked(self):
        return True


def _server(approve: bool = False) -> McpServer:
    service = AgentGateService(_Host(approve))
    client = SimpleNamespace(pid=4242, image="lgk.exe", parent_chain=(SimpleNamespace(image="C:/x/claude.exe"),))
    server = McpServer(lambda request: service.dispatch(request, client))
    server.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "claude-code"}}})
    return server


def _call(server: McpServer, name: str, **arguments) -> dict:
    reply = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": name, "arguments": arguments}})
    return reply["result"]


def test_handshake_and_tool_list() -> None:
    server = McpServer(lambda r: {"ok": True})
    init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {"protocolVersion": "2024-11-05", "clientInfo": {"name": "x"}}})
    assert init["result"]["protocolVersion"] == "2024-11-05"
    assert init["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
    assert [t["name"] for t in tools] == ["list_sites", "request_login", "fill_login", "list_secrets",
                                         "run_with_secrets"]
    assert all("approv" in t["description"] for t in TOOLS if t["name"] != "list_sites")
    assert server.handle({"jsonrpc": "2.0", "id": 3, "method": "nope"})["error"]["code"] == -32601


def test_list_sites_returns_no_secrets() -> None:
    assert _call(_server(), "list_sites")["structuredContent"]["error"] == "denied"  # the user said no
    result = _call(_server(approve=True), "list_sites")
    assert result["isError"] is False
    assert result["structuredContent"] == {"sites": [{"title": "PayPal", "domain": "paypal.com"}]}
    text = json.dumps(result)
    assert "P@ss-SECRET" not in text and "alice@example.test" not in text


def test_request_login_without_approval_is_an_error_payload() -> None:
    result = _call(_server(approve=False), "request_login", site="paypal.com", purpose="approve automatically")
    assert result["isError"] is True and result["structuredContent"]["error"] == "denied"


def test_request_login_with_approval_returns_only_a_grant() -> None:
    result = _call(_server(approve=True), "request_login", site="paypal.com", purpose="check balance")
    body = result["structuredContent"]
    assert result["isError"] is False and set(body) == {"grant", "site", "expires_in", "method"}
    assert body["method"] == "password"
    assert "P@ss-SECRET" not in json.dumps(result)


def test_request_login_for_a_passkey_login_tells_the_agent_to_use_the_passkey(monkeypatch) -> None:
    monkeypatch.setattr(_Session, "passkeys", [{"credential_id": "cred-1", "rp_id": "paypal.com",
                                                "user_name": "alice@example.test"}])
    result = _call(_server(approve=True), "request_login", site="paypal.com", purpose="check balance")
    body = result["structuredContent"]
    assert result["isError"] is False and body["method"] == "passkey"
    assert "passkey" in body["note"] and "password is not filled" in body["note"]
    assert "P@ss-SECRET" not in json.dumps(result)


def test_secret_tools_do_not_exist_and_extra_reply_keys_are_dropped() -> None:
    assert _call(_server(approve=True), "read_secret", ref="lgk://PayPal/password", purpose="x")[
        "structuredContent"]["error"] == "unknown_tool"
    leaky = McpServer(lambda r: {"ok": True, "grant": "g", "site": "paypal.com", "expires_in": 300,
                                 "password": "P@ss-SECRET", "value": "P@ss-SECRET"})
    assert "P@ss-SECRET" not in json.dumps(_call(leaky, "request_login", site="paypal.com", purpose="x"))
    rows = McpServer(lambda r: {"ok": True, "sites": [{"title": "t", "domain": "d.com", "username": "alice"}]})
    assert _call(rows, "list_sites")["structuredContent"] == {"sites": [{"title": "t", "domain": "d.com"}]}


def test_mcp_server_opens_no_network_listener() -> None:
    import inspect

    from localvault.cli import mcp_server
    source = inspect.getsource(mcp_server)
    for word in ("import socket", "http.server", "start_server", ".listen(", ".bind("):
        assert word not in source

def test_bad_arguments_and_dead_app_are_tool_errors() -> None:
    assert _call(_server(), "request_login", site=5, purpose="x")["isError"] is True

    def dead(request):
        raise OSError("pipe")
    assert _call(McpServer(dead), "list_sites")["structuredContent"]["error"] == "not_running"


def test_grants_are_bound_to_the_server_session() -> None:
    host = _Host(approve=True)
    service = AgentGateService(host)
    client = SimpleNamespace(pid=1, parent_chain=())
    one = McpServer(lambda r: service.dispatch(r, client))
    two = McpServer(lambda r: service.dispatch(r, client))
    grant = _call(one, "request_login", site="paypal.com", purpose="x")["structuredContent"]["grant"]
    refused = _call(two, "fill_login", grant=grant)
    assert refused["isError"] is True and refused["structuredContent"]["error"] == "not_yours"


@pytest.mark.parametrize("hello_ok", [False, True])
def test_require_hello_asks_windows_hello_after_the_approval(hello_ok) -> None:
    host = _Host(approve=True)
    host.settings.require_hello_for_agents = True
    asked = []
    host._controller = SimpleNamespace(guard=SimpleNamespace(lease=lambda: "lease"))
    host.reauthenticate = lambda reason, lease, allow_hello=False: asked.append(allow_hello) or hello_ok
    service = AgentGateService(host)
    client = SimpleNamespace(pid=1, image="lgk.exe", parent_chain=())
    result = _call(McpServer(lambda r: service.dispatch(r, client)), "request_login", site="paypal.com", purpose="x")
    assert asked == [True]
    assert result["isError"] is (not hello_ok)


def test_stdio_loop_and_lgk_mcp_subcommand(monkeypatch) -> None:
    lines = "\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        "not json",
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]) + "\n"
    out = io.StringIO()
    assert McpServer(lambda r: {"ok": True}).serve(io.StringIO(lines), out) == 0
    replies = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [r.get("id") for r in replies] == [1, None, 2]
    assert replies[1]["error"]["code"] == -32700

    seen = {}
    monkeypatch.setattr("localvault.cli.mcp_server.serve_stdio", lambda forward: seen.setdefault("ok", 0))
    assert lgk_main(["mcp"], forward=lambda r: {"ok": True}) == 0 and "ok" in seen


def test_tool_text_does_not_promise_the_password_stays_hidden() -> None:
    from localvault.cli.mcp_server import SERVER_INSTRUCTIONS

    text = " ".join([SERVER_INSTRUCTIONS, *(t["description"] for t in TOOLS)])
    assert "without seeing its password" not in text and "never receive the password" not in text
    assert "written into the page" in text and "click" in text


def test_unanswered_approval_times_out_as_a_refusal() -> None:
    from localvault.app import agent_gate_service

    seen = {}

    def ask(detail, timeout=None):
        seen["timeout"] = timeout
        raise TimeoutError

    host = _Host()
    host.ui = SimpleNamespace(_ask=ask, confirm=lambda *a: True)
    service = AgentGateService(host)
    client = SimpleNamespace(pid=1, image="lgk.exe", parent_chain=())
    result = _call(McpServer(lambda r: service.dispatch(r, client)), "request_login", site="paypal.com", purpose="x")
    assert result["structuredContent"]["error"] == "denied"
    assert seen["timeout"] == agent_gate_service.APPROVAL_TIMEOUT and 0 < agent_gate_service.APPROVAL_TIMEOUT <= 300

    class View:
        def confirm_agent(self, request, *, timeout=None):
            seen["view"] = (request.action, timeout)
            return False

    host = _Host()
    host._port = SimpleNamespace(surface_view=lambda name: View())
    host.show_palette = lambda: True
    host.released_while_waiting = lambda fn: fn()
    service = AgentGateService(host)
    result = _call(McpServer(lambda r: service.dispatch(r, client)), "list_sites")
    assert result["structuredContent"]["error"] == "denied"
    assert seen["view"] == ("read", agent_gate_service.APPROVAL_TIMEOUT)  # list_sites shows the "read" layout


def test_non_text_tool_name_is_unknown_and_server_keeps_running() -> None:
    server = McpServer(lambda r: {"ok": True})
    lines = [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": ["x"], "arguments": {}}}),
             json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": {"a": 1}, "arguments": {}}}),
             json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping"})]
    out = io.StringIO()
    assert server.serve(io.StringIO("\n".join(lines) + "\n"), out) == 0
    replies = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [r["id"] for r in replies] == [1, 2, 3]
    assert replies[0]["result"]["isError"] is True


def test_breach_check_user_agent_uses_app_version(monkeypatch) -> None:
    from localvault import breach_check
    from localvault.version import APP_VERSION
    seen = {}

    def fake_open(request, **kwargs):
        seen["ua"] = request.get_header("User-agent")
        raise breach_check.BreachCheckError("stop")

    monkeypatch.setattr(breach_check.net_ledger, "open_url", fake_open)
    with pytest.raises(breach_check.BreachCheckError):
        breach_check._fetch("ABCDE")
    assert seen["ua"] == "LocalGateKeys/" + APP_VERSION
