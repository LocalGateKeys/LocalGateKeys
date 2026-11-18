"""Write ``tests/vectors/agent/{mcp,gate,text}.json``: the Local Agent Gate as the Windows build behaves today.

LGKCore (Swift, ``lgk mcp`` on the Mac) replays the same files in ``AgentVectorsTests``; ``tests/test_agent_vectors.py``
checks that the files are exactly what this script writes from the Python code (``cli/mcp_server.py``,
``agent_gate.py``), so a change on either side shows up as a failing test.

* ``text.json``: ``clean_text``, ``registrable_domain``, ``site_host``, ``origin_domain``, ``agents_may_use`` and
  ``site_passkeys`` on fixed inputs.
* ``mcp.json``: ``McpServer.serve`` on input lines with a scripted app (``replies``, consumed in order; ``{"$raise":
  true}`` makes the forward raise, ``{"$value": x}`` returns the non-dict ``x``). ``forwarded`` is what the server sent
  to the app (session ``S1``). ``output`` is the reply lines, parsed. A reader compares each ``content[].text`` after
  parsing it as JSON (key order is not part of the contract), and ignores ``serverInfo.version`` and
  ``instructions`` (the Mac says "this Mac"). Only the three sign-in tools are pinned: ``tools/list`` keeps those.
* ``gate.json``: ``AgentGate`` scenarios with a fake vault, settings, approval view and clock. Each step names an
  operation and its expected result, the approval prompts it showed, the access-log events it wrote and the unlock
  prompts it asked for. Grant ids are ``G1``, ``G2``, ... in the order they were made. A ``fill_login`` step may carry
  ``during``: steps run while the fill waits for the browser (the wait then returns whether the grant finished).

Usage (from the repo root)::

    python scripts/make_agent_gate_vectors.py [OUT_DIR]
"""
from __future__ import annotations

import io
import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from localvault import agent_gate  # noqa: E402
from localvault.agent_gate import (  # noqa: E402
    AgentGate,
    ClientInfo,
    Grant,
    Refusal,
    agents_may_use,
    clean_text,
    origin_domain,
    registrable_domain,
    site_host,
    site_passkeys,
)
from localvault.cli import mcp_server  # noqa: E402
from localvault.cli.mcp_server import McpServer  # noqa: E402

OUT = ROOT / "tests" / "vectors" / "agent"
MAC_TOOLS = ("list_sites", "request_login", "fill_login")
START = 1000.0


def _dump(doc: Any) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=False) + "\n").encode("utf-8")


# ---------------------------------------------------------------------------------------------------- text.json
CLEAN = [
    ("plain", 80), ("  two   spaces\tand\ttabs  ", 80), ("line\nbreak\r\nend", 80), ("bell\u0007and\u0000nul", 80),
    ("bidi ‮gnp.exe‬", 80), ("zero​width‍joiner", 80), ("nbsp and　ideographic", 80),
    ("line separator para", 80), ("privateuse", 80), ("café 中文 \U0001f600", 80),
    ("x" * 120, 80), ("abc def", 5), ("", 80), ("   ", 80), ("soft­hyphen", 80), ("del\u007fchar", 80),
    ("c1\u0085control", 80), ("word joiner⁠", 80), ("bom﻿mark", 80),
]
SITES = [
    "paypal.com", "https://www.paypal.com/x", "login.paypal.com", "  login.example.com  ", "https://Login.Example.COM.",
    "http://shop.example.co.uk/path?q=1", "example.co.uk", "co.uk", "localhost", "127.0.0.1", "https://[::1]/",
    "", "   ", "not a url", "https://", "ftp://example.com", "https://user:pw@example.com", "example.com:8443",
    "bücher.example", "xn--bcher-kva.example", "a" * 300 + ".com", "https://bank.example.org/login",
    "www.github.com", "javascript:alert(1)",
]
ORIGINS = [
    "https://login.example.com", "https://example.com:443", "http://login.example.com", "https://example.com/path",
    "https://example.com:8443", "https://localhost", "http://localhost", "not an origin", "", "https://co.uk",
    "https://www.paypal.com",
]
ENTRIES = [
    {"scope": {"ai_agents": True}}, {"scope": {"ai_agents": False}}, {"scope": {"ai_agents": "true"}},
    {"scope": {"ai_agents": 1}}, {"scope": {}}, {"scope": None}, {"scope": ["ai_agents"]}, {}, {"scope": "x"},
]
PASSKEY_ROWS = [
    {"credential_id": "c1", "rp_id": "example.com", "user_name": "alice"},
    {"credential_id": "c2", "rp_id": "login.example.com", "user_name": "Bob"},
    {"credential_id": "c3", "rp_id": "other.com", "user_name": "alice"},
    {"credential_id": "", "rp_id": "example.com", "user_name": "alice"},
    {"credential_id": "c5", "rp_id": "EXAMPLE.COM.", "user_name": ""},
    {"credential_id": "c6", "rp_id": "co.uk", "user_name": "alice"},
    {"credential_id": "c7", "rp_id": "files.example.com", "user_name": "alice"},
]
PASSKEY_CASES = [
    ("alice", ["login.example.com"], "example.com"), ("bob", ["login.example.com"], "example.com"),
    ("carol", ["login.example.com"], "example.com"), ("", ["login.example.com"], "example.com"),
    ("alice", ["example.com", "www.example.com"], "example.com"), ("alice", ["shop.other.com"], "other.com"),
    ("alice", ["files.example.com"], "example.com"), ("alice", [], "example.com"),
    (" ALICE ", ["www.example.com"], "example.com"), ("alice", ["example.co.uk"], "example.co.uk"),
]


def text_doc() -> dict[str, Any]:
    return {
        "clean_text": [{"input": value, "limit": limit, "output": clean_text(value, limit)} for value, limit in CLEAN],
        "sites": [{"input": site, "registrable_domain": registrable_domain(site), "site_host": site_host(site)}
                  for site in SITES],
        "origin_domain": [{"input": origin, "output": origin_domain(origin)} for origin in ORIGINS],
        "agents_may_use": [{"entry": entry, "output": agents_may_use(entry)} for entry in ENTRIES],
        "site_passkeys": {
            "passkeys": PASSKEY_ROWS,
            "cases": [{"username": user, "hosts": hosts, "domain": domain,
                       "output": sorted(site_passkeys(user, hosts, domain, PASSKEY_ROWS))}
                      for user, hosts, domain in PASSKEY_CASES],
        },
    }


# ---------------------------------------------------------------------------------------------------- mcp.json
class _Raise(Exception):
    pass


def _call(name: str, arguments: Any = None, request_id: Any = 1) -> str:
    params: dict[str, Any] = {"name": name}
    if arguments is not None:
        params["arguments"] = arguments
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params})


MCP_CASES: list[dict[str, Any]] = [
    {"name": "initialize_known_version", "lines": [json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-03-26", "clientInfo": {"name": "Claude Code", "version": "2"}}})]},
    {"name": "initialize_unknown_version", "lines": [json.dumps(
        {"jsonrpc": "2.0", "id": "a", "method": "initialize", "params": {"protocolVersion": "1999-01-01"}})]},
    {"name": "initialize_no_params", "lines": ['{"jsonrpc":"2.0","id":0,"method":"initialize"}']},
    {"name": "client_name_is_cut_to_80", "lines": [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": "N" * 100}}}),
        _call("list_sites", {})], "replies": [{"ok": True, "sites": []}]},
    {"name": "client_name_not_text", "lines": [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": 7}}}),
        _call("list_sites")], "replies": [{"ok": True, "sites": []}]},
    {"name": "ping_and_notification", "lines": [
        '{"jsonrpc":"2.0","method":"notifications/initialized"}', '{"jsonrpc":"2.0","id":5,"method":"ping"}']},
    {"name": "tools_list", "lines": ['{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}']},
    {"name": "unknown_method", "lines": ['{"jsonrpc":"2.0","id":3,"method":"' + "x" * 100 + '"}']},
    {"name": "invalid_requests", "lines": [
        '{"jsonrpc":"1.0","id":1,"method":"ping"}', '{"jsonrpc":"2.0","id":2}', '{"jsonrpc":"2.0","id":3,"method":4}',
        '[1, "x"]', '"just text"', '{"jsonrpc":"2.0","id":null,"method":"ping"}']},
    {"name": "parse_error_and_blank_lines", "lines": ["{not json", "", "   ", '{"jsonrpc":"2.0","id":9,"method":"ping"}']},
    {"name": "batch", "lines": [
        '[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/x"},'
        '{"jsonrpc":"2.0","id":2,"method":"nope"}]', '[{"jsonrpc":"2.0","method":"notifications/x"}]', "[]"]},
    {"name": "params_not_object", "lines": ['{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[1]}']},
    {"name": "unknown_tool", "lines": [_call("reveal_password", {"site": "x"}), _call("copy_password", {})]},
    {"name": "list_sites_filters_rows", "lines": [_call("list_sites", {"query": "pay"})], "replies": [
        {"ok": True, "sites": [
            {"title": "PayPal", "domain": "paypal.com", "username": "alice", "password": "P@ss"},
            {"title": 5, "domain": True}, "not a row", {"title": None}, {"domain": "d" * 300, "title": "t" * 300}],
         "password": "LEAK", "username": "alice"}]},
    {"name": "list_sites_caps_at_50", "lines": [_call("list_sites")], "replies": [
        {"ok": True, "sites": [{"title": f"T{i}", "domain": f"d{i}.example"} for i in range(60)]}]},
    {"name": "list_sites_no_sites_key", "lines": [_call("list_sites")], "replies": [{"ok": True}]},
    {"name": "request_login_reply_keys", "lines": [
        _call("request_login", {"site": "paypal.com", "purpose": "Pay the bill", "extra": "dropped"})],
        "replies": [{"ok": True, "grant": "g-1", "site": "paypal.com", "expires_in": 300, "method": "password",
                     "password": "LEAK", "username": "alice", "hosts": ["www.paypal.com"]}]},
    {"name": "request_login_passkey", "lines": [_call("request_login", {"site": "github.com", "purpose": "PR"})],
     "replies": [{"ok": True, "grant": "g-2", "site": "github.com", "expires_in": 300, "method": "passkey",
                  "note": "Use the passkey."}]},
    {"name": "arguments_are_cut_to_2000", "lines": [
        _call("request_login", {"site": "s" * 2500, "purpose": "p" * 3000})], "replies": [{"ok": False,
                                                                                           "error": "invalid"}]},
    {"name": "argument_not_text", "lines": [
        _call("request_login", {"site": 5, "purpose": "x"}), _call("fill_login", {"grant": ["g"]}),
        _call("list_sites", {"query": None})], "replies": [{"ok": True, "sites": []}]},
    {"name": "arguments_not_object", "lines": [_call("fill_login", "grant")], "replies": [
        {"ok": False, "error": "invalid", "message": "The request is malformed."}]},
    {"name": "fill_login_reply_keys", "lines": [_call("fill_login", {"grant": "g-1", "tab_hint": "Sign in"})],
     "replies": [{"ok": True, "filled": True, "site": "paypal.com", "method": "password", "password": "LEAK",
                  "credential": {"password": "LEAK"}}]},
    {"name": "refusals", "lines": [_call("request_login", {"site": "a.com", "purpose": "x"}, i) for i in range(1, 9)],
     "replies": [
         {"ok": False, "error": "denied", "message": "The user did not approve this request."},
         {"ok": False, "error": "agent_state_missing", "message": "internal"},
         {"ok": False, "error": "agent_unavailable"}, {"ok": False, "error": "unauthorized", "message": "x"},
         {"ok": False}, {"ok": "yes", "error": "e" * 100, "message": "m" * 600},
         {"ok": False, "error": "", "message": ""}, {"ok": False, "error": 0, "message": None}]},
    {"name": "app_failures", "lines": [_call("list_sites", None, 1), _call("list_sites", None, 2)],
     "replies": [{"$raise": True}, {"$value": ["not", "a", "dict"]}]},
]


def _replay_mcp(case: dict[str, Any]) -> dict[str, Any]:
    replies = list(case.get("replies", []))
    forwarded: list[dict[str, Any]] = []

    def forward(request: dict[str, Any]) -> Any:
        forwarded.append(dict(request))
        reply = replies.pop(0)
        if isinstance(reply, dict) and reply.get("$raise") is True:
            raise _Raise("app down")
        if isinstance(reply, dict) and "$value" in reply:
            return reply["$value"]
        return reply

    out = io.StringIO()
    McpServer(forward, session="S1").serve(io.StringIO("".join(line + "\n" for line in case["lines"])), out)
    if replies:
        raise AssertionError(f"{case['name']}: unused replies")
    output = [json.loads(line) for line in out.getvalue().splitlines()]
    for message in output:
        result = message.get("result") if isinstance(message, dict) else None
        if isinstance(result, dict) and "tools" in result:
            result["tools"] = [tool for tool in result["tools"] if tool["name"] in MAC_TOOLS]
        if isinstance(result, dict) and "serverInfo" in result:
            result["serverInfo"]["version"] = "$version"
            result["instructions"] = "$instructions"
    return {**case, "forwarded": forwarded, "output": output}


def mcp_doc() -> dict[str, Any]:
    return {"protocol_versions": list(mcp_server.PROTOCOL_VERSIONS), "max_line": mcp_server.MAX_LINE,
            "cases": [_replay_mcp(case) for case in MCP_CASES]}


# ---------------------------------------------------------------------------------------------------- gate.json
def _login(entry_id: str, title: str, urls: list[str], *, agents: Any = True, username: str = "alice",
           policy: Any = None, kind: str = "web", origin: str | None = None) -> dict[str, Any]:
    scope: dict[str, Any] = {"urls": [{"url": url, "match": "exact_origin"} for url in urls]}
    if origin is not None:
        scope = {"origin": origin}
    if agents is not None:
        scope["ai_agents"] = agents
    record: dict[str, Any] = {"id": entry_id, "kind": kind, "label": title, "username": username, "scope": scope}
    if policy is not None:
        record["policy"] = policy
    return {"id": entry_id, "title": title, "kind": kind, "record": record}


VAULT = [
    _login("11111111-1111-4111-8111-111111111111", "PayPal", ["https://www.paypal.com", "https://paypal.com"]),
    _login("22222222-2222-4222-8222-222222222222", "Example login", ["https://login.example.com"]),
    _login("33333333-3333-4333-8333-333333333333", "Example shop", ["https://shop.example.com"], username="bob"),
    _login("44444444-4444-4444-8444-444444444444", "Bank", ["https://bank.example.org"],
           policy={"require_master_password": True}),
    _login("55555555-5555-4555-8555-555555555555", "Never", ["https://never.example.net"], policy={"fill": "never"}),
    _login("66666666-6666-4666-8666-666666666666", "Odd fill", ["https://odd.example.net"], policy={"fill": 5}),
    _login("77777777-7777-4777-8777-777777777777", "Not allowed", ["https://private.example.net"], agents=None),
    _login("88888888-8888-4888-8888-888888888888", "String flag", ["https://flag.example.net"], agents="true"),
    _login("99999999-9999-4999-8999-999999999999", "Note kind", ["https://note.example.net"], kind="note"),
    _login("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Two sites", ["https://a.twosites.com", "https://b.other.org"]),
    _login("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "Legacy", [], origin="https://legacy.example.io"),
    _login("cccccccc-cccc-4ccc-8ccc-cccccccccccc", "GitHub", ["https://github.com"], username="octo"),
    _login("dddddddd-dddd-4ddd-8ddd-dddddddddddd", "PayPal", ["https://www.paypal.com"], username="second"),
    _login("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "String yes is strict",
           ["https://loose.example.net"], policy={"require_master_password": "yes", "fill": "click"}),
]
PASSKEYS = [
    {"credential_id": "pk-octo", "rp_id": "github.com", "user_name": "octo"},
    {"credential_id": "pk-other", "rp_id": "github.com", "user_name": "someone"},
    {"credential_id": "pk-bob", "rp_id": "shop.example.com", "user_name": "carol"},
]
CLIENTS = {"A": {"client_id": "4242:S1", "name": "Claude Code", "process": "claude"},
           "B": {"client_id": "4343:S2", "name": "", "process": "node"},
           "C": {"client_id": "4444:S3", "name": "Bad‮\u0007 agent\nname" + "x" * 100, "process": "p\u0000y"}}
EX = "https://login.example.com"

SCENARIOS: list[dict[str, Any]] = [
    {"name": "agents_off", "settings": {"agents_enabled": False}, "steps": [
        {"op": "list_sites", "client": "A"},
        {"op": "request_login", "client": "A", "site": "paypal.com", "purpose": "x"},
        {"op": "request_login", "client": "A", "site": "not a url", "purpose": "x"},
        {"op": "fill_login", "client": "A", "grant": "G1"},
        {"op": "take_for_origin", "origin": EX}]},
    {"name": "not_pro", "pro": False, "steps": [
        {"op": "list_sites", "client": "A"},
        {"op": "request_login", "client": "A", "site": "paypal.com", "purpose": "x"}]},
    {"name": "locked", "locked": True, "steps": [
        {"op": "list_sites", "client": "A"},
        {"op": "request_login", "client": "A", "site": "paypal.com", "purpose": "x"}]},
    {"name": "listing_once_per_session", "steps": [
        {"op": "list_sites", "client": "A", "answer": False},
        {"op": "list_sites", "client": "A", "answer": True},
        {"op": "list_sites", "client": "A", "query": "EXAMPLE"},
        {"op": "list_sites", "client": "A", "query": "  pay\u0007pal  "},
        {"op": "list_sites", "client": "A", "query": "twosites.com"},
        {"op": "list_sites", "client": "B", "answer": True, "query": "nothing matches"},
        {"op": "list_sites", "client": "C", "answer": False}]},
    {"name": "listing_hello", "settings": {"require_hello_for_agents": True}, "steps": [
        {"op": "list_sites", "client": "A", "answer": True, "query": "git"}]},
    {"name": "request_hosts", "steps": [
        {"op": "request_login", "client": "A", "site": "paypal.com", "purpose": "Pay the\nbill ‮please",
         "answer": True},
        {"op": "request_login", "client": "A", "site": "https://login.example.com/signin", "purpose": "p" * 400,
         "answer": True},
        {"op": "request_login", "client": "B", "site": "example.com", "purpose": "", "answer": False},
        {"op": "advance", "seconds": 61},
        {"op": "request_login", "client": "A", "site": "files.example.com", "purpose": "x"},
        {"op": "request_login", "client": "A", "site": "bank.example.org", "purpose": "x"},
        {"op": "request_login", "client": "A", "site": "never.example.net", "purpose": "x"},
        {"op": "request_login", "client": "A", "site": "odd.example.net", "purpose": "x"},
        {"op": "request_login", "client": "A", "site": "private.example.net", "purpose": "x"},
        {"op": "request_login", "client": "A", "site": "flag.example.net", "purpose": "x"},
        {"op": "request_login", "client": "A", "site": "note.example.net", "purpose": "x"},
        {"op": "request_login", "client": "A", "site": "loose.example.net", "purpose": "x"},
        {"op": "request_login", "client": "A", "site": "legacy.example.io", "purpose": "x", "answer": True},
        {"op": "request_login", "client": "C", "site": "b.other.org", "purpose": "x", "answer": True},
        {"op": "request_login", "client": "A", "site": "localhost", "purpose": "x"},
        {"op": "request_login", "client": "A", "site": "", "purpose": "x"}]},
    {"name": "rate_limits", "steps": [
        *[{"op": "request_login", "client": "A", "site": "paypal.com", "purpose": str(i), "answer": False}
          for i in range(3)],
        {"op": "request_login", "client": "A", "site": "paypal.com", "purpose": "4"},
        {"op": "list_sites", "client": "A"},
        *[{"op": "request_login", "client": "B", "site": "paypal.com", "purpose": str(i), "answer": False}
          for i in range(3)],
        *[{"op": "request_login", "client": "C", "site": "paypal.com", "purpose": str(i), "answer": False}
          for i in range(3)],
        {"op": "advance", "seconds": 30},
        {"op": "list_sites", "client": "B"},
        {"op": "advance", "seconds": 31},
        {"op": "request_login", "client": "A", "site": "paypal.com", "purpose": "again", "answer": True}]},
    {"name": "password_grant_life", "steps": [
        {"op": "request_login", "client": "A", "site": "login.example.com", "purpose": "x", "answer": True},
        {"op": "take_for_origin", "origin": EX},
        {"op": "fill_login", "client": "B", "grant": "G1"},
        {"op": "fill_login", "client": "A", "grant": "nope"},
        {"op": "fill_login", "client": "A", "grant": None},
        {"op": "fill_login", "client": "A", "grant": "G1", "during": [
            {"op": "take_for_origin", "origin": "http://login.example.com"},
            {"op": "take_for_origin", "origin": "https://shop.example.com"},
            {"op": "take_for_origin", "origin": "https://examp1e.com"}]},
        {"op": "take_for_origin", "origin": EX},
        {"op": "fill_login", "client": "A", "grant": "G1", "during": [
            {"op": "take_for_origin", "origin": "https://login.example.com:8443"},
            {"op": "take_for_origin", "origin": EX},
            {"op": "finish", "grant": "G1", "outcome": "picker"}]},
        {"op": "fill_login", "client": "A", "grant": "G1"},
        {"op": "request_login", "client": "A", "site": "example.com", "purpose": "x", "answer": True},
        {"op": "fill_login", "client": "A", "grant": "G2", "during": [
            {"op": "take_for_origin", "origin": "https://example.com"},
            {"op": "take_for_origin", "origin": "https://shop.example.com"},
            {"op": "finish", "grant": "G2", "outcome": "filled"}]}]},
    {"name": "password_grant_expiry", "steps": [
        {"op": "request_login", "client": "A", "site": "paypal.com", "purpose": "x", "answer": True},
        {"op": "fill_login", "client": "A", "grant": "G1", "during": [
            {"op": "advance", "seconds": 61},
            {"op": "take_for_origin", "origin": "https://www.paypal.com"}]},
        {"op": "advance", "seconds": 240},
        {"op": "fill_login", "client": "A", "grant": "G1"},
        {"op": "request_login", "client": "A", "site": "paypal.com", "purpose": "x", "answer": True},
        {"op": "fill_login", "client": "A", "grant": "G2", "during": [
            {"op": "set", "settings": {"agents_enabled": False}},
            {"op": "take_for_origin", "origin": "https://www.paypal.com"},
            {"op": "set", "settings": {"agents_enabled": True}, "pro": False},
            {"op": "take_for_origin", "origin": "https://www.paypal.com"},
            {"op": "set", "pro": True},
            {"op": "take_for_origin", "origin": "https://paypal.com"},
            {"op": "finish", "grant": "G2", "outcome": "none"}]},
        {"op": "set", "settings": {"agents_enabled": False}},
        {"op": "fill_login", "client": "A", "grant": "G2"}]},
    {"name": "passkey_grant", "steps": [
        {"op": "request_login", "client": "A", "site": "github.com", "purpose": "Open a PR", "answer": True},
        {"op": "passkey_pending", "origin": "https://github.com"},
        {"op": "passkey_pending", "origin": "https://gist.github.com"},
        {"op": "take_for_origin", "origin": "https://github.com"},
        {"op": "take_passkey_for_origin", "origin": "https://github.com", "credentials": ["pk-other"]},
        {"op": "fill_login", "client": "A", "grant": "G1"},
        {"op": "fill_login", "client": "A", "grant": "G1", "during": [
            {"op": "take_passkey_for_origin", "origin": "https://github.com", "credentials": ["x", "pk-octo"]},
            {"op": "passkey_pending", "origin": "https://github.com"},
            {"op": "finish", "grant": "G1", "outcome": "passkey"}]},
        {"op": "fill_login", "client": "A", "grant": "G1"},
        {"op": "request_login", "client": "A", "site": "shop.example.com", "purpose": "x", "answer": True},
        {"op": "request_login", "client": "A", "site": "github.com", "purpose": "x", "answer": True},
        {"op": "fill_login", "client": "A", "grant": "G3", "during": [
            {"op": "take_passkey_for_origin", "origin": "https://github.com", "credentials": ["pk-octo"]},
            {"op": "finish", "grant": "G3", "outcome": "none"}]},
        {"op": "advance", "seconds": 301},
        {"op": "passkey_pending", "origin": "https://github.com"},
        {"op": "fill_login", "client": "A", "grant": "G3"}]},
    {"name": "hello_on_sign_in", "settings": {"require_hello_for_agents": True}, "steps": [
        {"op": "request_login", "client": "C", "site": "github.com", "purpose": "\u0000", "answer": True},
        {"op": "request_login", "client": "B", "site": "www.paypal.com", "purpose": "x", "answer": True}]},
]


class _Ui:
    def __init__(self) -> None:
        self.answers: list[bool] = []
        self.prompts: list[list[dict[str, Any]]] = [[]]  # one list per running step (a stack)

    def confirm_agent(self, request: Any) -> bool:
        self.prompts[-1].append({"action": request.action, "agent": request.agent, "process": request.process,
                             "site": request.site, "purpose": request.purpose, "hello": request.hello,
                             "method": request.method})
        if not self.answers:
            raise AssertionError(f"unexpected prompt {self.prompts[-1][-1]}")
        return self.answers.pop(0)


class _Session:
    def __init__(self, vault: list[dict[str, Any]], passkeys: list[dict[str, Any]]) -> None:
        self._vault = vault
        self._passkeys = passkeys

    def summaries(self) -> list[Any]:
        return [SimpleNamespace(id=row["id"], label=row["title"], kind=row["kind"]) for row in self._vault]

    def get_entry(self, entry_id: str) -> Any:
        for row in self._vault:
            if row["id"] == entry_id:
                return json.loads(json.dumps(row["record"]))
        return None

    def passkeys(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self._passkeys]


class _ScriptedEvent:
    """``Grant.done`` whose wait runs the step's ``during`` steps, then answers like ``threading.Event.wait``."""

    def __init__(self, event: threading.Event, during: list[dict[str, Any]], run: Any) -> None:
        self._event = event
        self._during = during
        self._run = run
        self.outputs: list[dict[str, Any]] = []

    def wait(self, timeout: float | None = None) -> bool:
        for step in self._during:
            self.outputs.append(self._run(step))
        self._during = []
        return self._event.is_set()

    def set(self) -> None:
        self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set()


def _result(value: Any, now: float) -> dict[str, Any]:
    if isinstance(value, Refusal):
        return {"refused": value.reason}
    if isinstance(value, Grant):
        return {"grant": value.id, "domain": value.domain, "hosts": sorted(value.hosts),
                "entry_ids": sorted(value.entry_ids), "passkey_ids": sorted(value.passkey_ids),
                "method": value.method, "expires_in": value.expires - now}
    if isinstance(value, list):
        return {"sites": value}
    if isinstance(value, dict):
        return {"fill": value}
    raise TypeError(type(value))


def _replay_gate(scenario: dict[str, Any]) -> dict[str, Any]:
    now = [START]
    settings = SimpleNamespace(agents_enabled=True, require_hello_for_agents=False)
    for key, value in scenario.get("settings", {}).items():
        setattr(settings, key, value)
    pro = [scenario.get("pro", True)]
    session = None if scenario.get("locked") else _Session(VAULT, PASSKEYS)
    ui = _Ui()
    log: list[list[list[str]]] = [[]]  # one list per running step (a stack), like the prompts and unlocks
    unlocks = [0]
    ids = iter(f"G{n}" for n in range(1, 1000))
    original = agent_gate.secrets.token_urlsafe
    agent_gate.secrets.token_urlsafe = lambda _n=18: next(ids)  # type: ignore[assignment]
    gate = AgentGate(lambda: session, settings, ui, lambda event, result: log[-1].append([event, result]),
                     is_pro=lambda: pro[0], request_unlock=lambda: unlocks.__setitem__(-1, unlocks[-1] + 1),
                     clock=lambda: now[0], locked_wait=0.0, fill_wait=0.0)

    def client(name: str) -> ClientInfo:
        info = CLIENTS[name]
        return ClientInfo(info["client_id"], info["name"], info["process"])

    def run(step: dict[str, Any]) -> dict[str, Any]:
        log.append([])
        ui.prompts.append([])
        unlocks.append(0)
        op = step["op"]
        if "answer" in step:
            ui.answers = [step["answer"]]
        out: dict[str, Any] = {}
        if op == "list_sites":
            out["result"] = _result(gate.list_sites(client(step["client"]), step.get("query", "")), now[0])
        elif op == "request_login":
            out["result"] = _result(gate.request_login(client(step["client"]), step["site"], step["purpose"]), now[0])
        elif op == "fill_login":
            scripted = None
            grant = gate._grants.get(step["grant"]) if isinstance(step["grant"], str) else None  # noqa: SLF001
            if grant is not None:
                original_event = grant.done
                scripted = _ScriptedEvent(original_event, step.get("during", []), run)
                grant.done = scripted  # type: ignore[assignment]
            elif step.get("during"):
                raise AssertionError("during on an unknown grant")
            value = gate.fill_login(client(step["client"]), step["grant"], step.get("tab_hint", ""))
            if grant is not None:
                grant.done = original_event
            if scripted is not None and scripted._during:  # noqa: SLF001
                raise AssertionError(f"{scenario['name']}: the fill never waited, so its during steps did not run")
            during = scripted.outputs if scripted is not None else []
            if during:
                out["during"] = during
            out["result"] = _result(value, now[0])
        elif op == "take_for_origin":
            taken = gate.take_for_origin(step["origin"])
            out["result"] = {"taken": taken.id if taken else None}
        elif op == "take_passkey_for_origin":
            taken = gate.take_passkey_for_origin(step["origin"], step["credentials"])
            out["result"] = {"taken": taken.id if taken else None}
        elif op == "passkey_pending":
            out["result"] = {"pending": gate.passkey_pending(step["origin"])}
        elif op == "finish":
            AgentGate.finish(gate._grants[step["grant"]], step["outcome"])  # noqa: SLF001
        elif op == "advance":
            now[0] += step["seconds"]
        elif op == "set":
            for key, value in step.get("settings", {}).items():
                setattr(settings, key, value)
            if "pro" in step:
                pro[0] = step["pro"]
        else:
            raise ValueError(op)
        if ui.answers:
            raise AssertionError(f"{scenario['name']}: unused answer in {step}")
        out["prompts"] = ui.prompts.pop()
        out["log"] = log.pop()
        out["unlocks"] = unlocks.pop()
        return {**step, "expect": out}

    try:
        steps = []
        for step in scenario["steps"]:
            done = run(step)
            if "during" in done.get("expect", {}):
                # Report the nested steps in place of the step's own during list.
                done["during"] = done["expect"].pop("during")
            steps.append(done)
    finally:
        agent_gate.secrets.token_urlsafe = original  # type: ignore[assignment]
    return {**scenario, "steps": steps}


def gate_doc() -> dict[str, Any]:
    return {
        "constants": {"grant_ttl": agent_gate.GRANT_TTL, "arm_ttl": agent_gate.ARM_TTL,
                      "max_purpose": agent_gate.MAX_PURPOSE, "max_site": agent_gate.MAX_SITE,
                      "max_listed": agent_gate.MAX_LISTED, "rate_window": agent_gate.RATE_WINDOW,
                      "rate_per_client": agent_gate.RATE_PER_CLIENT, "rate_total": agent_gate.RATE_TOTAL},
        "start": START, "clients": CLIENTS, "vault": VAULT, "passkeys": PASSKEYS,
        "scenarios": [_replay_gate(scenario) for scenario in SCENARIOS],
    }


def generate(out_dir: Path = OUT) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, doc in (("text.json", text_doc()), ("mcp.json", mcp_doc()), ("gate.json", gate_doc())):
        path = out_dir / name
        path.write_bytes(_dump(doc))
        written.append(path)
    return written


if __name__ == "__main__":
    for path in generate(Path(sys.argv[1]) if len(sys.argv) > 1 else OUT):
        print(path)
