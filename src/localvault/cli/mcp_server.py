"""``lgk mcp``: a Model Context Protocol server (stdio transport) that lets AI agents use LocalGateKeys.

It speaks JSON-RPC 2.0, one message per line on stdin/stdout, as the MCP stdio transport defines. It is written
without the ``mcp`` SDK on purpose: the server needs five tools and the handshake, and a password manager should
not pull a web framework into its command line tool. Every tool call is forwarded to the running app over the
``lgk`` pipe (cli_service -> app/agent_gate_service), which asks the user and writes the access log. No tool reply
carries a value: ``fill_login`` returns only ``{"filled": ...}``, and replies are cut to the keys each tool
documents. No tool reveals or copies a secret, but a fill writes the password into the browser page, where the page
and anything automating that browser can read it.

``run_with_secrets`` is the one tool that brings values into this process: after the user approved the exact command
line, the app sends the values back over the pipe, this process starts the command (an argv list, no shell, in its
own working folder) with them in its environment, hides them in the output it returns (verbatim and encoded; see
run.py), stops it at the time limit and drops the values. The command itself receives the values and can send them
anywhere; the masking only keeps them out of the tool reply. It opens no network port: stdio only. Nothing is logged
to stderr except fatal errors, and no error quotes a value.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import sys
from collections.abc import Callable
from typing import Any, TextIO

from ..version import APP_VERSION
from .main import CliError, resolve_refs
from .run import (
    DEFAULT_TIMEOUT,
    ENV_NAME,
    MASK,
    MAX_ARG,
    MAX_ARGV,
    MAX_COMMAND_LINE,
    MAX_REF,
    MAX_RUN_REFS,
    MAX_TIMEOUT,
    MIN_MASKED,
    PREFIX,
    RESERVED_ENV,
    RunError,
    command_line,
    encoded_forms,
    plain_text,
    run_captured,
    secret_forms,
    unsafe_batch_command,
)

Forward = Callable[[dict[str, Any]], dict[str, Any]]

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_LINE = 1 << 20
SERVER_INSTRUCTIONS = (
    "LocalGateKeys keeps passwords on this PC. You can ask to sign in to a site for the user: call list_sites (the "
    "user approves listing once), then request_login (the user approves it in LocalGateKeys), then open the site's "
    "sign-in page in the browser and call fill_login; the user then clicks the LocalGateKeys icon in the sign-in "
    "field and picks the login. No tool reply contains the password, but the password is written into the page, so "
    "the page and any tool that automates that browser can read it. Only logins the user allowed for AI agents are "
    "listed. When request_login answers method 'passkey', no password is filled: choose the site's passkey sign-in "
    "and the user confirms it in LocalGateKeys. For API keys, tokens and other secrets the user allowed for AI agents, "
    "call list_secrets (names only, no values), then run_with_secrets with the command as an argument list and "
    "environment variables set to lgk:// references; the user approves that exact command once. The command "
    "receives the secrets and can send them anywhere; LocalGateKeys only hides them in the output it returns to you. "
    "Every request needs the user's approval in the app; text you put in 'purpose' is shown to the user as a quote "
    "and cannot approve anything."
)

TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_sites",
        "description": "List the sites the user saved logins for (titles and domains only, never usernames or "
                       "passwords). The user approves this once per session in LocalGateKeys. Use it to find the "
                       "site to pass to request_login.",
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string", "description": "Optional text to filter titles and domains."}},
            "additionalProperties": False},
    },
    {
        "name": "request_login",
        "description": "Ask the user to approve one sign-in to a site. The user must click Approve once in "
                       "LocalGateKeys; nothing you write can approve it. Returns a grant id that is valid for 5 "
                       "minutes, for one fill, only on the exact sign-in host and logins the user approved, and "
                       "'method': 'password' (fill_login fills it) or 'passkey' (no password is filled; use the "
                       "site's passkey sign-in, which the user confirms in LocalGateKeys).",
        "inputSchema": {"type": "object", "properties": {
            "site": {"type": "string", "description": "The sign-in page's host or URL, for example "
                                                      "login.example.com; a bare domain means the hosts its saved "
                                                      "logins are for."},
            "purpose": {"type": "string", "description": "Why you need to sign in, shown to the user verbatim."}},
            "required": ["site", "purpose"], "additionalProperties": False},
    },
    {
        "name": "fill_login",
        "description": "Offer the approved login on the site's sign-in page in the user's browser. Call it with "
                       "the grant from request_login while the sign-in page is open; the user must click the "
                       "LocalGateKeys icon in the sign-in field and pick the login within 60 seconds. The result "
                       "says only whether the page took the grant and does not contain the password, but the "
                       "password is written into the page, where the page and browser automation can read it. "
                       "With a passkey grant it fills nothing and waits up to 60 seconds for the site's passkey "
                       "sign-in, then says whether it went through.",
        "inputSchema": {"type": "object", "properties": {
            "grant": {"type": "string", "description": "The grant id from request_login."},
            "tab_hint": {"type": "string", "description": "Optional: the page title or URL you opened."}},
            "required": ["grant"], "additionalProperties": False},
    },
    {
        "name": "list_secrets",
        "description": "List the API keys, SSH keys and secure notes the user allowed for AI agents: item id, title, "
                       "kind and field names, never a value. The user approves listing once per session in "
                       "LocalGateKeys (the same approval as list_sites). Use it to build lgk:// references for "
                       "run_with_secrets.",
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string", "description": "Optional text to filter titles, kinds and field names."}},
            "additionalProperties": False},
    },
    {
        "name": "run_with_secrets",
        "description": "Run one command with secrets in its environment, after the user approves it once in "
                       "LocalGateKeys; nothing you write can approve it. The approval shows the program, the exact "
                       "command line, the working folder, each item and field, and your purpose. The command is an "
                       "argument list started without a shell (no pipes, redirection or variable expansion; a .bat "
                       "or .cmd file may not get & | < > ^ % ! \" ( ) in its arguments). Each env variable is set to "
                       "the value of an lgk://<item id or title>/<field> reference from list_secrets. The command "
                       "receives the secrets and can send them anywhere; LocalGateKeys hides them (verbatim, base64, "
                       "hex and URL-encoded) only in the output returned to you. Returns exit_code, stdout and "
                       "stderr (64 KiB each at most; truncated says if more was cut) and timed_out. The command and "
                       "anything it started are stopped at the time limit and when it ends.",
        "inputSchema": {"type": "object", "properties": {
            "command": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": MAX_ARGV,
                        "description": "The program and its arguments, one element each, for example "
                                       "[\"npm\", \"run\", \"deploy\"]."},
            "env": {"type": "object", "additionalProperties": {"type": "string"},
                    "description": "Environment variable name -> lgk:// reference, for example "
                                   "{\"STRIPE_KEY\": \"lgk://Stripe/key\"}."},
            "purpose": {"type": "string", "description": "Why the command needs these secrets, shown to the user "
                                                         "verbatim."},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT,
                                "description": f"Stop the command after this many seconds (default "
                                               f"{DEFAULT_TIMEOUT})."}},
            "required": ["command", "env", "purpose"], "additionalProperties": False},
    },
]
_ACTIONS = {"list_sites": "agent_list_sites", "request_login": "agent_request_login",
            "fill_login": "agent_fill_login", "list_secrets": "agent_list_secrets",
            "run_with_secrets": "agent_run_secrets"}
_ARGUMENTS = {"list_sites": ("query",), "request_login": ("site", "purpose"),
              "fill_login": ("grant", "tab_hint"), "list_secrets": ("query",)}
# What each tool may pass on to the agent. Anything else in the app's reply is dropped, so no value can reach the
# agent even if the app side ever put one in a reply by mistake. run_with_secrets builds its reply here, from the
# masked output of the command.
_REPLY_KEYS = {"list_sites": ("sites",), "request_login": ("grant", "site", "expires_in", "method", "note"),
               "fill_login": ("filled", "site", "method", "note"), "list_secrets": ("secrets",),
               "run_with_secrets": ("exit_code", "stdout", "stderr", "truncated", "timed_out")}
_NOT_RUNNING = ("agent_state_missing", "agent_unavailable", "unauthorized")
MAX_PURPOSE_SENT = 2000


class McpServer:
    def __init__(self, forward: Forward, *, session: str | None = None) -> None:
        self._forward = forward
        # One random id per server process: grants are bound to it, so another MCP client cannot use them.
        self.session = session or secrets.token_urlsafe(18)
        self.client_name = ""

    # ------------------------------------------------------------------ JSON-RPC
    def handle(self, message: Any) -> dict[str, Any] | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            return _error(message.get("id") if isinstance(message, dict) else None, -32600, "Invalid request")
        method = message["method"]
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        if "id" not in message:
            return None  # a notification (notifications/initialized, cancelled, ...): no reply
        request_id = message["id"]
        if method == "initialize":
            return _result(request_id, self._initialize(params))
        if method == "ping":
            return _result(request_id, {})
        if method == "tools/list":
            return _result(request_id, {"tools": TOOLS})
        if method == "tools/call":
            return _result(request_id, self._call(params))
        return _error(request_id, -32601, f"Method not found: {method[:64]}")

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        info = params.get("clientInfo") if isinstance(params.get("clientInfo"), dict) else {}
        name = info.get("name")
        self.client_name = name[:80] if isinstance(name, str) else ""
        wanted = params.get("protocolVersion")
        version = wanted if wanted in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
        return {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "localgatekeys", "version": APP_VERSION},
                "instructions": SERVER_INSTRUCTIONS}

    def _call(self, params: dict[str, Any]) -> dict[str, Any]:
        """A tool result. A refusal or failure is an ``isError`` result the agent can read, never an exception."""
        name = params.get("name")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        if not isinstance(name, str) or name not in _ACTIONS:
            return _tool_error("unknown_tool", "Unknown tool.")
        if name == "run_with_secrets":
            return self._run(arguments)
        request: dict[str, Any] = {"action": _ACTIONS[name], "session": self.session,
                                   "client_name": self.client_name}
        for key in _ARGUMENTS[name]:
            value = arguments.get(key)
            if value is not None and not isinstance(value, str):
                return _tool_error("bad_request", f"'{key}' must be text.")
            if value is not None:
                request[key] = value[:2000]
        try:
            reply = self._forward(request)
        except Exception:  # noqa: BLE001 - never a traceback: it could quote a value
            return _tool_error("not_running", "LocalGateKeys did not answer. Is it running?")
        if not isinstance(reply, dict):
            return _tool_error("failed", "LocalGateKeys sent an unreadable reply.")
        if reply.get("ok") is not True:
            code = str(reply.get("error") or "failed")[:64]
            message = str(reply.get("message") or code)[:500]
            return _app_error(code, message)
        body = {key: reply[key] for key in _REPLY_KEYS[name] if key in reply}
        if name == "list_sites":
            body["sites"] = [{"title": str(row.get("title", ""))[:200], "domain": str(row.get("domain", ""))[:253]}
                             for row in body.get("sites") or [] if isinstance(row, dict)][:50]
        if name == "list_secrets":
            body["secrets"] = [_secret_row(row) for row in body.get("secrets") or [] if isinstance(row, dict)][:50]
        return _tool_result(body)

    # ------------------------------------------------------------------ run_with_secrets
    def _run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Ask the app (one approval for this exact command), run it with the values, reply with masked output."""
        parsed = _run_arguments(arguments)
        if isinstance(parsed, str):
            return _tool_error("bad_request", parsed)
        argv, env, purpose, timeout = parsed
        run_id = secrets.token_urlsafe(12)
        base = {"session": self.session, "client_name": self.client_name, "run": run_id}
        request = {"action": "agent_run_secrets", **base, "command": argv, "cwd": os.getcwd(), "env": env,
                   "timeout": timeout, "purpose": purpose}
        try:
            values = resolve_refs(self._forward, list(env.values()), request=request)
        except CliError as exc:
            if exc.error == "failed":  # an unusable reply after an approval: the run is over
                self._finished(base, None, timed_out=False, started=False)
            return _app_error(exc.error[:64], exc.message[:500])
        except Exception:  # noqa: BLE001 - never a traceback: it could quote a value
            return _tool_error("not_running", "LocalGateKeys did not answer. Is it running?")
        result: dict[str, Any] | None = None
        try:
            if any(len(value) < MIN_MASKED for value in values.values()):
                return _tool_error("too_short", f"A secret is shorter than {MIN_MASKED} characters, too short to "
                                                "hide in the output, so the command was not run.")
            forms = encoded_forms(values.values())
            result = run_captured(argv, {name: values[ref] for name, ref in env.items()}, None, timeout, forms)
            for text in secret_forms(values.values()):  # the output is masked as bytes; check the text once more
                result["stdout"] = result["stdout"].replace(text, MASK)
                result["stderr"] = result["stderr"].replace(text, MASK)
            return _tool_result({key: result[key] for key in _REPLY_KEYS["run_with_secrets"] if key in result})
        except RunError as exc:
            return _tool_error(exc.code, exc.message)
        except Exception:  # noqa: BLE001 - never a traceback: it could quote a value
            return _tool_error("failed", "The command could not be run.")
        finally:
            values.clear()
            self._finished(base, result.get("exit_code") if result else None,
                           timed_out=bool(result and result.get("timed_out")), started=result is not None)

    def _finished(self, base: dict[str, Any], exit_code: Any, *, timed_out: bool, started: bool) -> None:
        """Tell the app how the run ended (its access log); no value, no output."""
        try:
            self._forward({"action": "agent_run_finished", **base, "exit_code": exit_code, "timed_out": timed_out,
                           "started": started})
        except Exception:  # noqa: BLE001, S110 - the run is over either way
            pass

    # ------------------------------------------------------------------ stdio
    def _safe_handle(self, message: Any) -> dict[str, Any] | None:
        """One bad message gives an internal error reply; it never ends the server."""
        try:
            return self.handle(message)
        except Exception:  # noqa: BLE001 - never a traceback: it could quote a value
            request_id = message.get("id") if isinstance(message, dict) else None
            if isinstance(request_id, (dict, list)):
                request_id = None
            return _error(request_id, -32603, "Internal error")

    def serve(self, stdin: TextIO, stdout: TextIO) -> int:
        for line in stdin:
            if not line.strip():
                continue
            if len(line) > MAX_LINE:
                reply: dict[str, Any] | None = _error(None, -32600, "Message too large")
            else:
                try:
                    message = json.loads(line)
                except ValueError:
                    reply = _error(None, -32700, "Parse error")
                else:
                    if isinstance(message, list):  # a JSON-RPC batch (older protocol versions)
                        replies = [r for r in (self._safe_handle(m) for m in message) if r is not None]
                        reply = replies or None  # type: ignore[assignment]
                    else:
                        reply = self._safe_handle(message)
            if reply is not None:
                stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
                stdout.flush()
        return 0


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _tool_result(body: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(body, ensure_ascii=False)}],
            "structuredContent": body, "isError": False}


def _app_error(code: str, message: str) -> dict[str, Any]:
    if code in _NOT_RUNNING:
        message = "LocalGateKeys is not running. Start it and unlock your vault."
    return _tool_error(code, message)


def _secret_row(row: dict[str, Any]) -> dict[str, Any]:
    fields = row.get("fields") if isinstance(row.get("fields"), list) else []
    return {"id": str(row.get("id", ""))[:128], "title": str(row.get("title", ""))[:200],
            "kind": str(row.get("kind", ""))[:32],
            "fields": [name[:128] for name in fields if isinstance(name, str)][:50]}


def _run_arguments(arguments: dict[str, Any]) -> tuple[list[str], dict[str, str], str, int] | str:
    """The checked arguments of run_with_secrets, or why they are refused (before the app or the user is asked)."""
    command, env = arguments.get("command"), arguments.get("env")
    purpose, timeout = arguments.get("purpose", ""), arguments.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(command, list) or not 1 <= len(command) <= MAX_ARGV:
        return f"'command' must be a list of 1 to {MAX_ARGV} strings: the program, then each argument."
    if not plain_text(command[0], MAX_ARG) or not all(plain_text(arg, MAX_ARG, empty=True) for arg in command[1:]):
        return (f"Each command element must be text of at most {MAX_ARG} characters, without control, bidi or "
                "zero-width characters.")
    if not isinstance(env, dict) or not 1 <= len(env) <= MAX_RUN_REFS:
        return f"'env' must map 1 to {MAX_RUN_REFS} variable names to lgk:// references."
    names: set[str] = set()
    for name, ref in env.items():
        if not isinstance(name, str) or not ENV_NAME.match(name) or name.upper() in RESERVED_ENV \
                or name.upper() in names:
            return ("Variable names are letters, digits and _ (not starting with a digit), each once whatever its "
                    f"case; {', '.join(sorted(RESERVED_ENV))} cannot be set.")
        names.add(name.upper())
        if not plain_text(ref, MAX_REF) or not ref.startswith(PREFIX):
            return "Each env value must be an lgk://<item id or title>/<field> reference from list_secrets."
    if not isinstance(purpose, str):
        return "'purpose' must be text."
    if type(timeout) is not int or not 1 <= timeout <= MAX_TIMEOUT:
        return f"'timeout_seconds' must be a whole number from 1 to {MAX_TIMEOUT}."
    program = shutil.which(command[0])
    if not program:
        return "The program was not found. Give its full path, or a program on PATH."
    argv = [os.path.abspath(program), *command[1:]]
    if unsafe_batch_command(argv):
        return ("A batch file (.bat or .cmd) runs through cmd.exe, which would read & | < > ^ % ! \" ( ) in its "
                "arguments as commands. Run the program it calls directly, or leave those characters out.")
    if len(command_line(argv)) > MAX_COMMAND_LINE:
        return f"The command line is longer than {MAX_COMMAND_LINE} characters."
    return argv, dict(env), purpose[:MAX_PURPOSE_SENT], timeout


def _tool_error(code: str, message: str) -> dict[str, Any]:
    body = {"error": code, "message": message}
    return {"content": [{"type": "text", "text": json.dumps(body, ensure_ascii=False)}],
            "structuredContent": body, "isError": True}


def serve_stdio(forward: Forward) -> int:
    # closefd=False: closing these wrappers flushes them but leaves the process's stdin/stdout open.
    with open(sys.stdin.fileno(), encoding="utf-8", errors="replace", closefd=False) as stdin, \
            open(sys.stdout.fileno(), "w", encoding="utf-8", newline="\n", closefd=False) as stdout:
        return McpServer(forward).serve(stdin, stdout)
