"""``lgk mcp`` run_with_secrets and list_secrets: the runner (real child processes) and the tool layer (fake pipe).

The app side (approval, per-item switch, one use per session) is in tests/test_agent_secrets.py.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
import urllib.parse

import pytest

from localvault.cli import run as runner
from localvault.cli.mcp_server import TOOLS, McpServer
from localvault.cli.run import MASK, encoded_forms, mask_output, run_captured

SECRET = "sk-live-Zq9/x+y=w&p%Q~1"  # has characters that base64, hex and URL encoding all change
REF = "lgk://Stripe/key"
PY = sys.executable


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path))


def _forms(*values: str) -> list[bytes]:
    return encoded_forms(list(values))


def _leaks(text: str, secret: str = SECRET) -> list[str]:
    """Every form of ``secret`` that is still in ``text``."""
    raw = secret.encode()
    forms = {
        "verbatim": secret, "hex": raw.hex(), "HEX": raw.hex().upper(),
        "base64": base64.b64encode(raw).decode(), "base64url": base64.urlsafe_b64encode(raw).decode(),
        "url": urllib.parse.quote(secret, safe=""), "url+": urllib.parse.quote_plus(secret),
    }
    return [name for name, form in forms.items() if form in text]


# ---------------------------------------------------------------------------------------------------- masking
@pytest.mark.parametrize("encode", [
    lambda s: s.encode(),
    lambda s: s.encode().hex().encode(),
    lambda s: s.encode().hex().upper().encode(),
    lambda s: base64.b64encode(s.encode()),
    lambda s: base64.b64encode(s.encode()).rstrip(b"="),
    lambda s: base64.urlsafe_b64encode(s.encode()),
    lambda s: urllib.parse.quote(s, safe="").encode(),
    lambda s: urllib.parse.quote(s).encode(),
    lambda s: urllib.parse.quote_plus(s).encode(),
    lambda s: re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), urllib.parse.quote(s, safe="")).encode(),
    lambda s: s.encode("utf-16-le"),
    lambda s: json.dumps(s).encode(),
], ids=["verbatim", "hex", "HEX", "base64", "base64-nopad", "base64url", "url", "url-slash", "url-plus",
        "url-lower", "utf16", "json"])
def test_masking_hides_verbatim_and_encoded_forms(encode) -> None:
    data = b"before " + encode(SECRET) + b" after"
    masked = mask_output(data, _forms(SECRET))
    assert MASK.encode() in masked and masked.startswith(b"before ") and masked.endswith(b" after")
    assert encode(SECRET) not in masked


@pytest.mark.parametrize("offset", [0, 1, 2])
def test_masking_hides_a_value_inside_a_longer_base64_blob(offset) -> None:
    """``echo "user:$TOKEN" | base64`` puts the value at any byte offset; each alignment encodes differently."""
    blob = base64.b64encode(b"x" * offset + b"Authorization: " + SECRET.encode() + b" end")
    masked = mask_output(b"header " + blob, _forms(SECRET))
    assert MASK.encode() in masked
    decoded = base64.b64decode(blob)
    assert SECRET.encode() in decoded  # the test data really holds the value


def test_masking_merges_overlapping_values_and_keeps_the_mask_text_intact() -> None:
    data = b"xxABCDEFyy and Gate"
    masked = mask_output(data, _forms("ABCDEF", "EFyy", "Gate"))
    assert masked == MASK.encode() .join([b"xx", b" and ", b""])
    assert b"yy" not in masked


def test_masking_covers_each_line_of_a_multiline_value_and_crlf() -> None:
    key = "-----BEGIN KEY-----\nAAAAsecretline\n-----END KEY-----"
    masked = mask_output(key.replace("\n", "\r\n").encode(), _forms(key))
    assert b"AAAAsecretline" not in masked


def test_short_values_are_not_masked_forms() -> None:
    assert _forms("abc") == []


@pytest.mark.parametrize("shift", range(0, 30))
def test_a_value_split_across_the_output_cap_never_leaks(shift) -> None:
    limit = 64
    data = b"a" * (limit - shift) + SECRET.encode() + b"tail" * 40
    out, truncated = runner.cut_masked(data, _forms(SECRET), limit)
    assert truncated is True
    for size in range(4, len(SECRET) + 1):  # no piece of the value of 4 or more characters is shown
        assert SECRET[:size].encode() not in out
    assert len(out) <= limit + len(MASK)


def test_the_cap_keeps_text_before_the_value() -> None:
    out, truncated = runner.cut_masked(b"hello " + SECRET.encode(), _forms(SECRET), 1000)
    assert (out, truncated) == (b"hello " + MASK.encode(), False)


# ---------------------------------------------------------------------------------------------------- the child
def test_argv_with_shell_metacharacters_stays_one_argument(tmp_path) -> None:
    args = ["a & b", "x|y", "c > d", '"q"', "$(rm -rf /)", "%PATH%", "^!", "semi;colon", "", "back\\slash\\"]
    script = "import json,sys; print(json.dumps(sys.argv[1:]))"
    result = run_captured([PY, "-c", script, *args], {}, str(tmp_path), 30, [])
    assert result["exit_code"] == 0 and result["timed_out"] is False
    assert json.loads(result["stdout"]) == args
    assert not list(tmp_path.iterdir())  # no redirection happened


def test_the_child_gets_the_values_and_its_output_is_masked(tmp_path) -> None:
    script = ("import os,sys,base64; v=os.environ['API_KEY']; print(v); print(base64.b64encode(v.encode()).decode());"
              "print(v.encode().hex(), file=sys.stderr); print(os.getcwd())")
    result = run_captured([PY, "-c", script], {"API_KEY": SECRET}, str(tmp_path), 30, _forms(SECRET))
    assert result["exit_code"] == 0
    assert _leaks(result["stdout"]) == [] and _leaks(result["stderr"]) == []
    assert result["stdout"].count(MASK) == 2 and MASK in result["stderr"]
    assert os.path.normcase(str(tmp_path)) in os.path.normcase(result["stdout"])  # its own working folder


def test_output_is_capped_and_reported_truncated(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner, "OUTPUT_LIMIT", 100)
    script = "import os,sys; sys.stdout.write('x'*95 + os.environ['K'] + 'y'*5000)"
    result = run_captured([PY, "-c", script], {"K": SECRET}, None, 30, _forms(SECRET))
    assert result["truncated"] is True and _leaks(result["stdout"]) == []
    assert SECRET[:4] not in result["stdout"] and result["stdout"].startswith("x" * 95)


def test_the_timeout_kills_the_child(tmp_path) -> None:
    start = time.monotonic()
    result = run_captured([PY, "-c", "import time; print('started', flush=True); time.sleep(60)"], {}, None, 1, [])
    assert result["timed_out"] is True and time.monotonic() - start < 20
    assert "started" in result["stdout"]


@pytest.mark.skipif(sys.platform != "win32", reason="job objects are Windows only")
def test_the_child_and_what_it_started_are_stopped(tmp_path) -> None:
    """A background process the command leaves behind is stopped with it (it would hold the output pipes open)."""
    psutil = pytest.importorskip("psutil")
    script = ("import subprocess,sys; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']);"
              "print(p.pid, flush=True)")
    start = time.monotonic()
    result = run_captured([PY, "-c", script], {}, None, 30, [])
    assert time.monotonic() - start < 20 and result["timed_out"] is False
    pid = int(result["stdout"].strip())
    for _ in range(50):
        if not psutil.pid_exists(pid):
            break
        time.sleep(0.1)
    assert not psutil.pid_exists(pid)


def test_a_program_that_cannot_start_is_an_error_without_values(tmp_path) -> None:
    with pytest.raises(runner.RunError) as error:
        run_captured([str(tmp_path / "missing.exe")], {"K": SECRET}, None, 5, _forms(SECRET))
    assert SECRET not in str(error.value) and SECRET not in repr(error.value.args)


@pytest.mark.parametrize("argv, unsafe", [
    (["C:\\x\\deploy.cmd", "prod"], False),
    (["C:\\x\\deploy.cmd", "a & calc"], True),
    (["C:\\x\\deploy.BAT", "100%"], True),
    (["C:\\x\\deploy.bat", 'say "hi"'], True),
    (["C:\\x\\deploy.bat", "(x)"], True),
    (["C:\\x\\deploy.exe", "a & b"], False),
])
def test_batch_files_refuse_arguments_cmd_would_reparse(argv, unsafe) -> None:
    assert runner.unsafe_batch_command(argv) is unsafe


# ---------------------------------------------------------------------------------------------------- the tools
class _Pipe:
    """The app over the pipe: answers agent_run_secrets with the values, records every request."""

    def __init__(self, values=None, reply=None):
        self.requests: list[dict] = []
        self.values = values if values is not None else {REF: SECRET}
        self.reply = reply

    def __call__(self, request):
        self.requests.append(json.loads(json.dumps(request)))
        if request["action"] == "agent_run_secrets":
            if self.reply is not None:
                return self.reply
            return {"ok": True, "values": {ref: self.values[ref] for ref in request["refs"] if ref in self.values},
                    "value": SECRET, "debug": SECRET}
        if request["action"] == "agent_list_secrets":
            return {"ok": True, "secrets": [{"id": "i1", "title": "Stripe", "kind": "api_key", "fields": ["key", 5],
                                             "value": SECRET}, "junk"], "values": [SECRET]}
        return {"ok": True}

    def actions(self) -> list[str]:
        return [r["action"] for r in self.requests]


def _server(pipe) -> McpServer:
    server = McpServer(pipe)
    server.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "claude-code"}}})
    return server


def _call(server: McpServer, name: str, **arguments) -> dict:
    reply = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": name, "arguments": arguments}})
    return reply["result"]


PRINTS = [PY, "-c", ("import os,base64; v=os.environ['API_KEY']; print(v, base64.b64encode(v.encode()).decode(), "
                     "v.encode().hex())")]


def test_tools_are_listed_with_honest_descriptions() -> None:
    names = [tool["name"] for tool in TOOLS]
    assert "list_secrets" in names and "run_with_secrets" in names
    run = next(tool for tool in TOOLS if tool["name"] == "run_with_secrets")
    assert run["inputSchema"]["properties"]["command"]["type"] == "array"
    assert set(run["inputSchema"]["required"]) == {"command", "env", "purpose"}
    assert "anywhere" in run["description"] and "approv" in run["description"]


def test_run_with_secrets_runs_once_and_replies_without_values(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    pipe = _Pipe()
    server = _server(pipe)
    result = _call(server, "run_with_secrets", command=PRINTS, env={"API_KEY": REF}, purpose="deploy")
    assert result["isError"] is False
    body = result["structuredContent"]
    assert set(body) == {"exit_code", "stdout", "stderr", "truncated", "timed_out"}
    assert body["exit_code"] == 0 and body["stdout"].count(MASK) == 3
    assert _leaks(json.dumps(result)) == [] and SECRET not in json.dumps(result, ensure_ascii=False)
    ask, done = pipe.requests
    assert ask["action"] == "agent_run_secrets" and ask["session"] == server.session
    assert ask["command"][0] == os.path.abspath(PY) or os.path.samefile(ask["command"][0], PY)
    assert ask["command"][1:] == PRINTS[1:] and ask["env"] == {"API_KEY": REF} and ask["refs"] == [REF]
    assert ask["cwd"] == os.getcwd() and ask["timeout"] == 120 and ask["purpose"] == "deploy"
    assert done == {"action": "agent_run_finished", "session": server.session, "client_name": "claude-code",
                    "run": ask["run"], "exit_code": 0, "timed_out": False, "started": True}
    assert SECRET not in json.dumps(pipe.requests)  # nothing sent back to the app carries the value


def test_each_run_has_its_own_id() -> None:
    pipe = _Pipe()
    server = _server(pipe)
    for _ in range(2):
        _call(server, "run_with_secrets", command=PRINTS, env={"API_KEY": REF}, purpose="x")
    runs = [r["run"] for r in pipe.requests if r["action"] == "agent_run_secrets"]
    assert len(set(runs)) == 2


def test_a_refusal_runs_nothing(tmp_path) -> None:
    marker = tmp_path / "ran"
    pipe = _Pipe(reply={"ok": False, "error": "not_found", "message": "No item the agent may use has that id."})
    result = _call(_server(pipe), "run_with_secrets", command=[PY, "-c", f"open(r'{marker}','w')"],
                   env={"API_KEY": "lgk://Other/key"}, purpose="x")
    assert result["isError"] is True and result["structuredContent"]["error"] == "not_found"
    assert not marker.exists() and pipe.actions() == ["agent_run_secrets"]


@pytest.mark.parametrize("arguments", [
    {"command": "deploy --prod & del *", "env": {"API_KEY": REF}},
    {"command": [], "env": {"API_KEY": REF}},
    {"command": [PY, 5], "env": {"API_KEY": REF}},
    {"command": [PY, "a\nb"], "env": {"API_KEY": REF}},
    {"command": [PY, "a\u202eb"], "env": {"API_KEY": REF}},
    {"command": [PY] + ["x"] * 80, "env": {"API_KEY": REF}},
    {"command": [PY, "x" * 5000], "env": {"API_KEY": REF}},
    {"command": [PY], "env": {}},
    {"command": [PY], "env": "API_KEY=" + REF},
    {"command": [PY], "env": {"API_KEY": SECRET}},
    {"command": [PY], "env": {"1BAD": REF}},
    {"command": [PY], "env": {"PATH": REF}},
    {"command": [PY], "env": {"api_key": REF, "API_KEY": REF}},
    {"command": [PY], "env": {f"V{i}": REF for i in range(25)}},
    {"command": [PY], "env": {"API_KEY": REF}, "timeout_seconds": 0},
    {"command": [PY], "env": {"API_KEY": REF}, "timeout_seconds": 601},
    {"command": [PY], "env": {"API_KEY": REF}, "timeout_seconds": True},
    {"command": [PY], "env": {"API_KEY": REF}, "timeout_seconds": "60"},
    {"command": [PY], "env": {"API_KEY": REF}, "purpose": 5},
    {"command": ["no-such-program-lgk-test"], "env": {"API_KEY": REF}},
])
def test_bad_arguments_are_refused_before_the_app_is_asked(arguments) -> None:
    pipe = _Pipe()
    result = _call(_server(pipe), "run_with_secrets", **{"purpose": "x", **arguments})
    assert result["isError"] is True and result["structuredContent"]["error"] == "bad_request"
    assert pipe.requests == [] and SECRET not in json.dumps(result)


@pytest.mark.skipif(sys.platform != "win32", reason="cmd.exe batch files")
def test_a_batch_file_with_cmd_metacharacters_is_refused(tmp_path) -> None:
    script = tmp_path / "deploy.cmd"
    script.write_text("@echo %1\r\n", encoding="ascii")
    pipe = _Pipe()
    refused = _call(_server(pipe), "run_with_secrets", command=[str(script), "x & calc"], env={"API_KEY": REF},
                    purpose="x")
    assert refused["isError"] is True and refused["structuredContent"]["error"] == "bad_request"
    assert "batch" in refused["structuredContent"]["message"] and pipe.requests == []
    plain = _call(_server(pipe), "run_with_secrets", command=[str(script), "prod"], env={"API_KEY": REF},
                  purpose="x")
    assert plain["isError"] is False and plain["structuredContent"]["stdout"].strip() == "prod"


def test_a_value_too_short_to_mask_is_not_used(tmp_path) -> None:
    marker = tmp_path / "ran"
    pipe = _Pipe(values={REF: "abc"})
    result = _call(_server(pipe), "run_with_secrets", command=[PY, "-c", f"open(r'{marker}','w')"],
                   env={"API_KEY": REF}, purpose="x")
    assert result["isError"] is True and result["structuredContent"]["error"] == "too_short"
    assert not marker.exists() and "abc" not in result["structuredContent"]["message"]
    assert pipe.requests[-1]["action"] == "agent_run_finished" and pipe.requests[-1]["started"] is False


def test_an_incomplete_reply_runs_nothing() -> None:
    pipe = _Pipe(values={})
    result = _call(_server(pipe), "run_with_secrets", command=PRINTS, env={"API_KEY": REF}, purpose="x")
    assert result["isError"] is True and result["structuredContent"]["error"] == "failed"


def test_errors_never_quote_a_value(monkeypatch) -> None:
    def dead(request):
        raise OSError(f"pipe broke while holding {SECRET}")
    result = _call(_server(dead), "run_with_secrets", command=PRINTS, env={"API_KEY": REF}, purpose="x")
    assert result["structuredContent"]["error"] == "not_running" and SECRET not in json.dumps(result)

    def boom(*args, **kwargs):
        raise RuntimeError(f"unexpected {SECRET}")
    monkeypatch.setattr("localvault.cli.mcp_server.run_captured", boom)
    pipe = _Pipe()
    result = _call(_server(pipe), "run_with_secrets", command=PRINTS, env={"API_KEY": REF}, purpose="x")
    assert result["isError"] is True and SECRET not in json.dumps(result)
    assert pipe.requests[-1]["action"] == "agent_run_finished"


def test_a_timed_out_run_is_reported(monkeypatch) -> None:
    pipe = _Pipe()
    result = _call(_server(pipe), "run_with_secrets", command=[PY, "-c", "import time; time.sleep(60)"],
                   env={"API_KEY": REF}, purpose="x", timeout_seconds=1)
    assert result["isError"] is False and result["structuredContent"]["timed_out"] is True
    assert pipe.requests[-1]["timed_out"] is True


def test_list_secrets_replies_only_names() -> None:
    pipe = _Pipe()
    result = _call(_server(pipe), "list_secrets", query="str")
    assert result["structuredContent"] == {"secrets": [{"id": "i1", "title": "Stripe", "kind": "api_key",
                                                        "fields": ["key"]}]}
    assert pipe.requests[0]["action"] == "agent_list_secrets" and pipe.requests[0]["query"] == "str"
    assert SECRET not in json.dumps(result)
