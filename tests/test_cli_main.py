"""lgk client front end with the pipe faked by a stub ``forward``."""
from __future__ import annotations

import ast
import io
import subprocess
import sys
from pathlib import Path

import pytest

from localvault.cli import main as cli_main
from localvault.cli.main import main

ROOT = Path(__file__).resolve().parents[1]


def run(argv, forward):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, forward=forward, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_read_prints_value_only() -> None:
    seen = []

    def forward(request):
        seen.append(request)
        return {"ok": True, "value": "s3cret"}

    code, out, err = run(["read", "lgk://GitHub/password"], forward)
    assert (code, out, err) == (0, "s3cret\n", "")
    assert seen == [{"action": "read", "ref": "lgk://GitHub/password"}]


def test_status_list_and_totp() -> None:
    status = {"ok": True, "unlocked": True, "cli_enabled": False}
    listing = {"ok": True, "items": [{"id": "a1", "title": "Prod key", "kind": "api_key"}]}
    assert run(["status"], lambda r: status)[:2] == (0, "unlocked: yes\ncommand line access: off\n")
    requests = []
    code, out, _ = run(["list", "--kind", "api_key"], lambda r: requests.append(r) or listing)
    assert (code, out) == (0, "a1\tProd key\tapi_key\n")
    assert requests == [{"action": "list", "kind": "api_key"}]
    totp = {"ok": True, "code": "123456", "seconds_left": 9}
    assert run(["totp", "lgk://GitHub/totp"], lambda r: totp)[:2] == (0, "123456\n")


def test_exit_code_app_not_running() -> None:
    for name in ("agent_state_missing", "agent_unavailable"):
        code, out, err = run(["status"], lambda r, c=name: {"ok": False, "error": c, "message": "gone"})
        assert code == 2 and out == "" and "LocalGateKeys running" in err


@pytest.mark.parametrize("error,expected", [
    ("denied", 4), ("not_allowed", 4), ("cli_disabled", 4), ("client_pin_mismatch", 4),
    ("locked", 3), ("not_found", 5), ("ambiguous", 5), ("no_field", 5),
    ("bad_reference", 1), ("cli_failed", 1), ("something_new", 1),
])
def test_error_codes_map_to_exit_codes(error, expected) -> None:
    code, out, err = run(["read", "lgk://x/y"], lambda r: {"ok": False, "error": error, "message": "no"})
    assert code == expected and out == "" and err.startswith("lgk: no")


def test_exit_code_denied() -> None:
    code, _, err = run(["read", "lgk://x/y"], lambda r: {"ok": False, "error": "denied", "message": "You said no."})
    assert code == 4 and "You said no." in err


def test_usage_errors_exit_1() -> None:
    assert run([], lambda r: {"ok": True})[0] == 1
    assert run(["read"], lambda r: {"ok": True})[0] == 1
    assert run(["run"], lambda r: {"ok": True})[0] == 1  # no command


def test_default_forward_adds_scope_hint_and_maps_failures(monkeypatch) -> None:
    from localvault import pipe_transport
    from localvault.bridge_status import BridgeFailure

    sent = []
    monkeypatch.setattr(pipe_transport, "forward_named_pipe",
                        lambda request, timeout_ms=0, **kw: sent.append(request) or {"ok": True})
    assert cli_main.default_forward({"action": "status"}) == {"ok": True}
    assert sent == [{"action": "status", "scope_hint": "cli"}]

    def refuse(request, timeout_ms=0, **kw):
        raise BridgeFailure("agent_state_missing", "state")

    monkeypatch.setattr(pipe_transport, "forward_named_pipe", refuse)
    assert cli_main.default_forward({"action": "status"})["error"] == "agent_state_missing"
    assert run(["status"], cli_main.default_forward)[0] == 2


def test_cli_never_imports_the_vault_or_crypto() -> None:
    """The client is IPC only: importing it must not pull in the vault, cryptography or local_clients."""
    code = (
        f"import sys; sys.path.insert(0, {str(ROOT / 'src')!r})\n"
        "import localvault.cli.main, localvault.cli.run, localvault.cli.inject, localvault.pipe_transport\n"
        "bad = [m for m in sys.modules if m.split('.')[0] in ('cryptography', 'cffi', 'argon2', 'ssl')"
        " or m in ('localvault.vault', 'localvault.local_clients', 'localvault.cli_service')]\n"
        "print(','.join(bad)); sys.exit(1 if bad else 0)"
    )
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_cli_sources_have_no_forbidden_imports() -> None:
    for path in (ROOT / "src" / "localvault" / "cli").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [("." * node.level) + (node.module or "")] + [alias.name for alias in node.names]
            for name in names:
                assert name.split(".")[0] != "cryptography", path
                assert "vault" not in name.split("."), (path, name)
                assert "local_clients" not in name, (path, name)


def test_unexpected_exception_prints_short_message_without_secret() -> None:
    def forward(request):
        raise RuntimeError("hunter2-secret")

    code, out, err = run(["read", "lgk://x/y"], forward)
    assert code == 1 and out == "" and "RuntimeError" in err and "hunter2" not in err and "Traceback" not in err
