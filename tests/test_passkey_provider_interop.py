"""The C# provider reads the agent-state.json the Python app writes (DPAPI token, pid, pipe name).

Runs one xUnit test (PythonInteropTests) with the paths in its environment. Skipped off Windows, without pywin32's
DPAPI, or without a .NET 10 SDK (``%LOCALAPPDATA%\\Microsoft\\dotnet10`` or ``dotnet`` on PATH).
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "windows-passkey-provider" / "tests" / "LocalGateKeys.PasskeyProvider.Tests" / \
    "LocalGateKeys.PasskeyProvider.Tests.csproj"

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows only")


def _dotnet10() -> tuple[str, dict[str, str]] | None:
    env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1")
    local = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "dotnet10" / "dotnet.exe"
    if local.is_file():
        env["DOTNET_ROOT"] = str(local.parent)
        return str(local), env
    found = shutil.which("dotnet")
    if not found:
        return None
    try:
        sdks = subprocess.run([found, "--list-sdks"], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return (found, env) if re.search(r"^10\.", sdks, re.MULTILINE) else None


def test_csharp_reads_the_state_file_python_writes(tmp_path) -> None:
    from localvault.config import atomic_write_json
    from localvault.pipe_transport import (
        AGENT_STATE_VERSION,
        PIPE_PREFIX,
        _current_user_sid_string,
        protect_agent_token,
    )

    dotnet = _dotnet10()
    if dotnet is None:
        pytest.skip(".NET 10 SDK not found")
    token = secrets.token_urlsafe(32)
    protected = protect_agent_token(token)
    if protected.get("protection") != "dpapi-user":
        pytest.skip("DPAPI (pywin32) not available")
    pipe = PIPE_PREFIX + secrets.token_hex(16)
    state = tmp_path / "agent-state.json"
    # The shape NamedPipeAgentServer.start writes.
    atomic_write_json(state, {"version": AGENT_STATE_VERSION, "transport": "named_pipe", "pipe": pipe, **protected,
                              "pid": os.getpid(), "user_sid": _current_user_sid_string(),
                              "bridge_revision": "interop-test"})
    expected = tmp_path / "expected.txt"
    expected.write_text(f"{token}\n{os.getpid()}\n{pipe}\n", encoding="utf-8")

    exe, env = dotnet
    env.update(LGK_INTEROP_AGENT_STATE=str(state), LGK_INTEROP_EXPECTED=str(expected))
    result = subprocess.run([exe, "test", str(TESTS), "-c", "Release", "--filter",
                             "FullyQualifiedName~PythonInteropTests"],
                            capture_output=True, text=True, env=env, timeout=600, cwd=str(TESTS.parent))
    tail = result.stdout[-3000:]
    assert result.returncode == 0, tail
    assert re.search(r"Passed!\s+-\s+Failed:\s+0,\s+Passed:\s+1,", tail), tail
