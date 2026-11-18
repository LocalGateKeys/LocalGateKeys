"""``tests/vectors/agent``: the Local Agent Gate vectors LGKCore replays for ``lgk mcp`` on the Mac.

The files must be exactly what ``scripts/make_agent_gate_vectors.py`` writes from the Python code today, so a change
to ``cli/mcp_server.py`` or ``agent_gate.py`` that the Mac does not follow yet fails here first (regenerate the files,
then make ``AgentVectorsTests`` pass on the Mac).
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "tests" / "vectors" / "agent"


def _generator():
    spec = importlib.util.spec_from_file_location("make_agent_gate_vectors",
                                                  ROOT / "scripts" / "make_agent_gate_vectors.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    out = tmp_path_factory.mktemp("agent-vectors")
    return {path.name: path.read_bytes() for path in _generator().generate(out)}


@pytest.mark.parametrize("name", ["text.json", "mcp.json", "gate.json"])
def test_vectors_are_what_the_python_side_does_today(generated, name: str) -> None:
    assert (VECTORS / name).read_bytes() == generated[name], f"regenerate with scripts/make_agent_gate_vectors.py"


def test_no_tool_reply_in_the_vectors_carries_a_value() -> None:
    """The reply-key filter: no output line names a password, username or credential field."""
    doc = json.loads((VECTORS / "mcp.json").read_text(encoding="utf-8"))
    for case in doc["cases"]:
        for message in case["output"]:
            text = json.dumps(message)
            assert "LEAK" not in text and "P@ss" not in text, case["name"]
            assert not re.search(r'(username|password|credential)\\?"\s*:', text), case["name"]


def test_vectors_cover_every_refusal_and_tool() -> None:
    gate = json.loads((VECTORS / "gate.json").read_text(encoding="utf-8"))
    refusals: set[str] = set()
    ops: set[str] = set()

    def walk(steps):
        for step in steps:
            ops.add(step["op"])
            result = step["expect"].get("result") or {}
            if "refused" in result:
                refusals.add(result["refused"])
            walk(step.get("during", []))

    for scenario in gate["scenarios"]:
        walk(scenario["steps"])
    assert refusals >= {"disabled", "pro", "locked", "not_found", "denied", "invalid", "expired", "used", "not_yours",
                        "rate_limited", "no_tab", "no_passkey"}
    assert ops >= {"list_sites", "request_login", "fill_login", "take_for_origin", "take_passkey_for_origin",
                   "passkey_pending", "finish"}
    mcp = json.loads((VECTORS / "mcp.json").read_text(encoding="utf-8"))
    listed = next(c for c in mcp["cases"] if c["name"] == "tools_list")["output"][0]["result"]["tools"]
    assert [tool["name"] for tool in listed] == ["list_sites", "request_login", "fill_login"]
