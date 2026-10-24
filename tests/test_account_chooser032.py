import ast
from pathlib import Path


def test_agent_parses():
    ast.parse(Path("src/localvault/agent.py").read_text(encoding="utf-8"))
