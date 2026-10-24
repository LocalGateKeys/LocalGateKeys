import ast
from pathlib import Path


def test_account_chooser_happens_before_binding_match():
    text = Path("src/localvault/app/desktop.py").read_text(encoding="utf-8")
    chooser = text.index('"Choose account for this app"')
    validation = text.index("desktop_entry_matches_snapshot(entry, snapshot)", chooser)
    assert chooser < validation
    assert "len(entries) > 1" in text

def test_agent_parses():
    ast.parse(Path("src/localvault/agent.py").read_text(encoding="utf-8"))
