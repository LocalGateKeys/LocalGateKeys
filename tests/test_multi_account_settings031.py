import ast
from pathlib import Path


def test_multi_account_chooser_happens_before_validation():
    text = Path("src/localvault/app/desktop.py").read_text(encoding="utf-8")
    chooser = text.index('t("desktop.chooseAccountForThisApp")')
    validation = text.index("desktop_entry_matches_snapshot(entry, snapshot)", chooser)
    assert chooser < validation
    assert "len(entries) > 1" in text

def test_modified_files_parse():
    for rel in (
        "src/localvault/agent.py",
        "src/localvault/settings_ui.py",
    ):
        ast.parse(Path(rel).read_text(encoding="utf-8"))
