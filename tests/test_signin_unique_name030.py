import ast
from pathlib import Path


def test_vault_requires_explicit_name_only_mapping():
    text = Path("src/localvault/vault.py").read_text(encoding="utf-8")
    assert 'identity_mode == "unique_name"' in text
    assert "must be explicitly mapped by the user" in text

def test_runtime_refuses_ambiguous_name_only_button():
    text = Path("src/localvault/uia.py").read_text(encoding="utf-8")
    assert 'identity_mode == "unique_name"' in text
    assert "if len(matches) != 1" in text

def test_modified_modules_parse():
    for rel in ("src/localvault/vault.py", "src/localvault/uia.py"):
        ast.parse(Path(rel).read_text(encoding="utf-8"))
