from __future__ import annotations

from types import SimpleNamespace

from localvault.app.catalog import SHELL_LABELS, CatalogItemRef, _summary_title


def test_shell_vocabulary_explains_profile_scoped_browse_and_setup() -> None:
    assert SHELL_LABELS["all"] == "All items"
    assert SHELL_LABELS["web"] == "Browser"
    assert SHELL_LABELS["desktop"] == "Desktop"
    assert SHELL_LABELS["connections"] == "Devices & connections"
    assert SHELL_LABELS["search"] == "Search this profile"
    assert SHELL_LABELS["recovery"] == "Backups & recovery"


def test_mixed_shell_rows_keep_an_explicit_owner_reference() -> None:
    credential = CatalogItemRef(source="credential", id="cred-1", kind="web")
    typed = CatalogItemRef(source="typed", id="item-1", kind="note")

    assert credential.source != typed.source
    assert credential.id != typed.id
    assert credential.kind == "web"
    assert typed.kind == "note"


def test_summary_title_supports_both_metadata_summary_shapes() -> None:
    assert _summary_title(SimpleNamespace(label="Credential")) == "Credential"
    assert _summary_title(SimpleNamespace(title="Typed item")) == "Typed item"


