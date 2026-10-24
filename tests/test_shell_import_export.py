"""Import review flow and the Export… screen, driven with fake sessions."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from localvault.export import EXPORT_FORMATS, KDBX_MIN_PASSWORD, ExportWarning
from localvault.app.import_export import (
    EXPORT_MIN_PASSWORD,
    export_request_issue,
    export_summary_text,
    import_decision_for,
    import_mapping_defaults,
    import_summary_text,
)
from localvault.import_workflow import SourceInspection
from localvault.importers.chrome import MAPPING_TARGETS

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "localvault"


# ----------------------------------------------------------------- helpers
def _inspection(fmt="chrome-csv", *, needs_password=False, fields=(), mapping=(), unmapped=()):
    return SourceInspection(Path("x.csv"), fmt, "hash", 10, tuple(fields), tuple(mapping), tuple(unmapped),
                            3, (), needs_password=needs_password)


# ------------------------------------------------------------------ import


def test_import_decisions_follow_row_status() -> None:
    assert import_decision_for("new", "apply") == "add"
    assert import_decision_for("conflict", "apply") == "replace"
    assert import_decision_for("duplicate", "apply") == "skip"
    assert import_decision_for("conflict", "merge") == "merge"
    assert import_decision_for("new", "merge") == "add"
    assert import_decision_for("conflict", "skip") == "skip"
    assert import_decision_for("conflict", "keep_both") == "keep_both"
    assert import_decision_for("duplicate", "keep_both") == "keep_both"
    assert import_decision_for("new", "keep_both") == "skip"


def test_import_mapping_defaults_prefill_guessed_targets() -> None:
    source = _inspection("csv", fields=("Site", "Login", "Pass", "Extra"),
                         mapping=("url:Site", "username:Login", "password:Pass"), unmapped=("Extra",))
    defaults = import_mapping_defaults(source)
    assert set(defaults) == set(MAPPING_TARGETS)
    assert defaults["url"] == "Site" and defaults["password"] == "Pass" and defaults["title"] == ""


def test_import_summary_text_counts_decisions_and_diagnostics() -> None:
    plan = SimpleNamespace(summary=lambda: {"total": 4, "skip": 1, "add": 2, "replace": 1, "merge": 0, "skipped_rows": 1},
                           diagnostics=("Row 9 skipped.",))
    text = import_summary_text(plan, 3)
    assert "3" in text and "added 2" in text.casefold() and "replaced 1" in text.casefold()
    assert "Row 9 skipped." in text


# ------------------------------------------------------------------ export


def test_export_request_validation_for_kdbx_and_plaintext() -> None:
    assert export_request_issue("csv", "", "") is None
    assert export_request_issue("kdbx", "", "") is not None
    assert export_request_issue("kdbx", "short", "short") is not None
    assert export_request_issue("kdbx", "x" * EXPORT_MIN_PASSWORD, "y" * EXPORT_MIN_PASSWORD) is not None
    assert export_request_issue("kdbx", "x" * EXPORT_MIN_PASSWORD, "x" * EXPORT_MIN_PASSWORD) is None
    assert export_request_issue("bogus", "", "") is not None
    assert EXPORT_MIN_PASSWORD == KDBX_MIN_PASSWORD == 12


def test_export_summary_text_mentions_counts_and_permission_warning(tmp_path) -> None:
    summary = SimpleNamespace(path=tmp_path / "out.csv", format="csv", count=3, skipped=1, warnings=(ExportWarning.PERMISSIONS,),
                              permissions_restricted=False, encrypted=False, label=EXPORT_FORMATS["csv"])
    text = export_summary_text(summary)
    assert "3" in text and "out.csv" in text and ExportWarning.PERMISSIONS in text and "1" in text


