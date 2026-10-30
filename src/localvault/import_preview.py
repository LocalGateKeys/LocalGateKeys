"""Compatibility wrapper around :mod:`localvault.import_workflow` for the current UI.

The original module parsed CSV / Bitwarden JSON itself.  It now delegates to
the format importers and the record workflow while keeping the historic
contract: :func:`load_import` returns website-login rows plus diagnostics,
:func:`classify` marks duplicates/conflicts and :func:`apply_import` writes
the selected rows in one transaction.  Rows that are not website logins
(notes, identities, cards) are reported as issues here; the full workflow in
:mod:`localvault.import_workflow` imports them as catalog items.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .import_workflow import canonical_origin_for, normalise_records, plan_records
from .importers import ImportedRecord, cap_diagnostics
from .importers import ImporterError as ImportError  # noqa: A001 - historic public name
from .importers.detect import load_records
from .vault import ItemLimitReached
from .i18n import t

__all__ = ["ImportError", "ImportRow", "apply_import", "classify", "load_import"]


@dataclass
class ImportRow:
    row: int
    label: str
    origin: str
    username: str
    password: str = field(repr=False)
    status: str = "new"
    selected: str = "add"
    target_id: str | None = None


def _origin(value: str) -> str:
    return canonical_origin_for(value)


def load_import(path: Path, *, password: str | None = None) -> tuple[list[ImportRow], list[str]]:
    """Load website logins from any supported export (CSV, JSON, 1PUX, KDBX with ``password``)."""
    result = load_records(Path(path), password=password)
    try:
        rows, issues = normalise_records(result.records)
        issues = list(result.diagnostics) + cap_diagnostics(issues)
        results: list[ImportRow] = []
        for row in rows:
            if row.kind != "login":
                issues.append(t("importPreview.rowNotAWebsiteLogin", row=row.row, kind=row.kind))
            elif not row.in_import_duplicate:
                results.append(ImportRow(row.row, row.label, row.origin, row.username, row.password))
        return results, issues
    finally:
        result.wipe()


def classify(rows: list[ImportRow], entries: list[dict[str, Any]]) -> None:
    existing = {(e.get("scope", {}).get("origin"), e.get("username")): e for e in entries if e.get("kind") == "web"}
    for row in rows:
        entry = existing.get((row.origin, row.username))
        if entry:
            row.target_id = str(entry["id"])
            row.status = "duplicate" if entry.get("password") == row.password else "conflict"
            row.selected = "skip"


def apply_import(session: Any, rows: list[ImportRow]) -> int:
    """Apply ``add``/``replace`` selections transactionally through the record workflow."""
    for row in rows:
        if row.selected not in ("skip", "add", "replace"):
            raise ImportError("Unknown import decision")
    records = [ImportedRecord(kind="login", title=row.label, username=row.username, password=row.password,
                              urls=[row.origin], source_row=row.row) for row in rows]
    plan = plan_records(session, records)
    by_row = {item.row: item for item in plan.rows}
    for row in rows:
        item = by_row.get(row.row)
        if item is None:
            raise ImportError(t("importPreview.rowUnsupportedUrlOrInvalid", row=row.row))
        if row.selected == "skip":
            plan.set_decision(item, "skip")
        elif row.selected == "add":
            if item.status != "new":
                raise ImportError(t("importPreview.vaultChangedAfterPreviewReview"))
            plan.set_decision(item, "add")
        else:
            if item.status == "new" or item.target_id != row.target_id:
                raise ImportError(t("importPreview.conflictTargetChangedReviewThe"))
            plan.set_decision(item, "replace", fields={"label": "import", "password": "import"})
    if any(item.limited for item in plan.rows):
        # This historic contract writes every selected row or nothing.
        limit = plan.item_limit if plan.item_limit is not None else 0
        raise ImportError(str(ItemLimitReached(limit, limit - (plan.free_slots or 0))))
    plan.review()
    return plan.apply(session)
