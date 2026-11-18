"""Undo of the last import, one level, digest-checked (feature pack 2026-11-15, section 6.1).

Pure rule shared with the phone and Mac cores (``tests/vectors/import/report/undo.json``).  A created
record that is still exactly what the import wrote moves to Recently deleted; a replaced record that
is still exactly what the import wrote gets its earlier version back; anything changed since is kept.
"""
from __future__ import annotations

import copy
import hashlib
from collections.abc import Iterable, Mapping
from typing import Any

from .updates import canonical_json

MAX_AGE_SECONDS = 7 * 86400


def digest(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(record)).hexdigest()


def plan(journal: Mapping[str, Any], current: Iterable[Mapping[str, Any]], now: int) -> dict[str, Any]:
    """``{"records": live records after undo (input order), "trashed": ids, "restored": ids, "kept": ids}``."""
    created = journal.get("created") if isinstance(journal.get("created"), Mapping) else {}
    replaced = journal.get("replaced") if isinstance(journal.get("replaced"), Mapping) else {}
    records: list[dict[str, Any]] = []
    trashed: list[str] = []
    restored: list[str] = []
    kept: list[str] = []
    for record in current:
        rid = str(record.get("id"))
        if rid in created:
            if digest(record) == created[rid]:
                trashed.append(rid)
                continue
            kept.append(rid)
        elif rid in replaced:
            row = replaced[rid]
            if isinstance(row, Mapping) and isinstance(row.get("before"), Mapping) and digest(record) == row.get("after"):
                before = copy.deepcopy(dict(row["before"]))
                before["updated_at"] = int(now)
                records.append(before)
                restored.append(rid)
                continue
            kept.append(rid)
        records.append(copy.deepcopy(dict(record)))
    return {"records": records, "trashed": sorted(trashed), "restored": sorted(restored), "kept": sorted(kept)}


__all__ = ["MAX_AGE_SECONDS", "digest", "plan"]
