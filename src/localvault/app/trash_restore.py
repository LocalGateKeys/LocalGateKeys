"""Trash restore that stops at the free item limit (no UI toolkit)."""
from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field

from ..vault import ItemLimitReached, VaultError


@dataclass
class TrashRestoreResult:
    restored: int = 0
    failed: list[tuple[str, Exception]] = dataclass_field(default_factory=list)
    limit: ItemLimitReached | None = None


def restore_trash_entries(session, entries, sources, check) -> TrashRestoreResult:
    """Restore trash rows in order; stop at the free item limit instead of failing each row.

    *sources* maps a row id to ``"typed"`` or ``"credential"``; *check* runs
    before each restore (the session lease check).
    """
    result = TrashRestoreResult()
    for entry in entries:
        check()
        try:
            if sources.get(entry) == 'typed':
                session.item_service.restore_item(entry)
            else:
                session.restore_deleted(entry)
            result.restored += 1
        except ItemLimitReached as exc:
            result.limit = exc
            break
        except (VaultError, ValueError) as exc:
            result.failed.append((entry, exc))
    return result
