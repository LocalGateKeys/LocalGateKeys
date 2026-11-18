"""Switch report and whole-import undo (feature idea 1, 2026-11-15).

After an import the app shows one page: what landed per item kind (counted from the vault itself, before and
after, so it can never claim more than arrived), passkeys imported vs skipped, custom fields kept / split / moved,
duplicates found, and by name what was not brought over. :class:`ImportUndo` takes the whole import back in one
step through the normal mutation paths: items it added go to the Trash (recoverable, and synced as ordinary
deletions) and items it changed get their pre-import values back as a new revision, so sync sees ordinary edits.
The undo record lives in memory only and is dropped when the vault locks.
"""
from __future__ import annotations

import copy
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any

from .i18n import t

CREDENTIAL_KINDS = frozenset({"web", "desktop"})
_ROW_KIND = {"login": "web"}


def _items(session: Any) -> Any:
    return getattr(session, "item_service", None) or getattr(session, "items", None)


def census(session: Any) -> dict[str, set[str]]:
    """Ids per item kind, from metadata only (no secrets are read)."""
    result: dict[str, set[str]] = {}
    for summary in _items(session).all_metadata_summaries():
        result.setdefault(str(summary.kind), set()).add(str(summary.id))
    return result


def landed(before: dict[str, set[str]], after: dict[str, set[str]]) -> dict[str, set[str]]:
    """Ids per kind present after the import and not before it: what actually arrived as new items."""
    return {kind: ids - before.get(kind, set()) for kind, ids in after.items() if ids - before.get(kind, set())}


@dataclass
class RowFacts:
    """What the report needs from one plan row, taken before the plan wipes its records."""

    row: int
    kind: str
    name: str
    status: str
    decision: str
    limited: bool
    target_id: str | None
    custom_fields: int
    field_events: dict[str, int]
    attachments: int

    @property
    def taken(self) -> bool:
        return self.decision != "skip" and not self.limited


def row_facts(plan: Any) -> list[RowFacts]:
    facts = []
    for row in plan.rows:
        record = row.record
        facts.append(RowFacts(
            row=int(row.row), kind=_ROW_KIND.get(row.kind, row.kind), name=str(record.title or row.origin or ""),
            status=str(row.status), decision=str(row.decision), limited=bool(row.limited),
            target_id=str(row.target_id) if row.target_id else None,
            custom_fields=len(record.custom_fields or ()),
            field_events=dict(getattr(record, "field_events", None) or {}),
            attachments=int(getattr(record, "attachments", 0) or 0)))
    return facts


def _skip_reason(fact: RowFacts) -> str:
    if fact.limited:
        return t("switchReport.reasonNeedsPro")
    if fact.status == "duplicate":
        return t("switchReport.reasonDuplicate")
    return t("switchReport.reasonSkipped")


def build_report(facts: list[RowFacts], arrived: dict[str, set[str]], written: int,
                 diagnostics: tuple[str, ...] | list[str], source_label: str = "",
                 skipped_source_rows: int = 0) -> dict[str, Any]:
    """The switch report. Per-kind counts come from ``arrived`` (vault before/after), capped by what the
    plan asked to add, so the page never says more arrived than did."""
    from .app.catalog import kind_label

    asked: dict[str, int] = {}
    for fact in facts:
        if fact.taken and fact.decision in {"add", "keep_both"}:
            kind = "note" if fact.kind == "web" and fact.decision == "keep_both" else fact.kind
            asked[kind] = asked.get(kind, 0) + 1
    kinds = []
    for kind in sorted(set(arrived) | set(asked)):
        count = len(arrived.get(kind, ()))
        if count:
            kinds.append({"kind": kind, "label": kind_label(kind), "count": count})
    added = sum(row["count"] for row in kinds)
    passkeys_total = sum(1 for fact in facts if fact.kind == "passkey")
    passkeys_in = min(len(arrived.get("passkey", ())),
                      sum(1 for fact in facts if fact.kind == "passkey" and fact.taken))
    passkeys_updated = sum(1 for fact in facts if fact.kind == "passkey" and fact.taken
                           and fact.decision in {"replace", "merge"})
    taken = [fact for fact in facts if fact.taken]
    fields = {"kept": sum(fact.custom_fields for fact in taken),
              "split": sum(fact.field_events.get("split", 0) for fact in taken),
              "moved": sum(fact.field_events.get("moved", 0) for fact in taken),
              "dropped": sum(fact.field_events.get("dropped", 0) for fact in taken)}
    not_carried = [{"row": fact.row, "name": fact.name or t("secrets.thisItem"), "reason": _skip_reason(fact)}
                   for fact in facts if not fact.taken]
    total = len(facts) + max(0, int(skipped_source_rows))
    return {
        "source": source_label,
        "total": total,
        "written": int(written),
        "added": added,
        "updated": max(0, int(written) - added),
        "kinds": kinds,
        "passkeys": {"total": passkeys_total, "imported": passkeys_in + passkeys_updated,
                     "skipped": max(0, passkeys_total - passkeys_in - passkeys_updated)},
        "attachments": sum(1 for fact in facts if fact.attachments),
        "fields": fields,
        "duplicates": sum(1 for fact in facts if fact.status == "duplicate"),
        "not_carried": not_carried,
        "unreadable_rows": max(0, int(skipped_source_rows)),
        "notes": list(diagnostics)[:200],
        "toast": toast_text(int(written), total, len(not_carried) + max(0, int(skipped_source_rows)), not_carried),
    }


def toast_text(written: int, total: int, skipped: int, not_carried: list[dict[str, Any]]) -> str:
    """Quick win 2: "Imported N of M, K skipped (why)"."""
    if not skipped:
        return t("switchReport.toastAll", written=written, total=total)
    reasons: dict[str, int] = {}
    for row in not_carried:
        reasons[row["reason"]] = reasons.get(row["reason"], 0) + 1
    why = ", ".join(f"{reason}: {count}" for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]))
    return t("switchReport.toastSkipped", written=written, total=total, skipped=skipped,
             why=why or t("switchReport.reasonUnreadable"))


# ---------------------------------------------------------------------------- undo
class UndoError(Exception):
    """The import can no longer be undone as a whole."""


def record_digest(session: Any, kind: str, item_id: str) -> str | None:
    """Digest of one record as it is now (``import_undo.digest``); None when it is gone.

    Taken right after the import commits (``ImportPlan.written``) and again at undo, so undo can tell
    a record the import wrote and nobody touched since from one edited (or synced) after the import.
    """
    import hashlib

    from .import_undo import digest
    from .item_history import comparable

    if kind in CREDENTIAL_KINDS:
        record = session.get_entry(item_id)
    else:
        items = _items(session)
        record = items.get_item(item_id, include_protected=True) if items is not None else None
    if not isinstance(record, dict):
        return None
    try:
        if kind in CREDENTIAL_KINDS:
            # Local-only fields (the site icon fetched after an import, local trust approvals) are not edits.
            return hashlib.sha256(comparable(record)).hexdigest()
        return digest(record)
    except (TypeError, ValueError):
        return None
    finally:
        record.clear()


@dataclass
class ImportUndo:
    """In-memory record of one applied import; holds pre-import copies of the logins it changed.

    ``written`` (W-L4): id -> digest of each record the import itself created or changed, as committed
    (``ImportPlan.written``).  When given, undo touches only those ids, and only while they still have
    that digest: a record that arrived during the import from sync or a browser save is not trashed,
    and one edited after the import is kept and listed in ``missed``.  ``None`` (older callers): no check.
    """

    token: str
    profile: str
    created: dict[str, set[str]]
    changed_entries: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)
    changed_items: dict[str, set[str]] = field(default_factory=dict)
    used: bool = False
    written: dict[str, str] | None = field(default=None, repr=False)

    def wipe(self) -> None:
        for entry in self.changed_entries.values():
            entry.clear()
        self.changed_entries.clear()
        if self.written is not None:
            self.written.clear()


def prepare_undo(session: Any, facts: list[RowFacts]) -> tuple[dict[str, set[str]], dict[str, Any], dict[str, set[str]]]:
    """Before apply: the census, deep copies of the logins the plan will change, and the history snapshot ids
    each typed item it will change already has (the import's own snapshot is the one added after)."""
    before = census(session)
    entries: dict[str, Any] = {}
    items: dict[str, set[str]] = {}
    history = getattr(session, "history", None)
    for fact in facts:
        if not fact.taken or fact.decision not in {"replace", "merge"} or not fact.target_id:
            continue
        if fact.kind in CREDENTIAL_KINDS:
            entry = session.get_entry(fact.target_id)
            if entry is not None:
                web_urls = getattr(_items(session), "web_urls", None)
                entry["_urls"] = web_urls(fact.target_id) if callable(web_urls) else []
                entries[fact.target_id] = entry
        elif history is not None:
            items[fact.target_id] = {row["snapshot_id"] for row in history.list(fact.target_id)}
    return before, entries, items


def _restore_entry(session: Any, entry_id: str, old: dict[str, Any]) -> bool:
    current = session.get_entry(entry_id)
    if current is None:
        return False
    try:
        session.update_entry_fields(entry_id, label=str(old.get("label") or current.get("label") or "") or None,
                                    username=str(old.get("username", "")),
                                    password=str(old.get("password") or "") or None)
        session.set_details(entry_id, favorite=bool(old.get("favorite")), tags=list(old.get("tags") or []),
                            notes=str(old.get("notes") or ""), totp=old.get("totp"),
                            recovery_codes=list(old.get("recovery_codes") or []), policy=old.get("policy"),
                            custom_fields=list(old.get("custom_fields") or []))
        items = _items(session)
        urls = old.get("_urls")
        if isinstance(urls, list) and urls and hasattr(items, "set_web_urls"):
            items.set_web_urls(entry_id, copy.deepcopy(urls))
    finally:
        current.clear()
    return True


def undo_import(session: Any, undo: ImportUndo) -> dict[str, Any]:
    """Take the whole import back in one transaction: added items to the Trash, changed ones restored.

    Returns counts plus the names of anything that could not be restored (changed or removed since)."""
    if undo.used:
        raise UndoError(t("switchReport.undoUsed"))
    items = _items(session)
    history = getattr(session, "history", None)
    written = undo.written
    trashed = restored = 0
    missed: list[str] = []

    def untouched(kind: str, item_id: str) -> bool | None:
        """True: still what the import wrote; False: changed since; None: the import did not write it."""
        if written is None:
            return True
        expected = written.get(item_id)
        if expected is None:
            return None
        return record_digest(session, kind, item_id) == expected

    with session.transaction():
        present = census(session)
        titles = {str(s.id): str(s.title or "") for s in items.all_metadata_summaries()} if written is not None else {}
        for kind, ids in undo.created.items():
            for item_id in sorted(ids):
                if item_id not in present.get(kind, set()):
                    continue  # already removed by the user or a peer
                state = untouched(kind, item_id)
                if state is None:
                    continue  # arrived meanwhile (sync, browser save): not this import's
                if state is False:
                    missed.append(titles.get(item_id) or item_id)  # edited after the import: kept
                    continue
                done = session.delete(item_id) if kind in CREDENTIAL_KINDS else items.delete_item(item_id)
                trashed += int(bool(done))
        for entry_id, old in undo.changed_entries.items():
            state = untouched("web", entry_id)
            if state is None:
                continue  # the import left this login as it was
            if state and _restore_entry(session, entry_id, old):
                restored += 1
            else:
                missed.append(str(old.get("label") or entry_id))
        for item_id, before in undo.changed_items.items():
            state = untouched("note", item_id)
            if state is None:
                continue
            if state is False:
                missed.append(titles.get(item_id) or item_id)
                continue
            rows = [row for row in (history.list(item_id) if history is not None else [])
                    if row["snapshot_id"] not in before and row.get("change_type") != "restore"]
            if not rows:
                missed.append(item_id)
                continue
            # Oldest snapshot taken during the import is the item as it was before it.
            oldest = min(rows, key=lambda row: (row["revision"], row["created_at"]))
            history.restore_as_new_revision(item_id, oldest["snapshot_id"])
            restored += 1
    undo.used = True
    undo.wipe()
    return {"trashed": trashed, "restored": restored, "missed": missed}


class UndoStore:
    """The last few imports' undo records for this unlocked session (memory only)."""

    MAX = 4

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, ImportUndo] = {}

    def add(self, profile: str, created: dict[str, set[str]], entries: dict[str, Any],
            items: dict[str, set[str]], *, written: dict[str, str] | None = None) -> ImportUndo:
        """``written``: the plan's ``ImportPlan.written`` (pass it; see :class:`ImportUndo`)."""
        record = ImportUndo(token=secrets.token_urlsafe(12), profile=profile, created=created,
                            changed_entries=entries, changed_items=items,
                            written=dict(written) if written is not None else None)
        with self._lock:
            while len(self._records) >= self.MAX:
                self._records.pop(next(iter(self._records))).wipe()
            self._records[record.token] = record
        return record

    def take(self, token: str, profile: str) -> ImportUndo:
        with self._lock:
            record = self._records.get(str(token))
            if record is None or record.profile != profile:
                raise UndoError(t("switchReport.undoExpired"))
            return record

    def drop(self, token: str) -> None:
        with self._lock:
            record = self._records.pop(str(token), None)
        if record is not None:
            record.wipe()

    def clear(self) -> None:
        with self._lock:
            records, self._records = self._records, {}
        for record in records.values():
            record.wipe()
