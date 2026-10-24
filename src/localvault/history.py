"""Bounded typed-item history and revision comparison.

The vault already encrypts and authenticates the complete v2 catalog.  Typed
history therefore lives in that same catalog envelope rather than introducing
another key or a plaintext index.  The service stores immutable copies of the
previous item, while its public projections redact protected fields by
default.

This module intentionally contains no UI or lease implementation.  Callers
which release protected values must perform their own explicit approval and
session checks, just as :mod:`item_service` does for current values.
"""
from __future__ import annotations

import copy
import hashlib
import json
import time
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .item_schema import MAX_ITEMS, validate_item
from .vault import VaultError, VaultLockedError

DEFAULT_MAX_VERSIONS = 20
MIN_MAX_VERSIONS = 1
MAX_MAX_VERSIONS = 100
DEFAULT_MAX_BYTES = 256 * 1024 * 1024
# A small lower bound keeps quota behavior directly testable while still
# rejecting zero and negative budgets.  The vault's authenticated catalog is
# the effective upper bound in practice.
MIN_MAX_BYTES = 1
MAX_MAX_BYTES = 256 * 1024 * 1024
MAX_HISTORY_ROWS = MAX_ITEMS * DEFAULT_MAX_VERSIONS


class HistoryError(VaultError):
    """Base error for typed history operations."""


class HistoryConflict(HistoryError):
    """The caller's expected current revision is stale."""


class HistoryQuotaError(HistoryError):
    """A snapshot would exceed the configured bounded history store."""


class SnapshotNotFound(HistoryError):
    """A snapshot does not belong to the requested item."""


@dataclass(frozen=True)
class SnapshotSummary:
    snapshot_id: str
    item_id: str
    revision: int
    parent_revision: int | None
    created_at: int
    kind: str
    title: str
    change_type: str = "update"
    attachment_ids: tuple[str, ...] = ()
    relation_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "item_id": self.item_id,
            "revision": self.revision,
            "parent_revision": self.parent_revision,
            "created_at": self.created_at,
            "kind": self.kind,
            "title": self.title,
            "change_type": self.change_type,
            "attachment_ids": list(self.attachment_ids),
            "relation_count": self.relation_count,
        }


@dataclass(frozen=True)
class FieldDifference:
    field: str
    before: Any
    after: Any
    protected: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "before": copy.deepcopy(self.before),
            "after": copy.deepcopy(self.after),
            "protected": self.protected,
        }


def _canonical_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    if isinstance(value, Mapping):
        for key in sorted(value):
            child = f"{prefix}.{key}" if prefix else str(key)
            result.update(_flatten(value[key], child))
    elif isinstance(value, list):
        # Lists are compared as one stable field.  This avoids inventing
        # unstable indexes for custom fields and document dependencies.
        result[prefix] = copy.deepcopy(value)
    else:
        result[prefix] = copy.deepcopy(value)
    return result


def _protected_field(kind: str, field: str) -> bool:
    if not field.startswith("payload."):
        return False
    name = field.removeprefix("payload.").split(".", 1)[0]
    if kind == "note":
        return name in {"body", "fields"}
    if kind == "bookmark":
        return name in {"url", "notes"}
    if kind == "identity":
        return name != "template_id"
    if kind == "license":
        return name in {"license_value", "notes"}
    if kind in {"purchase", "warranty", "subscription"}:
        return name in {"notes"}
    return False


def _mask(value: Any) -> str:
    # Do not echo lengths or fragments of protected data.  The marker is
    # deliberately constant so diffs cannot become a side channel.
    return "[protected]"


def _item_attachment_ids(item: Mapping[str, Any]) -> tuple[str, ...]:
    payload = item.get("payload", {})
    if not isinstance(payload, Mapping):
        return ()
    result: list[str] = []
    attachment_id = payload.get("attachment_id")
    if isinstance(attachment_id, str):
        result.append(attachment_id)
    return tuple(result)


def _validate_limits(max_versions: int, max_bytes: int) -> tuple[int, int]:
    if type(max_versions) is not int or not MIN_MAX_VERSIONS <= max_versions <= MAX_MAX_VERSIONS:
        raise HistoryError(f"max_versions must be between {MIN_MAX_VERSIONS} and {MAX_MAX_VERSIONS}")
    if type(max_bytes) is not int or not MIN_MAX_BYTES <= max_bytes <= MAX_MAX_BYTES:
        raise HistoryError(f"max_bytes must be between {MIN_MAX_BYTES} and {MAX_MAX_BYTES}")
    return max_versions, max_bytes


class HistoryService:
    """Immutable, bounded snapshots for typed catalog items."""

    def __init__(self, session: Any, *, max_versions: int = DEFAULT_MAX_VERSIONS,
                 max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.session = session
        self.max_versions, self.max_bytes = _validate_limits(max_versions, max_bytes)

    def _payload(self) -> dict[str, Any]:
        if not getattr(self.session, "is_unlocked", False):
            raise VaultLockedError("Vault is locked")
        return self.session._require_typed_catalog()

    def _rows(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        rows = payload.setdefault("history", [])
        if not isinstance(rows, list):
            raise HistoryError("Typed history is malformed")
        if len(rows) > MAX_HISTORY_ROWS:
            raise HistoryError("Typed history exceeds the profile bound")
        return rows

    @staticmethod
    def _snapshot_item(row: Mapping[str, Any]) -> dict[str, Any]:
        item = row.get("item")
        if not isinstance(item, dict):
            raise HistoryError("Typed history snapshot is malformed")
        return copy.deepcopy(item)

    def _used_bytes(self, rows: Iterable[Mapping[str, Any]]) -> int:
        return sum(_canonical_size(row) for row in rows)

    def _find(self, item_id: str, snapshot_id: str) -> dict[str, Any]:
        for row in self._rows(self._payload()):
            if row.get("item_id") == item_id and row.get("snapshot_id") == snapshot_id:
                return row
        raise SnapshotNotFound("History snapshot was not found")

    def _summary(self, row: Mapping[str, Any]) -> SnapshotSummary:
        item = self._snapshot_item(row)
        return SnapshotSummary(
            snapshot_id=str(row["snapshot_id"]), item_id=str(row["item_id"]),
            revision=int(row["revision"]),
            parent_revision=(int(row["parent_revision"]) if row.get("parent_revision") is not None else None),
            created_at=int(row["created_at"]), kind=str(item["kind"]), title=str(item["title"]),
            change_type=str(row.get("change_type", "update")),
            attachment_ids=tuple(row.get("attachment_ids", ())),
            relation_count=len(row.get("relations", ())) if isinstance(row.get("relations"), list) else 0,
        )

    def list(self, item_id: str | None = None) -> list[dict[str, Any]]:
        """Return metadata-only snapshot rows in newest-first order."""
        rows = self._rows(self._payload())
        result = [self._summary(row).to_dict() for row in rows
                  if item_id is None or row.get("item_id") == item_id]
        return sorted(result, key=lambda row: (-row["revision"], -row["created_at"], row["snapshot_id"]))

    history = list

    def snapshot(self, item_id: str, snapshot_id: str, *, reveal: bool = False,
                 intent: str | None = None) -> dict[str, Any]:
        """Return a snapshot projection, masking protected payload by default."""
        item = self._snapshot_item(self._find(item_id, snapshot_id))
        if reveal and (not isinstance(intent, str) or not intent.strip()):
            raise HistoryError("An explicit caller intent is required to reveal protected history")
        if not reveal:
            kind = str(item.get("kind", ""))
            protected = item.get("payload")
            if isinstance(protected, dict):
                for field in tuple(protected):
                    if _protected_field(kind, f"payload.{field}"):
                        protected[field] = _mask(protected[field])
        return item

    def record_before_change(self, item: Mapping[str, Any], *, relations: Iterable[Mapping[str, Any]] = (),
                             change_type: str = "update", persist: bool = False) -> str:
        """Append an immutable copy of the current item before a mutation.

        ``persist=False`` is used by item/relationship services inside their
        existing ``session.save`` transaction.  Direct callers can request a
        standalone commit with ``persist=True``.
        """
        payload = self._payload()
        if not isinstance(item, Mapping):
            raise HistoryError("History item must be an object")
        clean = validate_item(copy.deepcopy(dict(item)), known_collection_ids={
            row["id"] for row in payload.get("collections", []) if isinstance(row, dict) and "id" in row
        })
        item_id = clean["id"]
        rows = self._rows(payload)
        if any(row.get("item_id") == item_id and row.get("revision") == clean["revision"] for row in rows):
            return next(row["snapshot_id"] for row in rows
                        if row.get("item_id") == item_id and row.get("revision") == clean["revision"])
        per_item = [row for row in rows if row.get("item_id") == item_id]
        if len(per_item) >= self.max_versions:
            # Retain the newest bounded set, dropping the oldest before
            # checking the global quota.  A caller can therefore continue to
            # edit without unbounded growth.
            oldest = sorted(per_item, key=lambda row: (int(row.get("revision", 0)), row.get("created_at", 0)))[0]
            rows.remove(oldest)
        now = int(time.time())
        snapshot_id = str(uuid.uuid4())
        relation_rows = [copy.deepcopy(dict(edge)) for edge in relations]
        row = {
            "snapshot_id": snapshot_id,
            "item_id": item_id,
            "revision": clean["revision"],
            "parent_revision": clean["revision"] - 1 if clean["revision"] > 1 else None,
            "created_at": now,
            "change_type": str(change_type),
            "item": clean,
            "attachment_ids": list(_item_attachment_ids(clean)),
            "relations": relation_rows,
        }
        if self._used_bytes([*rows, row]) > self.max_bytes:
            # Put a removed oldest row back only when quota rejected.  This
            # gives callers a failure that leaves the pre-mutation payload
            # untouched, matching the vault's save rollback invariant.
            if per_item and oldest not in rows:
                rows.append(oldest)
            raise HistoryQuotaError("Typed history quota would be exceeded")
        if len(rows) >= MAX_HISTORY_ROWS:
            raise HistoryQuotaError("Typed history row limit would be exceeded")
        rows.append(row)
        payload["history"] = rows
        payload["updated_at"] = now
        if persist:
            self.session.save()
        return snapshot_id

    # Names used by integrations that prefer manifest terminology.
    capture = record_before_change
    append_snapshot = record_before_change

    def compare(self, item_id: str, snapshot_id: str, *, reveal: bool = False,
                intent: str | None = None) -> dict[str, Any]:
        payload = self._payload()
        row = self._find(item_id, snapshot_id)
        current = next((item for item in payload.get("items", [])
                        if isinstance(item, dict) and item.get("id") == item_id), None)
        if current is None:
            raise HistoryError("Current item was not found")
        if reveal and (not isinstance(intent, str) or not intent.strip()):
            raise HistoryError("An explicit caller intent is required to reveal protected history")
        before = _flatten(self._snapshot_item(row))
        after = _flatten(current)
        fields = sorted(set(before) | set(after))
        differences: list[dict[str, Any]] = []
        kind = str(current.get("kind", row.get("kind", "")))
        for field in fields:
            left = before.get(field)
            right = after.get(field)
            protected = _protected_field(kind, field)
            if left == right:
                continue
            differences.append(FieldDifference(
                field=field,
                before=left if (reveal or not protected) else _mask(left),
                after=right if (reveal or not protected) else _mask(right),
                protected=protected,
            ).to_dict())
        return {
            "item_id": item_id,
            "snapshot_id": snapshot_id,
            "from_revision": int(row["revision"]),
            "to_revision": int(current["revision"]),
            "differences": differences,
            "revealed": bool(reveal),
        }

    diff = compare

    def restore_preview(self, item_id: str, snapshot_id: str) -> dict[str, Any]:
        row = self._find(item_id, snapshot_id)
        item = self._snapshot_item(row)
        payload = self._payload()
        current = next((value for value in payload.get("items", [])
                        if isinstance(value, dict) and value.get("id") == item_id), None)
        if current is None:
            raise HistoryError("Current item was not found")
        historical_relations = copy.deepcopy(row.get("relations", []))
        targets = {value.get("id") for value in payload.get("items", []) if isinstance(value, dict)}
        targets.update(value.get("entry", {}).get("id") for value in payload.get("trash", [])
                       if isinstance(value, dict) and isinstance(value.get("entry"), dict))
        return {
            "item_id": item_id,
            "snapshot_id": snapshot_id,
            "current_revision": int(current["revision"]),
            "proposed_revision": int(current["revision"]) + 1,
            "item": copy.deepcopy(item),
            "relations": historical_relations,
            "missing_relation_targets": sorted({edge.get("target_id") for edge in historical_relations
                                                 if edge.get("target_id") not in targets}),
        }

    def restore_as_new_revision(self, item_id: str, snapshot_id: str, *,
                                expected_revision: int | None = None,
                                restore_relations: bool = False) -> bool:
        payload = self._payload()
        row = self._find(item_id, snapshot_id)
        current = next((value for value in payload.get("items", [])
                        if isinstance(value, dict) and value.get("id") == item_id), None)
        if current is None:
            raise HistoryError("Current item was not found")
        actual_revision = current.get("revision")
        if expected_revision is not None and expected_revision != actual_revision:
            raise HistoryConflict("Item revision conflict")
        proposed = self._snapshot_item(row)
        proposed["id"] = item_id
        proposed["created_at"] = current["created_at"]
        proposed["revision"] = int(actual_revision) + 1
        proposed["updated_at"] = int(time.time())
        proposed = validate_item(proposed, known_collection_ids={
            value["id"] for value in payload.get("collections", []) if isinstance(value, dict) and "id" in value
        })
        # The current revision itself is retained as an immutable history row
        # before it is replaced.  Any validation/quota failure occurs before
        # the item is changed.
        relations = []
        if restore_relations:
            relations = copy.deepcopy(row.get("relations", []))
        original = copy.deepcopy(current)
        self.record_before_change(original, relations=relations, change_type="restore", persist=False)
        current.clear()
        current.update(proposed)
        payload["updated_at"] = int(time.time())
        try:
            self.session.save()
        except BaseException:
            current.clear()
            current.update(original)
            raise
        if restore_relations and relations:
            # Relations are a separately reviewed operation.  Do not
            # auto-resurrect targets; callers can apply valid edges later.
            pass
        return True

    restore = restore_as_new_revision

    def clear(self, item_id: str | None = None) -> int:
        """Explicitly prune retained snapshots and return the number removed."""
        payload = self._payload()
        rows = self._rows(payload)
        before = len(rows)
        if item_id is None:
            rows.clear()
        else:
            rows[:] = [row for row in rows if row.get("item_id") != item_id]
        if len(rows) != before:
            payload["updated_at"] = int(time.time())
            self.session.save()
        return before - len(rows)


def history_digest(session: Any) -> str:
    """Return a stable digest of history metadata for backup/reachability use."""
    rows = HistoryService(session)._rows(HistoryService(session)._payload())
    metadata = [{key: row.get(key) for key in
                 ("snapshot_id", "item_id", "revision", "parent_revision", "created_at", "attachment_ids")}
                for row in rows]
    return hashlib.sha256(json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


__all__ = [
    "DEFAULT_MAX_BYTES", "DEFAULT_MAX_VERSIONS", "FieldDifference", "HistoryConflict",
    "HistoryError", "HistoryQuotaError", "HistoryService", "SnapshotNotFound", "SnapshotSummary",
    "history_digest",
]
