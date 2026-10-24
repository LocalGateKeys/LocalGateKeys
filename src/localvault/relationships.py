"""Canonical encrypted typed-item relationships and reachability helpers."""
from __future__ import annotations

import copy
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .history import HistoryService
from .item_schema import validate_item
from .vault import VaultError, VaultLockedError

MAX_OUTGOING_EDGES = 100
MAX_PROFILE_EDGES = 20_000
MAX_TRAVERSAL_DEPTH = 5
MAX_TRAVERSAL_NODES = 1_000
RELATION_TYPES = frozenset({
    "related_to", "supports_document", "references", "depends_on", "supersedes",
})
LEGACY_DOCUMENT_KINDS = frozenset({"license", "purchase", "warranty", "subscription"})


class RelationshipError(VaultError):
    """Invalid or stale relationship operation."""


class RelationshipConflict(RelationshipError):
    """The source revision no longer matches the reviewed operation."""


class RelationshipMigrationError(RelationshipError):
    """Legacy relation migration failed before publication."""


@dataclass(frozen=True)
class RelationEdge:
    edge_id: str
    profile_id: str
    source_id: str
    target_id: str
    relation_type: str
    created_at: int
    tombstoned: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "profile_id": self.profile_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type,
            "created_at": self.created_at,
            "tombstoned": self.tombstoned,
        }


def _uuid(value: Any, field: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise RelationshipError(f"{field} must be a UUID") from None


def _profile_id(session: Any) -> str:
    value = getattr(session, "profile_id", None)
    if isinstance(value, str) and value:
        return value
    path = getattr(session, "path", None)
    try:
        scope = str(path.resolve().parent) if path is not None else "localvault-profile"
    except (OSError, AttributeError):
        scope = "localvault-profile"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"localvault-profile:{scope}"))


def _edge_uuid(profile_id: str, source_id: str, target_id: str, relation_type: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL,
                          f"localvault-edge:{profile_id}:{source_id}:{target_id}:{relation_type}"))


def _all_typed_items(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    result = [value for value in payload.get("items", []) if isinstance(value, dict)]
    result.extend(
        value["entry"] for value in payload.get("trash", [])
        if isinstance(value, dict) and isinstance(value.get("entry"), dict)
        and value["entry"].get("kind") not in {"web", "desktop"}
    )
    return result


class RelationshipService:
    """Own the one writable relationship edge table for a profile."""

    def __init__(self, session: Any, *, profile_id: str | None = None) -> None:
        self.session = session
        self.profile_id = profile_id or _profile_id(session)
        if not isinstance(self.profile_id, str) or not self.profile_id:
            raise RelationshipError("profile_id is malformed")

    def _payload(self) -> dict[str, Any]:
        if not getattr(self.session, "is_unlocked", False):
            raise VaultLockedError("Vault is locked")
        return self.session._require_typed_catalog()

    def _rows(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        rows = payload.setdefault("relationships", [])
        if not isinstance(rows, list) or len(rows) > MAX_PROFILE_EDGES:
            raise RelationshipError("Relationship edge table exceeds the profile bound")
        return rows

    @staticmethod
    def _clean_row(row: Mapping[str, Any]) -> RelationEdge:
        allowed = {"edge_id", "profile_id", "source_id", "target_id", "relation_type", "created_at", "tombstoned"}
        if set(row) - allowed:
            raise RelationshipError("Relationship edge contains unsupported fields")
        edge_id = _uuid(row.get("edge_id"), "edge_id")
        profile_id = str(row.get("profile_id", ""))
        if not profile_id or len(profile_id) > 128:
            raise RelationshipError("edge profile_id is malformed")
        source_id = _uuid(row.get("source_id"), "source_id")
        target_id = _uuid(row.get("target_id"), "target_id")
        if source_id == target_id:
            raise RelationshipError("self relationships are not allowed")
        relation_type = str(row.get("relation_type", ""))
        if relation_type not in RELATION_TYPES:
            raise RelationshipError("Unsupported relationship type")
        created_at = row.get("created_at")
        if type(created_at) is not int or not 0 <= created_at <= 2**63 - 1:
            raise RelationshipError("edge created_at is malformed")
        tombstoned = row.get("tombstoned", False)
        if type(tombstoned) is not bool:
            raise RelationshipError("edge tombstone flag is malformed")
        return RelationEdge(edge_id, profile_id, source_id, target_id, relation_type,
                            created_at, tombstoned)

    def list(self, *, include_tombstoned: bool = False) -> list[dict[str, Any]]:
        rows = self._rows(self._payload())
        clean = [self._clean_row(row).to_dict() for row in rows]
        if not include_tombstoned:
            clean = [row for row in clean if not row["tombstoned"]]
        return sorted(clean, key=lambda row: (row["source_id"], row["relation_type"], row["target_id"], row["edge_id"]))

    edges = list

    def _targets(self, payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        return {item["id"]: item for item in _all_typed_items(payload) if isinstance(item.get("id"), str)}

    def _validate_endpoints(self, payload: Mapping[str, Any], source_id: str, target_id: str,
                            relation_type: str) -> tuple[dict[str, Any], dict[str, Any]]:
        source_id = _uuid(source_id, "source_id")
        target_id = _uuid(target_id, "target_id")
        if source_id == target_id:
            raise RelationshipError("self relationships are not allowed")
        if relation_type not in RELATION_TYPES:
            raise RelationshipError("Unsupported relationship type")
        targets = self._targets(payload)
        source = targets.get(source_id)
        target = targets.get(target_id)
        if source is None or source_id not in {item["id"] for item in payload.get("items", []) if isinstance(item, dict)}:
            raise RelationshipError("Relationship source must be a live typed item")
        if target is None:
            raise RelationshipError("Relationship target does not exist in this profile")
        if relation_type == "supports_document" and target.get("kind") != "document":
            raise RelationshipError("supports_document targets must be documents")
        return source, target

    def _capture_source(self, payload: dict[str, Any], source: Mapping[str, Any], *, change_type: str) -> None:
        relation_rows = [row for row in self._rows(payload)
                         if row.get("source_id") == source.get("id") and not row.get("tombstoned", False)]
        HistoryService(self.session).record_before_change(source, relations=relation_rows,
                                                           change_type=change_type, persist=False)

    def _commit_source_revision(self, payload: dict[str, Any], source: dict[str, Any], *, expected_revision: int | None,
                                change_type: str, mutate: Any) -> None:
        if expected_revision is not None and (type(expected_revision) is not int
                                              or expected_revision != source.get("revision")):
            raise RelationshipConflict("Item revision conflict")
        original = copy.deepcopy(source)
        self._capture_source(payload, source, change_type=change_type)
        source["revision"] = int(source.get("revision", 1)) + 1
        source["updated_at"] = int(time.time())
        try:
            mutate()
            source_copy = validate_item(copy.deepcopy(source), known_collection_ids={
                row["id"] for row in payload.get("collections", []) if isinstance(row, dict) and "id" in row
            })
            source.clear()
            source.update(source_copy)
            payload["updated_at"] = int(time.time())
            self.session.save()
        except BaseException:
            source.clear()
            source.update(original)
            raise

    def add(self, source_id: str, target_id: str, relation_type: str = "related_to", *,
            expected_revision: int | None = None) -> str:
        payload = self._payload()
        source, _target = self._validate_endpoints(payload, source_id, target_id, relation_type)
        source_id = str(source["id"])
        target_id = _uuid(target_id, "target_id")
        rows = self._rows(payload)
        for row in rows:
            edge = self._clean_row(row)
            if (not edge.tombstoned and edge.profile_id == self.profile_id and edge.source_id == source_id
                    and edge.target_id == target_id and edge.relation_type == relation_type):
                raise RelationshipError("Duplicate relationship edge")
        if sum(1 for row in rows if row.get("source_id") == source_id and not row.get("tombstoned", False)) >= MAX_OUTGOING_EDGES:
            raise RelationshipError("The source item relationship limit has been reached")
        if len(rows) >= MAX_PROFILE_EDGES:
            raise RelationshipError("The profile relationship limit has been reached")
        edge = RelationEdge(_edge_uuid(self.profile_id, source_id, target_id, relation_type), self.profile_id,
                            source_id, target_id, relation_type, int(time.time()))
        tombstone = next((row for row in rows
                          if row.get("edge_id") == edge.edge_id and row.get("tombstoned", False)), None)
        def mutate() -> None:
            if tombstone is not None:
                tombstone["tombstoned"] = False
            else:
                rows.append(edge.to_dict())
        self._commit_source_revision(payload, source, expected_revision=expected_revision,
                                     change_type="relation_add", mutate=mutate)
        return edge.edge_id

    create = add
    add_edge = add

    def remove(self, edge_id: str, *, expected_revision: int | None = None) -> bool:
        payload = self._payload()
        rows = self._rows(payload)
        edge_id = _uuid(edge_id, "edge_id")
        row = next((value for value in rows if value.get("edge_id") == edge_id and not value.get("tombstoned", False)), None)
        if row is None:
            return False
        source = next((item for item in payload.get("items", [])
                       if isinstance(item, dict) and item.get("id") == row.get("source_id")), None)
        if source is None:
            raise RelationshipError("Relationship source is not live")
        def mutate() -> None:
            row["tombstoned"] = True
        self._commit_source_revision(payload, source, expected_revision=expected_revision,
                                     change_type="relation_remove", mutate=mutate)
        return True

    remove_edge = remove
    delete = remove

    def edit(self, edge_id: str, *, target_id: str | None = None, relation_type: str | None = None,
             expected_revision: int | None = None) -> bool:
        payload = self._payload()
        rows = self._rows(payload)
        edge_id = _uuid(edge_id, "edge_id")
        row = next((value for value in rows if value.get("edge_id") == edge_id and not value.get("tombstoned", False)), None)
        if row is None:
            return False
        source = next((item for item in payload.get("items", [])
                       if isinstance(item, dict) and item.get("id") == row.get("source_id")), None)
        if source is None:
            raise RelationshipError("Relationship source is not live")
        new_target = _uuid(target_id or row["target_id"], "target_id")
        new_type = relation_type or row["relation_type"]
        self._validate_endpoints(payload, source["id"], new_target, new_type)
        new_edge_id = _edge_uuid(self.profile_id, source["id"], new_target, new_type)
        if any(value.get("edge_id") == new_edge_id and value.get("edge_id") != edge_id
               and not value.get("tombstoned", False) for value in rows):
            raise RelationshipError("Duplicate relationship edge")
        def mutate() -> None:
            row.update({"edge_id": new_edge_id, "target_id": new_target, "relation_type": new_type})
        self._commit_source_revision(payload, source, expected_revision=expected_revision,
                                     change_type="relation_update", mutate=mutate)
        return True

    update = edit

    def outgoing(self, source_id: str, *, include_tombstoned: bool = False) -> list[dict[str, Any]]:
        source_id = _uuid(source_id, "source_id")
        return [row for row in self.list(include_tombstoned=include_tombstoned)
                if row["source_id"] == source_id]

    forward = outgoing

    def backlinks(self, target_id: str, *, include_tombstoned: bool = False) -> list[dict[str, Any]]:
        target_id = _uuid(target_id, "target_id")
        return [row for row in self.list(include_tombstoned=include_tombstoned)
                if row["target_id"] == target_id]

    incoming = backlinks

    def traverse(self, start_id: str, *, depth: int = MAX_TRAVERSAL_DEPTH,
                 max_nodes: int = MAX_TRAVERSAL_NODES) -> dict[str, Any]:
        if type(depth) is not int or not 0 <= depth <= MAX_TRAVERSAL_DEPTH:
            raise RelationshipError(f"Traversal depth must be between 0 and {MAX_TRAVERSAL_DEPTH}")
        if type(max_nodes) is not int or not 1 <= max_nodes <= MAX_TRAVERSAL_NODES:
            raise RelationshipError(f"Traversal node bound must be between 1 and {MAX_TRAVERSAL_NODES}")
        start_id = _uuid(start_id, "start_id")
        rows = self.list()
        adjacency: dict[str, list[str]] = {}
        for row in rows:
            adjacency.setdefault(row["source_id"], []).append(row["target_id"])
        visited = {start_id}
        frontier = [(start_id, 0)]
        truncated = False
        while frontier:
            current, current_depth = frontier.pop(0)
            if current_depth >= depth:
                continue
            for target in adjacency.get(current, []):
                if target in visited:
                    continue
                if len(visited) >= max_nodes:
                    truncated = True
                    break
                visited.add(target)
                frontier.append((target, current_depth + 1))
            if truncated:
                break
        return {"start_id": start_id, "nodes": sorted(visited), "depth": depth, "truncated": truncated}

    walk = traverse

    def migrate_legacy(self, *, persist: bool = True) -> dict[str, Any]:
        """Convert every typed ``document_ids`` reference to canonical edges.

        Validation is completed against a copy before ``payload`` is changed,
        so an invalid UUID, missing document, wrong target kind, or unexpected
        link-bearing field aborts without a partial migration.
        """
        payload = self._payload()
        rows = copy.deepcopy(self._rows(payload))
        items = _all_typed_items(payload)
        known = {item.get("id"): item for item in items if isinstance(item.get("id"), str)}
        unexpected: list[str] = []
        candidates: list[dict[str, Any]] = []
        for item in items:
            kind = item.get("kind")
            typed = item.get("payload")
            if not isinstance(typed, dict):
                continue
            for key in typed:
                if key.endswith("_ids") and key != "document_ids":
                    unexpected.append(f"{item.get('id')}:{key}")
            if "document_ids" not in typed:
                continue
            if kind not in LEGACY_DOCUMENT_KINDS:
                unexpected.append(f"{item.get('id')}:document_ids")
                continue
            refs = typed.get("document_ids")
            if not isinstance(refs, list):
                raise RelationshipMigrationError("Legacy document_ids must be a list")
            for target_value in refs:
                try:
                    source_id = _uuid(item.get("id"), "source_id")
                    target_id = _uuid(target_value, "document_id")
                except RelationshipError as exc:
                    raise RelationshipMigrationError(str(exc)) from None
                target = known.get(target_id)
                if target is None or target.get("kind") != "document":
                    raise RelationshipMigrationError("Legacy document_ids target is not a document")
                candidates.append({
                    "edge_id": _edge_uuid(self.profile_id, source_id, target_id, "supports_document"),
                    "profile_id": self.profile_id, "source_id": source_id, "target_id": target_id,
                    "relation_type": "supports_document", "created_at": int(item.get("updated_at", time.time())),
                    "tombstoned": False,
                })
        if unexpected:
            raise RelationshipMigrationError("Unsupported legacy relationship fields: " + ", ".join(sorted(unexpected)))
        seen: set[str] = set()
        merged: list[dict[str, Any]] = []
        for row in [*rows, *candidates]:
            edge = self._clean_row(row)
            if edge.profile_id != self.profile_id:
                raise RelationshipMigrationError("Cross-profile relationship edge")
            if edge.edge_id in seen:
                continue
            seen.add(edge.edge_id)
            merged.append(edge.to_dict())
        if len(merged) > MAX_PROFILE_EDGES:
            raise RelationshipMigrationError("Relationship edge table exceeds the profile bound")
        # Once a valid legacy reference has been published as a canonical
        # edge, clear the old writable list.  If validation above failed, no
        # payload mutation has happened and the source reference remains for
        # repair.  The schema still accepts an empty document_ids list for
        # compatibility with older readers.
        if persist and candidates:
            for item in items:
                typed = item.get("payload")
                if isinstance(typed, dict) and item.get("kind") in LEGACY_DOCUMENT_KINDS and "document_ids" in typed:
                    typed["document_ids"] = []
        if persist and merged != rows:
            payload["relationships"] = merged
            payload["updated_at"] = int(time.time())
            self.session.save()
        elif persist and candidates:
            payload["relationships"] = merged
            payload["updated_at"] = int(time.time())
            self.session.save()
        return {
            "migrated": len(candidates),
            "deduplicated": len(rows) + len(candidates) - len(merged),
            "edge_count": len(merged),
            "legacy_cleared": len(candidates),
            "invalid": [],
        }

    migrate_legacy_document_ids = migrate_legacy
    ensure_migrated = migrate_legacy


class ReachabilityResolver:
    """Resolve live, trash, history, relation, and attachment references."""

    def __init__(self, session: Any) -> None:
        self.session = session

    def resolve(self) -> dict[str, Any]:
        if not getattr(self.session, "is_unlocked", False):
            raise VaultLockedError("Vault is locked")
        payload = self.session._require_typed_catalog()
        live = {item["id"] for item in payload.get("items", []) if isinstance(item, dict) and "id" in item}
        trash = {record["entry"]["id"] for record in payload.get("trash", [])
                 if isinstance(record, dict) and isinstance(record.get("entry"), dict)
                 and record["entry"].get("kind") not in {"web", "desktop"}}
        history_items = {row.get("item_id") for row in payload.get("history", []) if isinstance(row, dict)}
        edge_items = {value for row in payload.get("relationships", []) if isinstance(row, dict)
                      for value in (row.get("source_id"), row.get("target_id")) if isinstance(value, str)}
        # Attachment records are reachable only through item payloads or
        # retained snapshots.  Catalog rows without either reference are
        # intentionally omitted so callers can identify orphan cleanup.
        attachment_ids: set[str] = set()
        reachable_items = [value for value in payload.get("items", []) if isinstance(value, dict)]
        reachable_items.extend(
            record["entry"] for record in payload.get("trash", [])
            if isinstance(record, dict) and isinstance(record.get("entry"), dict)
            and record["entry"].get("kind") not in {"web", "desktop"}
        )
        for item in reachable_items:
            typed = item.get("payload", {})
            if isinstance(typed, dict) and isinstance(typed.get("attachment_id"), str):
                attachment_ids.add(typed["attachment_id"])
        for row in payload.get("history", []):
            if isinstance(row, dict):
                attachment_ids.update(value for value in row.get("attachment_ids", []) if isinstance(value, str))
        return {
            "live_item_ids": sorted(live), "trash_item_ids": sorted(trash),
            "history_item_ids": sorted(value for value in history_items if isinstance(value, str)),
            "relation_item_ids": sorted(edge_items), "attachment_ids": sorted(attachment_ids),
        }

    reachable = resolve


def purge_blockers(session: Any, item_id: str) -> list[dict[str, Any]]:
    """Return metadata-only reasons an item cannot be hard-purged safely."""
    if not getattr(session, "is_unlocked", False):
        raise VaultLockedError("Vault is locked")
    item_id = _uuid(item_id, "item_id")
    payload = session._require_typed_catalog()
    blockers: list[dict[str, Any]] = []
    for row in payload.get("relationships", []):
        if not isinstance(row, dict) or row.get("tombstoned", False):
            continue
        if row.get("source_id") == item_id or row.get("target_id") == item_id:
            blockers.append({"kind": "relationship", "edge_id": row.get("edge_id")})
    for row in payload.get("history", []):
        if isinstance(row, dict) and row.get("item_id") == item_id:
            blockers.append({"kind": "history", "snapshot_id": row.get("snapshot_id")})
    return blockers


__all__ = [
    "MAX_OUTGOING_EDGES", "MAX_PROFILE_EDGES", "MAX_TRAVERSAL_DEPTH", "MAX_TRAVERSAL_NODES",
    "RELATION_TYPES", "ReachabilityResolver", "RelationEdge", "RelationshipConflict",
    "RelationshipError", "RelationshipMigrationError", "RelationshipService", "purge_blockers",
]
