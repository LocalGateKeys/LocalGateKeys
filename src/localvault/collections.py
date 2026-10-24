"""Named collection and cross-item metadata operations."""
from __future__ import annotations

import copy
import time
import uuid
from typing import Any

from .item_schema import MAX_COLLECTIONS, ItemSchemaError, validate_collections
from .vault import VaultLockedError

STARTER_COLLECTIONS = ("Personal", "Work", "Travel", "Emergency")


class CollectionService:
    def __init__(self, session: Any) -> None:
        self.session = session

    def _payload(self) -> dict[str, Any]:
        if not getattr(self.session, "is_unlocked", False):
            raise VaultLockedError("Vault is locked")
        return self.session._require_typed_catalog()

    def list(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._payload().get("collections", []))

    def create(self, name: str, *, description: str = "", starter: bool = False) -> str:
        payload = self._payload()
        rows = payload.setdefault("collections", [])
        if len(rows) >= MAX_COLLECTIONS:
            raise ItemSchemaError("Collection limit reached")
        if any(row["name"].casefold() == name.strip().casefold() for row in rows):
            raise ItemSchemaError("A collection with that name already exists")
        now = int(time.time())
        row = {
            "id": str(uuid.uuid4()), "name": name, "description": description,
            "created_at": now, "updated_at": now, "revision": 1, "starter": bool(starter),
        }
        validated = validate_collections([*rows, row])
        payload["collections"] = validated
        payload["updated_at"] = now
        self.session.save()
        self._record_activity("collection.create", item_id=validated[-1]["id"])
        return validated[-1]["id"]

    def _record_activity(self, event_type: str, *, item_id: str | None = None) -> None:
        """Record only an operation and opaque collection ID."""
        try:
            self.session.activity.record(event_type, item_id=item_id)
        except (AttributeError, ItemSchemaError, VaultLockedError):
            # Activity is convenience history and must not make a committed
            # collection unusable on older or minimal session objects.
            pass

    def ensure_starters(self) -> list[str]:
        existing = {row["name"].casefold(): row["id"] for row in self.list()}
        result = []
        for name in STARTER_COLLECTIONS:
            result.append(existing.get(name.casefold()) or self.create(name, starter=True))
        return result

    def rename(self, collection_id: str, name: str, *, description: str | None = None) -> bool:
        payload = self._payload()
        row = next((value for value in payload.get("collections", []) if value["id"] == collection_id), None)
        if row is None:
            return False
        if any(value["id"] != collection_id and value["name"].casefold() == name.strip().casefold()
               for value in payload.get("collections", [])):
            raise ItemSchemaError("A collection with that name already exists")
        candidate = copy.deepcopy(row)
        candidate["name"] = name
        if description is not None:
            candidate["description"] = description
        candidate["updated_at"] = int(time.time())
        candidate["revision"] = int(row.get("revision", 1)) + 1
        candidates = [candidate if value["id"] == collection_id else value
                      for value in payload.get("collections", [])]
        payload["collections"] = validate_collections(candidates)
        payload["updated_at"] = int(time.time())
        self.session.save()
        self._record_activity("collection.update", item_id=collection_id)
        return True

    def delete(self, collection_id: str) -> bool:
        payload = self._payload()
        rows = payload.get("collections", [])
        if not any(row["id"] == collection_id for row in rows):
            return False
        payload["collections"] = [row for row in rows if row["id"] != collection_id]
        # Removing a collection is metadata-only and does not delete its
        # items. Clean retained typed trash as well so validation cannot keep
        # a reference to a deleted collection.
        item_rows = list(payload.get("items", []))
        item_rows.extend(
            record.get("entry") for record in payload.get("trash", [])
            if isinstance(record, dict) and isinstance(record.get("entry"), dict)
        )
        for item in item_rows:
            if not isinstance(item, dict):
                continue
            item["collection_ids"] = [value for value in item.get("collection_ids", []) if value != collection_id]
        payload["updated_at"] = int(time.time())
        self.session.save()
        self._record_activity("collection.delete", item_id=collection_id)
        return True

    def archive(self, collection_id: str) -> bool:
        """Archive a collection while retaining its items.

        The catalog schema has no hidden archived state. An archived
        collection is absent from active lists and all memberships are safely
        removed; items themselves remain untouched.
        """
        return self.delete(collection_id)

    archive_collection = archive

    def members(self, collection_id: str) -> list[Any]:
        """Return metadata-only typed-item summaries for a collection."""
        self._payload()
        if not any(row.get("id") == collection_id for row in self.list()):
            return []
        return self.session.items.metadata_summaries(collection_id=collection_id)

    def set_membership(self, item_id: str, collection_ids: list[str], *,
                       expected_revision: int | None = None) -> bool:
        """Edit membership through the schema-validating item service."""
        self._payload()
        return self.session.items.update_item(
            item_id, collection_ids=collection_ids, expected_revision=expected_revision,
        )
