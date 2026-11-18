"""Named collection and cross-item metadata operations."""
from __future__ import annotations

import copy
import time
import uuid
from typing import Any

from .i18n import t
from .item_schema import MAX_COLLECTIONS, ItemSchemaError, validate_collections
from .vault import VaultError, VaultLockedError

STARTER_COLLECTIONS = ("Personal", "Work", "Travel", "Emergency")


def display_name(name: str) -> str:
    """The name to show: starters stay English in the vault (every platform adds and matches them by it), so they
    are translated only on screen. Any other name is shown as typed."""
    return t(f"collection.starter.{name}") if name in STARTER_COLLECTIONS else name


class SharedCollection(VaultError):
    """A shared collection (sub-plan 07) refuses a delete, and a read-only one a rename (as LGKCore and lgk-core)."""


def _read_only(session: Any) -> frozenset[str]:
    """Collections this vault holds read-only: as a member of a read-only share, or through a share link of
    another of this person's devices (``VaultSession.read_only_collection_ids``)."""
    read_only = getattr(session, "read_only_collection_ids", None)
    if read_only is not None:
        return frozenset(read_only)
    from .sync.share_group import linked_read_only_collection_ids

    return linked_read_only_collection_ids(session)


def _shared_here(session: Any, payload: dict[str, Any], row: dict[str, Any]) -> bool:
    """Whether *row* is shared on this device or on another of this person's devices (a share link)."""
    from .sync.vault_bridge import _stored_links

    if row.get("shared_group_id") or row["id"] in _stored_links(payload):
        return True
    read_only = getattr(session, "read_only_collection_ids", None)
    return read_only is not None and row["id"] in read_only


class TravelHiddenCollection(VaultError):
    """Travel mode hides this collection on this device: it cannot be renamed, archived, deleted or have its
    members changed until travel mode is turned off (which asks for the master password)."""


class CollectionService:
    def __init__(self, session: Any) -> None:
        self.session = session

    def _refuse_travel_hidden(self, collection_ids: Any) -> None:
        from .travel import hidden_collection_ids

        hidden = hidden_collection_ids(self.session)
        if hidden and any(str(value).strip().lower() in hidden for value in collection_ids):
            raise TravelHiddenCollection(t("travel.collectionHidden"))

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
        self._refuse_travel_hidden([collection_id])
        if collection_id in _read_only(self.session):
            # Read-only here (a member of a read-only share), or on another of this person's devices (a link):
            # the owner's name is not changed from here, as on the Mac, the iPhone and Android.
            raise SharedCollection(t("collections.sharedReadOnlyRename"))
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
        row = next((value for value in rows if value["id"] == collection_id), None)
        if row is None:
            return False
        # Deleting (or archiving) strips the collection from every item: on a travel-hidden one that would show its
        # items again without the master password that turning travel mode off asks for.
        self._refuse_travel_hidden([collection_id])
        if _shared_here(self.session, payload, row):
            # Never orphan a share group (here or on the device that holds it): stop sharing or leave first.
            raise SharedCollection(t("collections.sharedNoDelete"))
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

    def shared_group_id(self, collection_id: str) -> str | None:
        """The share group (sub-plan 07) *collection_id* syncs with, or None when it is not shared."""
        row = next((value for value in self._payload().get("collections", []) if value["id"] == collection_id), None)
        return None if row is None else row.get("shared_group_id")

    def set_shared_group(self, collection_id: str, group_id: str | None, *, save: bool = True) -> bool:
        """Mark *collection_id* as shared with *group_id* (None: no longer shared); items are untouched.

        ``save=False`` changes the record only, for a caller that saves inside its own transaction.
        """
        payload = self._payload()
        rows = payload.get("collections", [])
        row = next((value for value in rows if value["id"] == collection_id), None)
        if row is None:
            return False
        if row.get("shared_group_id") == group_id:
            return True
        candidate = {k: v for k, v in copy.deepcopy(row).items() if k != "shared_group_id"}
        if group_id is not None:
            candidate["shared_group_id"] = group_id
        now = max(int(time.time()), int(row.get("updated_at", 0)))
        candidate["updated_at"] = now
        candidate["revision"] = int(row.get("revision", 1)) + 1
        payload["collections"] = validate_collections(
            [candidate if value["id"] == collection_id else value for value in rows])
        payload["updated_at"] = now
        if save:
            self.session.save()
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
        from .travel import hidden_collection_ids

        if str(collection_id).strip().lower() in hidden_collection_ids(self.session):
            return []
        return self.session.items.metadata_summaries(collection_id=collection_id)

    def set_membership(self, item_id: str, collection_ids: list[str], *,
                       expected_revision: int | None = None) -> bool:
        """Edit membership through the schema-validating item service."""
        payload = self._payload()
        current = next((row for row in payload.get("items", [])
                        if isinstance(row, dict) and str(row.get("id")) == str(item_id)), None)
        before = set(current.get("collection_ids") or []) if isinstance(current, dict) else set()
        self._refuse_travel_hidden(before ^ set(collection_ids or []))
        return self.session.items.update_item(
            item_id, collection_ids=collection_ids, expected_revision=expected_revision,
        )
