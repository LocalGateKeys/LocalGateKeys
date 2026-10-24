"""Bounded content-free encrypted activity events."""
from __future__ import annotations

import copy
import time
import uuid
from typing import Any, ClassVar

from .item_schema import ItemSchemaError, validate_events
from .vault import VaultLockedError


class ActivityService:
    """A local convenience history; never accepts item content or secrets."""

    # Activity is intentionally a small vocabulary.  Callers can compose a
    # domain and action, but cannot use the history as an arbitrary text log.
    _SAFE_EVENT_DOMAINS: ClassVar[set[str]] = {
        "activity", "attachment", "auth", "backup", "collection", "credential",
        "document", "import", "item", "reminder", "session", "settings", "template",
        "vault",
    }
    _SAFE_EVENT_ACTIONS: ClassVar[set[str]] = {
        "add", "backup", "change", "check", "clear", "close", "complete", "copy",
        "create", "delete", "deny", "export", "fill", "import", "lock", "open",
        "prune", "read", "restore", "reveal", "search", "signin", "sign_in",
        "snooze", "start", "stop", "test", "unlock", "update", "view",
    }
    _SAFE_RESULTS: ClassVar[set[str]] = {
        "cancelled", "canceled", "cleared", "completed", "conflict", "created", "deleted",
        "denied", "error", "failed", "failure", "locked", "missing", "not_found", "ok",
        "open", "present", "pruned", "skipped", "snoozed", "success", "updated",
    }
    _FORBIDDEN_TOKENS: ClassVar[set[str]] = {
        "attachment_name", "body", "clipboard", "content", "license", "note", "password",
        "raw", "secret", "serial", "url", "username", "value",
    }

    def __init__(self, session: Any, *, retention_days: int = 90, max_events: int = 5_000) -> None:
        self.session = session
        self.retention_days = max(1, min(int(retention_days), 365))
        self.max_events = max(1, min(int(max_events), 5_000))

    def _payload(self) -> dict[str, Any]:
        if not getattr(self.session, "is_unlocked", False):
            raise VaultLockedError("Vault is locked")
        return self.session._require_typed_catalog()

    @classmethod
    def _safe_event_type(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > 64:
            raise ItemSchemaError("activity event type is malformed")
        value = value.strip().casefold()
        parts = value.split(".")
        if (len(parts) != 2 or parts[0] not in cls._SAFE_EVENT_DOMAINS
                or parts[1] not in cls._SAFE_EVENT_ACTIONS
                or any(token in cls._FORBIDDEN_TOKENS for token in parts)):
            raise ItemSchemaError("activity event type cannot describe secret content")
        return value

    @classmethod
    def _safe_result(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > 32:
            raise ItemSchemaError("activity result is malformed")
        value = value.strip().casefold()
        if value not in cls._SAFE_RESULTS:
            raise ItemSchemaError("activity result is malformed")
        return value

    @staticmethod
    def _safe_item_id(item_id: str | None) -> str | None:
        if item_id is None:
            return None
        if not isinstance(item_id, str):
            raise ItemSchemaError("activity item id is malformed")
        try:
            return str(uuid.UUID(item_id))
        except (ValueError, AttributeError):
            raise ItemSchemaError("activity item id is malformed") from None

    def _append_to_payload(self, event_type: str, *, item_id: str | None = None,
                           result: str = "ok", count: int = 0,
                           timestamp: int | None = None,
                           **forbidden: Any) -> str:
        """Append one validated event without committing the vault.

        Reminder mutations use this inside ``VaultSession.transaction`` so
        the mutation and its history row share one encrypted commit.
        """
        if forbidden:
            raise ItemSchemaError("activity events cannot contain content or secrets")
        event_type = self._safe_event_type(event_type)
        result = self._safe_result(result)
        item_id = self._safe_item_id(item_id)
        if type(count) is not int or not 0 <= count <= 2**31 - 1:
            raise ItemSchemaError("activity event count is malformed")
        if timestamp is None:
            now = int(time.time())
        elif type(timestamp) is int and 0 <= timestamp <= 2**63 - 1:
            now = timestamp
        else:
            raise ItemSchemaError("activity timestamp is malformed")
        row = {"id": str(uuid.uuid4()), "event_type": event_type, "timestamp": now,
               "item_id": item_id, "result": result, "count": count}
        payload = self._payload()
        events = self._validated_events(payload)
        events.append(row)
        cutoff = now - self.retention_days * 86400
        events = [value for value in events if int(value.get("timestamp", 0)) >= cutoff]
        events = validate_events(events)[-self.max_events:]
        payload["events"] = events
        payload["updated_at"] = now
        return row["id"]

    @classmethod
    def _validated_events(cls, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Validate the structural schema and the stricter activity vocabulary."""
        events = validate_events(payload.get("events", []))
        for event in events:
            cls._safe_event_type(event["event_type"])
            cls._safe_result(event["result"])
            cls._safe_item_id(event.get("item_id"))
        return events

    def record(self, event_type: str, *, item_id: str | None = None,
               result: str = "ok", count: int = 0, timestamp: int | None = None,
               persist: bool = True, **forbidden: Any) -> str:
        if forbidden:
            raise ItemSchemaError("activity events cannot contain content or secrets")
        event_id = self._append_to_payload(event_type, item_id=item_id, result=result,
                                           count=count, timestamp=timestamp)
        if persist:
            self.session.save()
        return event_id

    def list(self) -> list[dict[str, Any]]:
        payload = self._payload()
        now = int(time.time())
        cutoff = now - self.retention_days * 86400
        events = [event for event in self._validated_events(payload)
                  if int(event.get("timestamp", 0)) >= cutoff]
        retained = events[-self.max_events:]
        if retained != payload.get("events", []):
            payload["events"] = retained
            payload["updated_at"] = now
            self.session.save()
        return copy.deepcopy(retained)

    history = list

    def clear(self) -> None:
        payload = self._payload()
        payload["events"] = []
        payload["updated_at"] = int(time.time())
        self.session.save()
