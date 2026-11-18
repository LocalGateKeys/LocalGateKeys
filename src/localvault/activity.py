"""Bounded content-free encrypted activity events."""
from __future__ import annotations

import copy
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, ClassVar

from .item_schema import ItemSchemaError, validate_events
from .vault import VaultLockedError

GENESIS_HASH = "0" * 64


def event_hash(event: dict[str, Any]) -> str:
    """SHA-256 of an event's canonical JSON (sorted keys, no spaces)."""
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChainReport:
    ok: bool
    first_bad_id: str | None
    checkpoint: str | None


def _chain_state(payload: dict[str, Any]) -> dict[str, str | None]:
    raw = payload.get("events_chain")
    state: dict[str, str | None] = {"checkpoint": None, "head": None}
    if isinstance(raw, dict):
        for key in state:
            value = raw.get(key)
            if isinstance(value, str) and len(value) == 64:
                state[key] = value
    return state


class ActivityService:
    """A local convenience history; never accepts item content or secrets."""

    # Activity is intentionally a small vocabulary.  Callers can compose a
    # domain and action, but cannot use the history as an arbitrary text log.
    _SAFE_EVENT_DOMAINS: ClassVar[set[str]] = {
        "activity", "agent", "attachment", "auth", "backup", "collection", "credential",
        "document", "import", "item", "reminder", "session", "settings", "template",
        "vault",
    }
    _SAFE_EVENT_ACTIONS: ClassVar[set[str]] = {
        "add", "backup", "change", "check", "clear", "close", "complete", "copy",
        "create", "delete", "deny", "export", "fill", "import", "lock", "open", "request",
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
        state = _chain_state(payload)
        row["prev_hash"] = event_hash(events[-1]) if events else (state["head"] or state["checkpoint"]
                                                                  or GENESIS_HASH)
        events.append(row)
        cutoff = now - self.retention_days * 86400
        kept = [value for value in events if int(value.get("timestamp", 0)) >= cutoff][-self.max_events:]
        self._store(payload, events, validate_events(kept), now)
        return row["id"]

    @staticmethod
    def _store(payload: dict[str, Any], before: list[dict[str, Any]], kept: list[dict[str, Any]],
               now: int) -> None:
        """Write the retained events and keep the chain checkpoint and head current.

        Pruning drops events from the front only; the checkpoint is the hash of
        the last dropped event so the first kept event still verifies.
        """
        state = _chain_state(payload)
        kept_ids = {e["id"] for e in kept}
        dropped = [e for e in before if e["id"] not in kept_ids]
        if dropped:
            state["checkpoint"] = event_hash(dropped[-1])
        if kept:
            state["head"] = event_hash(kept[-1])
        elif before:
            state["head"] = state["checkpoint"] = event_hash(before[-1])
        payload["events"] = kept
        payload["events_chain"] = state
        payload["updated_at"] = now

    def verify_chain(self) -> ChainReport:
        """Check every chained event links to the one before it (or the checkpoint)."""
        payload = self._payload()
        events = validate_events(payload.get("events", []))
        state = _chain_state(payload)
        expected = state["checkpoint"] or GENESIS_HASH
        chained = False
        for index, event in enumerate(events):
            prev = event.get("prev_hash")
            if prev is None:
                if chained:
                    return ChainReport(False, event["id"], state["checkpoint"])
                expected = event_hash(event)  # pre-chain event from an older build
                continue
            chained = True
            if prev != expected:
                bad = events[index - 1]["id"] if index else event["id"]
                return ChainReport(False, bad, state["checkpoint"])
            expected = event_hash(event)
        # Once a chain exists its head must match: this catches a cut-off tail, an emptied log and events whose
        # prev_hash was stripped to pass them off as pre-chain ones.
        if state["head"] is not None and state["head"] != expected:
            return ChainReport(False, events[-1]["id"] if events else None, state["checkpoint"])
        return ChainReport(True, None, state["checkpoint"])

    def export_jsonl(self) -> str:
        """A JSON-lines export: a chain header, then each event with its own hash."""
        payload = self._payload()
        events = validate_events(payload.get("events", []))
        state = _chain_state(payload)
        lines = [json.dumps({"type": "chain", "checkpoint": state["checkpoint"], "head": state["head"],
                             "algorithm": "sha256-canonical-json"}, sort_keys=True)]
        for event in events:
            row = dict(event)
            row["hash"] = event_hash(event)
            lines.append(json.dumps(row, sort_keys=True))
        return "\n".join(lines) + "\n"

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
            self._store(payload, self._validated_events(payload), retained, now)
            self.session.save()
        return copy.deepcopy(retained)

    history = list

    def clear(self) -> None:
        payload = self._payload()
        self._store(payload, self._validated_events(payload), [], int(time.time()))
        self.session.save()
