"""Saved metadata-only smart views.

Smart views are a deliberately small data language.  Validation produces a
canonical AST and evaluation operates on safe summary rows only; no Python
expression, SQL, arbitrary payload path, content search, or network predicate
is accepted.
"""
from __future__ import annotations

import copy
import datetime as _datetime
import json
import re
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .item_schema import ITEM_KINDS
from .vault import VaultError, VaultLockedError

MAX_VIEWS = 100
MAX_CLAUSES = 20
MAX_AST_DEPTH = 3
MAX_AST_BYTES = 16 * 1024
MAX_NAME = 100
ALLOWED_FIELDS = frozenset({
    "kind", "title", "tags", "favorite", "collection_ids", "created_at", "updated_at", "revision",
    "due_date", "expiration_date", "renewal_date", "reminder_status",
})
ALLOWED_OPERATORS = frozenset({
    "eq", "neq", "contains", "not_contains", "in", "not_in", "has", "before", "after",
    "on_or_before", "on_or_after", "is_true", "is_false",
})
ALLOWED_SORT_KEYS = frozenset({
    "kind", "title", "created_at", "updated_at", "revision", "favorite", "due_date",
    "expiration_date", "renewal_date",
})
_RELATIVE_DATE = re.compile(r"^(today|tomorrow|yesterday)(?:([+-])(\d{1,3}))?$")


class SmartViewError(VaultError):
    """Invalid saved-view definition or evaluation."""


class SmartViewStale(SmartViewError):
    """A view references metadata that no longer exists."""


@dataclass(frozen=True)
class SmartViewDefinition:
    id: str
    name: str
    predicate: dict[str, Any]
    sort_keys: tuple[dict[str, Any], ...]
    pinned: bool
    created_at: int
    updated_at: int
    schema_version: int = 1
    stale_references: tuple[str, ...] = ()
    disabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "predicate": copy.deepcopy(self.predicate),
            "sort_keys": [copy.deepcopy(value) for value in self.sort_keys], "pinned": self.pinned,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "schema_version": self.schema_version, "stale_references": list(self.stale_references),
            "disabled": self.disabled,
        }


def _text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
        raise SmartViewError(f"{field} is malformed")
    return value.strip()


def _canonical_date(value: Any) -> str:
    if not isinstance(value, str):
        raise SmartViewError("date predicate must be text")
    value = value.strip().casefold()
    if _RELATIVE_DATE.match(value):
        return value
    try:
        return _datetime.date.fromisoformat(value).isoformat()
    except ValueError:
        raise SmartViewError("date predicate must be YYYY-MM-DD or a relative date") from None


def _date_value(value: Any, *, today: _datetime.date | None = None) -> str:
    if isinstance(value, str):
        value = _canonical_date(value)
        match = _RELATIVE_DATE.match(value)
        if match:
            today = today or _datetime.date.today()
            result = today + _datetime.timedelta(days={"today": 0, "tomorrow": 1, "yesterday": -1}[match.group(1)])
            if match.group(2):
                result += _datetime.timedelta(days=(1 if match.group(2) == "+" else -1) * int(match.group(3)))
            return result.isoformat()
        return value
    raise SmartViewError("date predicate is malformed")


def _value(field: str, value: Any) -> Any:
    if field not in ALLOWED_FIELDS:
        raise SmartViewError("Smart view field is not allowlisted")
    if field == "kind":
        if not isinstance(value, str) or value not in ITEM_KINDS:
            raise SmartViewError("kind predicate is unsupported")
        return value
    if field in {"title"}:
        return _text(value, field, 512)
    if field in {"tags", "collection_ids"}:
        if isinstance(value, str):
            return _text(value, field, 128)
        if not isinstance(value, list) or len(value) > 20:
            raise SmartViewError(f"{field} predicate must be a bounded list")
        return [_text(item, field, 128) for item in value]
    if field in {"favorite"}:
        if type(value) is not bool:
            raise SmartViewError("favorite predicate must be boolean")
        return value
    if field in {"created_at", "updated_at", "revision"}:
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise SmartViewError(f"{field} predicate must be a bounded integer")
        return value
    if field in {"due_date", "expiration_date", "renewal_date"}:
        return _canonical_date(value)
    if field == "reminder_status":
        if value not in {"pending", "snoozed", "dismissed", "overdue", "none"}:
            raise SmartViewError("reminder status predicate is unsupported")
        return value
    raise SmartViewError("Smart view field is unsupported")


def _clause(field: Any, operator: Any, value: Any = None) -> dict[str, Any]:
    field = str(field)
    operator = str(operator)
    if field not in ALLOWED_FIELDS or operator not in ALLOWED_OPERATORS:
        raise SmartViewError("Smart view clause is not allowlisted")
    if operator in {"is_true", "is_false"}:
        if field not in {"favorite"}:
            raise SmartViewError("Boolean predicate requires a boolean field")
        return {"field": field, "op": operator}
    if operator in {"in", "not_in"}:
        if not isinstance(value, list) or len(value) > 20:
            raise SmartViewError("membership predicate must be a bounded list")
        return {"field": field, "op": operator, "value": [_value(field, item) for item in value]}
    if operator in {"contains", "not_contains", "has"} and field not in {"tags", "collection_ids", "title"}:
        raise SmartViewError("contains predicate is not allowed for this field")
    return {"field": field, "op": operator, "value": _value(field, value)}


def _predicate(node: Any, *, depth: int = 0, clauses: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if clauses is None:
        clauses = []
    if depth > MAX_AST_DEPTH:
        raise SmartViewError("Smart view predicate is too deeply nested")
    if not isinstance(node, Mapping):
        raise SmartViewError("Smart view predicate must be an object")
    if "field" in node:
        if set(node) - {"field", "op", "value"}:
            raise SmartViewError("Smart view clause contains unsupported fields")
        clauses.append(_clause(node.get("field"), node.get("op"), node.get("value")))
        if len(clauses) > MAX_CLAUSES:
            raise SmartViewError(f"A smart view may contain at most {MAX_CLAUSES} clauses")
        return clauses[-1]
    op = node.get("op")
    if op in {"and", "or"}:
        raw = node.get("clauses", node.get("args"))
        if not isinstance(raw, list) or not raw:
            raise SmartViewError("Boolean predicate requires clauses")
        result = [_predicate(value, depth=depth + 1, clauses=clauses) for value in raw]
        return {"op": op, "clauses": result}
    if op == "not":
        raw = node.get("clause")
        return {"op": "not", "clause": _predicate(raw, depth=depth + 1, clauses=clauses)}
    raise SmartViewError("Smart view predicate operator is unsupported")


def validate_predicate(value: Any) -> dict[str, Any]:
    result = _predicate(value)
    if len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()) > MAX_AST_BYTES:
        raise SmartViewError("Smart view predicate is too large")
    return result


def validate_sort_keys(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return [{"field": "title", "direction": "asc"}]
    if not isinstance(value, list) or len(value) > len(ALLOWED_SORT_KEYS):
        raise SmartViewError("Smart view sort keys are malformed")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in value:
        if isinstance(row, str):
            row = {"field": row, "direction": "asc"}
        if not isinstance(row, Mapping) or set(row) - {"field", "direction"}:
            raise SmartViewError("Smart view sort key is malformed")
        field = str(row.get("field"))
        direction = str(row.get("direction", "asc")).casefold()
        if field not in ALLOWED_SORT_KEYS or direction not in {"asc", "desc"} or field in seen:
            raise SmartViewError("Smart view sort key is unsupported")
        seen.add(field)
        result.append({"field": field, "direction": direction})
    return result


def _metadata_rows(session: Any) -> list[dict[str, Any]]:
    payload = session._require_typed_catalog()
    reminders: dict[str, list[str]] = {}
    today = _datetime.date.today().isoformat()
    for reminder in payload.get("reminders", []):
        if not isinstance(reminder, Mapping):
            continue
        status = str(reminder.get("status", "pending"))
        due = reminder.get("due_date", "")
        if status == "pending" and isinstance(due, str) and due < today:
            status = "overdue"
        reminders.setdefault(str(reminder.get("item_id")), []).append(status)
    rows: list[dict[str, Any]] = []
    for item in payload.get("items", []):
        if not isinstance(item, Mapping):
            continue
        typed = item.get("payload", {}) if isinstance(item.get("payload"), Mapping) else {}
        # These are approved date metadata fields.  Do not copy notes, URLs,
        # identity values, custom fields, or protected license values.
        row = {
            "id": item.get("id"), "kind": item.get("kind"), "title": item.get("title"),
            "tags": list(item.get("tags", [])), "favorite": item.get("favorite", False),
            "collection_ids": list(item.get("collection_ids", [])),
            "created_at": item.get("created_at"), "updated_at": item.get("updated_at"),
            "revision": item.get("revision", 1),
            "due_date": typed.get("due_date", ""),
            "expiration_date": typed.get("expiration_date", ""),
            "renewal_date": typed.get("renewal_date", ""),
            "reminder_status": (reminders.get(str(item.get("id")), ["none"])[0]),
        }
        rows.append(row)
    return rows


def _field_value(row: Mapping[str, Any], field: str) -> Any:
    return row.get(field, [] if field in {"tags", "collection_ids"} else "")


def _compare(actual: Any, operator: str, expected: Any) -> bool:
    if operator in {"before", "after", "on_or_before", "on_or_after"}:
        if actual in (None, ""):
            return False
        try:
            actual = _date_value(actual)
            expected = _date_value(expected)
        except SmartViewError:
            return False
    if operator == "eq":
        return actual == expected
    if operator == "neq":
        return actual != expected
    if operator == "contains":
        if isinstance(actual, (list, tuple, set)):
            return expected in actual
        return isinstance(actual, str) and str(expected).casefold() in actual.casefold()
    if operator == "not_contains":
        return not _compare(actual, "contains", expected)
    if operator == "has":
        return expected in actual if isinstance(actual, (list, tuple, set)) else bool(actual)
    if operator == "in":
        return actual in expected
    if operator == "not_in":
        return actual not in expected
    if operator == "is_true":
        return actual is True
    if operator == "is_false":
        return actual is False
    if operator == "before":
        return actual < expected
    if operator == "after":
        return actual > expected
    if operator == "on_or_before":
        return actual <= expected
    if operator == "on_or_after":
        return actual >= expected
    return False


def evaluate_predicate(predicate: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    node = predicate
    if "field" in node:
        return _compare(_field_value(row, str(node["field"])), str(node["op"]), node.get("value"))
    op = node.get("op")
    if op == "and":
        return all(evaluate_predicate(value, row) for value in node.get("clauses", []))
    if op == "or":
        return any(evaluate_predicate(value, row) for value in node.get("clauses", []))
    if op == "not":
        return not evaluate_predicate(node.get("clause", {}), row)
    return False


def _sort_value(row: Mapping[str, Any], field: str) -> Any:
    value = _field_value(row, field)
    if value in (None, ""):
        return (0, "")
    if isinstance(value, bool):
        return (1, int(value))
    return (1, str(value).casefold() if isinstance(value, str) else value)


class SmartViewService:
    def __init__(self, session: Any) -> None:
        self.session = session

    def _payload(self) -> dict[str, Any]:
        if not getattr(self.session, "is_unlocked", False):
            raise VaultLockedError("Vault is locked")
        return self.session._require_typed_catalog()

    def _rows(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        rows = payload.setdefault("smart_views", [])
        if not isinstance(rows, list) or len(rows) > MAX_VIEWS:
            raise SmartViewError("Smart view limit reached")
        return rows

    @staticmethod
    def _definition(row: Mapping[str, Any]) -> SmartViewDefinition:
        return SmartViewDefinition(
            id=str(row["id"]), name=str(row["name"]), predicate=validate_predicate(row["predicate"]),
            sort_keys=tuple(validate_sort_keys(row.get("sort_keys"))), pinned=bool(row.get("pinned", False)),
            created_at=int(row["created_at"]), updated_at=int(row["updated_at"]),
            schema_version=int(row.get("schema_version", 1)),
            stale_references=tuple(str(value) for value in row.get("stale_references", [])),
            disabled=bool(row.get("disabled", False)),
        )

    def list(self) -> list[dict[str, Any]]:
        payload = self._payload()
        collection_ids = {
            value["id"] for value in payload.get("collections", [])
            if isinstance(value, Mapping) and "id" in value
        }
        rows = []
        for value in self._rows(payload):
            definition = self._definition(value).to_dict()
            stale = self._stale_refs(definition["predicate"], collection_ids)
            definition["stale_references"] = stale
            definition["disabled"] = bool(definition["disabled"] or stale)
            rows.append(definition)
        return sorted(rows, key=lambda value: (not value["pinned"], value["name"].casefold(), value["id"]))

    views = list

    def get(self, view_id: str) -> dict[str, Any] | None:
        for row in self.list():
            if row["id"] == view_id:
                return row
        return None

    def _stale_refs(self, predicate: Mapping[str, Any], collection_ids: set[str]) -> list[str]:
        stale: list[str] = []
        def walk(node: Mapping[str, Any]) -> None:
            if "field" in node:
                if node.get("field") == "collection_ids" and node.get("op") in {"eq", "contains", "has", "in"}:
                    values = node.get("value") if node.get("op") == "in" else [node.get("value")]
                    for value in values or []:
                        if isinstance(value, str) and value not in collection_ids:
                            stale.append(value)
                return
            for child in node.get("clauses", []):
                if isinstance(child, Mapping):
                    walk(child)
            if isinstance(node.get("clause"), Mapping):
                walk(node["clause"])
        walk(predicate)
        return sorted(set(stale))

    def create(self, name: str, predicate: Mapping[str, Any], *, sort_keys: Any = None,
               pinned: bool = False) -> str:
        payload = self._payload()
        rows = self._rows(payload)
        if len(rows) >= MAX_VIEWS:
            raise SmartViewError("The smart view limit has been reached")
        name = _text(name, "Smart view name", MAX_NAME)
        clean_predicate = validate_predicate(predicate)
        clean_sort = validate_sort_keys(sort_keys)
        if any(value["name"].casefold() == name.casefold() for value in rows):
            raise SmartViewError("A smart view with that name already exists")
        now = int(time.time())
        view_id = str(uuid.uuid4())
        stale = self._stale_refs(clean_predicate, {
            value["id"] for value in payload.get("collections", []) if isinstance(value, Mapping) and "id" in value
        })
        rows.append({"id": view_id, "name": name, "predicate": clean_predicate, "sort_keys": clean_sort,
                     "pinned": bool(pinned), "created_at": now, "updated_at": now,
                     "schema_version": 1, "stale_references": stale, "disabled": bool(stale)})
        payload["updated_at"] = now
        self.session.save()
        return view_id

    save = create

    def rename(self, view_id: str, name: str) -> bool:
        payload = self._payload()
        row = next((value for value in self._rows(payload) if value.get("id") == view_id), None)
        if row is None:
            return False
        name = _text(name, "Smart view name", MAX_NAME)
        if any(value.get("id") != view_id and value.get("name", "").casefold() == name.casefold()
               for value in self._rows(payload)):
            raise SmartViewError("A smart view with that name already exists")
        row["name"] = name
        row["updated_at"] = int(time.time())
        payload["updated_at"] = row["updated_at"]
        self.session.save()
        return True

    def pin(self, view_id: str, pinned: bool = True) -> bool:
        payload = self._payload()
        row = next((value for value in self._rows(payload) if value.get("id") == view_id), None)
        if row is None:
            return False
        row["pinned"] = bool(pinned)
        row["updated_at"] = int(time.time())
        payload["updated_at"] = row["updated_at"]
        self.session.save()
        return True

    set_pinned = pin

    def delete(self, view_id: str) -> bool:
        payload = self._payload()
        rows = self._rows(payload)
        before = len(rows)
        rows[:] = [value for value in rows if value.get("id") != view_id]
        if len(rows) == before:
            return False
        payload["updated_at"] = int(time.time())
        self.session.save()
        return True

    remove = delete

    def repair(self, view_id: str, *, action: str = "disable") -> bool:
        payload = self._payload()
        row = next((value for value in self._rows(payload) if value.get("id") == view_id), None)
        if row is None:
            return False
        action = str(action).casefold()
        if action == "delete":
            return self.delete(view_id)
        if action not in {"disable", "enable"}:
            raise SmartViewError("Unknown smart view repair action")
        stale = self._stale_refs(row["predicate"], {
            value["id"] for value in payload.get("collections", []) if isinstance(value, Mapping) and "id" in value
        })
        if action == "enable" and stale:
            raise SmartViewStale("Smart view still has stale references")
        row["stale_references"] = stale
        row["disabled"] = action == "disable" or bool(stale)
        row["updated_at"] = int(time.time())
        payload["updated_at"] = row["updated_at"]
        self.session.save()
        return True

    def evaluate(self, view_id: str) -> list[dict[str, Any]]:
        definition = self.get(view_id)
        if definition is None:
            raise SmartViewError("Smart view was not found")
        if definition["disabled"] or definition["stale_references"]:
            return []
        rows = [row for row in _metadata_rows(self.session)
                if evaluate_predicate(definition["predicate"], row)]
        # Stable, deterministic sort with item ID as the final tie-breaker.
        # The final tie-breaker is always the stable item ID.  Stable sorting
        # from that base preserves deterministic order even when a descending
        # display key is selected.
        rows.sort(key=lambda row: str(row.get("id", "")))
        for sort_key in reversed(definition["sort_keys"]):
            field, direction = sort_key["field"], sort_key["direction"]
            rows.sort(key=lambda row, f=field: _sort_value(row, f),
                      reverse=direction == "desc")
        return [copy.deepcopy(row) for row in rows]

    run = evaluate


SavedViewService = SmartViewService


__all__ = [
    "ALLOWED_FIELDS", "ALLOWED_OPERATORS", "SmartViewDefinition", "SmartViewError", "SmartViewService",
    "SmartViewStale", "SavedViewService", "evaluate_predicate", "validate_predicate", "validate_sort_keys",
]
