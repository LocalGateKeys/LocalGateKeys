"""Travel mode: hide chosen collections and tags on this device only (feature pack 2026-11-15, section 2).

The setting lives in the vault's encrypted, never-synced preferences (``travel_mode``).  Hidden
items stay in the vault, keep syncing both ways and stay in encrypted backups; they are left out of
lists, search, fill, agents, the CLI, health checks, recently deleted and CSV/CXF exports.
"""
from __future__ import annotations

import re
import time
from collections.abc import Iterable, Mapping
from typing import Any

PREF_KEY = "travel_mode"
MAX_COLLECTIONS = 20
MAX_TAGS = 20
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
LOGIN_KINDS = frozenset({"web", "desktop"})


def fold(value: Any) -> str:
    return str(value).strip().casefold()


def _setting_parts(setting: Any) -> tuple[bool, set[str], set[str]]:
    if not isinstance(setting, Mapping) or setting.get("on") is not True:
        return False, set(), set()
    collections = setting.get("collections")
    tags = setting.get("tags")
    cols = {value for value in collections if isinstance(value, str)} if isinstance(collections, list) else set()
    folded = {fold(value) for value in tags if isinstance(value, str) and fold(value)} if isinstance(tags, list) else set()
    return True, cols, folded


def is_on(setting: Any) -> bool:
    return _setting_parts(setting)[0]


def hidden(record: Mapping[str, Any], setting: Any, *, collections: Iterable[str] | None = None) -> bool:
    """Contract 2.2: on && ((typed item && a collection is chosen) || a tag is chosen, compared folded)."""
    on, cols, tags = _setting_parts(setting)
    if not on:
        return False
    kind = record.get("kind")
    member_of = collections if collections is not None else record.get("collection_ids", record.get("collections"))
    if kind not in LOGIN_KINDS and isinstance(member_of, (list, tuple, set, frozenset)):
        if any(isinstance(value, str) and value in cols for value in member_of):
            return True
    record_tags = record.get("tags")
    if isinstance(record_tags, list) and tags:
        return any(isinstance(tag, str) and fold(tag) in tags for tag in record_tags)
    return False


def hidden_ids(items: Iterable[Mapping[str, Any]], setting: Any) -> list[str]:
    """Ids of hidden items, in input order.  ``items``: ``{id, kind, tags, collections}`` rows or records."""
    return [str(item.get("id")) for item in items if hidden(item, setting)]


def clean_setting(on: bool, collections: Iterable[Any], tags: Iterable[Any], *, since: int | None = None) -> dict[str, Any]:
    """The stored form; raises ``ValueError`` for more than 20 collections or tags or a malformed id."""
    from .item_schema import ItemSchemaError, normalize_tags

    cols: list[str] = []
    for value in collections:
        text = str(value).strip().lower()
        if not _UUID.fullmatch(text):
            raise ValueError("collection id is malformed")
        if text not in cols:
            cols.append(text)
    if len(cols) > MAX_COLLECTIONS:
        raise ValueError("too many collections")
    try:
        clean_tags = normalize_tags([str(value) for value in tags])
    except ItemSchemaError as exc:
        raise ValueError(str(exc)) from None
    if len(clean_tags) > MAX_TAGS:
        raise ValueError("too many tags")
    return {"on": bool(on), "collections": cols, "tags": clean_tags,
            "since": int(time.time()) if since is None else int(since)}


def setting_of(session: Any) -> dict[str, Any] | None:
    """The stored travel setting of an unlocked session, or ``None``.  Never raises."""
    try:
        value = session._read_prefs().get(PREF_KEY)
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def active_setting(session: Any) -> dict[str, Any] | None:
    value = setting_of(session)
    return value if is_on(value) else None


def hidden_id_set(session: Any) -> frozenset[str]:
    """Ids of the live logins and typed items hidden on this device right now (empty when off)."""
    setting = active_setting(session)
    if setting is None:
        return frozenset()
    try:
        payload = session._require_payload()
    except Exception:
        return frozenset()
    ids: set[str] = set()
    for key in ("entries", "items"):
        rows = payload.get(key)
        if isinstance(rows, list):
            ids.update(str(row.get("id")) for row in rows if isinstance(row, dict) and hidden(row, setting))
    trash = payload.get("trash")
    if isinstance(trash, list):
        for row in trash:
            entry = row.get("entry") if isinstance(row, dict) else None
            if isinstance(entry, dict) and hidden(entry, setting):
                ids.add(str(entry.get("id")))
    return frozenset(ids)


def hidden_collection_ids(session: Any) -> frozenset[str]:
    """Ids of the collections travel mode hides on this device right now (empty when off).  Never raises."""
    return frozenset(_setting_parts(active_setting(session))[1])


def visible_collections(session: Any, rows: Iterable[Any]) -> list[Any]:
    """``rows`` (collection dicts) without the ones travel mode hides: lists, pickers, the sidebar (contract 2.3)."""
    hidden_cols = hidden_collection_ids(session)
    return [row for row in rows
            if not (isinstance(row, Mapping) and str(row.get("id", "")).strip().lower() in hidden_cols)]


__all__ = ["PREF_KEY", "active_setting", "clean_setting", "fold", "hidden", "hidden_collection_ids", "hidden_id_set",
           "hidden_ids", "is_on", "setting_of", "visible_collections"]
