"""Clean-up sweep: duplicates, old and expired items, and confirmed merges (feature pack 2026-11-15, section 3).

Pure rules, no network.  Findings are computed on demand and never stored.  The caller passes only
the records the user can see (travel mode hides items from the sweep too).
"""
from __future__ import annotations

import copy
import re
from collections.abc import Iterable, Mapping
from typing import Any

from .updates import canonical_json

TYPES = ("same_login", "same_account_other_password", "same_site", "same_item", "not_changed_2y", "expired")
DUPLICATE_TYPES = frozenset(TYPES[:4])
TWO_YEARS = 730 * 86400
_EXPIRY_KINDS = {"license": "expiration_date", "purchase": "expiration_date", "warranty": "expiration_date",
                 "subscription": "expiration_date", "api_key": "expires"}
_PAYLOAD_IGNORED = ("notes", "template_id", "document_ids")
MAX_NOTES = 20_000
_LIST_CAPS = {"recovery_codes": 100, "custom_fields": 50}
MAX_URLS = 20
MAX_COLLECTIONS = 20


class MergeRefused(ValueError):
    """``code``: ``too_many_tags``, ``too_many_values``, ``notes_too_long`` or ``not_mergeable``."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def fold(value: Any) -> str:
    return str(value if value is not None else "").strip().casefold()


def _canon(value: Any) -> bytes:
    return canonical_json(value)


def _updated(record: Mapping[str, Any]) -> int:
    value = record.get("updated_at")
    return value if type(value) is int else 0


def _sorted_ids(records: Iterable[Mapping[str, Any]]) -> list[str]:
    return [str(r["id"]) for r in sorted(records, key=lambda r: (-_updated(r), str(r["id"])))]


def _origin(record: Mapping[str, Any]) -> str:
    scope = record.get("scope")
    value = scope.get("origin") if isinstance(scope, Mapping) else None
    return value if isinstance(value, str) else ""


def _base_domain(origin: str) -> str:
    from .origin import base_domain_of

    try:
        return base_domain_of(origin) or ""
    except Exception:
        return ""


def _passkey_key(payload: Any) -> tuple[str, str] | None:
    if not isinstance(payload, Mapping):
        return None
    rp_id = str(payload.get("relying_party_id", "") or "").strip().casefold()
    credential_id = str(payload.get("credential_id", "") or "")
    return (rp_id, credential_id) if rp_id and credential_id else None


def _groups(records: Iterable[Mapping[str, Any]], key: Any) -> list[list[Mapping[str, Any]]]:
    buckets: dict[Any, list[Mapping[str, Any]]] = {}
    for record in records:
        value = key(record)
        if value is not None:
            buckets.setdefault(value, []).append(record)
    return [rows for rows in buckets.values() if len(rows) > 1]


def _iso_day(text: Any) -> str | None:
    if not isinstance(text, str):
        return None
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text):
        return text
    if re.fullmatch(r"[0-9]{8}", text):
        return f"{text[:4]}-{text[4:6]}-{text[6:]}"
    return None


def is_expired(record: Mapping[str, Any], today: str) -> bool:
    kind = record.get("kind")
    payload = record.get("payload")
    if not isinstance(payload, Mapping):
        return False
    if kind == "card":
        match = re.fullmatch(r"([0-9]{1,2})/([0-9]{2}|[0-9]{4})", str(payload.get("expiry", "")).strip())
        if match is None:
            return False
        month, year = int(match.group(1)), match.group(2)
        year_n = int(year) if len(year) == 4 else 2000 + int(year)
        return (year_n, month) < (int(today[:4]), int(today[5:7]))
    field = _EXPIRY_KINDS.get(str(kind))
    if field is None:
        return False
    if kind == "subscription" and payload.get("active", True) is False:
        return False
    day = _iso_day(payload.get(field))
    return day is not None and day < today


def findings(records: Iterable[Mapping[str, Any]], now: int, today: str) -> list[dict[str, Any]]:
    """Every finding as ``{type, ids}``; types in ``TYPES`` order, groups of a type ordered by their ids."""
    rows = [r for r in records if isinstance(r, Mapping) and r.get("kind") != "desktop" and isinstance(r.get("id"), str)]
    logins = [r for r in rows if r.get("kind") == "web"]
    items = [r for r in rows if r.get("kind") not in ("web", "desktop")]
    out: dict[str, list[list[str]]] = {name: [] for name in TYPES}

    def account(r: Mapping[str, Any]) -> tuple[str, str]:
        return _origin(r), fold(r.get("username"))

    for group in _groups(logins, lambda r: (*account(r), str(r.get("password", "")))):
        out["same_login"].append(_sorted_ids(group))
    for group in _groups(logins, account):
        if len({str(r.get("password", "")) for r in group}) > 1:
            out["same_account_other_password"].append(_sorted_ids(group))

    def site(r: Mapping[str, Any]) -> tuple[str, str] | None:
        user = fold(r.get("username"))
        base = _base_domain(_origin(r))
        return (base, user) if user and base else None

    for group in _groups(logins, site):
        if len({_origin(r) for r in group}) > 1:
            out["same_site"].append(_sorted_ids(group))

    def item_key(r: Mapping[str, Any]) -> Any:
        kind = r.get("kind")
        payload = r.get("payload") if isinstance(r.get("payload"), Mapping) else {}
        if kind == "passkey":
            key = _passkey_key(payload)
            return ("passkey", *key) if key else None
        if kind == "card":
            number = str(payload.get("number", "") or "")
            return ("card", number) if number else None
        rest = {k: v for k, v in payload.items() if k not in _PAYLOAD_IGNORED}
        return ("item", str(kind), fold(r.get("title")), _canon(rest))

    for group in _groups(items, item_key):
        out["same_item"].append(_sorted_ids(group))

    old = [r for r in rows if type(r.get("updated_at")) is int and r["updated_at"] < int(now) - TWO_YEARS]
    if old:
        out["not_changed_2y"].append(_sorted_ids(old))
    expired = [r for r in items if is_expired(r, today)]
    if expired:
        out["expired"].append(_sorted_ids(expired))
    result = []
    for name in TYPES:
        for ids in sorted(out[name]):
            result.append({"type": name, "ids": ids})
    return result


def summary(found: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    """Counts for ``hygiene.summary``: distinct items in duplicate groups, old items, expired items."""
    dupes: set[str] = set()
    old = expired = 0
    for row in found:
        if row["type"] in DUPLICATE_TYPES:
            dupes.update(row["ids"])
        elif row["type"] == "not_changed_2y":
            old += len(row["ids"])
        elif row["type"] == "expired":
            expired += len(row["ids"])
    return {"dupes": len(dupes), "old": old, "expired": expired}


def _union(first: Any, second: Any, cap: int) -> list[Any]:
    out: list[Any] = []
    seen: set[bytes] = set()
    for value in [*(first if isinstance(first, list) else []), *(second if isinstance(second, list) else [])]:
        key = _canon(value)
        if key not in seen:
            seen.add(key)
            out.append(copy.deepcopy(value))
    if len(out) > cap:
        raise MergeRefused("too_many_values")
    return out


def _url_rows(record: Mapping[str, Any]) -> list[dict[str, str]]:
    """A web login's URL rows (``origin.entry_urls``): ``scope.urls``, else its legacy ``scope.origin``."""
    from .origin import entry_urls

    return [{"url": row["url"], "match": row["match"]} for row in entry_urls(record)]


def _merged_urls(keeper: Mapping[str, Any], other: Mapping[str, Any]) -> list[dict[str, str]]:
    """Keeper's rows then the other's, deduplicated by ``(url, match)`` (contract 3.2, 2026-11-15 revision)."""
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in [*_url_rows(keeper), *_url_rows(other)]:
        key = (row["url"], row["match"])
        if key not in seen:
            seen.add(key)
            out.append(row)
    if len(out) > MAX_URLS:
        raise MergeRefused("too_many_values")
    return out


def _tags(keeper: Mapping[str, Any], other: Mapping[str, Any]) -> list[str]:
    from .item_schema import ItemSchemaError, normalize_tags

    joined = [*(keeper.get("tags") or []), *(other.get("tags") or [])]
    try:
        return normalize_tags([str(t) for t in joined])
    except ItemSchemaError:
        raise MergeRefused("too_many_tags") from None


def _notes(mine: Any, theirs: Any) -> str:
    mine = mine if isinstance(mine, str) else ""
    theirs = theirs if isinstance(theirs, str) else ""
    if theirs and theirs != mine:
        mine = f"{mine}\n\n{theirs}" if mine else theirs
    if len(mine) > MAX_NOTES:
        raise MergeRefused("notes_too_long")
    return mine


def merge(keeper: Mapping[str, Any], other: Mapping[str, Any], now: int) -> dict[str, Any]:
    """The keeper after merging ``other`` into it (contract 3.2).  Raises ``MergeRefused``."""
    from .access_policy import ACCESS_SCOPE_KEY, stricter_access, stricter_policy
    from .vault import push_password_history

    result = copy.deepcopy(dict(keeper))
    login = keeper.get("kind") in ("web", "desktop")
    if login != (other.get("kind") in ("web", "desktop")) or (not login and keeper.get("kind") != other.get("kind")):
        raise MergeRefused("not_mergeable")
    if "tags" in keeper or "tags" in other:
        result["tags"] = _tags(keeper, other)
    if login:
        for name, cap in _LIST_CAPS.items():
            if name in keeper or name in other:
                result[name] = _union(keeper.get(name), other.get(name), cap)
        scope = result.get("scope") if isinstance(result.get("scope"), dict) else {}
        other_scope = other.get("scope") if isinstance(other.get("scope"), Mapping) else {}
        if keeper.get("kind") == "web":
            # The other login's addresses (its urls, or its legacy origin) are kept as rows; scope.origin stays the
            # keeper's. Nothing new → scope.urls is left exactly as the keeper had it.
            urls = _merged_urls(keeper, other)
            if urls != _url_rows(keeper):
                scope["urls"] = urls
        if "notes" in keeper or "notes" in other:
            result["notes"] = _notes(keeper.get("notes"), other.get("notes"))
        mine, theirs = keeper.get("password", ""), other.get("password", "")
        if isinstance(theirs, str) and theirs and theirs != mine:
            result["password_history"] = push_password_history(keeper.get("password_history"), theirs, int(now))
        if not keeper.get("totp") and other.get("totp"):
            result["totp"] = copy.deepcopy(other["totp"])
        access = stricter_access(scope.get(ACCESS_SCOPE_KEY), other_scope.get(ACCESS_SCOPE_KEY))
        if access is None:
            scope.pop(ACCESS_SCOPE_KEY, None)
        else:
            scope[ACCESS_SCOPE_KEY] = access
        result["scope"] = scope
        policy = stricter_policy(keeper.get("policy"), other.get("policy"))
        if policy is not None:
            result["policy"] = policy
    else:
        payload = result.get("payload") if isinstance(result.get("payload"), dict) else {}
        other_payload = other.get("payload") if isinstance(other.get("payload"), Mapping) else {}
        if "notes" in payload or "notes" in other_payload:
            payload["notes"] = _notes(payload.get("notes"), other_payload.get("notes"))
        result["payload"] = payload
        if "collection_ids" in keeper or "collection_ids" in other:
            ids = _union(keeper.get("collection_ids"), other.get("collection_ids"), MAX_COLLECTIONS)
            result["collection_ids"] = ids
    if "favorite" in keeper or "favorite" in other:
        result["favorite"] = keeper.get("favorite") is True or other.get("favorite") is True
    result["updated_at"] = int(now)
    return result


__all__ = ["DUPLICATE_TYPES", "MergeRefused", "TYPES", "findings", "is_expired", "merge", "summary"]
