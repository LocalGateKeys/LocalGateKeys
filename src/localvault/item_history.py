"""Device-local item history: retention, field diff and one-field restore (feature pack 2026-11-15, section 1).

History never syncs.  Each device snapshots the version it is about to replace.  This module holds
the pure rules shared with the iPhone, Mac and Android cores (``tests/vectors/history``) and the
Windows store for logins (``payload["entry_history"]``); typed items keep ``history.HistoryService``.
"""
from __future__ import annotations

import copy
import time
import uuid
from collections.abc import Iterable, Mapping
from typing import Any

from .updates import canonical_json

FREE_LIMITS = {"max_versions": 5, "max_age_days": 30, "max_bytes": 32 * 1024 * 1024}
PRO_LIMITS = {"max_versions": 30, "max_age_days": 365, "max_bytes": 32 * 1024 * 1024}
# The Windows vault caps its whole decrypted payload at 12 MiB (vault.MAX_VAULT_BYTES // 2), so the
# login history store on Windows is bounded well below the contract's 32 MiB.
WINDOWS_ENTRY_HISTORY_BYTES = 3 * 1024 * 1024
CHANGE_TYPES = frozenset({"update", "sync", "restore", "import", "merge"})
ENTRY_HISTORY_KEY = "entry_history"
MASK = "[protected]"

_LOCAL_TRUST_SCOPE_KEYS = (
    "sign_in_selector", "embedded_web_fill_approved", "browser_approval",
    "browser_approvals", "sync_pairing", "pairing_secret", "pairing_state",
)
IGNORED_PATHS = (
    "id", "created_at", "updated_at", "revision", "collection_ids", "password_history", "site_icon",
    "payload.document_ids", "policy.sign_in",
    *(f"scope.{name}" for name in _LOCAL_TRUST_SCOPE_KEYS),
)
_NOT_RESTORABLE = ("id", "kind", "created_at", "updated_at", "password_history")
_SECRET_PATHS: dict[str, tuple[str, ...]] = {
    "web": ("password", "totp", "recovery_codes", "custom_fields", "notes"),
    "desktop": ("password", "totp", "recovery_codes", "custom_fields", "notes"),
    "note": ("payload.body", "payload.fields"),
    "card": ("payload.number", "payload.cvv", "payload.pin"),
    "bank_account": ("payload.account_number", "payload.pin"),
    "license": ("payload.license_value", "payload.notes"),
    "ssh_key": ("payload.private_key", "payload.passphrase"),
    "api_key": ("payload.key", "payload.secret"),
    "wifi": ("payload.password",),
    "passkey": ("payload.private_key", "payload.user_handle"),
    "bookmark": ("payload.url", "payload.notes"),
    "purchase": ("payload.notes",),
    "warranty": ("payload.notes",),
    "subscription": ("payload.notes",),
}


class RestoreError(ValueError):
    """``code`` is ``not_restorable`` or ``invalid_on_this_device``."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def canon(value: Any) -> bytes:
    """``updates.canonical_json``; a lone surrogate (an old vault's odd text) is kept, never an error."""
    try:
        return canonical_json(value)
    except UnicodeEncodeError:
        import json

        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8", "surrogatepass")


def limits_for(pro: bool, *, max_bytes: int | None = None) -> dict[str, int]:
    limits = dict(PRO_LIMITS if pro else FREE_LIMITS)
    if max_bytes is not None:
        limits["max_bytes"] = max_bytes
    return limits


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + ".")


def ignored(path: str) -> bool:
    return any(_under(path, prefix) for prefix in IGNORED_PATHS)


def secret(kind: str, path: str) -> bool:
    if kind == "identity":
        return path.startswith("payload.") and not _under(path, "payload.template_id")
    return any(_under(path, prefix) for prefix in _SECRET_PATHS.get(kind, ()))


def prune(rows: Iterable[Mapping[str, Any]], now: int, limits: Mapping[str, int]) -> list[dict[str, Any]]:
    """Apply age cut, per-item cap, then the byte cap (contract 1.4).  Keeps input order."""
    kept = [dict(row) for row in rows]
    cutoff = int(now) - int(limits["max_age_days"]) * 86400
    kept = [row for row in kept if int(row["created_at"]) >= cutoff]
    by_item: dict[str, list[dict[str, Any]]] = {}
    for row in kept:
        by_item.setdefault(str(row["item_id"]), []).append(row)
    keep_ids: set[str] = set()
    for item_rows in by_item.values():
        ordered = sorted(item_rows, key=lambda r: (-int(r["created_at"]), str(r["snapshot_id"])))
        keep_ids.update(str(r["snapshot_id"]) for r in ordered[: int(limits["max_versions"])])
    kept = [row for row in kept if str(row["snapshot_id"]) in keep_ids]
    sizes = {str(row["snapshot_id"]): len(canon(row)) for row in kept}
    total = sum(sizes.values())
    oldest_first = sorted(kept, key=lambda r: (int(r["created_at"]), str(r["snapshot_id"])))
    dropped: set[str] = set()
    for row in oldest_first:
        if total <= int(limits["max_bytes"]):
            break
        dropped.add(str(row["snapshot_id"]))
        total -= sizes[str(row["snapshot_id"])]
    return [row for row in kept if str(row["snapshot_id"]) not in dropped]


def flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    """Objects recurse with dotted paths; a list is one field; scalars as is."""
    out: dict[str, Any] = {}
    if isinstance(value, Mapping):
        for key in value:
            child = f"{prefix}.{key}" if prefix else str(key)
            out.update(flatten(value[key], child))
    else:
        out[prefix] = copy.deepcopy(value)
    return out


def diff(before: Mapping[str, Any] | None, after: Mapping[str, Any] | None, kind: str, *,
         reveal: bool = False) -> list[dict[str, Any]]:
    """Changed fields between two versions, sorted by path (code-point order).

    Secret values are replaced by ``"[protected]"`` unless ``reveal``; a missing value stays ``null``.
    """
    left = flatten(before or {})
    right = flatten(after or {})
    rows = []
    for path in sorted(set(left) | set(right)):
        if ignored(path):
            continue
        old, new = left.get(path), right.get(path)
        if canon(old) == canon(new):
            continue
        hidden = secret(kind, path)
        if hidden and not reveal:
            old = None if old is None else MASK
            new = None if new is None else MASK
        rows.append({"field": path, "before": old, "after": new, "secret": hidden})
    return rows


def _lookup(record: Mapping[str, Any], parts: list[str]) -> tuple[bool, Any]:
    node: Any = record
    for part in parts:
        if not isinstance(node, Mapping) or part not in node:
            return False, None
        node = node[part]
    return True, node


def restorable(path: str) -> bool:
    return bool(path) and not any(_under(path, name) for name in _NOT_RESTORABLE) and not ignored(path)


def apply_field(current: Mapping[str, Any], snapshot: Mapping[str, Any], path: str, now: int,
                *, push_password_history: Any = None) -> dict[str, Any]:
    """The record after restoring ``path`` from ``snapshot`` (no normaliser; see ``restore_field``)."""
    if not isinstance(path, str) or not restorable(path):
        raise RestoreError("not_restorable")
    parts = path.split(".")
    result = copy.deepcopy(dict(current))
    present, value = _lookup(snapshot, parts)
    node: Any = result
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            if not present:
                node = None
                break
            child = {}
            node[part] = child
        node = child
    if node is not None:
        if present:
            node[parts[-1]] = copy.deepcopy(value)
        else:
            node.pop(parts[-1], None)
    if path == "password" and push_password_history is not None:
        previous = current.get("password")
        if isinstance(previous, str) and previous and previous != result.get("password"):
            result["password_history"] = push_password_history(current.get("password_history"), previous, int(now))
    result["updated_at"] = int(now)
    return result


def restore_field(current: Mapping[str, Any], snapshot: Mapping[str, Any], path: str, now: int) -> dict[str, Any]:
    """Restore one field; the result passes this device's sync normaliser or ``invalid_on_this_device``."""
    from .item_schema import ItemSchemaError
    from .origin import OriginError
    from .sync.vault_bridge import normal_form
    from .totp import TotpError
    from .vault import VaultError, push_password_history

    result = apply_field(current, snapshot, path, now, push_password_history=push_password_history)
    ns = "entry" if result.get("kind") in ("web", "desktop") else "item"
    try:
        normal_form(ns, result)
    except (VaultError, ItemSchemaError, TotpError, OriginError, ValueError, TypeError, KeyError):
        raise RestoreError("invalid_on_this_device") from None
    return result


def strip_for_row(record: Mapping[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(dict(record))
    out.pop("site_icon", None)
    return out


def make_row(record: Mapping[str, Any], *, ns: str, change_type: str, now: int | None = None) -> dict[str, Any]:
    if change_type not in CHANGE_TYPES:
        change_type = "update"
    return {
        "snapshot_id": str(uuid.uuid4()),
        "item_id": str(record.get("id")),
        "ns": ns,
        "created_at": int(time.time()) if now is None else int(now),
        "change_type": change_type,
        "record": strip_for_row(record),
    }


def comparable(record: Mapping[str, Any]) -> bytes:
    """Canonical bytes of a login minus local-only fields, to tell real edits from local-only changes."""
    rec = copy.deepcopy(dict(record))
    rec.pop("site_icon", None)
    scope = rec.get("scope")
    if isinstance(scope, dict):
        for name in _LOCAL_TRUST_SCOPE_KEYS:
            scope.pop(name, None)
    policy = rec.get("policy")
    if isinstance(policy, dict):
        policy.pop("sign_in", None)
    return canon(rec)


def valid_row(row: Any) -> bool:
    return (isinstance(row, dict) and isinstance(row.get("snapshot_id"), str) and len(row["snapshot_id"]) <= 64
            and isinstance(row.get("item_id"), str) and len(row["item_id"]) <= 128
            and type(row.get("created_at")) is int and row["created_at"] >= 0
            and row.get("change_type") in CHANGE_TYPES and isinstance(row.get("record"), dict))


__all__ = [
    "CHANGE_TYPES", "ENTRY_HISTORY_KEY", "FREE_LIMITS", "MASK", "PRO_LIMITS", "RestoreError",
    "WINDOWS_ENTRY_HISTORY_BYTES", "apply_field", "comparable", "diff", "flatten", "ignored", "limits_for",
    "make_row", "prune", "restorable", "restore_field", "secret", "strip_for_row", "valid_row",
]
