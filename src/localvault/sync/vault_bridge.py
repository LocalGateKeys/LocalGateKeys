"""Bridge between the vault payload and the pure version-vector merge engine.

``local_view`` turns the unlocked vault into engine ``ItemState`` values and
``apply`` writes a ``MergeOutcome`` back.  Both refuse to run unless the
caller's lease is still valid, and every write happens in one
``session.transaction()`` so a failure leaves the vault untouched.

What syncs
----------
* Website and desktop logins (``payload["entries"]``) as namespace ``"entry"``
  and typed items (``payload["items"]``) as namespace ``"item"``.  The engine
  sees ``{"ns": ..., "updated_at": int, "record": <record minus local-only
  fields>}``; ``updated_at`` mirrors the record's (int in 0..2**53-1, else 0)
  so the engine's newest-edit rule ranks concurrent edits.  The state id is
  the record id, and the same id in both lists (live or trashed) is an error.
* Credentials are validated against what the vault's own writers can
  produce: an allowlist of top-level fields, the vault's credential
  validator, and the writers' types and bounds (tags 20 x 40, notes 20000,
  recovery codes 100 x 512, password history 5 rows, custom fields 50 and
  TOTP as small dicts of JSON scalars, the desktop binding's typed keys;
  other scope keys are kept).  A remote record that fails is rejected with
  ``BridgeError``.  A local record that fails is skipped
  (``LocalView.skipped`` / ``ApplyReport.skipped``): no state, meta untouched,
  never overwritten, and every other record still syncs.
* Typed ``document`` items do not sync in v1 (they are attachment-backed and
  attachments are out of scope); they are invisible to sync.
* The Pro licence as namespace ``"license"``: ``{"ns": "license", "schema": 1,
  "updated_at": 0, "record": <signed bundle>}`` under the state id
  ``licensing.sync_state_id(license_id)``.  Published: the vault's licence copy
  and ``payload["sync_licenses"]`` (state id -> bundle, received licences,
  at most ``MAX_SYNC_LICENSES``), each only while it verifies and is not
  revoked, and none at all while ``licensing.removal_pending()``.  A received licence must verify and hash to its state id (else
  ``bad-remote``); it is stored in ``sync_licenses``, never in entries or
  items, and listed in ``ApplyReport.licenses``.  Licences are only added: a
  tombstone never deletes one (a published one is republished above it), the
  same id with other bytes is ``bad-remote`` (the vault copy wins at publish;
  an engine conflict copy of a licence is dropped without a word), an
  unpublished one is never tombstoned, and a revoked licence (or any licence in
  a build without licence keys) is dropped without a write.  A licence signed
  with a well-formed but unknown key id or an unknown algorithm, or correctly
  signed in a newer format, is ``update-needed``; a malformed key id is ``bad-remote``.
* Both lists share the vault's trash (``payload["trash"]``, records
  ``{"entry": record, "deleted_at": int}``).  A trashed or purged record is a
  local delete; remote deletes move records to that trash and never purge.

Local-only fields (never synced, kept per device)
-------------------------------------------------
* Items: ``revision`` (a per-device edit counter used for optimistic edit
  checks and history snapshots), ``collection_ids`` (collections do not sync
  in v1) and ``payload.document_ids`` (links to document items, which do not
  sync; syncing them would leave dangling links that block later edits).
* Entries: ``site_icon`` - display metadata written in the background by the
  icon fetcher/browser capture without touching ``updated_at``.  Syncing it
  would turn every icon fetch into an edit that conflicts with real password
  edits on other devices.
* Entries, per-device trust (the same keys ``transfer`` never exports,
  ``transfer.LOCAL_TRUST_SCOPE_KEYS``): ``scope.sign_in_selector``,
  ``scope.embedded_web_fill_approved``, ``scope.browser_approval(s)``,
  ``scope.sync_pairing``, ``scope.pairing_secret``, ``scope.pairing_state``
  and ``policy.sign_in``.  An approval given on one PC never applies on
  another.  On apply each device keeps its own values from the live or
  trashed record; new records get ``embedded_web_fill_approved = False``
  (desktop) and ``sign_in = "never"``.
* Every other entry field is user-authored and syncs: the rest of ``scope``
  (the desktop binding), ``policy`` fill/master-password/save-prompt choices,
  ``tags``, ``notes``, ``totp``, ``recovery_codes``, ``custom_fields`` and
  ``password_history``.  Entries carry no usage counters or last-used stamps.
* A local-only change that also moves ``updated_at`` (a collection move, a
  trust approval) is not a sync edit: when nothing else in the synced content
  changed, the view keeps the last synced ``updated_at`` (meta ``body`` /
  ``updated_at``).

Change detection
----------------
``payload["sync_meta"] = {"device_id": str, "items": {id: {"digest", "body",
"updated_at", "vv", "deleted", "deleted_at"}}}`` records, per id, the sha256 of
the canonical JSON of the synced wrapper (``body``: the same without
``updated_at``; ``updated_at``: the published stamp) and its version vector.
Remote tombstones store ``min(deleted_at, now)``; tombstones older than
``TOMBSTONE_MAX_AGE_DAYS`` come from stale devices and are ignored.  A full
trash or history raises ``BridgeError`` with ``reason`` ``"trash-full"`` or
``"history-quota"``.  A live record whose digest
differs from its meta (or that has no meta) is a local edit: ``vv =
engine.bump(vv, device_id)``.  A record in meta that is no longer live becomes
a tombstone with a bumped vector.  After ``apply`` each touched id's meta holds
the digest of the stored content and the merged vector, so the next
``local_view`` does not re-attribute the change to this device.  Stored content
is always the vault-normalized form; if normalization changes an incoming
record, the result is recorded as a local edit (bumped vector) so the
normalized form wins everywhere instead of flapping between devices.

``payload["sync_group"]`` holds the device's sync group membership
(``SyncGroupState``): group key and epoch, the device identity's private keys,
last-seen counters per peer, folder path, LAN peers and install id.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import copy
import hashlib
import json
import logging
import math
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from .. import licensing
from ..access_policy import normalized_policy
from ..history import HistoryError, HistoryQuotaError
from ..item_schema import MAX_ITEMS, MAX_TITLE, ItemSchemaError, validate_item, validate_web_urls
from ..origin import OriginError
from ..session_guard import StaleSession
from ..totp import _DIGITS as TOTP_DIGITS
from ..totp import _PERIOD_RANGE as TOTP_PERIOD_RANGE
from ..totp import TotpError
from ..transfer import LOCAL_TRUST_SCOPE_KEYS
from ..updates import canonical_json
from ..vault import (
    LEGACY_FORMAT_VERSION,
    VaultError,
    VaultLockedError,
    _validate_legacy_payload,
    _validated_sha256,
    _validated_text,
    stored_license_ok,
)
from .engine import EngineError, ItemState, MergeOutcome, bump, is_valid_id
from .pairing import DeviceIdentity, PairingError

_log = logging.getLogger(__name__)

MAX_SYNC_RECORDS = 20_000
#: Format number carried by every synced item wrapper; a larger one needs a newer app.
ITEM_WRAPPER_SCHEMA = 1
TOMBSTONE_MAX_AGE_DAYS = 365
CONFLICT_SUFFIX = " (sync conflict)"
LOCAL_ONLY_ITEM_FIELDS = ("revision", "collection_ids")
LOCAL_ONLY_ITEM_PAYLOAD_FIELDS = ("document_ids",)
LOCAL_ONLY_ENTRY_FIELDS = ("site_icon",)
LOCAL_ONLY_ENTRY_SCOPE_FIELDS = LOCAL_TRUST_SCOPE_KEYS
LOCAL_ONLY_ENTRY_POLICY_FIELDS = ("sign_in",)
ENTRY_FIELDS = frozenset({
    "id", "kind", "label", "username", "password", "scope", "created_at", "updated_at",
    "favorite", "tags", "notes", "totp", "recovery_codes", "custom_fields", "policy",
    "password_history", "site_icon",
})
_DESKTOP_BINDING_MODES = frozenset({"strict", "embedded_web_volatile", "dynamic_layout", "discord_stable"})
# Bounds of the vault's own credential writers: set_details (tags 20 x 40,
# recovery codes 100 x 512, custom fields 50, notes 20000), set_entry_extras
# (totp and custom-field dicts stored as given, custom fields cut to 50) and
# upsert_web/_apply_entry_fields (password history cut to 5).
_MAX_ENTRY_TAGS = 20
_MAX_RECOVERY_CODES = 100
_MAX_CUSTOM_FIELDS = 50
_MAX_PASSWORD_HISTORY = 5
_MAX_SMALL_DICT_KEYS = 16
_MAX_SCALAR_TEXT = 4096
_MAX_ENTRY_BYTES = 512 * 1024
# vault._validate_next_release_state rejects a catalog with more history rows.
_MAX_SAVED_HISTORY_ROWS = 20_000
UNSYNCED_ITEM_KINDS = frozenset({"document"})
ENTRY_KINDS = frozenset({"web", "desktop"})
# The credential validator's label bound (vault._validate_legacy_payload).
_MAX_ENTRY_LABEL = 512
_MAX_INT53 = 2**53 - 1
_MAX_INT63 = 2**63 - 1
_META_KEYS = frozenset({"digest", "body", "updated_at", "vv", "deleted", "deleted_at"})
#: Namespace and id prefix of licence states; no entry or item may use the prefix.
LICENSE_NS = "license"
LICENSE_ID_PREFIX = "lic:"
#: Most licences ``payload["sync_licenses"]`` keeps.
MAX_SYNC_LICENSES = 16


class BridgeError(VaultError):
    """Sync data could not be read from or applied to the vault.

    ``reason`` is a stable code, else None: ``"trash-full"`` and
    ``"history-quota"`` (the user can fix them), ``"history-error"``,
    ``"vault-changed"`` (``apply``
    refused because a record changed locally after the view was taken; take a
    fresh view and retry) and ``"bad-remote"`` (``apply`` rejected the remote
    state named by ``item_id``).
    """

    def __init__(self, message: str, *, reason: str | None = None, item_id: str | None = None) -> None:
        super().__init__(f"{reason}: {message}" if reason else message)
        self.reason = reason
        self.item_id = item_id


@dataclass(frozen=True)
class ApplyReport:
    """``skipped``: (id, reason) of local records that cannot be read for sync;
    outcome entries for them were dropped instead of overwriting them."""

    applied: int
    deleted: int
    conflicts: int
    skipped: tuple[tuple[str, str], ...] = ()
    #: Licence bundles received in this apply that verified (stored or already known).
    licenses: tuple[dict[str, Any], ...] = ()


class LocalView(dict):
    """``local_view`` result: id -> ItemState, plus ``skipped`` {id: reason}.

    A skipped record is a live local record that fails validation.  It gets
    no state (so it is never published as deleted) and its meta is untouched.
    """

    def __init__(self, states: Mapping[str, ItemState] = (), skipped: Mapping[str, str] | None = None) -> None:
        super().__init__(states)
        self.skipped: dict[str, str] = dict(skipped or {})


# --- helpers -----------------------------------------------------------------------------


def _check_lease(session: Any, lease: Any) -> None:
    """Raise unless the vault is unlocked and *lease* is still valid.

    *lease* is an object with a ``check()`` method, or a zero-argument
    callable, that raises when the unlock session it was issued for has ended.
    """
    if not getattr(session, "is_unlocked", False):
        raise VaultLockedError("Vault is locked")
    check: Callable[[], Any] | None = getattr(lease, "check", None)
    if check is None and callable(lease):
        check = lease
    if check is None:
        raise BridgeError("A sync lease is required")
    check()


def _check_now(now: Any) -> int:
    if isinstance(now, bool) or not isinstance(now, int) or not 0 <= now <= _MAX_INT53:
        raise BridgeError("Sync clock value is malformed")
    return now


def _check_device(device_id: Any) -> str:
    try:
        bump({}, device_id)
    except EngineError as exc:
        raise BridgeError(f"Sync device id is malformed: {exc}") from None
    return device_id


def wrapper_digest(wrapper: Mapping[str, Any]) -> str:
    """sha256 hex of the canonical JSON of a synced wrapper."""
    return hashlib.sha256(canonical_json(wrapper)).hexdigest()


def _int_field(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_INT63:
        raise VaultError(f"Credential {name} is malformed")
    return value


def _scalar(value: Any, name: str) -> None:
    """A JSON scalar within bounds (what set_entry_extras can store)."""
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -_MAX_INT63 <= value <= _MAX_INT63:
            raise VaultError(f"{name} is out of range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise VaultError(f"{name} is malformed")
        return
    if isinstance(value, str):
        _validated_text(value, name, _MAX_SCALAR_TEXT, allow_empty=True)
        return
    raise VaultError(f"{name} is malformed")


def _scalar_dict(value: Any, name: str) -> None:
    if not isinstance(value, dict) or len(value) > _MAX_SMALL_DICT_KEYS:
        raise VaultError(f"{name} is malformed")
    for key, item in value.items():
        _validated_text(key, f"{name} key", 100, allow_empty=False)
        _scalar(item, name)


def _check_totp_fields(totp: Mapping[str, Any]) -> None:
    """Type the TOTP keys the app reads (as set_details writes them); extra scalar keys pass.

    Export and the login editor call ``int()`` on digits/period, so a text or
    None value there would crash them.
    """
    for name in ("secret", "algorithm"):
        if name in totp and not isinstance(totp[name], str):
            raise VaultError(f"TOTP {name} must be text")
    if "digits" in totp and (type(totp["digits"]) is not int or totp["digits"] not in TOTP_DIGITS):
        raise VaultError("TOTP digits are unsupported")
    if "period" in totp and (type(totp["period"]) is not int
                             or not TOTP_PERIOD_RANGE[0] <= totp["period"] <= TOTP_PERIOD_RANGE[1]):
        raise VaultError("TOTP period is unsupported")


def _canonical_scope(kind: str, scope: dict[str, Any]) -> None:
    """Validate a credential scope in place with the vault's binding validators.

    Keys beyond the ones checked here are kept (the vault's writers preserve
    other scope keys); their size is covered by the record bound.
    """
    for key in scope:
        if not isinstance(key, str):
            raise VaultError("Credential scope keys must be text")
    if kind == "web":
        if "urls" in scope:
            scope["urls"] = validate_web_urls(scope["urls"])
        return
    _validated_text(scope.get("exe_path"), "exe_path", 32768, allow_empty=False)
    scope["exe_sha256"] = _validated_sha256(scope.get("exe_sha256"))
    _validated_text(scope.get("window_title"), "window_title", 1024, allow_empty=False)
    fingerprint = scope.get("control_fingerprint")
    if not isinstance(fingerprint, list) or not fingerprint or not all(isinstance(v, dict) for v in fingerprint):
        raise VaultError("control_fingerprint is malformed")
    for name in ("username_selector", "password_selector", "signer"):
        if scope.get(name) is not None and not isinstance(scope[name], dict):
            raise VaultError(f"{name} is malformed")
    if scope.get("binding_mode", "strict") not in _DESKTOP_BINDING_MODES:
        raise VaultError("Unsupported desktop binding mode")
    if "embedded_web_fill_approved" in scope and type(scope["embedded_web_fill_approved"]) is not bool:
        raise VaultError("embedded_web_fill_approved is malformed")


def _canonical_entry(record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one credential strictly and return its canonical stored form.

    Runs the vault's credential validator (text bounds, canonical origin,
    normalized policy) plus the bounds the vault's own setters enforce, and
    rejects fields no setter writes.  Raises VaultError, ItemSchemaError or
    TotpError.
    """
    rec = copy.deepcopy(dict(record))
    unknown = set(rec) - ENTRY_FIELDS
    if unknown:
        raise VaultError(f"Credential contains unsupported fields: {sorted(unknown)}")
    # Strict: a stored origin the current rules refuse is tolerated only inside
    # its own vault (never filled); it is not synced to other devices.
    _validate_legacy_payload({"version": LEGACY_FORMAT_VERSION, "entries": [rec], "trash": []},
                             strict_origins=True)
    for name in ("created_at", "updated_at"):
        if name in rec:
            _int_field(rec[name], name)
    if "favorite" in rec and type(rec["favorite"]) is not bool:
        raise VaultError("Credential favorite is malformed")
    tags = rec.get("tags", [])
    if not isinstance(tags, list) or len(tags) > _MAX_ENTRY_TAGS:
        raise VaultError("Credential tags are malformed")
    for tag in tags:
        _validated_text(tag, "tag", 40, allow_empty=False)
    if "notes" in rec:
        _validated_text(rec["notes"], "notes", 20000, allow_empty=True)
    codes = rec.get("recovery_codes", [])
    if not isinstance(codes, list) or len(codes) > _MAX_RECOVERY_CODES:
        raise VaultError("Credential recovery codes are malformed")
    for code in codes:
        _validated_text(code, "recovery code", 512, allow_empty=False)
    fields = rec.get("custom_fields", [])
    if not isinstance(fields, list) or len(fields) > _MAX_CUSTOM_FIELDS:
        raise VaultError("Custom fields are malformed")
    for row in fields:
        _scalar_dict(row, "custom field")
    totp = rec.get("totp")
    if totp is not None:
        _scalar_dict(totp, "TOTP")
        _check_totp_fields(totp)
    history = rec.get("password_history", [])
    if not isinstance(history, list) or len(history) > _MAX_PASSWORD_HISTORY:
        raise VaultError("Password history is malformed")
    canonical_history = []
    for row in history:
        if not isinstance(row, dict) or set(row) - {"password", "changed_at", "replaced_at"}:
            raise VaultError("Password history is malformed")
        changed = row.get("changed_at", row.get("replaced_at"))  # older builds wrote replaced_at
        canonical_history.append({
            "password": _validated_text(row.get("password"), "password", 4096, allow_empty=True),
            "changed_at": _int_field(changed, "password history time"),
        })
    if "password_history" in rec:
        rec["password_history"] = canonical_history
    if "site_icon" in rec and not isinstance(rec["site_icon"], str):
        raise VaultError("Credential icon is malformed")
    _canonical_scope(rec["kind"], rec["scope"])
    try:
        size = len(canonical_json(rec))
    except (TypeError, ValueError, RecursionError):
        raise VaultError("Credential holds unsupported values") from None
    if size > _MAX_ENTRY_BYTES:
        raise VaultError("Credential is too large")
    return rec


def _strip_entry_local(rec: dict[str, Any]) -> None:
    for name in LOCAL_ONLY_ENTRY_FIELDS:
        rec.pop(name, None)
    for container, names in (("scope", LOCAL_ONLY_ENTRY_SCOPE_FIELDS),
                             ("policy", LOCAL_ONLY_ENTRY_POLICY_FIELDS)):
        value = rec.get(container)
        if isinstance(value, dict):
            for name in names:
                value.pop(name, None)


def _rank_updated_at(record: Mapping[str, Any]) -> int:
    """The engine's newest-edit rank value: the record's updated_at, else 0."""
    value = record.get("updated_at", 0)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_INT53:
        return 0
    return value


def normal_form(ns: str, record: Mapping[str, Any]) -> dict[str, Any]:
    """Normalized record minus local-only fields."""
    if ns == "entry":
        rec = _canonical_entry(record)
        _strip_entry_local(rec)
        return rec
    rec = validate_item(copy.deepcopy(dict(record)))
    for name in LOCAL_ONLY_ITEM_FIELDS:
        rec.pop(name, None)
    for name in LOCAL_ONLY_ITEM_PAYLOAD_FIELDS:
        rec["payload"].pop(name, None)
    return rec


def _wrapper(ns: str, record: Mapping[str, Any]) -> dict[str, Any]:
    try:
        rec = normal_form(ns, record)
    except (VaultError, ItemSchemaError, TotpError, OriginError) as exc:
        raise BridgeError(f"Vault record {record.get('id')!r} is malformed: {exc}") from None
    return {"ns": ns, "schema": ITEM_WRAPPER_SCHEMA, "updated_at": _rank_updated_at(rec), "record": rec}


def _ns_of(record: Any) -> str:
    return "entry" if isinstance(record, dict) and record.get("kind") in ENTRY_KINDS else "item"


def _live_records(payload: Mapping[str, Any]) -> dict[str, tuple[str, dict[str, Any]]]:
    """id -> (namespace, stored record) for every live synced record."""
    out: dict[str, tuple[str, dict[str, Any]]] = {}
    for ns, key in (("entry", "entries"), ("item", "items")):
        rows = payload.get(key, [])
        if not isinstance(rows, list):
            raise BridgeError(f"Vault {key} are malformed")
        for record in rows:
            if not isinstance(record, dict) or not isinstance(record.get("id"), str):
                raise BridgeError(f"Vault {key} are malformed")
            if ns == "item" and record.get("kind") in UNSYNCED_ITEM_KINDS:
                continue
            if record["id"] in out:
                raise BridgeError(f"Record id {record['id']!r} appears more than once in the vault")
            out[record["id"]] = (ns, record)
    if len(out) > MAX_SYNC_RECORDS:
        raise BridgeError("The vault holds more records than sync supports")
    return out


def _trash_index(payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in payload.get("trash", []):
        entry = row.get("entry") if isinstance(row, dict) else None
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            out.setdefault(entry["id"], row)
    return out


def _body_digest(wrapper: Mapping[str, Any]) -> str:
    """Digest of a wrapper without its updated_at stamps."""
    record = {k: v for k, v in wrapper["record"].items() if k != "updated_at"}
    return wrapper_digest({"ns": wrapper["ns"], "record": record})


def _live_meta(wrapper: Mapping[str, Any], vv: Mapping[str, int]) -> dict[str, Any]:
    return {"digest": wrapper_digest(wrapper), "body": _body_digest(wrapper),
            "updated_at": wrapper["record"].get("updated_at"),
            "vv": dict(vv), "deleted": False, "deleted_at": None}


def _tomb_meta(vv: Mapping[str, int], deleted_at: int) -> dict[str, Any]:
    return {"digest": None, "body": None, "updated_at": None, "vv": dict(vv),
            "deleted": True, "deleted_at": deleted_at}


def _view_wrapper(ns: str, record: Mapping[str, Any], m: Mapping[str, Any] | None) -> dict[str, Any]:
    """Synced wrapper of a live record as this device last published it.

    Local-only changes (moving an item into a collection) also move the
    record's ``updated_at``.  When nothing else in the synced content changed,
    the last synced ``updated_at`` is kept so the change is not a sync edit.
    """
    wrapper = _wrapper(ns, record)
    if m is None or m["deleted"] or wrapper["record"].get("updated_at") == m["updated_at"]:
        return wrapper
    if _body_digest(wrapper) != m["body"]:
        return wrapper
    if m["updated_at"] is None:
        wrapper["record"].pop("updated_at", None)
    else:
        wrapper["record"]["updated_at"] = m["updated_at"]
    wrapper["updated_at"] = _rank_updated_at(wrapper["record"])
    return wrapper


def _load_meta(payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Validated deep copy of ``sync_meta["items"]``; fail closed on anything odd."""
    raw = payload.get("sync_meta")
    if raw is None:
        return {}
    if not (isinstance(raw, dict) and isinstance(raw.get("items"), dict)
            and isinstance(raw.get("device_id"), str)):
        raise BridgeError("Sync metadata is malformed")
    items = raw["items"]
    if len(items) > MAX_SYNC_RECORDS:
        raise BridgeError("Sync metadata exceeds its bound")
    out: dict[str, dict[str, Any]] = {}
    for item_id, meta in items.items():
        if not isinstance(meta, dict) or set(meta) != _META_KEYS:
            raise BridgeError("Sync metadata is malformed")
        deleted, digest, body, stamp = meta["deleted"], meta["digest"], meta["body"], meta["updated_at"]
        try:
            # ItemState enforces the engine's id, vector and deleted_at rules.
            ItemState(item_id, meta["vv"], deleted, meta["deleted_at"], None if deleted is True else {})
        except EngineError as exc:
            raise BridgeError(f"Sync metadata is malformed: {exc}") from None
        if deleted:
            if digest is not None or body is not None or stamp is not None or meta["deleted_at"] is None:
                raise BridgeError("Sync metadata is malformed")
        elif (not isinstance(digest, str) or len(digest) != 64 or not isinstance(body, str)
              or len(body) != 64 or meta["deleted_at"] is not None
              or not (stamp is None or (type(stamp) is int and 0 <= stamp <= _MAX_INT63))):
            raise BridgeError("Sync metadata is malformed")
        out[item_id] = copy.deepcopy(meta)
    return out


def prune_tombstones(meta: Mapping[str, Mapping[str, Any]], now: int,
                     max_age_days: int = TOMBSTONE_MAX_AGE_DAYS) -> dict[str, dict[str, Any]]:
    """Copy of *meta* without tombstones deleted more than *max_age_days* ago."""
    cutoff = now - max_age_days * 86400
    return {item_id: copy.deepcopy(dict(m)) for item_id, m in meta.items()
            if not (m.get("deleted") and isinstance(m.get("deleted_at"), int) and m["deleted_at"] < cutoff)}


def _store_meta(payload: dict[str, Any], device_id: str, meta: dict[str, dict[str, Any]]) -> None:
    if len(meta) > MAX_SYNC_RECORDS:
        raise BridgeError("Sync metadata exceeds its bound")
    payload["sync_meta"] = {"device_id": device_id, "items": dict(sorted(meta.items()))}


# --- licence states ----------------------------------------------------------------------


def _is_license_id(item_id: Any) -> bool:
    return isinstance(item_id, str) and item_id.startswith(LICENSE_ID_PREFIX)


def _license_wrapper(bundle: Mapping[str, Any]) -> dict[str, Any]:
    return {"ns": LICENSE_NS, "schema": ITEM_WRAPPER_SCHEMA, "updated_at": 0,
            "record": copy.deepcopy(dict(bundle))}


def _verified_license(bundle: Any) -> licensing.License | None:
    """The licence a stored bundle carries when it verifies and is not revoked, else None."""
    try:
        lic = licensing.verify_bundle(bundle)
    except licensing.LicenseError:
        return None
    return None if lic.license_id in licensing._cached_revoked_ids() else lic


def _stored_licenses(payload: Mapping[str, Any]) -> dict[str, Any]:
    stored = payload.get("sync_licenses")
    return stored if isinstance(stored, dict) else {}


def _published_licenses(payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """state id -> wrapper of every licence this device publishes.

    The vault's own licence copy and the licences received by sync
    (``payload["sync_licenses"]``), each only while it verifies and is not
    revoked.  The vault copy wins over a received licence at the same id.
    Nothing while ``licensing.removal_pending()``.
    """
    if not licensing.LICENSE_KEYS or licensing.removal_pending():
        # While a removal is pending this PC publishes no licence at all, received ones included.
        return {}
    out: dict[str, dict[str, Any]] = {}
    candidates: list[tuple[str | None, Any]] = []
    copy_bundle = payload.get("license")
    if isinstance(copy_bundle, dict):
        candidates.append((None, copy_bundle))
    candidates.extend((sid, bundle) for sid, bundle in _stored_licenses(payload).items())
    for key, bundle in candidates:
        lic = _verified_license(bundle)
        if lic is None:
            continue
        sid = licensing.sync_state_id(lic.license_id)
        if key is not None and key != sid:
            continue
        try:
            out.setdefault(sid, _license_wrapper(_json_copy(bundle)))
        except (TypeError, ValueError):
            continue
    return out


def published_licenses(session: Any) -> tuple[dict[str, Any], ...]:
    """The licence bundles this vault publishes (vault copy and received ones), sorted by state id."""
    published = _published_licenses(session._require_typed_catalog())
    return tuple(published[sid]["record"] for sid in sorted(published))


def _json_copy(value: Any) -> Any:
    """A plain-JSON deep copy of *value* (canonical round trip)."""
    return json.loads(canonical_json(value))


# --- local_view --------------------------------------------------------------------------

#: ``LocalView.skipped`` reason of an item whose stored vector cannot be bumped (audit M-6).
COUNTER_OVERFLOW = "version counter overflow"


def _bumped(vv: Mapping[str, int], device_id: str) -> dict[str, int] | None:
    """``bump(vv, device_id)``, or None when this device's counter would overflow."""
    if vv.get(device_id, 0) >= _MAX_INT53:
        return None
    return bump(vv, device_id)


def local_view(session: Any, lease: Any, *, device_id: str, now: int) -> LocalView:
    """Engine states for every synced record and tombstone; persists changed meta.

    A live record that fails validation is skipped (``result.skipped``): it
    gets no state and its meta is left alone, so it is never turned into a
    tombstone and every other record still syncs.
    """
    _check_lease(session, lease)
    _check_device(device_id)
    _check_now(now)
    payload = session._require_typed_catalog()
    stored_meta = _load_meta(payload)
    meta = prune_tombstones(stored_meta, now)
    states: dict[str, ItemState] = {}
    skipped: dict[str, str] = {}
    live = _live_records(payload)
    licenses = _published_licenses(payload)
    try:
        for item_id, (ns, record) in live.items():
            m = meta.get(item_id)
            if not is_valid_id(item_id) or _is_license_id(item_id):
                skipped[item_id] = "invalid-id"
                continue
            try:
                wrapper = _view_wrapper(ns, record, m)
            except BridgeError as exc:
                skipped[item_id] = str(exc)
                continue
            if m is None or m["deleted"] or m["digest"] != wrapper_digest(wrapper):
                vv = _bumped(m["vv"] if m else {}, device_id)
                if vv is None:  # a vector stored before the plausibility rule: skip only this item
                    skipped[item_id] = COUNTER_OVERFLOW
                    continue
                m = _live_meta(wrapper, vv)
                meta[item_id] = m
            states[item_id] = ItemState(item_id, m["vv"], False, None, wrapper)
        for item_id, wrapper in licenses.items():
            m = meta.get(item_id)
            if m is None or m["deleted"] or m["digest"] != wrapper_digest(wrapper):
                vv = _bumped(m["vv"] if m else {}, device_id)
                if vv is None:
                    skipped[item_id] = COUNTER_OVERFLOW
                    continue
                m = _live_meta(wrapper, vv)
                meta[item_id] = m
            states[item_id] = ItemState(item_id, m["vv"], False, None, wrapper)
        for item_id, m in list(meta.items()):
            if item_id in live:  # includes skipped records: they are live, just unreadable
                continue
            if _is_license_id(item_id):  # a licence is never deleted: one no longer published just goes quiet
                continue
            if not is_valid_id(item_id):  # stale meta under an unsyncable id: leave it alone
                continue
            if not m["deleted"]:
                vv = _bumped(m["vv"], device_id)
                if vv is None:  # cannot record the delete without an overflow: publish nothing for it
                    continue
                m = _tomb_meta(vv, now)
                meta[item_id] = m
            states[item_id] = ItemState(item_id, m["vv"], True, m["deleted_at"], None)
    except EngineError as exc:
        raise BridgeError(f"Vault content cannot be synced: {exc}") from None
    if len(meta) > MAX_SYNC_RECORDS:
        raise BridgeError("Sync metadata exceeds its bound")
    current = payload.get("sync_meta")
    if meta != stored_meta or not isinstance(current, dict) or current.get("device_id") != device_id:
        with sync_only_save(session), session.transaction():
            payload = session._require_typed_catalog()
            _store_meta(payload, device_id, meta)
            _check_lease(session, lease)
    return LocalView(states, skipped)


# --- apply -------------------------------------------------------------------------------


def _unwrap(state: ItemState, *, is_copy: bool) -> tuple[str, dict[str, Any]]:
    """Namespace and a private copy of the record carried by a live state."""
    item = state.item
    # The schema comes first: a newer schema may add wrapper fields, so it is
    # update-needed before the key set is checked (spec Part 1).
    schema = item.get("schema") if isinstance(item, dict) else None
    if type(schema) is int and schema > ITEM_WRAPPER_SCHEMA:
        raise BridgeError(f"Sync state {state.item_id!r} was written by a newer LocalGateKeys",
                          reason="update-needed", item_id=state.item_id)
    required = {"ns", "schema", "updated_at", "record"}
    allowed = required | {"id"} if is_copy else required
    if not isinstance(item, dict) or not required <= set(item) or set(item) - allowed:
        raise BridgeError(f"Sync state {state.item_id!r} is malformed")
    if type(schema) is not int or schema < 1:
        raise BridgeError(f"Sync state {state.item_id!r} is malformed")
    ns, record = item["ns"], item["record"]
    if ns == LICENSE_NS:
        return ns, _unwrap_license(state, item, is_copy=is_copy)
    if ns not in ("entry", "item") or not isinstance(record, dict) or _is_license_id(state.item_id):
        raise BridgeError(f"Sync state {state.item_id!r} is malformed")
    if item["updated_at"] != _rank_updated_at(record) or type(item["updated_at"]) is not int:
        raise BridgeError(f"Sync state {state.item_id!r} has a rank that does not match its record")
    record = copy.deepcopy(record)
    if is_copy:
        if item.get("id") != state.item_id:
            raise BridgeError(f"Sync conflict copy {state.item_id!r} is malformed")
        record["id"] = state.item_id
    elif record.get("id") != state.item_id:
        raise BridgeError(f"Sync state {state.item_id!r} does not match its record")
    if _ns_of(record) != ns:
        raise BridgeError(f"Sync state {state.item_id!r} is in the wrong namespace")
    if ns == "item" and record.get("kind") in UNSYNCED_ITEM_KINDS:
        raise BridgeError(f"Sync state {state.item_id!r} is a kind that does not sync")
    return ns, record


def _without_local_fields(ns: str, record: Mapping[str, Any]) -> dict[str, Any]:
    """A copy of a remote record without the fields ``apply`` replaces with this device's own."""
    rec = copy.deepcopy(dict(record))
    if ns == "entry":
        _strip_entry_local(rec)
        return rec
    for name in LOCAL_ONLY_ITEM_FIELDS:
        rec.pop(name, None)
    payload = rec.get("payload")
    if isinstance(payload, dict):
        for name in LOCAL_ONLY_ITEM_PAYLOAD_FIELDS:
            payload.pop(name, None)
    return rec


def _unwrap_remote(state: ItemState) -> tuple[str, dict[str, Any]]:
    """``_unwrap`` of a live remote upsert, with its record normalised as ``apply`` will store it.

    Local-only fields are stripped before the check: ``apply`` drops whatever a peer
    sent there (each device keeps its own), so a bad value in one never refuses the record.
    """
    ns, record = _unwrap(state, is_copy=False)
    if ns != LICENSE_NS:
        try:
            normal_form(ns, _without_local_fields(ns, record))
        except (VaultError, ItemSchemaError, TotpError, OriginError) as exc:
            raise BridgeError(f"Remote record {state.item_id!r} is invalid: {exc}") from None
    return ns, record


def check_remote_state(state: ItemState) -> str | None:
    """Why ``apply`` would refuse a remote upsert of *state*, else None.

    The reason is ``"bad-remote"`` or ``"update-needed"``, from the same checks
    ``apply`` runs before it stores the state.  Tombstones and licence states
    that ``apply`` drops quietly (no licence keys in this build, or revoked)
    give None.  ``apply`` may still refuse a record for reasons that depend on
    this vault (an id used by another kind of record), so callers keep
    handling its errors.
    """
    if state.deleted or _quiet_license(state):
        return None
    try:
        with _blame(state.item_id):
            _unwrap_remote(state)
    except BridgeError as exc:
        return exc.reason or "bad-remote"
    return None


def _unwrap_license(state: ItemState, item: Mapping[str, Any], *, is_copy: bool) -> dict[str, Any]:
    """The verified bundle of a licence state; its id must be ``sync_state_id`` of its licence."""
    record = item["record"]
    if is_copy or "id" in item or not _is_license_id(state.item_id):
        raise BridgeError(f"Licence state {state.item_id!r} is malformed")
    if type(item["updated_at"]) is not int or item["updated_at"] != 0:
        raise BridgeError(f"Licence state {state.item_id!r} is malformed")
    try:
        bundle = _json_copy(record)
        lic = licensing.verify_bundle(bundle)
    except licensing.LicenseError as exc:
        if exc.reason in ("unknown-key", "bad-alg") or licensing.newer_format(record):
            # Signed with a key or in a format only a newer LocalGateKeys knows.
            raise BridgeError(f"Licence state {state.item_id!r} needs a newer LocalGateKeys",
                              reason="update-needed", item_id=state.item_id) from None
        raise BridgeError(f"Licence state {state.item_id!r} does not verify ({exc.reason})") from None
    except (TypeError, ValueError, RecursionError):
        raise BridgeError(f"Licence state {state.item_id!r} is malformed") from None
    if licensing.sync_state_id(lic.license_id) != state.item_id:
        raise BridgeError(f"Licence state {state.item_id!r} does not match its licence")
    return bundle


def _with_suffix(text: Any, limit: int) -> Any:
    if not isinstance(text, str) or text.endswith(CONFLICT_SUFFIX):
        return text
    return text[: max(0, limit - len(CONFLICT_SUFFIX))] + CONFLICT_SUFFIX


def _remote_wrapper(ns: str, record: Mapping[str, Any]) -> dict[str, Any]:
    return {"ns": ns, "schema": ITEM_WRAPPER_SCHEMA, "updated_at": _rank_updated_at(record),
            "record": copy.deepcopy(dict(record))}


def _history_error(exc: HistoryError) -> BridgeError:
    if isinstance(exc, HistoryQuotaError):
        return BridgeError(f"Item history is full ({exc}); remove old versions and sync again",
                           reason="history-quota")
    return BridgeError(f"Item history could not be updated: {exc}", reason="history-error")


class _Applier:
    def __init__(self, session: Any, payload: dict[str, Any], meta: dict[str, dict[str, Any]],
                 licenses: Mapping[str, dict[str, Any]]) -> None:
        self.session = session
        self.payload = payload
        self.meta = meta
        self.live = _live_records(payload)
        self.trash = _trash_index(payload)
        self.collections = {row["id"] for row in payload.get("collections", [])
                            if isinstance(row, dict) and isinstance(row.get("id"), str)}
        self.licenses = dict(licenses)  # published licence wrappers, taken once per apply

    def check_fresh(self, item_id: str) -> None:
        """Refuse to apply over a local change that the merged view did not include."""
        if _is_license_id(item_id):
            return  # licences are only ever added, never edited or removed by apply
        m = self.meta.get(item_id)
        current = self.live.get(item_id)
        if m is None or m["deleted"]:
            fresh = current is None
        else:
            fresh = current is not None and wrapper_digest(_view_wrapper(*current, m)) == m["digest"]
        if not fresh:
            raise BridgeError("The vault changed since the sync view was taken; sync again",
                              reason="vault-changed", item_id=item_id)

    def delete(self, item_id: str) -> bool:
        current = self.live.get(item_id)
        if current is None:
            return False
        if len(self.payload.get("trash", [])) >= MAX_ITEMS:
            raise BridgeError("The vault trash is full; empty it and sync again", reason="trash-full")
        ns, _record = current
        try:
            if ns == "entry":
                removed = self.session.delete(item_id)
            else:
                removed = self.session.item_service.delete_item(item_id)
        except HistoryError as exc:
            raise _history_error(exc) from None
        if not removed:
            raise BridgeError(f"Record {item_id!r} could not be moved to the trash")
        del self.live[item_id]
        self.trash = _trash_index(self.payload)
        return True

    def store(self, ns: str, incoming: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Insert, replace or restore one record; returns (stored wrapper, changed)."""
        item_id = incoming["id"]
        current = self.live.get(item_id)
        if current is not None and current[0] != ns:
            raise BridgeError(f"Record id {item_id!r} is used by a different kind of record")
        trashed = self.trash.get(item_id)
        if current is None and trashed is not None and _ns_of(trashed["entry"]) != ns:
            raise BridgeError(f"Record id {item_id!r} is used by a different kind of record in the trash")
        local = current[1] if current is not None else (trashed["entry"] if trashed else None)
        try:
            record = self._with_local_fields(ns, incoming, local)
        except (VaultError, ItemSchemaError, TotpError) as exc:
            raise BridgeError(f"Remote record {item_id!r} is invalid: {exc}") from None
        stored = _wrapper(ns, record)
        if current is not None and _view_wrapper(*current, self.meta.get(item_id)) == stored:
            return stored, False
        rows = self.payload.setdefault("entries" if ns == "entry" else "items", [])
        if current is not None:
            if ns == "item":
                self._snapshot(current[1])
            index = next(n for n, row in enumerate(rows) if row is current[1])
            rows[index] = record
        else:
            if trashed is not None:
                self.payload["trash"].remove(trashed)
                del self.trash[item_id]
            rows.append(record)
        self.live[item_id] = (ns, record)
        return stored, True

    def store_license(self, item_id: str, bundle: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Keep a received, verified licence in ``payload["sync_licenses"]``; returns (wrapper, changed).

        A licence this device already publishes under *item_id* with other
        content is refused (the id is derived from the licence id, so the same
        licence id with different bytes is never a valid edit).
        """
        wrapper = _license_wrapper(bundle)
        known = self.licenses.get(item_id)
        if known is not None:
            if canonical_json(known["record"]) != canonical_json(bundle):
                raise BridgeError(f"Licence state {item_id!r} differs from the licence stored under that id")
            return wrapper, False
        stored = self.payload.get("sync_licenses")
        if not isinstance(stored, dict):
            stored = self.payload["sync_licenses"] = {}
        if item_id not in stored and len(stored) >= MAX_SYNC_LICENSES:
            raise BridgeError("The vault holds as many synced licences as it keeps")
        if not stored_license_ok(bundle):
            raise BridgeError(f"Licence state {item_id!r} is too large")
        stored[item_id] = copy.deepcopy(bundle)
        self.licenses[item_id] = wrapper
        return wrapper, True

    def _with_local_fields(self, ns: str, incoming: dict[str, Any],
                           local: Mapping[str, Any] | None) -> dict[str, Any]:
        record = copy.deepcopy(incoming)
        if ns == "entry":
            return self._entry_with_local_fields(record, local)
        typed = record.get("payload")
        if isinstance(typed, dict):
            for name in LOCAL_ONLY_ITEM_PAYLOAD_FIELDS:
                typed.pop(name, None)
        current_revision = local.get("revision", 0) if local is not None else 0
        if type(current_revision) is not int or not 0 <= current_revision < _MAX_INT63:
            current_revision = 0
        record["revision"] = current_revision + 1
        kept = local.get("collection_ids", []) if local is not None else []
        record["collection_ids"] = [c for c in kept if c in self.collections] if isinstance(kept, list) else []
        normalized = validate_item(record, known_collection_ids=self.collections)
        local_payload = local.get("payload") if local is not None else None
        for name in LOCAL_ONLY_ITEM_PAYLOAD_FIELDS:
            if name in normalized["payload"] and isinstance(local_payload, dict) and name in local_payload:
                normalized["payload"][name] = copy.deepcopy(local_payload[name])
        return validate_item(normalized, known_collection_ids=self.collections)

    @staticmethod
    def _entry_with_local_fields(record: dict[str, Any], local: Mapping[str, Any] | None) -> dict[str, Any]:
        """Drop any device-local trust the remote sent; keep this device's own or safe defaults."""
        _strip_entry_local(record)
        scope = record.get("scope")
        if not isinstance(scope, dict):
            raise VaultError("Credential scope is missing")
        same_kind = local is not None and local.get("kind") == record.get("kind")
        if local is not None:
            for name in LOCAL_ONLY_ENTRY_FIELDS:
                if name in local:
                    record[name] = copy.deepcopy(local[name])
        local_scope = local.get("scope") if same_kind else None
        if isinstance(local_scope, dict):
            for name in LOCAL_ONLY_ENTRY_SCOPE_FIELDS:
                if name in local_scope:
                    scope[name] = copy.deepcopy(local_scope[name])
        elif record.get("kind") == "desktop":
            scope["embedded_web_fill_approved"] = False
        policy = record.get("policy")
        policy = dict(policy) if isinstance(policy, dict) else {}
        policy["sign_in"] = normalized_policy(local.get("policy"))["sign_in"] if same_kind else "never"
        record["policy"] = policy
        return _canonical_entry(record)

    def _snapshot(self, original: Mapping[str, Any]) -> None:
        """Keep the overwritten typed item in history, as a local edit would."""
        history = getattr(self.session, "history", None)
        if history is None:
            return
        try:
            history.record_before_change(original, change_type="sync", persist=False)
        except HistoryError as exc:
            raise _history_error(exc) from None


def apply(session: Any, lease: Any, outcome: MergeOutcome, *, device_id: str, now: int) -> ApplyReport:
    """Write a merge outcome into the vault in one transaction.

    The outcome must come from ``merge(local_view(...), ...)`` taken on this
    session; a record changed locally since that view makes the whole apply
    fail without writes.  A remote tombstone's ``deleted_at`` is capped at
    *now*; tombstones older than ``TOMBSTONE_MAX_AGE_DAYS`` come from stale
    devices and are ignored.  Outcome entries for a live local record that
    cannot be read (``LocalView.skipped``) are dropped, never applied over it,
    and listed in ``ApplyReport.skipped``.
    """
    _check_lease(session, lease)
    _check_device(device_id)
    _check_now(now)
    if not isinstance(outcome, MergeOutcome):
        raise BridgeError("Merge outcome is malformed")
    for state in (*outcome.upserts, *outcome.deletes, *outcome.copies):
        if not isinstance(state, ItemState):
            raise BridgeError("Merge outcome is malformed")
    ids = [s.item_id for s in (*outcome.upserts, *outcome.deletes, *outcome.copies)]
    if len(ids) != len(set(ids)):
        raise BridgeError("Merge outcome names a record more than once")
    if any(s.deleted for s in (*outcome.upserts, *outcome.copies)) or not all(s.deleted for s in outcome.deletes):
        raise BridgeError("Merge outcome is malformed")
    cutoff = now - TOMBSTONE_MAX_AGE_DAYS * 86400
    deletes = []
    for state in outcome.deletes:
        at = now if state.deleted_at is None else min(state.deleted_at, now)
        if at >= cutoff:
            deletes.append((state, at))
    stale = {s.item_id for s in outcome.deletes} - {s.item_id for s, _at in deletes}
    # Licence states: a tombstone never deletes one (one this device publishes is
    # republished above it), and a revoked licence, or any licence in a build
    # without licence keys, is dropped quietly: never stored, installed or republished.
    published = _published_licenses(session._require_typed_catalog())
    for state, _at in deletes:
        if _is_license_id(state.item_id) and state.item_id not in published:
            stale.add(state.item_id)
    stale.update(s.item_id for s in outcome.upserts if _quiet_license(s))
    # A conflict copy of a licence (a reissue under the same licence id) is never kept.
    stale.update(s.item_id for s in outcome.copies
                 if isinstance(s.item, dict) and s.item.get("ns") == LICENSE_NS)
    deletes = [(s, at) for s, at in deletes if s.item_id not in stale]
    ids = [item_id for item_id in ids if item_id not in stale]
    skipped = _unreadable(session._require_typed_catalog(), ids)
    report_skipped = tuple(sorted(skipped.items()))
    ids = [item_id for item_id in ids if item_id not in skipped]
    if not ids:
        return ApplyReport(0, 0, len(outcome.conflicts), report_skipped)

    applied = deleted = 0
    received: list[dict[str, Any]] = []
    with session.transaction():
        payload = session._require_typed_catalog()
        meta = _load_meta(payload)
        work = _Applier(session, payload, meta, published)
        for item_id in ids:
            work.check_fresh(item_id)
        history_rows = len(payload.get("history", []))
        try:
            for state, at in deletes:
                if state.item_id in skipped:
                    continue
                if _is_license_id(state.item_id):
                    with _blame(state.item_id):  # an overflowing bump refuses only this state
                        meta[state.item_id] = _live_meta(work.licenses[state.item_id], bump(state.vv, device_id))
                    continue
                if work.delete(state.item_id):
                    deleted += 1
                meta[state.item_id] = _tomb_meta(state.vv, at)
            for state in outcome.upserts:
                if state.item_id in skipped or state.item_id in stale:
                    continue
                with _blame(state.item_id):
                    ns, record = _unwrap_remote(state)
                    if ns == LICENSE_NS:
                        stored, _changed = work.store_license(state.item_id, record)
                        meta[state.item_id] = _live_meta(stored, state.vv)
                        received.append(record)
                        continue
                    stored, changed = work.store(ns, record)
                    applied += changed
                    vv = state.vv if stored == _remote_wrapper(ns, record) else bump(state.vv, device_id)
                    meta[state.item_id] = _live_meta(stored, vv)
            for state in outcome.copies:
                if (state.item_id in skipped or state.item_id in stale or state.item_id in work.live
                        or state.item_id in work.trash):
                    continue
                with _blame(state.item_id):
                    ns, record = _unwrap(state, is_copy=True)
                    if ns == "entry":
                        record["label"] = _with_suffix(record.get("label"), _MAX_ENTRY_LABEL)
                    else:
                        record["title"] = _with_suffix(record.get("title"), MAX_TITLE)
                    stored, changed = work.store(ns, record)
                    applied += changed
                    vv = state.vv if stored == _remote_wrapper(ns, record) else bump(state.vv, device_id)
                    meta[state.item_id] = _live_meta(stored, vv)
        except (EngineError, ItemSchemaError) as exc:
            raise BridgeError(f"Merge outcome cannot be applied: {exc}") from None
        if len(work.live) > MAX_SYNC_RECORDS:
            raise BridgeError("The vault would hold more records than sync supports")
        rows = len(payload.get("history", []))
        if rows > history_rows and rows > _MAX_SAVED_HISTORY_ROWS:
            raise BridgeError("Item history is full; remove old versions and sync again",
                              reason="history-quota")
        _store_meta(payload, device_id, meta)
        _check_lease(session, lease)
    return ApplyReport(applied, deleted, len(outcome.conflicts), report_skipped, tuple(received))


def _quiet_license(state: ItemState) -> bool:
    """A live licence state to drop without a word: no licence keys in this build, or revoked."""
    if not _is_license_id(state.item_id) or state.deleted:
        return False
    if not licensing.LICENSE_KEYS:
        return True
    item = state.item
    record = item.get("record") if isinstance(item, dict) and item.get("ns") == LICENSE_NS else None
    try:
        lic = licensing.verify_bundle(record)
    except licensing.LicenseError:
        return False  # not a valid licence: apply rejects it as bad-remote
    return lic.license_id in licensing._cached_revoked_ids()


@contextlib.contextmanager
def _blame(item_id: str) -> Iterator[None]:
    """Re-raise a reason-less failure while storing a remote state as ``bad-remote`` for *item_id*."""
    try:
        yield
    except BridgeError as exc:
        if exc.reason is not None:
            raise
        raise BridgeError(str(exc), reason="bad-remote", item_id=item_id) from None
    except (VaultLockedError, StaleSession):
        raise  # lock and lease errors end the run; they are not the record's fault
    except Exception as exc:  # noqa: BLE001 - one bad remote state must not abort the whole run
        _log.debug("Remote state %r could not be stored", item_id, exc_info=True)
        raise BridgeError(f"Merge outcome cannot be applied: {exc}", reason="bad-remote",
                          item_id=item_id) from None


def _unreadable(payload: Mapping[str, Any], ids: list[str]) -> dict[str, str]:
    """id -> reason for the live local records among *ids* that fail validation."""
    meta = _load_meta(payload)
    live = _live_records(payload)
    out: dict[str, str] = {}
    for item_id in ids:
        current = live.get(item_id)
        if current is None:
            continue
        if not is_valid_id(item_id) or _is_license_id(item_id):
            out[item_id] = "invalid-id"
            continue
        try:
            _view_wrapper(*current, meta.get(item_id))
        except BridgeError as exc:
            out[item_id] = str(exc)
    return out


# --- sync group state --------------------------------------------------------------------

MAX_GROUP_ID = 128
MAX_PEERS_SEEN = 64
MAX_LAN_PEERS = 16
MAX_LAN_PEER_BYTES = 16 * 1024
MAX_FOLDER_PATH = 32_768
MAX_INSTALL_ID = 128
MAX_MEMBERS_SEEN = 64
SYNC_GROUP_VERSION = 1
MAX_STORED_KEYRING_BYTES = 256 * 1024
_OPTIONAL_GROUP_KEYS = frozenset({"own_counter", "peer_digests", "members_epoch", "members", "keyring",
                                  "hello_counter", "lan_removed", "unacked_members", "view_signers"})
_IDENTITY_KEYS = frozenset({"device_id", "signing_private", "exchange_private"})


def _is_public_key_b64(value: Any) -> bool:
    """True for standard base64 (with padding, canonical) of exactly 32 bytes."""
    if not isinstance(value, str) or len(value) != 44:
        return False
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        return False
    return len(raw) == 32 and base64.b64encode(raw).decode("ascii") == value


def _text(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or "\x00" in value:
        raise BridgeError(f"Sync {name} is malformed")
    return value


def _json_safe(value: Any, depth: int = 0) -> None:
    if depth > 16:
        raise BridgeError("Sync LAN peer is nested too deeply")
    if value is None or isinstance(value, (bool, str, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise BridgeError("Sync LAN peer holds a non-finite number")
        return
    if isinstance(value, list):
        for v in value:
            _json_safe(v, depth + 1)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise BridgeError("Sync LAN peer keys must be text")
            _json_safe(v, depth + 1)
        return
    raise BridgeError("Sync LAN peer holds an unsupported value")


@dataclass(frozen=True)
class SyncGroupState:
    """This device's sync group membership, stored in ``payload["sync_group"]``.

    ``device_identity`` is ``DeviceIdentity.protected_dict()``; ``last_seen``
    maps peer device ids to the highest device-file counter accepted from them
    and ``peer_digests`` to the sha256 hex of that accepted file (same counter,
    different bytes is a suspicious rewrite).  ``own_counter`` is the last
    counter this device reserved for its own file; it is persisted before the
    file is written, so a crash never reuses one.  ``members`` are the keyring
    member ids seen at ``members_epoch`` (a member that disappears without a
    rotation is reported).  ``keyring`` holds the bytes of the last keyring
    this device accepted; the folder transport writes it back when the folder
    shows an older or tampered keyring of the same group (never over another
    group's keyring or a competing rotation).  ``hello_counter`` is the last LAN
    session-hello counter this device used (persisted before the hello is sent).
    ``lan_removed`` is True once a Wi-Fi peer was removed from ``lan_peers``
    since the group key last changed: that peer still holds ``key``, so a cloud
    folder added later must not be protected by it (audit M9).
    ``unacked_members`` are keyring member ids that appeared without this
    device adding them and that the user has not acknowledged yet (audit M10);
    they are reported as ``member-added`` on every folder run.
    ``view_signers`` maps a device id to the base64 Ed25519 public key whose
    signature its view files carry (audit M-7): this device's own key once it
    wrote a signed view, and each peer's key once a signed view of it verified
    (trust on first use within an epoch).  A pinned peer's view must carry a
    valid signature by that key; adopting a new epoch keeps only the own entry.
    The nine newer fields are optional in stored form; the last three are written
    only when they differ from their defaults, so an older version still reads
    an unaffected state (one that holds ``view_signers`` is refused by a version
    from before 2026-10-24).
    """

    group_id: str
    epoch: int
    key: bytes = field(repr=False)
    device_identity: Mapping[str, str] = field(repr=False)
    last_seen: Mapping[str, int] = field(default_factory=dict)
    folder_path: str | None = None
    lan_peers: tuple[Mapping[str, Any], ...] = ()
    install_id: str | None = None
    own_counter: int = 0
    peer_digests: Mapping[str, str] = field(default_factory=dict)
    members_epoch: int | None = None
    members: tuple[str, ...] = ()
    keyring: bytes | None = field(default=None, repr=False)
    hello_counter: int = 0
    lan_removed: bool = False
    unacked_members: tuple[str, ...] = ()
    view_signers: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.group_id, "group id", MAX_GROUP_ID)
        if isinstance(self.epoch, bool) or not isinstance(self.epoch, int) or not 1 <= self.epoch <= _MAX_INT53:
            raise BridgeError("Sync epoch is malformed")
        if not isinstance(self.key, bytes) or len(self.key) != 32:
            raise BridgeError("Sync group key is malformed")
        identity = self.device_identity
        if not isinstance(identity, Mapping) or set(identity) != _IDENTITY_KEYS:
            raise BridgeError("Sync device identity is malformed")
        try:
            DeviceIdentity.from_protected_dict(identity)
        except PairingError as exc:
            raise BridgeError(f"Sync device identity is malformed: {exc}") from None
        object.__setattr__(self, "device_identity", dict(identity))
        seen = self.last_seen
        if not isinstance(seen, Mapping) or len(seen) > MAX_PEERS_SEEN:
            raise BridgeError("Sync last-seen counters are malformed")
        for dev, counter in seen.items():
            _text(dev, "peer device id", 128)
            if "|" in dev or isinstance(counter, bool) or not isinstance(counter, int) \
                    or not 0 <= counter <= _MAX_INT63:
                raise BridgeError("Sync last-seen counters are malformed")
        object.__setattr__(self, "last_seen", dict(sorted(seen.items())))
        if self.folder_path is not None:
            _text(self.folder_path, "folder path", MAX_FOLDER_PATH)
        peers = self.lan_peers
        if isinstance(peers, (str, bytes, Mapping)) or not hasattr(peers, "__iter__"):
            raise BridgeError("Sync LAN peers are malformed")
        peers = tuple(peers)
        if len(peers) > MAX_LAN_PEERS:
            raise BridgeError("Sync LAN peers exceed their bound")
        for peer in peers:
            if not isinstance(peer, Mapping):
                raise BridgeError("Sync LAN peers are malformed")
            _json_safe(dict(peer))
            if len(canonical_json(dict(peer))) > MAX_LAN_PEER_BYTES:
                raise BridgeError("Sync LAN peer is too large")
        object.__setattr__(self, "lan_peers", tuple(copy.deepcopy(dict(p)) for p in peers))
        if self.install_id is not None:
            _text(self.install_id, "install id", MAX_INSTALL_ID)
        if type(self.own_counter) is not int or not 0 <= self.own_counter <= _MAX_INT53:
            raise BridgeError("Sync own counter is malformed")
        digests = self.peer_digests
        if not isinstance(digests, Mapping) or len(digests) > MAX_PEERS_SEEN:
            raise BridgeError("Sync peer digests are malformed")
        for dev, digest in digests.items():
            if (not is_valid_id(dev) or not isinstance(digest, str) or len(digest) != 64
                    or any(ch not in "0123456789abcdef" for ch in digest)):
                raise BridgeError("Sync peer digests are malformed")
        object.__setattr__(self, "peer_digests", dict(sorted(digests.items())))
        if self.members_epoch is not None and (type(self.members_epoch) is not int
                                               or not 1 <= self.members_epoch <= _MAX_INT53):
            raise BridgeError("Sync member epoch is malformed")
        members = self.members
        if isinstance(members, (str, bytes, Mapping)) or not hasattr(members, "__iter__"):
            raise BridgeError("Sync members are malformed")
        members = tuple(members)
        if (len(members) > MAX_MEMBERS_SEEN or len(set(members)) != len(members)
                or not all(is_valid_id(m) for m in members)):
            raise BridgeError("Sync members are malformed")
        if members and self.members_epoch is None:
            raise BridgeError("Sync members need an epoch")
        object.__setattr__(self, "members", tuple(sorted(members)))
        if type(self.hello_counter) is not int or not 0 <= self.hello_counter <= _MAX_INT63:
            raise BridgeError("Sync hello counter is malformed")
        if self.keyring is not None and (not isinstance(self.keyring, bytes) or not self.keyring
                                         or len(self.keyring) > MAX_STORED_KEYRING_BYTES):
            raise BridgeError("Sync stored keyring is malformed")
        if type(self.lan_removed) is not bool:
            raise BridgeError("Sync LAN removal flag is malformed")
        unacked = self.unacked_members
        if isinstance(unacked, (str, bytes, Mapping)) or not hasattr(unacked, "__iter__"):
            raise BridgeError("Sync unacknowledged members are malformed")
        unacked = tuple(unacked)
        if (len(unacked) > MAX_MEMBERS_SEEN or len(set(unacked)) != len(unacked)
                or not all(is_valid_id(m) for m in unacked)):
            raise BridgeError("Sync unacknowledged members are malformed")
        object.__setattr__(self, "unacked_members", tuple(sorted(unacked)))
        signers = self.view_signers
        if not isinstance(signers, Mapping) or len(signers) > MAX_PEERS_SEEN + 1:
            raise BridgeError("Sync view signers are malformed")
        for dev, public in signers.items():
            if not is_valid_id(dev) or not _is_public_key_b64(public):
                raise BridgeError("Sync view signers are malformed")
        object.__setattr__(self, "view_signers", dict(sorted(signers.items())))

    @property
    def device_id(self) -> str:
        return self.device_identity["device_id"]

    def identity(self) -> DeviceIdentity:
        return DeviceIdentity.from_protected_dict(self.device_identity)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "version": SYNC_GROUP_VERSION,
            "group_id": self.group_id,
            "epoch": self.epoch,
            "key": base64.b64encode(self.key).decode("ascii"),
            "device_identity": dict(self.device_identity),
            "last_seen": dict(self.last_seen),
            "folder_path": self.folder_path,
            "lan_peers": [copy.deepcopy(dict(p)) for p in self.lan_peers],
            "install_id": self.install_id,
            "own_counter": self.own_counter,
            "peer_digests": dict(self.peer_digests),
            "members_epoch": self.members_epoch,
            "members": list(self.members),
            "keyring": base64.b64encode(self.keyring).decode("ascii") if self.keyring is not None else None,
            "hello_counter": self.hello_counter,
        }
        if self.lan_removed:
            out["lan_removed"] = True
        if self.unacked_members:
            out["unacked_members"] = list(self.unacked_members)
        if self.view_signers:
            out["view_signers"] = dict(self.view_signers)
        return out

    @classmethod
    def from_dict(cls, raw: Any) -> SyncGroupState:
        expected = {"version", "group_id", "epoch", "key", "device_identity", "last_seen",
                    "folder_path", "lan_peers", "install_id"}
        if (not isinstance(raw, Mapping) or not expected <= set(raw) <= expected | _OPTIONAL_GROUP_KEYS
                or raw["version"] != SYNC_GROUP_VERSION):
            raise BridgeError("Stored sync group state is malformed")
        if (not isinstance(raw["key"], str) or not isinstance(raw["lan_peers"], list)
                or not isinstance(raw.get("members", []), list)
                or not isinstance(raw.get("unacked_members", []), list)
                or not isinstance(raw.get("view_signers", {}), dict)
                or not isinstance(raw.get("keyring"), (str, type(None)))):
            raise BridgeError("Stored sync group state is malformed")
        keyring = None
        if raw.get("keyring") is not None:
            try:
                keyring = base64.b64decode(raw["keyring"].encode("ascii"), validate=True)
            except (binascii.Error, UnicodeEncodeError, ValueError):
                raise BridgeError("Stored sync keyring is malformed") from None
        try:
            key = base64.b64decode(raw["key"].encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError, ValueError):
            raise BridgeError("Stored sync group key is malformed") from None
        return cls(group_id=raw["group_id"], epoch=raw["epoch"], key=key,
                   device_identity=raw["device_identity"], last_seen=raw["last_seen"],
                   folder_path=raw["folder_path"], lan_peers=tuple(raw["lan_peers"]),
                   install_id=raw["install_id"], own_counter=raw.get("own_counter", 0),
                   peer_digests=raw.get("peer_digests", {}), members_epoch=raw.get("members_epoch"),
                   members=tuple(raw.get("members", [])), keyring=keyring,
                   hello_counter=raw.get("hello_counter", 0), lan_removed=raw.get("lan_removed", False),
                   unacked_members=tuple(raw.get("unacked_members", [])),
                   view_signers=raw.get("view_signers", {}))


def load_sync_state(session: Any) -> SyncGroupState | None:
    """The stored sync group state, or None when this vault has not joined a group."""
    payload = session._require_typed_catalog()
    raw = payload.get("sync_group")
    if raw is None:
        return None
    return SyncGroupState.from_dict(raw)


def sync_only_save(session: Any) -> contextlib.AbstractContextManager[None]:
    """Saves inside skip the vault's rolling backup: they change only sync metadata.

    Delegates to ``VaultSession.sync_metadata_save``.  Only takes effect for a
    save that commits inside the block (an outer transaction commits later and
    keeps its backup).
    """
    return session.sync_metadata_save()


def save_sync_state(session: Any, state: SyncGroupState) -> bool:
    """Store *state*; returns False (and writes nothing) when it equals the stored state.

    A real change is saved without a rolling backup (``sync_only_save``).
    """
    if not isinstance(state, SyncGroupState):
        raise BridgeError("Sync group state is malformed")
    new = state.to_dict()
    if session._require_typed_catalog().get("sync_group") == new:
        return False
    with sync_only_save(session), session.transaction():
        session._require_typed_catalog()["sync_group"] = new
    return True


def clear_sync_state(session: Any) -> None:
    payload = session._require_typed_catalog()
    if "sync_group" in payload:
        with session.transaction():
            session._require_typed_catalog().pop("sync_group", None)


__all__ = [
    "CONFLICT_SUFFIX", "COUNTER_OVERFLOW", "ITEM_WRAPPER_SCHEMA", "LOCAL_ONLY_ENTRY_FIELDS", "LOCAL_ONLY_ITEM_FIELDS",
    "LOCAL_ONLY_ITEM_PAYLOAD_FIELDS", "MAX_SYNC_RECORDS", "TOMBSTONE_MAX_AGE_DAYS", "UNSYNCED_ITEM_KINDS",
    "ApplyReport", "BridgeError", "LocalView", "SyncGroupState", "apply", "check_remote_state", "clear_sync_state",
    "load_sync_state", "local_view", "normal_form", "prune_tombstones", "published_licenses", "save_sync_state",
    "sync_only_save", "wrapper_digest",
]
