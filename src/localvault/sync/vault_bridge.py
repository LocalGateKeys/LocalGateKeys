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
  recovery codes 100 x 512, password history 10 rows read, custom fields 50 and
  TOTP as small dicts of JSON scalars, the desktop binding's typed keys;
  other scope keys are kept).  A remote record that fails is rejected with
  ``BridgeError``.  A local record that fails is skipped
  (``LocalView.skipped`` / ``ApplyReport.skipped``): no state, meta untouched,
  never overwritten, and every other record still syncs.
* Typed ``document`` items sync (2026-10-29): inside ``local_view`` / ``apply`` their
  wrapper carries one more key, ``attachment`` (``attachment_sync.AttachmentRef``),
  and a received one is applied only once its file was imported
  (``attachment-missing`` otherwise).  Transports leave them out of views for
  older readers (``publishable``).  Outside those two calls they stay invisible.
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
* The emergency access plan (sub-plan 08) as namespace ``"heir"`` under the one state id
  ``"heir:plan"``: ``{"ns": "heir", "schema": 1, "updated_at": <the plan's created>, "record": <the plan
  record without its local-only keys>}`` (``heir.synced_record``: the plan's signing key, holder keys,
  backup public key, check and refused request ids, ``stale`` and ``denied`` always present).  It lives in
  ``payload["preferences"]["heir_plan"]``, so any of the owner's devices can deny or grant.  The engine's
  newest-``updated_at`` rule makes the newest plan win; on apply the same plan merges with the local one
  (``heir.merge_synced``: ``denied`` is the union, ``stale`` either side's) and a merged result that differs
  from the remote is a local edit, so it travels back.  A conflict copy of the plan is never stored: its
  refused ids are merged into the local plan the same way.  ``folder`` (this device's path) and ``home``
  (made here) never sync.  ``heir.remove_plan`` publishes a tombstone, and a remote tombstone removes the plan.
  Transports publish the ``heir:plan`` state only to peers that advertise the ``heir`` feature
  (``publishable(heir=...)``: a signed ``attachments/<device>.lgkheircap`` in a folder, ``heir_peers`` on
  Wi-Fi), so older desktops and the phone apps never see a namespace they would refuse.
* Both lists share the vault's trash (``payload["trash"]``, records
  ``{"entry": record, "deleted_at": int}``).  A trashed or purged record is a
  local delete; remote deletes move records to that trash and never purge.

Local-only fields (never synced, kept per device)
-------------------------------------------------
* Items: ``revision`` (a per-device edit counter used for optimistic edit
  checks and history snapshots), ``collection_ids`` (membership syncs as its own
  ``cm:`` state, "Personal collections") and ``payload.document_ids`` (links to document items, which do not
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

``payload["sync_rejoin"]`` (``KeptIdentity``, 2026-11-17) holds the identity this device had in the
group it last left: Leave keeps it so a later join of the same group reuses the device id instead of
showing up as a second device elsewhere.  It is device-local (bound to the install id, stripped from
every backup, never synced) and dropped by Reset sync, by the join that reuses it and by anything that
says the device was removed (``docs/superpowers/specs/2026-11-17-keep-device-id-on-rejoin-design.md``).

Personal collections (sub-plan 07 Task 4)
-----------------------------------------
Collections and item membership sync between one person's devices as states of namespace
``"collection"`` in the personal group, only in runs whose peers all read them (``collections=True``:
a folder member's signed ``.lgkcol`` capability file, a Wi-Fi peer's ``features`` answer).  Item
records keep their v1 shape (``collection_ids`` stays a local-only item field), so an older peer
never sees a new field: it gets v1 views, its edits keep the newer device's collections, and a run
without collections neither builds nor tombstones collection states (their meta is left alone).

* ``col:<collection id>``: ``{"kind": "collection", "collection_id", "name", "description",
  "created_at", "updated_at"}`` (never ``revision``, ``starter`` or ``shared_group_id``).  Two
  rows of one name: the larger id gets " (n)" on every device.  A tombstone deletes the row (items
  stay, their membership goes) unless the collection is shared on this device (republished).
* ``cm:<item id>``: ``{"kind": "membership", "item_id", "collection_ids"}`` (sorted, non-empty; no
  collection is a tombstone).  It waits (no meta) until the item and every named collection are
  here.  Two devices changing one membership at once keep the union (the engine's conflict copy of
  a collection state is never stored).
* ``csl:<collection id>``: ``{"kind": "share-link", "collection_id", "mode", "role"}``, published by
  a device that holds the share (owner or member) and relayed unchanged by the others, stored in
  ``payload["collection_links"]``.  Never the group id, keys, keyring, members, folder or owner key:
  a second device is not in the share and gains no share authority.  A ``read``/``member`` link
  makes the item service refuse edits there (``VaultSession.read_only_collection_ids``).
* Read-only stays read-only across a member's own devices: on a device that holds a read-only share,
  a personal-group edit, delete or membership change of that collection's items, and a rename or
  description change of its catalog row, is refused and this device's version is republished above it
  (with or without collections in the run); nothing reaches the share (its own view publishes no local
  change).  Edit shares: the member's other devices'
  edits flow into the share through the member device, as the member's own edits.
* At most ``MAX_SYNC_RECORDS`` states in all: past that, collection states wait.

Shared collections (sub-plan 07)
--------------------------------
``local_view`` and ``apply`` with ``collection_id`` run for a share group (``share_group.py``)
instead of the personal group.  The collection must be shared in this vault (``not-shared``
otherwise).  The personal path is unchanged.  In a share:

* Only typed items whose ``collection_ids`` hold the collection are in the view.  Logins,
  documents (and so every attachment file), licences, the trash, other items and vault settings
  never are.  A published record carries ``collection_ids == [collection_id]`` (the owner's other
  collections stay private); ``revision``, ``tags``, ``favorite`` and ``payload.document_ids`` stay
  local (each person keeps their own).  An item that
  leaves the collection (untagged, trashed or purged) becomes a tombstone in the share view only,
  so members lose it (to their trash) while the device that untagged it keeps it.  A member's
  edit of an item this device untagged meanwhile is skipped quietly here (the tombstone stays
  published), never refused as ``bad-remote``.
* Incoming records must be typed items claiming exactly ``[collection_id]`` (``bad-remote``
  otherwise) and are stored with this device's own collections plus that one.  A record may only
  replace or restore a local record that is tagged with the collection, or that this share last
  saw as live (its meta): an id of a personal item (live or trashed) is ``bad-remote``, and a
  tombstone for one is recorded in the share's meta without touching the vault.
* Read-only (this device is a member of a ``"read"`` share, ``share_group.read_only_collection_ids``):
  a local change (edit, new tagged item, untag, delete) is never published, its meta is left
  alone, and the owner's version replaces it on the next apply (no ``vault-changed`` refusal).
  The item service refuses such edits up front (``ReadOnlyCollection``); bridge writes run inside
  ``item_service.sync_writes``.
* Bookkeeping lives in ``payload["share_sync_meta"][collection_id]`` (same shape as
  ``sync_meta``), separate from the personal group's.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import copy
import dataclasses
import hashlib
import json
import logging
import math
import time
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import licensing
from ..access_policy import normalized_policy
from ..history import HistoryError, HistoryQuotaError
from ..item_schema import (
    MAX_COLLECTION_MEMBERSHIPS,
    MAX_COLLECTIONS,
    MAX_ITEMS,
    MAX_TITLE,
    ItemSchemaError,
    validate_collections,
    validate_item,
    validate_web_urls,
)
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
# upsert_web/_apply_entry_fields (password history written cut to 5, read up to 10:
# vault.PASSWORD_HISTORY_READ_LIMIT, so a newer peer writing 10 rows still syncs).
_MAX_ENTRY_TAGS = 20
_MAX_RECOVERY_CODES = 100
_MAX_CUSTOM_FIELDS = 50
_MAX_PASSWORD_HISTORY = 10
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
#: ``payload`` key of the share groups' change bookkeeping: ``{collection_id: <sync_meta shape>}``.
SHARE_META_KEY = "share_sync_meta"
#: Item fields that stay local in a share group (the collection tag is published as ``[collection_id]``):
#: each person keeps their own tags and favourites.
SHARE_LOCAL_ONLY_ITEM_FIELDS = ("revision", "tags", "favorite")
#: Personal collections (sub-plan 07 Task 4): the namespace of the collection states and their id
#: prefixes (catalog rows, item memberships, share links).  No entry or item may use a prefix.
COLLECTION_NS = "collection"
CATALOG_ID_PREFIX = "col:"
MEMBERSHIP_ID_PREFIX = "cm:"
LINK_ID_PREFIX = "csl:"
COLLECTION_ID_PREFIXES = (CATALOG_ID_PREFIX, MEMBERSHIP_ID_PREFIX, LINK_ID_PREFIX)
#: ``payload`` key of the share links learned from this person's other devices:
#: ``{collection_id: {"mode": "read"|"edit", "role": "owner"|"member"}}``.
LINKS_KEY = "collection_links"
_CATALOG_FIELDS = ("id", "name", "description", "created_at", "updated_at")
_LINK_MODES = frozenset({"read", "edit"})
_LINK_ROLES = frozenset({"owner", "member"})
#: Emergency access (sub-plan 08): namespace and the one state id of the owner's plan record.
HEIR_NS = "heir"
HEIR_STATE_ID = "heir:plan"
_HEIR_PREF = "heir_plan"


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


@dataclass(frozen=True)
class _Scope:
    """A share group's view of the vault: only items tagged with *collection_id*."""

    collection_id: str
    read_only: bool  # this device may not publish local changes (member of a read-only share)


def _scope_for(session: Any, collection_id: Any) -> _Scope | None:
    """The share scope of *collection_id* (None: the personal group); ``not-shared`` unless shared here."""
    if collection_id is None:
        return None
    payload = session._require_typed_catalog()
    rows = payload.get("collections", [])
    row = None
    if isinstance(rows, list) and isinstance(collection_id, str):
        row = next((r for r in rows if isinstance(r, dict) and r.get("id") == collection_id), None)
    if row is None or not row.get("shared_group_id"):
        raise BridgeError("That collection is not shared", reason="not-shared")
    from .share_group import read_only_collection_ids

    return _Scope(collection_id, collection_id in read_only_collection_ids(session))


def _tagged(record: Any, scope: _Scope) -> bool:
    ids = record.get("collection_ids") if isinstance(record, dict) else None
    return isinstance(ids, list) and scope.collection_id in ids


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


def normal_form(ns: str, record: Mapping[str, Any], scope: _Scope | None = None) -> dict[str, Any]:
    """Normalized record minus local-only fields (in a share: tagged with only its collection)."""
    if ns == "entry":
        if scope is not None:
            raise VaultError("Logins are not shared through a collection")
        rec = _canonical_entry(record)
        _strip_entry_local(rec)
        return rec
    rec = validate_item(copy.deepcopy(dict(record)))
    for name in (LOCAL_ONLY_ITEM_FIELDS if scope is None else SHARE_LOCAL_ONLY_ITEM_FIELDS):
        rec.pop(name, None)
    for name in LOCAL_ONLY_ITEM_PAYLOAD_FIELDS:
        rec["payload"].pop(name, None)
    if scope is not None:
        rec["collection_ids"] = [scope.collection_id]
    return rec


def _wrapper(ns: str, record: Mapping[str, Any], scope: _Scope | None = None) -> dict[str, Any]:
    try:
        rec = normal_form(ns, record, scope)
    except (VaultError, ItemSchemaError, TotpError, OriginError) as exc:
        raise BridgeError(f"Vault record {record.get('id')!r} is malformed: {exc}") from None
    out = {"ns": ns, "schema": ITEM_WRAPPER_SCHEMA, "updated_at": _rank_updated_at(rec), "record": rec}
    if ns == "item" and rec.get("kind") == DOCUMENT_KIND:
        out["attachment"] = _document_ref(rec)
    return out


# --- documents (attachment sync, docs/SYNC.md "Documents and files") ------------
#
# While ``local_view`` or ``apply`` runs, ``_DOC_SESSION`` holds the session and ``document``
# items sync: their wrapper carries one more key, ``attachment`` (an ``AttachmentRef`` dict) built
# from this vault's catalog row.  Outside those calls documents stay invisible, as before.  The
# blob id of a catalog row is deterministic, so it is cached by (id, sha256, key).

DOCUMENT_KIND = "document"
_DOC_SESSION: ContextVar[Any] = ContextVar("lgk_sync_doc_session", default=None)
#: Keyed by a hash of (id, sha256, key) so no attachment key outlives a lock in this process-wide cache.
_BLOB_IDS: dict[bytes, tuple[str, int]] = {}
_MAX_BLOB_IDS = 4096


def _blob_cache_key(row: Mapping[str, Any]) -> bytes:
    text = json.dumps([row.get("id"), row.get("sha256"), row.get("key")], ensure_ascii=True)
    return hashlib.sha256(b"lgk-blob-id-cache|" + text.encode("ascii")).digest()


def _documents_on() -> bool:
    return _DOC_SESSION.get() is not None


@contextlib.contextmanager
def _documents(session: Any) -> Iterator[None]:
    token = _DOC_SESSION.set(session)
    try:
        yield
    finally:
        _DOC_SESSION.reset(token)


def remember_blob(row: Mapping[str, Any], blob_id: str, blob_size: int) -> None:
    """Cache the blob id of a catalog row (``AttachmentRef.catalog_record`` shape)."""
    if len(_BLOB_IDS) >= _MAX_BLOB_IDS:
        _BLOB_IDS.clear()
    _BLOB_IDS[_blob_cache_key(row)] = (blob_id, blob_size)


def _catalog_row(payload: Mapping[str, Any], attachment_id: Any) -> dict[str, Any] | None:
    rows = payload.get("attachments", [])
    if not isinstance(rows, list):
        return None
    return next((r for r in rows if isinstance(r, dict) and r.get("id") == attachment_id), None)


def _document_ref(record: Mapping[str, Any]) -> dict[str, Any]:
    """The ``attachment`` reference of a document record in this vault (BridgeError if unavailable)."""
    session = _DOC_SESSION.get()
    if session is None:
        raise BridgeError(f"Record {record.get('id')!r} is a kind that does not sync")
    from ..attachments import AttachmentError, AttachmentStore
    from .attachment_sync import AttachmentRef, AttachmentSyncError

    typed = record.get("payload")
    attachment_id = typed.get("attachment_id") if isinstance(typed, dict) else None
    row = _catalog_row(session._require_typed_catalog(), attachment_id)
    if row is None:
        raise BridgeError(f"Document {record.get('id')!r} has no attachment", reason="attachment-missing",
                          item_id=record.get("id"))
    try:
        cached = _BLOB_IDS.get(_blob_cache_key(row))
        if cached is None:
            ref_dict, _blob = AttachmentStore(session).export_sync_blob(row["id"])
            remember_blob(row, ref_dict["blob"], ref_dict["blob_size"])
            cached = (ref_dict["blob"], ref_dict["blob_size"])
        key = base64.b64decode(str(row.get("key", "")).encode("ascii"), validate=True)
        ref = AttachmentRef(row.get("id"), cached[0], cached[1], row.get("name"),
                            row.get("mime_type") or "application/octet-stream", row.get("size"),
                            row.get("sha256"), key)
    except (AttachmentError, AttachmentSyncError, binascii.Error, ValueError, TypeError, OSError) as exc:
        raise BridgeError(f"Document {record.get('id')!r} attachment cannot be synced: {exc}",
                          reason="attachment-missing", item_id=record.get("id")) from None
    return ref.to_dict()


def _check_remote_document(item: Mapping[str, Any], record: Mapping[str, Any], item_id: str) -> None:
    """A received document's reference must be well formed and name its record's attachment."""
    from .attachment_sync import AttachmentRef, AttachmentSyncError

    try:
        ref = AttachmentRef.from_value(item.get("attachment"))
    except AttachmentSyncError as exc:
        raise BridgeError(f"Sync state {item_id!r} has a malformed attachment ({exc.reason})",
                          item_id=item_id) from None
    typed = record.get("payload")
    if not isinstance(typed, dict) or typed.get("attachment_id") != ref.attachment_id:
        raise BridgeError(f"Sync state {item_id!r} names another attachment", item_id=item_id)


def _require_attachment(session: Any, item: Mapping[str, Any], item_id: str) -> None:
    """Refuse to store a received document until its file was imported (``attachment-missing``)."""
    from .attachment_sync import AttachmentRef

    ref = AttachmentRef.from_value(item["attachment"])
    row = _catalog_row(session._require_typed_catalog(), ref.attachment_id)
    if row is None or {**row, "mime_type": row.get("mime_type") or "application/octet-stream"} != ref.catalog_record():
        raise BridgeError(f"Document {item_id!r} waits for its file", reason="attachment-missing",
                          item_id=item_id)
    remember_blob(row, ref.blob, ref.blob_size)


def is_document_state(state: ItemState) -> bool:
    item = state.item
    return (isinstance(item, dict) and item.get("ns") == "item" and isinstance(item.get("record"), dict)
            and item["record"].get("kind") == DOCUMENT_KIND)


def publishable(states: Any, *, documents: bool, heir: bool = False) -> tuple[ItemState, ...]:
    """*states* to publish; without *documents* the document items are left out, and without *heir* the
    emergency access plan (``heir:plan``) is left out (older readers and the phone apps refuse them)."""
    return tuple(s for s in states
                 if (documents or not is_document_state(s)) and (heir or s.item_id != HEIR_STATE_ID))


def document_refs(states: Any) -> list[Any]:
    """The well-formed references of the live document states in *states* (others are skipped)."""
    from .attachment_sync import AttachmentRef, AttachmentSyncError

    out = []
    for state in states:
        if state.deleted or not is_document_state(state):
            continue
        try:
            out.append(AttachmentRef.from_value(state.item.get("attachment")))
        except AttachmentSyncError:
            continue
    return out


def _ns_of(record: Any) -> str:
    return "entry" if isinstance(record, dict) and record.get("kind") in ENTRY_KINDS else "item"


def _unconfirmed_passkey(record: Mapping[str, Any]) -> bool:
    """A passkey whose website page has not confirmed it yet (``passkey_broker``): local until confirmed.

    It lives a few seconds at most and is then confirmed (and published as a new record) or removed for
    good; it is never published, so its removal leaves no tombstone and no copy in a peer's trash.
    """
    payload = record.get("payload")
    return record.get("kind") == "passkey" and isinstance(payload, dict) and payload.get("unconfirmed") is True


def _live_records(payload: Mapping[str, Any]) -> dict[str, tuple[str, dict[str, Any]]]:
    """id -> (namespace, stored record) for every live synced record (unconfirmed passkeys stay local)."""
    out: dict[str, tuple[str, dict[str, Any]]] = {}
    for ns, key in (("entry", "entries"), ("item", "items")):
        rows = payload.get(key, [])
        if not isinstance(rows, list):
            raise BridgeError(f"Vault {key} are malformed")
        for record in rows:
            if not isinstance(record, dict) or not isinstance(record.get("id"), str):
                raise BridgeError(f"Vault {key} are malformed")
            if ns == "item" and record.get("kind") in UNSYNCED_ITEM_KINDS and not _documents_on():
                continue
            if ns == "item" and _unconfirmed_passkey(record):
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


def _view_wrapper(ns: str, record: Mapping[str, Any], m: Mapping[str, Any] | None,
                  scope: _Scope | None = None) -> dict[str, Any]:
    """Synced wrapper of a live record as this device last published it.

    Local-only changes (moving an item into a collection) also move the
    record's ``updated_at``.  When nothing else in the synced content changed,
    the last synced ``updated_at`` is kept so the change is not a sync edit.
    """
    wrapper = _wrapper(ns, record, scope)
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


def _raw_meta(payload: Mapping[str, Any], scope: _Scope | None) -> Any:
    if scope is None:
        return payload.get("sync_meta")
    shares = payload.get(SHARE_META_KEY)
    if shares is None:
        return None
    if not isinstance(shares, dict):
        raise BridgeError("Sync metadata is malformed")
    return shares.get(scope.collection_id)


def _load_meta(payload: Mapping[str, Any], scope: _Scope | None = None) -> dict[str, dict[str, Any]]:
    """Validated deep copy of ``sync_meta["items"]`` (or the share's); fail closed on anything odd."""
    raw = _raw_meta(payload, scope)
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


def _store_meta(payload: dict[str, Any], device_id: str, meta: dict[str, dict[str, Any]],
                scope: _Scope | None = None) -> None:
    if len(meta) > MAX_SYNC_RECORDS:
        raise BridgeError("Sync metadata exceeds its bound")
    value = {"device_id": device_id, "items": dict(sorted(meta.items()))}
    if scope is None:
        payload["sync_meta"] = value
        return
    shares = payload.get(SHARE_META_KEY)
    shares = dict(shares) if isinstance(shares, dict) else {}
    shares[scope.collection_id] = value
    payload[SHARE_META_KEY] = shares


def forget_share_meta(payload: dict[str, Any], collection_id: str) -> None:
    """Drop a share's bookkeeping (the device left the share group); the caller saves."""
    shares = payload.get(SHARE_META_KEY)
    if isinstance(shares, dict) and collection_id in shares:
        shares = {k: v for k, v in shares.items() if k != collection_id}
        if shares:
            payload[SHARE_META_KEY] = shares
        else:
            payload.pop(SHARE_META_KEY, None)


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


def licenses_in_views(views: Iterable[Any]) -> tuple[dict[str, Any], ...]:
    """The verified, unrevoked licence bundles peer *views* carry; touches no vault.

    For licence-only sync on a free PC (``SyncService(licence_only=True)``):
    only live states in the ``license`` namespace whose bundle verifies and
    hashes to its state id count; every other state is ignored.  At most
    ``MAX_SYNC_LICENSES`` per view.
    """
    out: list[dict[str, Any]] = []
    for view in views:
        found = 0
        for state in getattr(view, "states", ()) or ():
            if found >= MAX_SYNC_LICENSES:
                break
            if not isinstance(state, ItemState) or state.deleted or not _is_license_id(state.item_id):
                continue
            item = state.item
            if not isinstance(item, dict) or item.get("ns") != LICENSE_NS or "updated_at" not in item:
                continue
            if _quiet_license(state):
                continue  # revoked, or no licence keys in this build
            try:
                out.append(_unwrap_license(state, item, is_copy=False))
            except BridgeError:
                continue
            found += 1
    return tuple(out)


def _json_copy(value: Any) -> Any:
    """A plain-JSON deep copy of *value* (canonical round trip)."""
    return json.loads(canonical_json(value))


# --- personal collections (module docstring "Personal collections") ---------------------


def is_collection_state_id(item_id: Any) -> bool:
    """Whether *item_id* names a collection state (catalog row, membership or share link)."""
    return isinstance(item_id, str) and item_id.startswith(COLLECTION_ID_PREFIXES)


def _is_reserved_id(item_id: Any) -> bool:
    """Ids no entry or item may use: licence states, the emergency access plan and collection states."""
    return _is_license_id(item_id) or _is_heir_id(item_id) or is_collection_state_id(item_id)


def _canonical_uuid(value: Any) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _collection_wrapper(record: Mapping[str, Any]) -> dict[str, Any]:
    rec = copy.deepcopy(dict(record))
    return {"ns": COLLECTION_NS, "schema": ITEM_WRAPPER_SCHEMA, "updated_at": _rank_updated_at(rec), "record": rec}


def _catalog_record(row: Mapping[str, Any]) -> dict[str, Any]:
    """The synced part of a collection row: never ``revision``, ``starter`` or ``shared_group_id``.

    The row id travels as ``collection_id`` (a sealed record's ``id`` must equal its state id).
    """
    return {"kind": "collection", "collection_id": row["id"],
            **{name: row[name] for name in _CATALOG_FIELDS if name != "id"}}


def _collection_row_of(record: Mapping[str, Any]) -> dict[str, Any]:
    """The row fields a catalog record carries (``_catalog_record`` reversed)."""
    return {"id": record["collection_id"], **{name: record[name] for name in _CATALOG_FIELDS if name != "id"}}


def _membership_record(item_id: str, collection_ids: Iterable[str]) -> dict[str, Any]:
    return {"kind": "membership", "item_id": item_id, "collection_ids": sorted(set(collection_ids))}


def _link_record(collection_id: str, link: Mapping[str, Any]) -> dict[str, Any]:
    return {"kind": "share-link", "collection_id": collection_id, "mode": link["mode"], "role": link["role"]}


def _link_beats(mine: Mapping[str, Any], theirs: Mapping[str, Any]) -> bool:
    """Whether link record *mine* wins over *theirs* when two of this person's devices share one collection (final
    review B1): the owner role over a member's, then the larger canonical record. The same on every device, so the
    two stop republishing over each other: only the winner's link is published, the loser relays it."""
    def rank(record: Mapping[str, Any]) -> tuple[bool, bytes]:
        return record["role"] == "owner", canonical_json(record)

    return rank(mine) > rank(theirs)


def _check_collection_record(state_id: str, record: Any) -> dict[str, Any]:
    """A private copy of a collection state's record; ``BridgeError`` unless it is exactly well formed."""
    bad = BridgeError(f"Sync state {state_id!r} is malformed")
    if not isinstance(record, dict):
        raise bad
    kind = record.get("kind")
    if kind == "collection":
        if set(record) != {"kind", "collection_id", *_CATALOG_FIELDS} - {"id"}:
            raise bad
        try:
            row = validate_collections([{**_collection_row_of(record), "revision": 1, "starter": False}])[0]
        except ItemSchemaError:
            raise bad from None
        out = _catalog_record(row)
        if out != record or state_id != CATALOG_ID_PREFIX + row["id"]:
            raise bad
        return out
    if kind == "membership":
        ids = record.get("collection_ids")
        if (set(record) != {"kind", "item_id", "collection_ids"} or not _canonical_uuid(record["item_id"])
                or state_id != MEMBERSHIP_ID_PREFIX + record["item_id"] or not isinstance(ids, list)
                or not 1 <= len(ids) <= MAX_COLLECTION_MEMBERSHIPS or ids != sorted(set(ids))
                or not all(_canonical_uuid(c) for c in ids)):
            raise bad
        return copy.deepcopy(record)
    if kind == "share-link":
        if (set(record) != {"kind", "collection_id", "mode", "role"} or not _canonical_uuid(record["collection_id"])
                or state_id != LINK_ID_PREFIX + record["collection_id"] or record["mode"] not in _LINK_MODES
                or record["role"] not in _LINK_ROLES):
            raise bad
        return copy.deepcopy(record)
    raise bad


def _stored_links(payload: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    """The share links this vault learned from its other devices (malformed entries are ignored)."""
    raw = payload.get(LINKS_KEY)
    out: dict[str, dict[str, str]] = {}
    if isinstance(raw, dict):
        for cid, link in raw.items():
            if (_canonical_uuid(cid) and isinstance(link, dict) and set(link) == {"mode", "role"}
                    and link["mode"] in _LINK_MODES and link["role"] in _LINK_ROLES):
                out[cid] = {"mode": link["mode"], "role": link["role"]}
    return out


def _own_links(session: Any) -> dict[str, dict[str, str]] | None:
    """{collection_id: link} of the collections shared on this device (it speaks for them), None if unreadable."""
    from .share_group import share_links

    return share_links(session)


def _collection_rows(payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    rows = payload.get("collections", [])
    if not isinstance(rows, list):
        raise BridgeError("Vault collections are malformed")
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise BridgeError("Vault collections are malformed")
        out[row["id"]] = row
    return out


@dataclass
class _CollectionView:
    """What this device publishes in the collection namespace (``_collection_view``)."""

    own: dict[str, dict[str, Any]]  # state id -> wrapper this device stands for (bumped when it changes)
    relay: dict[str, dict[str, Any]]  # share links learned from another device: republished as received, never bumped
    quiet: set[str]  # ids to leave alone this run (no state, meta untouched)
    links_known: bool  # False: this device's own share links could not be read (no link is tombstoned)


def _collection_view(session: Any, payload: Mapping[str, Any],
                     live: Mapping[str, tuple[str, dict[str, Any]]], skipped: Mapping[str, str]) -> _CollectionView:
    """The collection states of this vault: every catalog row, one membership per item in a collection,
    one share link per collection shared on this device; learned links are relayed."""
    own: dict[str, dict[str, Any]] = {}
    quiet: set[str] = set()
    rows = _collection_rows(payload)
    for cid, row in rows.items():
        sid = CATALOG_ID_PREFIX + cid
        try:
            own[sid] = _collection_wrapper(_check_collection_record(sid, _catalog_record(row)))
        except (BridgeError, KeyError):
            quiet.add(sid)
    for item_id, (ns, record) in live.items():
        sid = MEMBERSHIP_ID_PREFIX + item_id
        if ns != "item":
            continue
        ids = record.get("collection_ids") or []
        if item_id in skipped or not isinstance(ids, list):
            quiet.add(sid)
            continue
        if not ids:
            continue
        try:
            own[sid] = _collection_wrapper(_check_collection_record(sid, _membership_record(item_id, ids)))
        except BridgeError:
            quiet.add(sid)
    links = _own_links(session)
    stored = _stored_links(payload)
    for cid, link in (links or {}).items():
        if cid in rows:
            other = stored.get(cid)
            if other is not None and other != link and not _link_beats(_link_record(cid, link),
                                                                       _link_record(cid, other)):
                continue  # another of this person's devices shares it too and its link wins: relayed (B1)
            own[LINK_ID_PREFIX + cid] = _collection_wrapper(_link_record(cid, link))
    relay = {LINK_ID_PREFIX + cid: _collection_wrapper(_link_record(cid, link))
             for cid, link in stored.items() if LINK_ID_PREFIX + cid not in own}
    return _CollectionView(own, relay, quiet, links is not None)


# --- emergency access plan (namespace "heir") ----------------------------------------------


def _is_heir_id(item_id: Any) -> bool:
    return item_id == HEIR_STATE_ID


def _heir_record(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    prefs = payload.get("preferences")
    value = prefs.get(_HEIR_PREF) if isinstance(prefs, dict) else None
    return value if isinstance(value, dict) else None


def _heir_wrapper(synced: Mapping[str, Any]) -> dict[str, Any]:
    return {"ns": HEIR_NS, "schema": ITEM_WRAPPER_SCHEMA, "updated_at": synced["created"],
            "record": _json_copy(dict(synced))}


def _local_heir_wrapper(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    """The synced wrapper of this vault's plan, ``None`` without one; a damaged plan raises ``BridgeError``."""
    from .. import heir

    record = _heir_record(payload)
    if record is None:
        return None
    try:
        return _heir_wrapper(heir.synced_record(record))
    except heir.HeirError:
        raise BridgeError("The emergency access plan is damaged") from None


def _unwrap_heir(state: ItemState, item: Mapping[str, Any], *, is_copy: bool) -> dict[str, Any]:
    """The checked synced plan record of a ``heir`` state (a conflict copy keeps its own id)."""
    from .. import heir

    if (not is_copy and ("id" in item or not _is_heir_id(state.item_id))) or (is_copy and _is_heir_id(state.item_id)):
        raise BridgeError(f"Emergency access state {state.item_id!r} is malformed")
    record = item["record"]
    try:
        heir.merge_synced(None, record)
    except (heir.HeirError, TypeError, ValueError):
        raise BridgeError(f"Emergency access state {state.item_id!r} is malformed") from None
    if type(item["updated_at"]) is not int or item["updated_at"] != record["created"]:
        raise BridgeError(f"Emergency access state {state.item_id!r} has a rank that does not match its record")
    return _json_copy(record)


def _store_heir(payload: dict[str, Any], incoming: Mapping[str, Any]) -> dict[str, Any]:
    """Merge a remote synced plan into this vault's plan; returns the stored record's synced wrapper."""
    from .. import heir

    try:
        stored = heir.merge_synced(_heir_record(payload), incoming)
    except heir.HeirError:
        raise BridgeError("The emergency access plan cannot be merged") from None
    prefs = payload.get("preferences")
    if not isinstance(prefs, dict):
        prefs = payload["preferences"] = {}
    prefs[_HEIR_PREF] = stored
    return _heir_wrapper(heir.synced_record(stored))


# --- local_view --------------------------------------------------------------------------

#: ``LocalView.skipped`` reason of an item whose stored vector cannot be bumped (audit M-6).
COUNTER_OVERFLOW = "version counter overflow"


def _bumped(vv: Mapping[str, int], device_id: str) -> dict[str, int] | None:
    """``bump(vv, device_id)``, or None when this device's counter would overflow."""
    if vv.get(device_id, 0) >= _MAX_INT53:
        return None
    return bump(vv, device_id)


def local_view(session: Any, lease: Any, *, device_id: str, now: int, collection_id: str | None = None,
               collections: bool = False) -> LocalView:
    """Engine states for every synced record and tombstone, documents included (``_local_view``).

    With *collection_id*: the view of that collection's share group (module docstring), no documents.
    With *collections* (personal group only, every peer of the run reads them): the collection
    states too (module docstring "Personal collections"); without, they are left alone.
    """
    if collection_id is not None:
        _check_lease(session, lease)
    scope = _scope_for(session, collection_id)
    if scope is not None:
        return _local_view(session, lease, device_id=device_id, now=now, scope=scope)
    with _documents(session):
        return _local_view(session, lease, device_id=device_id, now=now, collections=collections)


def _shared_records(payload: Mapping[str, Any], scope: _Scope) -> dict[str, tuple[str, dict[str, Any]]]:
    """The live typed items tagged with the share's collection (documents never: no ``_documents``)."""
    return {item_id: (ns, record) for item_id, (ns, record) in _live_records(payload).items()
            if ns == "item" and record.get("kind") not in UNSYNCED_ITEM_KINDS and _tagged(record, scope)}


def _local_view(session: Any, lease: Any, *, device_id: str, now: int, scope: _Scope | None = None,
                collections: bool = False) -> LocalView:
    """Engine states for every synced record and tombstone; persists changed meta.

    A live record that fails validation is skipped (``result.skipped``): it
    gets no state and its meta is left alone, so it is never turned into a
    tombstone and every other record still syncs.
    """
    _check_lease(session, lease)
    _check_device(device_id)
    _check_now(now)
    payload = session._require_typed_catalog()
    stored_meta = _load_meta(payload, scope)
    meta = prune_tombstones(stored_meta, now)
    states: dict[str, ItemState] = {}
    skipped: dict[str, str] = {}
    live = _live_records(payload) if scope is None else _shared_records(payload, scope)
    licenses = _published_licenses(payload) if scope is None else {}
    read_only = scope is not None and scope.read_only
    try:
        for item_id, (ns, record) in live.items():
            m = meta.get(item_id)
            if not is_valid_id(item_id) or _is_reserved_id(item_id):
                skipped[item_id] = "invalid-id"
                continue
            try:
                wrapper = _view_wrapper(ns, record, m, scope)
            except BridgeError as exc:
                skipped[item_id] = str(exc)
                continue
            if m is None or m["deleted"] or m["digest"] != wrapper_digest(wrapper):
                if read_only:  # a local change of a read-only share is never published
                    continue
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
        if scope is None:  # the plan is never published to a share group
            _heir_state(payload, meta, states, skipped, device_id, now)
        for item_id, m in list(meta.items()):
            if item_id in live:  # includes skipped records: they are live, just unreadable
                continue
            if _is_license_id(item_id):  # a licence is never deleted: one no longer published just goes quiet
                continue
            if is_collection_state_id(item_id):  # collection states: ``_collection_states`` below
                continue
            if _is_heir_id(item_id):  # the plan's own state (``_heir_state``)
                continue
            if not is_valid_id(item_id):  # stale meta under an unsyncable id: leave it alone
                continue
            if not m["deleted"]:
                if read_only:  # a local delete or untag of a read-only share is never published
                    continue
                vv = _bumped(m["vv"], device_id)
                if vv is None:  # cannot record the delete without an overflow: publish nothing for it
                    continue
                m = _tomb_meta(vv, now)
                meta[item_id] = m
            states[item_id] = ItemState(item_id, m["vv"], True, m["deleted_at"], None)
        if scope is None and collections:
            meta = _collection_states(session, payload, live, skipped, meta, states, device_id, now)
    except EngineError as exc:
        raise BridgeError(f"Vault content cannot be synced: {exc}") from None
    if len(meta) > MAX_SYNC_RECORDS:
        raise BridgeError("Sync metadata exceeds its bound")
    current = _raw_meta(payload, scope)
    if meta != stored_meta or not isinstance(current, dict) or current.get("device_id") != device_id:
        with sync_only_save(session), session.transaction():
            payload = session._require_typed_catalog()
            _store_meta(payload, device_id, meta, scope)
            _check_lease(session, lease)
    return LocalView(states, skipped)


def _collection_states(session: Any, payload: Mapping[str, Any], live: Mapping[str, tuple[str, dict[str, Any]]],
                       skipped: Mapping[str, str], meta: dict[str, dict[str, Any]], states: dict[str, ItemState],
                       device_id: str, now: int) -> dict[str, dict[str, Any]]:
    """Add the collection states to *states*; returns the meta to store.

    A change of a state this device stands for is a local edit (bumped vector), a state it no longer
    has becomes a tombstone.  A relayed share link is published only exactly as it was received.
    When the view would exceed ``MAX_SYNC_RECORDS`` no collection state is published and their meta
    is left as it was (collections wait; everything else still syncs).
    """
    view = _collection_view(session, payload, live, skipped)
    work = dict(meta)
    found: dict[str, ItemState] = {}
    for item_id, wrapper in view.own.items():
        m = work.get(item_id)
        if m is None or m["deleted"] or m["digest"] != wrapper_digest(wrapper):
            vv = _bumped(m["vv"] if m else {}, device_id)
            if vv is None:
                continue
            m = work[item_id] = _live_meta(wrapper, vv)
        found[item_id] = ItemState(item_id, m["vv"], False, None, wrapper)
    for item_id, wrapper in view.relay.items():
        m = work.get(item_id)
        if m is not None and not m["deleted"] and m["digest"] == wrapper_digest(wrapper):
            found[item_id] = ItemState(item_id, m["vv"], False, None, wrapper)
    for item_id, m in list(work.items()):
        if not is_collection_state_id(item_id) or item_id in view.own or item_id in view.quiet:
            continue
        if item_id in view.relay:
            continue  # a relayed link that changed here (not as received) goes quiet until it comes again
        if item_id.startswith(LINK_ID_PREFIX) and not view.links_known:
            continue
        if not m["deleted"]:
            vv = _bumped(m["vv"], device_id)
            if vv is None:
                continue
            m = work[item_id] = _tomb_meta(vv, now)
        found[item_id] = ItemState(item_id, m["vv"], True, m["deleted_at"], None)
    if len(states) + len(found) > MAX_SYNC_RECORDS or len(work) > MAX_SYNC_RECORDS:
        return meta
    states.update(found)
    return work


def _heir_state(payload: Mapping[str, Any], meta: dict[str, dict[str, Any]], states: dict[str, ItemState],
                skipped: dict[str, str], device_id: str, now: int) -> None:
    """The plan's state for ``local_view``: live (bumped when changed here), a tombstone once removed, or none."""
    try:
        wrapper = _local_heir_wrapper(payload)
    except BridgeError as exc:
        skipped[HEIR_STATE_ID] = str(exc)  # a damaged plan is never published, nor deleted elsewhere
        return
    m = meta.get(HEIR_STATE_ID)
    if wrapper is not None:
        if m is None or m["deleted"] or m["digest"] != wrapper_digest(wrapper):
            vv = _bumped(m["vv"] if m else {}, device_id)
            if vv is None:
                skipped[HEIR_STATE_ID] = COUNTER_OVERFLOW
                return
            m = _live_meta(wrapper, vv)
            meta[HEIR_STATE_ID] = m
        states[HEIR_STATE_ID] = ItemState(HEIR_STATE_ID, m["vv"], False, None, wrapper)
        return
    if m is None:
        return
    if not m["deleted"]:
        vv = _bumped(m["vv"], device_id)
        if vv is None:
            return
        m = _tomb_meta(vv, now)
        meta[HEIR_STATE_ID] = m
    states[HEIR_STATE_ID] = ItemState(HEIR_STATE_ID, m["vv"], True, m["deleted_at"], None)


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
    document = (_documents_on() and isinstance(item, dict) and isinstance(item.get("record"), dict)
                and item.get("ns") == "item" and item["record"].get("kind") == DOCUMENT_KIND)
    if document:
        required = required | {"attachment"}
        allowed = allowed | {"attachment"}
    if not isinstance(item, dict) or not required <= set(item) or set(item) - allowed:
        raise BridgeError(f"Sync state {state.item_id!r} is malformed")
    if type(schema) is not int or schema < 1:
        raise BridgeError(f"Sync state {state.item_id!r} is malformed")
    ns, record = item["ns"], item["record"]
    if ns == LICENSE_NS:
        return ns, _unwrap_license(state, item, is_copy=is_copy)
    if ns == COLLECTION_NS:
        return ns, _unwrap_collection(state, item, is_copy=is_copy)
    if ns == HEIR_NS:
        return ns, _unwrap_heir(state, item, is_copy=is_copy)
    if ns not in ("entry", "item") or not isinstance(record, dict) or _is_reserved_id(state.item_id):
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
        if not document:
            raise BridgeError(f"Sync state {state.item_id!r} is a kind that does not sync")
        _check_remote_document(item, record, state.item_id)
    return ns, record


def _unwrap_collection(state: ItemState, item: Mapping[str, Any], *, is_copy: bool) -> dict[str, Any]:
    """The checked record of a collection state (of a conflict copy: the record it was a copy of)."""
    record = item["record"]
    if is_copy:
        if item.get("id") != state.item_id:
            raise BridgeError(f"Sync conflict copy {state.item_id!r} is malformed")
        kind = record.get("kind") if isinstance(record, dict) else None
        key = {"collection": ("collection_id", CATALOG_ID_PREFIX), "membership": ("item_id", MEMBERSHIP_ID_PREFIX),
               "share-link": ("collection_id", LINK_ID_PREFIX)}.get(kind) if isinstance(kind, str) else None
        if key is None or not isinstance(record.get(key[0]), str):
            raise BridgeError(f"Sync state {state.item_id!r} is malformed")
        state_id = key[1] + record[key[0]]
    else:
        state_id = state.item_id
        if not is_collection_state_id(state_id):
            raise BridgeError(f"Sync state {state_id!r} is malformed")
    record = _check_collection_record(state_id, record)
    if item["updated_at"] != _rank_updated_at(record) or type(item["updated_at"]) is not int:
        raise BridgeError(f"Sync state {state.item_id!r} has a rank that does not match its record")
    return record


def _without_local_fields(ns: str, record: Mapping[str, Any], scope: _Scope | None = None) -> dict[str, Any]:
    """A copy of a remote record without the fields ``apply`` replaces with this device's own.

    In a share the collection tag is kept: it is part of what the peer published (and checked).
    """
    rec = copy.deepcopy(dict(record))
    if ns == "entry":
        _strip_entry_local(rec)
        return rec
    for name in (LOCAL_ONLY_ITEM_FIELDS if scope is None else SHARE_LOCAL_ONLY_ITEM_FIELDS):
        rec.pop(name, None)
    payload = rec.get("payload")
    if isinstance(payload, dict):
        for name in LOCAL_ONLY_ITEM_PAYLOAD_FIELDS:
            payload.pop(name, None)
    return rec


def _check_share_record(state: ItemState, ns: str, record: Mapping[str, Any], scope: _Scope | None) -> None:
    """In a share, a remote record must be a typed item that claims exactly the share's collection."""
    if scope is None:
        return
    if ns != "item":
        raise BridgeError(f"Sync state {state.item_id!r} is not an item of the shared collection",
                          item_id=state.item_id)
    if record.get("collection_ids") != [scope.collection_id]:
        raise BridgeError(f"Sync state {state.item_id!r} claims another collection", item_id=state.item_id)


def _unwrap_remote(state: ItemState, scope: _Scope | None = None) -> tuple[str, dict[str, Any]]:
    """``_unwrap`` of a live remote upsert, with its record normalised as ``apply`` will store it.

    Local-only fields are stripped before the check: ``apply`` drops whatever a peer
    sent there (each device keeps its own), so a bad value in one never refuses the record.
    """
    ns, record = _unwrap(state, is_copy=False)
    _check_share_record(state, ns, record, scope)
    if ns not in (LICENSE_NS, COLLECTION_NS, HEIR_NS):
        try:
            normal_form(ns, _without_local_fields(ns, record, scope), scope)
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
    out = {"ns": ns, "schema": ITEM_WRAPPER_SCHEMA, "updated_at": _rank_updated_at(record),
           "record": copy.deepcopy(dict(record))}
    if ns == "item" and record.get("kind") == DOCUMENT_KIND and _documents_on():
        out["attachment"] = _document_ref(record)
    return out


def _history_error(exc: HistoryError) -> BridgeError:
    if isinstance(exc, HistoryQuotaError):
        return BridgeError(f"Item history is full ({exc}); remove old versions and sync again",
                           reason="history-quota")
    return BridgeError(f"Item history could not be updated: {exc}", reason="history-error")


class _Applier:
    def __init__(self, session: Any, payload: dict[str, Any], meta: dict[str, dict[str, Any]],
                 licenses: Mapping[str, dict[str, Any]], scope: _Scope | None = None,
                 read_only: frozenset[str] = frozenset()) -> None:
        self.scope = scope
        self.read_only = read_only  # personal group: collections this device holds in a read-only share
        self.session = session
        self.payload = payload
        self.meta = meta
        self.live = _live_records(payload)
        self.trash = _trash_index(payload)
        self.collections = {row["id"] for row in payload.get("collections", [])
                            if isinstance(row, dict) and isinstance(row.get("id"), str)}
        self.licenses = dict(licenses)  # published licence wrappers, taken once per apply

    def _shared(self, item_id: str, record: Any) -> bool:
        """In a share: whether *record* (the local record of *item_id*) belongs to the share.

        It does when it is tagged with the collection, or when this share last saw *item_id* live
        (shared content the user untagged or trashed here).  Anything else is a personal record that
        no share peer may replace or delete.
        """
        if self.scope is None:
            return False
        m = self.meta.get(item_id)
        return _tagged(record, self.scope) or (m is not None and not m["deleted"])

    def protected(self, item_id: str) -> bool:
        """Personal group: *item_id* is live here in a collection this device holds read-only (a share).

        Another of this person's devices (which may not know the share) cannot edit or delete it here.
        """
        if self.scope is not None or not self.read_only:
            return False
        current = self.live.get(item_id)
        ids = current[1].get("collection_ids") if current is not None and current[0] == "item" else None
        return isinstance(ids, list) and not self.read_only.isdisjoint(ids)

    def current_wrapper(self, item_id: str) -> dict[str, Any]:
        """The wrapper this device publishes for its live record *item_id*."""
        return _view_wrapper(*self.live[item_id], self.meta.get(item_id), self.scope)

    def untagged_here(self, item_id: str) -> bool:
        """In a share: this device untagged *item_id* (live here, untagged, a tombstone in the share).

        A peer that edited the item meanwhile keeps sending it; that upsert is skipped quietly and
        the tombstone stays published, so the item never returns into the share from here.
        """
        if self.scope is None:
            return False
        current = self.live.get(item_id)
        m = self.meta.get(item_id)
        return (current is not None and not _tagged(current[1], self.scope)
                and m is not None and bool(m["deleted"]))

    def check_fresh(self, item_id: str) -> None:
        """Refuse to apply over a local change that the merged view did not include."""
        if _is_license_id(item_id):
            return  # licences are only ever added, never edited or removed by apply
        if _is_heir_id(item_id):
            m = self.meta.get(item_id)
            current = _local_heir_wrapper(self.payload)
            if m is None or m["deleted"]:
                fresh = current is None
            else:
                fresh = current is not None and wrapper_digest(current) == m["digest"]
            if not fresh:
                raise BridgeError("The vault changed since the sync view was taken; sync again",
                                  reason="vault-changed", item_id=item_id)
            return
        m = self.meta.get(item_id)
        current = self.live.get(item_id)
        if self.scope is not None:
            if self.scope.read_only:
                return  # read-only: the owner's version replaces any local change
            if current is not None and not _tagged(current[1], self.scope):
                current = None  # not in the share view (personal, or untagged: a tombstone there)
        if m is None or m["deleted"]:
            fresh = current is None
        else:
            fresh = current is not None and wrapper_digest(_view_wrapper(*current, m, self.scope)) == m["digest"]
        if not fresh:
            raise BridgeError("The vault changed since the sync view was taken; sync again",
                              reason="vault-changed", item_id=item_id)

    def delete(self, item_id: str) -> bool:
        current = self.live.get(item_id)
        if current is None:
            return False
        if self.scope is not None and not _tagged(current[1], self.scope):
            return False  # a share deletes only what is in its collection; personal records stay
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
        if self.scope is not None:
            if ns != "item":
                raise BridgeError(f"Record {item_id!r} is not an item of the shared collection")
            if local is not None and not self._shared(item_id, local):
                raise BridgeError(f"Record id {item_id!r} belongs to an item outside the shared collection")
        try:
            record = self._with_local_fields(ns, incoming, local)
        except (VaultError, ItemSchemaError, TotpError) as exc:
            raise BridgeError(f"Remote record {item_id!r} is invalid: {exc}") from None
        stored = _wrapper(ns, record, self.scope)
        if current is not None and _view_wrapper(*current, self.meta.get(item_id), self.scope) == stored:
            return stored, False
        rows = self.payload.setdefault("entries" if ns == "entry" else "items", [])
        if current is not None:
            if ns == "item":
                self._snapshot(current[1])
            else:
                mark = getattr(self.session, "mark_history_change", None)
                if callable(mark):
                    mark([item_id], "sync")  # login history row (feature pack 2026-11-15, 1.3)
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
            # A peer never sends a passkey's unconfirmed mark (those stay local); one that does would hide the
            # passkey here and make this device publish a tombstone for it.
            typed.pop("unconfirmed", None)
        current_revision = local.get("revision", 0) if local is not None else 0
        if type(current_revision) is not int or not 0 <= current_revision < _MAX_INT63:
            current_revision = 0
        record["revision"] = current_revision + 1
        kept = local.get("collection_ids", []) if local is not None else []
        record["collection_ids"] = [c for c in kept if c in self.collections] if isinstance(kept, list) else []
        if self.scope is not None:
            if self.scope.collection_id not in record["collection_ids"]:
                # Incoming items land in the shared collection (and keep this device's own others).
                record["collection_ids"].append(self.scope.collection_id)
            # Tags and favourites are personal: this device's own (none for a new item), never the peer's.
            record["tags"] = copy.deepcopy(local.get("tags", [])) if local is not None else []
            record["favorite"] = local.get("favorite", False) if local is not None else False
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


def _unique_name(name: str, taken: Iterable[str]) -> str:
    """*name*, or *name* with the first free " (n)" suffix (collection names are unique, ignoring case)."""
    used = {t.casefold() for t in taken}
    candidate, n = name, 2
    while candidate.casefold() in used:
        suffix = f" ({n})"
        candidate = name[:100 - len(suffix)].rstrip() + suffix
        n += 1
    return candidate


class _Collections:
    """Applies the collection states of one personal-group outcome (module docstring "Personal collections").

    Runs inside ``_apply``'s transaction: catalog rows before the items, memberships and share links after.
    """

    def __init__(self, session: Any, payload: dict[str, Any], meta: dict[str, dict[str, Any]],
                 device_id: str, read_only: frozenset[str], now: int) -> None:
        self.session = session
        self.now = now
        self.payload = payload
        self.meta = meta
        self.device_id = device_id
        self.read_only = read_only  # this device is a member of these read-only shares: they never change here
        self.rows = _collection_rows(payload)
        self.links = _stored_links(payload)
        self.own_links = _own_links(session)

    # --- what this device publishes now (for the freshness check) ---

    def _current(self, state_id: str, live: Mapping[str, tuple[str, dict[str, Any]]]) -> dict[str, Any] | None:
        if state_id.startswith(CATALOG_ID_PREFIX):
            row = self.rows.get(state_id[len(CATALOG_ID_PREFIX):])
            return None if row is None else _collection_wrapper(_catalog_record(row))
        current = live.get(state_id[len(MEMBERSHIP_ID_PREFIX):])
        ids = current[1].get("collection_ids") if current is not None and current[0] == "item" else None
        return _collection_wrapper(_membership_record(current[1]["id"], ids)) if ids else None

    def check_fresh(self, state_id: str, live: Mapping[str, tuple[str, dict[str, Any]]]) -> None:
        """Refuse to apply over a catalog row or membership changed since the view was taken."""
        if state_id.startswith(LINK_ID_PREFIX):
            return  # links change only here and through the share actions
        m = self.meta.get(state_id)
        current = self._current(state_id, live)
        if m is None or m["deleted"]:
            fresh = current is None
        else:
            fresh = current is not None and wrapper_digest(current) == m["digest"]
        if not fresh:
            raise BridgeError("The vault changed since the sync view was taken; sync again",
                              reason="vault-changed", item_id=state_id)

    def _room(self, state_id: str) -> bool:
        return state_id in self.meta or len(self.meta) < MAX_SYNC_RECORDS

    def _save_rows(self) -> None:
        self.payload["collections"] = validate_collections(list(self.rows.values()))
        self.rows = _collection_rows(self.payload)

    def _save_links(self) -> None:
        if self.links:
            self.payload[LINKS_KEY] = {cid: dict(link) for cid, link in sorted(self.links.items())}
        else:
            self.payload.pop(LINKS_KEY, None)

    def _keep(self, state_id: str, wrapper: dict[str, Any], vv: Mapping[str, int]) -> None:
        """This device's version wins over *vv*: published above it."""
        self.meta[state_id] = _live_meta(wrapper, bump(vv, self.device_id))

    # --- catalog rows ---

    def catalog_upsert(self, state: ItemState, record: dict[str, Any]) -> bool:
        cid, sid = record["collection_id"], state.item_id
        row = self.rows.get(cid)
        if (row is None and len(self.rows) >= MAX_COLLECTIONS) or not self._room(sid):
            return False  # no room: the row waits (no meta), everything else applies
        if row is not None and cid in self.read_only:
            # A read-only share's row never changes from another device: this device's row is republished.
            mine = _collection_wrapper(_catalog_record(row))
            vv = state.vv if mine == _collection_wrapper(record) else bump(state.vv, self.device_id)
            self.meta[sid] = _live_meta(mine, vv)
            return False
        new = dict(row) if row is not None else {"revision": 0, "starter": False}
        new.update(_collection_row_of(record))
        revision = new.get("revision", 0)
        new["revision"] = (revision if type(revision) is int and 0 <= revision < _MAX_INT63 else 0) + 1
        other = next((r for r in self.rows.values() if r["id"] != cid
                      and r["name"].casefold() == new["name"].casefold()), None)
        if other is not None:
            # Two collections of one name (made on two devices): the larger id gets a number, the same
            # on every device, and its updated_at stays, so devices that rename alike agree.
            names = [r["name"] for r in self.rows.values() if r["id"] not in (cid, other["id"])]
            if cid > other["id"]:
                new["name"] = _unique_name(new["name"], [*names, other["name"]])
            else:
                renamed = dict(other)
                renamed["name"] = _unique_name(other["name"], [*names, new["name"]])
                self.rows[other["id"]] = renamed
        self.rows[cid] = new
        self._save_rows()
        stored = _collection_wrapper(_catalog_record(self.rows[cid]))
        vv = state.vv if stored == _collection_wrapper(record) else bump(state.vv, self.device_id)
        self.meta[sid] = _live_meta(stored, vv)
        return row is None or _catalog_record(row) != _catalog_record(self.rows[cid])

    def catalog_delete(self, state: ItemState, at: int) -> bool:
        cid, sid = state.item_id[len(CATALOG_ID_PREFIX):], state.item_id
        row = self.rows.get(cid)
        if row is not None and row.get("shared_group_id"):
            # Shared on this device: only leaving the share removes it here; this row is republished.
            self._keep(sid, _collection_wrapper(_catalog_record(row)), state.vv)
            return False
        if not self._room(sid):
            return False
        self.meta[sid] = _tomb_meta(state.vv, at)
        if row is None:
            return False
        del self.rows[cid]
        self._save_rows()
        # As CollectionService.delete: the items stay, only their membership goes (trash included).
        records = [r for r in self.payload.get("items", []) if isinstance(r, dict)]
        records += [r["entry"] for r in self.payload.get("trash", [])
                    if isinstance(r, dict) and isinstance(r.get("entry"), dict)]
        for record in records:
            ids = record.get("collection_ids")
            if isinstance(ids, list) and cid in ids:
                record["collection_ids"] = [c for c in ids if c != cid]
        if self.links.pop(cid, None) is not None:
            self._save_links()
        return True

    # --- memberships ---

    def _target(self, wanted: Iterable[str], current: list[str]) -> list[str] | None:
        """The membership to store: *wanted* minus unknown and read-only-share collections, plus this
        device's own read-only-share ones; None while a wanted collection is not known here yet."""
        known: list[str] = []
        for cid in wanted:
            if cid in self.rows:
                known.append(cid)
                continue
            m = self.meta.get(CATALOG_ID_PREFIX + cid)
            if m is None or not m["deleted"]:
                return None  # its catalog row has not arrived yet: wait (no meta)
        kept = [c for c in current if c in self.read_only]
        target = kept + [c for c in sorted(set(known)) if c not in self.read_only and c not in kept]
        return target if len(target) <= MAX_COLLECTION_MEMBERSHIPS else None

    @staticmethod
    def _set_membership(record: dict[str, Any], target: list[str]) -> bool:
        current = list(record.get("collection_ids") or [])
        if set(current) == set(target):
            return False
        record["collection_ids"] = [c for c in current if c in target] + [c for c in target if c not in current]
        revision = record.get("revision", 0)
        record["revision"] = (revision if type(revision) is int and 0 <= revision < _MAX_INT63 else 0) + 1
        return True

    def membership_upsert(self, state: ItemState, record: dict[str, Any], live: Mapping[str, Any],
                          union: bool = False) -> bool:
        sid = MEMBERSHIP_ID_PREFIX + record["item_id"]
        current = live.get(record["item_id"])
        if current is None or current[0] != "item" or not self._room(sid):
            return False  # the item is not here (yet): the membership waits
        item = current[1]
        have = list(item.get("collection_ids") or [])
        wanted = [*have, *record["collection_ids"]] if union else record["collection_ids"]
        target = self._target(wanted, have)
        if target is None:
            return False
        changed = self._set_membership(item, target)
        stored = _collection_wrapper(_membership_record(record["item_id"], target)) if target else None
        if union:
            if changed:
                m = self.meta.get(sid)
                self.meta[sid] = _live_meta(stored, bump(m["vv"] if m else {}, self.device_id))
            return changed
        if stored is None:
            self.meta[sid] = _tomb_meta(bump(state.vv, self.device_id), self.now)
        else:
            vv = state.vv if stored == _collection_wrapper(record) else bump(state.vv, self.device_id)
            self.meta[sid] = _live_meta(stored, vv)
        return changed

    def membership_delete(self, state: ItemState, at: int, live: Mapping[str, Any]) -> bool:
        sid = state.item_id
        if not self._room(sid):
            return False
        current = live.get(sid[len(MEMBERSHIP_ID_PREFIX):])
        if current is None or current[0] != "item":
            self.meta[sid] = _tomb_meta(state.vv, at)
            return False
        item = current[1]
        target = [c for c in (item.get("collection_ids") or []) if c in self.read_only]
        changed = self._set_membership(item, target)
        if target:
            self._keep(sid, _collection_wrapper(_membership_record(item["id"], target)), state.vv)
        else:
            self.meta[sid] = _tomb_meta(state.vv, at)
        return changed

    # --- share links ---

    def link_upsert(self, state: ItemState, record: dict[str, Any]) -> bool:
        cid, sid = record["collection_id"], state.item_id
        if not self._room(sid) or self.own_links is None:
            return False  # no room, or this device's own shares cannot be read: decide nothing now
        own = self.own_links.get(cid)
        link = {"mode": record["mode"], "role": record["role"]}
        if own is not None and cid in self.rows:
            mine = _link_record(cid, own)
            wrapper = _collection_wrapper(mine)
            if link == own:
                # The same link: no other device shares it differently (any such link stored here goes).
                changed = self.links.pop(cid, None) is not None
                if changed:
                    self._save_links()
                self.meta[sid] = _live_meta(wrapper, state.vv)
                return changed
            # Shared from two of this person's devices (final review B1). Both keep the other's link (the share
            # page warns); only the winner's is published: the winner republishes its own above, the loser
            # records the peer's vector and relays the winner's link as received, so the two stop.
            changed = self.links.get(cid) != link
            self.links[cid] = link
            self._save_links()
            if _link_beats(mine, _link_record(cid, link)):
                self._keep(sid, wrapper, state.vv)
            else:
                self.meta[sid] = _live_meta(_collection_wrapper(record), state.vv)
            return changed
        changed = self.links.get(cid) != link
        self.links[cid] = link
        self._save_links()
        self.meta[sid] = _live_meta(_collection_wrapper(record), state.vv)
        return changed

    def link_delete(self, state: ItemState, at: int) -> bool:
        cid, sid = state.item_id[len(LINK_ID_PREFIX):], state.item_id
        if not self._room(sid) or self.own_links is None:
            return False
        own = self.own_links.get(cid)
        if own is not None and cid in self.rows:
            # This device speaks for its own share; another device's link of it, if one was stored, is gone.
            changed = self.links.pop(cid, None) is not None
            if changed:
                self._save_links()
            self._keep(sid, _collection_wrapper(_link_record(cid, own)), state.vv)
            return changed
        changed = self.links.pop(cid, None) is not None
        if changed:
            self._save_links()
        self.meta[sid] = _tomb_meta(state.vv, at)
        return changed


def _is_collection_state(state: ItemState) -> bool:
    """A collection state, or a conflict copy of one (its id is a plain uuid)."""
    return is_collection_state_id(state.item_id) or (
        isinstance(state.item, dict) and state.item.get("ns") == COLLECTION_NS)


def apply(session: Any, lease: Any, outcome: MergeOutcome, *, device_id: str, now: int,
          collection_id: str | None = None, collections: bool = False) -> ApplyReport:
    """Write a merge outcome; a document only once its file was imported (``_apply``).

    With *collection_id*: an outcome of that collection's share group (module docstring).
    With *collections* (personal group only): the collection states of the outcome are applied
    too; without, they are dropped without a word.
    """
    from ..item_service import sync_writes

    if collection_id is not None:
        _check_lease(session, lease)
    scope = _scope_for(session, collection_id)
    if scope is not None:
        with sync_writes():
            return _apply(session, lease, outcome, device_id=device_id, now=now, scope=scope)
    with _documents(session), sync_writes():
        return _apply(session, lease, outcome, device_id=device_id, now=now, collections=collections)


def _apply(session: Any, lease: Any, outcome: MergeOutcome, *, device_id: str, now: int,
           scope: _Scope | None = None, collections: bool = False) -> ApplyReport:
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
    # Collection states (and conflict copies of them) are applied by ``_Collections``, never as records;
    # a merge of them is not a conflict the user sees.
    col_on = scope is None and collections
    col_upserts = [s for s in outcome.upserts if _is_collection_state(s)] if col_on else []
    col_deletes = [(s, now if s.deleted_at is None else min(s.deleted_at, now)) for s in outcome.deletes
                   if is_collection_state_id(s.item_id)] if col_on else []
    col_deletes = [(s, at) for s, at in col_deletes if at >= cutoff]
    col_copies = [s for s in outcome.copies if _is_collection_state(s)] if col_on else []
    conflicts = sum(1 for _loc, remote in outcome.conflicts if not _is_collection_state(remote))
    outcome = MergeOutcome(tuple(s for s in outcome.upserts if not _is_collection_state(s)),
                           tuple(s for s in outcome.deletes if not is_collection_state_id(s.item_id)),
                           outcome.conflicts,
                           tuple(s for s in outcome.copies if not _is_collection_state(s)))
    ids = [s.item_id for s in (*outcome.upserts, *outcome.deletes, *outcome.copies)]
    deletes = []
    for state in outcome.deletes:
        at = now if state.deleted_at is None else min(state.deleted_at, now)
        if at >= cutoff:
            deletes.append((state, at))
    stale = {s.item_id for s in outcome.deletes} - {s.item_id for s, _at in deletes}
    # Licence states: a tombstone never deletes one (one this device publishes is
    # republished above it), and a revoked licence, or any licence in a build
    # without licence keys, is dropped quietly: never stored, installed or republished.
    published = _published_licenses(session._require_typed_catalog()) if scope is None else {}
    for state, _at in deletes:
        if _is_license_id(state.item_id) and state.item_id not in published:
            stale.add(state.item_id)
    stale.update(s.item_id for s in outcome.upserts if _quiet_license(s))
    # A conflict copy of a licence (a reissue under the same licence id) is never kept.
    stale.update(s.item_id for s in outcome.copies
                 if isinstance(s.item, dict) and s.item.get("ns") == LICENSE_NS)
    # A conflict copy of the emergency access plan is never stored; its refused ids join the local plan.
    # In a share group (sub-plan 07) the plan never travels: any state under its id is dropped there.
    heir_copies = [s for s in outcome.copies
                   if scope is None and isinstance(s.item, dict) and s.item.get("ns") == HEIR_NS]
    stale.update(s.item_id for s in heir_copies)
    if scope is not None:
        stale.update(item_id for item_id in ids if _is_heir_id(item_id))
    deletes = [(s, at) for s, at in deletes if s.item_id not in stale]
    ids = [item_id for item_id in ids if item_id not in stale]
    skipped = _unreadable(session._require_typed_catalog(), ids, scope)
    report_skipped = tuple(sorted(skipped.items()))
    ids = [item_id for item_id in ids if item_id not in skipped]
    if not ids and not heir_copies and not (col_upserts or col_deletes or col_copies):
        return ApplyReport(0, 0, conflicts, report_skipped)

    applied = deleted = 0
    received: list[dict[str, Any]] = []
    with session.transaction():
        payload = session._require_typed_catalog()
        meta = _load_meta(payload, scope)
        read_only: frozenset[str] = frozenset()
        if scope is None:
            from .share_group import read_only_collection_ids

            read_only = read_only_collection_ids(session)
        cols = _Collections(session, payload, meta, device_id, read_only, now) if col_on else None
        work = _Applier(session, payload, meta, published, scope, read_only)
        for item_id in ids:
            work.check_fresh(item_id)
        if cols is not None:
            for state in (*col_upserts, *(s for s, _at in col_deletes)):
                if is_collection_state_id(state.item_id):
                    cols.check_fresh(state.item_id, work.live)
        history_rows = len(payload.get("history", []))
        try:
            if cols is not None:
                # Catalog rows first: the items and memberships below may name a new collection.
                for state, at in col_deletes:
                    if state.item_id.startswith(CATALOG_ID_PREFIX):
                        with _blame(state.item_id):
                            applied += cols.catalog_delete(state, at)
                for state in col_upserts:
                    if state.item_id.startswith(CATALOG_ID_PREFIX):
                        with _blame(state.item_id):
                            _ns, record = _unwrap(state, is_copy=False)
                            applied += cols.catalog_upsert(state, record)
                work.collections = set(cols.rows)
            for state, at in deletes:
                if state.item_id in skipped:
                    continue
                if _is_license_id(state.item_id):
                    with _blame(state.item_id):  # an overflowing bump refuses only this state
                        meta[state.item_id] = _live_meta(work.licenses[state.item_id], bump(state.vv, device_id))
                    continue
                if _is_heir_id(state.item_id):  # the owner removed the plan on another device
                    prefs = payload.get("preferences")
                    if isinstance(prefs, dict) and prefs.pop(_HEIR_PREF, None) is not None:
                        deleted += 1
                    meta[state.item_id] = _tomb_meta(state.vv, at)
                    continue
                if work.protected(state.item_id):
                    # In a read-only share on this device: only the owner removes it (through the share).
                    with _blame(state.item_id):
                        meta[state.item_id] = _live_meta(work.current_wrapper(state.item_id),
                                                         bump(state.vv, device_id))
                    continue
                if work.delete(state.item_id):
                    deleted += 1
                meta[state.item_id] = _tomb_meta(state.vv, at)
            for state in outcome.upserts:
                if state.item_id in skipped or state.item_id in stale or work.untagged_here(state.item_id):
                    continue
                with _blame(state.item_id):
                    ns, record = _unwrap_remote(state, scope)
                    if ns == LICENSE_NS:
                        stored, _changed = work.store_license(state.item_id, record)
                        meta[state.item_id] = _live_meta(stored, state.vv)
                        received.append(record)
                        continue
                    if ns == HEIR_NS:
                        stored = _store_heir(payload, record)
                        applied += 1
                        vv = state.vv if stored == state.item else bump(state.vv, device_id)
                        meta[state.item_id] = _live_meta(stored, vv)
                        continue
                    if work.protected(state.item_id):
                        mine = work.current_wrapper(state.item_id)
                        if wrapper_digest(mine) != wrapper_digest(_remote_wrapper(ns, record)):
                            # Read-only share: another of this person's devices cannot change it here;
                            # this device's copy (the owner's version) is republished above it.
                            meta[state.item_id] = _live_meta(mine, bump(state.vv, device_id))
                            continue
                    if "attachment" in state.item:
                        _require_attachment(session, state.item, state.item_id)
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
                    _check_share_record(state, ns, record, scope)
                    if ns == "entry":
                        record["label"] = _with_suffix(record.get("label"), _MAX_ENTRY_LABEL)
                    else:
                        record["title"] = _with_suffix(record.get("title"), MAX_TITLE)
                    if "attachment" in state.item:
                        _require_attachment(session, state.item, state.item_id)
                    stored, changed = work.store(ns, record)
                    applied += changed
                    vv = state.vv if stored == _remote_wrapper(ns, record) else bump(state.vv, device_id)
                    meta[state.item_id] = _live_meta(stored, vv)
            if cols is not None:
                for state, at in col_deletes:
                    with _blame(state.item_id):
                        if state.item_id.startswith(MEMBERSHIP_ID_PREFIX):
                            applied += cols.membership_delete(state, at, work.live)
                        elif state.item_id.startswith(LINK_ID_PREFIX):
                            applied += cols.link_delete(state, at)
                for state in col_upserts:
                    if not is_collection_state_id(state.item_id) or state.item_id.startswith(CATALOG_ID_PREFIX):
                        continue
                    with _blame(state.item_id):
                        _ns, record = _unwrap(state, is_copy=False)
                        if record["kind"] == "membership":
                            applied += cols.membership_upsert(state, record, work.live)
                        else:
                            applied += cols.link_upsert(state, record)
                for state in col_copies:
                    # Two devices changed one membership at once: this device keeps both (a union),
                    # never a copy.  A losing catalog row or link is dropped (the winner was applied).
                    with _blame(state.item_id):
                        _ns, record = _unwrap(state, is_copy=True)
                        if record["kind"] == "membership":
                            applied += cols.membership_upsert(state, record, work.live, union=True)
            for state in heir_copies:
                local = _heir_record(payload)
                with _blame(state.item_id):
                    _ns, record = _unwrap(state, is_copy=True)
                    if local is not None and local.get("plan_id") == record["plan_id"]:
                        try:
                            _store_heir(payload, record)  # the next local_view publishes the union as an edit
                        except BridgeError:
                            pass  # a copy that re-keys the plan is ignored: the local plan stays as it is
        except (EngineError, ItemSchemaError) as exc:
            raise BridgeError(f"Merge outcome cannot be applied: {exc}") from None
        if len(work.live) > MAX_SYNC_RECORDS:
            raise BridgeError("The vault would hold more records than sync supports")
        rows = len(payload.get("history", []))
        if rows > history_rows and rows > _MAX_SAVED_HISTORY_ROWS:
            raise BridgeError("Item history is full; remove old versions and sync again",
                              reason="history-quota")
        _store_meta(payload, device_id, meta, scope)
        _check_lease(session, lease)
    return ApplyReport(applied, deleted, conflicts, report_skipped, tuple(received))


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


def _unreadable(payload: Mapping[str, Any], ids: list[str], scope: _Scope | None = None) -> dict[str, str]:
    """id -> reason for the live local records among *ids* that fail validation."""
    meta = _load_meta(payload, scope)
    live = _live_records(payload)
    out: dict[str, str] = {}
    for item_id in ids:
        if _is_heir_id(item_id):
            try:
                _local_heir_wrapper(payload)
            except BridgeError as exc:
                out[item_id] = str(exc)
            continue
        current = live.get(item_id)
        if current is None:
            continue
        if not is_valid_id(item_id) or _is_reserved_id(item_id):
            out[item_id] = "invalid-id"
            continue
        try:
            _view_wrapper(*current, meta.get(item_id), scope)
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
                                  "hello_counter", "lan_removed", "unacked_members", "view_signers",
                                  "peer_generations", "rollback_suspected", "witness_peers",
                                  "witness_counters", "attachment_peers", "peer_synced_at", "collection_peers",
                                  "heir_peers"})
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
    Rollback witnesses (2026-10-29, ``witness.py``): ``peer_generations`` maps
    a peer id to the highest vault generation it published; ``rollback_suspected``
    is the highest generation of THIS vault a peer has seen above our own (0 =
    none; sticky until acknowledged); ``witness_peers`` are peer ids that showed
    support for view format 2 (a format-2 view, a witness file or a LAN witness
    message).  ``witness_counters`` maps a folder peer to the view counter of
    the last view whose generation this device saw (format 2 or a matching
    witness file); a newer view of a witnessing peer without one is reported
    as ``witness-missing`` after a grace run.  A folder device writes format-2 views only once every other
    member is listed; a LAN device writes one to a peer only once it is listed.
    The thirteen newer fields are optional in stored form; the last seven are written
    only when they differ from their defaults, so an older version still reads
    an unaffected state (one that holds ``view_signers`` is refused by a version
    from before 2026-10-24, one that holds a witness field by a version from
    before 2026-10-29).
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
    peer_generations: Mapping[str, int] = field(default_factory=dict)
    rollback_suspected: int = 0
    witness_peers: tuple[str, ...] = ()
    witness_counters: Mapping[str, int] = field(default_factory=dict)
    #: Wi-Fi peers that answered a ``blob-get`` (attachment sync, 2026-10-29): they get documents.
    attachment_peers: tuple[str, ...] = ()
    #: Wi-Fi peers that answered ``heir-hello`` (sub-plan 08): they get the emergency access plan.
    heir_peers: tuple[str, ...] = ()
    #: Per-device "last synced" time (UX workstream 6, Android ``PeerSyncedAt``): peer id -> unix
    #: seconds when this device last accepted that peer's newer data (a newer folder view, or a
    #: Wi-Fi merge that changed records).  Local only: never sent; written only when non-empty.
    peer_synced_at: Mapping[str, int] = field(default_factory=dict)
    #: Wi-Fi peers that answered a ``features`` message with ``collections`` (sub-plan 07 Task 4):
    #: personal collection states are exchanged with them.  Written only when non-empty.
    collection_peers: tuple[str, ...] = ()

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
        gens = self.peer_generations
        if not isinstance(gens, Mapping) or len(gens) > MAX_PEERS_SEEN:
            raise BridgeError("Sync peer generations are malformed")
        for dev, gen in gens.items():
            if not is_valid_id(dev) or type(gen) is not int or not 0 <= gen <= _MAX_INT53:
                raise BridgeError("Sync peer generations are malformed")
        object.__setattr__(self, "peer_generations", dict(sorted(gens.items())))
        if type(self.rollback_suspected) is not int or not 0 <= self.rollback_suspected <= _MAX_INT53:
            raise BridgeError("Sync rollback suspicion is malformed")
        capable = self.witness_peers
        if isinstance(capable, (str, bytes, Mapping)) or not hasattr(capable, "__iter__"):
            raise BridgeError("Sync witness peers are malformed")
        capable = tuple(capable)
        if (len(capable) > MAX_PEERS_SEEN or len(set(capable)) != len(capable)
                or not all(is_valid_id(m) for m in capable)):
            raise BridgeError("Sync witness peers are malformed")
        object.__setattr__(self, "witness_peers", tuple(sorted(capable)))
        wc = self.witness_counters
        if not isinstance(wc, Mapping) or len(wc) > MAX_PEERS_SEEN:
            raise BridgeError("Sync witness counters are malformed")
        for dev, ctr in wc.items():
            if not is_valid_id(dev) or type(ctr) is not int or not 0 <= ctr <= _MAX_INT53:
                raise BridgeError("Sync witness counters are malformed")
        object.__setattr__(self, "witness_counters", dict(sorted(wc.items())))
        ap = self.attachment_peers
        if isinstance(ap, (str, bytes, Mapping)) or not hasattr(ap, "__iter__"):
            raise BridgeError("Sync attachment peers are malformed")
        ap = tuple(ap)
        if len(ap) > MAX_PEERS_SEEN or len(set(ap)) != len(ap) or not all(is_valid_id(m) for m in ap):
            raise BridgeError("Sync attachment peers are malformed")
        object.__setattr__(self, "attachment_peers", tuple(sorted(ap)))
        cp = self.collection_peers
        if isinstance(cp, (str, bytes, Mapping)) or not hasattr(cp, "__iter__"):
            raise BridgeError("Sync collection peers are malformed")
        cp = tuple(cp)
        if len(cp) > MAX_PEERS_SEEN or len(set(cp)) != len(cp) or not all(is_valid_id(m) for m in cp):
            raise BridgeError("Sync collection peers are malformed")
        object.__setattr__(self, "collection_peers", tuple(sorted(cp)))
        hp = self.heir_peers
        if isinstance(hp, (str, bytes, Mapping)) or not hasattr(hp, "__iter__"):
            raise BridgeError("Sync emergency access peers are malformed")
        hp = tuple(hp)
        if len(hp) > MAX_PEERS_SEEN or len(set(hp)) != len(hp) or not all(is_valid_id(m) for m in hp):
            raise BridgeError("Sync emergency access peers are malformed")
        object.__setattr__(self, "heir_peers", tuple(sorted(hp)))
        ps = self.peer_synced_at
        if not isinstance(ps, Mapping) or len(ps) > MAX_PEERS_SEEN:
            raise BridgeError("Sync peer times are malformed")
        for dev, at in ps.items():
            if not is_valid_id(dev) or type(at) is not int or not 0 <= at <= _MAX_INT53:
                raise BridgeError("Sync peer times are malformed")
        object.__setattr__(self, "peer_synced_at", dict(sorted(ps.items())))

    def synced_with(self, peers: Any, now: int, limit: int = MAX_PEERS_SEEN) -> SyncGroupState:
        """This state with *peers* synced at *now* (the *limit* most recent peers kept)."""
        peers = [p for p in peers if p != self.device_id]
        if not peers:
            return self
        now = max(0, min(int(now), _MAX_INT53))
        times = {**self.peer_synced_at, **{p: now for p in peers}}
        if len(times) > limit:
            times = dict(sorted(times.items(), key=lambda kv: kv[1], reverse=True)[:limit])
        return dataclasses.replace(self, peer_synced_at=times)

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
        if self.peer_generations:
            out["peer_generations"] = dict(self.peer_generations)
        if self.rollback_suspected:
            out["rollback_suspected"] = self.rollback_suspected
        if self.witness_peers:
            out["witness_peers"] = list(self.witness_peers)
        if self.witness_counters:
            out["witness_counters"] = dict(self.witness_counters)
        if self.attachment_peers:
            out["attachment_peers"] = list(self.attachment_peers)
        if self.heir_peers:
            out["heir_peers"] = list(self.heir_peers)
        if self.peer_synced_at:
            out["peer_synced_at"] = dict(self.peer_synced_at)
        if self.collection_peers:
            out["collection_peers"] = list(self.collection_peers)
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
                or not isinstance(raw.get("peer_generations", {}), dict)
                or not isinstance(raw.get("witness_peers", []), list)
                or not isinstance(raw.get("witness_counters", {}), dict)
                or not isinstance(raw.get("attachment_peers", []), list)
                or not isinstance(raw.get("heir_peers", []), list)
                or not isinstance(raw.get("peer_synced_at", {}), dict)
                or not isinstance(raw.get("collection_peers", []), list)
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
                   view_signers=raw.get("view_signers", {}),
                   peer_generations=raw.get("peer_generations", {}),
                   rollback_suspected=raw.get("rollback_suspected", 0),
                   witness_peers=tuple(raw.get("witness_peers", [])),
                   witness_counters=raw.get("witness_counters", {}),
                   attachment_peers=tuple(raw.get("attachment_peers", [])),
                   peer_synced_at=raw.get("peer_synced_at", {}),
                   collection_peers=tuple(raw.get("collection_peers", [])),
                   heir_peers=tuple(raw.get("heir_peers", [])))


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


def epoch_reset_fields(state: SyncGroupState) -> dict[str, Any]:
    """Fields cleared when this device moves to a new epoch: per-peer counters, digests and signing keys.

    Only members of the new epoch can write files for it, so a counter or key forged by a
    member that the rotation removed no longer blocks anyone.  This device's own key stays.
    """
    own = {d: k for d, k in state.view_signers.items() if d == state.device_id}
    return {"last_seen": {}, "peer_digests": {}, "view_signers": own, "witness_counters": {}}


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


def acknowledge_vault_rollback(session: Any, lease: Any) -> bool:
    """The user confirmed this vault was restored on purpose (``vault-rollback``).

    Raises the vault's generation floor above every value a peer witnessed
    (``rollback_suspected + 1``) and clears ``rollback_suspected`` in the same
    save, so the next published generation is above the witnesses and the
    warning stops.  Returns False (and writes nothing) when nothing was suspected.
    """
    _check_lease(session, lease)
    state = load_sync_state(session)
    if state is None or state.rollback_suspected <= 0:
        return False
    session.raise_generation_floor(min(state.rollback_suspected + 1, _MAX_INT53))
    _check_lease(session, lease)
    save_sync_state(session, dataclasses.replace(state, rollback_suspected=0))
    return True


def forget_peer_generation(session: Any, lease: Any, peer_id: str) -> bool:
    """The user dismissed ``peer-vault-rollback`` for *peer_id*: accept its older copy.

    Drops the remembered generation of that peer, so its next view is
    remembered as it is and no longer reported.  Returns whether one was dropped.
    """
    _check_lease(session, lease)
    state = load_sync_state(session)
    if state is None or not isinstance(peer_id, str) or peer_id not in state.peer_generations:
        return False
    left = {k: v for k, v in state.peer_generations.items() if k != peer_id}
    _check_lease(session, lease)
    save_sync_state(session, dataclasses.replace(state, peer_generations=left))
    return True


def clear_sync_state(session: Any, *, keep: KeptIdentity | None = None) -> None:
    """Drop the sync group; with *keep*, store it as the kept identity in the same save (Leave)."""
    from .removal import forget_session_watch

    forget_session_watch(session)  # a device that left must never be erased by a later removal notice
    payload = session._require_typed_catalog()
    if "sync_group" in payload or keep is not None:
        with session.transaction():
            payload = session._require_typed_catalog()
            payload.pop("sync_group", None)
            if keep is not None:
                payload[KEPT_IDENTITY_KEY] = keep.to_dict()  # replaces any earlier one: at most one per vault


# --- kept identity (keep the device id on rejoin, 2026-11-17) -------------------------------------------------

#: Payload key of the kept identity; ``backup.DEVICE_ONLY_PAYLOAD_KEYS`` strips it from every backup.
KEPT_IDENTITY_KEY = "sync_rejoin"
KEPT_IDENTITY_VERSION = 1
_KEPT_KEYS = frozenset({"version", "group_id", "device_identity", "install_id", "own_counter", "hello_counter"})


@dataclass(frozen=True)
class KeptIdentity:
    """The identity this device had in the group it left, and the counters peers hold it to.

    A peer refuses a file or hello from this device id whose counter is not above the last one it
    accepted, so a rejoin under the same id must continue them: ``own_counter`` (the folder view
    counter, ``SyncGroupState.own_counter``) and ``hello_counter`` (the Wi-Fi session hello).  The vault
    generation and the per-item version vectors (``sync_meta``) are not cleared by Leave, so they
    continue by themselves.  ``install_id`` binds it to this installation: a copied or restored vault
    never reuses another PC's identity.
    """

    group_id: str
    device_identity: Mapping[str, str] = field(repr=False)
    install_id: str
    own_counter: int = 0
    hello_counter: int = 0

    def __post_init__(self) -> None:
        _text(self.group_id, "kept group id", MAX_GROUP_ID)
        _text(self.install_id, "kept install id", MAX_INSTALL_ID)
        identity = self.device_identity
        if not isinstance(identity, Mapping) or set(identity) != _IDENTITY_KEYS:
            raise BridgeError("Kept device identity is malformed")
        try:
            DeviceIdentity.from_protected_dict(identity)
        except PairingError as exc:
            raise BridgeError(f"Kept device identity is malformed: {exc}") from None
        object.__setattr__(self, "device_identity", dict(identity))
        if type(self.own_counter) is not int or not 0 <= self.own_counter <= _MAX_INT53:
            raise BridgeError("Kept own counter is malformed")
        if type(self.hello_counter) is not int or not 0 <= self.hello_counter <= _MAX_INT63:
            raise BridgeError("Kept hello counter is malformed")

    @property
    def device_id(self) -> str:
        return self.device_identity["device_id"]

    def identity(self) -> DeviceIdentity:
        return DeviceIdentity.from_protected_dict(self.device_identity)

    @classmethod
    def of(cls, state: SyncGroupState) -> KeptIdentity:
        """What Leave keeps of *state* (bound to the state's own install id, which must be set)."""
        return cls(state.group_id, state.device_identity, state.install_id or "",
                   own_counter=state.own_counter, hello_counter=state.hello_counter)

    def to_dict(self) -> dict[str, Any]:
        return {"version": KEPT_IDENTITY_VERSION, "group_id": self.group_id,
                "device_identity": dict(self.device_identity), "install_id": self.install_id,
                "own_counter": self.own_counter, "hello_counter": self.hello_counter}

    @classmethod
    def from_dict(cls, raw: Any) -> KeptIdentity:
        if not isinstance(raw, Mapping) or set(raw) != _KEPT_KEYS or raw.get("version") != KEPT_IDENTITY_VERSION:
            raise BridgeError("Kept device identity is malformed")
        return cls(raw["group_id"], raw["device_identity"], raw["install_id"],
                   own_counter=raw["own_counter"], hello_counter=raw["hello_counter"])

    def continue_counters(self, state: SyncGroupState) -> SyncGroupState:
        """*state* (a new membership under this identity) with counters that never go below the kept ones."""
        return dataclasses.replace(state, own_counter=max(state.own_counter, self.own_counter),
                                   hello_counter=max(state.hello_counter, self.hello_counter))


def load_kept_identity(session: Any) -> KeptIdentity | None:
    """The kept identity, or None (none kept, or one that does not parse: it is then simply not reused)."""
    raw = session._require_typed_catalog().get(KEPT_IDENTITY_KEY)
    if raw is None:
        return None
    try:
        return KeptIdentity.from_dict(raw)
    except BridgeError:
        return None


def kept_identity_for(session: Any, group_id: Any, install_id: Any) -> KeptIdentity | None:
    """The kept identity if it may be reused to join *group_id* on installation *install_id*, else None.

    Never in the duress vault (it never keeps one, and must not use one either).
    """
    from ..duress import is_decoy

    if is_decoy(session):
        return None
    kept = load_kept_identity(session)
    if kept is None or kept.group_id != group_id or kept.install_id != install_id:
        return None
    return kept


def drop_kept_identity(session: Any) -> bool:
    """Forget the kept identity; returns whether there was one."""
    payload = session._require_typed_catalog()
    if KEPT_IDENTITY_KEY not in payload:
        return False
    with sync_only_save(session), session.transaction():
        session._require_typed_catalog().pop(KEPT_IDENTITY_KEY, None)
    return True


def save_rejoined_state(session: Any, state: SyncGroupState, *, drop_kept: bool) -> None:
    """Store a new membership; with *drop_kept*, forget the kept identity in the same save.

    A join of the kept group drops it either way: it is the live identity again, or it could not be
    reused (removed, another key) and must not be tried again.
    """
    with sync_only_save(session), session.transaction():
        save_sync_state(session, state)
        if drop_kept:
            session._require_typed_catalog().pop(KEPT_IDENTITY_KEY, None)


__all__ = [
    "CONFLICT_SUFFIX", "COUNTER_OVERFLOW", "ITEM_WRAPPER_SCHEMA", "LOCAL_ONLY_ENTRY_FIELDS", "LOCAL_ONLY_ITEM_FIELDS",
    "LOCAL_ONLY_ITEM_PAYLOAD_FIELDS", "MAX_SYNC_RECORDS", "TOMBSTONE_MAX_AGE_DAYS", "UNSYNCED_ITEM_KINDS",
    "RESTORED_MARKER_SUFFIX", "ApplyReport", "BridgeError", "LocalView", "SyncGroupState",
    "acknowledge_vault_rollback", "apply", "forget_peer_generation", 
    "check_remote_state", "clear_sync_state", "epoch_reset_fields",
    "SHARE_META_KEY", "forget_share_meta", "licenses_in_views", "load_sync_state", "local_view", "normal_form", "prune_tombstones", "published_licenses", "save_sync_state",
    "sync_only_save", "wrapper_digest",
]
