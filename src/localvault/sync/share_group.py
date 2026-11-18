"""Share groups: a collection shared with other people through its own sync group (sub-plan 07).

A shared collection is a second sync group next to the vault's personal one, with its own keyring
(``keyring.create_group`` / ``join_with_password`` / ``rotate``), its own device identity and its own
removal notices.  The keyring carries the share ``metadata`` (collection id, encrypted name, shared
mode, owner device id and owner Ed25519 key) and the owner's signature over the approved members
(``owner_sig``, see ``keyring.py``).  The personal group (``payload["sync_group"]``) is never read for
anything but a clash check, and never changed.

Losing the owner's device freezes the group: nobody else can rotate, remove or approve, and
there is no owner recovery yet (members keep syncing with the members already approved; the
owner shares the collection again from a new device).  Owner recovery is a planned follow-up
(plan 07, "Follow-ups from the Task 1 review").

Owner authority is cryptographic: only the owner's key can sign a share keyring, and every device
pins the owner (device id and key), the collection id and the shared mode when it creates or joins
the group.  ``adopt_keyring`` refuses a keyring that changes any of them or no longer lists the
owner; the keyring layer refuses one whose owner signature does not verify.  Members the owner has
not approved yet (a password join) are "pending": they get no removal-notice authority and are
dropped when the owner removes someone.

Stored in the vault (encrypted with it), ``payload["share_groups"]``::

    {group_id: {"version": 1, "collection_id", "role": "owner"|"member", "owner", "owner_key",
                "shared_mode", "state": SyncGroupState.to_dict(),
                "removed"?: [{"name": str | None, "at": int}]}}   # owner only: who was removed

Share v2 (``docs/superpowers/specs/2026-11-12-collections-crypto-gating.md``): new shares seal their
items with a content key that the owner wraps only to the devices it approved (``view_key``), so the
share password lets a device join (pending) but opens no item.  A share v1 group (items sealed with
the group key) keeps syncing until its owner upgrades it (``upgrade_share``, or any removal).

Removal notices of a share group are accepted only when signed by the pinned owner key
(``share_watch`` / ``verify_share_notice``); the owner's own device never acts on one.

Licence (Global Constraints): creating, joining and syncing need Pro (``licensing.item_limit() is
None``); a free device gets ``ProRequired`` (the app shows the upgrade sheet) before any key
derivation.  A device whose Pro lapsed keeps its groups, collections and items (read access):
``share_sync_allowed()`` is False, so the share runner stops syncing them.  Leaving and removing a
member (a security action) work without Pro.

Nothing here logs; keys, passwords and the keyring never appear in a repr.
"""
from __future__ import annotations

import dataclasses
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import licensing
from ..item_schema import MAX_COLLECTIONS, ItemSchemaError, validate_collections
from ..updates import canonical_json
from ..vault import ProFeatureRequired
from .engine import is_valid_id
from .group import GroupKey
from .keyring import (
    SHARE_FORMAT,
    KeyringError,
    accept_keyring,
    approved_members,
    check_share_spec,
    create_group,
    join_with_password,
    keyring_metadata,
    member_names,
    open_content_key,
    owner_approve_members,
    parse_keyring,
    rotate,
    share_name,
    share_version,
    upgrade_share_keyring,
    verify_keyring_structure,
)
from .pairing import DeviceIdentity
from .removal import Notice, RemovalError, Watch, make_notice, verify_notice
from .vault_bridge import (
    BridgeError,
    SyncGroupState,
    epoch_reset_fields,
    forget_share_meta,
    load_sync_state,
    sync_only_save,
)

STORE_KEY = "share_groups"
STORE_VERSION = 1
ROLES = ("owner", "member")
SHARE_FEATURE = "sharing"
_RECORD_FIELDS = frozenset({"version", "collection_id", "role", "owner", "owner_key", "shared_mode", "state"})
#: Optional record field: the members the owner removed, ``[{"name": str | None, "at": int}]`` (oldest first).
_REMOVED = "removed"
MAX_REMOVED = 50
_PINNED = ("collection_id", "owner", "owner_key", "shared_mode")
_MAX_NAME = 100
#: The share version new shares are created with (keyring format 3, share v2); tests set 2 to make a share v1.
_NEW_SHARE_FORMAT = SHARE_FORMAT


class ShareGroupError(Exception):
    """A share-group operation that is refused; ``reason`` is a stable code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class ProRequired(ProFeatureRequired):
    """Shared collections need Pro on this device (the app shows the upgrade sheet)."""

    def __init__(self) -> None:
        super().__init__(SHARE_FEATURE)


@dataclass(frozen=True)
class Member:
    device_id: str
    name: str | None  # None: the name cannot be read ("Unnamed device")
    added_at: int
    approved: bool  # the owner signed this member (False: joined, waiting for the owner)


@dataclass(frozen=True)
class ShareGroup:
    group_id: str
    collection_id: str
    name: str
    shared_mode: str
    owner: str  # the owner's device id in this group
    members: tuple[Member, ...]
    #: 1: items sealed with the group key (the share password opens them); 2: with the content key that
    #: only approved members hold (``docs/superpowers/specs/2026-11-12-collections-crypto-gating.md``).
    version: int = 2


# --- licence ------------------------------------------------------------------------------------------

def share_sync_allowed() -> bool:
    """Whether this device may create, join and sync shared collections (Pro)."""
    return licensing.item_limit() is None


def require_share_sync() -> None:
    if not share_sync_allowed():
        raise ProRequired()


# --- stored state -------------------------------------------------------------------------------------

def _payload(session: Any) -> dict[str, Any]:
    return session._require_typed_catalog()


def _bad() -> ShareGroupError:
    return ShareGroupError("bad-state", "stored share group is malformed")


def _check_record(group_id: object, record: object) -> SyncGroupState:
    if (not isinstance(group_id, str) or not is_valid_id(group_id) or not isinstance(record, Mapping)
            or set(record) - {_REMOVED} != _RECORD_FIELDS or type(record["version"]) is not int
            or record["version"] != STORE_VERSION or record["role"] not in ROLES
            or (_REMOVED in record and not _removed_ok(record[_REMOVED]))):
        raise _bad()
    try:
        state = SyncGroupState.from_dict(record["state"])
        ring = parse_keyring(state.keyring) if state.keyring is not None else None
        meta = keyring_metadata(ring) if ring is not None else None
    except (BridgeError, KeyringError) as exc:
        raise _bad() from exc
    if (state.group_id != group_id or meta is None or any(meta[k] != record[k] for k in _PINNED)
            or (record["role"] == "owner") != (state.device_id == record["owner"])):
        raise _bad()
    return state


def _removed_ok(rows: object) -> bool:
    return isinstance(rows, list) and len(rows) <= MAX_REMOVED and all(
        isinstance(r, dict) and set(r) == {"name", "at"} and type(r["at"]) is int and r["at"] >= 0
        and (r["name"] is None or (isinstance(r["name"], str) and len(r["name"]) <= _MAX_NAME))
        for r in rows)


def _note_removed(record: dict[str, Any], names: Iterable[str | None], at: int) -> None:
    """Add *names* to the owner's "removed" list of *record* (bounded: the oldest go first)."""
    rows = [*record.get(_REMOVED, []), *({"name": n, "at": int(at)} for n in names)]
    record[_REMOVED] = rows[-MAX_REMOVED:]


def removed_members(session: Any, group_id: str) -> tuple[tuple[str | None, int], ...]:
    """``(name, removed_at)`` of the members the owner removed on this device (oldest first)."""
    record, _ = _record(session, group_id)
    return tuple((r["name"], r["at"]) for r in record.get(_REMOVED, ()))


def _records(session: Any) -> dict[str, dict[str, Any]]:
    raw = _payload(session).get(STORE_KEY, {})
    if not isinstance(raw, dict):
        raise _bad()
    for group_id, record in raw.items():
        _check_record(group_id, record)
    return raw


def _record(session: Any, group_id: str) -> tuple[dict[str, Any], SyncGroupState]:
    record = _records(session).get(group_id) if isinstance(group_id, str) else None
    if record is None:
        raise ShareGroupError("not-joined", "this vault is not in that share group")
    return record, _check_record(group_id, record)


def share_state(session: Any, group_id: str) -> SyncGroupState:
    """The stored sync state of share group *group_id* (for the share transports)."""
    return _record(session, group_id)[1]


def share_info(session: Any, group_id: str) -> dict[str, Any]:
    """The pinned facts of *group_id*: ``role``, ``collection_id``, ``owner``, ``owner_key``, ``shared_mode``."""
    record, _ = _record(session, group_id)
    return {k: record[k] for k in ("role", *_PINNED)}


def share_folders(session: Any) -> list[tuple[str, str]]:
    """``(group_id, folder)`` of every share group that syncs through a folder (for the scheduler)."""
    out = []
    for group_id, record in sorted(_records(session).items()):
        state = _check_record(group_id, record)
        if state.folder_path:
            out.append((group_id, state.folder_path))
    return out


def read_only_collection_ids(session: Any) -> frozenset[str]:
    """Collections this vault holds as a member of a read-only share: local edits there are refused.

    Fails closed: if the stored share groups cannot be read, every shared collection is read-only.
    """
    payload = _payload(session)
    if not payload.get(STORE_KEY):
        return frozenset()
    try:
        records = _records(session)
    except ShareGroupError:
        rows = payload.get("collections", [])
        return frozenset(r["id"] for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str)
                         and r.get("shared_group_id")) if isinstance(rows, list) else frozenset()
    return frozenset(r["collection_id"] for r in records.values() if r["role"] == "member" and r["shared_mode"] == "read")


def share_links(session: Any) -> dict[str, dict[str, str]] | None:
    """``{collection_id: {"mode", "role"}}`` of the collections shared on this device (personal collections
    sync publishes them as share links to this person's other devices), None when unreadable.

    Only the mode and this device's role leave the device: never the group id, keys, keyring,
    members, folder or the owner's key.
    """
    payload = _payload(session)
    if not payload.get(STORE_KEY):
        return {}
    try:
        records = _records(session)
    except ShareGroupError:
        return None
    marked = {r.get("id"): r.get("shared_group_id") for r in _collections(session) if isinstance(r, dict)}
    return {r["collection_id"]: {"mode": r["shared_mode"], "role": r["role"]}
            for group_id, r in records.items() if marked.get(r["collection_id"]) == group_id}


def linked_read_only_collection_ids(session: Any) -> frozenset[str]:
    """Collections another of this person's devices holds as a member of a read-only share (a share link
    received through personal collections sync): the item service refuses edits there too."""
    from .vault_bridge import _stored_links

    shared = {r.get("id") for r in _collections(session) if isinstance(r, dict) and r.get("shared_group_id")}
    return frozenset(cid for cid, link in _stored_links(_payload(session)).items()
                     if link["mode"] == "read" and link["role"] == "member" and cid not in shared)


def _link(session: Any, collection_id: str) -> dict[str, str] | None:
    from .vault_bridge import _stored_links

    return _stored_links(_payload(session)).get(collection_id)


def _drop_link(session: Any, collection_id: str) -> None:
    from .vault_bridge import LINKS_KEY

    links = _payload(session).get(LINKS_KEY)
    if isinstance(links, dict) and collection_id in links:
        links = {k: v for k, v in links.items() if k != collection_id}
        if links:
            _payload(session)[LINKS_KEY] = links
        else:
            _payload(session).pop(LINKS_KEY, None)


def _shared_on_this_device(session: Any, collection_id: str) -> bool:
    row = next((r for r in _collections(session) if isinstance(r, dict) and r.get("id") == collection_id), None)
    if row is not None and row.get("shared_group_id"):
        return True
    try:
        return any(r.get("collection_id") == collection_id for r in _records(session).values())
    except ShareGroupError:
        return True  # unreadable share store: fail closed


def received_share_link(session: Any, collection_id: str) -> dict[str, str] | None:
    """``{"mode", "role"}`` of the share link of *collection_id* that another of this person's devices
    published (it holds the share, this device does not), None when there is none."""
    if _shared_on_this_device(session, collection_id):
        return None
    return _link(session, collection_id)


def shared_twice(session: Any, collection_id: str) -> bool:
    """Whether *collection_id* is shared on this device and another of this person's devices also shares it (its
    link is stored here, final review B1): the share page warns, and one share should be stopped or left."""
    try:
        own = share_links(session)
    except ShareGroupError:
        return False
    return bool(own) and collection_id in own and _link(session, collection_id) is not None


def forget_share_link(session: Any, collection_id: str) -> None:
    """Forget the share link of *collection_id* received from another of this person's devices (final review
    finding 4, the same rule as lgk-core and LGKCore ``ShareGroups.forgetLink``).

    A received link goes away only through a tombstone its holder publishes, so the link of a device that
    was lost, reset or left device sync stays forever: it blocks sharing the collection again (the owner-loss
    recovery), deleting it, and (read-only) every edit on this person's devices.  The link is dropped here
    and the next personal collections sync publishes its tombstone (the link is no longer relayed), so the
    person's other devices drop it too.  A holder that still exists republishes its own link above the
    tombstone (``vault_bridge`` ``link_delete``), so forgetting can never take a live share away.

    Refused: ``shared-here`` when this device holds the share itself (leave or stop sharing instead),
    ``no-link`` when there is no received link.
    """
    if _shared_on_this_device(session, collection_id):
        raise ShareGroupError("shared-here", "that collection is shared on this device")
    if _link(session, collection_id) is None:
        raise ShareGroupError("no-link", "that collection has no share link")
    with session.transaction():
        _drop_link(session, collection_id)


def save_share_state(session: Any, group_id: str, state: SyncGroupState) -> bool:
    """Store the transport's new *state* of *group_id* (counters, peers); False when unchanged.

    The group, device and pinned facts cannot change here (``bad-state``); keyrings change only
    through ``adopt_keyring`` and the owner operations.  Saved without a rolling backup.
    """
    record, old = _record(session, group_id)
    if (not isinstance(state, SyncGroupState) or state.group_id != old.group_id or state.device_id != old.device_id
            or state.epoch != old.epoch or state.key != old.key or state.keyring != old.keyring):
        raise _bad()
    new = _with_state(record, state)
    _check_record(group_id, new)
    if new == record:
        return False
    with sync_only_save(session), session.transaction():
        _store(session, group_id, new)
    return True


def set_share_folder(session: Any, group_id: str, folder: str | None) -> None:
    """Sync *group_id* through *folder* (None: no folder); the folder transport writes the keyring there."""
    record, state = _record(session, group_id)
    new_state = dataclasses.replace(state, folder_path=None if folder is None else str(folder))
    with session.transaction():
        _store(session, group_id, _with_state(record, new_state))


def share_keyring(session: Any, group_id: str) -> bytes:
    """The bytes of the last keyring of *group_id* this device accepted or wrote."""
    keyring = share_state(session, group_id).keyring
    if keyring is None:  # _check_record already refuses this
        raise _bad()
    return keyring


def _gk(state: SyncGroupState) -> GroupKey:
    return GroupKey(state.group_id, state.epoch, state.key)


def _group(state: SyncGroupState) -> ShareGroup:
    ring = parse_keyring(state.keyring)
    meta = keyring_metadata(ring)
    names = member_names(ring, _gk(state))
    signed = approved_members(ring) or frozenset()
    members = tuple(Member(m["device_id"], names[m["device_id"]], m["added_at"], m["device_id"] in signed)
                    for m in ring["members"])
    return ShareGroup(state.group_id, meta["collection_id"], share_name(ring, _gk(state)), meta["shared_mode"],
                      meta["owner"], members, share_version(ring) or 1)


def view_key(session: Any, group_id: str) -> GroupKey | None:
    """The key the share's item views are sealed with on this device; None while it waits for approval.

    Share v1: the group key ``G`` of an approved member (the owner always).  Share v2: the content key
    ``C`` from this device's content wrap (``keyring.open_content_key``).  Raises ``KeyringError``
    (``content-key``) when the wrap does not open to the committed key.
    """
    record, state = _record(session, group_id)
    ring = parse_keyring(state.keyring)
    if share_version(ring) == 2:
        return open_content_key(ring, state.identity())
    approved = set(approved_members(ring) or ()) | {record["owner"]}
    return _gk(state) if state.device_id in approved else None


def needs_upgrade(session: Any, group_id: str) -> bool:
    """Whether this device owns share v1 *group_id* (the share page offers the upgrade to share v2)."""
    record, state = _record(session, group_id)
    return (record["role"] == "owner" and state.device_id == record["owner"]
            and share_version(parse_keyring(state.keyring)) == 1)


def upgrade_share(session: Any, group_id: str, *, password: str,
                  _kdf_override: tuple[int, int, int] | None = None) -> ShareGroup:
    """The owner upgrades share v1 *group_id* to share v2 (works without Pro: a security action).

    A rotation to epoch + 1 that removes nobody: approved members get the new content key, pending
    members stay pending, the share password may stay the same (it no longer opens any item).  The new
    keyring is kept in the vault for the share transport to write.  Refused: ``not-owner``,
    ``already-upgraded``, and the keyring refusals (``WeakSyncPassword`` for a weak password).
    """
    record, state = _record(session, group_id)
    _require_owner(record, state)
    ring = parse_keyring(state.keyring)
    if share_version(ring) != 1:
        raise ShareGroupError("already-upgraded", "this share is already upgraded")
    new_ring, gk = upgrade_share_keyring(ring, _gk(state), state.identity(), password, _kdf_override=_kdf_override)
    new_state = dataclasses.replace(state, epoch=gk.epoch, key=gk.key, members_epoch=gk.epoch,
                                    members=_member_ids(new_ring), keyring=canonical_json(new_ring),
                                    unacked_members=_pending(new_ring, state.device_id), **epoch_reset_fields(state))
    with session.transaction():
        _store(session, group_id, _with_state(record, new_state))
    return _group(new_state)


def list_share_groups(session: Any) -> list[ShareGroup]:
    """Every share group of this vault (works without Pro: read access stays)."""
    return [_group(_check_record(gid, rec)) for gid, rec in sorted(_records(session).items())]


def _store(session: Any, group_id: str, record: dict[str, Any] | None) -> None:
    """Set (or drop, *record* None) one stored group; the caller holds ``session.transaction()``."""
    payload = _payload(session)
    groups = dict(payload.get(STORE_KEY, {}))
    if record is None:
        groups.pop(group_id, None)
    else:
        groups[group_id] = record
    if groups:
        payload[STORE_KEY] = groups
    else:
        payload.pop(STORE_KEY, None)


def _new_record(meta: Mapping[str, Any], role: str, state: SyncGroupState) -> dict[str, Any]:
    return {"version": STORE_VERSION, "role": role, **{k: meta[k] for k in _PINNED}, "state": state.to_dict()}


def _with_state(record: Mapping[str, Any], state: SyncGroupState) -> dict[str, Any]:
    return {**record, "state": state.to_dict()}


def _member_ids(ring: Mapping) -> tuple[str, ...]:
    return tuple(sorted(m["device_id"] for m in ring["members"]))


def _pending(ring: Mapping, own: str) -> tuple[str, ...]:
    """Members the owner has not approved (never this device itself)."""
    approved = approved_members(ring) or frozenset()
    return tuple(d for d in _member_ids(ring) if d not in approved and d != own)


_SAME_EPOCH_FIXED = ("format", "group_id", "epoch", "kdf", "password_wrap", "metadata", "prev_mac")

def _check_same_epoch_growth(old: Mapping, new: Mapping) -> None:
    """At one epoch a share keyring may only grow: ``tampered`` for anything else.

    Within an epoch the only legitimate changes are a password join (one member entry and its
    device wrap appended) and an owner approval (``owner_sig`` approving more members).  Every
    member holds ``G`` and can re-MAC, and an older owner signature of the same epoch can be
    replayed, so the MAC and the signature alone cannot stop a member from dropping someone,
    replacing someone's wrap or key, swapping the password wrap, or un-approving members.
    Removing a member therefore always needs an owner-signed rotation (epoch + 1).
    """
    if any(old[k] != new[k] for k in _SAME_EPOCH_FIXED):
        raise KeyringError("tampered", "a share keyring changed within its epoch")
    old_members, new_members = old["members"], new["members"]
    if new_members[:len(old_members)] != old_members:
        raise KeyringError("tampered", "a share keyring dropped or changed a member within its epoch")
    if any(new["device_wraps"].get(d) != w for d, w in old["device_wraps"].items()):
        raise KeyringError("tampered", "a share keyring changed a device wrap within its epoch")
    if not (approved_members(old) or frozenset()) <= (approved_members(new) or frozenset()):
        raise KeyringError("tampered", "a share keyring un-approved a member within its epoch")
    old_content, new_content = old.get("content"), new.get("content")
    if (old_content is None) != (new_content is None):
        raise KeyringError("tampered", "a share keyring changed its version within its epoch")
    if old_content is not None and (old_content["commit"] != new_content["commit"] or any(
            new_content["wraps"].get(d) != w for d, w in old_content["wraps"].items())):
        raise KeyringError("tampered", "a share keyring changed its content key or a content wrap within its epoch")


def grows_from(old: Mapping, new: Mapping) -> bool:
    """Whether share keyring *new* is a later state of *old* (a later epoch, or growth within one).

    Used by the transport to decide that the folder holds an older keyring than this device's
    trusted one, which it then writes back (never for another group).
    """
    try:
        if old["group_id"] != new["group_id"]:
            return False
        if type(old["epoch"]) is int and type(new["epoch"]) is int and old["epoch"] < new["epoch"]:
            return True
        if old["epoch"] != new["epoch"] or old == new:
            return False
        _check_same_epoch_growth(old, new)
    except (KeyringError, KeyError, TypeError, AttributeError, IndexError):
        return False
    return True


# --- collections --------------------------------------------------------------------------------------

def _collections(session: Any) -> list[dict[str, Any]]:
    return list(_payload(session).get("collections", []))


def _mark_collection(session: Any, collection_id: str, group_id: str | None) -> None:
    from ..collections import CollectionService

    CollectionService(session).set_shared_group(collection_id, group_id, save=False)


def _unique_name(name: str, rows: list[dict[str, Any]]) -> str:
    taken = {row["name"].casefold() for row in rows}
    candidate, n = name, 2
    while candidate.casefold() in taken:
        suffix = f" ({n})"
        candidate = name[:_MAX_NAME - len(suffix)].rstrip() + suffix
        n += 1
    return candidate


def _add_shared_collection(session: Any, collection_id: str, name: str, group_id: str) -> None:
    payload = _payload(session)
    rows = _collections(session)
    now = int(time.time())
    row = {"id": collection_id, "name": _unique_name(name, rows), "description": "",
           "created_at": now, "updated_at": now, "revision": 1, "starter": False, "shared_group_id": group_id}
    payload["collections"] = validate_collections([*rows, row])
    payload["updated_at"] = now


# --- operations ---------------------------------------------------------------------------------------

def create_share_group(session: Any, collection_id: str, *, password: str, device: str,
                       shared_mode: str = "read", install_id: str | None = None,
                       _kdf_override: tuple[int, int, int] | None = None) -> ShareGroup:
    """Share *collection_id*: a new share group with this device (named *device*) as its owner.

    *password* is the share password the other people type to join (same strength rules as the
    sync password).  The keyring is kept in the vault (``share_keyring``); the share transport
    writes it to the shared folder.
    """
    require_share_sync()
    row = next((r for r in _collections(session) if r.get("id") == collection_id), None)
    if row is None:
        raise ShareGroupError("no-collection", "that collection does not exist")
    if row.get("shared_group_id") is not None or _link(session, collection_id) is not None:
        # A link: another of this person's devices shares it (as owner or member); sharing it again
        # from here would hand someone else's items to new people.
        raise ShareGroupError("already-shared", "that collection is already shared")
    spec = check_share_spec({"kind": "share", "collection_id": collection_id, "name": row["name"],
                             "shared_mode": shared_mode})
    identity = DeviceIdentity.generate()
    ring, gk = create_group(password, identity, device, metadata=spec, share_format=_NEW_SHARE_FORMAT,
                            _kdf_override=_kdf_override)
    state = SyncGroupState(gk.group_id, gk.epoch, gk.key, identity.protected_dict(), install_id=install_id,
                           members_epoch=gk.epoch, members=(identity.device_id,), keyring=canonical_json(ring))
    with session.transaction():
        _store(session, gk.group_id, _new_record(ring["metadata"], "owner", state))
        _mark_collection(session, collection_id, gk.group_id)
    return _group(state)


def join_share_group(session: Any, keyring_bytes: bytes, *, password: str, device: str,
                     install_id: str | None = None,
                     _kdf_override: tuple[int, int, int] | None = None) -> ShareGroup:
    """Join the share group of *keyring_bytes* with its share password, as device *device*.

    Refused on a free device (``ProRequired``, before any key derivation), for a keyring without
    share metadata (``not-share``: a personal device-sync keyring), for the vault's own device-sync
    group (``personal-group``) and for a group this vault is already in (``already-joined``).
    The owner (device id and key), collection id and shared mode are pinned from this keyring
    (trust on first use, authenticated by the share password).  The collection is added, named
    like the owner's (with a number if this vault already has one of that name).  A vault that
    already holds a collection with the keyring's collection id is refused (``collection-exists``)
    unless that collection is a leftover of this same group: marking an existing collection as
    shared would publish items the user never chose to share to whoever made the keyring.  The new
    keyring (with this device, pending until the owner approves it) is kept in the vault for the
    share transport to write.

    Joining again: a member whose join was lost to someone else's join at the same moment
    (``superseded_join``) joins the same group again with a new device identity; its collection,
    items and folder stay, and the pinned facts must not change (``tampered``).
    """
    require_share_sync()
    ring = parse_keyring(keyring_bytes)
    verify_keyring_structure(ring, _kdf_override=_kdf_override)
    # Not authenticated yet (the MAC is checked by join_with_password below): the metadata read
    # here only chooses a refusal; nothing from it is stored before the join succeeds.
    meta = keyring_metadata(ring)
    if meta is None:
        raise ShareGroupError("not-share", "that keyring is device sync, not a shared collection")
    group_id = ring["group_id"]
    personal = load_sync_state(session)
    if personal is not None and personal.group_id == group_id:
        raise ShareGroupError("personal-group", "that is this vault's own device sync group")
    previous = _records(session).get(group_id)
    if previous is not None and not superseded_join(session, group_id, keyring_bytes, _kdf_override=_kdf_override):
        raise ShareGroupError("already-joined", "this vault is already in that share group")
    rows = _collections(session)
    existing = next((r for r in rows if r.get("id") == meta["collection_id"]), None)
    link = _link(session, meta["collection_id"]) if existing is not None else None
    if link is not None and link["role"] == "owner" and existing.get("shared_group_id") is None:
        # Shared by this person's own other device: it already syncs here through device sync.
        raise ShareGroupError("own-share", "you shared this collection from another of your devices")
    if existing is not None and existing.get("shared_group_id") != group_id and link is None:
        raise ShareGroupError("collection-exists", "this vault already has that collection")
    if existing is None and len(rows) >= MAX_COLLECTIONS:
        raise ItemSchemaError("Collection limit reached")
    identity = DeviceIdentity.generate()
    new_ring, gk = join_with_password(ring, password, identity, device, _kdf_override=_kdf_override)
    name = share_name(new_ring, gk)
    if previous is not None and any(new_ring["metadata"][k] != previous[k] for k in _PINNED):
        raise KeyringError("tampered", "the keyring changes the share's owner, collection or mode")
    folder = _check_record(group_id, previous).folder_path if previous is not None else None
    state = SyncGroupState(gk.group_id, gk.epoch, gk.key, identity.protected_dict(), install_id=install_id,
                           members_epoch=gk.epoch, members=_member_ids(new_ring),
                           keyring=canonical_json(new_ring), folder_path=folder,
                           unacked_members=_pending(new_ring, identity.device_id))
    with session.transaction():
        _store(session, group_id, _new_record(new_ring["metadata"], "member", state))
        if existing is None:
            _add_shared_collection(session, meta["collection_id"], name, group_id)
        else:
            _mark_collection(session, meta["collection_id"], group_id)
            _drop_link(session, meta["collection_id"])  # now shared here: this device speaks for it
    return _group(state)


def adopt_keyring(session: Any, group_id: str, keyring_bytes: bytes, *,
                  _kdf_override: tuple[int, int, int] | None = None) -> ShareGroup:
    """Accept a newer keyring of *group_id* (same epoch, e.g. a member joined, or the next epoch).

    Authenticated against the stored trusted key (``accept_keyring``) and the owner's signature
    (structure check).  Refused (``tampered``) if it changes the pinned owner id or key, the
    collection id or the shared mode; one that no longer lists the owner fails the structure
    check (``bad-owner``).  At the stored epoch the keyring may only grow
    (``_check_same_epoch_growth``): a member cannot drop anyone, this device included, or
    replay an older owner signature.  Members the owner has not approved are stored as
    unacknowledged (``unacked_members``): no signing authority, never signers of a removal notice.
    """
    record, state = _record(session, group_id)
    ring = parse_keyring(keyring_bytes)
    gk = accept_keyring(ring, _gk(state), state.identity(), _kdf_override=_kdf_override)
    meta = keyring_metadata(ring)
    if meta is None or any(meta[k] != record[k] for k in _PINNED):
        raise KeyringError("tampered", "the keyring changes the share's owner, collection or mode")
    if gk.epoch == state.epoch:
        _check_same_epoch_growth(parse_keyring(state.keyring), ring)
    ids = _member_ids(ring)
    if state.device_id not in ids:  # only an owner-signed rotation gets here
        raise ShareGroupError("removed", "this device is no longer in the share group")
    reset = epoch_reset_fields(state) if gk.epoch != state.epoch else {}
    new_state = dataclasses.replace(state, epoch=gk.epoch, key=gk.key, members_epoch=gk.epoch, members=ids,
                                    keyring=canonical_json(ring),
                                    unacked_members=_pending(ring, state.device_id), **reset)
    with session.transaction():
        _store(session, group_id, _with_state(record, new_state))
    return _group(new_state)


def reconcile_owner_keyring(session: Any, group_id: str, keyring_bytes: bytes, *,
                            _kdf_override: tuple[int, int, int] | None = None) -> bool:
    """Owner only: re-sign this device's approvals onto a folder keyring that others grew meanwhile.

    The owner approved members (``approve_members``, kept in the vault) while someone else joined
    through the folder at the same epoch, so neither keyring grows from the other.  When the folder
    keyring authenticates under the trusted key and, with the owner's approvals re-applied, grows
    from the stored one (``_check_same_epoch_growth``: nobody dropped, no wrap or key changed), it
    becomes the stored keyring; the new joiners stay pending.  Returns False (and changes nothing)
    on a member's device or for any other keyring.
    """
    record, state = _record(session, group_id)
    if record["role"] != "owner" or state.device_id != record["owner"]:
        return False
    try:
        stored = parse_keyring(state.keyring)
        folder = parse_keyring(keyring_bytes)
        if folder.get("group_id") != state.group_id or folder.get("epoch") != state.epoch:
            return False
        ring = owner_approve_members(folder, _gk(state), state.identity(),
                                     approve=approved_members(stored) or (), reuse_wraps=stored.get("content"),
                                     _kdf_override=_kdf_override)
        meta = keyring_metadata(ring)
        if meta is None or any(meta[k] != record[k] for k in _PINNED):
            return False
        _check_same_epoch_growth(stored, ring)
    except (KeyringError, KeyError, TypeError, AttributeError):
        return False
    new_state = dataclasses.replace(state, members_epoch=state.epoch, members=_member_ids(ring),
                                    keyring=canonical_json(ring), unacked_members=_pending(ring, state.device_id))
    with session.transaction():
        _store(session, group_id, _with_state(record, new_state))
    return True


def superseded_join(session: Any, group_id: str, keyring_bytes: bytes, *,
                    _kdf_override: tuple[int, int, int] | None = None) -> bool:
    """Whether this device's pending join of *group_id* was lost to another join at the same moment.

    Two people joined from the same folder keyring; the other one's keyring reached the folder
    and this device's never did.  True only on a member's device when the folder keyring
    *keyring_bytes* authenticates under the trusted key (MAC and owner signature), is at the
    stored epoch, no longer lists this device, and grows (``_check_same_epoch_growth``) from the
    stored keyring with this device's own join (its last member entry and wrap) taken out: so it
    dropped nobody else and changed no wrap or key.  The user joins again (``join_share_group``);
    anything else stays a refusal (``tampered``).
    """
    try:
        record, state = _record(session, group_id)
        if record["role"] != "member" or state.device_id == record["owner"]:
            return False
        stored = parse_keyring(state.keyring)
        folder = parse_keyring(keyring_bytes)
        if folder.get("group_id") != state.group_id or folder.get("epoch") != state.epoch:
            return False
        accept_keyring(folder, _gk(state), state.identity(), _kdf_override=_kdf_override)
        own = state.device_id
        if own in _member_ids(folder):
            return False
        members = stored["members"]
        if not members or members[-1]["device_id"] != own:
            return False
        base = {**stored, "members": members[:-1],
                "device_wraps": {d: w for d, w in stored["device_wraps"].items() if d != own}}
        _check_same_epoch_growth(base, folder)
    except (ShareGroupError, KeyringError, KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False
    return True


def _owner_signed_ahead(record: Mapping[str, Any], state: SyncGroupState, ring: Mapping, *,
                        _kdf_override: tuple[int, int, int] | None = None) -> bool:
    """Whether *ring* is a later epoch of this share, signed by the pinned owner key.

    Only the owner's own device can make one, so an owner's device that trusts an older epoch (its
    vault went back, for example to a backup) never writes that older keyring over it.
    """
    try:
        epoch = ring.get("epoch")
        if ring.get("group_id") != state.group_id or type(epoch) is not int or epoch <= state.epoch:
            return False
        verify_keyring_structure(ring, _kdf_override=_kdf_override)  # the owner signature included
        meta = keyring_metadata(ring)
        return meta is not None and all(meta[k] == record[k] for k in _PINNED)
    except (KeyringError, KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _authenticates_at_epoch(record: Mapping[str, Any], state: SyncGroupState, ring: Mapping, *,
                            _kdf_override: tuple[int, int, int] | None = None) -> bool:
    """Whether *ring* (at the trusted epoch) has a valid MAC under ``G`` and the pinned owner's signature."""
    try:
        accept_keyring(dict(ring), _gk(state), state.identity(), _kdf_override=_kdf_override)
        meta = keyring_metadata(ring)
        return meta is not None and meta["owner"] == record["owner"] and meta["owner_key"] == record["owner_key"]
    except (KeyringError, KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def restores_over(session: Any, group_id: str, keyring_bytes: bytes, *,
                  _kdf_override: tuple[int, int, int] | None = None) -> bool:
    """Whether this device writes its trusted keyring over a folder keyring it could not take.

    The transport asks only after adopting, reconciling and the superseded-join check failed, or
    for bytes that do not parse or that name another group.  Without this, anyone who can write to
    the share folder could stop the share on every device, and a removed person usually keeps
    access to the cloud folder.

    * The owner's device: always.  The owner is the only authority, so its trusted copy is always
      legitimate.  The one exception is a later epoch signed by the pinned owner key
      (``_owner_signed_ahead``): only this owner made it, and writing an older keyring over it
      would undo the owner's own rotation.
    * A member's device: only when the folder keyring is at the trusted epoch and does not
      authenticate (MAC under the trusted key, or the pinned owner's signature).  An authenticated
      keyring of that epoch that does not grow is a concurrent join and still stops the run.
    """
    try:
        record, state = _record(session, group_id)
    except ShareGroupError:
        return False
    owner = record["role"] == "owner" and state.device_id == record["owner"]
    try:
        ring = parse_keyring(keyring_bytes)
    except KeyringError:
        return owner
    if owner:
        return not _owner_signed_ahead(record, state, ring, _kdf_override=_kdf_override)
    epoch = ring.get("epoch")
    if ring.get("group_id") != state.group_id or type(epoch) is not int or epoch != state.epoch:
        return False
    return not _authenticates_at_epoch(record, state, ring, _kdf_override=_kdf_override)


def _require_owner(record: Mapping[str, Any], state: SyncGroupState) -> None:
    if record["role"] != "owner" or state.device_id != record["owner"]:
        raise ShareGroupError("not-owner", "only the person who shared the collection does this")


def pending_members(session: Any, group_id: str) -> tuple[Member, ...]:
    """Members waiting for the owner's approval, with their names: the UI shows these to the owner."""
    _, state = _record(session, group_id)
    return tuple(m for m in _group(state).members if not m.approved)


def approve_members(session: Any, group_id: str, device_ids: Iterable[str], *,
                    _kdf_override: tuple[int, int, int] | None = None) -> tuple[Member, ...]:
    """The owner approves *device_ids*, each of which the UI showed by name (``pending_members``).

    Only pending members can be named (``not-pending`` otherwise, also for an empty choice); the
    others stay pending.  Returns the members just approved (with their names).  The new keyring
    (same epoch, owner-signed again) is kept in the vault for the share transport to write.
    """
    record, state = _record(session, group_id)
    _require_owner(record, state)
    chosen = set(device_ids)
    pending = {m.device_id: m for m in pending_members(session, group_id)}
    if not chosen or not chosen <= set(pending):
        raise ShareGroupError("not-pending", "approve only members that are waiting")
    ring = owner_approve_members(parse_keyring(state.keyring), _gk(state), state.identity(), approve=chosen,
                                 _kdf_override=_kdf_override)
    new_state = dataclasses.replace(state, keyring=canonical_json(ring),
                                    unacked_members=_pending(ring, state.device_id))
    with session.transaction():
        _store(session, group_id, _with_state(record, new_state))
    return tuple(dataclasses.replace(pending[d], approved=True) for d in sorted(chosen))


def leave_share_group(session: Any, group_id: str) -> None:
    """Forget *group_id* on this vault (allowed without Pro).

    The collection stops being shared here and keeps its items; the group's keys are dropped.
    The other members still list this device until the owner removes it.
    """
    record, _ = _record(session, group_id)
    with session.transaction():
        _forget(session, group_id, record)


def _forget(session: Any, group_id: str, record: Mapping[str, Any]) -> None:
    """Drop the group, its share bookkeeping and the collection's share mark (inside a transaction)."""
    _store(session, group_id, None)
    forget_share_meta(_payload(session), record["collection_id"])
    # A link of the same collection from another of this person's devices that also shares it (final review B1)
    # goes too: this device's next personal run tombstones the link, and a device that still shares republishes it.
    _drop_link(session, record["collection_id"])
    row = next((r for r in _collections(session) if r.get("id") == record["collection_id"]), None)
    if row is not None and row.get("shared_group_id") == group_id:
        _mark_collection(session, record["collection_id"], None)


def remove_member(session: Any, group_id: str, device_id: str, *, new_password: str,
                  now: int | None = None, _kdf_override: tuple[int, int, int] | None = None) -> bytes:
    """Remove *device_id* from *group_id* (owner only); returns the signed removal notice to write.

    Works without Pro (revoking access is a security action).  Rotates the share keyring (new
    key, epoch + 1, a NEW share password, required because the removed person knows the old one)
    and the owner signs the remaining members.  Members the owner has not approved are dropped too
    (audit M10) but get no notice.  The notice names this share group only, so it can never be
    taken for a removal from the member's own device sync; nothing of the member's own vault is
    touched.
    """
    record, state = _record(session, group_id)
    _require_owner(record, state)
    if not isinstance(device_id, str) or not is_valid_id(device_id):
        raise ShareGroupError("not-member", "invalid device id")
    ring = parse_keyring(state.keyring)
    pending = [d for d in state.unacked_members if d != device_id and d in _member_ids(ring)]
    names = member_names(ring, _gk(state))
    identity = state.identity()
    # A share v1 group is upgraded to share v2 in the same rotation (new content key for the others).
    new_ring, gk = rotate(ring, _gk(state), identity, new_password, remove=[device_id, *pending], upgrade=True,
                          _kdf_override=_kdf_override)
    notice = make_notice(identity.signing_key, group_id=group_id, device_id=device_id, epoch=gk.epoch,
                         signer=identity.device_id, now=now)
    new_state = dataclasses.replace(state, epoch=gk.epoch, key=gk.key, members_epoch=gk.epoch,
                                    members=_member_ids(new_ring), keyring=canonical_json(new_ring),
                                    unacked_members=(), **epoch_reset_fields(state))
    new_record = _with_state(record, new_state)
    _note_removed(new_record, [names.get(d) for d in (device_id, *pending) if d in names],
                  int(time.time()) if now is None else now)
    with session.transaction():
        _store(session, group_id, new_record)
    return notice


# --- removal notices ----------------------------------------------------------------------------------

def share_watch(session: Any, group_id: str, folder: Path | str) -> Watch | None:
    """The removal watch of this device in *group_id*: the pinned owner is the only signer.

    None on the owner's own device: the owner never acts on a removal notice.
    """
    record, state = _record(session, group_id)
    if record["role"] == "owner" or state.device_id == record["owner"]:
        return None
    return Watch(state.group_id, state.device_id, state.epoch, state.install_id or "", str(folder),
                 {record["owner"]: record["owner_key"]})


def verify_share_notice(session: Any, group_id: str, raw: bytes, folder_keyring: bytes) -> Notice:
    """The notice *raw* if the pinned owner removed this device from *group_id*; else ``RemovalError``.

    Refused (``owner``) on the owner's own device, whatever the notice says.
    """
    watch = share_watch(session, group_id, ".")
    if watch is None:
        raise RemovalError("owner")
    return verify_notice(raw, watch, folder_keyring)


def apply_share_removal(session: Any, group_id: str, raw: bytes, folder_keyring: bytes) -> int:
    """The pinned owner removed this device from *group_id*: trash this collection's items, leave the group.

    *raw* must verify as a notice from the owner for this device (``verify_share_notice``; refused
    on the owner's own device).  Every live item tagged with the shared collection goes to the trash
    (recoverable), documents last; a tagged document still linked from an item outside the
    collection stays (the vault refuses to trash it).  Nothing else in the vault is touched
    (personal items, other collections, the personal sync group).  Returns how many items were
    moved.  Allowed without Pro.  A trash too full for these items, a full history or any other
    item error refuses the whole removal with ``ShareGroupError("trash-full" | "history-quota" |
    "history-error" | "item-error")`` and nothing changes: the user frees space (or fixes the
    item) and the next run tries again.
    """
    verify_share_notice(session, group_id, raw, folder_keyring)
    record, _ = _record(session, group_id)
    collection_id = record["collection_id"]
    from .. import item_service
    from ..history import HistoryError, HistoryQuotaError
    from ..vault import VaultError

    service = item_service.ItemService(session)
    moved = 0
    try:
        with session.transaction(), item_service.sync_writes():
            rows = [i for i in _payload(session).get("items", [])
                    if isinstance(i, dict) and collection_id in (i.get("collection_ids") or ())]
            rows.sort(key=lambda i: i.get("kind") == "document")  # linking items first, then documents
            if rows and len(_payload(session).get("trash", [])) + len(rows) > item_service.MAX_ITEMS:
                raise ShareGroupError("trash-full", "the trash cannot hold this collection's items")
            for row in rows:
                if row.get("kind") == "document" and _linked_document(session, row["id"]):
                    continue
                moved += bool(service.delete_item(row["id"]))
            _forget(session, group_id, record)
    except HistoryQuotaError as exc:
        raise ShareGroupError("history-quota", str(exc)) from None
    except HistoryError as exc:
        raise ShareGroupError("history-error", str(exc)) from None
    except (ItemSchemaError, VaultError) as exc:
        # Not the trash limit (checked above): an item the vault refuses to move, reported as it is.
        raise ShareGroupError("item-error", str(exc)) from None
    return moved


def _linked_document(session: Any, document_id: str) -> bool:
    """Whether a live item still links *document_id* (``payload.document_ids``)."""
    for item in _payload(session).get("items", []):
        typed = item.get("payload") if isinstance(item, dict) else None
        if isinstance(typed, dict) and document_id in (typed.get("document_ids") or ()):
            return True
    return False


__all__ = [
    "Member", "ProRequired", "ShareGroup", "ShareGroupError", "adopt_keyring", "apply_share_removal",
    "approve_members", "linked_read_only_collection_ids", "pending_members", "read_only_collection_ids",
    "reconcile_owner_keyring", "share_links",
    "removed_members", "superseded_join",
    "save_share_state", "set_share_folder",
    "share_folders", "share_info",
    "create_share_group", "forget_share_link", "join_share_group", "leave_share_group", "list_share_groups",
    "received_share_link", "remove_member", "shared_twice", "needs_upgrade", "upgrade_share", "view_key",
    "require_share_sync", "share_keyring", "share_state", "share_sync_allowed", "share_watch",
    "verify_share_notice",
]
