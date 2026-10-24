"""Pure version-vector merge engine for LocalGateKeys device sync.

No I/O, no clocks.  The desktop app and the iOS app implement exactly these
rules, so every decision is derived from version vectors and canonical JSON.

Rules (mirrored by iOS)
-----------------------
* Canonical JSON: sorted keys, compact separators, ensure_ascii=False, UTF-8.  The full byte rules
  (code-point key order, float formatting) are in the "Canonical JSON" block of ``keyring.py``.
* Identifiers (device ids, item ids, group ids, version-vector keys) are
  ASCII only: 1..128 chars from ``[A-Za-z0-9._:-]`` (uuid strings qualify).
  This keeps canonical JSON byte-identical across Python and Swift (no
  escaping, ordering or length ambiguity).
* Version vector: device id -> counter.  Counters are ints in 0..2**53-1
  (bool rejected).  Missing entries equal 0; zero entries are dropped and
  vectors are stored with sorted keys.
* Plausibility (a policy of the runner, not a format rule): ``implausible_vv`` bounds how far a
  REMOTE vector may advance (2**40, 2**20 for unknown keys, or 2**20 above the local counter);
  ``runner.run_merge`` quarantines a remote state that fails it, so a poisoned vector can never
  make a local ``bump`` overflow.  A ``bump`` that still overflows (a vector stored before this
  rule) skips only that item.
* ``item_id``: an identifier as above.
* ``deleted_at``: None or an int in 0..2**53-1.  ``item`` is None iff deleted,
  otherwise a dict that canonical JSON can encode (str keys; str/int/finite
  float/bool/None/list/dict values; no lone surrogates).
* Compare: ``a``/``b`` if one vector dominates, ``equal``, else ``concurrent``.
  Remote dominates -> apply it; local dominates -> nothing.
* Equal vectors with differing content are treated as concurrent, except that
  when the LOCAL state wins nothing is upserted (the merged vector equals the
  local one, so it would be a no-op) and the pair is reported as a conflict
  only if a conflict copy is emitted.  A second merge of the same remote after
  applying the first is therefore empty (idempotent).
* Concurrent, both deleted: one tombstone, merged vector, deleted_at = max,
  emitted only if it differs from local.  Identical live content: merged vector.
* Concurrent, one side deleted: the live side wins with the merged vector
  (upserted whichever side it came from); the pair is reported as a conflict.
* Concurrent, both live and different: the winner has the larger
  ``item["updated_at"]`` (a non-int, bool, negative or > 2**53-1 value counts as
  0, so a float is 0), tie broken by the larger sha256 hex of canonical JSON of
  the item.  The winner keeps the id with the merged vector.  The loser becomes
  a copy state: id = ``conflict_copy_id(item_id, sha256(canonical_json(loser
  item without "id")))`` (uuid5 under the item's namespace, name
  ``"lgk-copy:" + digest``), vector = loser's vector, item = loser item with
  "id" set to the copy id.  The id depends only on content, so it is
  independent of merge order.
* A copy whose id local already holds, or that the remote batch carries, is
  dropped by ``merge``.
* Wall-clock values never influence which state wins except ``updated_at``
  as above.
* Local edits and deletes bump the item's vector the standard way:
  ``vv[device] = vv.get(device, 0) + 1`` (see ``bump``).
* No copy is ever retired automatically: a state is only superseded by a
  state whose vector dominates it, so user content disappears only through a
  user's own edit or delete.

Known v1 limitations
--------------------
* A rare duplicate live item can remain after certain 3-device
  edit/delete/edit histories (e.g. an edit that loses to a concurrent edit
  becomes a copy, then also wins back the original id over a concurrent
  delete).  It is harmless and visible; the user deletes it.
* A user-deleted conflict copy can reappear if the same loser content
  conflicts again at a vector its tombstone does not dominate.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

from localvault.updates import canonical_json

VersionVector = Mapping[str, int]

_MAX_INT = 2**53 - 1

_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")


def is_valid_id(value: object) -> bool:
    """True for a format-1 identifier: ASCII ``[A-Za-z0-9._:-]``, 1..128 chars."""
    return isinstance(value, str) and _ID_RE.fullmatch(value) is not None


class EngineError(ValueError):
    """Malformed input to the merge engine."""


def _check_vv(vv: object) -> None:
    if not isinstance(vv, Mapping):
        raise EngineError("version vector must be a mapping")
    for dev, n in vv.items():
        if not is_valid_id(dev):
            raise EngineError(f"invalid device id: {dev!r}")
        if isinstance(n, bool) or not isinstance(n, int) or not 0 <= n <= _MAX_INT:
            raise EngineError(f"invalid counter for {dev!r}: {n!r}")


#: Plausibility of a REMOTE vector (audit 2026-10-24 M-6).  The format allows counters up to 2**53-1, but
#: a counter counts one device's edits of ONE item, so honest values stay tiny.  A peer (anyone holding
#: the group key) could otherwise publish 2**53-1 and make the next local edit of that item overflow.
MAX_VV_COUNTER = 2**40
#: A key that is neither a known device nor already in the local vector of that item gets this bound.
MAX_UNKNOWN_VV_COUNTER = 2**20
#: A counter may always move this far above the local value of the same key (honest edits past a bound).
MAX_VV_STEP = 2**20
MAX_VV_KEYS = 512


def implausible_vv(remote: VersionVector, local: VersionVector | None,
                   known: Iterable[str] | frozenset[str] = frozenset()) -> str | None:
    """Why the remote vector *remote* of an item is implausible next to its local vector, else None.

    Rules (mirrored by Kotlin ``Plausibility`` and Swift ``Plausibility``): more than ``MAX_VV_KEYS``
    keys is ``"too-many-keys"``.  A key whose remote counter is at most the local one is fine.  A
    key that advances must stay within its bound (``MAX_VV_COUNTER`` for a key in *known* or in the
    local vector, else ``MAX_UNKNOWN_VV_COUNTER``) OR within ``MAX_VV_STEP`` of the local counter;
    otherwise ``"implausible-counter"``.  A missing local vector is empty.
    """
    base_vv = local or {}
    known_ids = known if isinstance(known, (set, frozenset)) else frozenset(known)
    if len(remote) > MAX_VV_KEYS:
        return "too-many-keys"
    for dev, n in remote.items():
        base = base_vv.get(dev, 0)
        if n <= base:
            continue
        limit = MAX_VV_COUNTER if (dev in known_ids or dev in base_vv) else MAX_UNKNOWN_VV_COUNTER
        if n > limit and n - base > MAX_VV_STEP:
            return "implausible-counter"
    return None


def compare(a: VersionVector, b: VersionVector) -> Literal["equal", "a", "b", "concurrent"]:
    """Compare two vectors; ``"a"`` means *a* dominates.  Missing entries are 0."""
    _check_vv(a)
    _check_vv(b)
    a_ahead = b_ahead = False
    for dev in set(a) | set(b):
        x, y = a.get(dev, 0), b.get(dev, 0)
        if x > y:
            a_ahead = True
        elif y > x:
            b_ahead = True
    if a_ahead and b_ahead:
        return "concurrent"
    if a_ahead:
        return "a"
    if b_ahead:
        return "b"
    return "equal"


def bump(vv: VersionVector, device_id: str) -> dict[str, int]:
    """Vector for a local edit or delete by *device_id*: ``vv[device_id] += 1``.

    Standard version-vector increment (missing counts as 0); the result has
    sorted keys and no zero entries.
    """
    _check_vv(vv)
    _check_vv({device_id: 1})
    n = vv.get(device_id, 0) + 1
    if n > _MAX_INT:
        raise EngineError(f"counter for {device_id!r} overflows")
    out = {d: c for d, c in vv.items() if c}
    out[device_id] = n
    return dict(sorted(out.items()))


def _max_vv(a: VersionVector, b: VersionVector) -> dict[str, int]:
    return {d: n for d in sorted(set(a) | set(b)) if (n := max(a.get(d, 0), b.get(d, 0)))}


MAX_ITEM_INT = 2**63 - 1  # item integers must fit a signed 64-bit value on every platform
_HYPHENATED_UUID = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")


def _check_json(value: object, depth: int = 0) -> None:
    if depth > 64:
        raise EngineError("item nesting too deep")
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if not -MAX_ITEM_INT <= value <= MAX_ITEM_INT:
            raise EngineError("integer out of range")
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise EngineError("non-finite float in item")
        return
    if isinstance(value, list):
        for v in value:
            _check_json(v, depth + 1)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise EngineError("item keys must be strings")
            _check_json(v, depth + 1)
        return
    raise EngineError(f"unsupported item value type: {type(value).__name__}")


@dataclass(frozen=True)
class ItemState:
    item_id: str
    vv: dict[str, int]
    deleted: bool
    deleted_at: int | None
    item: dict | None

    def __post_init__(self) -> None:
        if not is_valid_id(self.item_id):
            raise EngineError("item_id must be 1..128 ASCII chars from [A-Za-z0-9._:-]")
        _check_vv(self.vv)
        # canonical form: zero entries equal missing entries, so drop them
        object.__setattr__(self, "vv", {d: n for d, n in sorted(self.vv.items()) if n})
        if not isinstance(self.deleted, bool):
            raise EngineError("deleted must be a bool")
        if self.deleted_at is not None and (
            isinstance(self.deleted_at, bool)
            or not isinstance(self.deleted_at, int)
            or not 0 <= self.deleted_at <= _MAX_INT
        ):
            raise EngineError("deleted_at must be None or an int in 0..2**53-1")
        if self.deleted != (self.item is None):
            raise EngineError("item must be None exactly when deleted")
        if self.item is not None and not isinstance(self.item, dict):
            raise EngineError("item must be a dict")
        if self.item is not None:
            _check_json(self.item)
            try:
                canonical_json(self.item)
            except (ValueError, TypeError, RecursionError) as exc:
                raise EngineError(f"item is not canonical-JSON safe: {exc}") from exc


@dataclass(frozen=True)
class MergeOutcome:
    upserts: tuple[ItemState, ...]
    deletes: tuple[ItemState, ...]
    conflicts: tuple[tuple[ItemState, ItemState], ...]  # (local, remote)
    copies: tuple[ItemState, ...] = ()  # conflict copies not already held locally or in the remote batch


def _identical(a: ItemState, b: ItemState) -> bool:
    if a.deleted or b.deleted:
        return a.deleted and b.deleted
    return canonical_json(a.item) == canonical_json(b.item)


def _with_vv(s: ItemState, vv: dict[str, int], deleted_at: int | None) -> ItemState:
    return ItemState(s.item_id, vv, s.deleted, deleted_at, s.item)


def _updated_at(item: dict) -> int:
    v = item.get("updated_at", 0)
    if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= _MAX_INT:
        return v
    return 0


def _rank(s: ItemState) -> tuple[int, str]:
    return (_updated_at(s.item), hashlib.sha256(canonical_json(s.item)).hexdigest())


def merge(local: Mapping[str, ItemState], remote: Iterable[ItemState]) -> MergeOutcome:
    """Decide what to apply locally given remote states.  Pure and order-independent.

    Conflicts resolve deterministically so every device reaches the same state:
    the live side wins an edit/delete clash, and of two differing live states
    the one with the larger ``updated_at`` (then larger content hash) keeps the
    original id while the loser is preserved as an explicit copy state.
    """
    for key, st in local.items():
        if not isinstance(st, ItemState) or st.item_id != key:
            raise EngineError(f"local state keyed {key!r} is inconsistent")
    remote_list = list(remote)
    seen: set[str] = set()
    for r in remote_list:
        if not isinstance(r, ItemState):
            raise EngineError("remote entries must be ItemState")
        if r.item_id in seen:
            raise EngineError(f"duplicate remote item id: {r.item_id}")
        seen.add(r.item_id)

    upserts: list[ItemState] = []
    deletes: list[ItemState] = []
    conflicts: list[tuple[ItemState, ItemState]] = []
    copies: list[ItemState] = []

    for r in sorted(remote_list, key=lambda s: s.item_id):
        loc = local.get(r.item_id)
        if loc is None:
            (deletes if r.deleted else upserts).append(r)
            continue
        rel = compare(loc.vv, r.vv)
        if rel == "a":
            continue
        if rel == "b":
            (deletes if r.deleted else upserts).append(r)
            continue
        merged = _max_vv(loc.vv, r.vv)
        if loc.deleted and r.deleted:
            stamps = [t for t in (loc.deleted_at, r.deleted_at) if t is not None]
            at = max(stamps) if stamps else None
            if rel != "equal" or at != loc.deleted_at:
                deletes.append(_with_vv(r, merged, at))
            continue
        if rel == "equal" and _identical(loc, r):
            continue
        # concurrent (or equal vectors with differing content, treated as concurrent)
        if _identical(loc, r):
            upserts.append(_with_vv(r, merged, None))
        elif loc.deleted or r.deleted:
            live = r if r.deleted is False else loc
            # Equal vectors and the local live state wins: merged == local vector, so
            # re-upserting it would change nothing and repeat on every round.
            if live is r or rel != "equal":
                upserts.append(_with_vv(live, merged, None))
                conflicts.append((loc, r))
        else:
            win, lose = (r, loc) if _rank(r) > _rank(loc) else (loc, r)
            changed = win is r or rel != "equal"
            if changed:
                upserts.append(_with_vv(win, merged, None))
            cid = conflict_copy_id(r.item_id, _content_digest(lose.item))
            if cid not in local and cid not in seen:
                body = {k: v for k, v in lose.item.items() if k != "id"}
                copies.append(
                    ItemState(cid, dict(lose.vv), False, None, {**body, "id": cid})
                )
                changed = True
            if changed:
                conflicts.append((loc, r))

    return MergeOutcome(tuple(upserts), tuple(deletes), tuple(conflicts), tuple(copies))


def _content_digest(item: dict) -> str:
    body = {k: v for k, v in item.items() if k != "id"}
    return hashlib.sha256(canonical_json(body)).hexdigest()


def conflict_copy_id(item_id: str, content_digest: str) -> str:
    """Deterministic id for the conflict copy of *item_id* holding *content_digest*.

    The digest is the sha256 hex of canonical JSON of the loser item without "id".
    """
    if not isinstance(item_id, str) or not isinstance(content_digest, str) or not content_digest:
        raise EngineError("item_id and content_digest must be non-empty strings")
    if _HYPHENATED_UUID.fullmatch(item_id):
        ns = uuid.UUID(item_id)
    else:
        ns = uuid.uuid5(uuid.NAMESPACE_URL, "lgk-item:" + item_id)
    return str(uuid.uuid5(ns, "lgk-copy:" + content_digest))
