"""One sync run shared by every transport: local view -> merge peer views -> one apply.

``run_merge`` is the only place that turns peer views into vault changes.  The
cloud-folder transport (``folder_transport``) and the LAN transport both call
it, so an edit that arrives through both routes is merged by the same code and
is idempotent (the second arrival is dominated or identical).

Order and determinism
---------------------
Peer views are merged one after another in ``device_id`` order (a stable sort,
so the same view passed twice is harmless) into a working copy of the local
view, and the combined outcome is applied in one ``apply`` call (one vault
transaction).  A conflict copy produced earlier in the run that a later peer
view already carries is replaced by the peer's stored version before that view
is merged: this is the engine's own rule for a copy the remote batch carries,
extended across views, so a copy never conflicts with itself.

Failure handling
----------------
* A peer state whose version vector is implausible next to the local state of
  that id (``engine.implausible_vv``: a counter far beyond anything honest
  edits produce, audit M-6) is quarantined before the merge and reported as
  ``SyncIssue("implausible-vv", "<device_id>:<item_id>")``; the rest of that
  view merges.  Known devices for that rule are this device, the peers whose
  views are merged, and the stored group's members, last-seen peers and LAN
  peers (or *known_devices* when the caller passes them).
* A peer view the engine rejects as a whole (malformed batch, duplicate ids)
  is dropped with ``SyncIssue("bad-peer-data", device_id)``; the run continues
  with the other views.
* A single peer record the bridge refuses to store (``bad-remote``: for
  example a field a newer app version added) is quarantined: only that record
  is removed from that peer's view, reported once as
  ``SyncIssue("bad-peer-record", "<device_id>:<item_id>")``, and the rest of
  the view is merged again.  The local copy of that id is left exactly as it
  is (never tombstoned or overwritten because of the bad record; a peer view
  without a record never deletes it).  When the failing id cannot be traced
  to one record of that view, the whole view is dropped (``bad-peer-data``).
  A record whose wrapper ``schema`` is newer than this app understands
  (reason ``update-needed``) takes the same path and is reported as
  ``SyncIssue("update-needed", "<device_id>:<item_id>")``.  A document whose file
  has not been imported yet (reason ``attachment-missing``) is set aside the same
  way as ``SyncIssue("attachment-missing", "<device_id>:<item_id>")``; the next
  run tries again.
* ``apply`` refusing because a record changed locally after the view was taken
  (reason ``vault-changed``) is retried once with a fresh ``local_view``; a
  second refusal gives ``SyncIssue("busy")``.
* ``trash-full`` and ``history-quota`` become issues of that kind; any other
  bridge failure while applying gives ``apply-failed``.  Nothing is applied in
  these cases, but ``own_states`` still carries the local view so a transport
  can publish this device's own edits.
* A local vault that cannot be read for sync gives ``local-data`` and
  ``own_states`` None (publish nothing).
* Lock/lease errors propagate unchanged: the run stops without writing.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .engine import (
    EngineError,
    ItemState,
    MergeOutcome,
    _content_digest,
    conflict_copy_id,
    implausible_vv,
    is_valid_id,
    merge,
)
from .group import View
from .vault_bridge import BridgeError, LocalView, apply, load_sync_state, local_view

USER_FIXABLE = frozenset({"trash-full", "history-quota"})


@dataclass(frozen=True)
class SyncIssue:
    """Something a run skipped or refused; ``kind`` is a stable code, ``detail`` free text."""

    kind: str
    detail: str = ""


@dataclass(frozen=True)
class RunReport:
    """Result of one run.

    ``own_states`` is this device's post-apply view (sorted by id) for the
    transport to publish, or None when nothing should be published.
    ``wrote`` is set by a transport that wrote its own file or message.
    ``licenses`` are the licence bundles received in this run that verified;
    the sync service offers them to ``licensing.adopt_synced_license``.
    """

    applied: int = 0
    deleted: int = 0
    conflicts: int = 0
    skipped: tuple[tuple[str, str], ...] = ()
    issues: tuple[SyncIssue, ...] = ()
    own_states: tuple[ItemState, ...] | None = None
    wrote: bool = False
    licenses: tuple[dict[str, Any], ...] = ()


def _peer_id(view: Any) -> str | None:
    header = getattr(view, "header", None)
    if not isinstance(view, View) or not isinstance(header, Mapping):
        return None
    dev = header.get("device_id")
    return dev if is_valid_id(dev) else None


def _sorted_states(view: LocalView) -> tuple[ItemState, ...]:
    return tuple(view[k] for k in sorted(view))


def _combine(local: Mapping[str, ItemState], views: list[View],
             issues: list[SyncIssue]) -> tuple[MergeOutcome, dict[str, tuple[str, str]], list[View]]:
    """Merge *views* in order into a working copy of *local*; returns the combined outcome.

    Also returns, per changed id, the peer it came from and the id of that
    peer's record that caused it (a conflict copy maps to the record it
    conflicted with), and the views that merged.
    """
    working: dict[str, ItemState] = dict(local)
    pending: set[str] = set()  # conflict copies created in this run, not yet stored anywhere
    origin: dict[str, tuple[str, str]] = {}
    conflicts: list[tuple[ItemState, ItemState]] = []
    used: list[View] = []
    for view in views:
        dev = view.header["device_id"]
        trial, trial_pending = dict(working), set(pending)
        for item_id in {s.item_id for s in view.states} & trial_pending:
            # The peer already stores this copy: take its version, as merge() does for one batch.
            del trial[item_id]
            trial_pending.discard(item_id)
        try:
            out = merge(trial, view.states)
        except EngineError:
            issues.append(SyncIssue("bad-peer-data", dev))
            continue
        copy_cause: dict[str, str] = {}
        for loc, remote in out.conflicts:
            for side in (loc, remote):
                if side.item is not None:
                    copy_cause[conflict_copy_id(remote.item_id, _content_digest(side.item))] = remote.item_id
        for state in (*out.upserts, *out.deletes):
            trial[state.item_id] = state
            trial_pending.discard(state.item_id)
            origin[state.item_id] = (dev, state.item_id)
        for state in out.copies:
            trial[state.item_id] = state
            trial_pending.add(state.item_id)
            origin[state.item_id] = (dev, copy_cause.get(state.item_id, state.item_id))
        working, pending = trial, trial_pending
        conflicts.extend(out.conflicts)
        used.append(view)

    upserts: list[ItemState] = []
    deletes: list[ItemState] = []
    copies: list[ItemState] = []
    for item_id in sorted(working):
        state = working[item_id]
        if local.get(item_id) == state:
            continue
        if item_id in pending:
            copies.append(state)
        elif state.deleted:
            deletes.append(state)
        else:
            upserts.append(state)
    outcome = MergeOutcome(tuple(upserts), tuple(deletes), tuple(conflicts), tuple(copies))
    return outcome, origin, used


def _without_record(views: list[View], device_id: str, record_id: str) -> tuple[list[View], bool]:
    """*views* with *record_id* removed from *device_id*'s view; whether a record was removed."""
    out: list[View] = []
    removed = False
    for view in views:
        if view.header["device_id"] == device_id:
            kept = tuple(st for st in view.states if st.item_id != record_id)
            if len(kept) != len(view.states):
                removed = True
                view = View(view.header, kept)
        out.append(view)
    return out, removed


def _known_devices(session: Any, device_id: str, peers: list[View]) -> set[str]:
    """This device, the peers of this run and every device the stored group state knows."""
    known = {device_id} | {v.header["device_id"] for v in peers}
    try:
        state = load_sync_state(session)
    except BridgeError:
        state = None
    if state is not None:
        known |= set(state.members) | set(state.last_seen) | {state.device_id}
        known |= {p["device_id"] for p in state.lan_peers if isinstance(p.get("device_id"), str)}
    return known


def _plausible(views: list[View], local: LocalView, known: set[str], issues: list[SyncIssue],
               reported: set[tuple[str, str]]) -> list[View]:
    """*views* without the states whose vector is implausible next to *local* (reported once each)."""
    out: list[View] = []
    for view in views:
        dev = view.header["device_id"]
        kept: list[ItemState] = []
        for state in view.states:
            loc = local.get(state.item_id)
            if implausible_vv(state.vv, loc.vv if loc is not None else None, known) is None:
                kept.append(state)
            elif (dev, state.item_id) not in reported:
                reported.add((dev, state.item_id))
                issues.append(SyncIssue("implausible-vv", f"{dev}:{state.item_id}"))
        out.append(view if len(kept) == len(view.states) else View(view.header, tuple(kept)))
    return out


def run_merge(session: Any, lease: Any, *, device_id: str, views: Iterable[View], now: int,
              known_devices: Iterable[str] | None = None) -> RunReport:
    """Merge every peer view into the vault in one apply; see the module docstring."""
    issues: list[SyncIssue] = []
    peers: list[View] = []
    for view in views:
        dev = _peer_id(view)
        if dev is None:
            issues.append(SyncIssue("bad-peer-data", "?"))
        elif dev != device_id:
            peers.append(view)
    peers.sort(key=lambda v: v.header["device_id"])
    if known_devices is None:
        known = _known_devices(session, device_id, peers)
    else:
        known = {device_id, *known_devices} | {v.header["device_id"] for v in peers}

    retried = False
    quarantined: set[tuple[str, str]] = set()
    implausible: set[tuple[str, str]] = set()
    while True:
        try:
            local = local_view(session, lease, device_id=device_id, now=now)
        except BridgeError as exc:
            issues.append(SyncIssue("local-data", str(exc)))
            return RunReport(issues=tuple(issues))
        peers = _plausible(peers, local, known, issues, implausible)
        outcome, origin, peers = _combine(local, peers, issues)
        local_skipped = tuple(sorted(local.skipped.items()))
        try:
            report = apply(session, lease, outcome, device_id=device_id, now=now)
        except BridgeError as exc:
            if exc.reason in ("bad-remote", "update-needed", "attachment-missing") and exc.item_id in origin:
                bad, record_id = origin[exc.item_id]
                peers, removed = _without_record(peers, bad, record_id)
                if removed and (bad, record_id) not in quarantined:
                    quarantined.add((bad, record_id))
                    kind = {"update-needed": "update-needed",
                            "attachment-missing": "attachment-missing"}.get(exc.reason, "bad-peer-record")
                    issues.append(SyncIssue(kind, f"{bad}:{record_id}"))
                else:  # not traceable to one record of that view: drop the view
                    issues.append(SyncIssue("bad-peer-data", bad))
                    peers = [v for v in peers if v.header["device_id"] != bad]
                continue
            if exc.reason == "vault-changed" and not retried:
                retried = True
                continue
            if exc.reason == "vault-changed":
                kind = "busy"
            elif exc.reason in USER_FIXABLE:
                kind = exc.reason
            else:
                kind = "apply-failed"
            issues.append(SyncIssue(kind, str(exc)))
            return RunReport(skipped=local_skipped, issues=tuple(issues), own_states=_sorted_states(local))
        break

    try:
        final = local_view(session, lease, device_id=device_id, now=now)
    except BridgeError as exc:
        issues.append(SyncIssue("local-data", str(exc)))
        final = None
    skipped = tuple(sorted(set(local_skipped) | set(report.skipped)))
    return RunReport(
        applied=report.applied,
        deleted=report.deleted,
        conflicts=report.conflicts,
        skipped=skipped,
        issues=tuple(issues),
        own_states=_sorted_states(final) if final is not None else None,
        licenses=report.licenses,
    )


__all__ = ["RunReport", "SyncIssue", "run_merge"]
