"""Restore a phone backup (``LGKMBAK1``) into the desktop vault through the sync merge.

The backup's states go into ``run_merge`` as one peer view, so every sync rule
applies unchanged: an item the desktop holds at a newer or equal version vector
is never overwritten, a tombstone deletes only what the engine says it
dominates, and a failed apply leaves the vault as it was.  Device identity and
the group key are not in a backup, and ``pro_hint`` grants nothing.

On the free plan the view is trimmed before it is merged, so the preview shows
exactly what restore writes.  New live items beyond ``free_item_slots`` are held
back (newest ``updated_at`` kept, ties by id ascending).  A backup state whose
merge would create a conflict copy counts as a new item too: copies are ranked
after plain new items, and a state whose copy does not fit is left out of the
view (the desktop keeps its own version) and counted as held back.  Updates to
items the desktop already holds are never capped.  When ``totp`` is not an
allowed feature, every login state whose two-factor key differs from the local
one is rewritten so the key lives in a hidden custom field instead; the rewrite
happens before the merge, so restoring the same backup again changes nothing.
A state the bridge would refuse (``vault_bridge.check_remote_state``: malformed,
or written by a newer version) is left out of the view before the cap, so it
never takes a free slot, and is counted as skipped; so is a state whose version
vector is implausible next to the desktop's (``engine.implausible_vv``, audit
M-6: a crafted backup must not make the next local edit overflow); the merge still quarantines
anything the check could not foresee.  Counts come from merging the final view
into the vault's current view; items the phone deleted move to the trash and are
counted as deleted.  Licence states restore like sync's: the merge keeps a
licence only when it verifies on this build, and the caller offers the received
ones to ``licensing.adopt_synced_license`` (``RestoreReport.licenses``).

Document files (backup format 2): a live document state is restored only with its file. Its file
comes from the backup (``PhoneBackup.files``) or is already in this vault under the same catalog
row; otherwise the state is left out of the view and counted in ``files_missing`` (a format-1
backup, or a file the phone left out over the size limit). The preview writes nothing; ``restore``
verifies and stores the needed files (``attachment_flow.import_missing``) just before the merge, and
a refused file (``attachment-refused``) keeps its document out (``attachment-missing``).
"""
from __future__ import annotations

import copy
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..phone_backup import PhoneBackup
from ..transfer import _feature_allowed, _keep_totp_as_field
from ..vault import free_item_slots
from .engine import (
    ItemState,
    MergeOutcome,
    _content_digest,
    conflict_copy_id,
    implausible_vv,
    merge,
)
from .attachment_sync import AttachmentRef, AttachmentSyncError
from .group import View
from .runner import _known_devices, run_merge
from .vault_bridge import _catalog_row, _documents, check_remote_state, is_document_state, load_sync_state, local_view
from ..i18n import t


@dataclass(frozen=True)
class RestorePlan:
    new: int
    updated: int
    unchanged: int
    held_back: int
    totp_as_field: int
    view: View
    skipped: int = 0
    deleted: int = 0
    #: blob id -> sealed blob, the backup files the view's documents need.
    files: Any = None
    files_missing: int = 0


@dataclass(frozen=True)
class RestoreReport:
    new: int
    updated: int
    held_back: int
    totp_as_field: int
    issues: tuple[str, ...]
    skipped: int = 0
    deleted: int = 0
    licenses: tuple[dict[str, Any], ...] = ()
    files: int = 0
    files_missing: int = 0


# Run issue kinds that skip one record while the rest is applied.
QUARANTINE_KINDS = frozenset({"bad-peer-record", "update-needed", "implausible-vv"})


def desktop_device_id(session: Any) -> str:
    """This desktop's sync device id: the group's, else the stored one, else a new one."""
    state = load_sync_state(session)
    if state is not None:
        return state.device_id
    meta = session._require_typed_catalog().get("sync_meta")
    if isinstance(meta, dict) and isinstance(meta.get("device_id"), str) and meta["device_id"]:
        return meta["device_id"]
    return str(uuid.uuid4())


def _wrapper_ns(state: ItemState) -> str | None:
    item = state.item
    return item.get("ns") if isinstance(item, dict) else None


def _is_content(state: ItemState) -> bool:
    return not state.deleted and _wrapper_ns(state) in ("entry", "item")


def _updated_at(state: ItemState) -> int:
    value = state.item.get("updated_at") if state.item else 0
    return value if type(value) is int else 0


class PhoneRestoreError(Exception):
    """The backup cannot be restored on this computer."""


def _rewrite_totp(states: tuple[ItemState, ...], local: dict[str, ItemState]) -> tuple[dict[str, ItemState], set[str]]:
    """The backup states by id, with new two-factor keys kept as hidden fields; and the ids rewritten."""
    out: dict[str, ItemState] = {}
    rewritten: set[str] = set()
    for state in states:
        if _wrapper_ns(state) == "entry" and not state.deleted:
            local_state = local.get(state.item_id)
            original = local_state.item["record"] if local_state is not None and local_state.item else None
            item = copy.deepcopy(state.item)
            record = item["record"]
            before = copy.deepcopy(record)
            _keep_totp_as_field(record, original)
            if record != before:
                rewritten.add(state.item_id)
                state = ItemState(state.item_id, state.vv, False, None, item)
        out[state.item_id] = state
    return out, rewritten


def _copy_causes(out: MergeOutcome) -> dict[str, int]:
    """Backup state id -> number of conflict copies its merge creates (licence copies excluded)."""
    cause: dict[str, str] = {}
    for loc, remote in out.conflicts:
        for side in (loc, remote):
            if side.item is not None:
                cause[conflict_copy_id(remote.item_id, _content_digest(side.item))] = remote.item_id
    counts: dict[str, int] = {}
    for state in out.copies:
        if _wrapper_ns(state) in ("entry", "item") and state.item_id in cause:
            counts[cause[state.item_id]] = counts.get(cause[state.item_id], 0) + 1
    return counts


def _tally(local: dict[str, ItemState],
           states: Iterable[ItemState]) -> tuple[set[str], set[str], dict[str, int], set[str]]:
    """(new ids, updated ids, copies per backup state id, deleted ids) of merging *states* into *local*."""
    out = merge(local, states)
    upserts = [s.item_id for s in out.upserts if _is_content(s)]
    new = {i for i in upserts if i not in local or local[i].deleted}
    deleted = {s.item_id for s in out.deletes if s.item_id in local and _is_content(local[s.item_id])}
    return new, set(upserts) - new, _copy_causes(out), deleted


def _file_present(session: Any, attachment_id: str) -> bool:
    """The stored file exists (a catalog row whose file was deleted still needs the backup's copy)."""
    from ..attachments import AttachmentError, AttachmentStore

    try:
        path = AttachmentStore(session)._path(attachment_id)
    except AttachmentError:
        return False
    return path.is_file() and not path.is_symlink()


def _document_files(session: Any, states: dict[str, ItemState],
                    files: Any) -> tuple[dict[str, bytes], set[str]]:
    """(files the live documents need from the backup, ids of documents whose file is nowhere)."""
    payload = session._require_typed_catalog()
    needed: dict[str, bytes] = {}
    missing: set[str] = set()
    for item_id, state in states.items():
        if state.deleted or not is_document_state(state):
            continue
        try:
            ref = AttachmentRef.from_value(state.item.get("attachment"))
        except AttachmentSyncError:
            continue  # the bridge refuses it and the merge reports it
        row = _catalog_row(payload, ref.attachment_id)
        if row is not None and {**row, "mime_type": row.get("mime_type") or "application/octet-stream"} == ref.catalog_record()                 and _file_present(session, ref.attachment_id):
            continue  # already on this device, the file included
        blob = (files or {}).get(ref.blob)
        if blob is None:
            missing.add(item_id)
        else:
            needed[ref.blob] = blob
    return needed, missing


def plan_restore(session: Any, lease: Any, backup: PhoneBackup, *, now: int) -> RestorePlan:
    """What restoring *backup* would do; reads the vault only (apart from sync metadata).

    The counts come from merging the final view (after the free-plan cap and
    the two-factor rewrite), so they match what ``restore`` writes.
    """
    device_id = desktop_device_id(session)
    if backup.device_id == device_id:
        raise PhoneRestoreError(t("phoneRestore.thisBackupWasMadeOn"))
    local = dict(local_view(session, lease, device_id=device_id, now=now))
    by_id, rewritten = ({s.item_id: s for s in backup.states}, set())
    if not _feature_allowed(session, "totp"):
        by_id, rewritten = _rewrite_totp(backup.states, local)
    # Records the bridge would refuse never reach the merge, so they take no free slot; nor do
    # states with an implausible version vector (run_merge would quarantine them anyway).
    known = _known_devices(session, device_id, [View({"device_id": backup.device_id}, ())])
    with _documents(session):  # documents are checked as apply checks them (with their reference)
        unreadable = {i for i, s in by_id.items()
                      if check_remote_state(s) is not None
                      or implausible_vv(s.vv, local[i].vv if i in local else None, known) is not None}
    by_id = {i: s for i, s in by_id.items() if i not in unreadable}
    needed, no_file = _document_files(session, by_id, getattr(backup, "files", None))
    by_id = {i: s for i, s in by_id.items() if i not in no_file}

    held: set[str] = set()
    slots = free_item_slots(session)
    if slots is not None:
        new, _updated, copies, _deleted = _tally(local, by_id.values())
        ranked_new = sorted(new, key=lambda i: (-_updated_at(by_id[i]), i))
        held.update(ranked_new[slots:])
        remaining = max(0, slots - len(ranked_new))
        for item_id in sorted(copies, key=lambda i: (-_updated_at(by_id[i]), i)):
            if copies[item_id] <= remaining:
                remaining -= copies[item_id]
            else:
                held.add(item_id)
    final = tuple(s for i, s in by_id.items() if i not in held)

    new, updated, copies, deleted = _tally(local, final)
    touched = new | updated | set(copies)
    content = sum(1 for s in final if _is_content(s))
    return RestorePlan(
        new=len(new) + sum(copies.values()),
        updated=len(updated),
        unchanged=content - len(touched),
        held_back=len(held),
        totp_as_field=len(touched & rewritten),
        view=View({"device_id": backup.device_id}, final),
        skipped=len(unreadable),
        deleted=len(deleted),
        files={b: d for b, d in needed.items() if any(
            not s.deleted and is_document_state(s) and (s.item.get("attachment") or {}).get("blob") == b
            for s in final)},
        files_missing=len(no_file),
    )


def _live_ids(session: Any) -> set[str]:
    payload = session._require_typed_catalog()
    return {r["id"] for key in ("entries", "items") for r in payload.get(key, [])}


def restore(session: Any, lease: Any, plan: RestorePlan, *, now: int) -> RestoreReport:
    """Merge the planned view into the vault in one run; the counts are what was applied.

    ``skipped`` is the plan's unreadable records plus any the merge quarantined.
    """
    from .attachment_flow import import_missing

    before = _live_ids(session)
    files = plan.files or {}
    file_issues = import_missing(session, lease, plan.view.states, lambda ref: files.get(ref.blob)) if files else []
    report = run_merge(session, lease, device_id=desktop_device_id(session), views=[plan.view], now=now)
    new = len(_live_ids(session) - before)
    updated = max(0, report.applied - new)
    return RestoreReport(
        new=new,
        updated=updated,
        held_back=plan.held_back,
        # An upper bound: a stale plan that was only partly applied cannot say which items were rewritten.
        totp_as_field=min(plan.totp_as_field, new + updated),
        issues=tuple(issue.kind for issue in (*file_issues, *report.issues)),
        skipped=plan.skipped + sum(1 for issue in report.issues if issue.kind in QUARANTINE_KINDS),
        deleted=report.deleted,
        licenses=report.licenses,
        files=len(files) - sum(1 for issue in file_issues if issue.kind == "attachment-refused"),
        files_missing=plan.files_missing,
    )


__all__ = ["QUARANTINE_KINDS", "PhoneRestoreError", "RestorePlan", "RestoreReport", "desktop_device_id", "plan_restore", "restore"]
