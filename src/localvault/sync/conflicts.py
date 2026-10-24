"""Deterministic retention and explicit resolution of sync conflicts."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .manifest import ManifestError, SyncRecord, _revision_relation

MAX_CONFLICTS = 500
MAX_CONFLICT_ID_LENGTH = 128


class ConflictError(ManifestError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


@dataclass(frozen=True)
class ConflictCopy:
    conflict_id: str
    original_id: str
    retained: SyncRecord
    side: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"conflict_id": self.conflict_id, "original_id": self.original_id,
                "retained": self.retained.to_dict(), "side": self.side, "reason": self.reason}


@dataclass(frozen=True)
class MergeResult:
    records: tuple[SyncRecord, ...]
    conflicts: tuple[ConflictCopy, ...] = ()

    @property
    def has_conflicts(self) -> bool:
        return bool(self.conflicts)


def deterministic_conflict_id(original_id: str, local: SyncRecord, remote: SyncRecord) -> str:
    """Derive an id from content/revisions, independent of arrival order."""

    material = _canonical({
        "original_id": original_id,
        "left": {"digest": local.digest, "revision": local.revision.to_dict(),
                 "deleted": local.deleted},
        "right": {"digest": remote.digest, "revision": remote.revision.to_dict(),
                  "deleted": remote.deleted},
    })
    return f"{original_id}~conflict-{hashlib.sha256(material).hexdigest()[:24]}"


def _conflict_copy(original_id: str, retained: SyncRecord, conflict_id: str,
                   side: str, reason: str) -> ConflictCopy:
    copy_record = SyncRecord(
        record_id=conflict_id, ciphertext=retained.ciphertext, revision=retained.revision,
        deleted=retained.deleted, digest=retained.digest, original_id=original_id,
    )
    return ConflictCopy(conflict_id, original_id, copy_record, side, reason)


def merge_record_pair(local: SyncRecord, remote: SyncRecord) -> tuple[SyncRecord, ConflictCopy | None]:
    """Merge one id; concurrent edit/edit and edit/delete always retain both."""

    if local.record_id != remote.record_id:
        raise ConflictError("Cannot merge records with different IDs")
    relation = _revision_relation(local.revision, remote.revision)
    if relation in {"equal", "local"}:
        if relation == "equal" and local.digest != remote.digest:
            raise ConflictError("One revision was reused for different ciphertext")
        return local, None
    if relation == "remote":
        return remote, None
    reason = "edit-delete" if local.deleted != remote.deleted else "concurrent-edit"
    conflict_id = deterministic_conflict_id(local.record_id, local, remote)
    # Keep the local record at its stable id and retain the remote record under
    # a deterministic visible copy.  No arrival order can silently erase data.
    return local, _conflict_copy(local.record_id, remote, conflict_id, "remote", reason)


def merge_records(local_records: Iterable[SyncRecord],
                  remote_records: Iterable[SyncRecord]) -> MergeResult:
    local = {row.record_id: row for row in local_records}
    remote = {row.record_id: row for row in remote_records}
    if len(local) > MAX_CONFLICTS or len(remote) > MAX_CONFLICTS:
        raise ConflictError("Conflict merge exceeds the bounded record count")
    merged: dict[str, SyncRecord] = dict(local)
    conflicts: list[ConflictCopy] = []
    for record_id, remote_row in remote.items():
        if record_id not in local:
            merged[record_id] = remote_row
            continue
        chosen, conflict = merge_record_pair(local[record_id], remote_row)
        merged[record_id] = chosen
        if conflict is not None:
            if conflict.conflict_id in merged:
                raise ConflictError("Deterministic conflict ID collided with existing data")
            merged[conflict.conflict_id] = conflict.retained
            conflicts.append(conflict)
    if len(conflicts) > MAX_CONFLICTS:
        raise ConflictError("Conflict merge exceeds the bounded conflict count")
    return MergeResult(tuple(merged[key] for key in sorted(merged)), tuple(conflicts))


class ConflictStore:
    """In-memory conflict index; callers persist it inside encrypted state."""

    def __init__(self, conflicts: Iterable[ConflictCopy] = ()) -> None:
        self._conflicts: dict[str, ConflictCopy] = {}
        for conflict in conflicts:
            self.retain(conflict)

    def retain(self, conflict: ConflictCopy) -> None:
        if not isinstance(conflict, ConflictCopy):
            raise ConflictError("Conflict copy is malformed")
        if len(self._conflicts) >= MAX_CONFLICTS and conflict.conflict_id not in self._conflicts:
            raise ConflictError("Conflict store is full")
        self._conflicts[conflict.conflict_id] = conflict

    def list(self, original_id: str | None = None) -> tuple[ConflictCopy, ...]:
        rows = self._conflicts.values()
        if original_id is not None:
            rows = (row for row in rows if row.original_id == original_id)
        return tuple(sorted(rows, key=lambda row: row.conflict_id))

    def resolve(self, conflict_id: str, *, choice: str,
                merged_record: SyncRecord | None = None) -> SyncRecord | None:
        """Resolve explicitly; ``local`` discards only the retained copy."""

        conflict = self._conflicts.get(conflict_id)
        if conflict is None:
            raise ConflictError("Conflict was not found")
        if choice not in {"local", "remote", "merged"}:
            raise ConflictError("Conflict resolution choice is invalid")
        if choice == "merged":
            if merged_record is None or merged_record.record_id != conflict.original_id:
                raise ConflictError("A merged record with the original ID is required")
            result = merged_record
        elif choice == "remote":
            result = SyncRecord(
                record_id=conflict.original_id, ciphertext=conflict.retained.ciphertext,
                revision=conflict.retained.revision, deleted=conflict.retained.deleted,
                digest=conflict.retained.digest,
            )
        else:
            result = None
        del self._conflicts[conflict_id]
        return result

    def to_list(self) -> list[dict[str, Any]]:
        return [row.to_dict() for row in self.list()]


def resolve_conflict(result: MergeResult, conflict_id: str, *, choice: str,
                     merged_record: SyncRecord | None = None) -> MergeResult:
    """Return a new result after an explicit local/remote/merged decision."""

    target = next((row for row in result.conflicts if row.conflict_id == conflict_id), None)
    if target is None:
        raise ConflictError("Conflict was not found")
    if choice not in {"local", "remote", "merged"}:
        raise ConflictError("Conflict resolution choice is invalid")
    records = {row.record_id: row for row in result.records}
    records.pop(target.conflict_id, None)
    if choice == "remote":
        records[target.original_id] = SyncRecord(
            record_id=target.original_id, ciphertext=target.retained.ciphertext,
            revision=target.retained.revision, deleted=target.retained.deleted,
            digest=target.retained.digest,
        )
    elif choice == "merged":
        if merged_record is None or merged_record.record_id != target.original_id:
            raise ConflictError("A merged record with the original ID is required")
        records[target.original_id] = merged_record
    remaining = tuple(row for row in result.conflicts if row.conflict_id != conflict_id)
    return MergeResult(tuple(records[key] for key in sorted(records)), remaining)


__all__ = [
    "ConflictCopy", "MergeResult", "ConflictStore", "ConflictError",
    "deterministic_conflict_id", "merge_record_pair", "merge_records", "resolve_conflict",
]
