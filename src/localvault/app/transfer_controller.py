"""Encrypted transfer controller and its view helpers (no UI toolkit)."""
from __future__ import annotations

import copy
import logging
import os
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..session_guard import StaleSession
from ..transfer import (
    MAX_TRANSFER_BYTES,
    MAX_TRANSFER_FILES,
    MAX_TRANSFER_ITEMS,
    TransferCancelled,
    TransferError,
    export_selective_transfer,
    import_transfer,
    inspect_transfer,
    preview_selective_transfer,
    preview_transfer,
)
from ..vault import ItemLimitReached
from ..i18n import t

ConflictPolicy = str


CONFLICT_POLICIES = ("skip", "copy", "replace")


_log = logging.getLogger(__name__)


def import_limit_lines(summary: Mapping[str, Any]) -> list[str]:
    """Free plan lines for an import preview or result; empty when unlimited."""
    if summary.get("item_limit") is None:
        return []
    skipped = len(summary.get("limit_skipped_ids") or [])
    lines: list[str] = []
    if skipped:
        lines.append(t("transfer.limitSkippedDone" if summary.get("committed") else "transfer.limitSkippedPlan",
                       count=skipped, limit=summary["item_limit"]))
    free = summary.get("free_slots")
    if free is not None and not summary.get("committed"):
        lines.append(t("transfer.freeSlots", count=free))
    return lines


def notify_item_limit(callback: Callable[[ItemLimitReached], Any] | None, summary: Mapping[str, Any]) -> bool:
    """Offer Pro through ``callback`` when an import left records out; never raises."""
    limit = summary.get("item_limit")
    if callback is None or limit is None or not summary.get("limit_skipped_ids"):
        return False
    try:
        callback(ItemLimitReached(limit, limit))
    except Exception:
        _log.warning("Could not offer Pro after a limited transfer import", exc_info=True)
        return False
    return True


def _values(value: Iterable[str] | str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


@dataclass(frozen=True)
class TransferSelection:
    """Explicit, serializable selection criteria for one export preview."""

    ids: tuple[str, ...] = ()
    item_ids: tuple[str, ...] = ()
    credential_ids: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    collection_ids: tuple[str, ...] = ()
    exclude_ids: tuple[str, ...] = ()
    attachment_ids: tuple[str, ...] = ()
    favorite: bool | None = None
    include_attachments: bool = True

    def __post_init__(self) -> None:
        for name in (
            "ids", "item_ids", "credential_ids", "kinds", "tags",
            "collection_ids", "exclude_ids", "attachment_ids",
        ):
            object.__setattr__(self, name, _values(getattr(self, name)))
        if self.favorite is not None and type(self.favorite) is not bool:
            raise TransferError("Favorite selection must be a boolean")
        if type(self.include_attachments) is not bool:
            raise TransferError("Attachment inclusion must be a boolean")

    @classmethod
    def from_values(cls, **values: Any) -> TransferSelection:
        """Build a selection from UI form values without retaining widget state."""
        aliases = dict(values)
        if "selected_ids" in aliases and "ids" not in aliases:
            aliases["ids"] = aliases.pop("selected_ids")
        if "types" in aliases and "kinds" not in aliases:
            aliases["kinds"] = aliases.pop("types")
        if "tag" in aliases and "tags" not in aliases:
            aliases["tags"] = aliases.pop("tag")
        if "favorite_only" in aliases and "favorite" not in aliases:
            aliases["favorite"] = aliases.pop("favorite_only")
        allowed = {
            "ids", "item_ids", "credential_ids", "kinds", "tags", "collection_ids",
            "exclude_ids", "attachment_ids", "favorite", "include_attachments",
        }
        unknown = set(aliases) - allowed
        if unknown:
            raise TransferError(f"Unknown transfer selection fields: {', '.join(sorted(unknown))}")
        return cls(**aliases)

    @property
    def selected_ids(self) -> tuple[str, ...]:
        return self.ids

    def as_kwargs(self) -> dict[str, Any]:
        values: dict[str, Any] = {
            "ids": self.ids,
            "item_ids": self.item_ids,
            "credential_ids": self.credential_ids,
            "kinds": self.kinds,
            "tags": self.tags,
            "collection_ids": self.collection_ids,
            "exclude_ids": self.exclude_ids,
            "attachment_ids": self.attachment_ids,
            "favorite": self.favorite,
            "include_attachments": self.include_attachments,
        }
        return {key: value for key, value in values.items() if value not in ((), None)}


def _safe_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Copy only the documented, non-payload manifest fields."""
    if not isinstance(manifest, Mapping):
        raise TransferError("Transfer manifest is malformed")

    def rows(name: str, fields: tuple[str, ...]) -> list[dict[str, Any]]:
        raw = manifest.get(name, [])
        if not isinstance(raw, list):
            raise TransferError("Transfer manifest is malformed")
        result: list[dict[str, Any]] = []
        for row in raw:
            if not isinstance(row, Mapping):
                raise TransferError("Transfer manifest is malformed")
            result.append({key: copy.deepcopy(row[key]) for key in fields if key in row})
        return result

    safe = {
        "manifest_version": manifest.get("manifest_version"),
        "created_at": manifest.get("created_at"),
        "item_count": manifest.get("item_count", 0),
        "credential_count": manifest.get("credential_count", 0),
        "attachment_count": manifest.get("attachment_count", 0),
        "attachment_bytes": manifest.get("attachment_bytes", 0),
        "items": rows("items", ("id", "kind", "title", "revision", "collection_ids")),
        "credentials": rows("credentials", ("id", "kind", "label", "updated_at")),
        "collections": rows("collections", ("id", "name", "revision")),
        "attachments": rows("attachments", ("id", "name", "mime_type", "size", "sha256")),
    }
    for key in ("item_count", "credential_count", "attachment_count", "attachment_bytes"):
        if type(safe[key]) is not int or safe[key] < 0:
            raise TransferError("Transfer manifest counts are malformed")
    if safe["item_count"] != len(safe["items"]) or safe["credential_count"] != len(safe["credentials"]):
        raise TransferError("Transfer manifest counts are inconsistent")
    if safe["attachment_count"] != len(safe["attachments"]):
        raise TransferError("Transfer manifest attachment count is inconsistent")
    attachment_sizes = [row.get("size") for row in safe["attachments"]]
    if any(type(size) is not int or size < 0 for size in attachment_sizes):
        raise TransferError("Transfer manifest attachment sizes are malformed")
    if sum(attachment_sizes) != safe["attachment_bytes"]:
        raise TransferError("Transfer manifest attachment bytes are inconsistent")
    return safe


def summarize_manifest(manifest: Mapping[str, Any], **extra: Any) -> dict[str, Any]:
    """Return safe counts and metadata suitable for a confirmation dialog."""
    safe = _safe_manifest(manifest)
    kind_counts: dict[str, int] = {}
    for row in [*safe["items"], *safe["credentials"]]:
        kind = str(row.get("kind", "unknown"))
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
    result: dict[str, Any] = {
        "manifest": safe,
        "item_count": safe["item_count"],
        "credential_count": safe["credential_count"],
        "record_count": safe["item_count"] + safe["credential_count"],
        "attachment_count": safe["attachment_count"],
        "attachment_bytes": safe["attachment_bytes"],
        "kind_counts": kind_counts,
        "requires_confirmation": False,
        "committed": False,
    }
    result.update(copy.deepcopy(extra))
    return result


class TransferSessionBinding:
    """Bind transfer actions to one unlocked profile and optional lease."""

    def __init__(
        self,
        session: Any,
        *,
        lease: Any = None,
        guard: Any = None,
        require_lease: Callable[[Any], Any] | None = None,
        session_provider: Callable[[], Any] | None = None,
    ) -> None:
        self._session = session
        self._session_provider = session_provider
        self._guard = guard
        self._require_lease_callback = require_lease
        if lease is None and guard is not None and callable(getattr(guard, "lease", None)):
            lease = guard.lease()
        self.lease = lease
        self._path = self._session_path(session)

    @staticmethod
    def _session_path(session: Any) -> str | None:
        value = getattr(session, "path", None)
        if value is None:
            return None
        try:
            return os.path.normcase(os.path.abspath(os.fspath(value)))
        except (TypeError, ValueError, OSError):
            return str(value)

    def current(self) -> Any:
        current = self._session_provider() if self._session_provider is not None else self._session
        if current is not self._session:
            raise StaleSession(t("transfer.profileSessionChangedTheTransfer"))
        if self._session_path(current) != self._path:
            raise StaleSession(t("transfer.profileSessionDestinationChangedThe"))
        if not bool(getattr(current, "is_unlocked", False)):
            raise StaleSession(t("transfer.vaultIsLockedUnlockAnd"))
        if self._guard is not None:
            if self.lease is None or not callable(getattr(self._guard, "require", None)):
                raise StaleSession(t("transfer.theTransferHasNoValid"))
            self._guard.require(self.lease)
        if self._require_lease_callback is not None:
            if self.lease is None:
                raise StaleSession(t("transfer.theTransferHasNoValid"))
            self._require_lease_callback(self.lease)
        return current


class TransferController:
    """Controller/view-model for explicit encrypted transfer workflows.

    ``preview_export`` and ``preview_import`` never publish or commit data.
    ``export`` always performs a fresh export preview first.  ``import_package``
    returns a non-mutating preview until ``confirm=True`` is supplied.
    """

    def __init__(
        self,
        session: Any,
        *,
        lease: Any = None,
        guard: Any = None,
        require_lease: Callable[[Any], Any] | None = None,
        session_provider: Callable[[], Any] | None = None,
        max_items: int = MAX_TRANSFER_ITEMS,
        max_files: int = MAX_TRANSFER_FILES,
        max_bytes: int = MAX_TRANSFER_BYTES,
    ) -> None:
        if session is None:
            raise TransferError("An unlocked vault session is required")
        self.binding = TransferSessionBinding(
            session, lease=lease, guard=guard, require_lease=require_lease,
            session_provider=session_provider,
        )
        self.max_items = int(max_items)
        self.max_files = int(max_files)
        self.max_bytes = int(max_bytes)
        if self.max_items <= 0 or self.max_files <= 0 or self.max_bytes <= 0:
            raise TransferError("Transfer bounds must be positive")

    @property
    def session(self) -> Any:
        return self.binding.current()

    @staticmethod
    def _selection(selection: TransferSelection | Mapping[str, Any] | None, values: Mapping[str, Any]) -> TransferSelection:
        if selection is not None and values:
            raise TransferError("Specify either a TransferSelection or selection fields")
        if isinstance(selection, TransferSelection):
            return selection
        if isinstance(selection, Mapping):
            return TransferSelection.from_values(**dict(selection))
        return TransferSelection.from_values(**dict(values))

    @staticmethod
    def _local_path(value: Path | str, *, label: str) -> Path:
        raw = os.fspath(value)
        if not isinstance(raw, str) or not raw.strip():
            raise TransferError(f"{label} must be a local path")
        if raw.startswith(("\\\\", "//")) or "://" in raw:
            raise TransferError(f"{label} must be a local, non-network path")
        path = Path(raw)
        if path.name in {"", ".", ".."}:
            raise TransferError(f"{label} must name a file")
        return path

    def _check_manifest_bounds(self, manifest: Mapping[str, Any]) -> None:
        safe = _safe_manifest(manifest)
        if safe["item_count"] + safe["credential_count"] > self.max_items:
            raise TransferError("Transfer record count exceeds the UI bound")
        if safe["attachment_count"] > self.max_files or safe["attachment_bytes"] > self.max_bytes:
            raise TransferError("Transfer attachment bounds exceed the UI limit")

    @staticmethod
    def _check_cancel(cancel: Any) -> None:
        if cancel is None:
            return
        try:
            value = cancel.is_set() if hasattr(cancel, "is_set") else (
                cancel() if callable(cancel) else bool(cancel)
            )
        except Exception as exc:
            raise TransferCancelled(t("transfer.transferOperationWasCancelled")) from exc
        if value:
            raise TransferCancelled(t("transfer.transferOperationWasCancelled"))

    @staticmethod
    def _result_summary(result: Mapping[str, Any], **extra: Any) -> dict[str, Any]:
        safe_manifest = _safe_manifest(result.get("manifest", {}))
        result_copy = summarize_manifest(safe_manifest)
        result_copy.update({
            "manifest": safe_manifest,
            "conflict_policy": result.get("conflict_policy", "skip"),
            "dry_run": bool(result.get("dry_run", True)),
            "committed": bool(result.get("committed", False)),
            "imported_ids": list(result.get("imported_ids", [])),
            "skipped_ids": list(result.get("skipped_ids", [])),
            "copied_ids": list(result.get("copied_ids", [])),
            "replaced_ids": list(result.get("replaced_ids", [])),
            "limit_skipped_ids": list(result.get("limit_skipped_ids", [])),
            "item_limit": result.get("item_limit"),
            "free_slots": result.get("free_slots"),
            "id_map": copy.deepcopy(result.get("id_map", {})),
            "attachment_map": copy.deepcopy(result.get("attachment_map", {})),
        })
        result_copy.update(copy.deepcopy(extra))
        return result_copy

    def preview_export(
        self,
        selection: TransferSelection | Mapping[str, Any] | None = None,
        *,
        cancel: Any = None,
        **selection_fields: Any,
    ) -> dict[str, Any]:
        self._check_cancel(cancel)
        session = self.binding.current()
        chosen = self._selection(selection, selection_fields)
        manifest = preview_selective_transfer(session, cancel=cancel, **chosen.as_kwargs())
        self._check_manifest_bounds(manifest)
        self._check_cancel(cancel)
        return summarize_manifest(manifest, operation="export", dry_run=True)

    dry_run_export = preview_export

    def export(
        self,
        destination: Path | str,
        transfer_password: str,
        selection: TransferSelection | Mapping[str, Any] | None = None,
        *,
        cancel: Any = None,
        overwrite: bool = False,
        master_password: str | None = None,
        **selection_fields: Any,
    ) -> dict[str, Any]:
        destination_path = self._local_path(destination, label=t("transfer.transferDestination"))
        if master_password is not None and transfer_password == master_password:
            raise TransferError(t("transfer.transferPasswordMustBeDistinct"))
        # This is intentionally a fresh preview immediately before export.
        preview = self.preview_export(selection, cancel=cancel, **selection_fields)
        session = self.binding.current()
        manifest = export_selective_transfer(
            session, destination_path, transfer_password, cancel=cancel, overwrite=overwrite,
            **self._selection(selection, selection_fields).as_kwargs(),
        )
        self.binding.current()
        return summarize_manifest(
            manifest, operation="export", dry_run=False, committed=True,
            destination=str(destination_path), preview=preview,
        )

    export_transfer = export

    def inspect_package(self, source: Path | str) -> dict[str, Any]:
        self.binding.current()
        package = self._local_path(source, label=t("transfer.transferPackage"))
        manifest = inspect_transfer(package)
        self._check_manifest_bounds(manifest)
        return summarize_manifest(manifest, operation="inspect", dry_run=True)

    inspect = inspect_package

    def preview_import(
        self,
        source: Path | str,
        transfer_password: str,
        *,
        conflict_policy: ConflictPolicy = "skip",
        allow_replace: bool = False,
        expected_revisions: Mapping[str, int] | None = None,
        cancel: Any = None,
    ) -> dict[str, Any]:
        self._check_cancel(cancel)
        session = self.binding.current()
        package = self._local_path(source, label=t("transfer.transferPackage"))
        result = preview_transfer(
            package, session, transfer_password, conflict_policy=conflict_policy,
            allow_replace=allow_replace, expected_revisions=expected_revisions,
        )
        self._check_cancel(cancel)
        self._check_manifest_bounds(result["manifest"])
        return self._result_summary(
            result, operation="import", requires_confirmation=True,
            cancellation_supported=cancel is not None,
        )

    dry_run_import = preview_import

    def import_package(
        self,
        source: Path | str,
        transfer_password: str,
        *,
        confirm: bool = False,
        conflict_policy: ConflictPolicy = "skip",
        allow_replace: bool = False,
        expected_revisions: Mapping[str, int] | None = None,
        cancel: Any = None,
    ) -> dict[str, Any]:
        preview = self.preview_import(
            source, transfer_password, conflict_policy=conflict_policy,
            allow_replace=allow_replace, expected_revisions=expected_revisions,
            cancel=cancel,
        )
        if not confirm:
            return preview
        # Revalidate after the user confirmation and before any destination
        # mutation.  import_transfer performs a second authenticated plan.
        session = self.binding.current()
        package = self._local_path(source, label=t("transfer.transferPackage"))
        result = import_transfer(
            package, session, transfer_password, conflict_policy=conflict_policy,
            allow_replace=allow_replace, expected_revisions=expected_revisions,
            cancel=cancel,
        )
        self.binding.current()
        return self._result_summary(
            result, operation="import", requires_confirmation=False,
            preview=preview,
        )

    import_transfer = import_package

    def commit_import(self, source: Path | str, transfer_password: str, **kwargs: Any) -> dict[str, Any]:
        kwargs["confirm"] = True
        return self.import_package(source, transfer_password, **kwargs)
