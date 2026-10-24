"""Session-bound Phase 2 workspace seams.

This module is a small view-model/controller boundary for collections,
declarative templates, encrypted document sidecars, reminders, and activity.
It deliberately does not add a storage model or a network client.  Lists use
metadata summaries only; document bytes and protected typed values cross this
boundary only from an explicit action with a live session binding.

The optional Tk presentation lives in :mod:`safe_workspace_extras_ui` so this
module remains useful to tests and non-GUI callers without creating windows.
"""
from __future__ import annotations

import copy
import datetime as _datetime
import os
import uuid
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from .attachments import AttachmentCancelled, AttachmentError, AttachmentStore
from .item_schema import ItemSchemaError
from .session_guard import StaleSession
from .vault import VaultError, VaultLockedError


class WorkspaceError(ValueError):
    """Base error for safe workspace controller input and state failures."""


class WorkspaceSessionInvalidated(StaleSession, WorkspaceError):
    """The lock, profile, lease, or destination changed during an action."""


class WorkspaceCancelled(WorkspaceError):
    """A user-cancelled preview or attachment operation."""


GENERIC_REMINDER_NOTIFICATION = "A reminder is due in your local vault. Open LocalGateKeys to review it."
SNOOZE_CHOICES_DAYS = (1, 3, 7, 14, 30)


def _safe_path(value: Path | str, *, label: str) -> Path:
    """Accept only a caller-selected local filesystem path."""
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise WorkspaceError(f"{label} must be a local path") from exc
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise WorkspaceError(f"{label} must be a local path")
    if raw.startswith(("\\\\", "//")) or "://" in raw:
        raise WorkspaceError(f"{label} must be a local, non-network path")
    path = Path(raw)
    if path.name in {"", ".", ".."}:
        raise WorkspaceError(f"{label} must name a file")
    return path


def _safe_opaque(value: Any, label: str = "identifier") -> str:
    if not isinstance(value, str) or not value or len(value) > 128 or "\x00" in value:
        raise WorkspaceError(f"{label} is malformed")
    return value


def _safe_item_summary(summary: Any) -> dict[str, Any]:
    """Copy only non-payload fields from an ItemSummary."""
    return {
        "id": str(summary.id),
        "kind": str(summary.kind),
        "title": str(summary.title),
        "created_at": int(summary.created_at),
        "updated_at": int(summary.updated_at),
        "favorite": bool(summary.favorite),
        "tags": list(summary.tags),
        "collection_ids": list(summary.collection_ids),
    }


def _safe_template(value: Mapping[str, Any]) -> dict[str, Any]:
    """Project a validated template to a data-only field schema."""
    if not isinstance(value, Mapping):
        raise WorkspaceError("Template schema is malformed")
    allowed_types = {"text", "multiline", "date", "url", "number"}
    fields: list[dict[str, Any]] = []
    raw_fields = value.get("fields", [])
    if not isinstance(raw_fields, list) or len(raw_fields) > 50:
        raise WorkspaceError("Template field schema is malformed")
    for field in raw_fields:
        if not isinstance(field, Mapping):
            raise WorkspaceError("Template field schema is malformed")
        # This allow-list is intentionally repeated at the UI boundary.  A
        # future catalog field cannot silently become a callback or widget
        # instruction merely because it was added to encrypted data.
        name, label, field_type = field.get("name"), field.get("label"), field.get("type")
        required, secret = field.get("required"), field.get("secret")
        if (not isinstance(name, str) or not name or len(name) > 64
                or not isinstance(label, str) or not label or len(label) > 100
                or not isinstance(field_type, str) or field_type not in allowed_types
                or type(required) is not bool or type(secret) is not bool):
            raise WorkspaceError("Template field schema is malformed")
        fields.append({
            "name": name,
            "label": label,
            "type": field_type,
            "required": required,
            "secret": secret,
        })
    template_id = value.get("id")
    kind = value.get("kind")
    name = value.get("name")
    description = value.get("description", "")
    revision = value.get("revision", 1)
    if (not isinstance(template_id, str) or not template_id
            or not isinstance(kind, str) or not kind
            or not isinstance(name, str) or not name
            or not isinstance(description, str) or len(description) > 500
            or type(revision) is not int or revision < 1):
        raise WorkspaceError("Template schema is malformed")
    return {
        "id": template_id,
        "kind": kind,
        "name": name,
        "description": description,
        "fields": fields,
        "revision": revision,
        "declarative": True,
    }


class WorkspaceSessionBinding:
    """Bind operations to one session/path and optionally a SessionGuard lease."""

    def __init__(
        self,
        session: Any,
        *,
        lease: Any = None,
        guard: Any = None,
        require_lease: Callable[[Any], Any] | None = None,
        session_provider: Callable[[], Any] | None = None,
    ) -> None:
        if session is None:
            raise WorkspaceError("An unlocked vault session is required")
        if guard is None and require_lease is None:
            raise WorkspaceError("A session guard or lease checker is required")
        if guard is not None and lease is None and callable(getattr(guard, "lease", None)):
            lease = guard.lease()
        if lease is None:
            raise WorkspaceError("An explicit session lease is required")
        if require_lease is not None and not callable(require_lease):
            raise WorkspaceError("Lease checker is malformed")
        if guard is not None and not callable(getattr(guard, "require", None)):
            raise WorkspaceError("Session guard is malformed")
        if session_provider is not None and not callable(session_provider):
            raise WorkspaceError("Session provider is malformed")
        self._session = session
        self._session_provider = session_provider
        self._guard = guard
        self._require_lease_callback = require_lease
        self.lease = lease
        self._path = self._session_path(session)
        self._guard_fingerprint = self._guard_lease_fingerprint(guard, lease)
        self._session_fingerprint = self._fingerprint(session)
        if self._session_fingerprint is None:
            self._session_fingerprint = self._guard_fingerprint
        if self._session_fingerprint is None:
            raise WorkspaceError(
                "The workspace session must expose an immutable generation or fingerprint"
            )
        self._invalidated = False

    @staticmethod
    def _session_path(session: Any) -> str | None:
        value = getattr(session, "path", None)
        if value is None:
            return None
        try:
            raw = os.fspath(value)
        except (TypeError, ValueError, OSError):
            return str(value)

        if (not isinstance(raw, str) or raw.startswith(("\\\\", "//"))
                or "://" in raw):
                raise WorkspaceError("The workspace requires a local vault path")
        try:
            return os.path.normcase(os.path.abspath(raw))
        except (TypeError, ValueError, OSError):
            return str(value)

    @staticmethod
    def _fingerprint(session: Any) -> tuple[Any, ...] | None:
        """Return an immutable identity for the current unlock generation."""
        for name in (
            "workspace_session_generation", "session_generation", "profile_generation",
            "unlock_generation", "generation",
        ):
            value = getattr(session, name, None)
            if type(value) in (str, int, bytes):
                return ("explicit", name, value)
        # VaultSession replaces both containers on lock/unlock while normal
        # saves retain them. Their process identities are an unlock-generation
        # boundary without reading any protected catalog value.
        key = getattr(session, "_key", None)
        payload = getattr(session, "_payload", None)
        if key is not None or payload is not None:
            return ("memory", id(key), id(payload))
        return None

    @staticmethod
    def _guard_lease_fingerprint(guard: Any, lease: Any) -> tuple[Any, ...] | None:
        """Return the immutable generation exposed by a lease validator."""
        if guard is not None:
            stamp = getattr(guard, "stamp", None)
            if callable(stamp):
                try:
                    value = stamp()
                except Exception:
                    value = None
                if (type(value) is tuple
                        and all(type(part) in (str, int, bytes) for part in value)):
                    return ("guard", value)

        profile_id = getattr(lease, "profile_id", None)
        revision = getattr(lease, "revision", None)
        token = getattr(lease, "token", None)
        if (type(profile_id) is str and type(revision) is int
                and type(token) is str):
            return ("lease", profile_id, revision, token)
        return None

    def _current_fingerprint(self, session: Any) -> tuple[Any, ...] | None:
        fingerprint = self._fingerprint(session)
        return fingerprint if fingerprint is not None else self._guard_fingerprint

    @property
    def invalidated(self) -> bool:
        return self._invalidated

    def current(self) -> Any:
        if self._invalidated:
            raise WorkspaceSessionInvalidated("The vault session changed; the workspace action was cancelled")
        current = self._session_provider() if self._session_provider is not None else self._session
        if current is not self._session:
            raise WorkspaceSessionInvalidated("Profile/session changed; the workspace action was cancelled")
        if self._session_path(current) != self._path:
            raise WorkspaceSessionInvalidated("Vault destination changed; the workspace action was cancelled")
        if self._current_fingerprint(current) != self._session_fingerprint:
            raise WorkspaceSessionInvalidated(
                "The vault session generation changed; the workspace action was cancelled"
            )
        if not bool(getattr(current, "is_unlocked", False)):
            raise WorkspaceSessionInvalidated("Vault is locked; unlock and start the action again")
        if self._guard is not None:
            if self.lease is None or not callable(getattr(self._guard, "require", None)):
                raise WorkspaceSessionInvalidated("The workspace has no valid session lease")
            try:
                self._guard.require(self.lease)
            except Exception as exc:
                raise WorkspaceSessionInvalidated("The workspace lease expired; action cancelled") from exc
        if self._require_lease_callback is not None:
            if self.lease is None:
                raise WorkspaceSessionInvalidated("The workspace has no valid session lease")
            try:
                self._require_lease_callback(self.lease)
            except Exception as exc:
                raise WorkspaceSessionInvalidated("The workspace lease expired; action cancelled") from exc
        return current

    def invalidate(self) -> None:
        self._invalidated = True


class SafeWorkspaceController:
    """View-model/controller for Phase 2 local-only workflows."""

    def __init__(self, session: Any, **binding: Any) -> None:
        self.binding = WorkspaceSessionBinding(session, **binding)
        self._scheduler: Any | None = None
        self._windows: set[Any] = set()

    @property
    def session(self) -> Any:
        return self.binding.current()

    def require_session(self) -> Any:
        return self.binding.current()

    def _finish(self, session: Any, result: Any) -> Any:
        """Reject a result if the session changed while the service ran."""
        self.require_session()
        return result

    @staticmethod
    def _cleanup(rollback: Callable[[], Any] | None) -> None:
        if rollback is None:
            return
        try:
            rollback()
        except Exception:
            # Cleanup is best effort and must not hide the stale-session cause.
            pass

    def _call(self, session: Any, action: Callable[[], Any], *,
              rollback: Callable[[], Any] | None = None) -> Any:
        """Run a bound action and fail closed if it becomes stale."""
        try:
            result = action()
        except WorkspaceSessionInvalidated:
            self._cleanup(rollback)
            raise
        except AttachmentCancelled as exc:
            self._cleanup(rollback)
            try:
                self.require_session()
            except WorkspaceSessionInvalidated as stale:
                raise stale from exc
            raise WorkspaceCancelled("The workspace action was cancelled") from exc
        except (StaleSession, VaultLockedError) as exc:
            self._cleanup(rollback)
            raise WorkspaceSessionInvalidated(
                "The vault session changed; the workspace action was cancelled"
            ) from exc
        except BaseException:
            self._cleanup(rollback)
            raise
        try:
            return self._finish(session, result)
        except WorkspaceSessionInvalidated:
            self._cleanup(rollback)
            raise

    def _bound_cancel(self, cancel: Any = None) -> Callable[[], bool]:
        """Check caller cancellation and the live lease at sidecar checkpoints."""
        def check() -> bool:
            if cancel is not None:
                cancelled = cancel.is_set() if hasattr(cancel, "is_set") else bool(cancel())
                if cancelled:
                    return True
            try:
                self.require_session()
            except WorkspaceSessionInvalidated as exc:
                # AttachmentStore converts callback failures to
                # AttachmentCancelled and removes its temporary sidecar.
                raise AttachmentCancelled("The workspace lease was invalidated") from exc
            return False
        return check

    def register_window(self, window: Any) -> Any:
        """Register an optional presentation window for lock/profile cleanup."""
        self.require_session()
        self._windows.add(window)
        return window

    def unregister_window(self, window: Any) -> None:
        self._windows.discard(window)

    def invalidate_session(self) -> None:
        self.binding.invalidate()
        windows, self._windows = tuple(self._windows), set()
        for window in windows:
            try:
                window.invalidate_session()
            except Exception:  # noqa: BLE001 - UI cleanup must not block lock invalidation
                try:
                    window.destroy()
                except Exception:  # noqa: BLE001, S110 - best-effort UI cleanup
                    pass
        self._stop_scheduler_lifecycle()

    on_session_invalidated = invalidate_session

    def _stop_scheduler_lifecycle(self) -> None:
        """Stop scheduler during internal invalidation cleanup only."""
        scheduler = self._scheduler
        self._scheduler = None
        if scheduler is not None:
            scheduler.stop()

    # ----- collections -------------------------------------------------
    def list_collections(self) -> list[dict[str, Any]]:
        session = self.require_session()
        summaries = session.items.metadata_summaries()
        counts: dict[str, int] = {}
        for summary in summaries:
            for collection_id in summary.collection_ids:
                counts[collection_id] = counts.get(collection_id, 0) + 1
        result = []
        for row in session.collections.list():
            result.append({
                "id": str(row["id"]),
                "name": str(row["name"]),
                "description": str(row.get("description", "")),
                "starter": bool(row.get("starter", False)),
                "revision": int(row.get("revision", 1)),
                "member_count": counts.get(str(row["id"]), 0),
                "empty": counts.get(str(row["id"]), 0) == 0,
                "archived": False,
            })
        return self._finish(session, result)

    collections = list_collections

    def create_collection(self, name: str, *, description: str = "") -> str:
        session = self.require_session()
        return self._call(session, lambda: session.collections.create(name, description=description))

    def rename_collection(self, collection_id: str, name: str, *, description: str | None = None) -> bool:
        session = self.require_session()
        clean_id = _safe_opaque(collection_id, "collection id")
        return self._call(session, lambda: session.collections.rename(
            clean_id, name, description=description))

    def archive_collection(self, collection_id: str) -> bool:
        session = self.require_session()
        clean_id = _safe_opaque(collection_id, "collection id")
        return self._call(session, lambda: session.collections.archive(clean_id))

    delete_collection = archive_collection

    def collection_members(self, collection_id: str) -> list[dict[str, Any]]:
        session = self.require_session()
        clean_id = _safe_opaque(collection_id, "collection id")
        result = [_safe_item_summary(row) for row in session.collections.members(clean_id)]
        return self._finish(session, result)

    def set_membership(self, item_id: str, collection_ids: Iterable[str], *,
                       expected_revision: int | None = None) -> bool:
        values = tuple(_safe_opaque(value, "collection id") for value in collection_ids)
        session = self.require_session()
        clean_id = _safe_opaque(item_id, "item id")
        return self._call(session, lambda: session.collections.set_membership(
            clean_id, list(values), expected_revision=expected_revision))

    edit_membership = set_membership

    # ----- templates ---------------------------------------------------
    def list_templates(self, *, kind: str | None = None) -> list[dict[str, Any]]:
        session = self.require_session()
        result = [_safe_template(value) for value in session.templates.list(kind=kind)]
        return self._finish(session, result)

    templates = list_templates

    def select_template(self, template_id: str, *, kind: str | None = None) -> dict[str, Any] | None:
        session = self.require_session()
        value = session.templates.select(_safe_opaque(template_id, "template id"), kind=kind)
        result = _safe_template(value) if value is not None else None
        return self._finish(session, result)

    choose_template = select_template

    # ----- documents and encrypted sidecars --------------------------
    @staticmethod
    def _safe_destination(session: Any, value: Path | str) -> Path:
        path = _safe_path(value, label="Document destination")
        vault_path = getattr(session, "path", None)
        if vault_path is None:
            return path
        try:
            target = path.resolve(strict=False)
            vault = Path(vault_path).resolve(strict=False)
            attachment_root = (vault.parent / "Attachments").resolve(strict=False)
        except (TypeError, ValueError, OSError) as exc:
            raise WorkspaceError("Document destination is malformed") from exc
        if target == vault or target == attachment_root or attachment_root in target.parents:
            raise WorkspaceError("Document destination cannot overwrite vault data")
        return path

    def list_documents(self) -> list[dict[str, Any]]:
        session = self.require_session()
        result: list[dict[str, Any]] = []
        # metadata_summaries never reads note bodies, bookmark URLs, identity
        # fields, license values, or document bytes.  Attachment metadata is
        # obtained through the existing document service boundary, which uses
        # the default redacted item projection and never requests protected
        # fields.  Do not read the raw typed catalog here.
        for summary in session.items.metadata_summaries(kinds={"document"}):
            row = _safe_item_summary(summary)
            row["description"] = ""
            try:
                record = session.documents.attachment_for(summary.id)
            except (AttributeError, AttachmentError, VaultError, VaultLockedError, KeyError, TypeError):
                row.update({"attachment_available": False, "attachment": None})
            else:
                if not isinstance(record, Mapping):
                    row.update({"attachment_available": False, "attachment": None})
                    result.append(row)
                    continue
                row.update({
                    "attachment_available": True,
                    "attachment": {
                        "id": str(record["id"]),
                        "name": str(record["name"]),
                        "mime_type": str(record["mime_type"]),
                        "size": int(record["size"]),
                        "sha256": str(record["sha256"]),
                    },
                })
            result.append(row)
        return self._finish(session, result)

    documents = list_documents

    def preview_document(self, item_id: str, *, cancel: Any = None) -> dict[str, Any]:
        session = self.require_session()
        clean_id = _safe_opaque(item_id, "document id")
        bound_cancel = self._bound_cancel(cancel)
        try:
            result = session.documents.preview(clean_id, cancel=bound_cancel)
        except AttachmentCancelled as exc:
            raise WorkspaceCancelled("Document preview was cancelled") from exc
        except (StaleSession, VaultLockedError) as exc:
            raise WorkspaceSessionInvalidated(
                "The vault session changed; the workspace action was cancelled"
            ) from exc
        except AttachmentError:
            raise
        self._finish(session, None)
        output = copy.deepcopy(result)
        output["warning"] = "Treat document attachments as untrusted files. Active content is never executed."
        try:
            session.activity.record("document.view", item_id=clean_id)
        except (AttributeError, ItemSchemaError, VaultError):
            pass
        return self._finish(session, output)

    preview = preview_document

    def download_document(self, item_id: str, destination: Path | str, *, overwrite: bool = False,
                          cancel: Any = None) -> Path:
        session = self.require_session()
        destination = self._safe_destination(session, destination)
        clean_id = _safe_opaque(item_id, "document id")
        # A workspace export must never overwrite an existing user file.  This
        # keeps the stale-session rollback below lossless and makes a late
        # lease invalidation fail closed instead of destroying unrelated data.
        if overwrite and destination.exists():
            raise WorkspaceError(
                "Overwriting an existing document destination is disabled; choose a new path"
            )
        existed_before = destination.exists()

        def rollback_export() -> None:
            if not existed_before:
                try:
                    destination.unlink(missing_ok=True)
                except OSError:
                    pass

        bound_cancel = self._bound_cancel(cancel)
        return self._call(session, lambda: session.documents.export(
            clean_id, destination, overwrite=overwrite, cancel=bound_cancel),
            rollback=rollback_export)

    export_document = download_document
    download = download_document

    def replace_document(self, item_id: str, source: Path | str, *, description: str | None = None,
                         mime_type: str | None = None, name: str | None = None,
                         cancel: Any = None) -> str:
        source = _safe_path(source, label="Document source")
        session = self.require_session()
        clean_id = _safe_opaque(item_id, "document id")
        bound_cancel = self._bound_cancel(cancel)
        return self._call(session, lambda: session.documents.replace(
            clean_id, source, description=description, mime_type=mime_type, name=name,
            cancel=bound_cancel),
            # DocumentService commits the new sidecar before changing the
            # item reference.  GC is therefore a safe best-effort rollback:
            # it removes an unreferenced new sidecar but preserves a committed
            # replacement that is still referenced by the item.
            rollback=lambda: session.attachments.garbage_collect())

    replace = replace_document

    def delete_document(self, item_id: str) -> bool:
        session = self.require_session()
        clean_id = _safe_opaque(item_id, "document id")
        return self._call(session, lambda: session.documents.delete(clean_id))

    delete_document_item = delete_document

    def attachment_usage(self) -> dict[str, int]:
        session = self.require_session()
        store = session.attachments
        status = store.quota_status()
        # Keep this projection on the public metadata/service seams.  The
        # catalog may contain protected attachment keys, so this controller
        # must not count or expose raw attachment records.
        catalog_count = 0
        for summary in session.items.metadata_summaries(kinds={"document"}):
            try:
                session.documents.attachment_for(summary.id)
            except (AttributeError, AttachmentError, VaultError, VaultLockedError, KeyError, TypeError):
                continue
            catalog_count += 1
        return self._finish(session, {
            "used": int(status["used"]),
            "quota": int(status["quota"]),
            "available": int(status["available"]),
            "catalog_count": catalog_count,
        })

    usage = attachment_usage

    def orphan_report(self) -> dict[str, Any]:
        session = self.require_session()
        store = AttachmentStore(session)
        # Build the referenced set from the document metadata projection and
        # the document service.  This intentionally omits protected keys and
        # does not read the raw typed catalog.  There is no public catalog
        # enumeration seam for unreferenced records, so that diagnostic is
        # reported conservatively as empty rather than exposing raw records.
        referenced: set[str] = set()
        for summary in session.items.metadata_summaries(kinds={"document"}):
            try:
                record = session.documents.attachment_for(summary.id)
            except (AttributeError, AttachmentError, VaultError, VaultLockedError, KeyError, TypeError):
                continue
            if isinstance(record, Mapping) and isinstance(record.get("id"), str):
                referenced.add(str(record["id"]))
        blob_ids: set[str] = set()
        invalid_sidecars: list[str] = []
        orphan_bytes = 0
        for path in store.root.glob("*.blob"):
            try:
                attachment_id = str(uuid.UUID(path.stem))
            except (ValueError, AttributeError):
                invalid_sidecars.append(path.name)
                continue
            blob_ids.add(attachment_id)
            if attachment_id not in referenced:
                try:
                    orphan_bytes += int(path.stat().st_size)
                except OSError:
                    pass
        return self._finish(session, {
            "dry_run": True,
            "orphan_ids": sorted(blob_ids - referenced),
            "orphan_bytes": orphan_bytes,
            "unreferenced_catalog_ids": [],
            "missing_referenced_ids": sorted(referenced - blob_ids),
            "invalid_sidecars": sorted(invalid_sidecars),
        })

    cleanup_report = orphan_report

    def cleanup_orphans(self, *, dry_run: bool = True) -> dict[str, Any]:
        report = self.orphan_report()
        if dry_run:
            return report
        session = self.require_session()
        removed = self._call(session, lambda: session.attachments.garbage_collect())
        result = copy.deepcopy(report)
        result["dry_run"] = False
        result["removed_ids"] = list(removed)
        result["removed_count"] = len(removed)
        return self._finish(session, result)

    garbage_collect_orphans = cleanup_orphans

    # ----- reminders and activity -------------------------------------
    @staticmethod
    def _effective_date(row: Mapping[str, Any]) -> str:
        try:
            due = _datetime.date.fromisoformat(str(row["due_date"]))
            due -= _datetime.timedelta(days=int(row.get("lead_days", 0)))
            snooze_until = str(row.get("snooze_until", ""))
            if row.get("status") == "snoozed" and snooze_until:
                due = max(due, _datetime.date.fromisoformat(snooze_until))
            return due.isoformat()
        except (KeyError, TypeError, ValueError):
            return ""

    def list_reminders(self, *, include_dismissed: bool = True) -> list[dict[str, Any]]:
        session = self.require_session()
        summaries = {summary.id: summary for summary in session.items.metadata_summaries()}
        result: list[dict[str, Any]] = []
        for row in session.reminders.list():
            if not include_dismissed and row.get("status") == "dismissed":
                continue
            summary = summaries.get(row.get("item_id"))
            result.append({
                "id": str(row["id"]),
                "item_id": str(row["item_id"]),
                "item_title": str(summary.title) if summary is not None else "Unavailable item",
                "item_kind": str(summary.kind) if summary is not None else "unknown",
                "due_date": str(row["due_date"]),
                "effective_date": self._effective_date(row),
                "lead_days": int(row.get("lead_days", 0)),
                "status": str(row.get("status", "pending")),
                "snooze_until": str(row.get("snooze_until", "")),
            })
        return self._finish(session, result)

    reminders = list_reminders

    def default_lead_days(self) -> int:
        session = self.require_session()
        return int(self._finish(session, session.reminders.default_lead_days))

    def set_default_lead_days(self, days: int) -> int:
        session = self.require_session()
        return self._call(session, lambda: session.reminders.set_default_lead_days(days))

    def snooze_reminder(self, reminder_id: str, *, days: int | None = None,
                        until: Any = None, from_date: Any = None) -> bool:
        session = self.require_session()
        clean_id = _safe_opaque(reminder_id, "reminder id")
        return self._call(session, lambda: session.reminders.snooze(
            clean_id, until=until, days=days, from_date=from_date))

    snooze = snooze_reminder

    def dismiss_reminder(self, reminder_id: str) -> bool:
        session = self.require_session()
        clean_id = _safe_opaque(reminder_id, "reminder id")
        return self._call(session, lambda: session.reminders.dismiss(clean_id))

    dismiss = dismiss_reminder
    complete_reminder = dismiss_reminder

    def reschedule_reminder(self, reminder_id: str, due_date: Any, *, lead_days: int | None = None) -> bool:
        session = self.require_session()
        clean_id = _safe_opaque(reminder_id, "reminder id")
        return self._call(session, lambda: session.reminders.reschedule(
            clean_id, due_date, lead_days=lead_days))

    reschedule = reschedule_reminder

    def reminder_notification(self, reminder_id: str) -> dict[str, str]:
        """Return generic notification data with no title, URL, or content."""
        session = self.require_session()
        reminder_id = _safe_opaque(reminder_id, "reminder id")
        if not any(row["id"] == reminder_id for row in session.reminders.list()):
            raise WorkspaceError("Reminder was not found")
        return self._finish(session, {
            "reminder_id": reminder_id, "message": GENERIC_REMINDER_NOTIFICATION,
        })

    def start_scheduler(self, callback: Callable[[list[dict[str, str]]], Any] | None = None) -> Any:
        if callback is not None and not callable(callback):
            raise WorkspaceError("Reminder callback must be callable")
        session = self.require_session()
        scheduler = session.reminder_scheduler

        def deliver(rows: list[dict[str, str]]) -> None:
            if self.binding.invalidated:
                return
            try:
                self.require_session()
            except WorkspaceSessionInvalidated:
                scheduler.stop()
                return
            if callback is None:
                return
            # The scheduler's rows already contain only opaque IDs/dates; this
            # presentation layer adds generic wording and no item metadata.
            callback([
                {"reminder_id": str(row["id"]), "due_date": str(row["due_date"]),
                 "message": GENERIC_REMINDER_NOTIFICATION}
                for row in rows
            ])

        try:
            scheduler.start(deliver)
            self._scheduler = scheduler
            self.require_session()
        except (WorkspaceSessionInvalidated, StaleSession, VaultLockedError) as exc:
            scheduler.stop()
            self._scheduler = None
            raise WorkspaceSessionInvalidated(
                "The vault session changed; the reminder scheduler was stopped"
            ) from exc
        return scheduler

    def stop_scheduler(self) -> None:
        # Public lifecycle actions are still bound to the live lease.  The
        # private cleanup path used by invalidate_session() is the only path
        # allowed to stop after invalidation.
        self.require_session()
        self._stop_scheduler_lifecycle()

    def activity_summaries(self) -> list[dict[str, Any]]:
        session = self.require_session()
        result = []
        for row in session.activity.history():
            # Do not join titles or payloads into history. item_id is an
            # opaque reference and the remaining fields are bounded schema
            # values from ActivityService.
            result.append({
                "id": str(row["id"]),
                "event_type": str(row["event_type"]),
                "timestamp": int(row["timestamp"]),
                "item_id": row.get("item_id"),
                "result": str(row["result"]),
                "count": int(row.get("count", 0)),
            })
        return self._finish(session, result)

    activity = activity_summaries


# Short names make integration with callers that use the transfer/sync UI
# naming convention straightforward without creating a second implementation.
WorkspaceController = SafeWorkspaceController
SafeWorkspaceExtrasController = SafeWorkspaceController
SessionBinding = WorkspaceSessionBinding


__all__ = [
    "GENERIC_REMINDER_NOTIFICATION", "SNOOZE_CHOICES_DAYS", "SafeWorkspaceController",
    "SafeWorkspaceExtrasController", "SessionBinding", "WorkspaceCancelled", "WorkspaceController",
    "WorkspaceError", "WorkspaceSessionBinding", "WorkspaceSessionInvalidated",
]
