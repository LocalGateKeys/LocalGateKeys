"""Safe workspace controller and row summaries (no UI toolkit)."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..safe_workspace_extras import (
    GENERIC_REMINDER_NOTIFICATION,
    SafeWorkspaceController,
    WorkspaceError,
)


def _copy_fields(value: Mapping[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Copy a bounded allow-list from a controller result."""
    return {key: value[key] for key in fields if key in value}


def summarize_collections(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise WorkspaceError("Collection results are malformed")
    fields = ("id", "name", "description", "starter", "revision", "member_count", "empty", "archived")
    return [_copy_fields(row, fields) for row in rows if isinstance(row, Mapping)]


def summarize_templates(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise WorkspaceError("Template results are malformed")
    result: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        fields = []
        for field in row.get("fields", []):
            if not isinstance(field, Mapping):
                continue
            fields.append(_copy_fields(field, ("name", "label", "type", "required", "secret")))
        safe = _copy_fields(row, ("id", "kind", "name", "description", "revision", "declarative"))
        safe["fields"] = fields
        result.append(safe)
    return result


def summarize_documents(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise WorkspaceError("Document results are malformed")
    fields = ("id", "kind", "title", "created_at", "updated_at", "favorite", "tags",
              "collection_ids", "description", "attachment_available")
    result: list[dict[str, Any]] = []
    attachment_fields = ("id", "name", "mime_type", "size", "sha256")
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        safe = _copy_fields(row, fields)
        attachment = row.get("attachment")
        safe["attachment"] = (_copy_fields(attachment, attachment_fields)
                               if isinstance(attachment, Mapping) else None)
        result.append(safe)
    return result


def summarize_reminders(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise WorkspaceError("Reminder results are malformed")
    fields = ("id", "item_id", "item_title", "item_kind", "due_date", "effective_date",
              "lead_days", "status", "snooze_until")
    return [_copy_fields(row, fields) for row in rows if isinstance(row, Mapping)]


def summarize_activity(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise WorkspaceError("Activity results are malformed")
    fields = ("id", "event_type", "timestamp", "item_id", "result", "count")
    return [_copy_fields(row, fields) for row in rows if isinstance(row, Mapping)]


def summarize_preview(value: Any) -> dict[str, Any]:
    """Project one explicit preview without retaining unrelated result keys."""
    if not isinstance(value, Mapping):
        raise WorkspaceError("Document preview is malformed")
    result = _copy_fields(value, ("kind", "safe", "reason", "format", "width", "height", "pages",
                                  "content", "truncated", "warning"))
    metadata = value.get("metadata")
    if isinstance(metadata, Mapping):
        result["metadata"] = _copy_fields(metadata, ("name", "mime_type", "size", "sha256"))
    return result


class SafeWorkspaceCenter:
    """Testable UI-facing view model for local Phase 2 workflows.

    Every method enters through the session-bound controller.  The center does
    not accept a bare session because doing so would make it too easy for a UI
    callback to outlive its lease.
    """

    def __init__(self, controller: SafeWorkspaceController) -> None:
        if controller is None or not callable(getattr(controller, "require_session", None)):
            raise WorkspaceError("A safe workspace controller is required")
        self.controller = controller
        self.last_snapshot: dict[str, Any] | None = None

    @property
    def session(self) -> Any:
        return self.controller.require_session()

    def _call(self, method: str, *args: Any, **kwargs: Any) -> Any:
        self.controller.require_session()
        result = getattr(self.controller, method)(*args, **kwargs)
        self.controller.require_session()
        return result

    def snapshot(self, *, include_dismissed: bool = True) -> dict[str, Any]:
        result = {
            "collections": summarize_collections(self._call("list_collections")),
            "templates": summarize_templates(self._call("list_templates")),
            "documents": summarize_documents(self._call("list_documents")),
            "reminders": summarize_reminders(
                self._call("list_reminders", include_dismissed=include_dismissed)),
            "activity": summarize_activity(self._call("activity_summaries")),
        }
        self.last_snapshot = result
        return result

    # Collection manager -------------------------------------------------
    def collections(self) -> list[dict[str, Any]]:
        return summarize_collections(self._call("list_collections"))

    def create_collection(self, name: str, *, description: str = "") -> str:
        return self._call("create_collection", name, description=description)

    def rename_collection(self, collection_id: str, name: str, *, description: str | None = None) -> bool:
        return self._call("rename_collection", collection_id, name, description=description)

    def archive_collection(self, collection_id: str) -> bool:
        return self._call("archive_collection", collection_id)

    def collection_members(self, collection_id: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self._call("collection_members", collection_id)]

    def set_membership(self, item_id: str, collection_ids: Any, *, expected_revision: int | None = None) -> bool:
        return self._call("set_membership", item_id, collection_ids, expected_revision=expected_revision)

    # Templates -----------------------------------------------------------
    def templates(self, *, kind: str | None = None) -> list[dict[str, Any]]:
        return summarize_templates(self._call("list_templates", kind=kind))

    def select_template(self, template_id: str, *, kind: str | None = None) -> dict[str, Any] | None:
        result = self._call("select_template", template_id, kind=kind)
        return summarize_templates([result])[0] if result is not None else None

    # Documents -----------------------------------------------------------
    def documents(self) -> list[dict[str, Any]]:
        return summarize_documents(self._call("list_documents"))

    def preview_document(self, item_id: str, *, cancel: Any = None) -> dict[str, Any]:
        return summarize_preview(self._call("preview_document", item_id, cancel=cancel))

    preview = preview_document

    def download_document(self, item_id: str, destination: Path | str, *, overwrite: bool = False,
                          cancel: Any = None) -> Path:
        return self._call("download_document", item_id, destination, overwrite=overwrite, cancel=cancel)

    download = download_document

    def replace_document(self, item_id: str, source: Path | str, *, description: str | None = None,
                         mime_type: str | None = None, name: str | None = None,
                         cancel: Any = None) -> str:
        return self._call("replace_document", item_id, source, description=description,
                          mime_type=mime_type, name=name, cancel=cancel)

    replace = replace_document

    def delete_document(self, item_id: str) -> bool:
        return self._call("delete_document", item_id)

    # Reminders/activity --------------------------------------------------
    def reminders(self, *, include_dismissed: bool = True) -> list[dict[str, Any]]:
        return summarize_reminders(self._call("list_reminders", include_dismissed=include_dismissed))

    def set_default_lead_days(self, days: int) -> int:
        return self._call("set_default_lead_days", days)

    def snooze_reminder(self, reminder_id: str, *, days: int | None = None,
                        until: Any = None, from_date: Any = None) -> bool:
        return self._call("snooze_reminder", reminder_id, days=days, until=until, from_date=from_date)

    def dismiss_reminder(self, reminder_id: str) -> bool:
        return self._call("dismiss_reminder", reminder_id)

    dismiss = dismiss_reminder

    def reschedule_reminder(self, reminder_id: str, due_date: Any, *, lead_days: int | None = None) -> bool:
        return self._call("reschedule_reminder", reminder_id, due_date, lead_days=lead_days)

    def activity(self) -> list[dict[str, Any]]:
        return summarize_activity(self._call("activity_summaries"))

    def reminder_notification(self, reminder_id: str) -> dict[str, str]:
        result = self._call("reminder_notification", reminder_id)
        return {"reminder_id": str(result["reminder_id"]), "message": GENERIC_REMINDER_NOTIFICATION}

    def start_scheduler(self, callback: Any = None) -> Any:
        return self._call("start_scheduler", callback)

    def stop_scheduler(self) -> None:
        # The controller lease-gates explicit user lifecycle actions.  Its
        # private invalidation cleanup remains safe after the session expires.
        self.controller.stop_scheduler()

    def invalidate_session(self) -> None:
        self.controller.invalidate_session()
