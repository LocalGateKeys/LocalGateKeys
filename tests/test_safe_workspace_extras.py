from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from localvault.safe_workspace_extras import (
    SafeWorkspaceController,
    WorkspaceCancelled,
    WorkspaceError,
    WorkspaceSessionInvalidated,
)
from localvault.app.workspace_center import (
    summarize_documents,
    summarize_preview,
    summarize_templates,
)
from localvault.session_guard import SessionGuard
from localvault.vault import create_vault

MASTER = "safe workspace test master password"
KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


@pytest.fixture
def workspace_dir() -> Path:
    path = Path(__file__).parents[1] / f".safe-workspace-case-{uuid.uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _controller(workspace_dir: Path) -> tuple[object, SessionGuard, SafeWorkspaceController]:
    session = create_vault(workspace_dir / "vault.json", MASTER, kdf_overrides=KDF)
    guard = SessionGuard("safe-workspace-profile")
    guard.open(3600)
    controller = SafeWorkspaceController(
        session,
        lease=guard.lease(),
        guard=guard,
        session_provider=lambda: session,
    )
    return session, guard, controller


def test_workspace_requires_explicit_lease_validator(workspace_dir: Path) -> None:
    session = create_vault(workspace_dir / "vault.json", MASTER, kdf_overrides=KDF)
    with pytest.raises(WorkspaceError, match="guard or lease checker"):
        SafeWorkspaceController(session)

    guard = SessionGuard("profile")
    guard.open(3600)
    controller = SafeWorkspaceController(session, lease=guard.lease(), guard=guard)
    assert controller.list_templates()
    guard.invalidate()
    with pytest.raises(WorkspaceSessionInvalidated):
        controller.list_templates()


def test_collections_templates_and_metadata_lists_are_safe(workspace_dir: Path) -> None:
    session, _guard, controller = _controller(workspace_dir)
    collection_id = controller.create_collection("Receipts", description="Local receipt metadata")
    note_id = session.items.create_note(
        "Private receipt note", body="DO-NOT-LEAK-NOTE-BODY", tags=["receipt"],
        collection_ids=[collection_id],
    )

    collections = controller.list_collections()
    row = next(value for value in collections if value["id"] == collection_id)
    assert row["name"] == "Receipts"
    assert row["member_count"] == 1
    assert controller.collection_members(collection_id)[0]["id"] == note_id
    assert "DO-NOT-LEAK-NOTE-BODY" not in repr(collections)

    assert controller.rename_collection(collection_id, "Archived receipts")
    assert any(value["name"] == "Archived receipts" for value in controller.collections())
    assert controller.archive_collection(collection_id)
    assert all(value["id"] != collection_id for value in controller.list_collections())
    assert session.items.get_item(note_id) is not None
    assert "body" not in session.items.get_item(note_id)["payload"]
    assert session.items.get_item(note_id)["payload"]["body_present"] is True

    templates = controller.list_templates(kind="license")
    license_template = controller.select_template("builtin.license", kind="license")
    assert templates and license_template is not None
    assert license_template["declarative"] is True
    assert {field["name"] for field in license_template["fields"]} == {"product", "license_value"}
    assert all("callback" not in repr(value) and "secret-value" not in repr(value) for value in templates)


def test_document_metadata_preview_and_sidecar_actions_are_explicit(workspace_dir: Path) -> None:
    session, _guard, controller = _controller(workspace_dir)
    source = workspace_dir / "receipt.txt"
    replacement = workspace_dir / "replacement.txt"
    destination = workspace_dir / "downloaded.txt"
    source.write_text("PRIVATE-DOCUMENT-CONTENT", encoding="utf-8")
    replacement.write_text("REPLACED-DOCUMENT-CONTENT", encoding="utf-8")
    item_id = session.documents.create(source, title="Receipt", description="Receipt metadata")

    rows = controller.list_documents()
    assert rows[0]["title"] == "Receipt"
    assert rows[0]["attachment"]["name"] == "receipt.txt"
    assert rows[0]["attachment"]["size"] == len("PRIVATE-DOCUMENT-CONTENT")
    assert "PRIVATE-DOCUMENT-CONTENT" not in repr(rows)

    preview = controller.preview_document(item_id)
    assert preview["kind"] == "text"
    assert preview["content"] == "PRIVATE-DOCUMENT-CONTENT"
    assert "untrusted files" in preview["warning"]

    assert controller.download_document(item_id, destination) == destination
    assert destination.read_text(encoding="utf-8") == "PRIVATE-DOCUMENT-CONTENT"
    controller.replace_document(item_id, replacement, description="Updated metadata")
    assert session.documents.read(item_id) == b"REPLACED-DOCUMENT-CONTENT"
    assert controller.list_documents()[0]["attachment"]["name"] == "receipt.txt"

    usage = controller.attachment_usage()
    assert usage["used"] >= len("REPLACED-DOCUMENT-CONTENT")
    assert controller.delete_document(item_id)
    assert controller.list_documents() == []


def test_cancelled_export_cleans_new_destination_after_session_invalidation(workspace_dir: Path) -> None:
    session, _guard, controller = _controller(workspace_dir)
    source = workspace_dir / "receipt.txt"
    destination = workspace_dir / "downloaded.txt"
    source.write_text("PRIVATE-DOCUMENT-CONTENT", encoding="utf-8")
    item_id = session.documents.create(source, title="Receipt")

    def invalidate_before_read() -> bool:
        controller.invalidate_session()
        return False

    with pytest.raises(WorkspaceSessionInvalidated):
        controller.download_document(item_id, destination, cancel=invalidate_before_read)
    assert not destination.exists()


def test_preview_binds_cancel_to_live_lease(workspace_dir: Path) -> None:
    session, guard, controller = _controller(workspace_dir)
    source = workspace_dir / "receipt.txt"
    source.write_text("PRIVATE-DOCUMENT-CONTENT", encoding="utf-8")
    item_id = session.documents.create(source, title="Receipt")

    def invalidate_before_read() -> bool:
        guard.invalidate()
        return False

    with pytest.raises(WorkspaceCancelled):
        controller.preview_document(item_id, cancel=invalidate_before_read)


def test_reminders_activity_and_notification_are_content_free(workspace_dir: Path) -> None:
    session, _guard, controller = _controller(workspace_dir)
    item_id = session.items.create_purchase("Renewal", vendor="PRIVATE-VENDOR")
    reminder_id = session.reminders.create(item_id, "2035-01-10", lead_days=2)

    reminders = controller.list_reminders()
    assert reminders[0]["item_title"] == "Renewal"
    assert reminders[0]["effective_date"] == "2035-01-08"
    assert "PRIVATE-VENDOR" not in repr(reminders)
    assert controller.reminder_notification(reminder_id)["message"].startswith("A reminder is due")
    assert "Renewal" not in controller.reminder_notification(reminder_id)["message"]

    assert controller.snooze_reminder(reminder_id, until="2035-01-20")
    assert controller.list_reminders()[0]["status"] == "snoozed"
    assert controller.reschedule_reminder(reminder_id, "2035-02-01", lead_days=1)
    assert controller.dismiss_reminder(reminder_id)
    assert controller.list_reminders(include_dismissed=False) == []

    activity = controller.activity_summaries()
    assert activity
    assert all(set(row) <= {"id", "event_type", "timestamp", "item_id", "result", "count"}
               for row in activity)
    assert "PRIVATE-VENDOR" not in repr(activity)


def test_lock_profile_switch_cancels_late_workspace_calls(workspace_dir: Path) -> None:
    session, _guard, controller = _controller(workspace_dir)
    session.lock()
    with pytest.raises(WorkspaceSessionInvalidated):
        controller.list_collections()

    session2 = create_vault(workspace_dir / "other.json", MASTER, kdf_overrides=KDF)
    guard2 = SessionGuard("other-profile")
    guard2.open(3600)
    switched = SafeWorkspaceController(
        session,
        lease=guard2.lease(),
        guard=guard2,
        session_provider=lambda: session2,
    )
    with pytest.raises(WorkspaceSessionInvalidated):
        switched.list_templates()


def test_ui_projection_allow_lists_never_retain_untrusted_keys() -> None:
    documents = summarize_documents([{
        "id": "document-id", "title": "Receipt", "payload": {"content": "PRIVATE"},
        "attachment": {"id": "attachment-id", "name": "receipt.txt", "mime_type": "text/plain",
                        "size": 7, "sha256": "hash", "key": "PRIVATE-KEY"},
        "unexpected": "PRIVATE",
    }])
    assert "unexpected" not in documents[0]
    assert "key" not in documents[0]["attachment"]
    assert "PRIVATE" not in repr(documents)

    templates = summarize_templates([{
        "id": "template", "kind": "note", "name": "Note", "description": "safe",
        "fields": [{"name": "body", "label": "Body", "type": "multiline", "required": False,
                    "secret": True, "callback": "PRIVATE"}], "callback": "PRIVATE",
    }])
    assert "callback" not in repr(templates)


def test_document_list_uses_metadata_and_service_boundary_only() -> None:
    summary = SimpleNamespace(
        id="doc-id", kind="document", title="Receipt", created_at=1, updated_at=2,
        favorite=False, tags=[], collection_ids=[],
    )

    class MetadataItems:
        def metadata_summaries(self, **_kwargs: object) -> list[object]:
            return [summary]

    class Documents:
        def attachment_for(self, item_id: str) -> dict[str, object]:
            assert item_id == "doc-id"
            return {"id": "attachment-id", "name": "receipt.txt", "mime_type": "text/plain",
                    "size": 4, "sha256": "a" * 64}

    class MetadataOnlySession:
        is_unlocked = True
        path = "C:/vault/vault.json"
        session_generation = 1
        items = MetadataItems()
        documents = Documents()

        def _require_typed_catalog(self) -> object:
            raise AssertionError("document list must not read the raw typed catalog")

    controller = SafeWorkspaceController(
        MetadataOnlySession(), lease=object(), require_lease=lambda _lease: None,
    )
    rows = controller.list_documents()
    assert rows[0]["title"] == "Receipt"
    assert rows[0]["attachment"]["name"] == "receipt.txt"
    preview = summarize_preview({"kind": "text", "safe": True, "content": "explicit preview",
                                "metadata": {"name": "file.txt", "key": "PRIVATE"},
                                "private": "PRIVATE"})
    assert preview["content"] == "explicit preview"
    assert "private" not in preview and "key" not in repr(preview)


def test_session_generation_detects_in_place_reuse_without_provider() -> None:
    class Session:
        is_unlocked = True
        path = "C:/vault/vault.json"
        session_generation = 1

    session = Session()
    controller = SafeWorkspaceController(
        session, lease=object(), require_lease=lambda _lease: None,
    )
    session.session_generation = 2
    with pytest.raises(WorkspaceSessionInvalidated):
        controller.require_session()


def test_metadata_attachment_usage_does_not_read_raw_catalog() -> None:
    summary = SimpleNamespace(
        id="doc-id", kind="document", title="Receipt", created_at=1, updated_at=2,
        favorite=False, tags=[], collection_ids=[],
    )

    class MetadataItems:
        def metadata_summaries(self, **_kwargs: object) -> list[object]:
            return [summary]

    class Attachments:
        def quota_status(self) -> dict[str, int]:
            return {"used": 4, "quota": 100, "available": 96}

    class Documents:
        def attachment_for(self, item_id: str) -> dict[str, object]:
            assert item_id == "doc-id"
            return {"id": "attachment-id", "name": "receipt.txt", "size": 4}

    class MetadataOnlySession:
        is_unlocked = True
        path = "C:/vault/vault.json"
        session_generation = 1
        items = MetadataItems()
        documents = Documents()
        attachments = Attachments()

        def _require_typed_catalog(self) -> object:
            raise AssertionError("attachment usage must not read the raw typed catalog")

    controller = SafeWorkspaceController(
        MetadataOnlySession(), lease=object(), require_lease=lambda _lease: None,
    )
    assert controller.attachment_usage() == {
        "used": 4, "quota": 100, "available": 96, "catalog_count": 1,
    }


def test_scheduler_stop_requires_live_lease(workspace_dir: Path) -> None:
    _session, guard, controller = _controller(workspace_dir)

    class Scheduler:
        stopped = False

        def stop(self) -> None:
            self.stopped = True

    scheduler = Scheduler()
    controller._scheduler = scheduler
    guard.invalidate()
    with pytest.raises(WorkspaceSessionInvalidated):
        controller.stop_scheduler()
    assert scheduler.stopped is False
    controller.invalidate_session()
    assert scheduler.stopped is True
