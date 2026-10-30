"""Restoring document files from a phone backup (format 2) into the desktop vault."""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
from test_sync_vault_bridge import NOW, FakeLease, _vault

from localvault.attachments import AttachmentStore
from localvault.item_schema import new_item
from localvault.item_service import ItemService
from localvault.phone_backup import PhoneBackup, read_phone_backup, select_files, write_phone_backup
from localvault.sync.attachment_flow import own_blob
from localvault.sync.phone_restore import plan_restore, restore
from localvault.sync.vault_bridge import local_view

FAST_KDF = {"name": "argon2id", "time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
PHONE = "phone"
PASSWORD = "backup password"
DATA = b"passport bytes"


@pytest.fixture
def lease() -> FakeLease:
    return FakeLease()


def _own(tmp_path: Path, name: str) -> Path:
    """A folder per vault: attachment sidecars live next to the vault file."""
    (tmp_path / name).mkdir(exist_ok=True)
    return tmp_path / name


def _phone_with_document(tmp_path: Path):
    phone = _vault(_own(tmp_path, "p"), "phone")
    attachment_id = AttachmentStore(phone).add_bytes("passport.pdf", DATA, mime_type="application/pdf")
    item_id = ItemService(phone)._append(new_item("document", "Passport", {"attachment_id": attachment_id,
                                                                          "description": ""}))
    return phone, item_id


def _backup(phone, lease: FakeLease, *, with_files: bool = True) -> PhoneBackup:
    states = list(local_view(phone, lease, device_id=PHONE, now=NOW).values())
    files, left_out = select_files(states, lambda ref: own_blob(phone, ref)) if with_files else ({}, ())
    assert not left_out
    data = write_phone_backup(states, password=PASSWORD, device_id=PHONE, platform="android",
                              app_version="1.0", created_at=NOW, pro_hint=False, kdf=FAST_KDF, files=files)
    return read_phone_backup(data, PASSWORD)


def _ids(session) -> set[str]:
    return {r["id"] for r in (*session._payload["entries"], *session._payload["items"])}


def _doc_file(session, item_id: str) -> bytes:
    item = next(i for i in session._payload["items"] if i["id"] == item_id)
    return AttachmentStore(session).read_bytes(item["payload"]["attachment_id"])


def test_document_restores_with_its_file(tmp_path: Path, lease: FakeLease) -> None:
    phone, item_id = _phone_with_document(tmp_path)
    desk = _vault(_own(tmp_path, "d"), "desk")
    backup = _backup(phone, lease)
    assert backup.header.version == 2 and len(backup.files) == 1
    plan = plan_restore(desk, lease, backup, now=NOW)
    # the preview stores no file (it only persists sync metadata, like any plan)
    assert not desk._payload.get("attachments") and not _ids(desk)
    assert (plan.new, plan.files_missing, len(plan.files)) == (1, 0, 1)
    report = restore(desk, lease, plan, now=NOW)
    assert report.issues == () and report.new == 1 and report.files == 1
    assert _doc_file(desk, item_id) == DATA
    again = restore(desk, lease, plan_restore(desk, lease, backup, now=NOW), now=NOW)
    assert again.new == 0 and again.issues == ()


def test_document_without_its_file_is_left_out_and_counted(tmp_path: Path, lease: FakeLease) -> None:
    phone, _item_id = _phone_with_document(tmp_path)
    note_id = phone.item_service.create_note("Note", "body")
    desk = _vault(_own(tmp_path, "d"), "desk")
    backup = _backup(phone, lease, with_files=False)
    assert backup.header.version == 1
    plan = plan_restore(desk, lease, backup, now=NOW)
    assert (plan.new, plan.files_missing) == (1, 1)
    report = restore(desk, lease, plan, now=NOW)
    assert report.files_missing == 1 and report.issues == ()
    assert _ids(desk) == {note_id}


def test_tampered_file_is_refused_and_its_document_not_restored(tmp_path: Path, lease: FakeLease) -> None:
    phone, item_id = _phone_with_document(tmp_path)
    desk = _vault(_own(tmp_path, "d"), "desk")
    plan = plan_restore(desk, lease, _backup(phone, lease), now=NOW)
    ((blob_id, blob),) = plan.files.items()
    broken = bytearray(blob)
    broken[-1] ^= 1
    report = restore(desk, lease, dataclasses.replace(plan, files={blob_id: bytes(broken)}), now=NOW)
    assert "attachment-refused" in report.issues and report.files == 0
    assert item_id not in _ids(desk)


def test_a_catalog_row_whose_file_was_deleted_takes_the_backups_copy(tmp_path: Path, lease: FakeLease) -> None:
    phone, item_id = _phone_with_document(tmp_path)
    desk = _vault(_own(tmp_path, "d"), "desk")
    backup = _backup(phone, lease)
    restore(desk, lease, plan_restore(desk, lease, backup, now=NOW), now=NOW)
    item = next(i for i in desk._payload["items"] if i["id"] == item_id)
    AttachmentStore(desk)._path(item["payload"]["attachment_id"]).unlink()  # the row stays, the file is gone
    plan = plan_restore(desk, lease, backup, now=NOW)
    assert len(plan.files) == 1 and plan.files_missing == 0  # the backup's copy is queued again
    restore(desk, lease, plan, now=NOW)
    assert _doc_file(desk, item_id) == DATA
