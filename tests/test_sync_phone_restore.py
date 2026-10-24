"""Restoring a phone backup into the desktop vault through the sync merge."""
from __future__ import annotations

from pathlib import Path

import pytest
from test_sync_vault_bridge import NOW, FakeLease, _file, _state, _sync, _vault

from localvault.phone_backup import PhoneBackup, read_phone_backup, write_phone_backup
from localvault.sync.phone_restore import (
    PhoneRestoreError,
    desktop_device_id,
    plan_restore,
    restore,
)
from localvault.sync.vault_bridge import BridgeError, local_view, save_sync_state

FAST_KDF = {"name": "argon2id", "time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
PHONE, PC = "phone", "pc"
PASSWORD = "backup password"


@pytest.fixture
def lease() -> FakeLease:
    return FakeLease()


def _backup(phone, lease: FakeLease) -> PhoneBackup:
    states = list(local_view(phone, lease, device_id=PHONE, now=NOW).values())
    data = write_phone_backup(states, password=PASSWORD, device_id=PHONE, platform="android",
                              app_version="1.0", created_at=NOW, pro_hint=False, kdf=FAST_KDF)
    return read_phone_backup(data, PASSWORD)


def _ids(session) -> set[str]:
    return {r["id"] for r in (*session._payload["entries"], *session._payload["items"])}


def test_restore_into_empty_vault_adds_every_live_item(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    entry_id = phone.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    note_id = phone.item_service.create_note("Note", "body")
    plan = plan_restore(desk, lease, _backup(phone, lease), now=NOW)
    assert (plan.new, plan.updated, plan.unchanged, plan.held_back) == (2, 0, 0, 0)
    report = restore(desk, lease, plan, now=NOW)
    assert report.issues == () and report.new == 2
    assert _ids(desk) == {entry_id, note_id}


def test_restore_keeps_newer_desktop_version(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    entry_id = phone.upsert_web(origin="https://example.com", username="me", password="old-pass-1")
    backup = _backup(phone, lease)
    _sync(desk, PC, phone, PHONE, lease)
    desk.update_entry_fields(entry_id, password="newer-pass-2")
    plan = plan_restore(desk, lease, backup, now=NOW)
    assert (plan.new, plan.updated, plan.unchanged) == (0, 0, 1)
    restore(desk, lease, plan, now=NOW)
    assert next(e for e in desk._payload["entries"] if e["id"] == entry_id)["password"] == "newer-pass-2"


def test_unknown_tombstones_change_nothing(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    entry_id = phone.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    local_view(phone, lease, device_id=PHONE, now=NOW)
    phone.delete(entry_id)
    backup = _backup(phone, lease)
    assert backup.states and all(s.deleted for s in backup.states)
    plan = plan_restore(desk, lease, backup, now=NOW)
    assert (plan.new, plan.updated, plan.unchanged, plan.held_back) == (0, 0, 0, 0)
    report = restore(desk, lease, plan, now=NOW)
    assert report.issues == ()
    assert not desk._payload.get("trash")
    assert _ids(desk) == set()


def test_restore_twice_is_idempotent(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    phone.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    phone.item_service.create_note("Note", "body")
    backup = _backup(phone, lease)
    restore(desk, lease, plan_restore(desk, lease, backup, now=NOW), now=NOW)
    again = plan_restore(desk, lease, backup, now=NOW)
    assert again.new == again.updated == 0 and again.unchanged == 2


def test_free_plan_caps_only_new_items(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    entry_id = phone.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    _sync(desk, PC, phone, PHONE, lease)
    local_view(phone, lease, device_id=PHONE, now=NOW)
    phone.update_entry_fields(entry_id, password="changed-pass-9")
    phone.item_service.create_note("N1", "x")
    phone.item_service.create_note("N2", "y")
    desk.item_limit = desk.live_item_count()
    plan = plan_restore(desk, lease, _backup(phone, lease), now=NOW)
    assert (plan.updated, plan.new, plan.held_back) == (1, 0, 2)
    report = restore(desk, lease, plan, now=NOW)
    assert report.issues == () and report.held_back == 2
    assert _ids(desk) == {entry_id}
    assert desk._payload["entries"][0]["password"] == "changed-pass-9"


def test_cap_keeps_the_newest_items(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    b = phone.item_service.create_note("b", "x")
    a = phone.item_service.create_note("a", "y")
    for item in phone._payload["items"]:
        item["created_at"] = 1
        item["updated_at"] = 20 if item["id"] == a else 10
    desk.item_limit = 1
    plan = plan_restore(desk, lease, _backup(phone, lease), now=NOW)
    assert (plan.new, plan.held_back) == (1, 1)
    restore(desk, lease, plan, now=NOW)
    assert _ids(desk) == {a} and b not in _ids(desk)


def test_free_plan_keeps_new_two_factor_keys_as_hidden_fields(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    entry_id = phone.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    phone.set_entry_extras(entry_id, totp={"secret": "JBSWY3DPEHPK3PXP"})
    desk.pro_features = frozenset()
    plan = plan_restore(desk, lease, _backup(phone, lease), now=NOW)
    assert plan.totp_as_field == 1
    report = restore(desk, lease, plan, now=NOW)
    assert report.issues == () and report.totp_as_field == 1
    stored = desk._payload["entries"][0]
    assert stored.get("totp") is None
    assert any(f["name"] == "Two-factor key (needs Pro)" for f in stored["custom_fields"])


def test_pro_plan_keeps_two_factor_keys(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    entry_id = phone.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    phone.set_entry_extras(entry_id, totp={"secret": "JBSWY3DPEHPK3PXP"})
    plan = plan_restore(desk, lease, _backup(phone, lease), now=NOW)
    assert plan.totp_as_field == 0
    restore(desk, lease, plan, now=NOW)
    assert desk._payload["entries"][0]["totp"]["secret"] == "JBSWY3DPEHPK3PXP"


def test_desktop_device_id_prefers_group_then_meta_then_new(tmp_path: Path, lease: FakeLease) -> None:
    desk = _vault(tmp_path, "desk")
    fresh = desktop_device_id(desk)
    assert fresh and desktop_device_id(desk) != fresh  # a new id each time until one is stored
    local_view(desk, lease, device_id="meta-dev", now=NOW)
    assert desktop_device_id(desk) == "meta-dev"
    save_sync_state(desk, _state())
    assert desktop_device_id(desk) == "device-a"


def test_failed_merge_leaves_vault_bytes_unchanged(tmp_path: Path, lease: FakeLease, monkeypatch) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    phone.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    plan = plan_restore(desk, lease, _backup(phone, lease), now=NOW)
    before = _file(desk)

    def boom(*args, **kwargs):
        raise BridgeError("full", reason="trash-full")

    monkeypatch.setattr("localvault.sync.runner.apply", boom)
    report = restore(desk, lease, plan, now=NOW)
    assert report.issues == ("trash-full",)
    assert _file(desk) == before


def test_free_plan_restore_twice_changes_nothing(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    entry_id = phone.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    phone.set_entry_extras(entry_id, totp={"secret": "JBSWY3DPEHPK3PXP"})
    desk.pro_features = frozenset()
    backup = _backup(phone, lease)
    first = restore(desk, lease, plan_restore(desk, lease, backup, now=NOW), now=NOW)
    assert (first.new, first.totp_as_field) == (1, 1)
    before = _file(desk)
    again = plan_restore(desk, lease, backup, now=NOW)
    assert again.new == again.updated == again.totp_as_field == 0 and again.unchanged == 1
    second = restore(desk, lease, again, now=NOW)
    assert (second.new, second.updated, second.totp_as_field, second.issues) == (0, 0, 0, ())
    assert _file(desk) == before
    fields = desk._payload["entries"][0]["custom_fields"]
    assert [f["name"] for f in fields].count("Two-factor key (needs Pro)") == 1


def test_conflict_copy_takes_a_free_slot(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    entry_id = phone.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    _sync(desk, PC, phone, PHONE, lease)
    desk.update_entry_fields(entry_id, password="desk-edit-1")
    local_view(desk, lease, device_id=PC, now=NOW)
    local_view(phone, lease, device_id=PHONE, now=NOW)
    phone.update_entry_fields(entry_id, password="phone-edit-2")
    backup = _backup(phone, lease)
    # unlimited: the concurrent edit makes a conflict copy, counted as new
    assert plan_restore(desk, lease, backup, now=NOW).new == 1
    desk.item_limit = desk.live_item_count()
    plan = plan_restore(desk, lease, backup, now=NOW)
    assert (plan.new, plan.updated, plan.held_back) == (0, 0, 1)
    report = restore(desk, lease, plan, now=NOW)
    assert report.issues == () and report.held_back == 1
    assert desk.live_item_count() == desk.item_limit
    assert desk._payload["entries"][0]["password"] == "desk-edit-1"


def test_report_counts_what_was_applied(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    phone.upsert_web(origin="https://example.com", username="me", password="pw-123456")
    phone.item_service.create_note("Note", "body")
    plan = plan_restore(desk, lease, _backup(phone, lease), now=NOW)
    # a stale plan: the same view restored once already
    restore(desk, lease, plan, now=NOW)
    report = restore(desk, lease, plan, now=NOW)
    assert (report.new, report.updated) == (0, 0)


def test_cap_tie_keeps_the_smaller_id(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    ids = [phone.item_service.create_note("x", "1"), phone.item_service.create_note("y", "2")]
    for item in phone._payload["items"]:
        item["created_at"] = 1
        item["updated_at"] = 10
    desk.item_limit = 1
    plan = plan_restore(desk, lease, _backup(phone, lease), now=NOW)
    restore(desk, lease, plan, now=NOW)
    assert _ids(desk) == {min(ids)}


def test_backup_from_this_computer_is_refused(tmp_path: Path, lease: FakeLease) -> None:
    desk = _vault(tmp_path, "desk")
    desk.item_service.create_note("Note", "body")
    local_view(desk, lease, device_id=PC, now=NOW)
    data = write_phone_backup(list(local_view(desk, lease, device_id=PC, now=NOW).values()), password=PASSWORD,
                              device_id=PC, platform="android", app_version="1.0", created_at=NOW,
                              pro_hint=False, kdf=FAST_KDF)
    before = _file(desk)
    with pytest.raises(PhoneRestoreError, match="nothing to restore"):
        plan_restore(desk, lease, read_phone_backup(data, PASSWORD), now=NOW)
    assert _file(desk) == before


def _backup_with(states, lease=None) -> PhoneBackup:
    data = write_phone_backup(states, password=PASSWORD, device_id=PHONE, platform="android",
                              app_version="1.0", created_at=NOW, pro_hint=False, kdf=FAST_KDF)
    return read_phone_backup(data, PASSWORD)


def test_unreadable_record_is_skipped_and_takes_no_free_slot(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    good_id = phone.item_service.create_note("Good", "body")
    newer_id = phone.item_service.create_note("Newer", "body")
    for item in phone._payload["items"]:
        item["created_at"] = 1
        item["updated_at"] = 30 if item["id"] == newer_id else 10
    view = local_view(phone, lease, device_id=PHONE, now=NOW)
    # the newer note arrives in the engine form of a conflict copy, which apply refuses
    bad = view[newer_id]
    bad = type(bad)("copy-of-newer", bad.vv, False, None, {**bad.item, "id": "copy-of-newer"})
    backup = _backup_with([view[good_id], bad])
    desk.item_limit = 1
    plan = plan_restore(desk, lease, backup, now=NOW)
    assert (plan.new, plan.held_back, plan.skipped) == (1, 0, 1)
    report = restore(desk, lease, plan, now=NOW)
    assert report.issues == () and (report.new, report.skipped) == (1, 1)
    assert _ids(desk) == {good_id}


def test_phone_deletions_are_counted(tmp_path: Path, lease: FakeLease) -> None:
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    keep = phone.item_service.create_note("Keep", "body")
    gone = phone.item_service.create_note("Gone", "body")
    _sync(desk, PC, phone, PHONE, lease)
    local_view(phone, lease, device_id=PHONE, now=NOW)
    phone.item_service.delete_item(gone)
    plan = plan_restore(desk, lease, _backup(phone, lease), now=NOW)
    assert (plan.new, plan.updated, plan.unchanged, plan.deleted) == (0, 0, 1, 1)
    report = restore(desk, lease, plan, now=NOW)
    assert report.issues == () and report.deleted == 1
    assert _ids(desk) == {keep}
    assert gone in {row["entry"]["id"] for row in desk._payload["trash"]}
