"""Shared collections and backups on Windows (sub-plan 07, final review finding 3, ruling F3).

A backup never carries a share (its keys, keyring, owner key, bookkeeping, links or "shared" marks), and
a restore keeps the shares the replaced vault has now, like the Mac's ``keepingShared``: an owner that
restores an older backup keeps running its share.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from localvault import licensing
from localvault.app.recovery import restore_confirmation
from localvault.backup import (
    export_encrypted_backup,
    keep_current_shares,
    restore_full_backup,
    restore_verified_backup,
    without_share_records,
)
from localvault.collections import CollectionService
from localvault.i18n import t
from localvault.item_service import ItemService
from localvault.recovery import create_recovery_backup
from localvault.sync import share_group as sg
from localvault.sync.folder_transport import FolderSync
from localvault.sync.vault_bridge import LINKS_KEY
from localvault.vault import create_vault, unlock_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
FAST_BACKUP_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
CHEAP = (1024, 1, 1)
MASTER = "synthetic master"
BACKUP_PASSWORD = "synthetic independent backup password"
PW = "correct horse battery staple 7!"
PW2 = "another very long passphrase 42?"
PW3 = "a third share passphrase, long 9!"


class FakeLease:
    def check(self) -> None:
        pass


LEASE = FakeLease()


@pytest.fixture(autouse=True)
def pro(monkeypatch):
    monkeypatch.setattr(licensing, "item_limit", lambda st=None: None)


def _no_share_records(payload):
    assert not payload.get("share_groups") and not payload.get("share_sync_meta") and LINKS_KEY not in payload
    assert not any(r.get("shared_group_id") for r in payload.get("collections", []))


class Share:
    def __init__(self, root: Path):
        self.root = root
        self.folder = root / "Family share"
        self.folder.mkdir()
        self.owner_path = root / "owner" / "vault.json"
        self.owner_path.parent.mkdir()
        self.owner = create_vault(self.owner_path, MASTER, kdf_overrides=TEST_KDF)
        self.cid = CollectionService(self.owner).create("Family")
        self.note = ItemService(self.owner).create_note("Wi-Fi", "family wifi", collection_ids=[self.cid])
        self.gid = sg.create_share_group(self.owner, self.cid, password=PW, device="Owner PC", shared_mode="edit",
                                         install_id="install-owner", _kdf_override=CHEAP).group_id
        sg.set_share_folder(self.owner, self.gid, str(self.folder))
        self.now = int(time.time())

    def run(self, session, install="install-owner"):
        self.now += 1
        fs = FolderSync(self.folder, install_id=install, share=self.gid, _kdf_override=CHEAP)
        return fs.run_once(session, LEASE, now=self.now)

    def member(self, name: str, password: str):
        """A new member joins with *password* and is approved."""
        session = create_vault(self.root / f"{name}.json", MASTER, kdf_overrides=TEST_KDF)
        self.run(self.owner)
        raw = FolderSync(self.folder, install_id=f"install-{name}", share=self.gid,
                         _kdf_override=CHEAP).read_keyring_bytes()
        sg.join_share_group(session, raw, password=password, device=name, install_id=f"install-{name}",
                            _kdf_override=CHEAP)
        sg.set_share_folder(session, self.gid, str(self.folder))
        self.run(session, f"install-{name}")
        self.run(self.owner)
        sg.approve_members(self.owner, self.gid, [m.device_id for m in sg.pending_members(self.owner, self.gid)],
                           _kdf_override=CHEAP)
        self.run(self.owner)
        self.run(session, f"install-{name}")
        return session

    def remove(self, session, new_password: str) -> None:
        device = sg.share_state(session, self.gid).device_id
        notice = sg.remove_member(self.owner, self.gid, device, new_password=new_password, _kdf_override=CHEAP)
        fs = FolderSync(self.folder, install_id="install-owner", share=self.gid, _kdf_override=CHEAP)
        assert fs.publish_share_notice(device, notice)
        self.run(self.owner)


def kinds(report):
    return [i.kind for i in report.issues]


def test_a_backup_carries_no_share_and_a_new_profile_restore_has_none(tmp_path):
    s = Share(tmp_path)
    s.member("Ben", PW)
    backup = tmp_path / "owner.lgk"
    export_encrypted_backup(backup, vault_file=s.owner_path, settings_file=None, profile_name="Owner",
                            backup_password=BACKUP_PASSWORD, kdf_overrides=FAST_BACKUP_KDF,
                            vault_filter=without_share_records(s.owner))
    # The live vault keeps its share.
    assert sg.share_info(s.owner, s.gid)["role"] == "owner"
    restored = tmp_path / "restored" / "vault.json"
    restored.parent.mkdir()
    restore_verified_backup(backup, vault_file=restored, settings_file=None, backup_password=BACKUP_PASSWORD,
                            vault_password=MASTER)
    session = unlock_vault(restored, MASTER)
    try:
        _no_share_records(session._payload)
        assert sg.list_share_groups(session) == []
        # The collection and its item stay, as an ordinary collection.
        assert {r["id"] for r in session._payload["collections"]} == {s.cid}
        assert s.cid in {i["id"]: i for i in session._payload["items"]}[s.note]["collection_ids"]
    finally:
        session.lock()


def test_an_older_backup_without_the_share_filter_is_restored_without_its_share(tmp_path):
    # A backup written before this fix still carries the share: a restore into a new profile drops it.
    s = Share(tmp_path)
    backup = tmp_path / "old.lgk"
    export_encrypted_backup(backup, vault_file=s.owner_path, settings_file=None, profile_name="Owner",
                            backup_password=BACKUP_PASSWORD, kdf_overrides=FAST_BACKUP_KDF)
    restored = tmp_path / "restored" / "vault.json"
    restored.parent.mkdir()
    restore_verified_backup(backup, vault_file=restored, settings_file=None, backup_password=BACKUP_PASSWORD,
                            vault_password=MASTER)
    session = unlock_vault(restored, MASTER)
    try:
        _no_share_records(session._payload)
    finally:
        session.lock()


def test_owner_restores_a_backup_two_rotations_old_and_still_runs_its_share(tmp_path):
    # Create a share, back up, remove a member twice, restore: the owner keeps its current share record.
    s = Share(tmp_path)
    ben = s.member("Ben", PW)
    backup = tmp_path / "owner.lgk"
    export_encrypted_backup(backup, vault_file=s.owner_path, settings_file=None, profile_name="Owner",
                            backup_password=BACKUP_PASSWORD, kdf_overrides=FAST_BACKUP_KDF,
                            vault_filter=without_share_records(s.owner))
    s.remove(ben, PW2)
    cy = s.member("Cy", PW2)
    s.remove(cy, PW3)
    dee = s.member("Dee", PW3)
    ItemService(s.owner).update_item(s.note, title="Wi-Fi (now)")
    s.run(s.owner)
    epoch = sg.share_state(s.owner, s.gid).epoch
    assert epoch >= 3
    s.owner.lock()
    restore_verified_backup(backup, vault_file=s.owner_path, settings_file=None, backup_password=BACKUP_PASSWORD,
                            vault_password=MASTER, replace=True, allow_rollback=True)
    owner = unlock_vault(s.owner_path, MASTER)
    try:
        s.owner = owner
        assert sg.share_info(owner, s.gid)["role"] == "owner"
        assert sg.share_state(owner, s.gid).epoch == epoch
        # The shared item is as it is now, not as the backup had it.
        assert {i["id"]: i for i in owner._payload["items"]}[s.note]["title"] == "Wi-Fi (now)"
        report = s.run(owner)
        assert not {"missed-rotation", "rejoin-required", "share-removed", "tampered"} & set(kinds(report)), kinds(report)
        ItemService(owner).update_item(s.note, title="Wi-Fi after restore")
        s.run(owner)
        s.run(dee, "install-Dee")
        assert {i["id"]: i for i in dee._payload["items"]}[s.note]["title"] == "Wi-Fi after restore"
    finally:
        owner.lock()


def test_a_full_recovery_backup_carries_no_share(tmp_path):
    s = Share(tmp_path)
    s.owner.lock()
    backup = tmp_path / "full.lgk"
    created = create_recovery_backup(backup, profile_dir=s.owner_path.parent, profile_name="Owner",
                                     backup_password=BACKUP_PASSWORD, vault_password=MASTER)
    assert created["committed"] is True
    restored = tmp_path / "restored"
    restore_full_backup(backup, profile_dir=restored, backup_password=BACKUP_PASSWORD,
                        vault_password=MASTER)
    session = unlock_vault(restored / "vault.json", MASTER)
    try:
        _no_share_records(session._payload)
        assert {r["id"] for r in session._payload["collections"]} == {s.cid}
    finally:
        session.lock()
    # The live profile keeps its share.
    live = unlock_vault(s.owner_path, MASTER)
    try:
        assert sg.share_info(live, s.gid)["role"] == "owner"
    finally:
        live.lock()


def test_keep_current_shares_keeps_shared_items_as_they_are_now():
    shared, other = "c-shared", "c-other"
    current = {
        "collections": [{"id": shared, "name": "Family (now)", "shared_group_id": "g1"},
                        {"id": other, "name": "Other"}],
        "items": [{"id": "i1", "kind": "note", "title": "now", "collection_ids": [shared]},
                  {"id": "i4", "kind": "note", "title": "added since", "collection_ids": [shared, other]}],
        "share_groups": {"g1": {"collection_id": shared}},
        "share_sync_meta": {shared: {"i1": {}}},
        "collection_links": {"c-link": {"mode": "read", "role": "member"}},
    }
    restored = {
        "collections": [{"id": shared, "name": "Family (backup)", "shared_group_id": "g0"},
                        {"id": "c-gone", "name": "Old", "shared_group_id": "g9"}],
        "items": [{"id": "i1", "kind": "note", "title": "backup", "collection_ids": [shared]},
                  {"id": "i2", "kind": "note", "title": "left since", "collection_ids": [shared, "c-gone"]},
                  {"id": "i3", "kind": "document", "title": "doc", "collection_ids": [shared]}],
        "trash": [{"entry": {"id": "i4", "kind": "note", "collection_ids": [shared]}},
                  {"entry": {"id": "i5", "kind": "note", "collection_ids": [shared]}}],
        "share_groups": {"g0": {"collection_id": shared}},
        "share_sync_meta": {shared: {"old": {}}},
    }
    keep_current_shares(restored, current)
    assert restored["share_groups"] == current["share_groups"]
    assert restored["share_sync_meta"] == current["share_sync_meta"]
    assert restored["collection_links"] == current["collection_links"]
    rows = {r["id"]: r for r in restored["collections"]}
    assert rows[shared]["name"] == "Family (now)" and rows[shared]["shared_group_id"] == "g1"
    assert "shared_group_id" not in rows["c-gone"]
    items = {i["id"]: i for i in restored["items"]}
    assert items["i1"]["title"] == "now"
    assert items["i2"]["collection_ids"] == ["c-gone"], "a restored item that left the share is not put back in"
    assert items["i3"]["collection_ids"] == [shared], "documents never sync in a share and stay as restored"
    assert items["i4"]["collection_ids"] == [shared], "unknown collections are dropped from a kept item"
    assert [r["entry"]["id"] for r in restored["trash"]] == ["i5"]
    assert restored["trash"][0]["entry"]["collection_ids"] == []


def test_keep_current_shares_without_a_current_vault_strips_every_share():
    restored = {"collections": [{"id": "c", "shared_group_id": "g"}], "share_groups": {"g": {}},
                "share_sync_meta": {}, "collection_links": {}}
    keep_current_shares(restored, None)
    _no_share_records(restored)
    assert "share_sync_meta" not in restored and LINKS_KEY not in restored


def test_the_restore_confirmation_says_shared_collections_are_not_restored():
    text = restore_confirmation("Restored", {"format_kind": "full", "entries": 3, "attachments": 0})
    assert t("recovery.sharedNotRestored") in text


# --- re-review wave B: B2 ---------------------------------------------------------------------------------------

def test_a_kept_shared_row_gets_a_unique_name_beside_a_restored_collection_of_that_name():
    current = {"collections": [{"id": "c-shared", "name": "Family", "shared_group_id": "g1"}],
               "share_groups": {"g1": {"collection_id": "c-shared"}}}
    restored = {"collections": [{"id": "c-old", "name": "family"}], "items": []}
    keep_current_shares(restored, current)
    names = {r["id"]: r["name"] for r in restored["collections"]}
    assert names == {"c-old": "family", "c-shared": "Family (2)"}


def test_a_replace_restore_over_a_vault_that_does_not_open_with_its_password_is_refused(tmp_path):
    from localvault.backup import CURRENT_SHARES_UNREADABLE, BackupError

    s = Share(tmp_path)
    backup = tmp_path / "owner.lgk"
    export_encrypted_backup(backup, vault_file=s.owner_path, settings_file=None, profile_name="Owner",
                            backup_password=BACKUP_PASSWORD, kdf_overrides=FAST_BACKUP_KDF,
                            vault_filter=without_share_records(s.owner))
    # The owner changed its master password since: the restore cannot open the vault it would replace.
    s.owner.change_master_password(MASTER, "a newer master password 2026")
    s.owner.lock()
    before = s.owner_path.read_bytes()
    with pytest.raises(BackupError) as refused:
        restore_verified_backup(backup, vault_file=s.owner_path, settings_file=None, backup_password=BACKUP_PASSWORD,
                                vault_password=MASTER, replace=True, allow_rollback=True)
    assert str(refused.value) == CURRENT_SHARES_UNREADABLE
    assert s.owner_path.read_bytes() == before, "nothing was written"
    assert not (s.owner_path.parent / "Backups").exists()
    # Accepting the loss (API only) restores it without any share.
    restore_verified_backup(backup, vault_file=s.owner_path, settings_file=None, backup_password=BACKUP_PASSWORD,
                            vault_password=MASTER, replace=True, allow_rollback=True, drop_current_shares=True)
    session = unlock_vault(s.owner_path, MASTER)
    try:
        _no_share_records(session._payload)
    finally:
        session.lock()
