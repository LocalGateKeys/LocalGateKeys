"""Restoring a backup forgets the removal watch file, so an old notice cannot erase the restored vault."""
from __future__ import annotations

from pathlib import Path

from test_backup_v2 import BACKUP_PASSWORD, MASTER, _export, _profile, _restore
from test_sync_phone_restore import PASSWORD, _backup
from test_sync_vault_bridge import NOW, FakeLease, _vault

from localvault.backup import export_encrypted_backup, restore_encrypted_backup
from localvault.config import atomic_write_json
from localvault.sync import removal
from localvault.sync.phone_restore import plan_restore, restore


def _plant_watch(vault_file: Path) -> Path:
    watch = removal.watch_path(vault_file)
    watch.write_text("{}", encoding="utf-8")
    assert watch.exists()
    return watch


def test_encrypted_backup_restore_forgets_the_watch(tmp_path: Path) -> None:
    vault = tmp_path / "vault.json"
    backup = tmp_path / "profile.lgk"
    atomic_write_json(vault, {"cipher": {"ciphertext": "secret"}})
    export_encrypted_backup(backup, vault_file=vault, settings_file=None, profile_name="Alice",
                            backup_password="correct horse battery staple")
    watch = _plant_watch(vault)
    restore_encrypted_backup(backup, vault_file=vault, settings_file=None,
                             backup_password="correct horse battery staple")
    assert not watch.exists()


def test_full_backup_restore_forgets_the_watch(tmp_path: Path) -> None:
    profile, _item, _marker = _profile(tmp_path / "source")
    backup = _export(tmp_path, profile)
    target, _i, _m = _profile(tmp_path / "target")
    watch = _plant_watch(target / "vault.json")
    _restore(backup, target, replace=True, allow_rollback=True)
    assert not watch.exists()


def test_phone_backup_restore_forgets_the_watch(tmp_path: Path) -> None:
    lease = FakeLease()
    phone, desk = _vault(tmp_path, "phone"), _vault(tmp_path, "desk")
    phone.item_service.create_note("Note", "body")
    plan = plan_restore(desk, lease, _backup(phone, lease), now=NOW)
    watch = _plant_watch(Path(desk.path))
    restore(desk, lease, plan, now=NOW)
    assert not watch.exists()
