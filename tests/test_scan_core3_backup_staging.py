"""Scan core 3 (2026-11-15): M1 (restore checks never stage the backup's inner layer beside the backup file) and L4
(a v1 restore never leaves new settings beside an old or missing vault)."""
from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from localvault import backup as backup_module
from localvault import restore_test
from localvault.attachments import DocumentService
from localvault.backup import (
    BackupError,
    export_encrypted_backup,
    export_full_backup,
    private_temp_root,
    restore_full_backup,
    restore_verified_backup,
)
from localvault.config import atomic_write_json
from localvault.recovery import RecoveryError, inspect_recovery_backup, restore_as_new_profile, verify_recovery_backup
from localvault.vault import create_vault, unlock_vault

MASTER = "synthetic staging master password"
BACKUP_PASSWORD = "synthetic staging backup password"
KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
CHEAP = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}


def _profile(path: Path) -> Path:
    path.mkdir(parents=True)
    session = create_vault(path / "vault.json", MASTER, kdf_overrides=KDF)
    session.upsert_web(origin="https://example.test", username="synthetic-user", password="synthetic-secret",
                       label="Synthetic login")
    fixture = path.parent / "fixture.txt"
    fixture.write_bytes(b"synthetic attachment")
    DocumentService(session).create(fixture, title="Synthetic document", mime_type="text/plain")
    session.lock()
    atomic_write_json(path / "settings.json", {})
    return path


@pytest.fixture
def mirror_backup(tmp_path: Path) -> Path:
    """A full backup in a folder standing in for a OneDrive / Dropbox mirror."""
    profile = _profile(tmp_path / "source")
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    backup = mirror / "profile.lgkfull"
    export_full_backup(backup, profile_dir=profile, profile_name="Synthetic profile",
                       backup_password=BACKUP_PASSWORD, kdf_overrides=CHEAP)
    return backup


@pytest.fixture
def spy(monkeypatch):
    """Every staging folder and staged file the restore code creates."""
    created: list[Path] = []
    real_temp, real_atomic, real_mkdtemp = (backup_module._full_temp_dir, backup_module._full_atomic_bytes,
                                            tempfile.mkdtemp)

    def temp_dir(parent, prefix):
        made = real_temp(parent, prefix)
        created.append(Path(made))
        return made

    def atomic(target, data):
        created.append(Path(target))
        return real_atomic(target, data)

    def mkdtemp(*args, **kwargs):
        made = real_mkdtemp(*args, **kwargs)
        created.append(Path(made))
        return made

    monkeypatch.setattr(backup_module, "_full_temp_dir", temp_dir)
    monkeypatch.setattr(backup_module, "_full_atomic_bytes", atomic)
    monkeypatch.setattr(tempfile, "mkdtemp", mkdtemp)
    return created


def _nothing_in(folder: Path, created: list[Path]) -> None:
    assert created, "the check did stage something"
    folder = folder.resolve()
    for place in created:
        resolved = place.resolve()
        assert resolved != folder and folder not in resolved.parents, place


def test_restore_test_stages_inside_its_scratch_never_beside_the_backup(mirror_backup: Path, spy) -> None:
    before = sorted(p.name for p in mirror_backup.parent.iterdir())
    result = restore_test.run(None, 2_000_000_000, backup_path=mirror_backup, backup_password=BACKUP_PASSWORD,
                              vault_password=MASTER)
    assert result.ok, result
    _nothing_in(mirror_backup.parent, spy)
    scratch = restore_test.scratch_root().resolve()
    assert all(scratch in p.resolve().parents for p in spy if "lgk-full-restore" in str(p)), spy
    assert sorted(p.name for p in mirror_backup.parent.iterdir()) == before


@pytest.mark.parametrize("check", ["inspect", "verify"])
def test_recovery_preflight_stages_in_the_private_folder(mirror_backup: Path, spy, check: str) -> None:
    before = sorted(p.name for p in mirror_backup.parent.iterdir())
    if check == "inspect":
        result = inspect_recovery_backup(mirror_backup, backup_password=BACKUP_PASSWORD, vault_password=MASTER)
    else:
        result = verify_recovery_backup(mirror_backup, backup_password=BACKUP_PASSWORD, vault_password=MASTER)
    assert result["attachments"] == 1
    _nothing_in(mirror_backup.parent, spy)
    private = private_temp_root().resolve()
    assert all(private in p.resolve().parents for p in spy), spy
    assert sorted(p.name for p in mirror_backup.parent.iterdir()) == before


def test_real_restores_never_stage_beside_the_backup(mirror_backup: Path, spy, tmp_path: Path) -> None:
    before = sorted(p.name for p in mirror_backup.parent.iterdir())
    destination = tmp_path / "profiles" / "restored"
    result = restore_as_new_profile(mirror_backup, destination, backup_password=BACKUP_PASSWORD,
                                    vault_password=MASTER, confirm=True)
    assert result["committed"] is True
    direct = tmp_path / "direct"
    info = restore_full_backup(mirror_backup, profile_dir=direct, backup_password=BACKUP_PASSWORD,
                               vault_password=MASTER)
    assert info["attachments"] == 1
    _nothing_in(mirror_backup.parent, spy)
    assert sorted(p.name for p in mirror_backup.parent.iterdir()) == before
    for vault in (destination / "vault.json", direct / "vault.json"):
        unlock_vault(vault, MASTER).lock()


def test_a_read_only_backup_folder_does_not_break_the_checks(mirror_backup: Path, monkeypatch) -> None:
    """Read-only media: any write beside the backup fails; the checks never try one."""
    folder = mirror_backup.parent.resolve()
    real_temp, real_mkdtemp = backup_module._full_temp_dir, tempfile.mkdtemp

    def refuse(path) -> None:
        if Path(path).resolve() == folder:
            raise PermissionError("read-only media (test)")

    def temp_dir(parent, prefix):
        refuse(parent)
        return real_temp(parent, prefix)

    def mkdtemp(*args, dir=None, **kwargs):
        if dir is not None:
            refuse(dir)
        return real_mkdtemp(*args, dir=dir, **kwargs)

    monkeypatch.setattr(backup_module, "_full_temp_dir", temp_dir)
    monkeypatch.setattr(tempfile, "mkdtemp", mkdtemp)
    assert inspect_recovery_backup(mirror_backup, backup_password=BACKUP_PASSWORD)["dry_run"] is True
    assert restore_test.run(None, 2_000_000_000, backup_path=mirror_backup, backup_password=BACKUP_PASSWORD,
                            vault_password=MASTER).ok


def test_no_private_folder_is_a_handled_recovery_error(mirror_backup: Path, monkeypatch) -> None:
    def broken():
        raise OSError("The private temporary folder is a link")

    monkeypatch.setattr(backup_module, "private_temp_root", broken)
    with pytest.raises(RecoveryError):
        inspect_recovery_backup(mirror_backup, backup_password=BACKUP_PASSWORD)
    with pytest.raises(BackupError):
        restore_full_backup(mirror_backup, profile_dir=mirror_backup.parent / "probe",
                            backup_password=BACKUP_PASSWORD, dry_run=True)


def test_real_restore_stages_on_the_destination_volume(tmp_path: Path, monkeypatch) -> None:
    # The data folder on the volume of tmp_path (a CI runner keeps the system temp on another drive).
    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "lgk-data"))
    destination = tmp_path / "new" / "deeper" / "vault.json"
    # Same volume: the private folder.
    assert backup_module._full_restore_stage_parent(destination, dry_run=False, stage_parent=None) \
        == private_temp_root()
    # Another volume: the destination's nearest existing folder, never created here.
    other = SimpleNamespace(stat=lambda: SimpleNamespace(st_dev=-12345))
    monkeypatch.setattr(backup_module, "private_temp_root", lambda: other)
    assert backup_module._full_restore_stage_parent(destination, dry_run=False, stage_parent=None) == tmp_path
    assert not (tmp_path / "new").exists()
    # A dry run always uses the private folder.
    assert backup_module._full_restore_stage_parent(destination, dry_run=True, stage_parent=None) is other


def test_v1_restore_writes_settings_only_after_the_vault(tmp_path: Path, monkeypatch) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    create_vault(profile / "vault.json", MASTER, kdf_overrides=KDF).lock()
    atomic_write_json(profile / "settings.json", {"version": 5})
    backup = tmp_path / "b.lgk"
    export_encrypted_backup(backup, vault_file=profile / "vault.json", settings_file=profile / "settings.json",
                            profile_name="P", backup_password=BACKUP_PASSWORD, kdf_overrides=CHEAP)
    target = tmp_path / "restored"
    target.mkdir()
    vault_file, settings_file = target / "vault.json", target / "settings.json"
    real = backup_module.atomic_write_json

    def failing(path, value):
        if Path(path) == vault_file:
            raise OSError("disk full (test)")
        return real(path, value)

    monkeypatch.setattr(backup_module, "atomic_write_json", failing)
    with pytest.raises(OSError):
        restore_verified_backup(backup, vault_file=vault_file, settings_file=settings_file,
                                backup_password=BACKUP_PASSWORD, vault_password=MASTER)
    assert not vault_file.exists()
    assert not settings_file.exists(), "no restored settings beside a missing vault"
    monkeypatch.undo()
    restore_verified_backup(backup, vault_file=vault_file, settings_file=settings_file,
                            backup_password=BACKUP_PASSWORD, vault_password=MASTER)
    assert vault_file.exists() and settings_file.exists()
