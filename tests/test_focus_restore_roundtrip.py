"""Locked Recovery Center round trips keep the current profile untouched."""
from __future__ import annotations

import hashlib
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest

from localvault.backup import export_encrypted_backup
from localvault.config import atomic_write_json
from localvault.profiles import ProfileManager
from localvault.recovery import RecoveryService, create_recovery_backup, sha256_file
from localvault.app.recovery_center import RecoveryCenter
from localvault.vault import create_vault, unlock_vault

MASTER_PASSWORD = "synthetic source vault password"
CURRENT_PASSWORD = "synthetic current vault password"
BACKUP_PASSWORD = "synthetic independent backup password"
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}


@contextmanager
def _workspace_temporary_directory(root: Path, *, prefix: str = "tmp-", **_kwargs):
    """Use a normal workspace directory for libraries that call tempfile."""
    directory = root / f"{prefix}{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        yield str(directory)
    finally:
        shutil.rmtree(directory)


def _make_profile(directory: Path, password: str, label: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    session = create_vault(directory / "vault.json", password, kdf_overrides=TEST_KDF)
    session.upsert_web(
        origin="https://roundtrip.example.test",
        username=f"{label.casefold()}-user",
        password=f"{label.casefold()}-secret",
        label=label,
    )
    session.lock()
    atomic_write_json(directory / "settings.json", {"version": 5, "fill_and_sign_in": False})
    return directory


def _file_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


@pytest.mark.parametrize("backup_kind", ["full", "legacy-catalog"])
def test_locked_recovery_center_restores_new_profile_without_touching_current(
    workspace_tmp: Path, backup_kind: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _make_profile(workspace_tmp / "source", MASTER_PASSWORD, "Restored synthetic entry")
    backup = workspace_tmp / f"{backup_kind}.lgk"
    if backup_kind == "full":
        created = create_recovery_backup(
            backup,
            profile_dir=source,
            profile_name="Synthetic source profile",
            backup_password=BACKUP_PASSWORD,
            backup_password_confirmation=BACKUP_PASSWORD,
        )
        assert created["committed"] is True
    else:
        # The legacy decryptor uses tempfile.TemporaryDirectory internally.
        # This runner restricts %TEMP%, so keep that private encrypted staging
        # directory beside this synthetic test case.
        monkeypatch.setattr(
            tempfile,
            "TemporaryDirectory",
            lambda prefix="tmp-", **kwargs: _workspace_temporary_directory(
                workspace_tmp, prefix=prefix, **kwargs,
            ),
        )
        export_encrypted_backup(
            backup,
            vault_file=source / "vault.json",
            settings_file=source / "settings.json",
            profile_name="Synthetic source profile",
            backup_password=BACKUP_PASSWORD,
        )

    profiles = ProfileManager(workspace_tmp / "user-data")
    current = profiles.create_profile("Current synthetic profile")
    current_dir = profiles.profile_dir(current.id)
    _make_profile(current_dir, CURRENT_PASSWORD, "Current-only synthetic entry")
    current_files_before = _file_hashes(current_dir)
    active_id_before = profiles.active_profile().id
    pending = profiles.allocate_restore_profile(f"Restored {backup_kind}")

    center = RecoveryCenter(
        service=RecoveryService(current_dir, profile_name=current.name),
        profiles=profiles,
        active_profile_id=current.id,
        current_check=lambda: None,
        can_create=False,
    )
    assert center.can_create is False
    expected_kind = "catalog" if backup_kind == "legacy-catalog" else "full"
    assert center.backup_format(backup) == expected_kind

    preview = center.preview_restore(
        backup,
        profile_record=pending,
        backup_password=BACKUP_PASSWORD,
        vault_password=MASTER_PASSWORD,
    )
    assert preview["requires_confirmation"] is True
    assert preview["committed"] is False
    assert preview["format_kind"] == expected_kind
    assert not profiles.restore_profile_path(pending).exists()

    result = center.restore(
        backup,
        profile_record=pending,
        confirm=True,
        expected_sha256=preview["backup_sha256"],
        backup_password=BACKUP_PASSWORD,
        vault_password=MASTER_PASSWORD,
    )

    assert result["committed"] is True
    assert result["backup_sha256"] == sha256_file(backup)
    assert any(row.id == pending.id and row.name == pending.name for row in profiles.list_profiles())
    assert profiles.active_profile().id == active_id_before == current.id
    assert _file_hashes(current_dir) == current_files_before

    restored = unlock_vault(profiles.vault_path(pending.id), MASTER_PASSWORD)
    try:
        labels = {item["label"] for item in restored.all_entries()}
        assert "Restored synthetic entry" in labels
        assert "Current-only synthetic entry" not in labels
        assert restored.fill_and_sign_in_enabled() is False
    finally:
        restored.lock()
