from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

import pytest

from localvault.config import atomic_write_json
from localvault.recovery import (
    RecoveryController,
    RecoveryError,
    create_recovery_backup,
    plan_backup_rotation,
    restore_as_new_profile,
    sha256_file,
    verify_recovery_backup,
    verify_sha256_manifest,
    write_recovery_kit,
)
from localvault.settings import AppSettings
from localvault.vault import create_vault, unlock_vault

MASTER = "synthetic recovery master password"
BACKUP_PASSWORD = "synthetic independent backup password"
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}


@pytest.fixture
def case_dir() -> Path:
    root = Path(__file__).parents[1] / ".m3-recovery-cases" / uuid.uuid4().hex
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _profile(path: Path) -> Path:
    path.mkdir(parents=True)
    session = create_vault(path / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    entry_id = session.upsert_web(
        origin="https://example.test",
        username="synthetic-user",
        password="synthetic-secret",
        label="Synthetic login",
    )
    session.set_details(entry_id, policy={"fill": "click", "sign_in": "enabled"})
    session.set_fill_and_sign_in_enabled(True)
    session.set_hello_binding("a" * 32)
    session.set_face_binding("b" * 32)
    session.lock()
    atomic_write_json(path / "settings.json", {"version": 5, "fill_and_sign_in": True})
    return path


def _backup(root: Path) -> tuple[Path, Path]:
    profile = _profile(root / "source")
    backup = root / "profile.lgk"
    result = create_recovery_backup(
        backup,
        profile_dir=profile,
        profile_name="Synthetic profile",
        backup_password=BACKUP_PASSWORD,
        backup_password_confirmation=BACKUP_PASSWORD,
    )
    assert result["committed"] is True
    assert result["version"] == 2
    assert result["manifest"]
    return profile, backup


def test_create_and_verify_full_recovery_backup_without_live_mutation(case_dir: Path) -> None:
    profile, backup = _backup(case_dir)
    before = (profile / "vault.json").read_bytes()

    result = verify_recovery_backup(
        backup,
        backup_password=BACKUP_PASSWORD,
        vault_password=MASTER,
        expected_sha256=sha256_file(backup),
    )

    assert result["verified"] is True
    assert result["attachments"] == 0
    assert result["backup_sha256"] == sha256_file(backup)
    assert (profile / "vault.json").read_bytes() == before


def test_wrong_master_password_preserves_existing_backup_and_checksum_manifest(case_dir: Path) -> None:
    profile, backup = _backup(case_dir)
    manifest = backup.with_name(backup.name + ".sha256.json")
    backup_before = backup.read_bytes()
    manifest_before = manifest.read_bytes()

    with pytest.raises(RecoveryError):
        create_recovery_backup(
            backup,
            profile_dir=profile,
            backup_password=BACKUP_PASSWORD,
            backup_password_confirmation=BACKUP_PASSWORD,
            vault_password="synthetic wrong master password",
            overwrite=True,
        )

    assert backup.read_bytes() == backup_before
    assert manifest.read_bytes() == manifest_before
    assert verify_sha256_manifest(backup, manifest)["verified"] is True
    assert verify_recovery_backup(backup, backup_password=BACKUP_PASSWORD, vault_password=MASTER)["verified"] is True


def test_wrong_password_or_checksum_fails_before_restore(case_dir: Path) -> None:
    _, backup = _backup(case_dir)
    destination = case_dir / "restored"

    with pytest.raises(RecoveryError):
        verify_recovery_backup(
            backup,
            backup_password="wrong independent backup password",
            vault_password=MASTER,
        )
    with pytest.raises(RecoveryError, match="SHA-256"):
        verify_recovery_backup(
            backup,
            backup_password=BACKUP_PASSWORD,
            vault_password=MASTER,
            expected_sha256="0" * 64,
        )
    assert not destination.exists()


def test_restore_is_preview_first_and_disables_machine_trust(case_dir: Path) -> None:
    _, backup = _backup(case_dir)
    destination = case_dir / "restored"

    preview = restore_as_new_profile(
        backup,
        destination,
        backup_password=BACKUP_PASSWORD,
        vault_password=MASTER,
    )
    assert preview["requires_confirmation"] is True
    assert preview["dry_run"] is True
    assert not destination.exists()

    result = restore_as_new_profile(
        backup,
        destination,
        backup_password=BACKUP_PASSWORD,
        vault_password=MASTER,
        confirm=True,
    )
    assert result["committed"] is True
    restored = unlock_vault(destination / "vault.json", MASTER)
    try:
        assert restored.fill_and_sign_in_enabled() is False
        assert restored.hello_binding() == ""
        assert restored.face_binding() == ""
        assert all(entry.get("policy", {}).get("sign_in") == "never" for entry in restored.all_entries())
    finally:
        restored.lock()
    settings = AppSettings.load(destination / "settings.json")
    assert settings.fill_and_sign_in is False
    assert settings.breach_check_enabled is False
    assert settings.strict_offline_mode is True


def test_confirmed_controller_restore_checks_session_before_core_mutation(tmp_path: Path) -> None:
    from types import SimpleNamespace

    session = SimpleNamespace(path=tmp_path / "Profiles" / "Current" / "vault.json", is_unlocked=True)
    controller = RecoveryController(session)
    calls: list[str] = []

    def stale_session():
        raise RecoveryError("stale session")

    controller.binding = SimpleNamespace(current=stale_session)
    controller.service = SimpleNamespace(restore=lambda *_args, **_kwargs: calls.append("restore"))

    with pytest.raises(RecoveryError, match="stale session"):
        controller.restore("backup.lgk", "new-profile", confirm=True)

    assert calls == []


def test_recovery_kit_is_non_secret_and_contains_checksums(case_dir: Path) -> None:
    _, backup = _backup(case_dir)
    extension = case_dir / "extension.zip"
    installer = case_dir / "installer.exe"
    extension.write_bytes(b"extension package")
    installer.write_bytes(b"installer package")
    kit = case_dir / "recovery-kit.json"

    result = write_recovery_kit(
        kit,
        backup=backup,
        extension_package=extension,
        installer_package=installer,
    )
    payload = json.loads(kit.read_text(encoding="utf-8"))
    encoded = json.dumps(payload, sort_keys=True).casefold()
    assert result["committed"] is True
    assert payload["format"] == "localgatekeys-recovery-kit"
    assert payload["safety"]["contains_passwords"] is False
    assert MASTER.casefold() not in encoded
    assert BACKUP_PASSWORD.casefold() not in encoded
    assert {item["role"] for item in payload["files"]} == {
        "encrypted-full-backup-v2", "sha256-manifest", "browser-extension-package", "installer-package",
    }


def test_rotation_is_non_mutating_until_confirmed(case_dir: Path) -> None:
    root = case_dir / "backups"
    root.mkdir()
    for name in ("one.lgk", "two.lgk", "three.lgk"):
        (root / name).write_bytes(name.encode())
    orphan = root / "orphan.lgk.sha256.json"
    orphan.write_text("{}", encoding="utf-8")

    plan = plan_backup_rotation(root, keep=1)
    assert plan["dry_run"] is True
    assert set(plan["remove"]) == {"two.lgk", "one.lgk"} or set(plan["remove"]) == {"three.lgk", "two.lgk"}
    assert plan["orphan_manifests"] == [orphan.name]
    assert all(path.exists() for path in root.iterdir())
