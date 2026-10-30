from __future__ import annotations

import shutil
import uuid
import zipfile
from pathlib import Path

import pytest

import localvault.backup as backup_module
from localvault.attachments import DocumentService
from localvault.backup import (
    BackupCancelled,
    BackupError,
    export_full_backup,
    restore_full_backup,
)
from localvault.config import atomic_write_json
from localvault.settings import SETTINGS_VERSION
from localvault.vault import create_vault, unlock_vault

MASTER = "synthetic backup master password"
BACKUP_PASSWORD = "synthetic backup container password"
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}


@pytest.fixture
def case_dir(request: pytest.FixtureRequest) -> Path:
    root = Path(__file__).parents[1] / ".m3-focused" / f"backup-{request.node.name}-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _profile(profile: Path, marker: bytes = b"synthetic attachment") -> tuple[Path, str, bytes]:
    profile.mkdir(parents=True)
    session = create_vault(profile / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    atomic_write_json(profile / "settings.json", {})
    fixture = profile / "fixture.txt"
    fixture.write_bytes(marker)
    item_id = DocumentService(session).create(fixture, title="Synthetic document", mime_type="text/plain")
    session.lock()
    return profile, item_id, marker


def _export(case_dir: Path, profile: Path) -> Path:
    backup = case_dir / "profile.lgk"
    export_full_backup(
        backup,
        profile_dir=profile,
        profile_name="Synthetic profile",
        backup_password=BACKUP_PASSWORD,
    )
    return backup


def _rewrite_archive(source: Path, destination: Path, mutate=None, *, extra=None, duplicate=False) -> None:
    with zipfile.ZipFile(source, "r") as source_zip, zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_STORED, allowZip64=True
    ) as destination_zip:
        for info in source_zip.infolist():
            data = source_zip.read(info)
            if mutate is not None:
                data = mutate(info.filename, data)
            destination_zip.writestr(info, data)
        if duplicate:
            info = source_zip.infolist()[0]
            destination_zip.writestr(info, source_zip.read(info))
        if extra is not None:
            destination_zip.writestr(extra, b"synthetic")


def _restore(source: Path, destination: Path, **kwargs):
    return restore_full_backup(
        source,
        profile_dir=destination,
        backup_password=BACKUP_PASSWORD,
        vault_password=MASTER,
        **kwargs,
    )


def test_v2_round_trip_sidecars_and_dry_run(case_dir: Path) -> None:
    profile, item_id, marker = _profile(case_dir / "source")
    backup = _export(case_dir, profile)
    restored = case_dir / "restored"

    dry_run_info = _restore(backup, restored, dry_run=True)
    assert dry_run_info["version"] == 2
    assert dry_run_info["dry_run"] is True
    assert not restored.exists()

    info = _restore(backup, restored)
    assert info["verified_vault"] is True
    assert info["attachments"] == 1
    restored_session = unlock_vault(restored / "vault.json", MASTER)
    try:
        assert DocumentService(restored_session).read(item_id) == marker
    finally:
        restored_session.lock()


def test_v2_wrong_password_tamper_and_sidecar_corruption_are_rejected_atomically(case_dir: Path) -> None:
    profile, _, _ = _profile(case_dir / "source")
    backup = _export(case_dir, profile)

    wrong_destination = case_dir / "wrong-password"
    with pytest.raises(BackupError):
        restore_full_backup(
            backup,
            profile_dir=wrong_destination,
            backup_password="wrong synthetic password",
            vault_password=MASTER,
        )
    assert not wrong_destination.exists()

    wrong_master_destination = case_dir / "wrong-master"
    with pytest.raises(BackupError):
        restore_full_backup(
            backup,
            profile_dir=wrong_master_destination,
            backup_password=BACKUP_PASSWORD,
            vault_password="wrong synthetic master password",
        )
    assert not wrong_master_destination.exists()

    tampered = case_dir / "tampered.lgk"

    def flip_data(name: str, data: bytes) -> bytes:
        if name.startswith("data/") and data:
            return data[:-1] + bytes([data[-1] ^ 1])
        return data

    _rewrite_archive(backup, tampered, mutate=flip_data)
    tampered_destination = case_dir / "tampered-restore"
    with pytest.raises(BackupError):
        _restore(tampered, tampered_destination)
    assert not tampered_destination.exists()

    corrupt_sidecar = case_dir / "corrupt-sidecar.lgk"
    sidecar = next((profile / "Attachments").glob("*.blob"))
    original_sidecar = sidecar.read_bytes()
    sidecar.write_bytes(original_sidecar[:-1] + bytes([original_sidecar[-1] ^ 1]))
    export_full_backup(
        corrupt_sidecar,
        profile_dir=profile,
        profile_name="Synthetic profile",
        backup_password=BACKUP_PASSWORD,
    )
    corrupt_destination = case_dir / "corrupt-restore"
    with pytest.raises(BackupError):
        _restore(corrupt_sidecar, corrupt_destination)
    assert not corrupt_destination.exists()


def test_v2_rejects_traversal_duplicate_members_and_archive_size_bound(case_dir: Path, monkeypatch) -> None:
    profile, _, _ = _profile(case_dir / "source")
    backup = _export(case_dir, profile)

    traversal = case_dir / "traversal.lgk"
    _rewrite_archive(backup, traversal, extra="../escape.bin")
    with pytest.raises(BackupError):
        restore_full_backup(
            traversal,
            profile_dir=case_dir / "traversal-restore",
            backup_password=BACKUP_PASSWORD,
            vault_password=MASTER,
        )

    duplicate = case_dir / "duplicate.lgk"
    _rewrite_archive(backup, duplicate, duplicate=True)
    with pytest.raises(BackupError):
        restore_full_backup(
            duplicate,
            profile_dir=case_dir / "duplicate-restore",
            backup_password=BACKUP_PASSWORD,
            vault_password=MASTER,
        )

    monkeypatch.setattr(backup_module, "MAX_FULL_BACKUP_BYTES", backup.stat().st_size - 1)
    with pytest.raises(BackupError, match="too large"):
        restore_full_backup(
            backup,
            profile_dir=case_dir / "oversized-restore",
            backup_password=BACKUP_PASSWORD,
            vault_password=MASTER,
        )


def test_v2_quota_cancellation_and_restore_atomicity(case_dir: Path) -> None:
    profile, _, _ = _profile(case_dir / "source")
    backup = _export(case_dir, profile)

    cancelled_export = case_dir / "cancelled-export.lgk"
    with pytest.raises(BackupCancelled):
        export_full_backup(
            cancelled_export,
            profile_dir=profile,
            profile_name="Synthetic profile",
            backup_password=BACKUP_PASSWORD,
            cancel=lambda: True,
        )
    assert not cancelled_export.exists()

    quota_destination = case_dir / "quota-restore"
    with pytest.raises(BackupError, match="quota"):
        _restore(backup, quota_destination, attachment_quota_bytes=1)
    assert not quota_destination.exists()

    cancelled_destination = case_dir / "cancelled-restore"
    with pytest.raises(BackupCancelled):
        _restore(backup, cancelled_destination, cancel=lambda: True)
    assert not cancelled_destination.exists()

    existing = case_dir / "existing"
    _profile(existing, marker=b"synthetic existing profile")
    before = {
        path.relative_to(existing): path.read_bytes()
        for path in existing.rglob("*")
        if path.is_file()
    }
    with pytest.raises(BackupError, match="already exists"):
        _restore(backup, existing)
    after = {
        path.relative_to(existing): path.read_bytes()
        for path in existing.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_v2_replace_rolls_back_when_publication_fails(case_dir: Path, monkeypatch) -> None:
    source, _, _ = _profile(case_dir / "source")
    backup = _export(case_dir, source)
    destination = case_dir / "replace-target"
    _profile(destination, marker=b"synthetic old profile")
    before = {
        path.relative_to(destination): path.read_bytes()
        for path in destination.rglob("*")
        if path.is_file()
    }

    real_replace = backup_module.os.replace

    def fail_first_publish(source_path: str | Path, destination_path: str | Path) -> None:
        source_path = Path(source_path)
        destination_path = Path(destination_path)
        if destination_path == destination / "vault.json" and source_path.parent.name.startswith(".lgk-full-restore-"):
            raise OSError("synthetic publication failure")
        real_replace(source_path, destination_path)

    monkeypatch.setattr(backup_module.os, "replace", fail_first_publish)
    with pytest.raises(BackupError, match="publish|restore"):
        _restore(backup, destination, replace=True, allow_rollback=True)

    after = {
        path.relative_to(destination): path.read_bytes()
        for path in destination.rglob("*")
        if path.is_file()
    }
    assert after == before


FAST_BACKUP_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}


def test_v2_kdf_header_uses_vault_defaults_and_accepts_only_bounded_parameters(case_dir: Path, monkeypatch) -> None:
    import json

    profile, _, _ = _profile(case_dir / "source")
    default = _export(case_dir, profile)
    with zipfile.ZipFile(default) as archive:
        header = json.loads(archive.read("header.json"))
    assert header["version"] == 2
    assert {key: header["kdf"][key] for key in ("name", "time_cost", "memory_cost_kib", "parallelism")} == {
        "name": "argon2id", "time_cost": 3, "memory_cost_kib": 65536, "parallelism": 4}

    fast = case_dir / "fast.lgk"
    export_full_backup(fast, profile_dir=profile, profile_name="Synthetic profile",
                       backup_password=BACKUP_PASSWORD, kdf_overrides=FAST_BACKUP_KDF)
    with zipfile.ZipFile(fast) as archive:
        fast_header = json.loads(archive.read("header.json"))
    assert fast_header["kdf"]["memory_cost_kib"] == 8192
    restored = _restore(fast, case_dir / "fast-restore")
    assert restored["verified_vault"] is True
    with pytest.raises(BackupError):
        export_full_backup(case_dir / "bad.lgk", profile_dir=profile, profile_name="Synthetic profile",
                           backup_password=BACKUP_PASSWORD, kdf_overrides={**FAST_BACKUP_KDF, "memory_cost_kib": 4096})

    def rewrite(bad: dict) -> Path:
        destination = case_dir / f"mutated-{uuid.uuid4().hex}.lgk"

        def mutate(name: str, data: bytes) -> bytes:
            if name == "header.json":
                value = json.loads(data)
                value["kdf"] = {**value["kdf"], **bad}
                return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
            return data

        _rewrite_archive(fast, destination, mutate=mutate)
        return destination

    def refuse(*_args, **_kwargs):
        raise AssertionError("KDF must not run for out-of-range parameters")

    monkeypatch.setattr(backup_module, "hash_secret_raw", refuse)
    for bad in ({"memory_cost_kib": 4096}, {"memory_cost_kib": 1024 * 1024}, {"time_cost": 0},
                {"time_cost": 11}, {"parallelism": 0}, {"parallelism": 17}, {"time_cost": True}):
        with pytest.raises(BackupError):
            _restore(rewrite(bad), case_dir / f"bad-{uuid.uuid4().hex}")
    monkeypatch.undo()
    with pytest.raises(BackupError):
        _restore(rewrite({"memory_cost_kib": 16384}), case_dir / "in-range-tamper")


def test_v2_full_backup_keeps_the_per_device_language_out(case_dir: Path) -> None:
    import json

    profile, _item_id, _marker = _profile(case_dir / "source")
    atomic_write_json(profile / "settings.json", {"version": SETTINGS_VERSION, "language": "de"})
    backup = _export(case_dir, profile)
    with zipfile.ZipFile(backup) as archive:
        settings_blobs = [archive.read(n) for n in archive.namelist() if n.endswith("settings.json")]
    if settings_blobs:
        assert all("language" not in json.loads(b) for b in settings_blobs)

    # Restoring a backup that carries a language keeps this device's choice.
    restored = case_dir / "restored"
    _restore(backup, restored)
    atomic_write_json(restored / "settings.json", {"version": SETTINGS_VERSION, "language": "fr"})
    _restore(backup, restored, replace=True, allow_rollback=True)
    assert json.loads((restored / "settings.json").read_text("utf-8"))["language"] == "fr"


def test_validated_full_settings_ignore_a_language_key() -> None:
    from localvault.backup import _full_validate_settings

    assert "language" not in _full_validate_settings({"version": SETTINGS_VERSION, "language": "ja"})
