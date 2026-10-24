"""Scheduled encrypted backups, their retention, and the mirror folder (non-GUI)."""
from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import localvault.backup as backup_module
from localvault import backup_schedule as bs
from localvault.config import atomic_write_json
from localvault.settings import AppSettings
from localvault.settings_ui import settings_candidate
from localvault.vault import VaultError, create_vault, unlock_vault

MASTER = "synthetic schedule master password"
BACKUP_PASSWORD = "synthetic scheduled backup password"
SECRET_MARKER = "synthetic-plaintext-marker-6c1f"
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
TAG = bs.profile_tag("profile-a")
OTHER_TAG = bs.profile_tag("profile-b")


@pytest.fixture(autouse=True)
def _fast_backup_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backup_module, "BACKUP_KDF", {**backup_module.BACKUP_KDF, "time_cost": 1,
                                                      "memory_cost_kib": 8192, "parallelism": 1})


def _fake_container(path: Path, marker: bytes = b"x") -> None:
    """A structurally valid encrypted container (opaque members) for retention tests."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("header.json", json.dumps({"format": "localgatekeys-full-backup", "version": 2}))
        archive.writestr("manifest.bin", os.urandom(32))
        archive.writestr("data/00000000.bin", os.urandom(16) + marker)


def _run(directory: Path, when: datetime, *, keep: int = 2, mirror_dir: str = "", log=None,
         make=None, verify=None) -> bs.RunResult:
    return bs.run_scheduled_backup(
        directory=directory, tag=TAG, keep=keep, when=when,
        make_backup=make or _fake_container, verify=verify or (lambda _path: None),
        mirror_dir=mirror_dir, log=log)


# --- schedule logic with an injected clock ------------------------------------

def test_daily_due_only_after_todays_time() -> None:
    yesterday_run = datetime(2026, 10, 14, 9, 0, 5)
    assert not bs.is_due(datetime(2026, 10, 15, 8, 59), yesterday_run, "daily", "09:00")
    assert bs.is_due(datetime(2026, 10, 15, 9, 0), yesterday_run, "daily", "09:00")
    assert bs.is_due(datetime(2026, 10, 15, 23, 0), yesterday_run, "daily", "09:00")
    assert not bs.is_due(datetime(2026, 10, 15, 23, 0), datetime(2026, 10, 15, 9, 1), "daily", "09:00")


def test_weekly_uses_weekday_and_time() -> None:
    # 2026-10-15 is a Thursday (weekday 3).
    last = datetime(2026, 10, 8, 18, 30)  # previous Thursday's run
    assert bs.latest_slot(datetime(2026, 10, 15, 18, 0), "weekly", "18:30", 3) == datetime(2026, 10, 8, 18, 30)
    assert not bs.is_due(datetime(2026, 10, 15, 18, 29), last, "weekly", "18:30", 3)
    assert bs.is_due(datetime(2026, 10, 15, 18, 30), last, "weekly", "18:30", 3)
    # Monday schedule seen on Thursday: the slot was this week's Monday.
    assert bs.latest_slot(datetime(2026, 10, 15, 12, 0), "weekly", "07:00", 0) == datetime(2026, 10, 12, 7, 0)


def test_off_is_never_due_and_first_enable_runs_once() -> None:
    assert not bs.is_due(datetime(2026, 10, 15, 12), None, "off", "09:00")
    assert bs.is_due(datetime(2026, 10, 15, 12), None, "daily", "09:00")


def test_missed_runs_catch_up_once(workspace_tmp: Path) -> None:
    directory = workspace_tmp / "Scheduled"
    bs.write_last_success(directory, datetime(2026, 10, 9, 9, 0))  # app closed for six days
    now = datetime(2026, 10, 15, 14, 0)
    assert bs.is_due(now, bs.read_last_success(directory), "daily", "09:00")
    _run(directory, now)
    later = now + timedelta(hours=3)
    assert not bs.is_due(later, bs.read_last_success(directory), "daily", "09:00")
    assert len(bs.owned_backups(directory, TAG)) == 1


def test_no_duplicate_after_restart(workspace_tmp: Path) -> None:
    directory = workspace_tmp / "Scheduled"
    now = datetime(2026, 10, 15, 9, 0, 30)
    _run(directory, now)
    # A fresh process only has the persisted state file.
    restarted_view = bs.read_last_success(directory)
    assert restarted_view is not None
    assert not bs.is_due(datetime(2026, 10, 15, 9, 5), restarted_view, "daily", "09:00")
    assert bs.is_due(datetime(2026, 10, 16, 9, 0), restarted_view, "daily", "09:00")


def test_clock_moved_back_does_not_block_backups() -> None:
    assert bs.is_due(datetime(2026, 10, 15, 12), datetime(2027, 1, 1), "daily", "09:00")


def test_corrupt_state_counts_as_never_run(workspace_tmp: Path) -> None:
    workspace_tmp.joinpath(bs.STATE_FILENAME).write_text("{not json", encoding="utf-8")
    assert bs.read_last_success(workspace_tmp) is None


# --- retention and safe replacement -------------------------------------------

@pytest.mark.parametrize("keep", [1, 2])
def test_retention_keeps_requested_count(workspace_tmp: Path, keep: int) -> None:
    start = datetime(2026, 10, 1, 9, 0)
    paths = [_run(workspace_tmp, start + timedelta(days=day), keep=keep).path for day in range(4)]
    remaining = bs.owned_backups(workspace_tmp, TAG)
    assert remaining == list(reversed(paths))[:keep]


def test_failed_backup_keeps_existing_good_one(workspace_tmp: Path) -> None:
    good = _run(workspace_tmp, datetime(2026, 10, 14, 9), keep=1).path
    before = bs.read_last_success(workspace_tmp)

    def broken(path: Path) -> None:
        path.write_bytes(b"partial")
        raise OSError("disk full")

    with pytest.raises(bs.ScheduleError):
        _run(workspace_tmp, datetime(2026, 10, 15, 9), keep=1, make=broken)
    assert bs.owned_backups(workspace_tmp, TAG) == [good]
    assert bs.read_last_success(workspace_tmp) == before
    assert not list(workspace_tmp.glob(".lgk-scheduled-*"))


def test_failed_verification_keeps_existing_good_one(workspace_tmp: Path) -> None:
    good = _run(workspace_tmp, datetime(2026, 10, 14, 9), keep=1).path

    def reject(_path: Path) -> None:
        raise backup_module.BackupError("authentication failed")

    with pytest.raises(bs.ScheduleError):
        _run(workspace_tmp, datetime(2026, 10, 15, 9), keep=1, verify=reject)
    assert bs.owned_backups(workspace_tmp, TAG) == [good]


def test_pruning_ignores_safety_backups_exports_and_foreign_files(workspace_tmp: Path) -> None:
    foreign = [
        "before-restore-1760000000000000000-42.lgk",
        "vault-1760000000000-abcdef.json",
        "LocalGateKeys-backup-2026-10-01-090000.lgk",
        "notes.lgk",
        f"LocalGateKeys-scheduled-{TAG}-20261001-090000.lgk.txt",
        bs.scheduled_filename(OTHER_TAG, datetime(2020, 1, 1)),
    ]
    for name in foreign:
        workspace_tmp.joinpath(name).write_bytes(b"keep me")
    for day in range(3):
        _run(workspace_tmp, datetime(2026, 10, 1 + day, 9), keep=1)
    for name in foreign:
        assert workspace_tmp.joinpath(name).read_bytes() == b"keep me"
    assert len(bs.owned_backups(workspace_tmp, TAG)) == 1


def test_new_backup_is_kept_even_if_clock_went_back(workspace_tmp: Path) -> None:
    _run(workspace_tmp, datetime(2026, 10, 20, 9), keep=1)
    newest = _run(workspace_tmp, datetime(2026, 10, 15, 9), keep=1).path
    assert bs.owned_backups(workspace_tmp, TAG) == [newest]


def test_same_second_runs_do_not_overwrite(workspace_tmp: Path) -> None:
    when = datetime(2026, 10, 15, 9)
    first = _run(workspace_tmp, when, keep=2).path
    second = _run(workspace_tmp, when, keep=2).path
    assert first != second and first.exists() and second.exists()


# --- mirror -------------------------------------------------------------------

def test_mirror_copy_and_retention(workspace_tmp: Path) -> None:
    local, mirror = workspace_tmp / "local", workspace_tmp / "cloud"
    mirror.mkdir()
    mirror.joinpath("holiday.jpg").write_bytes(b"user file")
    mirror.joinpath("before-restore-1-1.lgk").write_bytes(b"user file")
    results = [_run(local, datetime(2026, 10, 1 + day, 9), keep=2, mirror_dir=str(mirror)) for day in range(3)]
    assert all(r.mirror_warning == "" for r in results)
    mirrored = bs.owned_backups(mirror, TAG)
    assert [p.name for p in mirrored] == [p.name for p in bs.owned_backups(local, TAG)]
    assert len(mirrored) == 2
    assert mirrored[0].read_bytes() == results[-1].path.read_bytes()
    assert mirror.joinpath("holiday.jpg").read_bytes() == b"user file"
    assert mirror.joinpath("before-restore-1-1.lgk").exists()
    assert not list(mirror.glob(".lgk-*"))


def test_mirror_failure_is_swallowed_and_logged(workspace_tmp: Path) -> None:
    local = workspace_tmp / "local"
    logged: list[tuple[str, BaseException]] = []
    result = _run(local, datetime(2026, 10, 15, 9), mirror_dir=str(workspace_tmp / "offline-drive"),
                  log=lambda where, exc: logged.append((where, exc)))
    assert result.path is not None and result.path.exists()
    assert result.mirrored is None and "not available" in result.mirror_warning
    assert [where for where, _ in logged] == ["backup-mirror"]
    assert bs.read_last_success(local) == datetime(2026, 10, 15, 9)


def test_mirror_copy_error_is_swallowed(workspace_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    local, mirror = workspace_tmp / "local", workspace_tmp / "cloud"
    mirror.mkdir()
    previous = _run(local, datetime(2026, 10, 14, 9), mirror_dir=str(mirror)).path

    def denied(*_args, **_kwargs):
        raise PermissionError("access denied")

    monkeypatch.setattr(bs.shutil, "copyfileobj", denied)
    logged: list[str] = []
    result = _run(local, datetime(2026, 10, 15, 9), mirror_dir=str(mirror),
                  log=lambda where, _exc: logged.append(where))
    assert result.path.exists() and result.mirror_warning
    assert logged == ["backup-mirror"]
    # The earlier mirror copy is untouched and no temp file is left behind.
    assert [p.name for p in bs.owned_backups(mirror, TAG)] == [previous.name]
    assert not list(mirror.glob(".lgk-*"))


def test_mirror_refuses_plaintext_even_with_backup_name(workspace_tmp: Path) -> None:
    local, mirror = workspace_tmp / "local", workspace_tmp / "cloud"
    local.mkdir()
    mirror.mkdir()
    fake = local / bs.scheduled_filename(TAG, datetime(2026, 10, 15, 9))
    fake.write_text(json.dumps({"entries": [{"password": SECRET_MARKER}]}), encoding="utf-8")
    with pytest.raises(bs.MirrorError):
        bs.mirror_backup(fake, mirror, tag=TAG, keep=2)
    vault_like = local / "vault.json"
    vault_like.write_text("{}", encoding="utf-8")
    with pytest.raises(bs.MirrorError):
        bs.mirror_backup(vault_like, mirror, tag=TAG, keep=2)
    assert list(mirror.iterdir()) == []


def test_mirror_same_folder_as_local_is_rejected(workspace_tmp: Path) -> None:
    result = _run(workspace_tmp, datetime(2026, 10, 15, 9), mirror_dir=str(workspace_tmp))
    assert result.path.exists() and result.mirror_warning


# --- real encrypted backups end to end ----------------------------------------

def _profile(root: Path) -> Path:
    profile = root / "profile"
    profile.mkdir(parents=True)
    session = create_vault(profile / "vault.json", MASTER, kdf_overrides=TEST_KDF)
    session.upsert_web(origin="https://example.test", username="synthetic-user", password=SECRET_MARKER)
    session.set_scheduled_backup_password(BACKUP_PASSWORD)
    session.lock()
    atomic_write_json(profile / "settings.json", {})
    return profile


def test_full_backup_is_encrypted_restorable_and_mirrored_without_plaintext(workspace_tmp: Path) -> None:
    profile = _profile(workspace_tmp)
    mirror = workspace_tmp / "cloud"
    mirror.mkdir()
    make, verify = bs.full_backup_functions(profile_dir=profile, profile_name="Synthetic",
                                            backup_password=BACKUP_PASSWORD)
    result = bs.run_scheduled_backup(directory=profile / "Backups" / bs.SCHEDULED_DIR_NAME, tag=TAG, keep=2,
                                     when=datetime(2026, 10, 15, 9), make_backup=make, verify=verify,
                                     mirror_dir=str(mirror))
    assert result.mirrored is not None and result.mirror_warning == ""
    assert [p.suffix for p in mirror.iterdir()] == [".lgk"]
    data = result.mirrored.read_bytes()
    for plaintext in (SECRET_MARKER.encode(), BACKUP_PASSWORD.encode(), b"example.test", b"synthetic-user",
                      (profile / "vault.json").read_bytes()[:64]):
        assert plaintext not in data
    checked = backup_module.preflight_full_backup(
        result.mirrored, profile_dir=workspace_tmp / "probe" / "profile", backup_password=BACKUP_PASSWORD)
    assert checked
    # The verify probe directory is cleaned up.
    assert not list((profile / "Backups" / bs.SCHEDULED_DIR_NAME).glob(".lgk-*"))


# --- backup password lives inside the encrypted vault -------------------------

def test_backup_password_stored_only_in_encrypted_vault(workspace_tmp: Path) -> None:
    path = workspace_tmp / "vault.json"
    session = create_vault(path, MASTER, kdf_overrides=TEST_KDF)
    assert session.scheduled_backup_password() == ""
    with pytest.raises(VaultError):
        session.set_scheduled_backup_password("short")
    session.set_scheduled_backup_password(BACKUP_PASSWORD)
    assert BACKUP_PASSWORD.encode() not in path.read_bytes()
    session.lock()
    with pytest.raises(VaultError):
        session.scheduled_backup_password()
    reopened = unlock_vault(path, MASTER)
    assert reopened.scheduled_backup_password() == BACKUP_PASSWORD
    reopened.set_scheduled_backup_password(None)
    assert not reopened.has_scheduled_backup_password()
    reopened.lock()
    assert not unlock_vault(path, MASTER).has_scheduled_backup_password()


# --- settings -----------------------------------------------------------------

def test_schedule_settings_default_off_and_round_trip(workspace_tmp: Path) -> None:
    defaults = AppSettings()
    assert (defaults.scheduled_backup_frequency, defaults.scheduled_backup_keep, defaults.backup_mirror_dir) == \
        ("off", 2, "")
    path = workspace_tmp / "settings.json"
    path.write_text('{"version":5,"auto_lock_seconds":420}', encoding="utf-8")
    assert AppSettings.load(path).scheduled_backup_frequency == "off"
    mirror = str(workspace_tmp / "cloud")
    AppSettings(scheduled_backup_frequency="weekly", scheduled_backup_time="07:45", scheduled_backup_weekday=4,
                scheduled_backup_keep=1, backup_mirror_dir=mirror).save(path)
    loaded = AppSettings.load(path)
    assert (loaded.scheduled_backup_frequency, loaded.scheduled_backup_time, loaded.scheduled_backup_weekday,
            loaded.scheduled_backup_keep, loaded.backup_mirror_dir) == ("weekly", "07:45", 4, 1, mirror)
    assert "backup_password" not in path.read_text(encoding="utf-8")


def test_invalid_schedule_settings_fall_back(workspace_tmp: Path) -> None:
    path = workspace_tmp / "settings.json"
    path.write_text(json.dumps({
        "version": 5, "scheduled_backup_frequency": "hourly", "scheduled_backup_time": "25:00",
        "scheduled_backup_weekday": 9, "scheduled_backup_keep": True,
        "backup_mirror_dir": "https://cloud.example/upload"}), encoding="utf-8")
    loaded = AppSettings.load(path)
    assert loaded.scheduled_backup_frequency == "off"
    assert loaded.scheduled_backup_time == bs.DEFAULT_TIME
    assert loaded.scheduled_backup_weekday == 6
    assert loaded.scheduled_backup_keep == 2
    assert loaded.backup_mirror_dir == ""


def test_settings_draft_validates_schedule_fields() -> None:
    base = AppSettings()
    candidate = settings_candidate(base, {"scheduled_backup_frequency": "daily", "scheduled_backup_time": "7:05",
                                          "scheduled_backup_keep": 1})
    assert (candidate.scheduled_backup_time, candidate.scheduled_backup_keep) == ("07:05", 1)
    with pytest.raises(ValueError):
        settings_candidate(base, {"scheduled_backup_time": "7pm"})
    with pytest.raises(ValueError):
        settings_candidate(base, {"scheduled_backup_keep": 3})
    with pytest.raises(ValueError):
        settings_candidate(base, {"backup_mirror_dir": "relative/folder"})


