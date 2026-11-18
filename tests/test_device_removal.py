"""Erase on a verified sync removal (WP-A): device_erase and app.device_removal.RemovalGuard."""
from __future__ import annotations

import os
import shutil
import stat
import threading
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_sync_folder_transport as ftt
from test_sync_folder_transport import CHEAP, NOW, PW2, _group

import localvault.backup as backup_module
from localvault import backup_schedule as bs
from localvault import device_erase
from localvault.app.device_removal import RemovalGuard
from localvault.config import atomic_write_json, data_dir
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from localvault.sync import folder_transport as ft
from localvault.sync import removal
from localvault.vault import create_vault, unlock_vault

root = ftt.root  # the fixture


def _profile_with_files(manager: ProfileManager, name: str) -> tuple[str, Path]:
    record = manager.create_profile(name)
    folder = manager.profile_dir(record.id)
    (folder / "vault.json").write_bytes(b"encrypted vault" * 100)
    (folder / "vault.hello.json").write_text('{"id": "hello-record-1"}', encoding="utf-8")
    (folder / "vault.face.json").write_bytes(b"camera sidecar")
    (folder / "Backups").mkdir()
    (folder / "Backups" / "before.json").write_bytes(b"backup")
    locked = folder / "Attachments" / "blob.bin"
    locked.parent.mkdir()
    locked.write_bytes(b"x" * 10)
    os.chmod(locked, stat.S_IREAD)
    return record.id, folder


def test_erase_profile_overwrites_and_removes_everything(tmp_path: Path) -> None:
    manager = ProfileManager(tmp_path / "data")
    keep_id, keep_dir = _profile_with_files(manager, "Keep")
    gone_id, gone_dir = _profile_with_files(manager, "Gone")
    manager.set_active(gone_id)
    deleted: list[str] = []
    left = device_erase.erase_profile(manager, gone_id, delete_hello_key=deleted.append, now=lambda: 1234)
    assert left == []
    assert not gone_dir.exists() and keep_dir.is_dir()
    assert not (tmp_path / "data" / "DeletedProfiles").exists()  # not an archive
    assert deleted == ["hello-record-1"]
    assert [p.id for p in manager.list_profiles()] == [keep_id]
    assert manager.active_profile().id == keep_id
    assert device_erase.erased_notice() == {"erased_at": 1234}
    device_erase.dismiss_erased_notice()
    assert device_erase.erased_notice() is None


def test_erasing_the_only_profile_leaves_no_active_profile(tmp_path: Path) -> None:
    manager = ProfileManager(tmp_path / "data")
    only, folder = _profile_with_files(manager, "Only")
    manager.set_active(only)
    device_erase.erase_profile(manager, only, delete_hello_key=lambda _r: None)
    assert manager.list_profiles() == [] and manager.active_profile() is None
    device_erase.dismiss_erased_notice()


def test_a_file_that_cannot_go_keeps_the_row_and_the_watch_file(tmp_path: Path, monkeypatch) -> None:
    manager = ProfileManager(tmp_path / "data")
    pid, folder = _profile_with_files(manager, "Busy")
    watch = removal.watch_path(folder / "vault.json")
    watch.write_text("{}", encoding="utf-8")
    real = device_erase._overwrite_and_delete

    def busy(path: Path) -> None:
        if path.name == "vault.json":
            raise PermissionError("in use")
        real(path)

    monkeypatch.setattr(device_erase, "_overwrite_and_delete", busy)
    left = device_erase.erase_profile(manager, pid, delete_hello_key=lambda _r: None)
    assert left == [str(folder / "vault.json")]
    assert watch.is_file() and pid in {p.id for p in manager.list_profiles()}
    assert device_erase.erased_notice() is None
    monkeypatch.setattr(device_erase, "_overwrite_and_delete", real)
    assert device_erase.erase_profile(manager, pid, delete_hello_key=lambda _r: None) == []
    assert not folder.exists() and pid not in {p.id for p in manager.list_profiles()}
    device_erase.dismiss_erased_notice()


def test_overwrite_happens_before_delete(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "secret.bin"
    target.write_bytes(b"A" * 5000)
    seen: list[bytes] = []
    real_unlink = Path.unlink

    def spy(self: Path, *args, **kwargs):
        if self == target:
            seen.append(self.read_bytes())
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", spy)
    assert device_erase.erase_tree(tmp_path) == []
    assert seen and len(seen[0]) == 5000 and seen[0] != b"A" * 5000


# --- RemovalGuard ---------------------------------------------------------------------------------


class FakeController:
    def __init__(self, profiles: ProfileManager, *, erase: bool = True, unlocked_id: str | None = None) -> None:
        self.profiles = profiles
        self.settings = AppSettings(erase_on_sync_removal=erase)
        self._lock = threading.RLock()
        self._unlocking = False
        self._extras_cache = None
        self.unlocked_id = unlocked_id
        self.events: list[str] = []
        self.guard = SimpleNamespace(invalidate=lambda pid=None: self.events.append(f"invalidate:{pid}"))

    def is_unlocked(self) -> bool:
        return self.unlocked_id is not None

    def lock(self) -> None:
        self.events.append("lock")
        self.unlocked_id = None

    def _publish(self) -> None:
        self.events.append("publish")


def _removed_profile(tmp_path: Path, root: Path) -> tuple[ProfileManager, str, str]:
    """A profile whose watch file is C's, after A removed C from the group (a real signed notice)."""
    a, b, c = _group(tmp_path, root)
    watch = removal.watch_path(c.session.path)
    ft.rotate_folder_group(root, a.session, a.lease, PW2, remove=[c.device_id], install_id=a.install, now=NOW,
                           _kdf_override=CHEAP)
    manager = ProfileManager(tmp_path / "data")
    pid, folder = _profile_with_files(manager, "Removed")
    manager.create_profile("Other")
    shutil.copy(watch, removal.watch_path(folder / "vault.json"))
    return manager, pid, c.install


def test_guard_erases_a_profile_with_a_verified_notice(tmp_path: Path, root: Path) -> None:
    manager, pid, install = _removed_profile(tmp_path, root)
    manager.set_active(pid)
    controller = FakeController(manager, unlocked_id=pid)
    erased: list[str] = []

    def erase(profiles, profile_id):
        erased.append(profile_id)
        return device_erase.erase_profile(profiles, profile_id, delete_hello_key=lambda _r: None)

    guard = RemovalGuard(controller, install_id=lambda: install, erase=erase)
    assert guard.check() == [pid]
    assert erased == [pid] and controller.events[0] == "lock" and "publish" in controller.events
    assert pid not in {p.id for p in manager.list_profiles()}
    assert guard.check() == []  # nothing left to erase
    device_erase.dismiss_erased_notice()


def test_guard_does_nothing_with_the_setting_off_or_another_install(tmp_path: Path, root: Path) -> None:
    manager, pid, install = _removed_profile(tmp_path, root)
    off = RemovalGuard(FakeController(manager, erase=False), install_id=lambda: install,
                       erase=lambda *a: (_ for _ in ()).throw(AssertionError("must not erase")))
    assert off.check() == []
    other = RemovalGuard(FakeController(manager), install_id=lambda: "another-pc",
                         erase=lambda *a: (_ for _ in ()).throw(AssertionError("must not erase")))
    assert other.check() == []
    assert pid in {p.id for p in manager.list_profiles()}


def test_guard_ignores_a_profile_whose_folder_has_no_notice(tmp_path: Path, root: Path) -> None:
    manager, pid, install = _removed_profile(tmp_path, root)
    notice = root / ft.SYNC_DIR_NAME / removal.REMOVED_DIR_NAME
    shutil.rmtree(notice)
    guard = RemovalGuard(FakeController(manager), install_id=lambda: install,
                         erase=lambda *a: (_ for _ in ()).throw(AssertionError("must not erase")))
    assert guard.check() == []


def test_erase_setting_defaults_on_and_round_trips(tmp_path: Path) -> None:
    assert AppSettings().erase_on_sync_removal is True
    path = tmp_path / "settings.json"
    AppSettings(erase_on_sync_removal=False).save(path)
    assert AppSettings.load(path).erase_on_sync_removal is False


def test_controller_state_carries_the_erased_notice_until_dismissed(tmp_path: Path) -> None:
    from localvault.app.controller import WebController

    events: list[tuple[str, dict]] = []
    bus = SimpleNamespace(emit=lambda name, payload: events.append((name, payload)))
    controller = WebController(profiles=ProfileManager(tmp_path / "data"), settings=AppSettings(), bus=bus)
    assert controller.state()["erased"] is None
    manager = controller.profiles
    pid, _folder = _profile_with_files(manager, "Gone")
    device_erase.erase_profile(manager, pid, delete_hello_key=lambda _r: None, now=lambda: 99)
    state = controller.state()
    assert state["state"] == "no_profile" and state["erased"] == {"erased_at": 99}
    assert controller.dismiss_erased_notice()["erased"] is None
    assert events[-1][0] == "vault.state"


# --- kept scheduled backups (owner decision 2026-10-31) -------------------------------------------

MASTER = "synthetic erase master password"
BACKUP_PASSWORD = "synthetic erase backup password"
SECRET = "synthetic-erase-marker-41d2"
FAST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
WHEN = datetime(2026, 10, 31, 12).timestamp()


@pytest.fixture
def fast_backup_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backup_module, "BACKUP_KDF", {**backup_module.BACKUP_KDF, "time_cost": 1,
                                                      "memory_cost_kib": 8192, "parallelism": 1})


def _vault_with_scheduled_backup(manager: ProfileManager, name: str) -> tuple[str, Path, Path]:
    """A real vault with one real scheduled backup, safety copies, a rolling copy and look-alikes."""
    record = manager.create_profile(name)
    folder = manager.profile_dir(record.id)
    session = create_vault(folder / "vault.json", MASTER, kdf_overrides=FAST_KDF)
    session.upsert_web(origin="https://example.test", username="synthetic-user", password=SECRET)
    from localvault.backup_key import build_record, derive_backup_key, new_kdf

    key = derive_backup_key(BACKUP_PASSWORD, new_kdf(parameters=backup_module.BACKUP_KDF))
    backup_record = build_record(key, now=1793000000, set_by="set", reset_authority=None)
    key.wipe()
    session.set_scheduled_backup_key(backup_record)
    session.lock()
    atomic_write_json(folder / "settings.json", {})
    scheduled = folder / "Backups" / bs.SCHEDULED_DIR_NAME
    tag = bs.profile_tag(record.id)
    make, verify = bs.full_backup_functions(profile_dir=folder, profile_name=name, record=backup_record)
    made = bs.run_scheduled_backup(directory=scheduled, tag=tag, keep=2, when=datetime(2026, 10, 30, 9),
                                   make_backup=make, verify=verify).path
    assert made is not None
    # Protected by the master password alone: erased.
    shutil.copy(folder / "vault.json", folder / "Backups" / "before-restore-1.json")
    shutil.copy(made, folder / "Backups" / "before-restore-2-3.lgk")
    shutil.copy(folder / "vault.json", folder / "Backups" / "vault-20261030-090000.json")
    # Named like a scheduled backup but not an encrypted container, and another profile's tag: both erased.
    (scheduled / bs.scheduled_filename(tag, datetime(2026, 10, 29, 9))).write_bytes(b"plain")
    shutil.copy(made, scheduled / bs.scheduled_filename(bs.profile_tag("someone-else"), datetime(2026, 10, 29, 9)))
    return record.id, folder, made


def test_erase_keeps_scheduled_backups_and_erases_the_rest(tmp_path: Path, fast_backup_kdf) -> None:
    manager = ProfileManager(tmp_path / "data")
    pid, folder, made = _vault_with_scheduled_backup(manager, "Work")
    mirror = tmp_path / "cloud"
    mirror.mkdir()
    outside = Path(shutil.copy(made, mirror / made.name))  # outside the profile (a mirror): untouched
    before = outside.read_bytes()
    left = device_erase.erase_profile(manager, pid, delete_hello_key=lambda _r: None, now=lambda: WHEN)
    assert left == [] and not folder.exists()
    kept = data_dir() / "Kept backups" / "Work 2026-10-31"
    try:
        assert sorted(p.name for p in kept.iterdir()) == [made.name]  # only the real scheduled backup moved
        assert outside.read_bytes() == before and sorted(p.name for p in mirror.iterdir()) == [made.name]
        assert device_erase.erased_notice() == {"erased_at": int(WHEN), "kept_folders": [str(kept)]}
        assert not list(data_dir().glob("erase-kept-*.json"))
        # Restoring needs the backup password and the master password.
        with pytest.raises(Exception):  # noqa: B017 - any refusal
            backup_module.restore_full_backup(kept / made.name, profile_dir=tmp_path / "wrong1",
                                              backup_password="not the backup password")
        with pytest.raises(Exception):  # noqa: B017
            backup_module.restore_full_backup(kept / made.name, profile_dir=tmp_path / "wrong2",
                                              backup_password=BACKUP_PASSWORD, vault_password="not the master password",
                                              validate_vault_password=True)
        restored = tmp_path / "restored"
        backup_module.restore_full_backup(kept / made.name, profile_dir=restored, backup_password=BACKUP_PASSWORD,
                                          vault_password=MASTER, validate_vault_password=True)
        session = unlock_vault(restored / "vault.json", MASTER)
        assert SECRET.encode() not in (restored / "vault.json").read_bytes()
        assert session.scheduled_backup_key()["set_by"] == "set"  # only the public key record, in the vault
        session.lock()
    finally:
        device_erase.dismiss_erased_notice()
        shutil.rmtree(data_dir() / "Kept backups", ignore_errors=True)


def test_erase_keeps_old_v2_and_new_v3_scheduled_backups(tmp_path: Path, fast_backup_kdf) -> None:
    """A profile with one v2 (made before the public key) and one v3 scheduled backup: both are kept."""
    manager = ProfileManager(tmp_path / "data")
    pid, folder, v3 = _vault_with_scheduled_backup(manager, "Mixed")
    assert backup_module.describe_backup(v3)["version"] == 3
    v2 = folder / "Backups" / bs.SCHEDULED_DIR_NAME / bs.scheduled_filename(bs.profile_tag(pid),
                                                                              datetime(2026, 10, 28, 9))
    backup_module.export_full_backup(v2, profile_dir=folder, profile_name="Mixed", backup_password="old v2 password!")
    left = device_erase.erase_profile(manager, pid, delete_hello_key=lambda _r: None, now=lambda: WHEN)
    assert left == [] and not folder.exists()
    kept = data_dir() / "Kept backups" / "Mixed 2026-10-31"
    try:
        assert sorted(p.name for p in kept.iterdir()) == sorted([v3.name, v2.name])
        backup_module.preflight_full_backup(kept / v3.name, profile_dir=tmp_path / "p3" / "profile",
                                            backup_password=BACKUP_PASSWORD)
        backup_module.preflight_full_backup(kept / v2.name, profile_dir=tmp_path / "p2" / "profile",
                                            backup_password="old v2 password!")
    finally:
        device_erase.dismiss_erased_notice()
        shutil.rmtree(data_dir() / "Kept backups", ignore_errors=True)


def test_kept_folder_names_are_safe_and_unique(tmp_path: Path, fast_backup_kdf) -> None:
    manager = ProfileManager(tmp_path / "data")
    parent = data_dir() / "Kept backups"
    (parent / "A_B_C 2026-10-31").mkdir(parents=True)
    try:
        first, _f1, _m1 = _vault_with_scheduled_backup(manager, "A/B:C")
        second, _f2, _m2 = _vault_with_scheduled_backup(manager, "A?B*C")  # the same safe name
        assert device_erase.erase_profile(manager, first, delete_hello_key=lambda _r: None, now=lambda: WHEN) == []
        assert device_erase.erase_profile(manager, second, delete_hello_key=lambda _r: None, now=lambda: WHEN) == []
        two, three = parent / "A_B_C 2026-10-31 (2)", parent / "A_B_C 2026-10-31 (3)"
        assert len(list(two.iterdir())) == 1 and len(list(three.iterdir())) == 1
        assert list((parent / "A_B_C 2026-10-31").iterdir()) == []  # an existing folder is never reused
        # An unread notice keeps the folders of every erase.
        assert device_erase.erased_notice()["kept_folders"] == [str(two), str(three)]
    finally:
        device_erase.dismiss_erased_notice()
        shutil.rmtree(parent, ignore_errors=True)


def test_safe_folder_name() -> None:
    assert device_erase.safe_folder_name("Work") == "Work"
    assert device_erase.safe_folder_name('a<b>c:"d/e\\f|g?h*i') == "a_b_c__d_e_f_g_h_i"
    assert device_erase.safe_folder_name("  ...  ") == "Vault"
    assert device_erase.safe_folder_name("") == "Vault"
    assert device_erase.safe_folder_name("name. ") == "name"
    assert device_erase.safe_folder_name("CON") == "_CON"
    assert device_erase.safe_folder_name("lpt1.txt") == "_lpt1.txt"
    assert device_erase.safe_folder_name("x\x00y\x1f") == "x_y_"
    assert len(device_erase.safe_folder_name("z" * 300)) == 60


def test_a_retry_after_a_failed_erase_still_reports_the_kept_folder(tmp_path: Path, monkeypatch,
                                                                    fast_backup_kdf) -> None:
    manager = ProfileManager(tmp_path / "data")
    pid, _folder, made = _vault_with_scheduled_backup(manager, "Busy")
    real = device_erase._overwrite_and_delete

    def busy(path: Path) -> None:
        if path.name == "vault.json":
            raise PermissionError("in use")
        real(path)

    kept = data_dir() / "Kept backups" / "Busy 2026-10-31"
    try:
        monkeypatch.setattr(device_erase, "_overwrite_and_delete", busy)
        assert device_erase.erase_profile(manager, pid, delete_hello_key=lambda _r: None, now=lambda: WHEN)
        assert (kept / made.name).is_file() and device_erase.erased_notice() is None
        monkeypatch.setattr(device_erase, "_overwrite_and_delete", real)
        assert device_erase.erase_profile(manager, pid, delete_hello_key=lambda _r: None, now=lambda: WHEN) == []
        assert device_erase.erased_notice()["kept_folders"] == [str(kept)]
        assert not (data_dir() / "Kept backups" / "Busy 2026-10-31 (2)").exists()
        assert not list(data_dir().glob("erase-kept-*.json"))
    finally:
        device_erase.dismiss_erased_notice()
        shutil.rmtree(data_dir() / "Kept backups", ignore_errors=True)


def test_no_scheduled_backups_means_no_kept_folder(tmp_path: Path) -> None:
    manager = ProfileManager(tmp_path / "data")
    pid, _folder = _profile_with_files(manager, "Plain")
    assert device_erase.erase_profile(manager, pid, delete_hello_key=lambda _r: None, now=lambda: 5) == []
    assert device_erase.erased_notice() == {"erased_at": 5}
    assert not (data_dir() / "Kept backups").exists()
    device_erase.dismiss_erased_notice()


def test_erase_deletes_the_rollback_marks_of_the_vault_and_its_second_vault(tmp_path: Path, monkeypatch) -> None:
    from localvault import duress, vault

    manager = ProfileManager(tmp_path / "data")
    pid, _folder = _profile_with_files(manager, "Gone")
    folder = Path(manager.root) / "Profiles" / pid
    forgotten: list[Path] = []
    monkeypatch.setattr(vault, "forget_rollback_marks", lambda path: forgotten.append(Path(path)))
    device_erase.erase_profile(manager, pid, delete_hello_key=lambda _r: None)
    assert folder / "vault.json" in forgotten
    assert duress.decoy_path(folder / "vault.json") in forgotten
