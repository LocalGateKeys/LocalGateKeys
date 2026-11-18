"""Scheduled backups to a public key on Windows: migration, proof-gated key API, scheduler, restore texts.

Design ``docs/design/backup-public-key-2026-10-31.md`` section 14 (Windows items), hard rule 1.1 (old-format
backups are never touched) and owner decisions Q1-Q3.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from localvault import backup as backup_module
from localvault import backup_key_state as device
from localvault import backup_schedule as bs
from localvault.api.bridge import Api
from localvault.api.result import ApiError
from localvault.app.backup_keys import BackupKeyService
from localvault.app.controller import WebController
from localvault.app.recovery import RecoveryWebService, key_line_text
from localvault.app.schedule import ScheduleRunner
from localvault.app.settings import SettingsService
from localvault.backup import BackupError, export_full_backup, restore_full_backup
from localvault.backup_key import password_matches
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from localvault.vault import VaultError, unlock_vault
from localvault.web.ui_port import WebUiPort

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
CHEAP = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
MASTER = "synthetic master password 0451"
OLD = "synthetic old backup password"
NEW = "synthetic new backup password"
NOW = 1793000000


class Bus:
    def __init__(self) -> None:
        self.events: list = []

    def emit(self, name, detail):
        self.events.append((name, detail))


class Sched:
    def call_later(self, delay, fn):
        return None

    def cancel(self, handle):
        pass


class Port:
    def confirm(self, title, message):
        return True


@pytest.fixture(autouse=True)
def _cheap_backup_kdf(monkeypatch):
    monkeypatch.setattr(backup_module, "BACKUP_KDF", {**backup_module.BACKUP_KDF, **CHEAP})
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)


class Env(SimpleNamespace):
    @property
    def session(self):
        return self.controller.session

    @property
    def scheduled(self) -> Path:
        return Path(self.controller.profiles.backups_dir(self.profile.id)) / bs.SCHEDULED_DIR_NAME

    @property
    def profile_dir(self) -> Path:
        return Path(self.controller.profiles.profile_dir(self.profile.id))

    @property
    def tag(self) -> str:
        return bs.profile_tag(self.profile.id)


@pytest.fixture
def env(tmp_path):
    profiles = ProfileManager(tmp_path / "data")
    profile = profiles.ensure_profile()
    clock = [NOW]
    controller = WebController(profiles=profiles, settings=AppSettings(scheduled_backup_frequency="daily", idle_source="vault"),
                               bus=Bus(), scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    keys = BackupKeyService(controller, clock=lambda: clock[0], spawn=lambda fn: None)
    controller.create(MASTER, MASTER)
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    controller.settings.backup_mirror_dir = str(mirror)
    return Env(controller=controller, keys=keys, clock=clock, profile=profile, mirror=mirror, tmp=tmp_path)


def _plant_legacy_password(session, password: str = OLD) -> None:
    """What releases before the public key stored (``preferences.scheduled_backup_password``)."""
    session._require_payload().setdefault("preferences", {})["scheduled_backup_password"] = password
    session.save()


def _v2_scheduled(env, when: datetime, password: str = OLD) -> Path:
    env.scheduled.mkdir(parents=True, exist_ok=True)
    path = env.scheduled / bs.scheduled_filename(env.tag, when)
    export_full_backup(path, profile_dir=env.profile_dir, profile_name="Synthetic", backup_password=password,
                       kdf_overrides=CHEAP)
    return path


def _snapshot(*folders: Path) -> dict[str, tuple[bytes, int]]:
    out = {}
    for folder in folders:
        for path in sorted(folder.iterdir()):
            if path.is_file():
                out[str(path)] = (path.read_bytes(), path.stat().st_mtime_ns)
    return out


def _restores(path: Path, password: str, target: Path) -> bool:
    try:
        restore_full_backup(path, profile_dir=target, backup_password=password, vault_password=MASTER,
                            validate_vault_password=True)
    except BackupError:
        return False
    return True


def _v3_run(env, when: datetime, record=None) -> bs.RunResult:
    record = record or env.session.scheduled_backup_key()
    make, verify = bs.full_backup_functions(profile_dir=env.profile_dir, profile_name="Synthetic", record=record)
    try:
        return bs.run_scheduled_backup(directory=env.scheduled, tag=env.tag, keep=2, when=when, make_backup=make,
                                       verify=verify, mirror_dir=str(env.mirror),
                                       protect_old=env.keys.protected_names())
    finally:
        make.discard()


# --------------------------------------------------------------------------------------------- migration
def test_migration_moves_the_password_to_a_record_and_touches_no_backup_file(env, monkeypatch):
    _plant_legacy_password(env.session)
    old = _v2_scheduled(env, datetime(2026, 10, 30, 9))
    older = _v2_scheduled(env, datetime(2026, 10, 29, 9))
    shutil.copy2(old, env.mirror / old.name)
    before = _snapshot(env.scheduled, env.mirror)
    calls = []
    watched = (str(env.scheduled), str(env.mirror))

    def spy(name, real):
        def run(*args, **kwargs):
            if any(str(a).startswith(watched) for a in args):
                calls.append((name, args))
            return real(*args, **kwargs)
        return run

    monkeypatch.setattr(bs, "prune", lambda *a, **k: calls.append(("prune", a)))
    for name in ("unlink", "replace", "rename", "remove", "utime"):
        monkeypatch.setattr(os, name, spy(name, getattr(os, name)))
    monkeypatch.setattr(Path, "unlink", spy("Path.unlink", Path.unlink))
    assert env.session.scheduled_backup_migration_pending()
    record = env.keys.migrate(env.session)
    monkeypatch.undo()
    assert calls == []
    assert _snapshot(env.scheduled, env.mirror) == before  # same names, count, bytes and mtimes
    assert record["set_by"] == "migrated" and record["set_at"] == NOW and record["reset_authority"] is None
    assert password_matches(record, OLD)
    prefs = env.session._require_payload()["preferences"]
    assert "scheduled_backup_password" not in prefs and prefs["scheduled_backup_key"] == record
    assert OLD.encode() not in (env.profile_dir / "vault.json").read_bytes()
    reopened = unlock_vault(env.profile_dir / "vault.json", MASTER)
    assert reopened.scheduled_backup_key() == record and not reopened.scheduled_backup_migration_pending()
    reopened.lock()
    state = device.load(env.profile_dir)
    assert (state.seen_key_id, state.seen_set_at) == (record["key_id"], NOW)
    assert state.protect_old == (old.name,)  # Q3: the newest old backup (its mirror copy has the same name)
    assert env.keys.migrate(env.session) is None  # idempotent
    # The old v2 backups still restore with the old password and the master password.
    assert _restores(old, OLD, env.tmp / "r1") and _restores(older, OLD, env.tmp / "r2")


def test_migration_captures_the_recovery_phrase_authority(env):
    env.session.create_recovery_phrase(MASTER)
    _plant_legacy_password(env.session)
    record = env.keys.migrate(env.session)
    assert record["reset_authority"]["kind"] == "recovery-wrapper-v1"


def test_migration_save_failure_keeps_the_password_and_skips_this_session(env, monkeypatch):
    _plant_legacy_password(env.session)

    def boom():
        raise VaultError("disk full")

    monkeypatch.setattr(env.session, "save", boom)
    assert env.keys.migrate(env.session) is None
    prefs = env.session._require_payload()["preferences"]
    assert prefs["scheduled_backup_password"] == OLD and "scheduled_backup_key" not in prefs
    assert env.keys.schedule_record() == ("failed", None)
    monkeypatch.undo()
    env.keys._failed = None  # the next unlock retries
    assert env.keys.migrate(env.session)["set_by"] == "migrated"
    assert env.keys.schedule_record()[0] == "ok"


def test_migration_after_a_newer_key_was_seen_pauses(env):
    device.save(env.profile_dir, device.DeviceKeyState(seen_key_id="ab" * 16, seen_set_at=NOW + 50))
    _plant_legacy_password(env.session)
    record = env.keys.migrate(env.session)
    assert env.keys.schedule_record() == ("paused", None)
    env.keys.confirm(OLD)
    assert env.keys.schedule_record() == ("ok", record)


def test_scheduler_waits_while_the_migration_runs(env):
    _plant_legacy_password(env.session)
    runner = ScheduleRunner(env.controller, env.controller._bus, spawn=lambda fn: fn(), keys=env.keys,
                            run_backup=lambda **job: pytest.fail("no backup during migration"))
    assert runner.check() is False
    assert not [e for e in env.controller._bus.events if e[0] == "toast"]


# --------------------------------------------------------------------------------------------- scheduler
def test_scheduled_v3_backup_prunes_by_name_and_keeps_the_protected_old_one(env):
    _plant_legacy_password(env.session)
    old = [_v2_scheduled(env, datetime(2026, 10, day, 9)) for day in (27, 28)]
    env.keys.migrate(env.session)
    assert env.keys.protected_names() == (old[1].name,)
    first = _v3_run(env, datetime(2026, 10, 31, 9))
    # keep=2 counts old and new files together by name; the protected one is not counted and never removed.
    assert sorted(p.name for p in bs.owned_backups(env.scheduled, env.tag)) == sorted([old[1].name, old[0].name,
                                                                                         first.path.name])
    second = _v3_run(env, datetime(2026, 11, 1, 9))
    third = _v3_run(env, datetime(2026, 11, 2, 9))
    names = {p.name for p in bs.owned_backups(env.scheduled, env.tag)}
    assert names == {old[1].name, second.path.name, third.path.name}
    assert old[1].exists() and not old[0].exists()
    state = (env.scheduled / bs.STATE_FILENAME).read_text()
    assert hashlib.sha256(third.path.read_bytes()).hexdigest() in state
    assert third.mirrored is not None and (env.mirror / third.path.name).exists()
    assert _restores(third.path, OLD, env.tmp / "r3")


def test_damaged_record_skips_with_a_warning(env):
    env.session.set_scheduled_backup_key(None)
    prefs = env.session._require_payload()["preferences"]
    prefs["scheduled_backup_key"] = {"v": 1}
    bus = env.controller._bus
    runner = ScheduleRunner(env.controller, bus, spawn=lambda fn: fn(), keys=env.keys,
                            run_backup=lambda **job: pytest.fail("no backup with a damaged key"))
    assert runner.check() is False
    toasts = [d for n, d in bus.events if n == "toast"]
    assert toasts[-1]["kind"] == "warning" and "damaged" in toasts[-1]["message"]
    assert env.keys.status()["damaged"] is True


def test_rollback_of_the_record_pauses_until_confirmed(env):
    env.keys.set_password(OLD, OLD)
    record = env.session.scheduled_backup_key()
    device.save(env.profile_dir, device.DeviceKeyState(seen_key_id="cd" * 16, seen_set_at=NOW + 100))
    assert env.keys.schedule_record() == ("paused", None)
    assert env.keys.status()["paused"] is True
    with pytest.raises(ApiError):
        env.keys.confirm(NEW)
    env.keys.confirm(OLD)
    assert env.keys.schedule_record() == ("ok", record)


def test_verify_fails_when_the_record_is_swapped_between_make_and_verify(env):
    env.keys.set_password(OLD, OLD)
    record = env.session.scheduled_backup_key()
    env.clock[0] += 10
    env.keys.change_password(OLD, NEW, NEW, relock=False)
    swapped = env.session.scheduled_backup_key()
    make, verify = bs.full_backup_functions(profile_dir=env.profile_dir, profile_name="Synthetic", record=record,
                                            current_record=lambda: swapped)
    with pytest.raises(bs.ScheduleError):
        bs.run_scheduled_backup(directory=env.scheduled, tag=env.tag, keep=2, when=datetime(2026, 11, 3, 9),
                                make_backup=make, verify=verify)
    assert bs.owned_backups(env.scheduled, env.tag) == []


# ------------------------------------------------------------------------------------------ set and change
def test_master_password_alone_never_replaces_or_removes_a_key(env):
    env.keys.set_password(OLD, OLD)
    with pytest.raises(ApiError):
        env.keys.set_password(NEW, NEW)
    with pytest.raises(ApiError):
        env.keys.change_password(MASTER, NEW, NEW)
    with pytest.raises(ApiError):
        env.keys.remove()
    with pytest.raises(ApiError):
        env.keys.remove(password=MASTER)
    with pytest.raises(ApiError):
        env.keys.reset_password(MASTER, NEW, NEW)
    assert password_matches(env.session.scheduled_backup_key(), OLD)


def test_change_relocks_v3_files_and_leaves_old_format_files_alone(env):
    _plant_legacy_password(env.session)
    v2 = _v2_scheduled(env, datetime(2026, 10, 30, 9))
    env.keys.migrate(env.session)
    v3 = _v3_run(env, datetime(2026, 10, 31, 9)).path
    v3_mirror = env.mirror / v3.name
    old_record = env.session.scheduled_backup_key()
    v2_before = (v2.read_bytes(), v2.stat().st_mtime_ns)
    v3_mtime = v3.stat().st_mtime_ns
    with pytest.raises(ApiError) as wrong:
        env.keys.change_password("not the backup password", NEW, NEW)
    assert wrong.value.message == "That is not the current backup password."
    env.clock[0] += 60
    message = env.keys.change_password(OLD, NEW, NEW, relock=True)["message"]
    assert "re-locked to the new password: 2" in message and ": 1." in message
    record = env.session.scheduled_backup_key()
    assert record["set_by"] == "changed" and record["history"][0]["key_id"] == old_record["key_id"]
    assert device.load(env.profile_dir).seen_key_id == record["key_id"]
    # The v2 file: same bytes and mtime, opens with the old password only.
    assert (v2.read_bytes(), v2.stat().st_mtime_ns) == v2_before
    assert _restores(v2, OLD, env.tmp / "a") and not _restores(v2, NEW, env.tmp / "b")
    # The v3 files: same name and mtime, open with the new password only.
    assert v3.stat().st_mtime_ns == v3_mtime
    for path in (v3, v3_mirror):
        assert _restores(path, NEW, env.tmp / f"c-{path.parent.name}")
        assert not _restores(path, OLD, env.tmp / f"d-{path.parent.name}")
    assert env.keys.status()["notice"] == ""  # Q1: no upgrade notice after a change


def test_change_without_relock_keeps_v3_files_on_the_old_key(env):
    env.keys.set_password(OLD, OLD)
    v3 = _v3_run(env, datetime(2026, 10, 31, 9)).path
    before = v3.read_bytes()
    env.clock[0] += 60
    env.keys.change_password(OLD, NEW, NEW, relock=False)
    assert v3.read_bytes() == before and _restores(v3, OLD, env.tmp / "o")


# ----------------------------------------------------------------------------------------- reset (Q2 strict)
def test_reset_without_authority_is_refused(env):
    env.keys.set_password(OLD, OLD)
    phrase = env.session.create_recovery_phrase(MASTER)
    with pytest.raises(ApiError) as refused:
        env.keys.reset_password(phrase, NEW, NEW)
    assert "cannot be reset" in refused.value.message


def test_reset_with_the_current_phrase_and_refusals(env):
    phrase = env.session.create_recovery_phrase(MASTER)
    env.keys.set_password(OLD, OLD)
    _plant_v2 = _v2_scheduled(env, datetime(2026, 10, 30, 9))
    v2_before = (_plant_v2.read_bytes(), _plant_v2.stat().st_mtime_ns)
    assert env.keys.status()["can_reset"] is True
    env.clock[0] += 60
    result = env.keys.reset_password(phrase, NEW, NEW)
    assert "still need the old backup password" in result["message"]
    record = env.session.scheduled_backup_key()
    assert record["set_by"] == "reset" and record["reset_at"] == NOW + 60
    assert password_matches(record, NEW)
    assert (_plant_v2.read_bytes(), _plant_v2.stat().st_mtime_ns) == v2_before
    assert _restores(_plant_v2, OLD, env.tmp / "x") and not _restores(_plant_v2, NEW, env.tmp / "y")


def test_a_replaced_phrase_never_resets_and_rebind_needs_the_backup_password(env):
    old_phrase = env.session.create_recovery_phrase(MASTER)
    env.keys.set_password(OLD, OLD)
    new_phrase = env.session.create_recovery_phrase(MASTER)  # replaces the phrase
    status = env.keys.status()
    assert status["rebind_needed"] is True and status["can_reset"] is False
    for words in (old_phrase, new_phrase):
        with pytest.raises(ApiError) as refused:
            env.keys.reset_password(words, NEW, NEW)
        assert "not the recovery phrase" in refused.value.message
    with pytest.raises(ApiError):
        env.keys.rebind(MASTER)
    env.keys.rebind(OLD)
    assert env.keys.status()["can_reset"] is True
    with pytest.raises(ApiError):
        env.keys.reset_password(old_phrase, NEW, NEW)
    env.clock[0] += 60
    env.keys.reset_password(new_phrase, NEW, NEW)
    assert env.session.scheduled_backup_key()["set_by"] == "reset"


def test_remove_needs_proof_and_then_a_new_set_works(env):
    phrase = env.session.create_recovery_phrase(MASTER)
    env.keys.set_password(OLD, OLD)
    env.keys.remove(phrase=phrase)
    assert not env.session.has_scheduled_backup_key()
    env.keys.set_password(NEW, NEW)
    assert password_matches(env.session.scheduled_backup_key(), NEW)


# --------------------------------------------------------------------------------------- Q1 notice
def test_upgrade_notice_dismiss_and_one_reminder_after_30_days(env):
    _plant_legacy_password(env.session)
    env.keys.migrate(env.session)
    assert env.keys.status()["notice"] == "notice"
    env.keys.dismiss_notice()
    assert env.keys.status()["notice"] == ""
    env.clock[0] += device.REMINDER_AFTER_SECONDS
    assert env.keys.status()["notice"] == "reminder"
    env.keys.dismiss_notice()
    env.clock[0] += 10 * device.REMINDER_AFTER_SECONDS
    assert env.keys.status()["notice"] == ""
    assert env.session.scheduled_backup_key()["set_by"] == "migrated"  # dismissing never undoes anything


def test_settings_page_rows_follow_the_key_state(env):
    service = SettingsService(env.controller, Port(), env.controller._bus, schedule=SimpleNamespace(
        keys=env.keys, settings_changed=lambda: None, _safe_check=lambda: None))
    _plant_legacy_password(env.session)
    env.keys.migrate(env.session)
    rows = next(s for s in service.page()["sections"] if s["key"] == "backups")["rows"]
    notices = [r for r in rows if r["type"] == "notice"]
    assert notices and notices[0]["title"] == "Change your backup password to finish the upgrade"
    assert [a["params"]["mode"] for a in notices[0]["actions"]] == ["change", "dismiss"]
    assert any(r.get("description") == "From before the upgrade (changing it is recommended)" for r in rows)
    env.clock[0] += 60
    service.change_backup_password(OLD, NEW, NEW, False)
    rows = next(s for s in service.page()["sections"] if s["key"] == "backups")["rows"]
    assert not [r for r in rows if r["type"] == "notice"]
    assert any(str(r.get("description", "")).startswith("Set on ") for r in rows)


# --------------------------------------------------------------------------------------- restore texts
def test_restore_key_lines_for_every_case(env, tmp_path):
    env.keys.set_password(OLD, OLD)
    first = _v3_run(env, datetime(2026, 10, 31, 9)).path
    shutil.copy2(first, tmp_path / "copy.lgk")
    env.clock[0] += 60
    env.keys.change_password(OLD, NEW, NEW, relock=False)
    current = _v3_run(env, datetime(2026, 11, 1, 9)).path
    v2 = _v2_scheduled(env, datetime(2026, 10, 29, 9))
    record = env.session.scheduled_backup_key()
    lines = {
        "current": key_line_text(backup_module.describe_backup(current, record=record)),
        "changed": key_line_text(backup_module.describe_backup(first, record=record)),
        "other": key_line_text(backup_module.describe_backup(first)),
        "old": key_line_text(backup_module.describe_backup(v2, record=record)),
    }
    assert lines["current"].startswith("This backup uses your current backup password (set on ")
    assert "It was changed on " in lines["changed"]
    assert "on the device that made it" in lines["other"]
    assert lines["old"].startswith("This backup uses the backup password that was in use when it was made (2026-10-29)")
    assert all(text.endswith("You will also need the master password of the backed-up vault.")
               for text in lines.values())
    # The Recovery centre reads the header before asking for passwords, then uses the chosen file.
    opened = []
    dialogs = SimpleNamespace(open_file=lambda title: opened.append(title) or str(current))
    recovery = RecoveryWebService(env.controller, Port(), dialogs)
    chosen = recovery.choose("verify")
    assert chosen["name"] == current.name and chosen["key_line"] == lines["current"]
    assert recovery._open("ignored", "verify") == current and len(opened) == 1


def test_restore_text_after_a_reset(env):
    phrase = env.session.create_recovery_phrase(MASTER)
    env.keys.set_password(OLD, OLD)
    first = _v3_run(env, datetime(2026, 10, 31, 9)).path
    env.clock[0] += 60
    env.keys.reset_password(phrase, NEW, NEW)
    text = key_line_text(backup_module.describe_backup(first, record=env.session.scheduled_backup_key()))
    assert "the new password does not open it" in text


def test_ensure_encrypted_container_accepts_v3(env):
    env.keys.set_password(OLD, OLD)
    bs.ensure_encrypted_container(_v3_run(env, datetime(2026, 10, 31, 9)).path)


# ============================================================================ review fixes (design 16c, L1-L8, N1)
LEAKED = OLD  # the rolled-back record's password, known to whoever brought the old vault back
OTHER = "synthetic other backup password"


def _put_record(session, record) -> None:
    """What an old vault copy brings back: ``record`` (or nothing, with ``None``) in the vault preferences."""
    prefs = session._require_payload().setdefault("preferences", {})
    if record is None:
        prefs.pop("scheduled_backup_key", None)
    else:
        prefs["scheduled_backup_key"] = record
    session.save()


def _rolled_back(env, *, phrase=False):
    """Set LEAKED (key K1), change to NEW (K2, seen here), then bring K1 back (the old vault copy)."""
    words = env.session.create_recovery_phrase(MASTER) if phrase else None
    env.keys.set_password(LEAKED, LEAKED)
    k1 = env.session.scheduled_backup_key()
    env.clock[0] += 60
    env.keys.change_password(LEAKED, NEW, NEW, relock=False)
    k2 = env.session.scheduled_backup_key()
    _put_record(env.session, k1)
    return k1, k2, words


def test_m1_rolled_back_record_and_its_leaked_password_cannot_unpause_or_change(env):
    k1, k2, _ = _rolled_back(env)
    assert device.load(env.profile_dir).seen_record == k2  # the full public record is kept on this device
    assert env.keys.schedule_record() == ("paused", None)
    status = env.keys.status()
    assert status["paused"] is True and status["paused_reason"] == "rollback" and status["seen_set_at"] == NOW + 60
    for attempt in (lambda: env.keys.confirm(LEAKED), lambda: env.keys.change_password(LEAKED, OTHER, OTHER),
                    lambda: env.keys.set_password(OTHER, OTHER), lambda: env.keys.remove(password=LEAKED),
                    lambda: env.keys.rebind(LEAKED), lambda: env.keys.confirm(MASTER),
                    lambda: env.keys.remove()):
        with pytest.raises(ApiError):
            attempt()
        assert env.session.scheduled_backup_key() == k1 and env.keys.schedule_record() == ("paused", None)
    # The newer password confirms and writes the seen record back.
    env.keys.confirm(NEW)
    assert env.session.scheduled_backup_key() == k2 and env.keys.schedule_record() == ("ok", k2)


def test_m1_change_while_paused_needs_the_seen_password(env):
    _k1, k2, _ = _rolled_back(env)
    env.clock[0] += 60
    env.keys.change_password(NEW, OTHER, OTHER, relock=False)
    record = env.session.scheduled_backup_key()
    assert record["history"][0]["key_id"] == k2["key_id"] and password_matches(record, OTHER)
    assert env.keys.schedule_record() == ("ok", record)


def test_m1_reset_while_paused_uses_the_phrase_bound_in_the_seen_record(env):
    _k1, k2, words = _rolled_back(env, phrase=True)
    assert env.keys.status()["can_reset"] is True
    env.clock[0] += 60
    env.keys.reset_password(words, OTHER, OTHER)
    record = env.session.scheduled_backup_key()
    assert record["set_by"] == "reset" and record["history"][0]["key_id"] == k2["key_id"]
    assert env.keys.schedule_record() == ("ok", record)


def test_m1_pre_migration_vault_coming_back_needs_the_seen_password(env):
    env.keys.set_password(NEW, NEW)
    k = env.session.scheduled_backup_key()
    _put_record(env.session, None)
    _plant_legacy_password(env.session, LEAKED)
    env.clock[0] += 60
    migrated = env.keys.migrate(env.session)
    assert migrated is not None and env.keys.schedule_record() == ("paused", None)
    with pytest.raises(ApiError):
        env.keys.confirm(LEAKED)
    with pytest.raises(ApiError):
        env.keys.change_password(LEAKED, OTHER, OTHER)
    env.keys.confirm(NEW)
    assert env.session.scheduled_backup_key() == k and env.keys.schedule_record() == ("ok", k)


def test_m2_missing_record_pauses_and_set_needs_proof(env):
    env.keys.set_password(OLD, OLD)
    k = env.session.scheduled_backup_key()
    _put_record(env.session, None)
    status = env.keys.status()
    assert status["paused"] is True and status["paused_reason"] == "missing" and status["has_key"] is False
    assert env.keys.schedule_record() == ("paused", None)
    with pytest.raises(ApiError) as refused:
        env.keys.set_password(OTHER, OTHER)
    assert "paused" in refused.value.message and env.session.scheduled_backup_key() is None
    env.keys.confirm(OLD)
    assert env.session.scheduled_backup_key() == k and env.keys.schedule_record() == ("ok", k)


def test_m2_missing_record_reset_with_the_bound_phrase(env):
    words = env.session.create_recovery_phrase(MASTER)
    env.keys.set_password(OLD, OLD)
    k = env.session.scheduled_backup_key()
    _put_record(env.session, None)
    env.clock[0] += 60
    env.keys.reset_password(words, NEW, NEW)
    record = env.session.scheduled_backup_key()
    assert record["history"][0]["key_id"] == k["key_id"] and env.keys.schedule_record() == ("ok", record)


def test_m2_fresh_device_behaves_as_before(env):
    assert device.load(env.profile_dir).seen_record is None
    env.keys.set_password(OLD, OLD)  # nothing seen: no proof needed
    assert env.keys.schedule_record()[0] == "ok"


def test_remove_with_proof_lets_a_new_set_follow(env):
    env.keys.set_password(OLD, OLD)
    env.keys.remove(password=OLD)
    assert device.load(env.profile_dir).seen_record is None
    env.keys.set_password(NEW, NEW)
    assert password_matches(env.session.scheduled_backup_key(), NEW)


def test_l3_damaged_record_with_a_seen_record_needs_its_password(env):
    env.keys.set_password(OLD, OLD)
    k = env.session.scheduled_backup_key()
    env.session._require_payload()["preferences"]["scheduled_backup_key"] = {"v": 1}
    status = env.keys.status()
    assert status["damaged"] and status["paused"] and status["paused_reason"] == "damaged"
    assert env.keys.schedule_record() == ("paused", None)
    with pytest.raises(ApiError):
        env.keys.set_password(OTHER, OTHER)
    with pytest.raises(ApiError):
        env.keys.confirm(MASTER)
    env.keys.confirm(OLD)
    assert env.session.scheduled_backup_key() == k


def test_l3_damaged_record_on_a_fresh_device_may_still_be_set(env, monkeypatch):
    logged = []
    monkeypatch.setattr("localvault.app.backup_keys._log", lambda where, exc: logged.append(where))
    env.session._require_payload().setdefault("preferences", {})["scheduled_backup_key"] = {"v": 1}
    assert env.keys.schedule_record() == ("damaged", None)
    env.keys.set_password(OLD, OLD)
    assert password_matches(env.session.scheduled_backup_key(), OLD)
    assert "backup-key-damaged-replaced" in logged


def test_legacy_device_file_is_adopted_when_it_names_the_vault_record(env):
    env.keys.set_password(OLD, OLD)
    k = env.session.scheduled_backup_key()
    device.save(env.profile_dir, device.DeviceKeyState(seen_key_id=k["key_id"], seen_set_at=k["set_at"]))
    assert device.load(env.profile_dir).legacy_seen
    assert env.keys.schedule_record() == ("ok", k)
    assert device.load(env.profile_dir).seen_record == k  # now full public data


def test_settings_page_while_paused_offers_confirm_and_reset_only(env):
    service = SettingsService(env.controller, Port(), env.controller._bus, schedule=SimpleNamespace(
        keys=env.keys, settings_changed=lambda: None, _safe_check=lambda: None))
    _rolled_back(env, phrase=True)
    rows = next(s for s in service.page()["sections"] if s["key"] == "backups")["rows"]
    notice = next(r for r in rows if r["type"] == "notice")
    assert "a newer one was set on this device" in notice["text"]
    assert [a["params"]["mode"] for a in notice["actions"]] == ["confirmSeen", "change", "reset"]
    assert not any(r.get("label") in ("Remove", "Set") for r in rows)


# ------------------------------------------------------------------------------------------- L1, L2
def _failing_save():
    raise VaultError("disk full")


def test_l1_failed_migration_does_not_block_once_it_is_no_longer_pending(env, monkeypatch):
    _plant_legacy_password(env.session)
    monkeypatch.setattr(env.session, "save", _failing_save)
    assert env.keys.migrate(env.session) is None and env.keys.schedule_record() == ("failed", None)
    monkeypatch.undo()
    env.session.migrate_scheduled_backup_password(NOW)  # done outside this service's failed session
    assert env.keys.schedule_record()[0] == "ok"


def test_l2_set_is_refused_while_a_stored_password_waits_and_starts_the_migration(env, monkeypatch):
    _plant_legacy_password(env.session)
    monkeypatch.setattr(env.session, "save", _failing_save)
    env.keys.migrate(env.session)
    monkeypatch.undo()
    with pytest.raises(ApiError) as refused:
        env.keys.set_password(OTHER, OTHER)  # spawn is a no-op here: the migration is only started
    assert "still being upgraded" in refused.value.message
    prefs = env.session._require_payload()["preferences"]
    assert prefs["scheduled_backup_password"] == OLD and "scheduled_backup_key" not in prefs
    env.keys._spawn = lambda fn: fn()
    env.keys._migrating = None
    with pytest.raises(ApiError):
        env.keys.set_password(OTHER, OTHER)  # retried now, synchronously
    record = env.session.scheduled_backup_key()
    assert password_matches(record, OLD) and env.keys.schedule_record() == ("ok", record)


# ------------------------------------------------------------------------------------------------ L4
def test_l4_a_file_that_vanishes_during_relock_is_reported_and_the_change_succeeds(env, monkeypatch):
    env.keys.set_password(OLD, OLD)
    gone = _v3_run(env, datetime(2026, 10, 31, 9)).path
    kept = _v3_run(env, datetime(2026, 11, 1, 9)).path
    real = backup_module._v3_read_header_only

    def vanish(path):
        result = real(path)
        if Path(path) == gone:
            gone.unlink()  # pruned or synced away between the header read and the stat
        return result

    monkeypatch.setattr(backup_module, "_v3_read_header_only", vanish)
    env.clock[0] += 60
    message = env.keys.change_password(OLD, NEW, NEW, relock=True)["message"]
    monkeypatch.undo()
    assert password_matches(env.session.scheduled_backup_key(), NEW)
    assert "Not re-locked" in message
    assert _restores(kept, NEW, env.tmp / "k")


def test_l4_utime_failure_after_replace_still_counts_as_relocked(env, monkeypatch):
    from localvault.backup_key import derive_backup_key

    env.keys.set_password(OLD, OLD)
    old_record = env.session.scheduled_backup_key()
    path = _v3_run(env, datetime(2026, 10, 31, 9)).path
    env.clock[0] += 60
    env.keys.change_password(OLD, NEW, NEW, relock=False)
    new_record = env.session.scheduled_backup_key()

    def denied(*_a, **_k):
        raise OSError("denied")

    monkeypatch.setattr(os, "utime", denied)
    old_key = derive_backup_key(OLD, old_record["kdf"])
    try:
        status = backup_module.relock_full_backup(path, old_key=old_key, new_record=new_record)
    finally:
        old_key.wipe()
    monkeypatch.undo()
    assert status == backup_module.RELOCK_RELOCKED
    assert _restores(path, NEW, env.tmp / "u")


def test_l4_relock_never_raises_for_one_file(monkeypatch, tmp_path):
    def boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(backup_module, "relock_full_backup", boom)
    summary = backup_module.relock_full_backups([tmp_path / "x.lgk"], old_key=None, new_record={})
    assert summary["relocked"] == [] and len(summary["failed"]) == 1


# ------------------------------------------------------------------------------------------------ L5
def test_l5_device_updates_are_serialised(env):
    names = [bs.scheduled_filename(env.tag, datetime(2026, 1, 1 + i % 28, 9, i)) for i in range(40)]

    def worker(chunk):
        for name in chunk:
            device.update(env.profile_dir, lambda state, n=name: device.protect(state, [n]))

    threads = [threading.Thread(target=worker, args=(names[i::4],)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert set(device.load(env.profile_dir).protect_old) == set(names)  # nothing lost, nothing truncated


def test_l5_unreadable_state_keeps_every_old_format_file(env):
    env.keys.set_password(OLD, OLD)
    old = [_v2_scheduled(env, datetime(2026, 10, day, 9)) for day in (25, 26)]
    device.state_file(env.profile_dir).write_text("{not json", encoding="utf-8")
    assert env.keys.protected_names() is None
    runs = [_v3_run(env, datetime(2026, 10, 27 + i, 9)).path for i in range(3)]
    left = {p.name for p in bs.owned_backups(env.scheduled, env.tag)}
    assert {o.name for o in old} <= left  # fail closed: no old-format file is pruned
    assert runs[0].name not in left and {runs[1].name, runs[2].name} <= left  # v3 files are pruned as usual
    # A later write keeps the damaged file aside and stays fail closed.
    env.keys.dismiss_notice()
    assert (env.profile_dir / (device.STATE_FILENAME + device.UNREADABLE_SUFFIX)).exists()
    assert device.load(env.profile_dir).keep_all_old and env.keys.protected_names() is None


def test_l5_newer_state_file_is_never_overwritten(env):
    device.state_file(env.profile_dir).write_text('{"version": 99}', encoding="utf-8")
    with pytest.raises(device.NewerStateError):
        device.update(env.profile_dir, lambda state: state)
    assert device.state_file(env.profile_dir).read_text(encoding="utf-8") == '{"version": 99}'


def test_l5_remigration_protects_the_old_format_file_never_a_v3_one(env):
    v2 = _v2_scheduled(env, datetime(2026, 10, 28, 9))
    env.keys.set_password(OLD, OLD)
    v3 = _v3_run(env, datetime(2026, 10, 30, 9)).path
    _put_record(env.session, None)  # a pre-migration vault copy comes back
    _plant_legacy_password(env.session)
    env.keys.migrate(env.session)
    protected = device.load(env.profile_dir).protect_old
    assert v2.name in protected and v3.name not in protected


# ------------------------------------------------------------------------------------------------ L6
def test_l6_scheduler_skips_while_a_change_holds_the_files(env):
    env.keys.set_password(OLD, OLD)
    ran = []
    runner = ScheduleRunner(env.controller, env.controller._bus, spawn=lambda fn: fn(), keys=env.keys,
                            run_backup=lambda **job: ran.append(job))
    assert env.keys.files_lock.acquire(blocking=False)
    try:
        assert runner.check() is False and ran == []
    finally:
        env.keys.files_lock.release()
    assert runner.check() is True and len(ran) == 1
    assert env.keys.files_lock.acquire(blocking=False)  # released after the run
    env.keys.files_lock.release()


def test_l6_change_waits_for_a_run_in_flight_and_saves_nothing_when_it_times_out(env, monkeypatch):
    env.keys.set_password(OLD, OLD)
    before = env.session.scheduled_backup_key()
    monkeypatch.setattr("localvault.app.backup_keys.RUN_WAIT_SECONDS", 0.05)
    env.keys.files_lock.acquire()
    try:
        with pytest.raises(ApiError) as busy:
            env.keys.change_password(OLD, NEW, NEW)
        assert busy.value.code == "busy" and env.session.scheduled_backup_key() == before
    finally:
        env.keys.files_lock.release()
    monkeypatch.setattr("localvault.app.backup_keys.RUN_WAIT_SECONDS", 5.0)
    env.keys.files_lock.acquire()
    threading.Timer(0.2, env.keys.files_lock.release).start()
    env.clock[0] += 60
    env.keys.change_password(OLD, NEW, NEW)
    assert password_matches(env.session.scheduled_backup_key(), NEW)


def test_l6_relock_lists_files_after_the_store(env, monkeypatch):
    """A file published while the change waited is re-locked too."""
    env.keys.set_password(OLD, OLD)
    late = []
    real_store = env.keys._store

    def store(*args, **kwargs):
        if not late:
            late.append(_v3_run(env, datetime(2026, 10, 31, 9)).path)  # made with the old record
        return real_store(*args, **kwargs)

    monkeypatch.setattr(env.keys, "_store", store)
    env.clock[0] += 60
    message = env.keys.change_password(OLD, NEW, NEW, relock=True)["message"]
    assert "re-locked to the new password: 2" in message  # the late file and its mirror copy
    assert _restores(late[0], NEW, env.tmp / "late")


# ------------------------------------------------------------------------------------------------ L7
def test_l7_no_decrypted_file_is_ever_created_in_the_mirror_folder(env, monkeypatch):
    env.keys.set_password(OLD, OLD)
    path = _v3_run(env, datetime(2026, 10, 31, 9)).path
    mirror_copy = env.mirror / path.name
    created = []
    real_temp, real_atomic = backup_module._full_temp_dir, backup_module._full_atomic_bytes
    real_mkdtemp = backup_module.tempfile.mkdtemp

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
    monkeypatch.setattr(backup_module.tempfile, "mkdtemp", mkdtemp)
    before = sorted(p.name for p in env.mirror.iterdir())
    env.clock[0] += 60
    env.keys.change_password(OLD, NEW, NEW, relock=True)
    monkeypatch.undo()
    assert created  # the preflight did stage something
    for folder in (env.mirror.resolve(), env.scheduled.resolve()):
        for place in created:
            resolved = place.resolve()
            assert resolved != folder and folder not in resolved.parents, place
    assert sorted(p.name for p in env.mirror.iterdir()) == before
    assert _restores(mirror_copy, NEW, env.tmp / "mc")


def test_l7_stale_relock_leftovers_are_swept(env):
    env.keys.set_password(OLD, OLD)
    _v3_run(env, datetime(2026, 10, 31, 9))
    stale = env.mirror / ".lgk-relock-abc.tmp"
    fresh = env.mirror / ".lgk-relock-new.tmp"
    probe = env.scheduled / ".lgk-scheduled-probe-old"
    stale.write_bytes(b"x")
    fresh.write_bytes(b"y")
    probe.mkdir()
    (probe / "settings.json").write_text("{}", encoding="utf-8")
    old_time = time.time() - 3600
    os.utime(stale, (old_time, old_time))
    os.utime(probe, (old_time, old_time))
    env.clock[0] += 60
    env.keys.change_password(OLD, NEW, NEW, relock=True)
    assert not stale.exists() and not probe.exists() and fresh.exists()


# ------------------------------------------------------------------------------------------------ L8
def test_l8_the_record_binds_the_phrase_current_when_it_is_stored(env, monkeypatch):
    real = env.keys._derive_new
    words = []

    def derive(*args, **kwargs):
        key = real(*args, **kwargs)
        words.append(env.session.create_recovery_phrase(MASTER))  # the phrase changes after the checks
        return key

    monkeypatch.setattr(env.keys, "_derive_new", derive)
    env.keys.set_password(OLD, OLD)
    monkeypatch.undo()
    record = env.session.scheduled_backup_key()
    assert record["reset_authority"] == env.session.recovery_wrapper_snapshot()
    assert env.keys.status()["can_reset"] is True
    env.clock[0] += 60
    env.keys.reset_password(words[0], NEW, NEW)


def test_l8_a_stale_authority_sets_the_rebind_flag(env):
    env.keys.set_password(OLD, OLD)
    record = env.session.scheduled_backup_key()  # bound to no phrase
    env.session.create_recovery_phrase(MASTER)
    env.session.set_scheduled_backup_key(record)
    assert env.session.scheduled_backup_key_rebind_needed() is True


# ------------------------------------------------------------------------------------------------ N1
def test_n1_mirror_copy_is_checked_against_the_recorded_digest(env):
    env.keys.set_password(OLD, OLD)
    path = _v3_run(env, datetime(2026, 10, 31, 9)).path
    with pytest.raises(bs.MirrorError):
        bs.mirror_backup(path, env.mirror, tag=env.tag, keep=2, expected_sha256="0" * 64)


def test_n1_confirm_touches_the_controller(env, monkeypatch):
    env.keys.set_password(OLD, OLD)
    touched = []
    monkeypatch.setattr(env.controller, "touch", lambda: touched.append(1))
    env.keys.confirm(OLD)
    assert touched == [1]


# ------------------------------------------------------------------------------------- bridge refusals
@pytest.fixture
def bridge(env):
    api = Api(env.controller, WebUiPort(env.controller._bus, timeout=1), SimpleNamespace(
        minimize=lambda: None, toggle_maximize=lambda: None, close=lambda: None))
    keys = api._settings.keys
    keys._clock = lambda: env.clock[0]
    keys._spawn = lambda fn: None
    api._settings._port = Port()
    return SimpleNamespace(api=api, keys=keys)


def _refused(result) -> bool:
    return result.get("ok") is False and result["error"]["code"] in ("invalid", "busy")


def _master_only_attempts(api, leaked=None):
    calls = [api.backup_password_set(OTHER, OTHER), api.backup_key_remove("", None), api.backup_key_remove(None, None),
             api.backup_key_remove(MASTER, None), api.backup_key_confirm(MASTER),
             api.backup_password_change(MASTER, OTHER, OTHER), api.backup_password_reset(MASTER, OTHER, OTHER),
             api.backup_key_rebind(MASTER)]
    if leaked:
        calls += [api.backup_key_confirm(leaked), api.backup_key_remove(leaked, None),
                  api.backup_password_change(leaked, OTHER, OTHER), api.backup_key_rebind(leaked)]
    return calls


def test_bridge_master_password_alone_changes_nothing_with_a_key(env, bridge):
    assert bridge.api.backup_password_set(OLD, OLD)["ok"] is True
    record = env.session.scheduled_backup_key()
    results = _master_only_attempts(bridge.api)
    assert all(_refused(r) for r in results), results
    assert env.session.scheduled_backup_key() == record


def test_bridge_refuses_everything_while_a_stored_password_waits(env, bridge):
    _plant_legacy_password(env.session)
    results = _master_only_attempts(bridge.api)
    assert all(_refused(r) for r in results), results
    prefs = env.session._require_payload()["preferences"]
    assert prefs["scheduled_backup_password"] == OLD and "scheduled_backup_key" not in prefs


def test_bridge_refuses_the_leaked_password_after_a_rollback(env, bridge):
    bridge.api.backup_password_set(LEAKED, LEAKED)
    k1 = env.session.scheduled_backup_key()
    env.clock[0] += 60
    assert bridge.api.backup_password_change(LEAKED, NEW, NEW, False)["ok"] is True
    _put_record(env.session, k1)
    results = _master_only_attempts(bridge.api, leaked=LEAKED)
    assert all(_refused(r) for r in results), results
    assert env.session.scheduled_backup_key() == k1
    assert bridge.api.backup_key_confirm(NEW)["ok"] is True


def test_bridge_refuses_set_over_a_missing_or_damaged_record(env, bridge):
    bridge.api.backup_password_set(OLD, OLD)
    _put_record(env.session, None)
    results = _master_only_attempts(bridge.api)
    assert all(_refused(r) for r in results), results
    assert env.session.scheduled_backup_key() is None
    env.session._require_payload()["preferences"]["scheduled_backup_key"] = {"v": 1}
    results = _master_only_attempts(bridge.api)
    assert all(_refused(r) for r in results), results
    assert bridge.api.backup_key_confirm(OLD)["ok"] is True
    assert password_matches(env.session.scheduled_backup_key(), OLD)


def test_a_brand_new_vault_starts_with_no_seen_record(env):
    env.keys.set_password(OLD, OLD)
    assert device.load(env.profile_dir).seen_record is not None
    names = [bs.scheduled_filename(env.tag, datetime(2026, 10, 1, 9))]
    device.update(env.profile_dir, lambda state: device.protect(state, names))
    env.controller.lock()
    for path in env.profile_dir.iterdir():  # e.g. after an erase: only this device's key state is left
        if path.is_file() and path.name != device.STATE_FILENAME:
            path.unlink()
    env.controller.create(MASTER, MASTER)
    state = device.load(env.profile_dir)
    assert state.seen_record is None and not state.seen_key_id
    assert state.protect_old == tuple(names)  # Q3 names stay
    env.keys.set_password(NEW, NEW)  # no proof needed: nothing is seen for this vault
    assert password_matches(env.session.scheduled_backup_key(), NEW)


def test_rebind_updates_the_seen_record_authority(env):
    env.keys.set_password(OLD, OLD)
    env.session.create_recovery_phrase(MASTER)
    env.keys.rebind(OLD)
    seen = device.load(env.profile_dir).seen_record
    assert seen == env.session.scheduled_backup_key()
    assert seen["reset_authority"] == env.session.recovery_wrapper_snapshot()


def test_proven_remove_with_the_phrase_clears_the_seen_record(env):
    words = env.session.create_recovery_phrase(MASTER)
    env.keys.set_password(OLD, OLD)
    env.keys.remove(phrase=words)
    assert device.load(env.profile_dir).seen_record is None
    assert env.keys.schedule_record() == ("none", None)
