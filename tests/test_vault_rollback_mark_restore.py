"""Rollback marks (tests/test_vault_rollback_mark.py) around restores, data-key changes and removal.

Review of the rollback marks (2026-11-13):
- B1: a full restore sets the destination's marks only once the restored profile is in place; a restore that stops
  earlier (cancelled, its pre-restore backup or its publish failed) leaves the store as it was.
- S1: "restore as a new profile" (Recovery Center, emergency access) marks the new profile's path, never the
  temporary folder it was staged in.
- S2: a copy from before several data-key changes (master-password changes), or from before the v3 format upgrade,
  is refused like any older copy.
- N2: a removed vault's marks can be deleted by name (``forget_rollback_marks``).
These tests use the in-memory store from tests/conftest.py, never the real registry.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localvault import backup as B
from localvault import heir, heir_flow, outside_marks
from localvault import vault as V
from localvault.backup import BackupCancelled, BackupError, export_full_backup, restore_full_backup
from localvault.config import atomic_write_json
from localvault.i18n import t
from localvault.recovery import restore_as_new_profile

LOW = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery staple"
BACKUP_PASSWORD = "synthetic backup container password"
FILES = ("vault.json", "vault.generation.json")


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    # A rotation (master-password change, phrase restore) wraps the new key under the default KDF: keep it small.
    monkeypatch.setattr(V, "DEFAULT_KDF", {**V.DEFAULT_KDF, **LOW})
    V._reset_unlock_throttle_state_for_tests()
    yield
    V._reset_unlock_throttle_state_for_tests()


def _profile(folder: Path) -> Path:
    path = folder / "vault.json"
    path.parent.mkdir(parents=True)
    V.create_vault(path, MASTER, kdf_overrides=LOW).lock()
    atomic_write_json(path.parent / "settings.json", {})
    return path


def _commit(path: Path, times: int = 1, *, live: bool = True) -> None:
    """Saves, by the app's own unlock of the live vault (``live``) or as a copy elsewhere (another PC)."""
    session = V.unlock_vault(path, MASTER, upgrade_kdf=live)
    try:
        for _ in range(times):
            session.save()
    finally:
        session.lock()


def _generation(path: Path) -> int:
    return int(json.loads(path.read_bytes())["generation"])


def _snapshot(path: Path) -> dict[str, bytes]:
    return {name: (path.parent / name).read_bytes() for name in FILES if (path.parent / name).exists()}


def _put_back(path: Path, snapshot: dict[str, bytes]) -> None:
    for name in FILES:
        target = path.parent / name
        if name in snapshot:
            target.write_bytes(snapshot[name])
        else:
            target.unlink(missing_ok=True)


def _path_name(path: Path) -> str:
    return outside_marks.name_for(V._ROLLBACK_MARK_PURPOSE, path)


def _id_name(path: Path) -> str:
    vault_id = V.header_vault_id(path)
    assert vault_id
    return outside_marks.name_for_id(V._ROLLBACK_ID_MARK_PURPOSE, vault_id)


def _marks(session: V.VaultSession, path: Path | None = None) -> tuple[V._RollbackMark, V._RollbackMark]:
    path = Path(path or session.path)
    vault_id = str(session._header["vault_id"])
    key = V._rollback_anchor_key(session._key)
    try:
        return (V._read_rollback_mark(_path_name(path), "path", key, vault_id, path),
                V._read_rollback_mark(outside_marks.name_for_id(V._ROLLBACK_ID_MARK_PURPOSE, vault_id), "id", key,
                                      vault_id, path))
    finally:
        V._zero(key)


def _refused(path: Path, password: str = MASTER, *, live: bool) -> None:
    with pytest.raises(V.VaultError) as caught:
        V.unlock_vault(path, password, upgrade_kdf=live)
    assert str(caught.value) == t("vault.err.rollbackMarkOlder", restore=t("command.backup-restore.title"))


# ------------------------------------------------------------------------------------------ B1: full restore
def _newer_backup_of_an_older_copy(tmp_path: Path) -> tuple[Path, Path]:
    """This PC holds an older copy of the vault; a full backup made on another PC, further ahead, is restored."""
    path = _profile(tmp_path / "pc2")
    other = tmp_path / "pc1"
    shutil.copytree(path.parent, other)
    _commit(other / "vault.json", 5, live=False)  # another PC: its own store, not this one
    backup = tmp_path / "newer.lgk"
    export_full_backup(backup, profile_dir=other, profile_name="Synthetic", backup_password=BACKUP_PASSWORD)
    shutil.rmtree(other)
    _commit(path, 1)  # this PC's marks for its copy
    assert _generation(path) < 6
    return path, backup


def _restore_in_place(path: Path, backup: Path, **kwargs) -> dict:
    return restore_full_backup(backup, profile_dir=path.parent, backup_password=BACKUP_PASSWORD,
                               vault_password=MASTER, replace=True, **kwargs)


def _still_opens_untouched(path: Path, before_files: dict[str, bytes], before_marks: dict[str, str],
                           store: outside_marks.MemoryBackend) -> None:
    assert _snapshot(path) == before_files  # nothing was published
    assert store.values == before_marks  # and nothing was marked
    session = V.unlock_vault(path, MASTER, upgrade_kdf=True)
    try:
        assert session.rollback_anchor_missing is False
        assert int(session._payload["generation"]) == _generation(path)
    finally:
        session.lock()


def test_a_cancelled_full_restore_leaves_the_vault_and_its_marks_alone(tmp_path: Path, monkeypatch,
                                                                         outside_marks_store) -> None:
    path, backup = _newer_backup_of_an_older_copy(tmp_path)
    before_files, before_marks = _snapshot(path), dict(outside_marks_store.values)
    checked: list[bool] = []
    real = B._full_sanitize_staged_vault

    def sanitize(*args, **kwargs):
        result = real(*args, **kwargs)
        checked.append(True)  # the user presses Cancel once the staged copy passed the vault check
        return result

    monkeypatch.setattr(B, "_full_sanitize_staged_vault", sanitize)
    with pytest.raises(BackupCancelled):
        _restore_in_place(path, backup, cancel=lambda: bool(checked))
    assert checked
    _still_opens_untouched(path, before_files, before_marks, outside_marks_store)


def test_a_full_restore_whose_pre_restore_backup_fails_leaves_the_vault_and_its_marks_alone(
        tmp_path: Path, monkeypatch, outside_marks_store) -> None:
    path, backup = _newer_backup_of_an_older_copy(tmp_path)
    before_files, before_marks = _snapshot(path), dict(outside_marks_store.values)

    def fail(**_kwargs):
        raise BackupError("synthetic: disk full")

    monkeypatch.setattr(B, "_full_make_pre_restore_backup", fail)
    with pytest.raises(BackupError):
        _restore_in_place(path, backup)
    _still_opens_untouched(path, before_files, before_marks, outside_marks_store)


def test_a_full_restore_whose_publish_fails_leaves_the_vault_and_its_marks_alone(tmp_path: Path, monkeypatch,
                                                                                  outside_marks_store) -> None:
    path, backup = _newer_backup_of_an_older_copy(tmp_path)
    before_files, before_marks = _snapshot(path), dict(outside_marks_store.values)
    real_publish, real_replace = B._full_publish, os.replace
    failed: list[bool] = []

    def publish(stage_root, **kwargs):
        def replace(source, target):
            # The last component (the anchor) cannot be moved in: the vault already was, so it is rolled back.
            if Path(target) == Path(kwargs["anchor"]) and Path(source).parent == Path(stage_root):
                failed.append(True)
                raise OSError("synthetic: publish failed")
            return real_replace(source, target)

        with monkeypatch.context() as patch:
            patch.setattr(B.os, "replace", replace)
            return real_publish(stage_root, **kwargs)

    monkeypatch.setattr(B, "_full_publish", publish)
    with pytest.raises(BackupError):
        _restore_in_place(path, backup)
    assert failed
    _still_opens_untouched(path, before_files, before_marks, outside_marks_store)


def test_a_full_restore_marks_the_restored_vault_once_it_is_in_place(tmp_path: Path, monkeypatch,
                                                                     outside_marks_store) -> None:
    path, backup = _newer_backup_of_an_older_copy(tmp_path)
    written: list[tuple[str, bool]] = []
    real_write, real_publish = outside_marks.write, B._full_publish
    published: list[bool] = []

    def write(name, value):
        written.append((name, bool(published)))
        return real_write(name, value)

    def publish(*args, **kwargs):
        result = real_publish(*args, **kwargs)
        published.append(True)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(outside_marks, "write", write)
        patch.setattr(B, "_full_publish", publish)
        _restore_in_place(path, backup)
    rollback_writes = [after for name, after in written if name.startswith(V._ROLLBACK_MARK_PURPOSE)]
    assert rollback_writes and all(rollback_writes)  # every mark written after the publish
    restored = _generation(path)
    assert restored >= 6
    session = V.unlock_vault(path, MASTER, upgrade_kdf=True)
    try:
        assert session.rollback_anchor_missing is False
        path_mark, id_mark = _marks(session)
        assert path_mark.state == id_mark.state == "ok"
        assert path_mark.generation == id_mark.generation == restored
        assert id_mark.place == V._mark_place(path)
    finally:
        session.lock()


# --------------------------------------------------------------------------------- S1: restore as a new profile
def _as_new_profile(tmp_path: Path, outside_marks_store) -> tuple[Path, Path]:
    """Profile A goes on after its backup; the backup is restored as profile B (Recovery Center)."""
    a = _profile(tmp_path / "Profiles" / "A")
    backup = tmp_path / "old.lgk"
    export_full_backup(backup, profile_dir=a.parent, profile_name="A", backup_password=BACKUP_PASSWORD)
    _commit(a, 3)
    before = dict(outside_marks_store.values)
    b = tmp_path / "Profiles" / "B" / "vault.json"
    result = restore_as_new_profile(backup, b.parent, backup_password=BACKUP_PASSWORD, vault_password=MASTER,
                                    confirm=True)
    assert result["committed"] is True
    # Only B's path mark is new (the vault id's mark already existed): nothing names the stage folder.
    assert set(outside_marks_store.values) - set(before) == {_path_name(b)}
    assert not any(p.name.startswith(".lgk-") for p in b.parent.parent.iterdir())
    session = V.unlock_vault(b, MASTER)  # a copy's unlock reads the path mark only and writes nothing new
    try:
        path_mark, id_mark = _marks(session)
        assert path_mark.state == id_mark.state == "ok"
        assert path_mark.generation == id_mark.generation == _generation(b)
        assert id_mark.place == V._mark_place(b)
    finally:
        session.lock()
    return a, b


def test_a_profile_restored_as_new_is_not_flagged_while_the_old_one_goes_on(tmp_path: Path,
                                                                            outside_marks_store) -> None:
    a, b = _as_new_profile(tmp_path, outside_marks_store)
    _commit(a, 1)  # the old profile, still open in the app, saves again
    session = V.unlock_vault(b, MASTER, upgrade_kdf=True)
    try:
        assert session.rollback_anchor_missing is False  # no false "protection was reset" warning
    finally:
        session.lock()


def test_a_profile_restored_as_new_opens_after_the_old_one_is_deleted(tmp_path: Path, outside_marks_store) -> None:
    a, b = _as_new_profile(tmp_path, outside_marks_store)
    _commit(a, 1)
    shutil.rmtree(a.parent)  # restore as new, delete the old profile, switch
    session = V.unlock_vault(b, MASTER, upgrade_kdf=True)
    try:
        assert session.rollback_anchor_missing is False
    finally:
        session.lock()


def test_emergency_access_marks_the_heirs_new_profile_not_its_stage(tmp_path: Path, monkeypatch,
                                                                    outside_marks_store) -> None:
    now, day = 1_800_000_000, 86400
    monkeypatch.delenv(heir_flow.NOW_ENV, raising=False)
    profile = tmp_path / "owner-profile"
    profile.mkdir()
    (tmp_path / "shared").mkdir()
    owner = V.create_vault(profile / "vault.json", MASTER, kdf_overrides=LOW)
    try:
        owner.upsert_web(origin="https://bank.example", username="owner", password="owner secret 1")
        phrase = owner.create_recovery_phrase(MASTER)
        _plan, packages = heir.create_plan(owner, k=2, n=3, holders=("Anna", "Ben", "Chris"), wait_days=7,
                                           folder=tmp_path / "shared", phrase=phrase, reauthenticate=lambda: True,
                                           owner="Owner", now=now)
        target = heir_flow.backup_target(owner)
        assert target is not None
        heir_flow.write_backup(target, profile_dir=profile, profile_name="Owner", now=now + 60)
    finally:
        owner.lock()
    identity = heir_flow.RequesterIdentity.generate()
    heir_flow.request_access(tmp_path / "shared", packages[0], identity, now=now + day)
    before = dict(outside_marks_store.values)
    destination = tmp_path / "heir-profiles" / "restored"
    destination.parent.mkdir()
    new_password = "the heir's new master password"
    heir_flow.combine_and_restore(tmp_path / "shared", packages[:2], identity, destination=destination,
                                  new_password=new_password, now=now + 9 * day)
    restored = destination / "vault.json"
    assert set(outside_marks_store.values) - set(before) <= {_path_name(restored), _id_name(restored)}
    assert _path_name(restored) in outside_marks_store.values
    session = V.unlock_vault(restored, new_password)
    try:
        path_mark, id_mark = _marks(session)
        assert path_mark.state == id_mark.state == "ok"
        assert path_mark.generation == id_mark.generation == _generation(restored)
        assert id_mark.place == V._mark_place(restored)
    finally:
        session.lock()
    session = V.unlock_vault(restored, new_password, upgrade_kdf=True)
    try:
        assert session.rollback_anchor_missing is False
    finally:
        session.lock()


# ---------------------------------------------------------------------------- S2: copies under retired keys
def test_a_copy_from_before_two_master_password_changes_is_refused(tmp_path: Path) -> None:
    path = _profile(tmp_path / "A")
    old = _snapshot(path)
    _commit(path, 2)
    session = V.unlock_vault(path, MASTER, upgrade_kdf=True)
    try:
        session.change_master_password(MASTER, "second master password words")
        session.change_master_password("second master password words", "third master password words")
        session.save()
    finally:
        session.lock()
    _put_back(path, old)  # under the first data key, opened with the first password
    _refused(path, live=True)
    _refused(path, live=False)


def test_a_copy_from_before_several_rotations_is_refused_and_the_chain_is_bounded(tmp_path: Path) -> None:
    path = _profile(tmp_path / "A")
    snapshots = [_snapshot(path)]
    session = V.unlock_vault(path, MASTER, upgrade_kdf=True)
    try:
        for _ in range(V._ROLLBACK_MARK_RETIRED_MAX + 2):
            session.rotate_data_key(MASTER)
            session.save()
            snapshots.append(_snapshot(path))
            path_mark, id_mark = _marks(session)
            assert len(path_mark.retired or []) <= V._ROLLBACK_MARK_RETIRED_MAX
            assert len(id_mark.retired or []) <= V._ROLLBACK_MARK_RETIRED_MAX
        assert len(path_mark.retired) == len(id_mark.retired) == V._ROLLBACK_MARK_RETIRED_MAX
    finally:
        session.lock()
    current = snapshots[-1]
    # Every copy under one of the last _ROLLBACK_MARK_RETIRED_MAX retired keys is refused...
    for old in snapshots[-1 - V._ROLLBACK_MARK_RETIRED_MAX:-1]:
        _put_back(path, old)
        _refused(path, live=True)
        _refused(path, live=False)
    # ...and the current vault still opens afterwards.
    _put_back(path, current)
    V.unlock_vault(path, MASTER, upgrade_kdf=True).lock()


def test_a_failed_rotation_keeps_the_retired_chain(tmp_path: Path, monkeypatch) -> None:
    path = _profile(tmp_path / "A")
    old = _snapshot(path)
    session = V.unlock_vault(path, MASTER, upgrade_kdf=True)
    try:
        session.rotate_data_key(MASTER)
        session.save()

        def fail(self, header, *, before_save=None):
            raise V.VaultError("synthetic commit failure")

        with monkeypatch.context() as patch:
            patch.setattr(V.VaultSession, "_commit_header_change", fail)
            with pytest.raises(V.VaultError):
                session.rotate_data_key(MASTER)
        path_mark, id_mark = _marks(session)
        assert path_mark.settled and id_mark.settled
        assert len(path_mark.retired) == len(id_mark.retired) == 1
    finally:
        session.lock()
    _put_back(path, old)
    _refused(path, live=True)


def _write_v2_vault(path: Path, password: str) -> None:
    """A format-2 vault (no vault id) whose Argon2 output is the catalog key (as tests/test_vault_v3.py)."""
    kdf = {**V.DEFAULT_KDF, **LOW, "salt": V._b64e(os.urandom(16))}
    header = {"version": 2, "format": "localgatekeys-vault-v2", "catalog": V.CATALOG_FORMAT, "kdf": kdf,
              "cipher": {"name": "aes-256-gcm", "nonce": "", "ciphertext": ""}}
    payload = V._empty_payload()
    payload["generation"] = 3
    nonce = os.urandom(12)
    header["cipher"]["nonce"] = V._b64e(nonce)
    key = V._derive_key(password, kdf)
    header["cipher"]["ciphertext"] = V._b64e(AESGCM(bytes(key)).encrypt(nonce, V._canonical_json(payload),
                                                                      V._aad(header)))
    atomic_write_json(path, header)


def test_a_copy_from_before_the_v3_upgrade_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "A" / "vault.json"
    path.parent.mkdir()
    _write_v2_vault(path, MASTER)
    old = _snapshot(path)
    session = V.unlock_vault(path, MASTER, upgrade_kdf=True, backup_dir=path.parent / "Backups")
    try:
        assert session.last_envelope_upgrade_result["outcome"] == "upgraded"
        session.save()
    finally:
        session.lock()
    assert V.header_vault_id(path)
    _put_back(path, old)  # the format-2 file as it was before the upgrade
    _refused(path, live=True)
    _refused(path, live=False)


def test_a_retired_record_in_the_old_single_form_is_still_read(tmp_path: Path, outside_marks_store) -> None:
    """Values written before the chain kept one ``retired`` record (a dict), not a list."""
    path = _profile(tmp_path / "A")
    vault_id = V.header_vault_id(path)
    old_key, new_key = os.urandom(32), os.urandom(32)
    record = V._retired_mark(old_key, "path", 9, vault_id, path)
    value = json.loads(V._rollback_mark_value(new_key, "path", 9, vault_id, path))
    if "dpapi" in value:
        value = json.loads(V._dpapi_unprotect(value["dpapi"], V._ROLLBACK_MARK_ENTROPY))
    value["retired"] = record
    outside_marks_store.values[_path_name(path)] = json.dumps(value)
    mark = V._read_rollback_mark(_path_name(path), "path", old_key, vault_id, path)
    assert mark.state == "ok" and mark.generation == 9


# ------------------------------------------------------------------------------- N2: a removed vault's marks
def test_forget_rollback_marks_deletes_only_that_vaults_marks(tmp_path: Path, outside_marks_store) -> None:
    gone = _profile(tmp_path / "gone")
    kept = _profile(tmp_path / "kept")
    _commit(gone, 1)
    _commit(kept, 1)
    gone_names = {_path_name(gone), _id_name(gone)}
    kept_values = {name: outside_marks_store.values[name] for name in (_path_name(kept), _id_name(kept))}
    assert gone_names <= set(outside_marks_store.values)
    V.forget_rollback_marks(gone)
    assert not gone_names & set(outside_marks_store.values)
    assert {name: outside_marks_store.values[name] for name in kept_values} == kept_values
    shutil.rmtree(gone.parent)
    V.forget_rollback_marks(gone)  # nothing there any more: no error


def test_the_test_restore_drill_leaves_the_marks_alone(tmp_path: Path, outside_marks_store) -> None:
    a = _profile(tmp_path / "Profiles" / "A")
    backup = tmp_path / "old.lgk"
    export_full_backup(backup, profile_dir=a.parent, profile_name="A", backup_password=BACKUP_PASSWORD)
    _commit(a, 3)
    before = dict(outside_marks_store.values)
    trial = tmp_path / "trial" / "profile"
    result = restore_as_new_profile(backup, trial, backup_password=BACKUP_PASSWORD, vault_password=MASTER,
                                    confirm=True, mark=False)
    assert result["committed"] is True and (trial / "vault.json").exists()
    assert outside_marks_store.values == before  # no orphan mark, the live profile's id mark not lowered


def test_a_copy_from_before_a_password_change_of_a_format_2_vault_is_refused(tmp_path: Path, monkeypatch) -> None:
    """A format-2 vault whose upgrade failed gets its id in the data-key rotation of a master-password change:
    the old key's copy, which has no id, is refused too."""
    path = tmp_path / "A" / "vault.json"
    path.parent.mkdir()
    _write_v2_vault(path, MASTER)

    def fail(*_args, **_kwargs):
        raise V.VaultError("synthetic promotion failure")

    with monkeypatch.context() as patch:
        patch.setattr(V.VaultSession, "_journaled_promotion", fail)
        session = V.unlock_vault(path, MASTER, upgrade_kdf=True)
        try:
            assert session.last_envelope_upgrade_result["outcome"] == "failed"
            old = _snapshot(path)  # still format 2, no id
            assert not V.header_vault_id(path)
            session.change_master_password(MASTER, "second master password words")  # the first commit
            assert V.header_vault_id(path)  # the rotation gave it its id
            session.save()
        finally:
            session.lock()
    _put_back(path, old)  # the format-2 file under the first data key, opened with the first password
    _refused(path, live=True)
    _refused(path, live=False)


def test_a_copy_from_before_a_failed_upgrades_first_save_is_refused(tmp_path: Path, monkeypatch) -> None:
    """A format-2 vault whose upgrade failed becomes format 3 at its next save: its copy from before is refused."""
    path = tmp_path / "A" / "vault.json"
    path.parent.mkdir()
    _write_v2_vault(path, MASTER)

    def fail(*_args, **_kwargs):
        raise V.VaultError("synthetic promotion failure")

    with monkeypatch.context() as patch:
        patch.setattr(V.VaultSession, "_journaled_promotion", fail)
        session = V.unlock_vault(path, MASTER, upgrade_kdf=True)
        try:
            assert session.last_envelope_upgrade_result["outcome"] == "failed"
            old = _snapshot(path)  # still format 2, no id
            session.save()
            session.save()
            assert V.header_vault_id(path)
        finally:
            session.lock()
    _put_back(path, old)
    _refused(path, live=True)
    _refused(path, live=False)
