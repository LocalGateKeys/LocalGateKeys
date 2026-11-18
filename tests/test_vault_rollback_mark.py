"""Known-limitations plan, item 1: rollback detection without sync.

The anchor beside the vault cannot tell an older vault+anchor pair copied back from the real one, so every
committed generation is also recorded outside the folder (``outside_marks``; HKCU on Windows).  These tests use
the in-memory store from tests/conftest.py, never the real registry.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from localvault import duress, outside_marks
from localvault import vault as V
from localvault.backup import (
    export_encrypted_backup,
    export_full_backup,
    restore_full_backup,
    restore_verified_backup,
)
from localvault.config import atomic_write_json
from localvault.i18n import t

LOW = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
MASTER = "correct horse battery staple"
DURESS = "orange tractor sunset meadow"
BACKUP_PASSWORD = "synthetic backup container password"
FILES = ("vault.json", "vault.generation.json")


@pytest.fixture(autouse=True)
def _fresh_throttle():
    V._reset_unlock_throttle_state_for_tests()
    yield
    V._reset_unlock_throttle_state_for_tests()


def _vault(tmp_path: Path, folder: str = "profile") -> Path:
    path = tmp_path / folder / "vault.json"
    path.parent.mkdir(parents=True)
    V.create_vault(path, MASTER, kdf_overrides=LOW).lock()
    return path


def _commit(path: Path, times: int = 1) -> None:
    session = V.unlock_vault(path, MASTER)
    try:
        for _ in range(times):
            session.save()
    finally:
        session.lock()


def _live(path: Path, password: str = MASTER) -> V.VaultSession:
    """The app's own password unlock of the live vault (controller -> duress.open_vault -> upgrade_kdf=True)."""
    return V.unlock_vault(path, password, upgrade_kdf=True)


def _snapshot(path: Path) -> dict[str, bytes]:
    return {name: (path.parent / name).read_bytes() for name in FILES}


def _put_back(path: Path, snapshot: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    for name, data in snapshot.items():
        (path.parent / name).write_bytes(data)


def _generation(path: Path) -> int:
    return int(json.loads(path.read_bytes())["generation"])


def _names(path: Path) -> tuple[str, str]:
    vault_id = V.header_vault_id(path)
    assert vault_id
    return (outside_marks.name_for(V._ROLLBACK_MARK_PURPOSE, path),
            outside_marks.name_for_id(V._ROLLBACK_ID_MARK_PURPOSE, vault_id))


def _marks(session: V.VaultSession, path: Path | None = None) -> tuple[V._RollbackMark, V._RollbackMark]:
    """Both marks as this session's data key reads them (for ``path``, default the session's)."""
    path = Path(path or session.path)
    vault_id = str(session._header["vault_id"])
    key = V._rollback_anchor_key(session._key)
    try:
        return (V._read_rollback_mark(outside_marks.name_for(V._ROLLBACK_MARK_PURPOSE, path), "path", key,
                                      vault_id, path),
                V._read_rollback_mark(outside_marks.name_for_id(V._ROLLBACK_ID_MARK_PURPOSE, vault_id), "id", key,
                                      vault_id, path))
    finally:
        V._zero(key)


def _refused(path: Path, *, live: bool = False) -> None:
    with pytest.raises(V.VaultError) as caught:
        V.unlock_vault(path, MASTER, upgrade_kdf=live)
    # The mark's own message: unlike the anchor's, it says how to go back to an older state on purpose.
    assert str(caught.value) == t("vault.err.rollbackMarkOlder", restore=t("command.backup-restore.title"))
    assert t("vault.err.rollbackMarkOlder") != t("vault.err.rollbackOlder")
    assert t("command.backup-restore.title") in str(caught.value)


def test_the_tests_never_use_the_real_registry(outside_marks_store) -> None:
    assert outside_marks.backend() is outside_marks_store
    assert isinstance(outside_marks_store, outside_marks.MemoryBackend)


def test_every_save_and_unlock_raise_both_marks(tmp_path: Path, outside_marks_store) -> None:
    path = _vault(tmp_path)
    assert set(_names(path)) <= set(outside_marks_store.values)
    _commit(path, 2)
    session = _live(path)
    try:
        path_mark, id_mark = _marks(session)
        assert path_mark.state == id_mark.state == "ok"
        assert path_mark.generation == id_mark.generation == _generation(path) == 3
        assert id_mark.place == V._mark_place(path)
    finally:
        session.lock()


def test_the_marks_name_no_folder_and_are_sealed_when_dpapi_is_there(tmp_path: Path, outside_marks_store) -> None:
    path = _vault(tmp_path)
    for name in _names(path):
        assert "profile" not in name
        record = json.loads(outside_marks_store.values[name])
        if V._dpapi() is not None:
            assert set(record) == {"dpapi"}
        else:
            assert record["generation"] == 1 and "profile" not in record["place"]


class _CountingRandom:
    """Stands in for ``os.urandom`` (and ``random._urandom``, which ``secrets`` uses) and counts what is drawn."""

    def __init__(self, real) -> None:
        self.real, self.taken = real, 0

    def __call__(self, count: int) -> bytes:
        self.taken += count
        return self.real(count)


def test_raising_a_mark_draws_nothing_from_the_random_source(tmp_path: Path, monkeypatch,
                                                             outside_marks_store) -> None:
    """A mark must not change any vault or backup bytes: a random draw would shift every later byte of a seeded
    stream (scripts/gen_mac_backup_vectors.py replays one), so the place nonce is derived, never drawn."""
    import random

    path = _vault(tmp_path)
    session = V.unlock_vault(path, MASTER)
    vault_id = str(session._header["vault_id"])
    key, other = V._rollback_anchor_key(session._key), V._rollback_anchor_key(b"\x07" * 32)
    counter = _CountingRandom(os.urandom)
    monkeypatch.setattr(os, "urandom", counter)
    monkeypatch.setattr(random, "_urandom", counter)
    try:
        outside_marks_store.values.clear()  # every value sealed again from scratch
        V._raise_rollback_marks(path, 5, key, vault_id)
        V._raise_rollback_marks(path, 6, key, vault_id, exact=True, previous_key=other)
        V._raise_rollback_marks(path, 7, key, vault_id, exact=True, retired_key=other)
        V._raise_rollback_marks(path, 8, key, vault_id)
        assert V._check_rollback_marks(path, 8, key, vault_id, live=True) == (True, False)
        assert counter.taken == 0
        assert _marks(session)[1].place == V._mark_place(path)
        # End to end: a save takes exactly as many random bytes with the marks store as without one.
        session.save()
        with_marks, counter.taken = counter.taken, 0
        previous = outside_marks.set_backend(None)
        try:
            session.save()
        finally:
            outside_marks.set_backend(previous)
        assert with_marks > 0 and counter.taken == with_marks
    finally:
        V._zero(key)
        V._zero(other)
        session.lock()


def test_an_older_vault_and_anchor_put_back_are_refused(tmp_path: Path) -> None:
    path = _vault(tmp_path)
    old = _snapshot(path)
    _commit(path, 2)
    _put_back(path, old)
    # The anchor alone is satisfied: the pair matches.
    assert V._read_generation_anchor(path)[0] == _generation(path) == 1
    _refused(path)
    _refused(path, live=True)


def test_an_older_pair_is_refused_after_the_folder_is_moved(tmp_path: Path) -> None:
    path = _vault(tmp_path)
    old = _snapshot(path)
    _commit(path, 2)
    moved = tmp_path / "moved" / "vault.json"
    shutil.move(str(path.parent), str(moved.parent))
    _put_back(moved, old)  # the older pair at the new place, before the first unlock there
    _refused(moved, live=True)


def test_a_moved_folder_opens_and_its_new_path_is_marked(tmp_path: Path) -> None:
    path = _vault(tmp_path)
    old = _snapshot(path)
    _commit(path, 2)
    moved = tmp_path / "moved" / "vault.json"
    shutil.move(str(path.parent), str(moved.parent))
    session = _live(moved)
    try:
        assert session.rollback_anchor_missing is False
        path_mark, id_mark = _marks(session)
        assert path_mark.generation == id_mark.generation == 3 and id_mark.place == V._mark_place(moved)
    finally:
        session.lock()
    _put_back(moved, old)
    _refused(moved)


def test_a_second_live_copy_is_flagged_not_refused(tmp_path: Path) -> None:
    """Two live copies of one vault id (a backup restored as a second profile): the older one still opens."""
    path = _vault(tmp_path)
    copy = tmp_path / "copy" / "vault.json"
    shutil.copytree(path.parent, copy.parent)
    _commit(path, 2)
    session = _live(copy)
    try:
        assert session.rollback_anchor_missing is True
    finally:
        session.lock()
    _live(path).lock()  # the original is unaffected


def test_a_private_copy_opened_elsewhere_is_neither_refused_nor_marked(tmp_path: Path, outside_marks_store) -> None:
    path = _vault(tmp_path)
    old = _snapshot(path)
    _commit(path, 2)
    before = dict(outside_marks_store.values)
    copy = tmp_path / "check" / "vault.json"
    copy.parent.mkdir()
    copy.write_bytes(old["vault.json"])  # a restore's or a check's copy: no anchor beside it
    session = V.unlock_vault(copy, MASTER)
    try:
        session.save()
    finally:
        session.lock()
    assert outside_marks_store.values == before


def test_a_missing_mark_is_minted_again_quietly(tmp_path: Path, outside_marks_store) -> None:
    path = _vault(tmp_path)
    old = _snapshot(path)
    _commit(path, 2)
    outside_marks_store.values.clear()
    session = _live(path)
    try:
        assert session.rollback_anchor_missing is False
    finally:
        session.lock()
    assert set(_names(path)) <= set(outside_marks_store.values)
    _put_back(path, old)
    _refused(path)


def test_a_vault_from_before_the_marks_opens(tmp_path: Path, outside_marks_store) -> None:
    """Upgrade: a vault and anchor with no mark at all open with every unlock, the live one mints the marks."""
    path = _vault(tmp_path)
    _commit(path, 2)
    outside_marks_store.values.clear()
    V.unlock_vault(path, MASTER).lock()
    V.unlock_vault(path, MASTER, upgrade_envelope=False).lock()
    assert outside_marks_store.values == {}
    _live(path).lock()
    assert set(_names(path)) <= set(outside_marks_store.values)


@pytest.mark.parametrize("which", ["path", "id", "both"])
@pytest.mark.parametrize("kind", ["garbage", "not-ours", "wrong-shape"])
def test_a_mark_that_does_not_authenticate_never_refuses_and_is_replaced(tmp_path: Path, outside_marks_store,
                                                                         which: str, kind: str) -> None:
    """Whoever can write a forged mark can also delete it: refusing on it would only lock owners out."""
    path = _vault(tmp_path)
    _commit(path, 1)
    vault_id = V.header_vault_id(path)
    path_name, id_name = _names(path)
    foreign_key = os.urandom(32)
    for name, mark_kind in ((path_name, "path"), (id_name, "id")):
        if which not in (mark_kind, "both"):
            continue
        outside_marks_store.values[name] = {
            "garbage": "not json",
            "not-ours": V._rollback_mark_value(foreign_key, mark_kind, 999, vault_id, path),
            "wrong-shape": json.dumps({"generation": 999, "place": "x", "mac": "AAAA"}),
        }[kind]
    session = _live(path)
    try:
        path_mark, id_mark = _marks(session)
        assert path_mark.state == id_mark.state == "ok" and path_mark.generation == id_mark.generation == 2
    finally:
        session.lock()


def test_a_new_vault_in_the_same_folder_is_not_refused_by_the_old_ones_marks(tmp_path: Path) -> None:
    path = _vault(tmp_path)
    _commit(path, 5)
    for name in FILES:
        (path.parent / name).unlink()
    V.create_vault(path, MASTER, kdf_overrides=LOW).lock()
    _live(path).lock()
    V.unlock_vault(path, MASTER).lock()


def test_a_genuine_higher_mark_refuses_even_without_the_anchor(tmp_path: Path) -> None:
    path = _vault(tmp_path)
    old = _snapshot(path)
    _commit(path, 2)
    _put_back(path, {"vault.json": old["vault.json"]})
    (path.parent / "vault.generation.json").unlink()
    _refused(path)


def test_a_confirmed_restore_lowers_the_marks(tmp_path: Path) -> None:
    path = _vault(tmp_path)
    backup = tmp_path / "old.lgk"
    export_encrypted_backup(backup, vault_file=path, settings_file=None, profile_name="Synthetic",
                            backup_password=BACKUP_PASSWORD, kdf_overrides=LOW)
    _commit(path, 3)
    with pytest.raises(V.RollbackRequiresConfirmation):
        restore_verified_backup(backup, vault_file=path, settings_file=None, backup_password=BACKUP_PASSWORD,
                                vault_password=MASTER, replace=True)
    restore_verified_backup(backup, vault_file=path, settings_file=None, backup_password=BACKUP_PASSWORD,
                            vault_password=MASTER, replace=True, allow_rollback=True)
    restored = _generation(path)
    assert restored < 4
    session = _live(path)
    try:
        path_mark, id_mark = _marks(session)
        assert path_mark.generation == id_mark.generation == restored
    finally:
        session.lock()
    V.unlock_vault(path, MASTER).lock()


def _full_profile(tmp_path: Path) -> Path:
    path = _vault(tmp_path)
    atomic_write_json(path.parent / "settings.json", {})
    return path


def test_a_confirmed_full_restore_in_place_opens(tmp_path: Path) -> None:
    path = _full_profile(tmp_path)
    backup = tmp_path / "old.lgk"
    export_full_backup(backup, profile_dir=path.parent, profile_name="Synthetic", backup_password=BACKUP_PASSWORD)
    _commit(path, 3)
    restore_full_backup(backup, profile_dir=path.parent, backup_password=BACKUP_PASSWORD, vault_password=MASTER,
                        replace=True, allow_rollback=True)
    assert _generation(path) < 4
    _live(path).lock()
    V.unlock_vault(path, MASTER).lock()


def test_a_full_restore_after_the_profile_was_lost_opens(tmp_path: Path) -> None:
    path = _full_profile(tmp_path)
    backup = tmp_path / "old.lgk"
    export_full_backup(backup, profile_dir=path.parent, profile_name="Synthetic", backup_password=BACKUP_PASSWORD)
    _commit(path, 3)
    shutil.rmtree(path.parent)  # the marks stay behind
    restore_full_backup(backup, profile_dir=path.parent, backup_password=BACKUP_PASSWORD, vault_password=MASTER)
    _live(path).lock()
    elsewhere = tmp_path / "new-profile"
    restore_full_backup(backup, profile_dir=elsewhere, backup_password=BACKUP_PASSWORD, vault_password=MASTER)
    _live(elsewhere / "vault.json").lock()


def test_store_failures_never_block_an_unlock_or_a_save(tmp_path: Path, outside_marks_store) -> None:
    path = _vault(tmp_path)
    _commit(path, 1)
    for flag in ("fail_reads", "fail_writes"):
        setattr(outside_marks_store, flag, True)
        try:
            session = _live(path)
            try:
                session.save()
                session.rotate_data_key(MASTER)
            finally:
                session.lock()
            V.unlock_vault(path, MASTER).lock()
        finally:
            setattr(outside_marks_store, flag, False)
    V._reset_unlock_throttle_state_for_tests()
    previous = outside_marks.set_backend(None)  # another platform: no store at all
    try:
        _commit(path, 1)
        _live(path).lock()
    finally:
        outside_marks.set_backend(previous)


def test_check_anchor_false_and_probes_never_read_or_write_a_mark(tmp_path: Path, outside_marks_store) -> None:
    path = _vault(tmp_path)
    old = _snapshot(path)
    _commit(path, 2)
    copy = tmp_path / "probe" / "vault.json"
    _put_back(copy, old)
    calls: list[str] = []

    class Spy(outside_marks.MemoryBackend):
        def read(self, name: str) -> str | None:
            calls.append("read " + name)
            return super().read(name)

        def write(self, name: str, value: str) -> None:
            calls.append("write " + name)
            super().write(name, value)

    spy = Spy()
    spy.values = dict(outside_marks_store.values)
    previous = outside_marks.set_backend(spy)
    try:
        live = V.unlock_vault(path, MASTER)
        calls.clear()
        try:
            header, source = V._read_vault_header(copy)
            probe = V._decrypt_vault(copy, header, source, bytearray(live._key), check_anchor=False)
            probe.save()
            probe.write_rollback_anchor()
            probe.lock()
        finally:
            live.lock()
        V.unlock_vault(copy, MASTER, upgrade_envelope=False).lock()
        assert [call for call in calls if "rollback-mark" in call] == []
    finally:
        outside_marks.set_backend(previous)


def test_the_duress_vault_has_its_own_marks(tmp_path: Path, outside_marks_store) -> None:
    path = _vault(tmp_path)
    real = V.unlock_vault(path, MASTER)
    try:
        second = duress.setup(real, DURESS, lock_hours=6, master_password=MASTER)
    finally:
        real.lock()
    real_marks = {name: outside_marks_store.values[name] for name in _names(path)}
    old_second = _snapshot(second)
    opened = duress.try_open(second, DURESS)
    assert opened is not None
    try:
        opened.save()
        opened.save()
        second_names = set(_names(second))
        assert second_names.isdisjoint(real_marks) and second_names <= set(outside_marks_store.values)
    finally:
        opened.lock()
    assert {name: outside_marks_store.values[name] for name in real_marks} == real_marks
    _put_back(second, old_second)
    assert duress.try_open(second, DURESS) is None  # its own older copy is refused like the real one's
    _live(path).lock()


def _crash_states(monkeypatch: pytest.MonkeyPatch, path: Path, store: outside_marks.MemoryBackend, action):
    """The folder's files and the store as a crash before each write (and after the last) would leave them."""
    states: list[tuple[dict[str, bytes], dict[str, str]]] = []

    def snap() -> None:
        files = {}
        for p in path.parent.iterdir():
            if p.is_file() and p.name.startswith("vault.") and not p.name.endswith(".lock"):
                files[p.name] = p.read_bytes()
        states.append((files, dict(store.values)))

    real_write_json, real_mark_write = V.atomic_write_json, outside_marks.write

    def write_json(target, value, *args, **kwargs):
        snap()
        return real_write_json(target, value, *args, **kwargs)

    def mark_write(name, value):
        snap()
        return real_mark_write(name, value)

    with monkeypatch.context() as patch:
        patch.setattr(V, "atomic_write_json", write_json)
        patch.setattr(outside_marks, "write", mark_write)
        action()
    snap()
    return states


def test_a_rotation_cut_short_at_any_step_still_opens(tmp_path: Path, monkeypatch, outside_marks_store) -> None:
    path = _vault(tmp_path)
    _commit(path, 2)
    session = _live(path)
    try:
        states = _crash_states(monkeypatch, path, outside_marks_store, lambda: session.rotate_data_key(MASTER))
    finally:
        session.lock()
    assert len(states) >= 5
    for files, values in states:
        for leftover in path.parent.iterdir():
            if leftover.is_file() and leftover.name not in files:
                leftover.unlink()
        for name, data in files.items():
            (path.parent / name).write_bytes(data)
        outside_marks_store.values = dict(values)
        V._reset_unlock_throttle_state_for_tests()
        _live(path).lock()
        V.unlock_vault(path, MASTER).lock()


def test_a_copy_from_before_a_rotation_is_still_refused(tmp_path: Path) -> None:
    path = _vault(tmp_path)
    old = _snapshot(path)
    _commit(path, 1)
    session = _live(path)
    try:
        session.change_master_password(MASTER, "a brand new master password")
    finally:
        session.lock()
    _put_back(path, old)  # under the retired data key, opened with the old password
    _refused(path)
    _refused(path, live=True)


def test_a_promotion_rolled_back_from_its_journal_leaves_no_mark_above_the_vault(tmp_path: Path,
                                                                                monkeypatch) -> None:
    """A journaled promotion (format / KDF upgrade) that fails after its save puts the older vault back."""
    import copy

    path = _vault(tmp_path)
    _commit(path, 1)
    before = _generation(path)
    session = _live(path)
    real_unlink = Path.unlink
    failed: list[bool] = []

    def unlink(self, *args, **kwargs):
        if self.name.endswith(".migration.json") and not failed:
            failed.append(True)
            raise OSError("synthetic: journal could not be removed")
        return real_unlink(self, *args, **kwargs)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path, "unlink", unlink)
            with pytest.raises(OSError):
                session._journaled_promotion("kdf-upgrade", copy.deepcopy(session._header),
                                             copy.deepcopy(session._payload), session._catalog_version)
    finally:
        session.lock()
    assert failed and _generation(path) == before
    session = _live(path)
    try:
        path_mark, id_mark = _marks(session)
        assert path_mark.generation == id_mark.generation == before
        session.save()
        path_mark, id_mark = _marks(session)
        assert path_mark.generation == id_mark.generation == before + 1
    finally:
        session.lock()


def test_a_failed_rotation_keeps_the_marks_with_the_old_key(tmp_path: Path, monkeypatch) -> None:
    path = _vault(tmp_path)
    old = _snapshot(path)
    _commit(path, 2)

    def fail(self, header, *, before_save=None):
        raise V.VaultError("synthetic commit failure")

    session = _live(path)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(V.VaultSession, "_commit_header_change", fail)
            with pytest.raises(V.VaultError):
                session.rotate_data_key(MASTER)
        path_mark, id_mark = _marks(session)
        assert path_mark.state == id_mark.state == "ok" and path_mark.settled and id_mark.settled
    finally:
        session.lock()
    _live(path).lock()
    _put_back(path, old)
    _refused(path)


def test_removing_the_duress_vault_deletes_its_marks(tmp_path: Path, outside_marks_store) -> None:
    path = _vault(tmp_path)
    real = V.unlock_vault(path, MASTER)
    second = duress.setup(real, DURESS, lock_hours=6, master_password=MASTER)
    opened = duress.try_open(second, DURESS)
    assert opened is not None
    try:
        opened.save()
    finally:
        opened.lock()
    second_names = set(_names(second))
    assert second_names <= set(outside_marks_store.values)
    real_marks = set(_names(path))
    try:
        removed = duress.remove(real)
        assert removed is True
    finally:
        real.lock()
    assert not second_names & set(outside_marks_store.values)  # nothing left says a second vault existed
    assert set(real_marks) <= set(outside_marks_store.values)  # the real vault keeps its own (raised by the save)
