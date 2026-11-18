"""Audit 2026-11-10: restoring a copy of the vault folder must not reset the unlock back-off.

Every file of the throttle sits in the vault folder, so the count also raises a high-water mark kept outside it
(``outside_marks``; HKCU on Windows).  These tests use the in-memory store from tests/conftest.py, never the
real registry.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from localvault import outside_marks
from localvault import vault as V

LOW = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}
MASTER = "correct horse battery staple"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(V, "_monotonic", fake)
    V._reset_unlock_throttle_state_for_tests()
    yield fake
    V._reset_unlock_throttle_state_for_tests()


def _fail(path: Path, times: int, clock: FakeClock) -> None:
    for _ in range(times):
        clock.now += 100
        with pytest.raises(V.InvalidMasterPassword):
            V.unlock_vault(path, "wrong password attempt")


def _vault(tmp_path: Path) -> Path:
    path = tmp_path / "profile" / "vault.json"
    path.parent.mkdir()
    V.create_vault(path, MASTER, kdf_overrides=LOW).lock()
    return path


def _mark(path: Path) -> str:
    return V.UnlockThrottle(path)._mark_name()


def test_the_tests_never_use_the_real_registry(outside_marks_store) -> None:
    assert outside_marks.backend() is outside_marks_store
    assert isinstance(outside_marks_store, outside_marks.MemoryBackend)


def test_restoring_the_folder_does_not_reset_the_count(tmp_path: Path, clock: FakeClock) -> None:
    path = _vault(tmp_path)
    copy = tmp_path / "copy"
    shutil.copytree(path.parent, copy)  # taken before guessing
    _fail(path, 7, clock)
    shutil.rmtree(path.parent)
    shutil.copytree(copy, path.parent)  # put back: the folder's own counter says 0
    V._reset_unlock_throttle_state_for_tests()  # app restart
    assert V.UnlockThrottle(path)._load_folder_failures() == 0
    assert V.UnlockThrottle(path).failures == 7
    assert V.remaining_backoff_seconds(path) > 0
    with pytest.raises(V.UnlockThrottled):
        V.unlock_vault(path, MASTER)


def test_a_success_clears_both(tmp_path: Path, clock: FakeClock, outside_marks_store) -> None:
    path = _vault(tmp_path)
    _fail(path, 3, clock)
    assert _mark(path) in outside_marks_store.values
    clock.now += 100
    V.unlock_vault(path, MASTER).lock()
    assert _mark(path) not in outside_marks_store.values
    V._reset_unlock_throttle_state_for_tests()
    assert V.UnlockThrottle(path).failures == 0


def test_the_mark_names_no_folder_and_is_sealed_when_dpapi_is_there(tmp_path: Path, clock: FakeClock,
                                                                   outside_marks_store) -> None:
    path = _vault(tmp_path)
    _fail(path, 1, clock)
    name = _mark(path)
    assert name.startswith("unlock-throttle-") and "profile" not in name and len(name) == len("unlock-throttle-") + 32
    record = json.loads(outside_marks_store.values[name])
    if V._dpapi() is not None:
        assert set(record) == {"dpapi"}
    else:
        assert record["failures"] == 1


def test_an_unreadable_store_falls_back_to_the_folder_counter(tmp_path: Path, clock: FakeClock,
                                                              outside_marks_store) -> None:
    path = _vault(tmp_path)
    _fail(path, 6, clock)
    outside_marks_store.fail_reads = True
    V._reset_unlock_throttle_state_for_tests()
    assert V.UnlockThrottle(path).failures == 6  # neither lower nor a lock-out
    clock.now += 1000
    V.unlock_vault(path, MASTER).lock()


def test_a_missing_or_unwritable_store_never_locks_the_owner_out(tmp_path: Path, clock: FakeClock,
                                                                 outside_marks_store) -> None:
    path = _vault(tmp_path)
    outside_marks_store.fail_writes = True
    _fail(path, 2, clock)
    assert not [name for name in outside_marks_store.values if name.startswith("unlock-throttle")]
    V._reset_unlock_throttle_state_for_tests()
    assert V.UnlockThrottle(path).failures == 2
    clock.now += 100
    V.unlock_vault(path, MASTER).lock()
    previous = outside_marks.set_backend(None)  # another platform: no store at all
    try:
        _fail(path, 1, clock)
        clock.now += 100
        V.unlock_vault(path, MASTER).lock()
    finally:
        outside_marks.set_backend(previous)


def test_a_malformed_mark_fails_closed_until_a_success(tmp_path: Path, clock: FakeClock,
                                                       outside_marks_store) -> None:
    path = _vault(tmp_path)
    outside_marks_store.values[_mark(path)] = "not json"
    V._reset_unlock_throttle_state_for_tests()
    assert V.UnlockThrottle(path).failures == V.THROTTLE_FAIL_CLOSED_FAILURES
    with pytest.raises(V.UnlockThrottled):
        V.unlock_vault(path, MASTER)
    clock.now += V.THROTTLE_MAX_SECONDS + 1  # the maximum wait, never a lock-out
    V.unlock_vault(path, MASTER).lock()
    assert _mark(path) not in outside_marks_store.values


def test_a_mark_for_another_location_is_malformed(tmp_path: Path, clock: FakeClock, outside_marks_store) -> None:
    path = _vault(tmp_path)
    outside_marks_store.values[_mark(path)] = json.dumps({"failures": 0, "location": "0" * 32})
    V._reset_unlock_throttle_state_for_tests()
    assert V.UnlockThrottle(path).failures == V.THROTTLE_FAIL_CLOSED_FAILURES


def test_a_stale_process_never_lowers_the_mark(tmp_path: Path, clock: FakeClock) -> None:
    path = _vault(tmp_path)
    throttle = V.UnlockThrottle(path)
    throttle.record_failure()  # this process now counts 1
    V.UnlockThrottle(path)._raise_outside_mark(9)  # another process counted 9 meanwhile
    throttle.record_failure()  # this process: 2
    assert V.UnlockThrottle(path)._outside_failures() == 9
    V._reset_unlock_throttle_state_for_tests()
    assert V.UnlockThrottle(path).failures == 9


def test_name_for_depends_on_purpose_and_path(tmp_path: Path) -> None:
    first = outside_marks.name_for("unlock-throttle", tmp_path / "a" / "vault.json")
    assert first == outside_marks.name_for("unlock-throttle", tmp_path / "a" / "vault.json")
    assert first != outside_marks.name_for("unlock-throttle", tmp_path / "b" / "vault.json")
    assert first.split("-")[-1] != outside_marks.name_for("duress-hold", tmp_path / "a" / "vault.json").split("-")[-1]


def test_oversized_values_are_not_written_and_read_as_malformed(outside_marks_store) -> None:
    assert outside_marks.write("x", "a" * (outside_marks.MAX_VALUE + 1)) is False
    outside_marks_store.values["y"] = "a" * (outside_marks.MAX_VALUE + 1)
    assert outside_marks.read("y") == ""


def test_a_copy_at_another_path_keeps_the_count(tmp_path: Path, clock: FakeClock) -> None:
    """Design decision 2026-11-12: the mark is also kept per vault id (authenticated by the catalog AAD), so a
    copy of the folder taken before guessing and opened from a new path does not start again at zero."""
    path = _vault(tmp_path)
    copy = tmp_path / "copy"
    shutil.copytree(path.parent, copy)  # taken before guessing
    _fail(path, 7, clock)
    moved = tmp_path / "elsewhere"
    shutil.copytree(copy, moved)
    V._reset_unlock_throttle_state_for_tests()
    assert V.UnlockThrottle(moved / "vault.json").failures == 7
    with pytest.raises(V.UnlockThrottled):
        V.unlock_vault(moved / "vault.json", MASTER)
    clock.now += V.THROTTLE_MAX_SECONDS + 1
    V.unlock_vault(moved / "vault.json", MASTER).lock()  # a success clears the id mark too
    V._reset_unlock_throttle_state_for_tests()
    assert V.UnlockThrottle(moved / "vault.json").failures == 0


def test_a_mark_for_another_vault_id_is_malformed(tmp_path: Path, clock: FakeClock, outside_marks_store) -> None:
    path = _vault(tmp_path)
    name = V.UnlockThrottle(path)._id_mark_name()
    assert name is not None and name.startswith("unlock-throttle-id-")
    outside_marks_store.values[name] = json.dumps({"failures": 0, "vault_id": "f" * 32})
    V._reset_unlock_throttle_state_for_tests()
    assert V.UnlockThrottle(path).failures == V.THROTTLE_FAIL_CLOSED_FAILURES
