"""Audit 2026-11-10: the duress hold survives a deleted hold file and a clock moved forward.

The hold record carries a monotonic anchor (``mono``, ``boot``): it ends only once the wall clock has passed
``until`` and the monotonic clock has counted the whole hold; after a restart only the time since then counts.
A copy of the record is kept outside the vault folder (``outside_marks``; the in-memory store from
tests/conftest.py here, never the real registry), and the vault is held while either copy says so.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from localvault import duress, outside_marks

HOURS = 6
LENGTH = HOURS * 3600
T0 = 1_800_000_000


@pytest.fixture
def boot(monkeypatch):
    """[boot id, monotonic seconds] of a fake clock."""
    clock = ["boot-1", 5000]
    monkeypatch.setattr(duress, "_boot_clock", lambda: (clock[0], clock[1]))
    return clock


@pytest.fixture
def path(tmp_path):
    return tmp_path / "profile" / "vault.json"


def _decoy(hours: int = HOURS):
    return SimpleNamespace(_read_prefs=lambda: {duress.DECOY_PREF: {"hours": hours}})


def _trip(path, now: int = T0) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    return duress.trip(path, _decoy(), now=now)


def test_the_record_carries_the_anchor_in_both_copies(path, boot, outside_marks_store) -> None:
    assert _trip(path) == T0 + LENGTH
    record = json.loads(duress.hold_path(path).read_text(encoding="utf-8"))
    assert record == {"version": 1, "since": T0, "until": T0 + LENGTH, "mono": 5000, "boot": "boot-1"}
    assert json.loads(outside_marks_store.values[duress._hold_mark(path)]) == record


def test_moving_the_clock_forward_does_not_end_the_hold(path, boot) -> None:
    _trip(path)
    boot[1] += 60  # one minute really passed; the date says a week
    later = T0 + 7 * 24 * 3600
    assert duress.held_until(path, now=later) == later + LENGTH - 60
    assert duress.release(path, now=later) is None and duress.hold_path(path).exists()
    boot[1] += LENGTH - 60
    assert duress.held_until(path, now=later) is None
    assert duress.release(path, now=later) == T0


def test_moving_the_clock_back_makes_it_longer(path, boot) -> None:
    _trip(path)
    boot[1] += LENGTH + 1
    assert duress.held_until(path, now=T0 + 10) == T0 + LENGTH


def test_a_restart_lengthens_never_shortens(path, boot) -> None:
    _trip(path)
    boot[1] += 3600
    # Restart: a new boot, its clock from zero.  Two hours of wall time passed, the new boot is 10 minutes old.
    boot[0], boot[1] = "boot-2", 600
    assert duress.held_until(path, now=T0 + 2 * 3600) == T0 + 2 * 3600 + LENGTH - 600
    # Only the time since the restart counts, even once the wall clock is past "until".
    assert duress.held_until(path, now=T0 + LENGTH + 1) == T0 + LENGTH + 1 + LENGTH - 600
    boot[1] = LENGTH
    assert duress.held_until(path, now=T0 + LENGTH + 1) is None


def test_a_clock_below_the_anchor_counts_as_a_restart(path, boot) -> None:
    _trip(path)
    boot[0], boot[1] = None, 100  # boot id unknown, clock went back: restarted
    assert duress.held_until(path, now=T0 + LENGTH + 1) == T0 + LENGTH + 1 + LENGTH - 100


def test_another_boot_counts_no_more_than_the_wall_clock(path, boot) -> None:
    _trip(path)
    # Another boot id while the tick count carried on (Fast Startup): 60 s really passed.
    boot[0], boot[1] = "boot-2", 5000 + 60
    assert duress.held_until(path, now=T0 + 60) == T0 + LENGTH
    assert duress._monotonic_remaining(LENGTH, 5000, "boot-1", "boot-2", 5060, 60) == LENGTH - 60
    # A genuine reboot long ago (uptime 2 h, wall says 3 h since the trip) counts the uptime.
    assert duress._monotonic_remaining(LENGTH, 5000, "boot-1", "boot-2", 7200, 3 * 3600) == LENGTH - 7200


def test_deleting_the_hold_file_does_not_end_the_hold(path, boot, outside_marks_store) -> None:
    _trip(path)
    duress.hold_path(path).unlink()
    assert duress.real_held(path, T0 + 60)
    assert duress.release(path, now=T0 + 60) is None
    boot[1] += LENGTH
    assert not duress.real_held(path, T0 + LENGTH)
    assert duress.release(path, now=T0 + LENGTH) == T0  # "when" comes from the outside copy
    assert duress._hold_mark(path) not in outside_marks_store.values


def test_editing_either_copy_alone_does_not_end_it(path, boot, outside_marks_store) -> None:
    _trip(path)
    forged = {"version": 1, "since": 0, "until": 1}
    outside_marks_store.values[duress._hold_mark(path)] = json.dumps(forged)
    assert duress.real_held(path, T0 + 60)
    _trip(path)  # both copies again
    duress.hold_path(path).write_text(json.dumps(forged), encoding="utf-8")
    assert duress.real_held(path, T0 + 60)


def test_an_unreadable_or_malformed_outside_copy_leaves_it_to_the_file(path, boot, outside_marks_store) -> None:
    _trip(path)
    boot[1] += LENGTH
    outside_marks_store.values[duress._hold_mark(path)] = "not json"
    assert not duress.real_held(path, T0 + LENGTH)
    outside_marks_store.fail_reads = True
    assert not duress.real_held(path, T0 + LENGTH)
    assert duress.release(path, now=T0 + LENGTH) == T0


def test_a_record_without_an_anchor_keeps_the_wall_clock_rule(path, boot) -> None:
    path.parent.mkdir(parents=True)
    duress.atomic_write_json(duress.hold_path(path), {"version": 1, "since": T0, "until": T0 + LENGTH})
    assert duress.real_held(path, T0 + LENGTH - 1)
    assert not duress.real_held(path, T0 + LENGTH)


def test_a_hold_file_that_cannot_be_written_still_holds(path, boot, monkeypatch) -> None:
    def refuse(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(duress, "atomic_write_json", refuse)
    with pytest.raises(OSError):
        _trip(path)
    assert not duress.hold_path(path).exists()
    assert duress.real_held(path, T0 + 60)


def test_no_outside_store_keeps_the_file_rule(path, boot) -> None:
    previous = outside_marks.set_backend(None)
    try:
        _trip(path)
        assert duress.real_held(path, T0 + 60)
        boot[1] += LENGTH
        assert duress.release(path, now=T0 + LENGTH) == T0
    finally:
        outside_marks.set_backend(previous)


def test_a_later_trip_never_shortens_a_monotonic_hold(path, boot) -> None:
    _trip(path)
    boot[1] += 60
    later = T0 + 7 * 24 * 3600  # the clock was moved forward
    until = duress.trip(path, _decoy(1), now=later)
    assert until == later + LENGTH - 60
    boot[1] += 3600
    assert duress.real_held(path, later + 3600)


def _real_vault(path) -> None:
    from localvault.vault import create_vault

    path.parent.mkdir(parents=True, exist_ok=True)
    create_vault(path, "real master password 1",
                 kdf_overrides={"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1}).lock()


def test_a_copy_at_another_path_without_the_hold_file_is_still_held(path, boot, outside_marks_store,
                                                                     tmp_path) -> None:
    """Design decision 2026-11-12: the outside copy is also kept per vault id, so moving the folder to a new path
    and deleting the hold file does not end the hold."""
    import shutil

    _real_vault(path)
    _trip(path)
    moved = tmp_path / "moved"
    shutil.copytree(path.parent, moved)
    duress.hold_path(moved / "vault.json").unlink()
    assert duress.real_held(moved / "vault.json", T0 + 60)
    assert duress.release(moved / "vault.json", now=T0 + 60) is None
    boot[1] += LENGTH
    assert not duress.real_held(moved / "vault.json", T0 + LENGTH)
    assert duress.release(path, now=T0 + LENGTH) == T0
    # both outside copies removed (the vault's rollback marks stay)
    assert not [name for name in outside_marks_store.values if not name.startswith("rollback-mark")]
