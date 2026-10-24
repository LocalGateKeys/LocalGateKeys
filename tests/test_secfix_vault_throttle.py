"""L-13 (audit 2026-10-24): deleting the throttle counter file must not reset failed attempts."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from localvault import vault as V
from localvault.config import atomic_write_json, read_json

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


def test_deleting_the_counter_file_fails_closed(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "vault.json"
    V.create_vault(path, MASTER, kdf_overrides=LOW).lock()
    _fail(path, 7, clock)
    V._unlock_throttle_path(path).unlink()
    V._reset_unlock_throttle_state_for_tests()  # app restart
    assert V.UnlockThrottle(path).failures >= V.THROTTLE_FREE_ATTEMPTS
    assert V.remaining_backoff_seconds(path) > 0


def test_success_keeps_a_macd_zero_record(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "vault.json"
    V.create_vault(path, MASTER, kdf_overrides=LOW).lock()
    _fail(path, 2, clock)
    V.unlock_vault(path, MASTER).lock()
    state = read_json(V._unlock_throttle_path(path))
    assert state["failures"] == 0 and state["mac"]
    V._reset_unlock_throttle_state_for_tests()
    assert V.remaining_backoff_seconds(path) == 0.0
    # ... and deleting that zero record is still detected.
    V._unlock_throttle_path(path).unlink()
    V._reset_unlock_throttle_state_for_tests()
    assert V.remaining_backoff_seconds(path) > 0


def test_fresh_vault_without_failures_has_no_throttle_files(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    V.create_vault(path, MASTER, kdf_overrides=LOW).lock()
    V.unlock_vault(path, MASTER).lock()
    assert not V._unlock_throttle_path(path).exists()
    assert not V._unlock_throttle_key_path(path).exists()
    assert V.remaining_backoff_seconds(path) == 0.0


def test_legacy_key_without_counter_is_not_locked_out_and_is_upgraded(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "vault.json"
    V.create_vault(path, MASTER, kdf_overrides=LOW).lock()
    _fail(path, 1, clock)
    # A release before the fix: version 1 key, counter deleted by a successful unlock.
    key_path = V._unlock_throttle_key_path(path)
    record = read_json(key_path)
    record["version"] = 1
    atomic_write_json(key_path, record)
    V._unlock_throttle_path(path).unlink()
    V._reset_unlock_throttle_state_for_tests()
    assert V.remaining_backoff_seconds(path) == 0.0
    V.unlock_vault(path, MASTER).lock()
    assert read_json(key_path)["version"] == 2
    assert read_json(V._unlock_throttle_path(path))["failures"] == 0


def test_unreadable_key_is_replaced_at_reset(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "vault.json"
    V.create_vault(path, MASTER, kdf_overrides=LOW).lock()
    _fail(path, 1, clock)
    key_path = V._unlock_throttle_key_path(path)
    key_path.write_text(json.dumps({"version": 2, "key": "not base64!"}), encoding="utf-8")
    V._reset_unlock_throttle_state_for_tests()
    assert V.remaining_backoff_seconds(path) > 0  # unverifiable counter: fails closed
    clock.now += V.THROTTLE_MAX_SECONDS
    V.unlock_vault(path, MASTER).lock()  # e.g. a profile copied to another Windows account
    V._reset_unlock_throttle_state_for_tests()
    assert V.remaining_backoff_seconds(path) == 0.0
