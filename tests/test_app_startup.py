"""Stage 6b: startup parity — the legacy-data prompt and decrypted-copy cleanup."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from localvault.api.result import ApiError
from localvault.app.controller import WebController
from localvault.app.documents import DocumentService
from localvault.app.startup import StartupService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"


class Bus:
    def emit(self, name, detail):
        pass


class Sched:
    def __init__(self):
        self.calls = []

    def call_later(self, delay, fn):
        self.calls.append((delay, fn))
        return fn

    def cancel(self, handle):
        pass


def _controller(profiles, sched=None):
    return WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                         scheduler=sched or Sched(), create_kwargs={"kdf_overrides": KDF})


def test_legacy_prompt_comes_before_any_profile(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    profiles = ProfileManager(tmp_path / "data")
    calls = []
    startup = StartupService(profiles, required=lambda: True, importer=lambda: calls.append("import") or "p",
                             fresh=lambda: calls.append("fresh"), location=lambda: tmp_path / "old")
    controller = _controller(profiles)
    controller.startup = startup
    state = controller.state()
    assert state["state"] == "legacy" and state["legacy"]["location"].endswith("old")
    assert profiles.list_profiles() == []
    with pytest.raises(ApiError):
        controller.create(MASTER, MASTER)
    startup.fresh()
    assert calls == ["fresh"] and profiles.list_profiles() and controller.state()["state"] != "legacy"
    with pytest.raises(ApiError):
        startup.fresh()  # decided once


def test_legacy_import_error_keeps_the_prompt(tmp_path):
    profiles = ProfileManager(tmp_path / "data")

    def boom():
        from localvault.migration import MigrationError
        raise MigrationError("No legacy LocalVaultPrototype vault was found")

    startup = StartupService(profiles, required=lambda: True, importer=boom, fresh=lambda: None,
                             location=lambda: tmp_path)
    with pytest.raises(ApiError) as failed:
        startup.import_legacy()
    assert failed.value.message == "Legacy data could not be imported.\n\nNo legacy LocalVaultPrototype vault was found"
    assert startup.pending is True


def test_lock_sweep_retries_while_copies_remain_and_stops_after_unlock(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    sched = Sched()
    controller = _controller(profiles, sched)
    controller.create(MASTER, MASTER)
    left = [[tmp_path / "busy.pdf"]]
    monkeypatch.setattr("localvault.app.documents.cleanup_open_copies", lambda d: left[0])
    DocumentService(controller, SimpleNamespace(), SimpleNamespace())
    sched.calls.clear()
    controller.lock()
    retries = [fn for delay, fn in sched.calls if delay == 30]
    assert len(retries) == 1
    retries[0]()  # still in use: schedules another try
    assert len([1 for delay, _ in sched.calls if delay == 30]) == 2
    controller.unlock(MASTER)
    sched.calls.clear()
    left[0] = []
    [fn for delay, fn in sched.calls if delay == 30]
    retries[0]()  # an old retry after a new unlock does nothing more
    assert [1 for delay, _ in sched.calls if delay == 30] == []


# ------------------------------------------------- review fix: real files, real order
def _legacy_tree(tmp_path):
    from localvault.vault import create_vault

    root, legacy = tmp_path / "LocalGateKeys", tmp_path / "Legacy"
    legacy.mkdir()
    create_vault(legacy / "vault.json", MASTER, kdf_overrides=KDF).lock()
    return root, legacy


def test_prompt_appears_with_real_files_and_nothing_is_written_first(tmp_path):
    from localvault.app.startup import prepare_startup

    root, legacy = _legacy_tree(tmp_path)
    startup, profiles = prepare_startup(root=root, legacy_root=legacy)
    assert startup.pending is True
    assert not (root / "profiles.json").exists()
    assert profiles.list_profiles() == [] and profiles.active_profile() is None
    with pytest.raises(ApiError) as pending:
        profiles.create_profile("Sneaky")
    assert pending.value.code == "legacy_pending"
    startup.fresh()
    assert (root / "profiles.json").exists() and profiles.active_profile() is not None
    assert (legacy / "vault.json").exists()  # the original is untouched


def test_real_legacy_import_creates_the_imported_profile(tmp_path):
    from localvault.app.startup import prepare_startup

    root, legacy = _legacy_tree(tmp_path)
    startup, profiles = prepare_startup(root=root, legacy_root=legacy)
    startup.import_legacy()
    record = profiles.active_profile()
    assert record is not None and profiles.vault_path(record.id).exists()


def test_no_prompt_without_legacy_data(tmp_path):
    from localvault.app.startup import prepare_startup

    startup, profiles = prepare_startup(root=tmp_path / "LocalGateKeys", legacy_root=tmp_path / "none")
    assert startup.pending is False and profiles.active_profile() is not None


def test_lock_sweep_keeps_the_profile_it_locked(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    profiles = ProfileManager(tmp_path / "data")
    first = profiles.ensure_profile()
    sched = Sched()
    controller = _controller(profiles, sched)
    controller.create(MASTER, MASTER)
    swept = []
    monkeypatch.setattr("localvault.app.documents.cleanup_open_copies", lambda d: swept.append(d) or [d])
    DocumentService(controller, SimpleNamespace(), SimpleNamespace())
    controller.lock()
    second = profiles.create_profile("Second")
    controller.select_profile(second.id)
    [fn for delay, fn in sched.calls if delay == 30][-1]()
    assert all(path == profiles.profile_dir(first.id) for path in swept)
