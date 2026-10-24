"""Audit 2026-10-18: lock() waits for a running save (H1); the free item limit fails closed (M8)."""
from __future__ import annotations

import threading

import pytest

from localvault import licensing, vault
from localvault.app.controller import WebController
from localvault.app.licence import LicenceService
from localvault.profiles import ProfileManager
from localvault.settings import AppSettings
from localvault.vault import VaultLockedError, create_vault, unlock_vault

KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
MASTER = "correct horse battery"


def _pause_before_encrypt(monkeypatch, session):
    """Block the save of ``session``'s payload right before its plaintext is encrypted."""
    entered, release = threading.Event(), threading.Event()
    target = session._payload
    # The save serialises the payload into a zeroable buffer (_canonical_json_buffer)
    # immediately before AES-GCM encryption.
    real = vault._canonical_json_buffer

    def paused(value):
        if value is target and not entered.is_set():
            entered.set()
            assert release.wait(10), "test never released the save"
        return real(value)

    monkeypatch.setattr(vault, "_canonical_json_buffer", paused)
    return entered, release


def _run(fn, errors):
    def body():
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001 - reported to the test thread
            errors.append(exc)
    thread = threading.Thread(target=body, daemon=True)
    thread.start()
    return thread


@pytest.fixture
def session(tmp_path):
    session = create_vault(tmp_path / "vault.json", MASTER, kdf_overrides=KDF)
    yield session
    session.lock()


def test_lock_waits_for_a_save_paused_before_encryption(session, monkeypatch):
    entered, release = _pause_before_encrypt(monkeypatch, session)
    save_errors, lock_errors = [], []
    saver = _run(lambda: session.item_service.create_note("Router", "wifi codes inside"), save_errors)
    assert entered.wait(10)
    locker = _run(session.lock, lock_errors)
    locker.join(0.3)
    assert locker.is_alive(), "lock() must wait for the running save"
    assert session._key is not None and any(session._key)
    release.set()
    saver.join(10)
    locker.join(10)
    assert not saver.is_alive() and not locker.is_alive()
    assert save_errors == [] and lock_errors == []
    assert session._key is None and session._payload is None

    reopened = unlock_vault(session.path, MASTER)
    try:
        assert [item["title"] for item in reopened.item_service.list_items()] == ["Router"]
    finally:
        reopened.lock()


def test_lock_waits_for_a_transaction_on_another_thread(session):
    inside, release = threading.Event(), threading.Event()
    errors, lock_errors = [], []

    def work():
        with session.transaction():
            session.item_service.create_note("One", "first")
            inside.set()
            assert release.wait(10)
            session.item_service.create_note("Two", "second")

    worker = _run(work, errors)
    assert inside.wait(10)
    locker = _run(session.lock, lock_errors)
    locker.join(0.3)
    assert locker.is_alive(), "lock() must wait for the open transaction"
    release.set()
    worker.join(10)
    locker.join(10)
    assert errors == [] and lock_errors == []
    assert session._payload is None

    reopened = unlock_vault(session.path, MASTER)
    try:
        assert sorted(item["title"] for item in reopened.item_service.list_items()) == ["One", "Two"]
    finally:
        reopened.lock()


def test_save_after_lock_raises_locked_and_writes_nothing(session):
    before = session.path.read_bytes()
    session.lock()
    with pytest.raises(VaultLockedError):
        session.save()
    assert session.path.read_bytes() == before


def test_transaction_rollback_after_lock_leaves_no_payload(session):
    with pytest.raises(RuntimeError):
        with session.transaction():
            session.item_service.create_note("Draft", "never committed")
            session.lock()
            raise RuntimeError("caller failed after the lock")
    assert session._payload is None
    assert not session.is_unlocked


def test_transaction_commit_after_lock_raises_locked(session):
    before = session.path.read_bytes()
    with pytest.raises(VaultLockedError):
        with session.transaction():
            session.item_service.create_note("Draft", "never committed")
            session.lock()
    assert session._payload is None
    assert session.path.read_bytes() == before


# ------------------------------------------------------------------ M8
class Bus:
    def emit(self, name, detail):
        pass


class Sched:
    def call_later(self, delay, fn):
        return fn

    def cancel(self, handle):
        pass


@pytest.fixture
def controller(tmp_path, monkeypatch):
    monkeypatch.setattr("localvault.app.controller.clear_master_unlock_requirement", lambda pid: None)
    monkeypatch.setattr(AppSettings, "save", lambda self, path=None: None)
    profiles = ProfileManager(tmp_path / "data")
    profiles.ensure_profile()
    controller = WebController(profiles=profiles, settings=AppSettings(idle_source="vault"), bus=Bus(),
                               scheduler=Sched(), create_kwargs={"kdf_overrides": KDF})
    yield controller
    controller.lock()


def _limit_seen_by_first_hook(controller):
    seen = []
    controller.on_unlock.insert(0, lambda: seen.append(controller.session.item_limit))
    return seen


def test_finish_publishes_the_session_with_the_free_limit(controller, monkeypatch):
    monkeypatch.setattr(licensing, "status", lambda *a, **k: licensing.LicenseStatus("free", None, ""))
    seen = _limit_seen_by_first_hook(controller)
    controller.create(MASTER, MASTER)
    assert seen == [licensing.FREE_ITEM_LIMIT]
    controller.lock()
    controller.unlock(MASTER)
    assert seen == [licensing.FREE_ITEM_LIMIT] * 2


def test_finish_fails_closed_when_the_licence_cannot_be_read(controller, monkeypatch):
    def broken(*a, **k):
        raise OSError("licence file unreadable")

    monkeypatch.setattr(licensing, "status", broken)
    seen = _limit_seen_by_first_hook(controller)
    controller.create(MASTER, MASTER)
    assert seen == [licensing.FREE_ITEM_LIMIT]


def test_pro_licence_still_unlocks_unlimited(controller, monkeypatch):
    monkeypatch.setattr(licensing, "status", lambda *a, **k: licensing.LicenseStatus("pro", None, ""))
    monkeypatch.setattr(licensing, "reconcile_vault_copy", lambda session: None)
    seen = _limit_seen_by_first_hook(controller)
    LicenceService(controller, port=None, dialogs=None)
    controller.create(MASTER, MASTER)
    assert seen == [None]
    assert controller.session.item_limit is None


def test_after_unlock_with_a_stale_lease_still_applies_the_limit(controller, monkeypatch):
    monkeypatch.setattr(licensing, "status", lambda *a, **k: licensing.LicenseStatus("free", None, ""))
    monkeypatch.setattr(licensing, "reconcile_vault_copy", lambda session: pytest.fail("must not reconcile"))
    controller.create(MASTER, MASTER)
    service = LicenceService(controller, port=None, dialogs=None)
    controller.session.item_limit = None  # e.g. a Pro limit before the licence was removed

    def stale(lease):
        raise vault.VaultError("stale")

    monkeypatch.setattr(controller, "require_lease", stale)
    service.after_unlock()
    assert controller.session.item_limit == licensing.FREE_ITEM_LIMIT
