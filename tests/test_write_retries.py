"""Vault and settings writes ride out brief Windows file contention (antivirus, indexer, a second writer)."""
from __future__ import annotations

import errno
import os
import threading
import time
from pathlib import Path

import pytest

from localvault import config
from localvault.file_lock import exclusive_writer


def test_a_briefly_refused_replace_is_retried(tmp_path, monkeypatch):
    target = tmp_path / "settings.json"
    real = os.replace
    refusals = [PermissionError(errno.EACCES, "sharing violation"), PermissionError(errno.EACCES, "again")]

    def flaky(src, dst):
        if refusals:
            raise refusals.pop(0)
        return real(src, dst)
    monkeypatch.setattr(config.os, "replace", flaky)
    config.atomic_write_json(target, {"ok": True})
    assert target.read_text(encoding="utf-8") == '{"ok":true}'


def test_a_replace_refused_for_good_still_fails_and_keeps_the_target(tmp_path, monkeypatch):
    target = tmp_path / "settings.json"
    target.write_text("old", encoding="utf-8")
    monkeypatch.setattr(config.os, "replace", lambda s, d: (_ for _ in ()).throw(PermissionError(errno.EACCES, "x")))
    monkeypatch.setattr(config, "REPLACE_RETRY_SECONDS", 0.1)
    with pytest.raises(PermissionError):
        config.atomic_write_json(target, {"new": 1})
    assert target.read_text(encoding="utf-8") == "old"
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]  # no temporary left behind


def test_the_writer_lock_waits_for_a_short_holder(tmp_path):
    path = tmp_path / "vault.json"
    released = threading.Event()

    def hold():
        with exclusive_writer(path):
            time.sleep(0.3)
        released.set()
    thread = threading.Thread(target=hold)
    thread.start()
    time.sleep(0.05)
    with exclusive_writer(path):  # used to fail at once
        assert released.is_set()
    thread.join()


def test_the_writer_lock_still_refuses_a_long_holder(tmp_path, monkeypatch):
    import localvault.file_lock as file_lock

    monkeypatch.setattr(file_lock, "LOCK_WAIT_SECONDS", 0.2)
    path = tmp_path / "vault.json"
    entered = threading.Event()
    done = threading.Event()

    def hold():
        with exclusive_writer(path):
            entered.set()
            done.wait(5)
    thread = threading.Thread(target=hold)
    thread.start()
    entered.wait(2)
    try:
        with pytest.raises(OSError):
            with exclusive_writer(path):
                pass
    finally:
        done.set()
        thread.join()
