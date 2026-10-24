"""Decrypted document copies are deleted when the app is done with them, not at the next launch."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from localvault import open_copy_watch as watch
from localvault.attachments import open_copies_dir


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class Process:
    def __init__(self):
        self.alive = True
        self.closed = False

    def running(self):
        return self.alive

    def close(self):
        self.closed = True


def _copy(tmp_path: Path, name="secret.txt") -> Path:
    folder = open_copies_dir(tmp_path) / "abcd1234"
    folder.mkdir(parents=True)
    path = folder / name
    path.write_text("decrypted", encoding="utf-8")
    return path


def test_deleted_as_soon_as_the_launched_app_exits(tmp_path):
    path = _copy(tmp_path)
    process = Process()
    clock = Clock()
    watcher = watch.CopyWatcher(path, process, in_use=lambda p: False, clock=clock)
    assert watcher.step() is False and path.exists()  # the app is still open
    clock.now = 30  # the user worked in it for a while
    process.alive = False
    assert watcher.step() is True
    assert not path.exists() and not path.parent.exists()


def test_an_app_holding_the_file_keeps_it_until_it_lets_go(tmp_path):
    path = _copy(tmp_path)
    busy = [True]
    watcher = watch.CopyWatcher(path, None, in_use=lambda p: busy[0], clock=Clock())
    assert watcher.step() is False and watcher.step() is False
    busy[0] = False
    assert watcher.step() is True and not path.exists()


def test_a_viewer_that_never_holds_the_file_gets_a_grace_period(tmp_path):
    path = _copy(tmp_path)
    clock = Clock()
    watcher = watch.CopyWatcher(path, None, in_use=lambda p: False, clock=clock, grace=45)
    assert watcher.step() is False and path.exists()
    clock.now = 46
    assert watcher.step() is True and not path.exists()


def test_a_failed_check_keeps_the_copy(tmp_path):
    path = _copy(tmp_path)

    def broken(_p):
        raise OSError("rm unavailable")
    process = Process()
    process.alive = False
    watcher = watch.CopyWatcher(path, process, in_use=broken, clock=Clock())
    assert watcher.step() is False and path.exists()


def test_the_watchers_delete_on_their_own_thread(tmp_path):
    path = _copy(tmp_path)
    process = Process()
    watchers = watch.OpenCopyWatchers(poll=0.02)
    clock = Clock()
    watchers.watch(watch.CopyWatcher(path, process, in_use=lambda p: False, clock=clock))
    time.sleep(0.1)
    assert watchers.remaining() == [path]
    clock.now = 30
    process.alive = False
    deadline = time.monotonic() + 3
    while path.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not path.exists() and watchers.remaining() == [] and process.closed


@pytest.mark.skipif(os.name != "nt", reason="Restart Manager is Windows-only")
def test_restart_manager_sees_a_process_holding_the_copy(tmp_path):
    path = _copy(tmp_path)
    holder = subprocess.Popen([sys.executable, "-c",
                               "import sys,time; f=open(sys.argv[1],'rb'); print('open', flush=True); time.sleep(30)",
                               str(path)], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "open"
        assert watch.file_in_use(path) is True
        watcher = watch.CopyWatcher(path, None)  # real Restart Manager check
        assert watcher.step() is False and path.exists()
    finally:
        holder.kill()
        holder.wait(10)
    assert watch.file_in_use(path) is False
    assert watcher.step() is True and not path.exists()


@pytest.mark.skipif(os.name != "nt", reason="Restart Manager is Windows-only")
def test_the_exit_sweeper_waits_for_an_open_copy_then_deletes_it(tmp_path):
    held = _copy(tmp_path, "held.pdf")
    free_folder = open_copies_dir(tmp_path) / "ffff0000"
    free_folder.mkdir()
    (free_folder / "free.txt").write_text("x", encoding="utf-8")
    holder = subprocess.Popen([sys.executable, "-c",
                               "import sys,time; f=open(sys.argv[1],'rb'); print('open', flush=True); time.sleep(30)",
                               str(held)], stdout=subprocess.PIPE, text=True)
    assert holder.stdout.readline().strip() == "open"
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 1:
            assert held.exists() and not (free_folder / "free.txt").exists()  # the free one went at once
            holder.kill()
            holder.wait(10)
    assert watch.run_exit_sweeper(tmp_path, poll=0, sleep=sleep) == 0
    assert not open_copies_dir(tmp_path).exists()


def test_the_sweeper_flag_only_works_inside_the_data_folder(tmp_path, monkeypatch):
    from localvault import agent

    monkeypatch.setenv("LOCALGATEKEYS_DATA_DIR", str(tmp_path / "data"))
    ran = []
    monkeypatch.setattr(watch, "run_exit_sweeper", lambda profile_dir: ran.append(profile_dir) or 0)
    assert agent.sweep_open_copies(str(tmp_path / "elsewhere")) == 2 and ran == []
    inside = tmp_path / "data" / "Profiles" / "p1"
    inside.mkdir(parents=True)
    assert agent.sweep_open_copies(str(inside)) == 0 and ran == [inside.resolve()]


def test_exit_deletes_free_copies_and_hands_open_ones_to_the_sweeper(tmp_path, monkeypatch):
    from localvault import attachments

    _copy(tmp_path)
    spawned = []
    monkeypatch.setattr(watch, "spawn_exit_sweeper", lambda d: spawned.append(d) or True)
    monkeypatch.setattr(attachments, "cleanup_open_copies", lambda d: [d / "still-open.pdf"])
    assert watch.finish_at_exit(tmp_path) is True and spawned == [tmp_path]
    monkeypatch.setattr(attachments, "cleanup_open_copies", lambda d: [])
    spawned.clear()
    assert watch.finish_at_exit(tmp_path) is False and spawned == []


def test_opening_a_document_watches_its_copy_by_default(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from localvault import attachments

    path = _copy(tmp_path, "report.pdf")
    watched = []
    monkeypatch.setattr(watch, "open_and_watch", lambda p: watched.append(Path(p)))
    monkeypatch.setattr(attachments.os, "name", "nt")
    store = SimpleNamespace(open_copy=lambda item_id: path)
    assert attachments.DocumentService.open_externally(store, "item-1") == path
    assert watched == [path]


def test_a_launcher_that_hands_off_and_exits_at_once_is_not_the_app_closing(tmp_path):
    path = _copy(tmp_path, "report.pdf")
    clock = Clock()
    process = Process()
    busy = [False]
    watcher = watch.CopyWatcher(path, process, in_use=lambda p: busy[0], clock=clock, grace=45)
    clock.now = 1.0
    process.alive = False  # a stub that passed the file to an app that was already running
    assert watcher.step() is False and path.exists()
    busy[0] = True  # the real app opens it
    clock.now = 10
    assert watcher.step() is False
    busy[0] = False  # and closes it
    assert watcher.step() is True and not path.exists()


def test_closing_the_document_while_the_app_stays_open_deletes_the_copy(tmp_path):
    path = _copy(tmp_path, "report.docx")
    process = Process()  # Word stays open after the document is closed
    busy = [True]
    watcher = watch.CopyWatcher(path, process, in_use=lambda p: busy[0], clock=Clock())
    assert watcher.step() is False
    busy[0] = False
    assert watcher.step() is True and not path.exists()


def test_the_exit_sweeper_only_touches_copies_from_before_it_started(tmp_path):
    old = _copy(tmp_path, "old.txt")
    sleeps = []
    new_folder = open_copies_dir(tmp_path) / "new00001"

    def sleep(_s):
        sleeps.append(1)
        if len(sleeps) == 1:  # LocalGateKeys was relaunched and opened another document
            new_folder.mkdir()
            (new_folder / "new.txt").write_text("fresh copy", encoding="utf-8")
    held = [True]
    monkey_remove = watch.remove_copy

    def remove(p):
        if p == old and held[0]:
            held[0] = False
            return False  # still open on the first pass
        return monkey_remove(p)
    import localvault.open_copy_watch as module
    original = module.remove_copy
    module.remove_copy = remove
    try:
        assert watch.run_exit_sweeper(tmp_path, poll=0, sleep=sleep) == 0
    finally:
        module.remove_copy = original
    assert not old.exists() and (new_folder / "new.txt").exists()


def test_the_exit_sweeper_does_not_depend_on_the_restart_manager(tmp_path, monkeypatch):
    path = _copy(tmp_path)
    monkeypatch.setattr(watch, "file_in_use", lambda p: True)  # a broken check would say "busy" forever
    assert watch.run_exit_sweeper(tmp_path, poll=0, max_seconds=5, sleep=lambda s: None) == 0
    assert not path.exists()


@pytest.mark.skipif(os.name != "nt", reason="NTFS junctions")
def test_a_junction_in_the_copies_folder_is_never_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "keep.txt"
    victim.write_text("not a copy", encoding="utf-8")
    root = open_copies_dir(tmp_path / "profile")
    root.mkdir(parents=True)
    made = subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "trap0001"), str(outside)],
                          capture_output=True, text=True)
    assert made.returncode == 0, made.stdout + made.stderr
    watch.run_exit_sweeper(tmp_path / "profile", poll=0, max_seconds=1, sleep=lambda s: None)
    from localvault.attachments import cleanup_open_copies
    cleanup_open_copies(tmp_path / "profile")
    assert victim.exists()
