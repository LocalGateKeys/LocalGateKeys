"""Audit 2026-10-18 round 4: thread-safe sync counters and the wider "Open file" allow-list."""
from __future__ import annotations

import threading
import time

import pytest

from localvault.attachments import OPENABLE_SUFFIXES, can_open_externally
from localvault.sync import DeviceIdentity, PairedDevice, SyncState
from localvault.sync.state import SyncStateError

THREADS = 16
CALLS = 50


def _peer(identity: DeviceIdentity, group_id: str) -> PairedDevice:
    return PairedDevice(identity.device_id, group_id, identity.signing_public_key,
                        identity.exchange_public_key, identity.fingerprint, 1000.0,
                        identity.sign(b"enrollment"))


def _run(threads: int, work):
    barrier = threading.Barrier(threads)
    errors: list[BaseException] = []

    def body(index: int) -> None:
        barrier.wait()
        try:
            work(index)
        except BaseException as exc:  # noqa: BLE001 - collected for the assertion
            errors.append(exc)

    workers = [threading.Thread(target=body, args=(i,)) for i in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(30)
    assert not any(worker.is_alive() for worker in workers)
    return errors


def _slow_source(start: int = 1000):
    """A persistent source like lan_sync's: its own lock, strictly increasing, and slow."""
    lock = threading.Lock()
    box = {"next": start}

    def source() -> int:
        with lock:
            value = box["next"]
            box["next"] += 1
        time.sleep(0.0005)  # widen the window between the source and the state update
        return value

    return source


def test_next_counter_is_safe_under_concurrent_handlers():
    state = SyncState()
    state.enable()
    state.counter_source = _slow_source()
    got: list[list[int]] = [[] for _ in range(THREADS)]

    def work(index: int) -> None:
        for _ in range(CALLS):
            got[index].append(state.next_counter())

    assert _run(THREADS, work) == []
    flat = [value for values in got for value in values]
    assert len(flat) == len(set(flat)) == THREADS * CALLS
    for values in got:
        assert values == sorted(values) and len(set(values)) == len(values)
    assert state.outbound_counter == max(flat)
    assert state.next_counter() > max(flat)


def test_next_counter_without_source_is_safe_under_threads():
    state = SyncState()
    state.enable()
    got: list[int] = []
    lock = threading.Lock()

    def work(_index: int) -> None:
        for _ in range(CALLS):
            value = state.next_counter()
            with lock:
                got.append(value)

    assert _run(THREADS, work) == []
    assert sorted(got) == list(range(1, THREADS * CALLS + 1))


def test_next_counter_still_rejects_a_source_that_does_not_increase():
    state = SyncState()
    state.enable()
    values = iter([5, 5, 4, 6])
    state.counter_source = lambda: next(values)
    assert state.next_counter() == 5
    with pytest.raises(SyncStateError, match="did not increase"):
        state.next_counter()
    with pytest.raises(SyncStateError, match="did not increase"):
        state.next_counter()
    assert state.next_counter() == 6
    assert state.outbound_counter == 6


def test_next_counter_rejects_a_duplicate_handed_to_concurrent_calls():
    state = SyncState()
    state.enable()
    both_inside = threading.Barrier(2)
    state.counter_source = lambda: (both_inside.wait(5), 7)[1]
    results: list[int] = []

    def work(_index: int) -> None:
        results.append(state.next_counter())

    errors = _run(2, work)
    assert results == [7]
    assert len(errors) == 1 and "did not increase" in str(errors[0])


def test_next_counter_source_may_take_a_lock_held_by_an_outbound_run():
    """The counter source is not called under the state lock: no lock-order deadlock with the gate."""
    gate = threading.RLock()
    state = SyncState()
    state.enable()
    inner = _slow_source()

    def source() -> int:
        with gate:  # like lan_sync's block refill entering the sync gate
            return inner()

    state.counter_source = source

    def work(index: int) -> None:
        for _ in range(CALLS):
            if index % 2:
                with gate:  # an outbound run already inside the gate
                    state.next_counter()
            else:
                state.next_counter()

    assert _run(8, work) == []


def test_accept_inbound_counter_is_atomic_and_refuses_replays():
    state = SyncState()
    state.enable()
    peer_identity = DeviceIdentity.generate("peer")
    state.trust_peer(_peer(peer_identity, state.group_id))
    accepted: list[int] = []
    lock = threading.Lock()

    def work(_index: int) -> None:
        # Every thread offers the same counters: each value may be accepted exactly once.
        for counter in range(1, CALLS + 1):
            try:
                state.accept_inbound_counter(peer_identity.device_id, counter)
            except SyncStateError as exc:
                assert "Replay" in str(exc)
                continue
            with lock:
                accepted.append(counter)

    assert _run(THREADS, work) == []
    assert len(accepted) == len(set(accepted))
    assert state.inbound_counters[peer_identity.device_id] == CALLS
    with pytest.raises(SyncStateError, match="Replay"):
        state.accept_inbound_counter(peer_identity.device_id, CALLS)


# ------------------------------------------------------------------ "Open file" allow-list additions

NEWLY_ALLOWED = ["photo.heif", "clip.webm", "film.mkv", "old.avi", "clip.m4v", "song.flac",
                 "song.ogg", "voice.aac", "book.epub", "letter.doc", "sheet.xls", "deck.ppt",
                 "LETTER.DOC", "Book.EPUB"]
STILL_BLOCKED = ["mail.eml", "page.html", "page.xhtml", "image.svg", "style.xsl", "style.xslt",
                 "script.js", "script.vbs", "run.bat", "run.cmd", "app.hta", "archive.zip",
                 "archive.7z", "archive.rar", "macro.docm", "macro.xlsm", "macro.pptm",
                 "addin.xla", "template.dot", "show.pps"]


@pytest.mark.parametrize("name", NEWLY_ALLOWED)
def test_common_harmless_types_open_directly(name):
    assert can_open_externally(name) is True


@pytest.mark.parametrize("name", STILL_BLOCKED)
def test_script_capable_archive_and_mail_types_stay_blocked(name):
    assert can_open_externally(name) is False


def test_allow_list_suffixes_are_lowercase_dotted():
    assert all(s.startswith(".") and s == s.lower() for s in OPENABLE_SUFFIXES)
