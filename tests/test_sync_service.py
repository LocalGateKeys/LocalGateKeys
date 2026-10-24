"""Background sync service: scheduling, single flight, lease aborts, status, LAN listener.

No Tk.  Sockets only in the C1 idle-peer test (loopback, real ``LanAdapter``).
"""
from __future__ import annotations

import dataclasses
import queue
import threading
import time
import uuid
from pathlib import Path

import pytest
import test_licensing

from localvault import licensing
from localvault.session_guard import StaleSession
from localvault.sync import folder_transport as ft
from localvault.sync import lan_sync as lan
from localvault.sync import pairing
from localvault.sync import service as svc
from localvault.sync.install import INSTALL_ID_FILENAME, load_or_create_install_id
from localvault.sync.pairing import DeviceIdentity
from localvault.sync.runner import RunReport, SyncIssue
from localvault.sync.state import SyncState
from localvault.sync.vault_bridge import (
    SyncGroupState,
    _check_lease,
    load_sync_state,
    save_sync_state,
)
from localvault.vault import create_vault

TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
CHEAP = (1024, 1, 1)
MASTER = "synthetic master"
PW = "correct horse battery staple 7!"
PW2 = "another very long passphrase 42?"
NOW = int(time.time())
INSTALL = "install-a"


# --- fakes -----------------------------------------------------------------------------------


class FakeLease:
    def __init__(self) -> None:
        self.valid = True

    def check(self) -> None:
        if not self.valid:
            raise StaleSession("Vault is locked")


class FakeClock:
    def __init__(self, now: float = NOW) -> None:
        self.now = float(now)

    def __call__(self) -> float:
        return self.now


class FakeScheduler:
    """call_later/cancel driven by ``advance``; callbacks run on the test thread."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.timers: dict[int, tuple[float, object]] = {}
        self._next = 0

    def call_later(self, delay: float, fn) -> int:
        self._next += 1
        self.timers[self._next] = (self.clock.now + delay, fn)
        return self._next

    def cancel(self, handle) -> None:
        self.timers.pop(handle, None)

    def advance(self, seconds: float) -> None:
        end = self.clock.now + seconds
        while True:
            due = [(when, h) for h, (when, _fn) in self.timers.items() if when <= end]
            if not due:
                break
            when, handle = min(due)
            _when, fn = self.timers.pop(handle)
            self.clock.now = max(self.clock.now, when)
            fn()
        self.clock.now = end


class InlineWorker:
    """Queues submitted jobs; ``drain`` runs them on the test thread."""

    def __init__(self) -> None:
        self.jobs: list = []
        self.stopped = False

    def submit(self, fn) -> None:
        self.jobs.append(fn)

    def drain(self) -> None:
        while self.jobs:
            self.jobs.pop(0)()

    def stop(self, wait: bool = False) -> None:
        self.stopped = True


class FakeTransport:
    """A transport adapter that records runs; ``hook`` runs inside a run."""

    def __init__(self, name: str = "fake", *, issues=(), configured: bool = True, hook=None,
                 conflicts: int = 0, skipped=()) -> None:
        self.name = name
        self.issues = tuple(issues)
        self.is_configured = configured
        self.hook = hook
        self.runs = 0
        self.active = 0
        self.max_active = 0
        self.conflicts = conflicts
        self.skipped = tuple(skipped)

    def configured(self, state) -> bool:
        return self.is_configured

    def run(self, session, lease, *, now: int, gate) -> RunReport:
        self.runs += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if self.hook is not None:
                self.hook()
            return RunReport(issues=self.issues, conflicts=self.conflicts, skipped=self.skipped, own_states=())
        finally:
            self.active -= 1


@pytest.fixture
def session(tmp_path: Path):
    return create_vault(tmp_path / "a.json", MASTER, kdf_overrides=TEST_KDF)


def _joined(session, install: str = INSTALL, **extra) -> SyncGroupState:
    state = SyncGroupState(str(uuid.uuid4()), 1, b"k" * 32, DeviceIdentity.generate().protected_dict(),
                           install_id=install, **extra)
    save_sync_state(session, state)
    return state


def _service(session, transports, *, lease=None, clock=None, worker=None, posted=None, **kw):
    clock = clock or FakeClock()
    scheduler = kw.pop("scheduler", None) or FakeScheduler(clock)
    service = svc.SyncService(
        session, lease or FakeLease(), install_id=INSTALL, transports=transports, clock=clock,
        scheduler=scheduler, worker=worker or InlineWorker(),
        post_result=(posted.append if posted is not None else None), **kw)
    return service, scheduler, service._worker


# --- scheduling ------------------------------------------------------------------------------


def test_unlock_runs_once_then_every_five_minutes(session) -> None:
    _joined(session)
    t = FakeTransport()
    service, sched, worker = _service(session, [t])
    service.on_unlock()
    worker.drain()
    assert t.runs == 1
    sched.advance(svc.RUN_INTERVAL_SECONDS - 1)
    worker.drain()
    assert t.runs == 1
    sched.advance(1)
    worker.drain()
    assert t.runs == 2
    sched.advance(svc.RUN_INTERVAL_SECONDS)
    worker.drain()
    assert t.runs == 3


def test_local_changes_are_debounced_ten_seconds(session) -> None:
    _joined(session)
    t = FakeTransport()
    service, sched, worker = _service(session, [t])
    service.on_local_change()
    sched.advance(5)
    service.on_local_change()
    sched.advance(9)
    worker.drain()
    assert t.runs == 0  # the second change restarted the 10 s window
    sched.advance(1)
    worker.drain()
    assert t.runs == 1
    sched.advance(60)
    worker.drain()
    assert t.runs == 1


def test_vault_writes_are_noticed_by_polling_the_change_marker(session) -> None:
    _joined(session)
    t = FakeTransport()
    marker = {"value": 1}
    service, sched, worker = _service(session, [t], change_marker=lambda: marker["value"])
    service.on_unlock()
    worker.drain()
    assert t.runs == 1
    sched.advance(30)
    worker.drain()
    assert t.runs == 1  # nothing changed
    marker["value"] = 2
    sched.advance(svc.POLL_SECONDS)
    sched.advance(svc.DEBOUNCE_SECONDS)
    worker.drain()
    assert t.runs == 2


def test_single_flight_coalesces_requests(session) -> None:
    _joined(session)
    calls: list[int] = []
    service = None

    def nested() -> None:
        calls.append(1)
        if len(calls) == 1:
            service.run_now()  # a request while running is coalesced, never nested
            service.run_now()

    t = FakeTransport(hook=nested)
    service, _sched, worker = _service(session, [t])
    service.run_now()
    service.run_now()
    worker.drain()
    assert t.max_active == 1
    assert t.runs == 2  # the run, then exactly one rerun for everything requested meanwhile


def test_single_flight_on_a_real_worker_thread(session) -> None:
    _joined(session)
    started, release = threading.Event(), threading.Event()

    def block() -> None:
        started.set()
        assert release.wait(5)

    t = FakeTransport(hook=block)
    worker = svc.ThreadWorker()
    service, _sched, _w = _service(session, [t], worker=worker)
    service.run_now()
    assert started.wait(5)
    service.run_now()
    service.run_now()
    release.set()
    worker.stop(wait=True, timeout=5)
    assert not worker.alive
    assert t.max_active == 1 and t.runs == 2


def test_stop_cancels_timers_and_refuses_new_runs(session) -> None:
    _joined(session)
    t = FakeTransport()
    service, sched, worker = _service(session, [t])
    service.on_unlock()
    service.on_local_change()
    service.stop()
    worker.drain()
    sched.advance(3600)
    service.run_now()
    worker.drain()
    assert t.runs == 0 and sched.timers == {} and worker.stopped


# --- lease -------------------------------------------------------------------------------------


def _folder_pair(tmp_path: Path):
    root = tmp_path / "OneDrive"
    root.mkdir()
    a = create_vault(tmp_path / "fa.json", MASTER, kdf_overrides=TEST_KDF)
    b = create_vault(tmp_path / "fb.json", MASTER, kdf_overrides=TEST_KDF)
    la, lb = FakeLease(), FakeLease()
    ft.create_folder_group(root, a, la, PW, "PC A", install_id=INSTALL, now=NOW, _kdf_override=CHEAP)
    ft.join_folder_group(root, b, lb, PW, "PC B", install_id="install-b", now=NOW, _kdf_override=CHEAP)
    for s, lease, inst in ((a, la, INSTALL), (b, lb, "install-b"), (a, la, INSTALL)):
        ft.FolderSync(root, install_id=inst, _kdf_override=CHEAP).run_once(s, lease, now=NOW)
    # A confirms B, which joined from another device (audit M10 "member-added").
    ft.acknowledge_members(a, la, load_sync_state(a).unacked_members, install_id=INSTALL)
    return root, (a, la), (b, lb)


def test_lock_during_run_aborts(tmp_path: Path, monkeypatch) -> None:
    root, (a, lease), (b, lb) = _folder_pair(tmp_path)
    b.upsert_web(origin="https://new.example.com", username="me", password="pw-123456", label="new")
    ft.FolderSync(root, install_id="install-b", _kdf_override=CHEAP).run_once(b, lb, now=NOW)
    own = root / ft.SYNC_DIR_NAME / "devices" / f"{load_sync_state(a).device_id}.lgksync"
    before_file, before_vault = own.read_bytes(), Path(a.path).read_bytes()
    original = ft.FolderSync.read_peers

    def read_then_lock(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        lease.valid = False  # the auto-lock fires while peers are being read
        return result

    monkeypatch.setattr(ft.FolderSync, "read_peers", read_then_lock)
    posted: list = []
    folder = svc.FolderAdapter(install_id=INSTALL, _kdf_override=CHEAP)
    service, _sched, worker = _service(a, [folder], lease=lease, posted=posted)
    service.run_now()
    worker.drain()
    assert own.read_bytes() == before_file
    assert Path(a.path).read_bytes() == before_vault
    assert "new" not in [e["label"] for e in a._payload["entries"]]
    view = service.status()
    assert view.last_sync is None and view.aborted and not view.running


def test_folder_run_reaches_merge_and_reports_synced(tmp_path: Path) -> None:
    root, (a, lease), (b, lb) = _folder_pair(tmp_path)
    b.upsert_web(origin="https://new.example.com", username="me", password="pw-123456", label="new")
    ft.FolderSync(root, install_id="install-b", _kdf_override=CHEAP).run_once(b, lb, now=NOW)
    posted: list = []
    service, _sched, worker = _service(a, [svc.FolderAdapter(install_id=INSTALL, _kdf_override=CHEAP)],
                                       lease=lease, posted=posted)
    service.run_now()
    worker.drain()
    assert "new" in [e["label"] for e in a._payload["entries"]]
    view = service.status()
    assert view.configured and view.last_sync == NOW and not view.needs_attention
    assert posted and posted[-1] == view


def test_counter_reuse_after_restore_is_resynced_and_reported_once(tmp_path: Path) -> None:
    root, (a, lease), _b = _folder_pair(tmp_path)
    state = load_sync_state(a)
    assert state.own_counter > 0
    save_sync_state(a, dataclasses.replace(state, own_counter=0))  # an older vault copy came back
    fs = ft.FolderSync(root, install_id=INSTALL, _kdf_override=CHEAP)
    first = fs.run_once(a, lease, now=NOW)
    assert [i.kind for i in first.issues].count("counter-resynced") == 1
    assert load_sync_state(a).own_counter > state.own_counter
    second = fs.run_once(a, lease, now=NOW)
    assert "counter-resynced" not in [i.kind for i in second.issues]


# --- gating, install binding, status ------------------------------------------------------------


def test_sync_runs_when_the_session_allows_it(session) -> None:
    session.pro_features = frozenset({"sync"})
    _joined(session)
    t = FakeTransport()
    service, _sched, worker = _service(session, [t])
    service.run_now()
    worker.drain()
    assert t.runs == 1


def test_free_plan_session_runs_no_round_and_no_listener(session) -> None:
    # Sync is Pro-only: a session whose plan lacks "sync" never runs a transport.
    session.pro_features = frozenset()
    _joined(session)
    t = FakeTransport()
    service, _sched, worker = _service(session, [t])
    service.on_unlock()
    service.run_now()
    worker.drain()
    assert t.runs == 0


def test_install_mismatch_requires_rejoin_and_runs_nothing(session) -> None:
    _joined(session, install="another-pc")
    t = FakeTransport()
    service, _sched, worker = _service(session, [t])
    service.run_now()
    worker.drain()
    view = service.status()
    assert t.runs == 0
    assert [i.kind for i in view.issues] == ["rejoin-required"] and view.needs_attention


def test_not_joined_is_not_configured(session) -> None:
    t = FakeTransport()
    service, _sched, worker = _service(session, [t])
    service.run_now()
    worker.drain()
    assert t.runs == 0 and not service.status().configured


def test_unconfigured_transports_are_skipped(session) -> None:
    _joined(session)
    on, off = FakeTransport("folder"), FakeTransport("lan", configured=False)
    service, _sched, worker = _service(session, [on, off])
    service.run_now()
    worker.drain()
    assert on.runs == 1 and off.runs == 0
    names = {t.name: t.configured for t in service.status().transports}
    assert names == {"folder": True, "lan": False}


def test_status_deduplicates_issues_and_skipped_records(session) -> None:
    _joined(session)
    issues = (SyncIssue("ignored-file", "1 file: x (1).lgksync"), SyncIssue("rollback", "dev-b"),
              SyncIssue("rollback", "dev-c"))
    one = FakeTransport("folder", issues=issues, conflicts=1, skipped=(("id1", "bad"),))
    two = FakeTransport("lan", issues=issues[1:2], conflicts=2, skipped=(("id1", "bad"),))
    service, _sched, worker = _service(session, [one, two])
    for _ in range(3):
        service.run_now()
        worker.drain()
    view = service.status()
    assert [(i.kind, i.detail) for i in view.issues] == [
        ("ignored-file", "1 file: x (1).lgksync"), ("rollback", "dev-b"), ("rollback", "dev-c")]
    assert view.skipped == (("id1", "bad"),)
    assert view.conflicts == 9  # three runs of 1 + 2 conflict copies since unlock
    assert view.needs_attention


def test_transport_exception_becomes_an_issue_not_a_crash(session) -> None:
    _joined(session)

    def boom() -> None:
        raise OSError("disk gone")

    service, _sched, worker = _service(session, [FakeTransport(hook=boom)])
    service.run_now()
    worker.drain()
    assert [i.kind for i in service.status().issues] == ["error"]


# --- install id file ------------------------------------------------------------------------------


def test_install_id_file_is_created_once_and_persists(tmp_path: Path) -> None:
    first = load_or_create_install_id(tmp_path)
    assert str(uuid.UUID(first)) == first
    assert (tmp_path / INSTALL_ID_FILENAME).is_file()
    assert load_or_create_install_id(tmp_path) == first
    assert [p.name for p in tmp_path.iterdir()] == [INSTALL_ID_FILENAME]  # no temp files left


@pytest.mark.parametrize("content", ["{not json", '{"version": 1, "install_id": "not-a-uuid"}', "[1, 2]"])
def test_install_id_file_that_is_malformed_is_kept_as_bad_and_replaced(tmp_path: Path, content: str) -> None:
    (tmp_path / INSTALL_ID_FILENAME).write_text(content, encoding="utf-8")
    value = load_or_create_install_id(tmp_path)
    assert str(uuid.UUID(value)) == value
    assert (tmp_path / (INSTALL_ID_FILENAME + ".bad")).read_text(encoding="utf-8") == content
    assert load_or_create_install_id(tmp_path) == value


def test_install_id_read_error_propagates_and_keeps_the_identity(tmp_path: Path, monkeypatch) -> None:
    first = load_or_create_install_id(tmp_path)
    real = Path.read_text

    def locked(self, *args, **kwargs):
        if self.name == INSTALL_ID_FILENAME:
            raise PermissionError("locked by another process")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", locked)
    with pytest.raises(PermissionError):
        load_or_create_install_id(tmp_path)
    monkeypatch.setattr(Path, "read_text", real)
    assert load_or_create_install_id(tmp_path) == first  # not rotated
    assert not (tmp_path / (INSTALL_ID_FILENAME + ".bad")).exists()


# --- one lock ----------------------------------------------------------------------------------------


def test_one_lock_serialises_state_writers_without_lost_counters(session) -> None:
    _joined(session)
    gate = svc.SyncGate()
    lease = FakeLease()
    tstate = lan.transport_state(load_sync_state(session), session, lease, gate=gate.hold)
    hello = tstate.counter_source  # the first call refills a block: that part runs inside the gate
    holding, release = threading.Event(), threading.Event()
    hello_started, hello_done = threading.Event(), threading.Event()

    def stale_writer() -> None:  # a folder-style read-modify-write of own_counter
        with gate.hold():
            state = load_sync_state(session)
            holding.set()
            assert release.wait(5)
            save_sync_state(session, dataclasses.replace(state, own_counter=state.own_counter + 1))

    def hello_writer() -> None:
        hello_started.set()
        hello()
        hello_done.set()

    a = threading.Thread(target=stale_writer)
    a.start()
    assert holding.wait(5)
    b = threading.Thread(target=hello_writer)
    b.start()
    assert hello_started.wait(5)
    assert not hello_done.wait(0.2)  # blocked behind the writer
    release.set()
    a.join(5)
    b.join(5)
    final = load_sync_state(session)
    assert final.own_counter == 1 and final.hello_counter > 0


def test_gate_released_lets_another_thread_in(session) -> None:
    gate = svc.SyncGate()
    entered = threading.Event()

    def other() -> None:
        with gate.hold():
            entered.set()

    with gate.hold(), gate.hold():
        with gate.released():
            th = threading.Thread(target=other)
            th.start()
            assert entered.wait(5)
            th.join(5)
        assert gate.owned()
    assert not gate.owned()


def test_ui_barrier_parks_the_ui_loop_while_held() -> None:
    import queue

    ui: queue.Queue = queue.Queue()
    stop = threading.Event()
    ran: list[str] = []

    def ui_loop() -> None:
        while not stop.is_set():
            try:
                fn = ui.get(timeout=0.01)
            except queue.Empty:
                continue
            fn()

    loop = threading.Thread(target=ui_loop)
    loop.start()
    barrier = svc.UiBarrier(ui.put, is_ui_thread=lambda: threading.current_thread() is loop)
    gate = svc.SyncGate(barrier)
    with gate.hold():
        ui.put(lambda: ran.append("ui"))
        time.sleep(0.1)
        assert ran == []  # the UI thread is parked: no handler runs meanwhile
        with gate.ui_released():
            deadline = time.monotonic() + 5
            while not ran and time.monotonic() < deadline:
                time.sleep(0.01)
            assert ran == ["ui"]
    stop.set()
    loop.join(5)
    assert not loop.is_alive()


def test_ui_barrier_gives_up_when_cancelled() -> None:
    barrier = svc.UiBarrier(lambda fn: None, is_ui_thread=lambda: False)  # the UI never drains
    gate = svc.SyncGate(barrier, cancelled=lambda: True)
    with pytest.raises(svc.SyncAborted), gate.hold():
        pass
    assert not gate.owned()


# --- reset -----------------------------------------------------------------------------------------


def test_reset_sync_clears_meta_and_group_state(tmp_path: Path) -> None:
    _root, (a, lease), _b = _folder_pair(tmp_path)
    assert "sync_meta" in a._payload and "sync_group" in a._payload
    svc.reset_sync(a, lease)
    assert "sync_meta" not in a._payload and "sync_group" not in a._payload
    assert load_sync_state(a) is None


def test_reset_sync_needs_a_valid_lease(tmp_path: Path) -> None:
    _root, (a, lease), _b = _folder_pair(tmp_path)
    lease.valid = False
    with pytest.raises(StaleSession):
        svc.reset_sync(a, lease)
    assert "sync_group" in a._payload


def test_service_reset_stops_and_clears_status(session) -> None:
    _joined(session)
    t = FakeTransport(issues=(SyncIssue("tampered", "x"),))
    service, _sched, worker = _service(session, [t])
    service.run_now()
    worker.drain()
    service.reset()
    worker.drain()
    view = service.status()
    assert load_sync_state(session) is None and view.issues == () and not view.configured


# --- LAN listener lifecycle and enrollment hardening -------------------------------------------------


class FakeSyncTransport:
    """Stands in for SyncTransport: records the lifecycle, opens no socket."""

    instances: list = []

    def __init__(self, state) -> None:
        self.state = state
        self.started = None
        self.stopped = False
        self.peer_handler = None
        self.enroll_handler = None
        FakeSyncTransport.instances.append(self)

    def set_peer_request_handler(self, handler) -> None:
        self.peer_handler = handler

    def set_enrollment_handler(self, handler) -> None:
        self.enroll_handler = handler

    def start(self, endpoint) -> None:
        self.started = endpoint

    def stop(self) -> None:
        self.stopped = True

    def request(self, *args, **kwargs):
        raise AssertionError("no network in these tests")


ENDPOINT = lan.LANEndpoint("127.0.0.1", 45871)


def _lan_group(session) -> SyncGroupState:
    return lan.create_lan_group(session, FakeLease(), install_id=INSTALL)


def _enroll(responder, offer, identity=None):
    identity = identity or DeviceIdentity.generate()
    raw = pairing.build_enrollment_request(offer, identity, endpoint=("127.0.0.1", 45872), now=NOW)
    return identity, responder.enroll(raw)


def _lan_service(session, *, clock=None, monotonic=None, endpoint=ENDPOINT):
    FakeSyncTransport.instances.clear()
    clock = clock or FakeClock()
    adapter = svc.LanAdapter(install_id=INSTALL, endpoint=lambda: endpoint,
                             transport_factory=FakeSyncTransport, clock=clock, monotonic=monotonic)
    service, sched, worker = _service(session, [adapter], clock=clock)
    return service, sched, worker, adapter


def test_listener_starts_on_unlock_and_stops_on_lock(session) -> None:
    _lan_group(session)
    service, _sched, worker, adapter = _lan_service(session)
    service.on_unlock()
    worker.drain()
    (transport,) = FakeSyncTransport.instances
    assert transport.started == ENDPOINT and transport.peer_handler is not None
    assert isinstance(transport.state, SyncState)
    assert service.status().listening
    service.stop()
    assert transport.stopped and adapter.transport is None and not service.status().listening


def test_no_listener_without_an_endpoint_or_group(session) -> None:
    service, _sched, worker, _adapter = _lan_service(session)
    service.on_unlock()
    worker.drain()
    assert FakeSyncTransport.instances == []  # not joined
    _lan_group(session)
    service2, _s, w2, _a = _lan_service(session, endpoint=None)
    service2.on_unlock()
    w2.drain()
    assert FakeSyncTransport.instances == []


def test_listener_is_not_started_on_install_mismatch(session) -> None:
    lan.create_lan_group(session, FakeLease(), install_id="another-pc")
    service, _sched, worker, _adapter = _lan_service(session)
    service.on_unlock()
    worker.drain()
    assert FakeSyncTransport.instances == []


def test_one_transport_state_serves_listening_and_requesting(session) -> None:
    _lan_group(session)
    service, _sched, worker, adapter = _lan_service(session)
    service.on_unlock()
    worker.drain()
    service.run_now()
    worker.drain()
    (transport,) = FakeSyncTransport.instances
    assert adapter.transport is transport
    tstate = transport.state
    first = tstate.counter_source()
    second = tstate.counter_source()
    assert second == first + 1  # one in-memory block, gate-wrapped


def test_enrollment_through_the_service_pins_peer_and_disarms_eagerly(session) -> None:
    _lan_group(session)
    clock = FakeClock()
    mono = FakeClock(1000.0)
    service, sched, worker, adapter = _lan_service(session, clock=clock, monotonic=mono)
    service.on_unlock()
    worker.drain()
    (transport,) = FakeSyncTransport.instances
    offer = lan.begin_pairing(session, FakeLease(), ENDPOINT.host, ENDPOINT.port, install_id=INSTALL,
                              now=clock())
    service.arm_enrollment(offer)
    worker.drain()  # arming touches the vault, so it runs on the worker inside the gate
    assert transport.enroll_handler is not None
    identity, reply = _enroll(adapter.responder, offer)
    assert reply is not None
    assert [p["device_id"] for p in load_sync_state(session).lan_peers] == [identity.device_id]
    # The offer is disarmed as soon as it expires, without waiting for another request.
    mono.now += pairing.PAIRING_TTL_SECONDS
    sched.advance(pairing.PAIRING_TTL_SECONDS)
    assert adapter.responder.pairing is not None  # the timer only queues the gated worker job
    worker.drain()
    assert adapter.responder.pairing is None
    assert transport.enroll_handler is not None  # late devices still get a clear refusal
    mono.now += lan.ENROLL_GRACE_SECONDS
    sched.advance(lan.ENROLL_GRACE_SECONDS)
    worker.drain()
    assert transport.enroll_handler is None


def test_offer_expiry_uses_a_monotonic_deadline(session) -> None:
    _lan_group(session)
    mono = FakeClock(50.0)
    responder = lan.LanResponder(session, FakeLease(), install_id=INSTALL, clock=lambda: NOW,
                                 monotonic=mono)
    transport = FakeSyncTransport(SyncState())
    offer = lan.begin_pairing(session, FakeLease(), ENDPOINT.host, ENDPOINT.port, install_id=INSTALL, now=NOW)
    responder.start_enrollment(offer, transport)
    mono.now += pairing.PAIRING_TTL_SECONDS  # the wall clock was set back; elapsed time still counts
    _identity, reply = _enroll(responder, offer)
    assert reply == pairing.enrollment_refusal("used-or-expired")
    assert load_sync_state(session).lan_peers == ()
    responder.expire_enrollment()
    assert responder.pairing is None
    mono.now += lan.ENROLL_GRACE_SECONDS
    responder.expire_enrollment()
    assert transport.enroll_handler is None


def test_revoked_device_ids_are_reserved_for_enrollment(session) -> None:
    _lan_group(session)
    lease = FakeLease()
    tstate = lan.transport_state(load_sync_state(session), session, lease)
    transport = FakeSyncTransport(tstate)
    responder = lan.LanResponder(session, lease, install_id=INSTALL, clock=lambda: NOW)
    offer = lan.begin_pairing(session, lease, ENDPOINT.host, ENDPOINT.port, install_id=INSTALL, now=NOW)
    responder.start_enrollment(offer, transport)
    identity, reply = _enroll(responder, offer)
    assert reply is not None
    assert lan.remove_lan_peer(session, lease, identity.device_id, install_id=INSTALL, transport=transport)
    assert identity.device_id in tstate.revoked_devices
    offer2 = lan.begin_pairing(session, lease, ENDPOINT.host, ENDPOINT.port, install_id=INSTALL, now=NOW)
    responder.start_enrollment(offer2, transport)
    _same, reply2 = _enroll(responder, offer2, identity)
    assert reply2 == pairing.enrollment_refusal()
    assert load_sync_state(session).lan_peers == ()
    assert responder.pairing.attempts == 1


# --- app integration -----------------------------------------------------------------------------


def test_statusbar_sync_text() -> None:
    from localvault.app.presentation import sync_status_text

    def view(**kw):
        base = dict(configured=True, last_sync=NOW - 120, issues=())
        base.update(kw)
        return svc.SyncStatusView(**base)

    assert sync_status_text(None, now=NOW) == ""
    assert sync_status_text(view(configured=False), now=NOW) == ""
    assert sync_status_text(view(), now=NOW) == "Synced 2 min ago"
    assert sync_status_text(view(last_sync=NOW - 20), now=NOW) == "Synced just now"
    assert sync_status_text(view(last_sync=NOW - 3 * 3600), now=NOW) == "Synced 3 h ago"
    assert sync_status_text(view(last_sync=None), now=NOW) == "Not synced yet"
    assert sync_status_text(view(issues=(SyncIssue("folder-missing"),)), now=NOW) == "Sync needs attention"
    assert sync_status_text(view(issues=(SyncIssue("counter-resynced"),)), now=NOW) == "Synced 2 min ago"


# --- fix round 1: park timeout, parked region, fence, hardening ---------------------------------------


class _UiLoop:
    """A stand-in UI thread draining a queue (joined deterministically by ``close``)."""

    def __init__(self) -> None:
        self.queue: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run)
        self.thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                fn = self.queue.get(timeout=0.01)
            except queue.Empty:
                continue
            fn()

    def barrier(self, max_park: float) -> svc.UiBarrier:
        return svc.UiBarrier(self.queue.put, is_ui_thread=lambda: threading.current_thread() is self.thread,
                             max_park=max_park)

    def close(self) -> None:
        self._stop.set()
        self.thread.join(5)
        assert not self.thread.is_alive()


def test_park_timeout_breaks_the_gate_until_the_hold_ends() -> None:
    ui = _UiLoop()
    try:
        gate = svc.SyncGate(ui.barrier(0.05))
        with gate.hold():
            gate.check()
            time.sleep(0.3)  # the UI gave up waiting and resumed
            with pytest.raises(svc.SyncAborted):
                gate.check()
            with gate.released():
                pass
            with pytest.raises(svc.SyncAborted):  # still broken for this run after re-acquiring
                gate.check()
        with gate.hold():
            gate.check()  # a new run starts clean
    finally:
        ui.close()


def test_vault_access_after_park_timeout_aborts_without_writing(tmp_path: Path, monkeypatch) -> None:
    root, (a, lease), (b, lb) = _folder_pair(tmp_path)
    b.upsert_web(origin="https://new.example.com", username="me", password="pw-123456", label="new")
    ft.FolderSync(root, install_id="install-b", _kdf_override=CHEAP).run_once(b, lb, now=NOW)
    own = root / ft.SYNC_DIR_NAME / "devices" / f"{load_sync_state(a).device_id}.lgksync"
    before_file, before_vault = own.read_bytes(), Path(a.path).read_bytes()
    real_merge = ft.run_merge

    def slow_merge(*args, **kwargs):
        time.sleep(0.3)  # parked longer than the safety valve: the UI resumes meanwhile
        return real_merge(*args, **kwargs)

    monkeypatch.setattr(ft, "run_merge", slow_merge)
    ui = _UiLoop()
    try:
        gate = svc.SyncGate(ui.barrier(0.05))
        service, _sched, worker = _service(a, [svc.FolderAdapter(install_id=INSTALL, _kdf_override=CHEAP)],
                                           lease=lease, gate=gate)
        service.run_now()
        worker.drain()
    finally:
        ui.close()
    assert own.read_bytes() == before_file and Path(a.path).read_bytes() == before_vault
    assert "new" not in [e["label"] for e in a._payload["entries"]]
    view = service.status()
    assert view.aborted and view.last_sync is None and not view.running


class _RecordingBarrier:
    def __init__(self) -> None:
        self.parked = False

    def park(self, cancelled):
        self.parked = True
        return object()

    def unpark(self, token) -> None:
        self.parked = False


def test_folder_io_runs_with_the_ui_free_and_vault_access_parked(tmp_path: Path, monkeypatch) -> None:
    _root, (a, lease), _b = _folder_pair(tmp_path)
    a.upsert_web(origin="https://mine.example.com", username="me", password="pw-123456", label="mine")
    barrier = _RecordingBarrier()
    seen: dict[str, set[bool]] = {}

    def spy(owner, name):
        real = getattr(owner, name)

        def call(*args, **kwargs):
            seen.setdefault(name, set()).add(barrier.parked)
            return real(*args, **kwargs)

        monkeypatch.setattr(owner, name, call)

    for name in ("_read_bounded", "_atomic_write", "load_sync_state", "save_sync_state", "run_merge"):
        spy(ft, name)
    for name in ("_folder_exists", "read_keyring_bytes", "_sweep_own_temp_files", "_sweep_keyring_temp_files"):
        spy(ft.FolderSync, name)
    service, _sched, worker = _service(a, [svc.FolderAdapter(install_id=INSTALL, _kdf_override=CHEAP)],
                                       lease=lease, gate=svc.SyncGate(barrier))
    service.run_now()
    worker.drain()
    assert service.status().last_sync == NOW
    for name in ("_read_bounded", "_atomic_write", "_folder_exists", "read_keyring_bytes",
                 "_sweep_own_temp_files", "_sweep_keyring_temp_files"):
        assert seen[name] == {False}, name  # folder I/O: UI free
    for name in ("load_sync_state", "save_sync_state", "run_merge"):
        assert seen[name] == {True}, name  # vault access: UI parked


def test_stopped_service_cannot_write_through_its_fenced_lease(session) -> None:
    _joined(session)
    writes: list[str] = []
    grabbed: dict = {}
    service = None

    def lock_then_write() -> None:
        service.stop()  # the vault locked (a new service may already exist)
        _check_lease(session, grabbed["lease"])
        writes.append("own file")

    class Grab(FakeTransport):
        def run(self, session, lease, *, now, gate):
            grabbed["lease"] = lease
            return super().run(session, lease, now=now, gate=gate)

    service, _sched, worker = _service(session, [Grab(hook=lock_then_write)])
    service.run_now()
    worker.drain()
    assert writes == [] and service.status().aborted


def test_base_exception_in_a_run_does_not_leave_the_service_running(session) -> None:
    _joined(session)
    calls: list[int] = []

    def interrupt() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise KeyboardInterrupt

    t = FakeTransport(hook=interrupt)
    service, _sched, worker = _service(session, [t])
    service.run_now()
    with pytest.raises(KeyboardInterrupt):
        worker.drain()
    assert not service.status().running
    service.run_now()
    worker.drain()
    assert t.runs == 2


def test_hello_counters_from_memory_do_not_wait_for_the_gate(session) -> None:
    _joined(session)
    gate = svc.SyncGate()
    tstate = lan.transport_state(load_sync_state(session), session, FakeLease(), gate=gate.hold)
    first = tstate.counter_source()  # refill (gated)
    holding, release, got = threading.Event(), threading.Event(), []

    def holder() -> None:
        with gate.hold():
            holding.set()
            assert release.wait(5)

    th = threading.Thread(target=holder)
    th.start()
    assert holding.wait(5)
    got.append(tstate.counter_source())  # from the in-memory block while another thread holds the gate
    release.set()
    th.join(5)
    assert got == [first + 1]


# --- UI jobs (Task 8 contract: every SyncGroupState change is a worker job inside the gate) ------------


def test_submit_runs_the_job_on_the_worker_inside_the_gate_and_reports(session) -> None:
    posted: list = []
    service, _sched, worker = _service(session, [FakeTransport()], posted=posted)
    seen: list = []

    def job(sess, lease, gate):
        seen.append((sess is session, gate.owned()))
        lan.create_lan_group(sess, lease, install_id=INSTALL)
        return "made"

    results: list = []
    assert service.submit(job, lambda result, error: results.append((result, error)))
    assert seen == [] and results == []  # nothing runs on the calling (Tk) thread
    worker.drain()
    assert seen == [(True, True)] and results == [("made", None)]
    assert load_sync_state(session) is not None
    assert posted and posted[-1].configured is True  # status re-read and published after the job


def test_submit_reports_errors_and_refuses_after_stop(session) -> None:
    service, _sched, worker = _service(session, [FakeTransport()])
    results: list = []

    def boom(sess, lease, gate):
        raise ft.FolderSyncError("weak-password", "too easy")

    service.submit(boom, lambda result, error: results.append((result, error)))
    worker.drain()
    ((result, error),) = results
    assert result is None and isinstance(error, ft.FolderSyncError) and error.reason == "weak-password"
    service.stop()
    assert service.submit(boom, lambda *_: results.append("late")) is False
    worker.drain()
    assert results[1:] == []


def test_submit_job_sees_a_fenced_lease(session) -> None:
    lease = FakeLease()
    service, _sched, worker = _service(session, [FakeTransport()], lease=lease)
    results: list = []
    lease.valid = False
    service.submit(lambda sess, ls, gate: ls.check(), lambda result, error: results.append(error))
    worker.drain()
    assert isinstance(results[0], (StaleSession, svc.SyncAborted))


def test_enrollment_result_names_the_device_that_used_this_offer(session) -> None:
    _lan_group(session)
    clock = FakeClock()
    service, _sched, worker, adapter = _lan_service(session, clock=clock, monotonic=FakeClock(1000.0))
    service.on_unlock()
    worker.drain()
    offer = lan.begin_pairing(session, FakeLease(), ENDPOINT.host, ENDPOINT.port, install_id=INSTALL,
                              now=clock())
    assert service.enrollment_result(offer.offer_id) is None
    service.arm_enrollment(offer)
    worker.drain()
    assert service.enrollment_result(offer.offer_id) is None
    identity, reply = _enroll(adapter.responder, offer)
    assert reply is not None
    assert service.enrollment_result(offer.offer_id) == identity.device_id
    assert service.enrollment_result("another-offer") is None


def test_cancel_enrollment_disarms_the_offer_through_a_gated_job(session) -> None:
    _lan_group(session)
    clock = FakeClock()
    service, _sched, worker, adapter = _lan_service(session, clock=clock, monotonic=FakeClock(1000.0))
    service.on_unlock()
    worker.drain()
    (transport,) = FakeSyncTransport.instances
    offer = lan.begin_pairing(session, FakeLease(), ENDPOINT.host, ENDPOINT.port, install_id=INSTALL,
                              now=clock())
    service.arm_enrollment(offer)
    worker.drain()
    assert service.cancel_enrollment("another-offer")
    worker.drain()
    assert adapter.responder.pairing is not None  # another offer: left alone
    assert service.cancel_enrollment(offer.offer_id)
    assert adapter.responder.pairing is not None  # queued, not done on the calling thread
    worker.drain()
    assert adapter.responder.pairing is None and transport.enroll_handler is None
    _identity, reply = _enroll(adapter.responder, offer)
    assert reply is None
    service.stop()
    assert service.cancel_enrollment(offer.offer_id) is False


def test_reset_reports_refusal_and_failure(session, monkeypatch) -> None:
    _joined(session)
    service, _sched, worker = _service(session, [FakeTransport()])
    results: list = []

    def boom(*_a):
        raise RuntimeError("disk full")

    monkeypatch.setattr(svc, "reset_sync", boom)
    assert service.reset(results.append) is True
    with pytest.raises(RuntimeError):
        worker.drain()  # the inline worker re-raises; ThreadWorker logs and carries on
    assert results == [None]  # failed: neither "cleared" nor "nothing to reset"
    service.stop()
    assert service.reset(results.append) is False


# --- C1: an idle LAN peer never makes the service trigger itself (real LanAdapter, loopback) -------------


def _loopback_endpoint() -> tuple[lan.LANEndpoint, object]:
    import socket

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    probe.bind(("127.0.0.1", 0))
    return lan.LANEndpoint("127.0.0.1", int(probe.getsockname()[1])), probe


@pytest.mark.parametrize("peer_listening", [False, True], ids=["unreachable", "reachable-idle"])
def test_idle_lan_peer_causes_no_vault_writes_and_no_self_triggered_runs(tmp_path: Path, peer_listening) -> None:
    from localvault.sync.transport import SyncTransport

    a = create_vault(tmp_path / "a.json", MASTER, kdf_overrides=TEST_KDF, backup_dir=tmp_path / "Backups",
                     backup_count=20)
    b = create_vault(tmp_path / "b.json", MASTER, kdf_overrides=TEST_KDF)
    lease_a, lease_b = FakeLease(), FakeLease()
    ep_a, hold_a = _loopback_endpoint()
    ep_b, hold_b = _loopback_endpoint()
    transports: list = []
    try:
        lan.create_lan_group(a, lease_a, install_id="install-a")
        # A's pairing listener (stands in for the app's QR screen).
        t_a = SyncTransport(lan.transport_state(load_sync_state(a), a, lease_a))
        transports.append(t_a)
        r_a = lan.LanResponder(a, lease_a, install_id="install-a", clock=lambda: NOW)
        t_a.set_peer_request_handler(r_a)
        hold_a.close()
        t_a.start(ep_a)
        offer = lan.begin_pairing(a, lease_a, ep_a.host, ep_a.port, install_id="install-a", now=NOW)
        r_a.start_enrollment(offer, t_a)
        lan.enroll_from_qr(pairing.offer_qr_payload(offer), b, lease_b, install_id="install-b",
                           endpoint=ep_b, now=NOW)
        t_a.stop()
        hold_b.close()
        if peer_listening:
            t_b = SyncTransport(lan.transport_state(load_sync_state(b), b, lease_b))
            transports.append(t_b)
            t_b.set_peer_request_handler(lan.LanResponder(b, lease_b, install_id="install-b", clock=lambda: NOW))
            t_b.start(ep_b)

        runs: list[list[str]] = []

        class CountingLan(svc.LanAdapter):
            def run(self, *args, **kwargs):
                report = super().run(*args, **kwargs)
                runs.append([i.kind for i in report.issues])
                return report

        clock = FakeClock(NOW)
        sched = FakeScheduler(clock)
        worker = InlineWorker()
        adapter = CountingLan(install_id="install-a", endpoint=lambda: ep_a, clock=clock, timeout=0.5)
        service = svc.SyncService(a, lease_a, install_id="install-a", transports=[adapter], clock=clock,
                                  scheduler=sched, worker=worker,
                                  change_marker=lambda: svc.vault_change_marker(a))
        service.on_unlock()
        worker.drain()
        assert len(runs) == 1
        assert runs[0] == (["unreachable"] if not peer_listening else [])
        after_first = (a._disk_digest, a._payload["generation"])
        backups = sorted(p.name for p in (tmp_path / "Backups").glob("vault-*.json")) \
            if (tmp_path / "Backups").exists() else []

        for _ in range(30 * 60):  # thirty simulated minutes, nobody edits anything
            sched.advance(1)
            worker.drain()

        assert (a._disk_digest, a._payload["generation"]) == after_first, "an idle peer must not write the vault"
        assert len(runs) == 1 + (30 * 60) // svc.RUN_INTERVAL_SECONDS, "no self-triggered (debounced) runs"
        now_backups = sorted(p.name for p in (tmp_path / "Backups").glob("vault-*.json")) \
            if (tmp_path / "Backups").exists() else []
        assert now_backups == backups, "sync bookkeeping must not rotate rolling backups"
        service.stop()
    finally:
        for t in transports:
            t.stop()
        hold_a.close()
        hold_b.close()


def test_sync_state_save_is_skipped_when_unchanged_and_never_takes_a_rolling_backup(tmp_path: Path) -> None:
    a = create_vault(tmp_path / "a.json", MASTER, kdf_overrides=TEST_KDF)
    a.backup_dir, a.backup_count = tmp_path / "Backups", 20
    state = _joined(a)
    digest = a._disk_digest
    assert save_sync_state(a, state) is False
    assert a._disk_digest == digest
    assert save_sync_state(a, dataclasses.replace(state, own_counter=5)) is True
    assert a._disk_digest != digest
    assert not list((tmp_path / "Backups").glob("vault-*.json"))  # sync-only save: no rolling backup
    a.upsert_web(origin="https://example.com", username="me", password="pw-123456", label="x")
    assert len(list((tmp_path / "Backups").glob("vault-*.json"))) == 1  # a user edit still backs up


def test_a_user_edit_during_a_ui_window_of_a_run_is_still_noticed(session) -> None:
    """The run settles the marker, except when it moved while the UI could run (a possible user edit)."""
    _joined(session)
    marker = {"value": 1}

    def edit_while_released() -> None:
        with service.gate.ui_released():
            marker["value"] += 1  # the user saved while sync waited on folder I/O

    t = FakeTransport(hook=edit_while_released)
    service, sched, worker = _service(session, [t], change_marker=lambda: marker["value"])
    service.on_unlock()
    worker.drain()
    assert t.runs == 1
    t.hook = None
    sched.advance(svc.POLL_SECONDS)
    sched.advance(svc.DEBOUNCE_SECONDS)
    worker.drain()
    assert t.runs == 2  # the edit made during the run triggers the debounced rerun
    sched.advance(60)
    worker.drain()
    assert t.runs == 2


def test_sync_writes_inside_a_run_do_not_trigger_a_rerun(session) -> None:
    _joined(session)
    marker = {"value": 1}

    def sync_write() -> None:
        marker["value"] += 1  # sync's own write, with the UI parked

    t = FakeTransport(hook=sync_write)
    service, sched, worker = _service(session, [t], change_marker=lambda: marker["value"])
    service.on_unlock()
    worker.drain()
    sched.advance(60)
    worker.drain()
    assert t.runs == 1


# --- I5: create, join and rotate jobs run the KDF and folder I/O with the UI released ----------------------


def test_create_join_rotate_jobs_release_the_ui_for_kdf_and_folder_io(tmp_path: Path, monkeypatch) -> None:
    from localvault.app import sync_view as ui

    root = tmp_path / "OneDrive"
    root.mkdir()
    seen: dict[str, set[bool]] = {}
    barriers: list[_RecordingBarrier] = []

    def parked() -> bool:
        return any(b.parked for b in barriers)

    def spy(owner, name, *, cheap: bool = False):
        real = getattr(owner, name)

        def call(*args, **kwargs):
            seen.setdefault(name, set()).add(parked())
            if cheap:
                kwargs["_kdf_override"] = CHEAP  # the real Argon2id parameters are too slow for a unit test
            return real(*args, **kwargs)

        monkeypatch.setattr(owner, name, call)

    for name in ("create_group", "join_with_password", "rotate"):
        spy(ft, name, cheap=True)
    for name in ("_read_bounded", "_atomic_write", "load_sync_state", "save_sync_state"):
        spy(ft, name)
    spy(ft.FolderSync, "write_keyring")

    def service_for(name: str, install: str):
        session = create_vault(tmp_path / f"{name}.json", MASTER, kdf_overrides=TEST_KDF)
        barrier = _RecordingBarrier()
        barriers.append(barrier)
        service = svc.SyncService(session, FakeLease(), install_id=install,
                                  transports=[svc.FolderAdapter(install_id=install, _kdf_override=CHEAP)],
                                  clock=FakeClock(), scheduler=FakeScheduler(FakeClock()), worker=InlineWorker(),
                                  gate=svc.SyncGate(barrier))
        return session, service

    def run_job(service, job) -> None:
        done: list = []
        assert service.submit(job, lambda result, error: done.append(error), run_after=True)
        service._worker.drain()
        assert done == [None]
        assert service.status().last_sync == NOW  # run_after: the service ran sync after the job

    a, service_a = service_for("ja", INSTALL)
    run_job(service_a, ui.create_group_job(str(root), PW, "PC A", INSTALL))
    b, service_b = service_for("jb", "install-b")
    run_job(service_b, ui.join_folder_job(str(root), PW, "PC B", "install-b"))
    # The keep-list is what the confirmation showed (audit M10): B was listed and kept.
    run_job(service_a, ui.rotate_job(PW2, (), INSTALL, lambda: None, (load_sync_state(b).device_id,)))

    for name in ("create_group", "join_with_password", "rotate", "write_keyring", "_read_bounded", "_atomic_write"):
        assert seen[name] == {False}, name  # Argon2id and folder I/O: UI free
    for name in ("load_sync_state", "save_sync_state"):
        assert seen[name] == {True}, name  # vault access: UI parked
    assert load_sync_state(a).epoch == 2
    assert set(load_sync_state(a).members) == {load_sync_state(a).device_id, load_sync_state(b).device_id}


def test_group_helpers_without_run_do_not_touch_the_folder_beyond_the_keyring(tmp_path: Path) -> None:
    root = tmp_path / "OneDrive"
    root.mkdir()
    a = create_vault(tmp_path / "ra.json", MASTER, kdf_overrides=TEST_KDF)
    report = ft.create_folder_group(root, a, FakeLease(), PW, "PC A", install_id=INSTALL, now=NOW, run=False,
                                    _kdf_override=CHEAP)
    assert report == RunReport()
    state = load_sync_state(a)
    assert not ft.FolderSync(root, install_id=INSTALL).device_file(state.device_id).exists()


# --- M7: the worker thread survives failing jobs and restarts after an interrupt ------------------------------


class _OddFailure(BaseException):
    """A BaseException that is not KeyboardInterrupt/SystemExit."""


def test_thread_worker_survives_base_exceptions_and_restarts_after_an_interrupt(caplog) -> None:
    worker = svc.ThreadWorker(name="test-sync-worker")
    done = queue.Queue()

    def fail_odd() -> None:
        raise _OddFailure("odd")

    def interrupt() -> None:
        raise KeyboardInterrupt

    try:
        worker.submit(fail_odd)
        worker.submit(lambda: done.put(("after-odd", threading.current_thread())))
        label, first_thread = done.get(timeout=5)
        assert label == "after-odd"  # the same thread carried on after a BaseException
        assert first_thread.is_alive()

        worker.submit(interrupt)
        first_thread.join(5)
        assert not first_thread.is_alive()  # KeyboardInterrupt: logged, then the thread stopped
        assert not worker.alive
        assert any("interrupted" in r.getMessage() for r in caplog.records)

        worker.submit(lambda: done.put(("restarted", threading.current_thread())))
        label, second_thread = done.get(timeout=5)
        assert label == "restarted" and second_thread is not first_thread
    finally:
        worker.stop(wait=True)


# --- licences carried by sync ---------------------------------------------------------------------


#: pytest fixture: a generated test licence key in LICENSE_KEYS (never a production key).
signer = test_licensing.signer
make_bundle = test_licensing.make_bundle
ISSUED = test_licensing.ISSUED


class LicenceTransport(FakeTransport):
    def __init__(self, bundles, **kw) -> None:
        super().__init__(**kw)
        self.bundles = tuple(bundles)

    def run(self, session, lease, *, now: int, gate) -> RunReport:
        report = super().run(session, lease, now=now, gate=gate)
        return dataclasses.replace(report, licenses=self.bundles)


def _run_with_licences(session, bundles, posted=None):
    _joined(session)
    service, _sched, worker = _service(session, [LicenceTransport(bundles)], posted=posted)
    service.run_now()
    worker.drain()
    return service


def test_synced_license_installs_when_free(session, signer) -> None:
    bundle = make_bundle(signer)
    assert licensing.status(build_date=ISSUED).state == "free"
    posted: list = []
    _run_with_licences(session, [bundle], posted)
    assert licensing.status(build_date=ISSUED).state == "pro"
    assert licensing.vault_copy(session) == bundle
    assert posted[-1].license_adopted is True


def test_synced_license_does_not_replace_a_valid_one(session, signer) -> None:
    mine = make_bundle(signer)
    licensing.install_license(licensing.encode_paste(mine))
    other = make_bundle(signer, license_id="lic-0002", name="Someone Else")
    posted: list = []
    _run_with_licences(session, [other], posted)
    assert licensing.status(build_date=ISSUED).license.license_id == "lic-0001"
    assert posted[-1].license_adopted is False


def test_synced_license_respects_removed_marker(session, signer) -> None:
    bundle = make_bundle(signer)
    licensing.install_license(licensing.encode_paste(bundle))
    licensing.remove_license()
    assert licensing.removal_pending()
    _run_with_licences(session, [bundle])
    assert licensing.status(build_date=ISSUED).state == "free"
    assert not licensing.license_path().exists()
    assert licensing.vault_copy(session) is None


def test_synced_revoked_license_not_installed(session, signer, monkeypatch) -> None:
    monkeypatch.setattr(licensing, "_cached_revoked_ids", lambda: frozenset({"lic-0001"}))
    good = make_bundle(signer, license_id="lic-0002")
    revoked = make_bundle(signer)
    _run_with_licences(session, [revoked])
    assert not licensing.license_path().exists()
    _run_with_licences(session, [revoked, good])
    assert licensing.status(build_date=ISSUED).license.license_id == "lic-0002"


def test_synced_license_is_not_adopted_after_lock(session, signer) -> None:
    _joined(session)
    lease = FakeLease()

    def lock() -> None:
        lease.valid = False

    t = LicenceTransport([make_bundle(signer)], hook=lock)
    service, _sched, worker = _service(session, [t], lease=lease)
    service.run_now()
    worker.drain()
    assert not licensing.license_path().exists()


def test_missed_adoption_is_retried_from_the_stored_licence(session, signer) -> None:
    from localvault.sync.vault_bridge import sync_only_save

    bundle = make_bundle(signer)
    sid = licensing.sync_state_id("lic-0001")
    _joined(session)
    lease = FakeLease()

    def store_then_lock() -> None:  # run_merge stored the licence, then the vault locked
        with sync_only_save(session), session.transaction():
            session._require_typed_catalog()["sync_licenses"] = {sid: bundle}
        lease.valid = False

    t = LicenceTransport([bundle], hook=store_then_lock)
    service, _sched, worker = _service(session, [t], lease=lease)
    service.run_now()
    worker.drain()
    assert not licensing.license_path().exists()

    lease.valid = True
    t.hook, t.bundles = None, ()
    service.run_now()
    worker.drain()
    assert licensing.status(build_date=ISSUED).state == "pro"


# --- the pairing screen asks whether the listener really runs ---------------------------------------------


def test_lan_listen_state_reports_the_bound_endpoint(session) -> None:
    _lan_group(session)
    service, _sched, worker, adapter = _lan_service(session)
    assert service.lan_listen_state() == (None, svc.SyncIssue("lan-not-listening"))
    service.on_unlock()
    worker.drain()
    assert service.lan_listen_state() == (ENDPOINT, None)
    service.stop()


def test_lan_listen_state_names_an_install_mismatch(session) -> None:
    lan.create_lan_group(session, FakeLease(), install_id="another-pc")
    service, _sched, worker, _adapter = _lan_service(session)
    service.on_unlock()
    worker.drain()
    endpoint, issue = service.lan_listen_state()
    assert endpoint is None and issue.kind == "rejoin-required"


def test_a_failed_bind_is_reported_with_a_readable_reason(session) -> None:
    class RefusingTransport(FakeSyncTransport):
        def start(self, endpoint) -> None:
            error = OSError(49, "Can't assign requested address")
            error.winerror = 10049
            raise lan.TransportError("LAN listener could not be started") from error

    _lan_group(session)
    adapter = svc.LanAdapter(install_id=INSTALL, endpoint=lambda: ENDPOINT, transport_factory=RefusingTransport,
                             clock=FakeClock())
    service, _sched, worker = _service(session, [adapter])
    service.on_unlock()
    worker.drain()
    endpoint, issue = service.lan_listen_state()
    assert endpoint is None and issue.kind == "listen-failed"
    assert issue.detail == "this address does not belong to this PC any more (OSError 10049)"


def test_a_real_bind_on_an_address_this_pc_does_not_have_fails_visibly(session) -> None:
    _lan_group(session)
    foreign = lan.LANEndpoint("10.254.254.254", 45873)  # not an address of this machine
    adapter = svc.LanAdapter(install_id=INSTALL, endpoint=lambda: foreign, clock=FakeClock())
    service, _sched, worker = _service(session, [adapter])
    service.on_unlock()
    worker.drain()
    endpoint, issue = service.lan_listen_state()
    service.stop()
    assert endpoint is None and issue.kind == "listen-failed"
    assert "does not belong to this PC" in issue.detail


def test_listen_issue_is_cleared_once_the_listener_runs_or_is_not_wanted(session) -> None:
    _lan_group(session)
    wanted = {"endpoint": ENDPOINT}
    adapter = svc.LanAdapter(install_id=INSTALL, endpoint=lambda: wanted["endpoint"],
                             transport_factory=FakeSyncTransport, clock=FakeClock())
    service, _sched, worker = _service(session, [adapter])
    service.on_unlock()
    worker.drain()
    adapter.listen_issue = svc.SyncIssue("listen-failed", "old")
    service.submit(lambda s, l, g: None)
    worker.drain()  # already listening on that endpoint: the old failure is gone
    assert adapter.listen_issue is None
    adapter.listen_issue = svc.SyncIssue("listen-failed", "old")
    wanted["endpoint"] = None
    service.submit(lambda s, l, g: None)
    worker.drain()  # Wi-Fi sync turned off: nothing to report
    assert adapter.listen_issue is None
    service.stop()


def test_lan_listen_state_ignores_unrelated_global_issues(session) -> None:
    service, _sched, worker, _adapter = _lan_service(session)
    with service._mu:
        service._status.global_issues = (svc.SyncIssue("keyring-missing"),)
    assert service.lan_listen_state() == (None, svc.SyncIssue("lan-not-listening"))
    with service._mu:
        service._status.global_issues = (svc.SyncIssue("keyring-missing"), svc.SyncIssue("state-corrupt", "x"))
    assert service.lan_listen_state()[1].kind == "state-corrupt"
