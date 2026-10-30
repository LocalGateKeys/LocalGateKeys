"""Background sync service: runs the folder and LAN transports for one unlocked vault.

When it runs
------------
* once on unlock (``on_unlock``), then every ``RUN_INTERVAL_SECONDS`` (``tick``);
* ``DEBOUNCE_SECONDS`` after the last local change (``on_local_change``; the app
  polls a cheap vault write marker every ``POLL_SECONDS`` instead of hooking
  every edit path).  Sync's own writes are not local changes: the poll skips
  while a run is in progress and each run, before it leaves the gate, takes the
  current marker as seen, unless the marker moved across a window in which the
  UI could run (a possible user edit, left for the next poll).  Runs that
  change nothing write nothing (unchanged ``SyncGroupState`` is not saved, LAN
  reserves no counters), and sync-only saves skip the rolling backup;
* on demand (``run_now``).

Runs are single-flight: one run at a time on the worker thread, and any number
of requests made during a run collapse into one rerun.  Nothing runs on the Tk
thread: the scheduler callbacks only flip flags and hand work to the worker.

Threads and the one lock
------------------------
``VaultSession`` is not thread-safe and the Tk thread edits it freely, so every
piece of sync work that touches the vault goes through one ``SyncGate``:

* a reentrant lock around every ``SyncGroupState`` read-modify-write in this
  process (folder runs, LAN requests served on listener threads, the LAN hello
  counter source, enrollment, reset).  Two writers can no longer load the same
  state and save over each other's counters;
* an optional ``UiBarrier``: while the gate is held off the Tk thread, the Tk
  thread is parked inside a posted callable, so no Tk handler reads or edits
  the vault meanwhile.  Pure folder I/O (reading peer files, writing the own
  file) releases the barrier but keeps the lock; LAN network round trips
  release both (``sync_with`` saves nothing from a stale snapshot), so two
  devices syncing with each other at the same time cannot deadlock.

Lock ordering is gate lock, then barrier.  The Tk thread must never wait for
the gate (it would deadlock with a worker waiting to park it), so every entry
point that needs the vault (listener start, enrollment, reset) is queued on the
worker.  Waiting to park gives up when the service stops or the lease ends.

Lease
-----
Every run checks the unlock lease before touching the vault, and the
transports check it before each write.  Locking the vault during a run makes
the next check raise; the run stops without writing and the status shows it as
aborted (``test_lock_during_run_aborts``).

Install binding
---------------
The install id comes from a file in the data directory (``sync.install``).  A
vault whose stored install id differs (copied or restored onto another PC) is
reported as ``rejoin-required``; no transport runs and no listener starts.

Contracts for UI code (Task 8)
------------------------------
* The Tk thread never waits on the gate (no ``gate.hold()``, no joining the
  worker): use ``SyncService`` entry points, which queue worker jobs.
* Every ``SyncGroupState`` change (join, leave, remove peer, rotate, reset,
  enrollment) goes through a worker job inside the gate, never directly from a
  Tk handler: ``SyncService.submit(job, on_done)`` runs ``job(session, lease,
  gate)`` that way and hands the result to ``on_done`` on the worker thread.
* A Tk handler that pumps a nested event loop (modal dialog, ``wait_window``,
  ``update``) must not hold a ``session.transaction()`` across it: a parked
  sync job could run inside that loop and see the half-done transaction.
* ``reset_sync`` / ``SyncService.reset`` only after explicit user confirmation.
* A job's slow non-vault work (Argon2id, cloud-folder I/O) runs inside
  ``gate.ui_released()`` so the UI is not parked meanwhile; the create, join
  and rotate helpers take ``ui_released=gate.ui_released`` for that.  A job
  that should be followed by a sync run asks for one with
  ``submit(..., run_after=True)`` instead of running a transport inline.

Sync is Pro-only (2026-10-19).  On the free plan the app builds only a
licence-only service (below); as a second line, a full service whose session
does not allow ``"sync"`` (``session.pro_features``) starts no listener and
runs no round.  Data earlier syncs brought stays in the vault either way.

Licence-only mode (free PC, 2026-10-29)
---------------------------------------
``SyncService(licence_only=True)`` lets a free PC receive a licence bought on
another device (App Store, Play, a Pro PC) and nothing else:

* it runs no round on unlock and no timers: only ``run_now`` and jobs with
  ``run_after`` start one.  The LAN listener runs only for
  ``LICENCE_ONLY_LISTEN_SECONDS`` after such a round, and while a pairing code
  is armed (plus that long), so a paired phone can connect;
* every adapter runs licence-only (``licence_only`` set on it; an adapter
  without the attribute is skipped): the folder reads the peers' views and
  writes nothing (``FolderSync.licence_round``); LAN exchanges send an empty
  view, answer a peer's view with an empty one, refuse witness and document
  requests, and keep only the licences (``vault_bridge.licenses_in_views``).
  No merge, no apply, no witness flush, no peer bookkeeping;
* the licences found go to ``licensing.adopt_synced_license`` as below
  (verifies, not revoked, covers this build, no removal pending).  Once it
  installs one, the app sees ``license_adopted``, the plan turns Pro and the
  app replaces this service with a full one.

Licences carried by sync
------------------------
A run's ``RunReport.licenses`` (licence bundles received that verified) and
every verified licence the vault already keeps (``published_licenses``) are
offered to ``licensing.adopt_synced_license`` at the end of every run, still
inside the gate: the UI is parked, so the vault copy it stores and the licence
file it writes cannot race a licence install or removal on the Tk thread, and
nothing happens once the vault locked (the lease is checked first).  When a
licence was installed, the run's ``SyncStatusView.license_adopted`` is set and
the app refreshes its Pro state from the posted status.
"""
from __future__ import annotations

import contextlib
import dataclasses
import functools
import logging
import queue
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from .. import licensing
from .folder_transport import FolderSync
from .lan_sync import ENROLL_GRACE_SECONDS, LanResponder, sync_with, transport_state
from .runner import RunReport, SyncIssue
from .transport import LANEndpoint, SyncTransport
from .vault_bridge import (
    BridgeError,
    SyncGroupState,
    _check_lease,
    load_sync_state,
    published_licenses,
)

RUN_INTERVAL_SECONDS = 5 * 60
DEBOUNCE_SECONDS = 10
POLL_SECONDS = 1.0
#: Licence-only: how long the LAN listener stays up after a requested round (and after a pairing code expires).
LICENCE_ONLY_LISTEN_SECONDS = 120.0
#: Longest the Tk thread stays parked for one held gate before it carries on regardless.
MAX_UI_PARK_SECONDS = 120.0

#: Issue kinds that are informational: shown in the sync screen, but the status bar stays calm.
NOTICE_KINDS = frozenset({
    "counter-resynced", "keyring-restored", "busy", "ignored-file", "stale-self", "unreachable", "no-endpoint",
})

_log = logging.getLogger(__name__)


class SyncAborted(RuntimeError):
    """The run stopped because the service stopped or the vault locked."""


# --- UI barrier and the gate ----------------------------------------------------------------------


class ParkToken:
    """One parking of the UI thread: ``release`` lets it go; ``broken`` is set if it gave up waiting."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.broken = threading.Event()


class UiBarrier:
    """Parks the UI thread inside a posted callable while a worker uses the vault.

    *post* queues a callable on the UI thread (``AgentApp._post_to_ui``).
    ``park`` returns once the UI thread is parked; ``unpark`` lets it go.  On
    the UI thread itself both are no-ops.

    Safety valve: after *max_park* seconds the UI thread marks the token
    broken and resumes.  From then on the gate refuses every vault touch of
    that hold (``SyncGate.check`` raises ``SyncAborted``), so the run aborts at
    its next check without writing.
    """

    def __init__(self, post: Callable[[Callable[[], None]], None], *,
                 is_ui_thread: Callable[[], bool], max_park: float = MAX_UI_PARK_SECONDS,
                 poll: float = 0.05) -> None:
        self._post = post
        self._is_ui_thread = is_ui_thread
        self._max_park = max_park
        self._poll = poll

    def park(self, cancelled: Callable[[], bool]) -> ParkToken | None:
        if self._is_ui_thread():
            return None
        parked = threading.Event()
        token = ParkToken()
        max_park = self._max_park

        def hold() -> None:
            parked.set()
            if not token.release.wait(max_park):
                token.broken.set()  # set before the UI resumes: the worker's next check aborts
                _log.warning("sync kept the UI parked for %.0f s; aborting the run and resuming the UI", max_park)

        self._post(hold)
        while not parked.wait(self._poll):
            if cancelled():
                token.release.set()  # if the UI picks it up later, it returns at once
                raise SyncAborted("Sync stopped while waiting for the UI")
        return token

    @staticmethod
    def unpark(token: ParkToken | None) -> None:
        if token is not None:
            token.release.set()


class SyncGate:
    """The one lock for sync state, plus the optional UI barrier (see the module docstring)."""

    def __init__(self, barrier: UiBarrier | None = None, *, cancelled: Callable[[], bool] | None = None) -> None:
        self._cond = threading.Condition(threading.Lock())
        self._owner: int | None = None
        self._count = 0
        self._barrier = barrier
        self._token: Any = None
        self._parked = False
        self._broken = False  # a park of the current outermost hold timed out
        self.cancelled: Callable[[], bool] = cancelled or (lambda: False)
        #: Optional vault change marker (set by the service).  Each window in which
        #: the owner lets the UI run (``ui_released``/``released``) compares it
        #: before and after; a change not explained by gated (sync) holds inside
        #: the window sets ``ui_changed``.
        self.watch: Callable[[], Any] | None = None
        self.ui_changed = False
        self._window_log: list[tuple[Any, Any]] | None = None

    def _watched(self) -> Any:
        watch = self.watch
        if watch is None:
            return None
        try:
            return watch()
        except Exception:  # noqa: BLE001 - a locked session has no marker
            return None

    def _open_window(self) -> tuple[Any, Any]:
        """Start watching a UI window; returns (marker before, the enclosing window's log)."""
        outer = self._window_log
        self._window_log = []
        return self._watched(), outer

    def _close_window(self, before: Any, outer: list[tuple[Any, Any]] | None) -> None:
        """End a UI window: any marker change not made by a gated hold may be a user edit."""
        log, self._window_log = self._window_log or [], outer
        if outer is not None:
            outer.extend(log)
        if self.watch is None:
            return
        current = before
        for entered, left in log:
            if entered != current:
                self.ui_changed = True
            current = left
        if self._watched() != current:
            self.ui_changed = True

    def owned(self) -> bool:
        return self._owner == threading.get_ident()

    def _acquire(self) -> None:
        me = threading.get_ident()
        with self._cond:
            if self._owner == me:
                self._count += 1
                return
            while self._owner is not None:
                self._cond.wait()
            self._owner, self._count = me, 1

    def _release(self) -> None:
        with self._cond:
            self._count -= 1
            if self._count == 0:
                self._owner = None
                self._broken = False
                self._cond.notify_all()

    @staticmethod
    def _token_broken(token: Any) -> bool:
        broken = getattr(token, "broken", None)
        return isinstance(broken, threading.Event) and broken.is_set()

    def check(self) -> None:
        """Raise ``SyncAborted`` if the UI stopped being parked under this hold (park timeout).

        Called before every vault touch (through the service's lease); a no-op
        for threads that do not hold the gate.
        """
        if not self.owned():
            return
        if self._parked and self._token_broken(self._token):
            self._broken = True
        if self._broken:
            raise SyncAborted("The UI resumed after the park timeout; sync run aborted")

    def _park(self) -> None:
        if self._barrier is not None and not self._parked:
            self._token = self._barrier.park(self.cancelled)
            self._parked = True

    def _unpark(self) -> None:
        if self._parked:
            self._parked = False
            token, self._token = self._token, None
            if self._token_broken(token):
                self._broken = True
            if self._barrier is not None:
                self._barrier.unpark(token)

    @contextlib.contextmanager
    def hold(self) -> Iterator[None]:
        """Hold the lock (reentrant) and park the UI thread for the outermost hold."""
        self._acquire()
        parked_here = False
        # Inside a UI window of the owner, record the marker around this (sync) hold.
        log = self._window_log if not self._parked else None
        entered = self._watched() if log is not None else None
        try:
            if not self._parked:
                self._park()
                parked_here = self._parked
            yield
        finally:
            if log is not None:
                log.append((entered, self._watched()))
            if parked_here:
                self._unpark()
            self._release()

    @contextlib.contextmanager
    def ui_released(self) -> Iterator[None]:
        """Inside ``hold``: let the UI run (no vault access here) but keep the lock."""
        was_parked = self.owned() and self._parked
        before, outer = self._open_window()
        if was_parked:
            self._unpark()
        try:
            yield
        finally:
            if was_parked:
                self._park()
            self._close_window(before, outer)

    @contextlib.contextmanager
    def released(self) -> Iterator[None]:
        """Inside ``hold``: give up the lock and the UI completely (network waits)."""
        if not self.owned():
            yield
            return
        was_parked = self._parked
        before, outer = self._open_window()
        self._unpark()
        broken, self._broken = self._broken, False
        with self._cond:
            count, self._count, self._owner = self._count, 0, None
            self._cond.notify_all()
        try:
            yield
        finally:
            self._acquire()
            with self._cond:
                self._count = count
            self._broken = broken  # a timed-out park earlier in this run still aborts it
            if was_parked:
                self._park()
            self._close_window(before, outer)

    def wrap(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """*fn* run inside ``hold`` (for handlers called on transport threads)."""

        def gated(*args: Any, **kwargs: Any) -> Any:
            with self.hold():
                return fn(*args, **kwargs)

        gated.__wrapped__ = fn  # type: ignore[attr-defined]
        return gated


# --- worker and schedulers ------------------------------------------------------------------------


class Scheduler(Protocol):
    def call_later(self, delay: float, fn: Callable[[], None]) -> Any: ...

    def cancel(self, handle: Any) -> None: ...


class ThreadScheduler:
    """``threading.Timer`` scheduler (callbacks on timer threads)."""

    def call_later(self, delay: float, fn: Callable[[], None]) -> threading.Timer:
        timer = threading.Timer(max(0.0, delay), fn)
        timer.daemon = True
        timer.name = "localgatekeys-sync-timer"
        timer.start()
        return timer

    def cancel(self, handle: Any) -> None:
        if isinstance(handle, threading.Timer):
            handle.cancel()


class TkScheduler:
    """``root.after`` scheduler: callbacks run on the Tk thread; call it from the Tk thread only."""

    def __init__(self, root: Any) -> None:
        self.root = root

    def call_later(self, delay: float, fn: Callable[[], None]) -> Any:
        return self.root.after(max(1, int(delay * 1000)), fn)

    def cancel(self, handle: Any) -> None:
        with contextlib.suppress(Exception):
            self.root.after_cancel(handle)


class ThreadWorker:
    """One daemon thread running submitted jobs in order; started on the first job.

    A job that raises never ends the thread (any ``BaseException`` is logged),
    except ``KeyboardInterrupt``/``SystemExit``: those are logged and the
    thread stops.  ``submit`` starts a new thread whenever the previous one is
    gone, so a worker never stays dead with jobs waiting.
    """

    def __init__(self, name: str = "localgatekeys-sync") -> None:
        self.name = name
        self._queue: queue.Queue[Callable[[], None] | None] = queue.Queue()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stopped = False

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def submit(self, fn: Callable[[], None]) -> None:
        with self._lock:
            if self._stopped:
                return
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._loop, name=self.name, daemon=True)
                self._thread.start()
            self._queue.put(fn)

    def _loop(self) -> None:
        try:
            while True:
                fn = self._queue.get()
                if fn is None:
                    return
                try:
                    fn()
                except (KeyboardInterrupt, SystemExit):
                    _log.exception("sync worker interrupted; its thread stops (the next job starts a new one)")
                    return
                except BaseException:  # noqa: BLE001 - one failed job must not end the worker
                    _log.exception("sync job failed")
        finally:
            with self._lock:
                if self._thread is threading.current_thread():
                    self._thread = None

    def stop(self, wait: bool = False, timeout: float = 2.0) -> None:
        with self._lock:
            self._stopped = True
            thread = self._thread
        self._queue.put(None)
        if wait and thread is not None and thread is not threading.current_thread():
            thread.join(timeout)


# --- status -----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TransportStatus:
    """``last_sync``: when a run of this transport last reached the merge step."""

    name: str
    configured: bool = False
    last_run: int | None = None
    last_sync: int | None = None
    issues: tuple[SyncIssue, ...] = ()


@dataclass(frozen=True)
class SyncStatusView:
    """What the status bar and the sync screen show.

    ``issues`` are de-duplicated by (kind, detail) across transports;
    ``skipped`` lists local records sync cannot read (id, reason);
    ``conflicts`` counts conflict copies made since unlock.
    """

    configured: bool = False
    last_sync: int | None = None
    transports: tuple[TransportStatus, ...] = ()
    issues: tuple[SyncIssue, ...] = ()
    skipped: tuple[tuple[str, str], ...] = ()
    conflicts: int = 0
    running: bool = False
    listening: bool = False
    aborted: bool = False
    #: The last run installed a Pro licence received by sync.
    license_adopted: bool = False
    #: How many items the last run, or the last sync a peer started, added, changed or deleted.
    items_changed: int = 0
    #: Per-device "last synced" times (``SyncGroupState.peer_synced_at``): peer id -> unix seconds.
    peer_synced_at: Mapping[str, int] = field(default_factory=dict)

    @property
    def needs_attention(self) -> bool:
        return any(issue.kind not in NOTICE_KINDS for issue in self.issues)


def dedupe_issues(issues: Iterable[SyncIssue]) -> tuple[SyncIssue, ...]:
    seen: set[tuple[str, str]] = set()
    out: list[SyncIssue] = []
    for issue in issues:
        key = (issue.kind, issue.detail)
        if key not in seen:
            seen.add(key)
            out.append(issue)
    return tuple(out)


# --- transports -------------------------------------------------------------------------------------


class SyncTransportAdapter(Protocol):
    name: str

    def configured(self, state: SyncGroupState) -> bool: ...

    def run(self, session: Any, lease: Any, *, now: int, gate: SyncGate) -> RunReport: ...


class FolderAdapter:
    """The cloud-folder transport (``FolderSync.run_once``) for the stored ``folder_path``."""

    name = "folder"

    def __init__(self, *, install_id: str, _kdf_override: tuple[int, int, int] | None = None) -> None:
        self.install_id = install_id
        self._kdf_override = _kdf_override
        #: Set by a licence-only ``SyncService``: runs read licences only (``FolderSync.licence_round``).
        self.licence_only = False

    def configured(self, state: SyncGroupState) -> bool:
        return bool(state.folder_path)

    def run(self, session: Any, lease: Any, *, now: int, gate: SyncGate) -> RunReport:
        state = load_sync_state(session)
        if state is None or not state.folder_path:
            return RunReport(issues=(SyncIssue("not-joined"),))
        fs = FolderSync(state.folder_path, install_id=self.install_id, _kdf_override=self._kdf_override)
        # Folder I/O (a cloud placeholder download can stall any of these) runs with
        # the UI free; the state lock stays held.  Only vault access stays parked.
        for name in FOLDER_IO_STEPS:
            setattr(fs, name, _ui_released(gate, getattr(fs, name)))
        # The own-file write is fenced: re-check lease, service and park state right before it.
        fs.write_own = _fenced(lease, fs.write_own)
        if self.licence_only:
            return fs.licence_round(session, lease, now=now)
        return fs.run_once(session, lease, now=now)


#: ``FolderSync`` steps that only touch the folder (never the vault).
FOLDER_IO_STEPS = ("_folder_exists", "_trusted_keyring", "_sweep_own_temp_files", "_sweep_keyring_temp_files",
                   "read_peers", "_own_file_status", "write_own")


def _ui_released(gate: SyncGate, fn: Callable[..., Any]) -> Callable[..., Any]:
    def call(*args: Any, **kwargs: Any) -> Any:
        with gate.ui_released():
            return fn(*args, **kwargs)

    return call


def _fenced(lease: Any, fn: Callable[..., Any]) -> Callable[..., Any]:
    def call(*args: Any, **kwargs: Any) -> Any:
        _call_lease(lease)
        return fn(*args, **kwargs)

    return call


def _call_lease(lease: Any) -> None:
    check = getattr(lease, "check", None)
    if check is None and callable(lease):
        check = lease
    if check is None:
        raise SyncAborted("A sync lease is required")
    check()


class FencedLease:
    """The lease the service hands to transports: refuses once the service stopped or the UI park broke.

    Every bridge read/write and every transport write checks the lease first,
    so this is the per-service write fence: a run of a stopped service (vault
    locked, maybe unlocked again with a new service) or a run whose UI park
    timed out aborts at its next check without writing.
    """

    def __init__(self, lease: Any, gate: SyncGate, stopped: Callable[[], bool]) -> None:
        self._lease, self._gate, self._stopped = lease, gate, stopped

    def check(self) -> None:
        if self._stopped():
            raise SyncAborted("The sync service stopped")
        self._gate.check()
        _call_lease(self._lease)


class _ReleasingTransport:
    """The listener transport for ``sync_with``: network round trips release the gate."""

    def __init__(self, inner: Any, gate: SyncGate) -> None:
        self._inner, self._gate = inner, gate

    @property
    def state(self) -> Any:
        return self._inner.state

    def request(self, *args: Any, **kwargs: Any) -> bytes:
        with self._gate.released():
            return self._inner.request(*args, **kwargs)


class _GatedEnrollment:
    """Passed to ``LanResponder.start_enrollment`` so the enrollment handler runs inside the gate."""

    def __init__(self, inner: Any, gate: SyncGate) -> None:
        self._inner, self._gate = inner, gate

    @property
    def state(self) -> Any:
        return self._inner.state

    def set_enrollment_handler(self, handler: Callable[[bytes], bytes | None] | None) -> None:
        """Install *handler* behind the gate; its responder's ``enroll_prefilter`` runs first, outside it.

        A frame for no armed offer, an expired one or another offer id is answered
        without waiting for the gate (a sync run in progress), so stray frames
        cannot queue up behind it or delay it.
        """
        if handler is None:
            self._inner.set_enrollment_handler(None)
            return
        owner = getattr(handler, "__self__", None)
        prefilter = getattr(owner, "enroll_prefilter", None)
        verify, wait, finish = (getattr(owner, name, None)
                                for name in ("enroll_verify", "await_decision", "enroll_finish"))
        if callable(verify) and callable(wait) and callable(finish):
            # Verify and admit inside the gate; the wait for Accept (up to a minute) holds no gate,
            # so sync runs and other requests go on while the prompt is open.
            gated_verify, gated_finish = self._gate.wrap(verify), self._gate.wrap(finish)

            def run(raw: bytes) -> bytes | None:
                first = gated_verify(raw)
                if isinstance(first, bytes) or first is None:
                    return first
                return gated_finish(first, wait(first))
        else:
            run = self._gate.wrap(handler)

        def enroll(raw: bytes) -> bytes | None:
            if callable(prefilter):
                answered, reply = prefilter(raw)
                if answered:
                    return reply
            return run(raw)

        self._inner.set_enrollment_handler(enroll)


#: Global issues that stop the LAN listener from starting (``_joined_state`` returns None for them).
_LAN_BLOCKING_ISSUES = frozenset({"rejoin-required", "state-corrupt", "not-joined"})

_LISTEN_ERRNO_TEXT = {
    10049: "this address does not belong to this PC any more",  # WSAEADDRNOTAVAIL
    49: "this address does not belong to this PC any more",  # EADDRNOTAVAIL (macOS)
    99: "this address does not belong to this PC any more",  # EADDRNOTAVAIL (Linux)
    10048: "another app already uses this port",  # WSAEADDRINUSE
    48: "another app already uses this port",
    98: "another app already uses this port",
    10013: "Windows refused this port (another app or a reserved port range)",  # WSAEACCES
    13: "the system refused this port",
}


def _listen_failure_detail(exc: BaseException) -> str:
    """Readable reason for a failed bind; the original error stays in the text for the error log."""
    cause = exc if isinstance(exc, OSError) else exc.__cause__
    text = f"{type(exc).__name__}: {exc}"
    if isinstance(cause, OSError):
        code = getattr(cause, "winerror", None) or cause.errno
        reason = _LISTEN_ERRNO_TEXT.get(int(code)) if code is not None else None
        text = f"{reason} ({type(cause).__name__} {code})" if reason else f"{type(cause).__name__}: {cause}"
    return text


class LanAdapter:
    """LAN sync: owns the listener and the vault's ONE transport state (one hello counter source).

    The listener runs while the vault is unlocked, joined on this installation,
    and *endpoint* (this device's own private ``LANEndpoint``, from settings)
    is set.  Listening, serving and requesting all use the same transport and
    transport state; the hello counter source and the request handlers run
    inside the gate.
    """

    name = "lan"

    def __init__(self, *, install_id: str, endpoint: Callable[[], LANEndpoint | None],
                 transport_factory: Callable[[Any], Any] | None = None,
                 clock: Callable[[], float] | None = None, monotonic: Callable[[], float] | None = None,
                 timeout: float | None = None, announcer: Any = None, browser: Any = None) -> None:
        self.install_id = install_id
        #: sync.discovery_client browser: finds a paired host whose pinned address stopped answering
        #: (None: no discovery).
        self.browser = browser
        self._endpoint = endpoint
        self.announcer = announcer  # sync.announce.Announcer, or None (no Bonjour announcement)
        self._factory = transport_factory or SyncTransport
        self._clock = clock or time.time
        self._monotonic = monotonic or time.monotonic
        self._timeout = timeout
        self._mu = threading.Lock()
        self._closed = False
        self._key: tuple[str, str, LANEndpoint] | None = None
        self.transport: Any = None
        self.responder: LanResponder | None = None
        self.listen_issue: SyncIssue | None = None
        #: Set by the service: called with the report of each merge a peer (a phone) started.
        self.on_served: Callable[[RunReport], None] | None = None
        #: Set by a licence-only ``SyncService``: exchanges send an empty view and keep only licences.
        self.licence_only = False

    @property
    def listening(self) -> bool:
        return self.transport is not None

    def _wanted_endpoint(self) -> LANEndpoint | None:
        try:
            endpoint = self._endpoint()
        except Exception:  # noqa: BLE001 - a bad setting means "not listening"
            return None
        return endpoint if isinstance(endpoint, LANEndpoint) else None

    def configured(self, state: SyncGroupState) -> bool:
        return self._wanted_endpoint() is not None

    def ensure_listener(self, session: Any, lease: Any, state: SyncGroupState, gate: SyncGate) -> None:
        """Start (or restart for another identity/endpoint) the listener; call inside the gate."""
        endpoint = self._wanted_endpoint()
        with self._mu:
            if self._closed:
                self.listen_issue = None
                return
            key = None if endpoint is None else (state.device_id, state.group_id, endpoint)
            if key is not None and key == self._key and self.transport is not None:
                self.listen_issue = None  # already listening there: an old failure no longer applies
                self._announce(state, endpoint)  # the group key may have rotated
                return
            self._stop_locked()
            if key is None:
                self.listen_issue = None
                return
            try:
                tstate = transport_state(state, session, lease, gate=gate.hold)  # gate only for block refills
                transport = self._factory(tstate)
                responder = LanResponder(session, lease, install_id=self.install_id,
                                         clock=lambda: int(self._clock()), monotonic=self._monotonic)
                responder.on_served = self._served
                responder.licence_only = self.licence_only
                transport.set_peer_request_handler(gate.wrap(responder))
            except Exception as exc:
                # Kept visible (the pairing screen reports it) instead of only in a log line.
                self.listen_issue = SyncIssue("listen-failed", f"{type(exc).__name__}: {exc}")
                raise
            try:
                transport.start(endpoint)
            except (OSError, ValueError) as exc:  # TransportError is a ValueError
                self.listen_issue = SyncIssue("listen-failed", _listen_failure_detail(exc))
                return
            self.listen_issue = None
            self.transport, self.responder, self._key = transport, responder, key
            self._announce(state, endpoint)

    def _announce(self, state: SyncGroupState, endpoint: LANEndpoint | None) -> None:
        if self.announcer is None or endpoint is None:
            return
        from .lan_sync import _group_key

        with contextlib.suppress(Exception):  # announcing is best effort; the pinned address still works
            self.announcer.start(_group_key(state), state.device_id, endpoint.host, endpoint.port)

    def _served(self, report: RunReport) -> None:
        on_served = self.on_served
        if on_served is not None:
            on_served(report)

    def _stop_locked(self) -> None:
        if self.announcer is not None:
            with contextlib.suppress(Exception):
                self.announcer.stop()
        transport, responder = self.transport, self.responder
        self.transport = self.responder = None
        self._key = None
        if responder is not None:
            with contextlib.suppress(Exception):
                responder.stop_enrollment()
        if transport is not None:
            with contextlib.suppress(Exception):
                transport.stop()

    def listening_endpoint(self) -> LANEndpoint | None:
        """The endpoint the listener is bound to and accepting on, or None when nothing listens."""
        transport, key = self.transport, self._key
        if transport is None or key is None:
            return None
        if getattr(transport, "running", True) is False:
            return None
        thread = getattr(transport, "_listener_thread", None)
        if thread is not None and not thread.is_alive():
            return None
        endpoint = getattr(transport, "endpoint", None)
        return endpoint if isinstance(endpoint, LANEndpoint) else key[2]

    def stop_listener(self) -> None:
        with self._mu:
            self._stop_locked()

    def close(self) -> None:
        """Stop the listener for good (the service stopped)."""
        with self._mu:
            self._closed = True
            self._stop_locked()

    def start_enrollment(self, offer: Any, gate: SyncGate) -> bool:
        responder, transport = self.responder, self.transport
        if responder is None or transport is None:
            return False
        responder.start_enrollment(offer, _GatedEnrollment(transport, gate))
        return True

    def expire_enrollment(self) -> None:
        responder = self.responder
        if responder is not None:
            responder.expire_enrollment()

    def _find_again(self, releasing: Any, gate: SyncGate, session: Any, lease: Any, peer_id: str, now: int,
                    found_box: list[Any]) -> RunReport | None:
        """The pinned address of *peer_id* failed: dial its announced LAN addresses (capped).

        The first exchange that completes (``wrote``: the hello verified the pinned keys) stores that
        address and its report is returned; None when no announced address worked.
        """
        from . import discovery, discovery_client
        from .lan_sync import _group_key, peer_endpoint, save_peer_endpoint

        if not found_box:
            try:
                with gate.released():  # the browse waits on the network: never inside the gate
                    found_box.append(self.browser.browse(discovery.SERVICE_TYPE, discovery_client.BROWSE_SECONDS))
            except Exception:  # noqa: BLE001 - discovery is best effort; the pinned failure stands
                found_box.append([])
        _check_lease(session, lease)
        state = load_sync_state(session)  # read again: the gate was released while browsing
        pinned = peer_endpoint(state, peer_id) if state is not None else None
        if pinned is None or not found_box[0]:
            return None
        targets = discovery_client.candidates(found_box[0], _group_key(state), peer_id, now,
                                              port=pinned.port, exclude=pinned)
        timeout = min(self._timeout or discovery_client.DIAL_SECONDS, discovery_client.DIAL_SECONDS)
        for target in targets:
            report = sync_with(releasing, peer_id, session, lease, install_id=self.install_id, now=now,
                               endpoint=target, timeout=timeout, licence_only=self.licence_only)
            if report.wrote:
                save_peer_endpoint(session, lease, peer_id, target, install_id=self.install_id)
                return report
        return None

    def run(self, session: Any, lease: Any, *, now: int, gate: SyncGate) -> RunReport:
        transport, responder = self.transport, self.responder
        if transport is None:
            issue = self.listen_issue or SyncIssue("lan-not-listening")
            return RunReport(issues=(issue,))
        state = load_sync_state(session)
        if state is None:
            return RunReport(issues=(SyncIssue("not-joined"),))
        issues: list[SyncIssue] = []
        skipped: set[tuple[str, str]] = set()
        applied = deleted = conflicts = 0
        own = None
        wrote = False
        licenses: list[dict[str, Any]] = []
        releasing = _ReleasingTransport(transport, gate)
        found_box: list[Any] = []  # one browse per run, shared by every unreachable host
        for entry in state.lan_peers:
            peer_id = entry.get("device_id")
            if not isinstance(peer_id, str) or entry.get("revoked") is True or not entry.get("endpoint"):
                continue  # a peer without an endpoint (a phone) connects to us instead
            report = sync_with(releasing, peer_id, session, lease, install_id=self.install_id, now=now,
                               timeout=self._timeout, licence_only=self.licence_only)
            if any(i.kind == "unreachable" for i in report.issues) and self.browser is not None:
                report = self._find_again(releasing, gate, session, lease, peer_id, now, found_box) or report
            applied, deleted = applied + report.applied, deleted + report.deleted
            conflicts += report.conflicts
            skipped.update(report.skipped)
            issues.extend(report.issues)
            wrote = wrote or report.wrote
            licenses.extend(report.licenses)
            if report.own_states is not None:
                own = report.own_states
        if responder is not None and responder.last_report is not None:
            issues.extend(responder.last_report.issues)  # problems seen while serving peers
            licenses.extend(responder.last_report.licenses)  # licences received from peers we served
            responder.last_report = None
        take_outdated = getattr(transport, "take_outdated_peers", None)
        if callable(take_outdated):
            # Paired devices whose signed hello was of an older protocol (refused, never downgraded).
            for peer_id in take_outdated():
                issues.append(SyncIssue("peer-update-needed", f"{peer_id}: older Wi-Fi sync version"))
        return RunReport(applied=applied, deleted=deleted, conflicts=conflicts, skipped=tuple(sorted(skipped)),
                         issues=tuple(issues), own_states=own, wrote=wrote, licenses=tuple(licenses))


# --- reset ---------------------------------------------------------------------------------------------


def reset_sync(session: Any, lease: Any) -> bool:
    """Forget this vault's sync state (``sync_meta`` and the group) in one transaction.

    For recovery from structural sync-metadata corruption or a forged conflict.
    Call it ONLY after the user explicitly confirmed (it drops the group key,
    device identity and all per-item version vectors; re-joining is needed).
    Items stay; the next join publishes them anew.  Returns whether anything
    was cleared.  In the app, use ``SyncService.reset`` (worker + gate).
    """
    _check_lease(session, lease)
    payload = session._require_typed_catalog()
    if "sync_meta" not in payload and "sync_group" not in payload:
        return False
    with session.transaction():
        payload = session._require_typed_catalog()
        payload.pop("sync_meta", None)
        payload.pop("sync_group", None)
        _check_lease(session, lease)
    return True


def vault_change_marker(session: Any) -> Any:
    """Cheap value that changes on every vault write (the digest of the last saved file)."""
    return getattr(session, "_disk_digest", None)


# --- the service ---------------------------------------------------------------------------------------


_UNSET = object()


@dataclass
class _Status:
    configured: bool = False
    global_issues: tuple[SyncIssue, ...] = ()
    transports: dict[str, TransportStatus] = field(default_factory=dict)
    skipped: dict[str, tuple[tuple[str, str], ...]] = field(default_factory=dict)
    conflicts: int = 0
    aborted: bool = False
    license_adopted: bool = False
    items_changed: int = 0


def _changed_items(report: RunReport) -> int:
    return report.applied + report.deleted + report.conflicts


class SyncService:
    """Runs the transports for one unlocked vault; see the module docstring.

    *lease* is what the bridge accepts (an object with ``check()`` or a
    callable) and raises once the unlock session ends.  *transports* are
    adapters with ``name``, ``configured(state)`` and ``run(session, lease, *,
    now, gate)``; adapters with ``ensure_listener``/``stop_listener``/``close``
    get the listener lifecycle.  *post_result* receives the new
    ``SyncStatusView`` after every run (on the worker thread; the app posts it
    to Tk).  Call the entry points from the UI thread (or use a thread-safe
    scheduler).
    """

    def __init__(self, session: Any, lease: Any, *, install_id: str,
                 transports: Sequence[SyncTransportAdapter], clock: Callable[[], float] = time.time,
                 scheduler: Scheduler | None = None, worker: Any = None,
                 post_result: Callable[[SyncStatusView], None] | None = None,
                 gate: SyncGate | None = None, change_marker: Callable[[], Any] | None = None,
                 licence_only: bool = False) -> None:
        if not isinstance(install_id, str) or not install_id:
            raise ValueError("install id must be a non-empty string")
        self.session = session
        #: A free PC: see "Licence-only mode" in the module docstring.
        self.licence_only = bool(licence_only)
        #: Licence-only: the clock time until which the LAN listener may run (pairing or a round).
        self._listen_until = 0.0
        self._raw_lease = lease
        self.install_id = install_id
        self._transports = tuple(transports)
        self._clock = clock
        self._scheduler = scheduler or ThreadScheduler()
        self._worker = worker if worker is not None else ThreadWorker()
        self._post_result = post_result
        self._stopped = threading.Event()
        self.gate = gate or SyncGate()
        self.gate.cancelled = self._cancelled
        self.gate.watch = change_marker
        # Everything below gets the fenced lease (service stopped / park broken -> SyncAborted).
        self._lease = FencedLease(lease, self.gate, self._stopped.is_set)
        self._marker = change_marker
        self._last_marker: Any = _UNSET
        self._mu = threading.Lock()
        self._running = False
        self._pending = False
        self._timers: dict[str, Any] = {}
        self._enroll_timers: list[Any] = []
        self._status = _Status(transports={t.name: TransportStatus(t.name) for t in self._transports})
        for adapter in self._transports:
            if hasattr(adapter, "on_served"):
                adapter.on_served = functools.partial(self._peer_synced, adapter.name)
            if hasattr(adapter, "licence_only"):
                adapter.licence_only = self.licence_only

    # lease ---------------------------------------------------------------------------------------

    def _lease_ok(self) -> bool:
        try:
            _check_lease(self.session, self._raw_lease)
        except Exception:  # noqa: BLE001 - any failure means the unlock session is over
            return False
        return True

    def _cancelled(self) -> bool:
        return self._stopped.is_set() or not self._lease_ok()

    # scheduling ----------------------------------------------------------------------------------

    def _schedule(self, key: str, delay: float, fn: Callable[[], None]) -> None:
        old = self._timers.pop(key, None)
        if old is not None:
            self._scheduler.cancel(old)
        if not self._stopped.is_set():
            self._timers[key] = self._scheduler.call_later(delay, fn)

    def _plan_allows_sync(self) -> bool:
        allowed = getattr(self.session, "pro_features", None)
        return allowed is None or "sync" in allowed

    def _may_run(self) -> bool:
        """A round may run: the plan includes sync, or this is a licence-only service."""
        return self.licence_only or self._plan_allows_sync()

    def on_unlock(self) -> None:
        """Start the listener (if configured), run once, then every five minutes.

        A licence-only service does nothing here: it runs only when asked
        (``run_now``, a job with ``run_after``) and listens only then.
        """
        if self._stopped.is_set() or self.licence_only or not self._plan_allows_sync():
            return
        self._worker.submit(self._listener_job)
        self._request()
        self._schedule("interval", RUN_INTERVAL_SECONDS, self.tick)
        if self._marker is not None:
            self._schedule("poll", POLL_SECONDS, self._poll)

    def tick(self) -> None:
        """The five-minute timer."""
        if self._stopped.is_set():
            return
        self._request()
        self._schedule("interval", RUN_INTERVAL_SECONDS, self.tick)

    def on_local_change(self) -> None:
        """A local edit: run ``DEBOUNCE_SECONDS`` after the last one."""
        self._schedule("debounce", DEBOUNCE_SECONDS, self._debounced)

    def _debounced(self) -> None:
        self._timers.pop("debounce", None)
        self._request()

    def _poll(self) -> None:
        if self._stopped.is_set() or self._marker is None:
            return
        changed = False
        with self._mu:
            # During a run the vault changes under sync's own writes; the run
            # settles the marker when it ends (``_settle_marker``).
            if not self._running:
                marker = self._read_marker()
                if self._last_marker is _UNSET:
                    self._last_marker = marker
                elif marker != self._last_marker:
                    self._last_marker = marker
                    changed = True
        if changed:
            self.on_local_change()
        self._schedule("poll", POLL_SECONDS, self._poll)

    def _read_marker(self) -> Any:
        if self._marker is None:
            return _UNSET
        try:
            return self._marker()
        except Exception:  # noqa: BLE001 - a locked session has no marker; stop() follows
            return _UNSET

    def _settle_marker(self) -> None:
        """End of a run, still inside the gate: sync's own writes are not a local change.

        A change seen across a window in which the UI could run (the gate's
        ``ui_changed``) may be a user edit, so the marker is left alone and the
        next poll reports it.
        """
        if self._marker is None:
            return
        marker = self._read_marker()
        with self._mu:
            if not self.gate.ui_changed:
                self._last_marker = marker

    def run_now(self) -> None:
        self._request()

    def _request(self) -> None:
        with self._mu:
            if self._stopped.is_set():
                return
            if self._running:
                self._pending = True
                return
            self._running = True
        self._worker.submit(self._run_loop)

    def stop(self) -> None:
        """Stop for good (vault locked or app closing): timers, listener, worker. Never blocks on a run."""
        self._stopped.set()
        for handle in (*self._timers.values(), *self._enroll_timers):
            self._scheduler.cancel(handle)
        self._timers.clear()
        self._enroll_timers.clear()
        for adapter in self._transports:
            close = getattr(adapter, "close", None)
            if close is not None:
                close()
        self._worker.stop(wait=False)

    # worker side ------------------------------------------------------------------------------------

    def _run_loop(self) -> None:
        while True:
            again = False
            try:
                try:
                    self._run_once()
                except Exception:  # noqa: BLE001 - keep the worker alive
                    _log.exception("sync run failed")
                finished = True
            except BaseException:
                finished = False
                raise
            finally:
                # Even a BaseException must never leave the service "running" forever.
                with self._mu:
                    again = finished and self._pending and not self._stopped.is_set()
                    self._pending = False
                    self._running = again
            self._publish()
            if not again:
                return

    def _joined_state(self) -> SyncGroupState | None:
        """The stored state if this installation may sync it; updates the global status."""
        try:
            state = load_sync_state(self.session)
        except BridgeError as exc:
            self._set_global(True, (SyncIssue("state-corrupt", str(exc)),))
            return None
        if state is None:
            self._set_global(False, ())
            return None
        if state.install_id != self.install_id:
            configured = any(t.configured(state) for t in self._transports)
            self._set_global(configured, (SyncIssue("rejoin-required", "install-mismatch"),))
            return None
        self._set_global(any(t.configured(state) for t in self._transports), ())
        return state

    def _set_global(self, configured: bool, issues: tuple[SyncIssue, ...]) -> None:
        with self._mu:
            self._status.configured = configured
            self._status.global_issues = issues

    def _sync_listeners(self, state: SyncGroupState | None) -> None:
        if self.licence_only and self._clock() >= self._listen_until:
            state = None  # licence-only: no listener outside pairing and a requested round
        for adapter in self._transports:
            if state is not None and hasattr(adapter, "ensure_listener"):
                adapter.ensure_listener(self.session, self._lease, state, self.gate)
            elif state is None and hasattr(adapter, "stop_listener"):
                adapter.stop_listener()

    def _open_listen_window(self, seconds: float) -> None:
        """Licence-only: let the LAN listener run for *seconds* from now, then stop it."""
        until = float(self._clock()) + max(0.0, float(seconds))
        with self._mu:
            if until <= self._listen_until:
                return
            self._listen_until = until
        self._schedule("listen-window", until - float(self._clock()),
                       lambda: self._worker.submit(self._listener_job))

    def _listener_job(self) -> None:
        if self._stopped.is_set() or not self._may_run():
            return
        try:
            with self.gate.hold():
                _check_lease(self.session, self._lease)
                self._sync_listeners(self._joined_state())
        except Exception:  # noqa: BLE001 - locked or stopped meanwhile: nothing to start
            if not self._cancelled():
                _log.exception("starting the sync listener failed")

    def _run_once(self) -> None:
        if self._stopped.is_set() or not self._may_run():
            return
        if self.licence_only:
            # A requested round: paired phones (which connect to this PC) can reach it for a while.
            self._open_listen_window(LICENCE_ONLY_LISTEN_SECONDS)
        now = int(self._clock())
        results: dict[str, RunReport] = {}
        configured: dict[str, bool] = {}
        adopted = False
        try:
            with self.gate.hold():
                self.gate.ui_changed = False
                if self._marker is not None:
                    with self._mu:
                        if self._last_marker is _UNSET:  # first run before the first poll
                            self._last_marker = self._read_marker()
                _check_lease(self.session, self._lease)
                try:
                    self._run_transports(now, results, configured)
                    adopted = self._adopt_licenses(results)
                finally:
                    self._settle_marker()
        except Exception as exc:
            if not (isinstance(exc, SyncAborted) or self._cancelled()):
                raise
            # Locked, stopped or the UI park timed out mid-run: nothing more was written.
            with self._mu:
                self._status.aborted = True
                self._status.license_adopted = False
            return
        self._record(now, configured, results, adopted)

    def _run_transports(self, now: int, results: dict[str, RunReport], configured: dict[str, bool]) -> None:
        """One pass over the configured transports (inside the gate)."""
        state = self._joined_state()
        self._sync_listeners(state)
        if state is not None:
            for adapter in self._transports:
                configured[adapter.name] = adapter.configured(state)
                if not configured[adapter.name]:
                    continue
                if self.licence_only and getattr(adapter, "licence_only", False) is not True:
                    continue  # an adapter that cannot run licence-only never runs on a free PC
                _check_lease(self.session, self._lease)
                try:
                    results[adapter.name] = adapter.run(self.session, self._lease, now=now, gate=self.gate)
                except SyncAborted:
                    raise
                except Exception as exc:
                    if self._cancelled():
                        raise
                    _log.exception("sync transport %s failed", adapter.name)
                    results[adapter.name] = RunReport(
                        issues=(SyncIssue("error", f"{type(exc).__name__}: {exc}"),))
            if self.licence_only:
                return  # writes no witness state either
            # Peer generations the LAN save throttle held back (served exchanges included) are saved at
            # every run, so a lock loses at most one run interval of rises, never a stored value.
            _check_lease(self.session, self._lease)
            try:
                from .lan_sync import flush_witness

                flush_witness(self.session, self._lease)
            except SyncAborted:
                raise
            except Exception:  # noqa: BLE001 - witness bookkeeping must not fail the run
                _log.exception("witness flush failed")

    def _adopt_licenses(self, results: dict[str, RunReport]) -> bool:
        """Offer licences to the licence store (inside the gate).

        The licences received in this run plus every verified licence the vault
        already keeps, so an adoption missed earlier (locked mid-run, a failed
        file write, a licence a peer pushed while we served it) is retried on
        every run; ``adopt_synced_license`` returns at once when this PC is
        already Pro or a removal is pending.
        """
        bundles = [bundle for report in results.values() for bundle in report.licenses]
        _check_lease(self.session, self._lease)  # locked meanwhile: install nothing
        try:
            bundles.extend(published_licenses(self.session))
        except BridgeError:
            _log.warning("Stored licences could not be read for adoption", exc_info=True)
        if not bundles:
            return False
        return licensing.adopt_synced_license(self.session, bundles) is not None

    def _record(self, now: int, configured: dict[str, bool], results: dict[str, RunReport],
                adopted: bool = False) -> None:
        with self._mu:
            st = self._status
            st.aborted = False
            st.license_adopted = adopted
            st.items_changed = sum(_changed_items(r) for r in results.values())
            for adapter in self._transports:
                old = st.transports.get(adapter.name, TransportStatus(adapter.name))
                report = results.get(adapter.name)
                if report is None:
                    st.transports[adapter.name] = dataclasses.replace(
                        old, configured=configured.get(adapter.name, False), issues=())
                    st.skipped.pop(adapter.name, None)
                    continue
                synced = report.own_states is not None
                st.transports[adapter.name] = TransportStatus(
                    adapter.name, True, now, now if synced else old.last_sync, dedupe_issues(report.issues))
                st.skipped[adapter.name] = tuple(report.skipped)
                st.conflicts += report.conflicts

    def _peer_synced(self, name: str, report: RunReport) -> None:
        """A peer (a phone, which connects to this PC) synced with us: record it like a run of *name*."""
        if self._stopped.is_set():
            return
        now = int(self._clock())
        with self._mu:
            st = self._status
            old = st.transports.get(name, TransportStatus(name))
            st.transports[name] = dataclasses.replace(old, last_sync=now)
            st.items_changed = _changed_items(report)
            st.license_adopted = False
            st.conflicts += report.conflicts
        self._publish()
        if self.licence_only and report.licenses:
            self._request()  # a round offers the served licences for adoption at once

    def _publish(self) -> None:
        if self._post_result is not None:
            self._post_result(self.status())

    def status(self) -> SyncStatusView:
        with self._mu:
            st = self._status
            transports = tuple(st.transports[t.name] for t in self._transports)
            issues = dedupe_issues([*st.global_issues, *(i for t in transports for i in t.issues)])
            skipped = tuple(sorted({row for rows in st.skipped.values() for row in rows}))
            synced = [t.last_sync for t in transports if t.last_sync is not None]
            return SyncStatusView(
                configured=st.configured, last_sync=max(synced) if synced else None, transports=transports,
                issues=issues, skipped=skipped, conflicts=st.conflicts, running=self._running,
                listening=any(getattr(t, "listening", False) for t in self._transports), aborted=st.aborted,
                license_adopted=st.license_adopted, items_changed=st.items_changed,
                peer_synced_at=self._peer_synced_at())

    def _peer_synced_at(self) -> dict[str, int]:
        """The stored per-device times; empty when the vault is locked or not in a group."""
        try:
            state = load_sync_state(self.session)
        except Exception:  # noqa: BLE001 - a status read never fails the status bar
            return {}
        return dict(state.peer_synced_at) if state is not None else {}

    # LAN enrollment ---------------------------------------------------------------------------------------

    def arm_enrollment(self, offer: Any) -> None:
        """Arm the LAN listener for one QR enrollment of *offer*; disarms itself when it expires."""
        lan = next((t for t in self._transports if hasattr(t, "start_enrollment")), None)
        if lan is None or self._stopped.is_set():
            return
        if self.licence_only:
            self._open_listen_window(max(0.0, float(offer.expires_at) - float(self._clock()))
                                     + LICENCE_ONLY_LISTEN_SECONDS)

        def job() -> None:
            if self._stopped.is_set():
                return
            with self.gate.hold():
                _check_lease(self.session, self._lease)
                state = self._joined_state()
                if state is not None:
                    lan.ensure_listener(self.session, self._lease, state, self.gate)
                    lan.start_enrollment(offer, self.gate)

        self._worker.submit(job)
        delay = max(0.0, float(offer.expires_at) - float(self._clock()))
        for when in (delay, delay + ENROLL_GRACE_SECONDS):
            self._enroll_timers.append(self._scheduler.call_later(when, lambda: self._expire_enrollment(lan)))

    def _expire_enrollment(self, lan: Any) -> None:
        """Timer callback: disarm through the worker, inside the gate (like every other responder change)."""
        if self._stopped.is_set():
            return

        def job() -> None:
            if self._stopped.is_set():
                return
            with self.gate.hold():
                lan.expire_enrollment()

        self._worker.submit(job)

    def enrollment_result(self, offer_id: str) -> str | None:
        """The device id that enrolled with the armed offer *offer_id*, or None (not yet, or another offer).

        A plain attribute read (no gate), so the Tk thread may poll it.
        """
        enrolled = self.enrollment_peer(offer_id)
        return None if enrolled is None else enrolled.device_id

    def _lan_responder(self) -> Any:
        lan = next((t for t in self._transports if hasattr(t, "start_enrollment")), None)
        return getattr(lan, "responder", None)

    def enrollment_peer(self, offer_id: str) -> Any:
        """The ``PairedDevice`` accepted with *offer_id* (id and fingerprint for the screen), or None."""
        responder = self._lan_responder()
        enrolled = getattr(responder, "enrolled", None)
        if enrolled is None or getattr(responder, "enrolled_offer", None) != offer_id:
            return None
        return enrolled

    def pending_enrollment(self, offer_id: str) -> Any:
        """The ``lan_sync.PendingEnrollment`` waiting for Accept on *offer_id* (name, code), or None.

        A plain attribute read (no gate), like ``enrollment_result``.
        """
        pending = getattr(self._lan_responder(), "pending", None)
        if pending is None or getattr(pending, "offer_id", None) != offer_id:
            return None
        return pending

    def enrollment_declined(self, offer_id: str) -> bool:
        """True once the request for *offer_id* was declined (by the user or the Accept timeout)."""
        return getattr(self._lan_responder(), "declined_offer", None) == offer_id

    def decide_enrollment(self, offer_id: str, accept: bool) -> bool:
        """Accept or Decline the request waiting on *offer_id*; False when none waits (answered or timed out).

        Needs no gate: it wakes the transport thread, which admits the device inside the gate.
        """
        responder = self._lan_responder()
        decide = getattr(responder, "decide", None)
        return bool(decide(offer_id, accept)) if callable(decide) else False

    def cancel_enrollment(self, offer_id: str) -> bool:
        """Disarm the armed offer *offer_id* now (the QR window was closed), through a gated worker job.

        Returns False once the service stopped.
        """
        lan = next((t for t in self._transports if hasattr(t, "start_enrollment")), None)
        if lan is None or self._stopped.is_set():
            return False

        def job() -> None:
            if self._stopped.is_set():
                return
            with self.gate.hold():
                responder = getattr(lan, "responder", None)
                pairing = getattr(responder, "pairing", None)
                if pairing is not None and getattr(pairing.offer, "offer_id", None) == offer_id:
                    responder.stop_enrollment()

        self._worker.submit(job)
        return True

    def lan_listen_state(self) -> tuple[LANEndpoint | None, SyncIssue | None]:
        """``(endpoint the LAN listener accepts on or None, why it does not listen or None)``.

        Read it after a job submitted behind ``arm_enrollment`` finished (the worker runs jobs in order).
        """
        lan = next((t for t in self._transports if hasattr(t, "start_enrollment")), None)
        if lan is None:
            return None, SyncIssue("lan-not-listening")
        endpoint = lan.listening_endpoint() if hasattr(lan, "listening_endpoint") else None
        if endpoint is not None:
            return endpoint, None
        issue = getattr(lan, "listen_issue", None)
        if issue is None:
            with self._mu:  # only the reasons that keep the LAN listener from starting
                issue = next((i for i in self._status.global_issues if i.kind in _LAN_BLOCKING_ISSUES), None)
        return None, issue or SyncIssue("lan-not-listening")

    @property
    def lan_announcement(self) -> str:
        """The Bonjour announcement state ("off", "announcing", "public-network", "unavailable")."""
        lan = next((t for t in self._transports if hasattr(t, "start_enrollment")), None)
        announcer = getattr(lan, "announcer", None)
        return "off" if announcer is None else str(announcer.state)

    def lan_transport(self) -> Any:
        """The running LAN transport (pass it to ``remove_lan_peer`` so the peer is revoked at once)."""
        lan = next((t for t in self._transports if hasattr(t, "start_enrollment")), None)
        return None if lan is None else lan.transport

    # UI jobs ---------------------------------------------------------------------------------------------------

    def submit(self, job: Callable[[Any, Any, SyncGate], Any],
               on_done: Callable[[Any, BaseException | None], None] | None = None, *,
               run_after: bool = False) -> bool:
        """Run ``job(session, lease, gate)`` on the worker inside the gate (Task 8 contract).

        For UI actions that change ``SyncGroupState`` (create, join, rotate,
        leave, remove a peer, enroll) or read it for display.  *lease* is the
        fenced lease.  Afterwards the listener and global status follow the
        stored state and the status is published; then ``on_done(result,
        error)`` is called on the worker thread (post it to Tk yourself).
        *run_after*: a job that succeeded is followed by a normal sync run
        (``run_now``; single flight, queued behind the job on the worker).
        Returns False, without calling *on_done*, once the service stopped.
        """
        if self._stopped.is_set():
            return False

        def run() -> None:
            result: Any = None
            error: BaseException | None = None
            try:
                with self.gate.hold():
                    try:
                        _check_lease(self.session, self._lease)
                        result = job(self.session, self._lease, self.gate)
                    finally:
                        if not self._cancelled():
                            with contextlib.suppress(Exception):
                                self._sync_listeners(self._joined_state())
            except Exception as exc:  # noqa: BLE001 - reported to the caller
                error = exc
            if run_after and error is None:
                self.run_now()
            self._publish()
            if on_done is not None:
                on_done(result, error)

        self._worker.submit(run)
        return True

    # reset ----------------------------------------------------------------------------------------------------

    def reset(self, on_done: Callable[[bool | None], None] | None = None) -> bool:
        """Clear this vault's sync state on the worker; stops the listener.

        Call only after the user explicitly confirmed (see ``reset_sync``).
        ``on_done`` gets True (cleared), False (nothing to clear) or None (the
        reset failed).  Returns False, without calling ``on_done``, once the
        service stopped.
        """
        if self._stopped.is_set():
            return False

        def job() -> None:
            cleared: bool | None = None
            try:
                with self.gate.hold():
                    self._sync_listeners(None)
                    cleared = bool(reset_sync(self.session, self._lease))
                with self._mu:
                    self._status = _Status(transports={t.name: TransportStatus(t.name) for t in self._transports})
            finally:
                self._publish()
                if on_done is not None:
                    on_done(cleared)

        self._worker.submit(job)
        return True


__all__ = [
    "DEBOUNCE_SECONDS", "NOTICE_KINDS", "POLL_SECONDS", "RUN_INTERVAL_SECONDS", "FolderAdapter", "LanAdapter",
    "SyncAborted", "SyncGate", "SyncService", "SyncStatusView", "ThreadScheduler", "ThreadWorker", "TkScheduler",
    "TransportStatus", "UiBarrier", "dedupe_issues", "reset_sync", "vault_change_marker",
]
