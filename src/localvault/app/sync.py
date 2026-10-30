"""Device sync for the WebView UI: the background service and the Sync page's actions.

Mirrors ``AgentApp._start_sync_service`` and ``sync_ui.SyncScreen``. Each page
action is one bridge call that validates in Python, asks for confirmation
through ``UiPort``, hands a job to the sync worker and waits for its result.
Folders come only from the Python folder dialog (single-use tokens); sync
passwords are checked here and dropped after the job; nothing secret is
published in events. Handing the vault to a new folder or device (create, join,
cloud folder setup, a pairing code, joining by code) asks for the master
password first (never Windows Hello), like an export; ordinary sync runs do not.
"""
from __future__ import annotations

import base64
import secrets
import sys
import threading
import time
from typing import Any, Callable

from ..api.result import ApiError, points_to_error_log
from .sync_view import (
    _ACTION_LABELS,
    _ACTION_ORDER,
    _PRIMARY,
    DEFAULT_LAN_PORT,
    PASSWORD_ADVICE,
    RESET_TEXT_1,
    RESET_TEXT_2,
    ISSUE_COPY,
    ROLLBACK_CONFIRM_TEXT,
    ROLLBACK_CONFIRM_TITLE,
    acknowledge_job,
    acknowledge_rollback_job,
    add_folder_job,
    begin_pairing_job,
    check_sync_password,
    countdown_text,
    create_group_job,
    default_device_name,
    dismiss_peer_rollback_job,
    enroll_job,
    error_text,
    folder_setup,
    issue_text,
    join_folder_job,
    lan_removed_folder_text,
    leave_job,
    leave_text,
    local_ipv4_addresses,
    orphan_members,
    refind_job,
    remove_lan_peer_job,
    remove_wifi_device_text,
    reset_result_text,
    rotate_job,
    rotation_intro,
    rollback_issues,
    rollback_view,
    rotation_plan,
    sanitize_name,
    short_id,
    snapshot_job,
    suggest_lan_endpoint,
    sync_view,
    validate_lan_endpoint,
)
from ..i18n import t

JOB_TIMEOUT = 180.0
CONFIRM_SYNC = "sync.confirmToSyncPasswordsTo"
NOT_RUNNING = "syncPage.needsUnlock"
PRO_REQUIRED = ("sync.deviceSyncIsPartOf")
STOPPED = "sync.syncStoppedTheVaultLocked"
WIFI_INTRO = ("sync.thisPcSAddressAnd")
PAIR_HINT = ("sync.phoneAndPcMustBe")
CHOOSE_ADDRESS = ("sync.theSavedAddressNoLonger")
CHOOSE_KEEP = ("sync.theSavedAddressIsOn")
CHOOSE_VIRTUAL = ("sync.theSavedAddressBelongsTo")
INTRO = ("sync.keepThisVaultInStep")


def _noop(session: Any, lease: Any, gate: Any) -> None:
    return None


def _split_endpoint(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    return host.strip("[]"), int(port)


def _announcer() -> Any:
    if sys.platform != "win32":
        return None
    from ..sync.announce import Announcer

    return Announcer()


def _browser() -> Any:
    """Finds a paired Wi-Fi host whose pinned address stopped answering (Windows DNS-SD)."""
    if sys.platform != "win32":
        return None
    from ..sync.discovery_client import default_browser

    return default_browser()


def _probe_network() -> Any:
    from ..sync.lan_interfaces import probe_interfaces

    return probe_interfaces()


class AddressFollower:
    """The stored Wi-Fi endpoint, moved to this PC's new address when the old one is gone.

    Probes the adapters at most every *min_interval* seconds (``route print`` is a process).
    ``moved`` is ``(old, new)`` after a move, for the Sync page.
    """

    def __init__(self, settings: Any, *, probe: Callable[[], Any] = _probe_network,
                 clock: Callable[[], float] = time.monotonic, min_interval: float = 30.0) -> None:
        self._settings = settings
        self._probe = probe
        self._clock = clock
        self._min_interval = min_interval
        self._last: float | None = None
        self._mu = threading.Lock()
        self.moved: tuple[str, str] | None = None

    def __call__(self) -> Any:
        from ..sync.lan_interfaces import followed_endpoint

        with self._mu:
            value = getattr(self._settings, "sync_lan_endpoint", None)
            if not isinstance(value, str) or ":" not in value:
                return value
            now = self._clock()
            if self._last is not None and now - self._last < self._min_interval:
                return value
            self._last = now
            try:
                new = followed_endpoint(value, self._probe())
            except Exception:  # noqa: BLE001 - a failed probe keeps the stored address
                return value
            if new is None or new == value:
                return value
            if getattr(self._settings, "sync_lan_endpoint_confirmed", "") == value:
                self._settings.sync_lan_endpoint_confirmed = new
            self._settings.sync_lan_endpoint = new
            try:
                self._settings.save()
            except OSError as exc:  # kept in memory; saved with the next settings write
                from ..error_log import log_exception

                log_exception("sync-ui", exc)
            self.moved = (value, new)
            return new


QR_MAX_CSS_PX = 260


def qr_layout(payload: str, *, max_css_px: int = QR_MAX_CSS_PX) -> tuple[int, int]:
    """``(PNG scale, CSS size)`` for a crisp pairing QR of at most *max_css_px* CSS pixels.

    Each module is a whole number of CSS pixels, and the PNG is rendered at twice that (an even
    scale), so it stays sharp at 100 % and 200 % display scaling.  segno's 4-module quiet zone
    is part of the symbol size, so it is kept.
    """
    import segno

    modules = segno.make(payload, error="m", micro=False, boost_error=False).symbol_size()[0]
    per_module = max(1, max_css_px // modules)
    return min(32, 2 * per_module), modules * per_module


def paired_fingerprint(value: Any) -> str:
    """The first 16 hex digits of a paired device's key fingerprint, in groups of four (display only)."""
    if not isinstance(value, str) or not value or any(c not in "0123456789abcdef" for c in value):
        return ""
    head = value[:16]
    return " ".join(head[i:i + 4] for i in range(0, len(head), 4))


def format_verification_code(code: Any) -> str:
    """A 6-digit pairing verification code as ``123 456`` (display only; empty when malformed)."""
    if not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit():
        return ""
    return f"{code[:3]} {code[3:]}"


def synced_items_text(count: int) -> str:
    """The toast after a sync that brought, changed or removed items."""
    return t("sync.itemsUpdated", count=count)


def not_listening_text(address: str, issue: Any) -> str:
    """Why no QR code is shown: nothing accepts connections on *address*."""
    kind = str(getattr(issue, "kind", "") or "lan-not-listening")
    detail = str(getattr(issue, "detail", "") or "")
    if kind == "listen-failed":
        reason = t("sync.listenFailedReason", detail=detail) if detail else ""
        return t("sync.listenFailed", address=address, reason=reason)
    advice = issue_text(issue) if kind != "lan-not-listening" else t("sync.tryAgainInAMoment")
    return t("sync.notListening", address=address, advice=advice)


class VaultLockBarrier:
    """``SyncGate`` barrier for the WebView UI: holding the gate holds ``controller.vault_lock``.

    Page calls take the same lock (see ``api.bridge``), so a sync run's vault
    writes are mutually exclusive with user saves, as the classic UI barrier
    made them by parking the Tk thread. Waiting gives up with ``SyncAborted``
    once the run is cancelled (lock, stop), like the classic barrier.
    """

    def __init__(self, lock: Any, *, poll: float = 0.05) -> None:
        self._lock = lock
        self._poll = poll

    def park(self, cancelled: Callable[[], bool]) -> Any:
        from ..sync.service import SyncAborted

        while not self._lock.acquire(timeout=self._poll):
            if cancelled():
                raise SyncAborted("Sync stopped while waiting for the vault")
        return self._lock

    @staticmethod
    def unpark(token: Any) -> None:
        if token is not None:
            token.release()


def _default_factory(controller: Any, on_status: Callable[[Any, Any], None], *, licence_only: bool = False) -> Any:
    """The real service, built like ``AgentApp._start_sync_service`` (no UI barrier: there is no UI thread).

    *licence_only*: the free plan's service (``sync.service`` "Licence-only mode").
    """
    from ..sync import service as sync_service
    from ..sync.install import load_or_create_install_id

    session = controller.session
    install_id = load_or_create_install_id()
    lease = controller.guard.lease()
    guard = controller.guard

    def check_lease() -> None:
        guard.require(lease)

    owner: list[Any] = []

    follower = AddressFollower(controller.settings)

    def endpoint() -> Any:
        from ..sync.transport import LANEndpoint

        value = follower()
        if not isinstance(value, str) or ":" not in value:
            return None
        host, _, port = value.rpartition(":")
        try:
            return LANEndpoint(host.strip("[]"), int(port))
        except (ValueError, TypeError):
            return None

    service = sync_service.SyncService(
        session, check_lease, install_id=install_id,
        transports=[sync_service.FolderAdapter(install_id=install_id),
                    sync_service.LanAdapter(install_id=install_id, endpoint=endpoint, announcer=_announcer(),
                                              browser=_browser())],
        scheduler=sync_service.ThreadScheduler(), gate=sync_service.SyncGate(VaultLockBarrier(controller.vault_lock)),
        post_result=lambda view: on_status(owner[0] if owner else None, view),
        change_marker=lambda: sync_service.vault_change_marker(session), licence_only=licence_only)
    owner.append(service)
    service.address_follower = follower
    return service


class SyncWebService:
    def __init__(self, controller: Any, port: Any, bus: Any, dialogs: Any, *,
                 factory: Callable[[Any, Callable[[Any, Any], None]], Any] = _default_factory,
                 on_licence: Callable[[], None] | None = None, timeout: float = JOB_TIMEOUT,
                 network: Callable[[], Any] = _probe_network, firewall: Any = None) -> None:
        self._controller = controller
        self._network = network
        self._firewall = firewall
        self._port = port
        self._bus = bus
        self._dialogs = dialogs
        self._factory = factory
        self._on_licence = on_licence
        self._timeout = timeout
        self.service: Any = None
        self.status: Any = None
        self._snapshot: Any = None
        self._state_corrupt = False
        self._folders: dict[str, str] = {}
        self._offers: dict[str, tuple[Any, str]] = {}
        self._busy = threading.Lock()
        self._busy_text = ""
        self._lock = threading.RLock()
        # (kind, detail) rollback issues acknowledged or dismissed, hidden until a sync run reports anew.
        self._rollback_hidden: set[tuple[str, str]] = set()
        self._rollback_mark: Any = None
        from .secrets import SecretService

        self._auth = SecretService(controller, port)
        controller.on_lock.append(self.stop)

    # ------------------------------------------------------------ lifecycle
    def enable(self) -> None:
        """Start sync after each unlock (the real app only; tests drive ``start`` themselves)."""
        self._controller.on_unlock.append(self.start)
        if self._controller.is_unlocked():
            self.start()

    def sync_allowed(self) -> bool:
        """Whether this session's plan includes device sync (Pro only)."""
        if not self._controller.is_unlocked():
            return False
        allowed = getattr(self._controller.session, "pro_features", None)
        return allowed is None or "sync" in allowed

    def licence_only(self) -> bool:
        """Whether the running service (if any) is the free plan's licence-only one."""
        return getattr(self.service, "licence_only", False) is True

    def plan_changed(self) -> None:
        """Switch between full and licence-only sync after the licence changed (installed, removed, restored)."""
        if self.service is not None and self.licence_only() == self.sync_allowed():
            self.stop()  # the other mode: replaced below (a synced licence turns full sync on here)
        self.start()
        self._bus.emit("sync.status", {})

    def start(self) -> None:
        from ..error_log import log_exception

        with self._lock:
            if self.service is not None or not self._controller.is_unlocked():
                return
            try:
                if self.sync_allowed():
                    service = self._factory(self._controller, self._status_changed)
                else:
                    # Free plan: a licence-only service.  It stores no item and publishes nothing; it
                    # runs (and listens) only when asked, so a licence bought elsewhere can arrive.
                    # What earlier syncs brought stays in the vault; a Pro licence resumes full sync.
                    service = self._factory(self._controller, self._status_changed, licence_only=True)
            except Exception as exc:  # noqa: BLE001 - sync never blocks unlock
                log_exception("sync-start", exc)
                return
            self.service = service
        try:
            service.on_unlock()
        except Exception as exc:  # noqa: BLE001
            log_exception("sync-start", exc)
        self._bus.emit("sync.status", {})

    def stop(self) -> None:
        with self._lock:
            service, self.service = self.service, None
            self.status = None
            self._snapshot = None
            self._rollback_hidden.clear()
            self._rollback_mark = None
            self._folders.clear()
            self._offers.clear()
        if service is not None:
            try:
                service.stop()
            except Exception:  # noqa: BLE001, S110 - a lock must not fail on sync
                pass

    def _status_changed(self, source: Any, view: Any) -> None:
        with self._lock:
            if source is None or source is not self.service:
                return  # a stopped service (the vault locked, maybe unlocked again since)
            self.status = view
            if self._rollback_hidden and self._run_mark(view) != self._rollback_mark:
                self._rollback_hidden.clear()  # a newer run: show what it reports
        if getattr(view, "license_adopted", False) and self._on_licence is not None:
            self._on_licence()
        self._bus.emit("sync.status", {})
        changed = getattr(view, "items_changed", 0)
        if changed:
            self._bus.emit("items.changed", {})  # the item list shows what sync brought without a relock
            self._bus.emit("toast", {"kind": "info", "title": t("sync.synced"),
                                     "message": synced_items_text(int(changed))})

    # ------------------------------------------------------------ rollback
    @staticmethod
    def _run_mark(status: Any) -> Any:
        """Identifies the last sync runs (each transport's last sync time and issues)."""
        if status is None:
            return None
        return tuple((getattr(t, "name", None), getattr(t, "last_sync", None),
                      tuple((i.kind, i.detail) for i in getattr(t, "issues", ()) or ()))
                     for t in getattr(status, "transports", ()) or ())

    def _hide_rollback(self, kind: str, detail: str) -> None:
        with self._lock:
            self._rollback_hidden.add((kind, detail))
            self._rollback_mark = self._run_mark(self.status)


    def acknowledge_rollback(self) -> dict[str, Any]:
        """"This was me": keep this (restored) copy; asks first, then the master password or Windows Hello."""
        self._service()
        if not any(i.kind == "vault-rollback" for i in rollback_issues(self.status)):
            return {"message": t("sync.thereIsNoWarningTo"), **self.view()}
        if not self._port.confirm(t(ROLLBACK_CONFIRM_TITLE), t(ROLLBACK_CONFIRM_TEXT)):
            raise ApiError("cancelled", t("error.cancelled"))
        lease = self._controller.guard.lease()
        self._auth.reauthenticate(t(ROLLBACK_CONFIRM_TITLE), lease, allow_hello=True)
        self._controller.require_lease(lease)
        self._run(acknowledge_rollback_job(), t("typedEditor.saving"))
        self._hide_rollback("vault-rollback", "")
        return {"message": t(ISSUE_COPY["rollback-acknowledged"]), **self.refresh()}

    def dismiss_peer_rollback(self, device_id: str) -> dict[str, Any]:
        """Dismiss ``peer-vault-rollback`` for one device: its older copy is accepted from now on."""
        self._service()
        if not isinstance(device_id, str) or not any(
                i.kind == "peer-vault-rollback" and i.detail == device_id for i in rollback_issues(self.status)):
            raise ApiError("invalid", t("sync.thatWarningIsNoLonger"))
        self._run(dismiss_peer_rollback_job(device_id), t("typedEditor.saving"))
        self._hide_rollback("peer-vault-rollback", device_id)
        return self.refresh()

    # ----------------------------------------------------------------- jobs
    def _service(self) -> Any:
        service = self.service
        if service is None:
            if self._controller.is_unlocked() and not self.sync_allowed():
                raise ApiError("pro_required", t(PRO_REQUIRED))
            raise ApiError("unavailable", t(NOT_RUNNING))
        return service

    def _run(self, job: Callable[[Any, Any, Any], Any], busy: str, *, run_after: bool = False) -> Any:
        service = self._service()
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", t("sync.anotherSyncActionIsStill"))
        self._busy_text = busy
        self._bus.emit("sync.status", {})
        done = threading.Event()
        box: dict[str, Any] = {"waiting": True}
        state_lock = threading.Lock()

        def finish_busy() -> None:
            self._busy_text = ""
            self._busy.release()
            self._bus.emit("sync.status", {})

        def on_done(result: Any, error: BaseException | None) -> None:
            with state_lock:
                box["result"], box["error"] = result, error
                done.set()
                late = not box["waiting"]
            if late:
                finish_busy()  # the page gave up waiting; the action is only now really over

        handed_over = False
        try:
            accepted = (service.submit(job, on_done, run_after=True) if run_after
                        else service.submit(job, on_done))
            if not accepted:
                raise ApiError("stopped", t(STOPPED))
            if not done.wait(self._timeout):
                with state_lock:
                    if not done.is_set():
                        box["waiting"] = False
                        handed_over = True  # on_done releases busy when the job ends
                if handed_over:
                    raise ApiError("timeout", t("sync.thisSyncActionIsStill"))
            if service is not self.service:
                raise ApiError("stopped", t(STOPPED))  # the vault locked meanwhile: drop the result
            error = box.get("error")
            if error is not None:
                if not isinstance(getattr(error, "reason", None), str):
                    from ..error_log import log_exception

                    log_exception("sync-ui", error)
                raise ApiError("sync_failed", error_text(error)) from None
            return box.get("result")
        finally:
            if not handed_over:
                finish_busy()

    def refresh(self) -> dict[str, Any]:
        service = self.service
        if service is not None:
            skipped = [row[0] for row in getattr(self.status, "skipped", ()) or ()]
            result = self._run(snapshot_job(service.install_id, skipped), "")
            if isinstance(result, tuple):
                self._snapshot, self._state_corrupt = result
        return self.view()

    # ----------------------------------------------------------------- view
    def view(self) -> dict[str, Any]:
        endpoint = getattr(self._controller.settings, "sync_lan_endpoint", "")
        view = sync_view(self.status, self._snapshot, lan_endpoint=endpoint if isinstance(endpoint, str) else "",
                         now=time.time(), available=self.service is not None, state_corrupt=self._state_corrupt)

        def issue(item: Any) -> dict[str, Any] | None:
            if item is None:
                return None
            text = item.text + (t("sync.ifThatDoesNotHelp") if item.reset_offered
                                else "")
            shown = {"kind": item.kind, "severity": item.severity, "text": text}
            if points_to_error_log(text):
                shown["error_log"] = True
            return shown

        def card(c: Any) -> dict[str, Any]:
            return {
                "key": c.key, "title": c.title, "state": c.state, "state_text": c.state_text,
                "last_sync_text": c.last_sync_text, "banner": issue(c.banner), "hint": c.hint,
                "members_heading": t("sync.devices") if c.key == "folder" else t("sync.pairedDevices"),
                "members": [{"id": m.device_id, "name": m.name, "detail": m.detail, "is_self": m.is_self,
                             "removable": m.removable} for m in c.members],
                "issues": [issue(i) for i in c.issues[1:]],
                "actions": [{"id": a, "label": t(_ACTION_LABELS[a]), "primary": a in _PRIMARY}
                            for a in _ACTION_ORDER if a in c.actions],
            }

        status_line = self._busy_text or (t("sync.syncingNow") if view.running else "")
        if view.conflicts_text:
            status_line = f"{status_line}  ·  {view.conflicts_text}" if status_line else view.conflicts_text
        wifi = card(view.wifi)
        moved = getattr(getattr(self.service, "address_follower", None), "moved", None)
        if moved and moved[1] == endpoint:
            wifi["hint"] = t("sync.addressChanged", address=moved[1])
        if getattr(self.service, "lan_announcement", "off") == "public-network":
            wifi["hint"] = (t("sync.windowsTreatsThisNetworkAs"))
        return {"intro": t(INTRO), "status_line": status_line, "banner": issue(view.banner),
                "cards": [wifi, card(view.folder)],
                "rollback": rollback_view(self.status, self._snapshot, hidden=set(self._rollback_hidden)), "skipped": list(view.skipped),
                "available": self.service is not None, "busy": bool(self._busy_text),
                "advice": t(PASSWORD_ADVICE), "pro": self.sync_allowed() or not self._controller.is_unlocked(),
                "pro_text": t(PRO_REQUIRED), "licence_only": self.licence_only()}

    def status_summary(self) -> dict[str, Any]:
        """The sidebar pill and the Sync status sheet (UX plan workstream 6)."""
        from .sync_status import summarize

        return summarize(self.view(), self.status, self._snapshot, now=time.time())

    # --------------------------------------------------------------- inputs
    def choose_folder(self) -> dict[str, Any]:
        self._service()
        folder = self._dialogs.choose_folder(t("sync.chooseTheSyncFolder"))
        if not folder:
            raise ApiError("cancelled", t("error.noFolderChosen"))
        token = secrets.token_urlsafe(12)
        self._folders[token] = str(folder)
        return {"token": token, "path": str(folder)}

    def _folder(self, token: str) -> str:
        folder = self._folders.pop(str(token or ""), None)
        if not folder:
            raise ApiError("invalid", t("sync.chooseTheSyncFolderFirst"))
        return folder

    @staticmethod
    def password_check(password: str, confirm: str) -> dict[str, Any]:
        check = check_sync_password(password, confirm)
        return {"ok": check.ok, "score": check.score, "label": check.label, "message": check.message}

    @staticmethod
    def _require_strong(password: str, confirm: str) -> None:
        check = check_sync_password(password, confirm)
        if not check.ok:
            raise ApiError("invalid", check.message)

    def _confirm_handover(self) -> None:
        """The master password (no Windows Hello, no grace window) before the vault goes to a new folder or device.

        Runs on the page call's thread, before any job is handed to the sync worker (sync calls do not hold the
        vault lock), so the prompt never waits inside the sync gate.
        """
        lease = self._controller.guard.lease()
        self._auth.reauthenticate(t(CONFIRM_SYNC), lease, allow_hello=False)
        self._controller.require_lease(lease)

    # -------------------------------------------------------------- actions
    def sync_now(self) -> dict[str, Any]:
        self._service().run_now()
        self._bus.emit("sync.status", {})
        return self.view()

    def create(self, token: str, password: str, confirm: str) -> dict[str, Any]:
        service = self._service()
        folder = self._folder(token)
        try:
            self._require_strong(password, confirm)
            self._confirm_handover()
            self._run(create_group_job(folder, password, default_device_name(), service.install_id),
                      t("sync.creatingTheSyncGroup"), run_after=True)
        finally:
            password = confirm = ""
        return {"message": t("sync.syncGroupCreatedJoinIt"), **self.refresh()}

    def join(self, token: str, password: str) -> dict[str, Any]:
        service = self._service()
        folder = self._folder(token)
        if not password:
            raise ApiError("invalid", t("sync.enterTheSyncPassword"))
        try:
            self._confirm_handover()  # this PC's items are merged into the folder for the group's devices
            self._run(join_folder_job(folder, password, default_device_name(), service.install_id), t("sync.joining"),
                      run_after=True)
        finally:
            password = ""
        return {"message": t("sync.thisPcJoinedTheSync"), **self.refresh()}

    def folder_setup(self, action: str, token: str, password: str, confirm: str) -> dict[str, Any]:
        service = self._service()
        setup = folder_setup(action)
        if setup is None:
            raise ApiError("invalid", t("sync.unknownSyncAction"))
        folder = self._folder(token)
        try:
            if setup.confirm_twice:
                self._require_strong(password, confirm)
            elif not password:
                raise ApiError("invalid", t("sync.enterTheSyncPassword"))
            fresh_key = action == "add-folder" and bool(getattr(self._snapshot, "lan_removed", False))
            if fresh_key and not self._port.confirm(t("sync.newSyncKey"), lan_removed_folder_text(self._snapshot)):
                # Audit M9: a removed Wi-Fi device still holds the group key; the folder gets a new one.
                raise ApiError("cancelled", t("error.cancelled"))
            self._confirm_handover()
            job = (add_folder_job(folder, password, default_device_name(), service.install_id, True) if fresh_key
                   else setup.job(folder, password, default_device_name(), service.install_id))
            self._run(job, setup.busy, run_after=True)
        finally:
            password = confirm = ""
        return {"message": setup.done_text, **self.refresh()}

    def setup_text(self, action: str) -> dict[str, Any]:
        setup = folder_setup(action)
        if setup is None:
            raise ApiError("invalid", t("sync.unknownSyncAction"))
        return {"title": setup.title, "intro": setup.intro, "confirm_twice": bool(setup.confirm_twice)}

    def _rotate(self, password: str, confirm: str, remove: tuple[str, ...], done_text: str, *,
                lead: str = "") -> dict[str, Any]:
        """One rotation; the confirmation lists every member that gets the new key (audit M10).

        The keep-list is exactly the list shown in that confirmation, so a member that
        appears in the folder afterwards (or one not confirmed) does not get the key.
        """
        service = self._service()
        try:
            self._require_strong(password, confirm)
            plan = rotation_plan(self._snapshot, removing=remove)
            if plan.text:
                text = f"{lead}\n\n{plan.text}" if lead else plan.text
                if not self._port.confirm(t("sync.changeSyncPassword2") if not remove else t("sync.removeDevice"), text):
                    raise ApiError("cancelled", t("error.cancelled"))
            elif lead and not self._port.confirm(t("sync.removeDevice"), lead):
                raise ApiError("cancelled", t("error.cancelled"))
            self._run(rotate_job(password, remove, service.install_id, service.lan_transport, plan.keep),
                      t("sync.changingTheSyncPassword"), run_after=True)
        finally:
            password = confirm = ""
        return {"message": done_text, **self.refresh()}

    def rotation_text(self) -> dict[str, Any]:
        return {"title": t("sync.changeSyncPassword2"), "intro": rotation_intro(self._snapshot)}

    def acknowledge_members(self) -> dict[str, Any]:
        """Confirm the devices shown as added by another device (``member-added``)."""
        service = self._service()
        group = self._snapshot
        ids = tuple(getattr(group, "unacked", ()) or ())
        if not ids:
            return {"message": t("sync.thereAreNoNewDevices"), **self.refresh()}
        names = group.names() if hasattr(group, "names") else {}
        shown = ", ".join(sanitize_name(names.get(d) or short_id(d)) for d in ids)
        if not self._port.confirm(t("sync.confirmDevices"), t("sync.areTheseYourDevices", shown=shown)):
            raise ApiError("cancelled", t("error.cancelled"))
        self._run(acknowledge_job(ids, service.install_id), t("typedEditor.saving"))
        return {"message": t("sync.confirmedList", shown=shown), **self.refresh()}

    def change_password(self, password: str, confirm: str) -> dict[str, Any]:
        return self._rotate(password, confirm, (), t("sync.theSyncPasswordWasChanged"))

    def _members(self, card: str) -> list[Any]:
        endpoint = getattr(self._controller.settings, "sync_lan_endpoint", "")
        view = sync_view(self.status, self._snapshot, lan_endpoint=endpoint if isinstance(endpoint, str) else "",
                         now=time.time(), available=self.service is not None, state_corrupt=self._state_corrupt)
        return [m for m in (view.folder.members if card == "folder" else view.wifi.members) if m.removable]

    def remove_info(self, card: str) -> dict[str, Any]:
        members = self._members(card)
        folder = bool(self._snapshot is not None and getattr(self._snapshot, "folder_path", None))
        return {"devices": [{"id": m.device_id, "name": m.name, "detail": m.detail} for m in members],
                "needs_password": folder}

    def remove_device(self, card: str, device_id: str, password: str = "", confirm: str = "") -> dict[str, Any]:
        service = self._service()
        member = next((m for m in self._members(card) if m.device_id == device_id), None)
        if member is None:
            raise ApiError("invalid", t("sync.thatDeviceIsNoLonger"))
        name = member.name
        if self._snapshot is not None and getattr(self._snapshot, "folder_path", None):
            self._require_strong(password, confirm)
            return self._rotate(password, confirm, (device_id,), t("sync.deviceRemovedFromSync", name=name),
                                lead=t("sync.removeDeviceFromSync", name=name))
        if not self._port.confirm(t("sync.removeDevice"), remove_wifi_device_text(name)):
            raise ApiError("cancelled", t("error.cancelled"))
        self._run(remove_lan_peer_job(device_id, service.install_id, service.lan_transport), t("sync.removing"))
        return {"message": t("sync.deviceRemovedFromWifi", name=name),
                **self.refresh()}

    def orphans(self) -> dict[str, Any]:
        orphans = orphan_members(self._snapshot, now=time.time())
        if not orphans:
            return {"devices": [], "message": t("sync.everyDeviceInThisSync")}
        return {"devices": [{"id": m.device_id, "name": m.name, "detail": m.detail} for m in orphans],
                "intro": rotation_intro(self._snapshot)}

    def remove_orphans(self, ids: list[str], password: str, confirm: str) -> dict[str, Any]:
        orphans = orphan_members(self._snapshot, now=time.time())
        chosen = [m for m in orphans if m.device_id in set(ids or ())]
        if not chosen:
            raise ApiError("invalid", t("sync.chooseAtLeastOneDevice"))
        names = ", ".join(m.name for m in chosen)
        return self._rotate(password, confirm, tuple(m.device_id for m in chosen), t("sync.removedList", names=names),
                            lead=t("sync.removeListFromSync", names=names))

    def leave(self) -> dict[str, Any]:
        service = self._service()
        if not self._port.confirm(t("sync.leaveSync2"), leave_text(self._snapshot)):
            raise ApiError("cancelled", t("error.cancelled"))
        self._run(leave_job(service.install_id), t("sync.leaving"))
        return {"message": t("sync.thisPcLeftSyncRemove"), **self.refresh()}

    def reset(self) -> dict[str, Any]:
        service = self._service()
        if not self._port.confirm(t("sync.resetSyncOnThisPc3"), t(RESET_TEXT_1)):
            raise ApiError("cancelled", t("error.cancelled"))
        if not self._port.confirm(t("sync.resetSyncOnThisPc3"), t(RESET_TEXT_2)):
            raise ApiError("cancelled", t("error.cancelled"))
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", t("sync.anotherSyncActionIsStill"))
        done = threading.Event()
        box: dict[str, Any] = {}
        try:
            self._busy_text = t("sync.resettingSyncOnThisPc")
            self._bus.emit("sync.status", {})
            if not service.reset(lambda cleared: (box.__setitem__("cleared", cleared), done.set())):
                raise ApiError("stopped", t(STOPPED))
            if not done.wait(self._timeout):
                raise ApiError("timeout", t("sync.syncIsTakingTooLong"))
        finally:
            self._busy_text = ""
            self._busy.release()
            self._bus.emit("sync.status", {})
        cleared = box.get("cleared")
        if cleared is None:
            raise ApiError("sync_failed", reset_result_text(None))
        self._snapshot, self._state_corrupt = None, False
        return {"message": reset_result_text(cleared), **self.refresh()}

    # -------------------------------------------------------------- pairing
    def _candidates(self) -> tuple[Any, list[Any]]:
        from ..sync.lan_interfaces import NetworkSnapshot, lan_candidates

        try:
            snapshot = self._network()
        except Exception as exc:  # noqa: BLE001 - no adapter data: the listener check still guards the QR
            from ..error_log import log_exception

            log_exception("sync-network", exc)
            snapshot = NetworkSnapshot()
        return snapshot, lan_candidates(snapshot)

    def _checked_endpoint(self, value: str) -> tuple[str | None, str, dict[str, Any] | None]:
        """``(endpoint to use, notice, None)``, or ``(None, "", choose-an-address result)``.

        * The saved host is a candidate (an up, non-virtual adapter with a gateway): use it.
        * It is still this PC's address but not a candidate (no gateway, direct cable, hotspot,
          IPv6, Hyper-V external switch): keep it when the user picked it themselves, otherwise
          ask once, with the saved address listed first and preselected.
        * It no longer belongs to this PC: correct it when one candidate is obvious, else ask.
        * Without adapter data nothing is judged; the listener check still guards the QR.
        """
        from ..sync.lan_interfaces import current_addresses, is_virtual_address, obvious_candidate, same_address

        host, port = _split_endpoint(value)
        snapshot, candidates = self._candidates()
        if not snapshot.interfaces or any(same_address(c.address, host) for c in candidates):
            return value, "", None
        owned = current_addresses(snapshot)
        if any(same_address(a, host) for a in owned):
            confirmed = getattr(self._controller.settings, "sync_lan_endpoint_confirmed", "") or ""
            if confirmed == value:
                return value, "", None  # the user chose this address; never rewrite it
            return None, "", self._choose(value, candidates, port, saved_owned=True,
                                          saved_virtual=is_virtual_address(snapshot, host))
        best = obvious_candidate(candidates)
        if best is not None:
            fixed = f"{best.address}:{port}"
            self._save_endpoint(fixed)
            return fixed, t("sync.wifiNowUses", address=fixed, host=host), None
        if not candidates:
            return value, "", None  # nothing better to offer: the listener check reports the failure
        return None, "", self._choose(value, candidates, port, saved_owned=False)

    @staticmethod
    def _choose(value: str, candidates: list[Any], port: int, *, saved_owned: bool,
                saved_virtual: bool = False) -> dict[str, Any]:
        """The choose-an-address result.

        A saved address that is still this PC's is listed too, labelled "(saved)". It is listed
        first and preselected when it may be deliberate (Mobile Hotspot, a direct cable); when it
        is on a virtual adapter (VirtualBox, Hyper-V, WSL, VPN) the best gateway candidate comes
        first and is preselected, with the saved address second.
        """
        from ..sync.lan_interfaces import obvious_candidate

        choices = [{"value": f"{c.address}:{port}", "label": c.label} for c in candidates]
        host = _split_endpoint(value)[0]
        if not saved_owned:
            return {"choose_address": True, "current": choices[0]["value"] if choices else value,
                    "addresses": choices, "message": t(CHOOSE_ADDRESS, saved=host)}
        saved = {"value": value, "label": t("sync.addressSaved", host=host)}
        if saved_virtual and candidates:
            best = obvious_candidate(candidates) or candidates[0]
            best_value = f"{best.address}:{port}"
            ordered = [c for c in choices if c["value"] == best_value]
            ordered += [saved] + [c for c in choices if c["value"] != best_value]
            return {"choose_address": True, "current": best_value, "addresses": ordered,
                    "message": t(CHOOSE_VIRTUAL, saved=host)}
        return {"choose_address": True, "current": value, "addresses": [saved, *choices],
                "message": t(CHOOSE_KEEP, saved=host)}

    def qr_show(self) -> dict[str, Any]:
        from ..sync.pairing import offer_qr_payload, render_qr_png

        service = self._service()
        value, problem = validate_lan_endpoint(getattr(self._controller.settings, "sync_lan_endpoint", "") or "")
        if value is None:
            raise ApiError("invalid", problem)
        value, notice, choose = self._checked_endpoint(value)
        if value is None:
            return choose or {}
        host, port = _split_endpoint(value)
        for earlier in list(self._offers):
            self.qr_close(earlier)
        self._confirm_handover()  # a scanned code enrolls a new device that then receives every item
        offer = self._run(begin_pairing_job(host, port, service.install_id), t("sync.preparingACode"))
        service.arm_enrollment(offer)
        listen_state = getattr(service, "lan_listen_state", None)
        if callable(listen_state):
            try:
                self._run(_noop, t("sync.preparingACode"))  # queued behind the arming job: the listener is settled now
            except BaseException:
                service.cancel_enrollment(offer.offer_id)
                raise
            endpoint, issue = listen_state()
            from ..sync.lan_interfaces import same_address

            if endpoint is None or int(endpoint.port) != port or not same_address(str(endpoint.host), host):
                service.cancel_enrollment(offer.offer_id)
                raise ApiError("listen_failed", not_listening_text(value, issue))
        payload = offer_qr_payload(offer)
        scale, size = qr_layout(payload)
        png = render_qr_png(payload, scale=scale)
        self._offers[offer.offer_id] = (offer, payload)
        return {"offer_id": offer.offer_id, "code": offer.code, "expires_at": float(offer.expires_at),
                "image": "data:image/png;base64," + base64.b64encode(png).decode("ascii"),
                "countdown": countdown_text(float(offer.expires_at) - time.time()),
                "size": size, "modules": size // (scale // 2), "address": value, "hint": t(PAIR_HINT),
                "notice": notice}

    def qr_poll(self, offer_id: str) -> dict[str, Any]:
        offers = self._offers
        entry = offers.get(offer_id)
        service = self.service
        if entry is None or service is None:
            return {"state": "closed"}
        offer, _payload = entry
        device_id = service.enrollment_result(offer_id)
        if device_id is not None:
            offers.pop(offer_id, None)
            service.run_now()
            # Accepted on this page; Undo still removes it again (Remove a device).
            peer = getattr(service, "enrollment_peer", lambda _o: None)(offer_id)
            fingerprint = paired_fingerprint(getattr(peer, "fingerprint", ""))
            name = short_id(str(device_id))
            detail = t("sync.keyFingerprint", fingerprint=fingerprint) if fingerprint else ""
            return {"state": "paired", "device": {"id": str(device_id), "name": name, "fingerprint": fingerprint},
                    "message": t("sync.pairedDevice", name=name, detail=detail)}
        pending = getattr(service, "pending_enrollment", lambda _o: None)(offer_id)
        if pending is not None and pending.accepted is True:
            return {"state": "adding", "message": t("sync.addingDevice", name=pending.name)}
        if pending is not None and pending.accepted is None:
            # A device proved it scanned this code; it joins only after Accept here.
            code = format_verification_code(pending.code)
            fingerprint = paired_fingerprint(pending.fingerprint)
            return {"state": "confirm",
                    "device": {"id": str(pending.peer.device_id), "name": pending.name, "fingerprint": fingerprint,
                               "code": code},
                    "seconds_left": int(pending.seconds_left()),
                    "message": t("sync.wantsToJoin", name=pending.name, code=code)}
        if getattr(service, "enrollment_declined", lambda _o: False)(offer_id):
            offers.pop(offer_id, None)
            return {"state": "declined", "message": t("sync.declinedTheDeviceWasNot")}
        left = float(offer.expires_at) - time.time()
        if left <= 0:
            offers.pop(offer_id, None)
            return {"state": "expired", "countdown": t("sync.expired")}
        return {"state": "waiting", "countdown": countdown_text(left)}

    def qr_decide(self, offer_id: str, accept: bool) -> dict[str, Any]:
        """Accept or Decline the device waiting on *offer_id* (the ``confirm`` state of ``qr_poll``)."""
        service = self.service
        if offer_id not in self._offers or service is None:
            return {"state": "closed"}
        if not service.decide_enrollment(offer_id, bool(accept)):
            raise ApiError("invalid", t("sync.thatRequestIsNoLonger"))
        return {}

    def qr_copy(self, offer_id: str) -> dict[str, Any]:
        entry = self._offers.get(offer_id)
        if entry is None or self.service is None or float(entry[0].expires_at) <= time.time():
            raise ApiError("invalid", t("sync.thisPairingCodeHasClosed"))
        self._controller.clipboard.copy(entry[1])
        return {"message": t("sync.codeTextCopied")}

    def qr_close(self, offer_id: str) -> dict[str, Any]:
        self._offers.pop(offer_id, None)
        service = self.service
        if service is not None:
            service.cancel_enrollment(offer_id)
        return {}

    def join_qr(self, text: str) -> dict[str, Any]:
        service = self._service()
        if not str(text or "").strip():
            raise ApiError("invalid", t("sync.pasteTheCodeTextFrom"))
        endpoint = None
        value, _problem = validate_lan_endpoint(getattr(self._controller.settings, "sync_lan_endpoint", "") or "")
        if value is not None:
            from ..sync.transport import LANEndpoint

            host, _, port = value.rpartition(":")
            endpoint = LANEndpoint(host.strip("[]"), int(port))
        self._confirm_handover()  # the paired device receives this PC's items on the first sync

        def show_code(code: str) -> None:
            # The other device shows the same code next to Accept; this text replaces "Pairing…" while it waits.
            self._busy_text = t("sync.verificationCode", code=format_verification_code(code))
            self._bus.emit("sync.status", {})

        self._run(enroll_job(str(text).strip(), service.install_id, endpoint, on_code=show_code), t("sync.pairing"))
        return {"message": t("sync.thisPcJoinedTheOther"), **self.refresh()}

    def find_again_qr(self, text: str) -> dict[str, Any]:
        """"Find again": the QR text of an already paired device updates only its address (no re-pairing)."""
        service = self._service()
        if not str(text or "").strip():
            raise ApiError("invalid", t("sync.pasteTheCodeTextFrom"))
        self._run(refind_job(str(text).strip(), service.install_id), t("sync.findingTheOtherDevice"), run_after=True)
        return {"message": t("sync.foundTheOtherDeviceSyncing"), **self.refresh()}

    # ---------------------------------------------------------------- Wi-Fi
    def wifi_suggest(self) -> dict[str, Any]:
        from ..sync.lan_interfaces import obvious_candidate, same_address

        current, _problem = validate_lan_endpoint(getattr(self._controller.settings, "sync_lan_endpoint", "") or "")
        current = current or ""  # a malformed legacy value is not offered
        _snapshot, candidates = self._candidates()
        port = _split_endpoint(current)[1] if current else DEFAULT_LAN_PORT
        choices = [{"value": f"{c.address}:{port}", "label": c.label} for c in candidates]
        if current and (not candidates or getattr(self._controller.settings, "sync_lan_endpoint_confirmed", "")
                        == current or any(same_address(c.address, _split_endpoint(current)[0])
                                          for c in candidates)):
            suggestion = current
        elif candidates:
            suggestion = f"{(obvious_candidate(candidates) or candidates[0]).address}:{port}"
        else:
            suggestion = suggest_lan_endpoint(local_ipv4_addresses()) or f"192.168.1.2:{DEFAULT_LAN_PORT}"
        return {"value": suggestion, "intro": t(WIFI_INTRO), "choices": choices}

    def _save_endpoint(self, value: str, *, confirmed: bool = False) -> dict[str, Any]:
        settings = self._controller.settings
        settings.sync_lan_endpoint = value
        if confirmed or not value:
            settings.sync_lan_endpoint_confirmed = value
        try:
            settings.save()
        except OSError as exc:
            from ..error_log import log_exception

            log_exception("sync-ui", exc)
            raise ApiError("invalid", t("settings.error.notSaved")) from None
        if self.service is not None:
            self._run(_noop, t("sync.updatingWiFiSync"))  # the listener follows the setting
        return self.view()

    def wifi_enable(self, text: str) -> dict[str, Any]:
        value, problem = validate_lan_endpoint(text)
        if value is None:
            raise ApiError("invalid", problem)
        return self._save_endpoint(value, confirmed=True)  # typed or picked by the user: kept as chosen

    def wifi_disable(self) -> dict[str, Any]:
        return self._save_endpoint("")

    # ------------------------------------------------------------- firewall
    def _firewall_module(self) -> Any:
        if self._firewall is not None:
            return self._firewall
        from ..sync import firewall

        return firewall

    def _firewall_target(self) -> tuple[int, str]:
        value, _problem = validate_lan_endpoint(getattr(self._controller.settings, "sync_lan_endpoint", "") or "")
        if value is None:
            raise ApiError("invalid", t("sync.turnOnWiFiSync2"))
        host, port = _split_endpoint(value)
        snapshot, _candidates = self._candidates()
        from ..sync.lan_interfaces import same_address

        interface = next((i.name for i in getattr(snapshot, "interfaces", ())
                          if any(same_address(a, host) for a in i.addresses)), "")
        return port, interface

    @staticmethod
    def _firewall_view(status: Any) -> dict[str, Any]:
        profile = str(getattr(status, "profile", "") or "")
        shown = {"DomainAuthenticated": "Domain"}.get(profile, profile) or "Unknown"
        shown_text = {"Public": t("sync.firewallProfile.public"), "Domain": t("sync.firewallProfile.domain"),
                      "Private": t("sync.firewallProfile.private"),
                      "Unknown": t("sync.firewallProfile.unknown")}.get(shown, shown)
        lines = []
        if shown == "Public":
            lines.append(t("sync.windowsTreatsThisNetworkAs2"))
        elif shown == "Domain":
            lines.append(t("sync.windowsTreatsThisNetworkAs3"))
        blocked = str(getattr(status, "blocked_by", "") or "")
        if blocked:
            lines.append(t("sync.firewallBlockedByRule", rule=blocked))
        supported = bool(getattr(status, "supported", False))
        return {"supported": supported, "allowed": bool(getattr(status, "allowed", False)), "profile": shown_text,
                "can_allow": supported and shown not in ("Public", "Domain") and not blocked,
                "advice": " ".join(lines), "detail": str(getattr(status, "detail", "") or "")}

    def firewall_status(self) -> dict[str, Any]:
        port, interface = self._firewall_target()
        return self._firewall_view(self._firewall_module().firewall_status(port, interface=interface))

    def firewall_allow(self) -> dict[str, Any]:
        """The user's "Allow through Windows Firewall" button: an elevated netsh (UAC prompt)."""
        firewall = self._firewall_module()
        port, interface = self._firewall_target()
        before = firewall.firewall_status(port, interface=interface)
        if not getattr(before, "supported", False):
            raise ApiError("unavailable", t("sync.windowsFirewallSettingsAreOnly"))
        view = self._firewall_view(before)
        if not view["can_allow"]:
            raise ApiError("invalid", view["advice"] or t("sync.windowsFirewallCannotBeChanged"))
        result = firewall.allow_inbound(port, status=before)
        if result.cancelled:
            raise ApiError("cancelled", result.message)
        if not result.ok:
            raise ApiError("firewall_failed", result.message)
        after = self._firewall_view(firewall.firewall_status(port, interface=interface))
        if not after["allowed"]:
            message = (t("sync.theRuleWasAddedBut") + " " + after["advice"]).strip()
            return {"message": message, **after}
        return {"message": result.message, **after}
