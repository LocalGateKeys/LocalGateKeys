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
import threading
import time
from typing import Any, Callable

from ..api.result import ApiError
from .sync_view import (
    _ACTION_LABELS,
    _ACTION_ORDER,
    _PRIMARY,
    DEFAULT_LAN_PORT,
    PASSWORD_ADVICE,
    RESET_TEXT_1,
    RESET_TEXT_2,
    acknowledge_job,
    add_folder_job,
    begin_pairing_job,
    check_sync_password,
    countdown_text,
    create_group_job,
    default_device_name,
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
    remove_lan_peer_job,
    remove_wifi_device_text,
    reset_result_text,
    rotate_job,
    rotation_intro,
    rotation_plan,
    sanitize_name,
    short_id,
    snapshot_job,
    suggest_lan_endpoint,
    sync_view,
    validate_lan_endpoint,
)

JOB_TIMEOUT = 180.0
CONFIRM_SYNC = "Confirm to sync passwords to another device"
NOT_RUNNING = "Sync runs while the vault is unlocked on this PC. Unlock and try again."
PRO_REQUIRED = ("Device sync is part of LocalGateKeys Pro. Everything already on this PC stays here and "
                "keeps working; with Pro, sync resumes where it left off.")
STOPPED = "Sync stopped (the vault locked). Unlock and try again."
WIFI_INTRO = ("This PC's address and port on your home network. Other devices connect to it here. Only private "
              "network addresses work.")
PAIR_HINT = ("Phone and PC must be on the same Wi-Fi. If the phone can't connect, allow LocalGateKeys through "
             "Windows Firewall on Private networks.")
CHOOSE_ADDRESS = ("The saved address ({saved}) no longer belongs to this PC, and this PC has more than one "
                  "network address. Choose the address of the Wi-Fi or Ethernet network your phone uses.")
CHOOSE_KEEP = ("The saved address ({saved}) is on an adapter a phone usually cannot reach (a virtual adapter, a "
               "direct cable, or a network without a router). Keep it only if your phone connects that way; "
               "otherwise choose your Wi-Fi or Ethernet address.")
CHOOSE_VIRTUAL = ("The saved address ({saved}) belongs to a virtual network adapter (for example VirtualBox, "
                  "Hyper-V, WSL or a VPN), which a phone cannot reach. Choose the address of the Wi-Fi or "
                  "Ethernet network your phone uses.")
INTRO = ("Keep this vault in step on your phone and other PCs. Everything is encrypted before it leaves this PC.")


def _noop(session: Any, lease: Any, gate: Any) -> None:
    return None


def _split_endpoint(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    return host.strip("[]"), int(port)


def _probe_network() -> Any:
    from ..sync.lan_interfaces import probe_interfaces

    return probe_interfaces()


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


def not_listening_text(address: str, issue: Any) -> str:
    """Why no QR code is shown: nothing accepts connections on *address*."""
    kind = str(getattr(issue, "kind", "") or "lan-not-listening")
    detail = str(getattr(issue, "detail", "") or "")
    if kind == "listen-failed":
        reason = f" Reason: {detail}." if detail else ""
        return (f"Wi-Fi sync could not start listening on {address}, so no pairing code is shown.{reason} Check "
                "the address under Turn on Wi-Fi sync, and that no other app uses that port.")
    advice = issue_text(issue) if kind != "lan-not-listening" else "Try again in a moment."
    return f"Wi-Fi sync is not listening on {address}, so no pairing code is shown. {advice}"


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


def _default_factory(controller: Any, on_status: Callable[[Any, Any], None]) -> Any:
    """The real service, built like ``AgentApp._start_sync_service`` (no UI barrier: there is no UI thread)."""
    from ..sync import service as sync_service
    from ..sync.install import load_or_create_install_id

    session = controller.session
    install_id = load_or_create_install_id()
    lease = controller.guard.lease()
    guard = controller.guard

    def check_lease() -> None:
        guard.require(lease)

    owner: list[Any] = []

    def endpoint() -> Any:
        from ..sync.transport import LANEndpoint

        value = getattr(controller.settings, "sync_lan_endpoint", None)
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
                    sync_service.LanAdapter(install_id=install_id, endpoint=endpoint)],
        scheduler=sync_service.ThreadScheduler(), gate=sync_service.SyncGate(VaultLockBarrier(controller.vault_lock)),
        post_result=lambda view: on_status(owner[0] if owner else None, view),
        change_marker=lambda: sync_service.vault_change_marker(session))
    owner.append(service)
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

    def plan_changed(self) -> None:
        """Start or stop sync after the licence changed (installed, removed, restored)."""
        if self.sync_allowed():
            self.start()
        else:
            self.stop()
        self._bus.emit("sync.status", {})

    def start(self) -> None:
        from ..error_log import log_exception

        with self._lock:
            if self.service is not None or not self._controller.is_unlocked():
                return
            if not self.sync_allowed():
                # Free plan: no sync round and no listener.  What earlier syncs
                # brought stays in the vault; a Pro licence resumes sync.
                return
            try:
                service = self._factory(self._controller, self._status_changed)
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
        if getattr(view, "license_adopted", False) and self._on_licence is not None:
            self._on_licence()
        self._bus.emit("sync.status", {})

    # ----------------------------------------------------------------- jobs
    def _service(self) -> Any:
        service = self.service
        if service is None:
            if self._controller.is_unlocked() and not self.sync_allowed():
                raise ApiError("pro_required", PRO_REQUIRED)
            raise ApiError("unavailable", NOT_RUNNING)
        return service

    def _run(self, job: Callable[[Any, Any, Any], Any], busy: str, *, run_after: bool = False) -> Any:
        service = self._service()
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", "Another sync action is still running.")
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
                raise ApiError("stopped", STOPPED)
            if not done.wait(self._timeout):
                with state_lock:
                    if not done.is_set():
                        box["waiting"] = False
                        handed_over = True  # on_done releases busy when the job ends
                if handed_over:
                    raise ApiError("timeout", "This sync action is still running. Its result shows here when it "
                                              "finishes; do not repeat it.")
            if service is not self.service:
                raise ApiError("stopped", STOPPED)  # the vault locked meanwhile: drop the result
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
            text = item.text + (" If that does not help, use Reset sync on this PC below." if item.reset_offered
                                else "")
            return {"kind": item.kind, "severity": item.severity, "text": text}

        def card(c: Any) -> dict[str, Any]:
            return {
                "key": c.key, "title": c.title, "state": c.state, "state_text": c.state_text,
                "last_sync_text": c.last_sync_text, "banner": issue(c.banner), "hint": c.hint,
                "members_heading": "Devices" if c.key == "folder" else "Paired devices",
                "members": [{"id": m.device_id, "name": m.name, "detail": m.detail, "is_self": m.is_self,
                             "removable": m.removable} for m in c.members],
                "issues": [issue(i) for i in c.issues[1:]],
                "actions": [{"id": a, "label": _ACTION_LABELS[a], "primary": a in _PRIMARY}
                            for a in _ACTION_ORDER if a in c.actions],
            }

        status_line = self._busy_text or ("Syncing now…" if view.running else "")
        if view.conflicts_text:
            status_line = f"{status_line}  ·  {view.conflicts_text}" if status_line else view.conflicts_text
        return {"intro": INTRO, "status_line": status_line, "banner": issue(view.banner),
                "cards": [card(view.wifi), card(view.folder)], "skipped": list(view.skipped),
                "available": self.service is not None, "busy": bool(self._busy_text),
                "advice": PASSWORD_ADVICE, "pro": self.sync_allowed() or not self._controller.is_unlocked(),
                "pro_text": PRO_REQUIRED}

    # --------------------------------------------------------------- inputs
    def choose_folder(self) -> dict[str, Any]:
        self._service()
        folder = self._dialogs.choose_folder("Choose the sync folder")
        if not folder:
            raise ApiError("cancelled", "No folder was chosen.")
        token = secrets.token_urlsafe(12)
        self._folders[token] = str(folder)
        return {"token": token, "path": str(folder)}

    def _folder(self, token: str) -> str:
        folder = self._folders.pop(str(token or ""), None)
        if not folder:
            raise ApiError("invalid", "Choose the sync folder first.")
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
        self._auth.reauthenticate(CONFIRM_SYNC, lease, allow_hello=False)
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
                      "Creating the sync group…", run_after=True)
        finally:
            password = confirm = ""
        return {"message": "Sync group created. Join it from your other devices with the same folder and sync "
                           "password.", **self.refresh()}

    def join(self, token: str, password: str) -> dict[str, Any]:
        service = self._service()
        folder = self._folder(token)
        if not password:
            raise ApiError("invalid", "Enter the sync password.")
        try:
            self._confirm_handover()  # this PC's items are merged into the folder for the group's devices
            self._run(join_folder_job(folder, password, default_device_name(), service.install_id), "Joining…",
                      run_after=True)
        finally:
            password = ""
        return {"message": "This PC joined the sync group.", **self.refresh()}

    def folder_setup(self, action: str, token: str, password: str, confirm: str) -> dict[str, Any]:
        service = self._service()
        setup = folder_setup(action)
        if setup is None:
            raise ApiError("invalid", "Unknown sync action.")
        folder = self._folder(token)
        try:
            if setup.confirm_twice:
                self._require_strong(password, confirm)
            elif not password:
                raise ApiError("invalid", "Enter the sync password.")
            fresh_key = action == "add-folder" and bool(getattr(self._snapshot, "lan_removed", False))
            if fresh_key and not self._port.confirm("New sync key", lan_removed_folder_text(self._snapshot)):
                # Audit M9: a removed Wi-Fi device still holds the group key; the folder gets a new one.
                raise ApiError("cancelled", "Cancelled.")
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
            raise ApiError("invalid", "Unknown sync action.")
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
                if not self._port.confirm("Change sync password" if not remove else "Remove device?", text):
                    raise ApiError("cancelled", "Cancelled.")
            elif lead and not self._port.confirm("Remove device?", lead):
                raise ApiError("cancelled", "Cancelled.")
            self._run(rotate_job(password, remove, service.install_id, service.lan_transport, plan.keep),
                      "Changing the sync password…", run_after=True)
        finally:
            password = confirm = ""
        return {"message": done_text, **self.refresh()}

    def rotation_text(self) -> dict[str, Any]:
        return {"title": "Change sync password", "intro": rotation_intro(self._snapshot)}

    def acknowledge_members(self) -> dict[str, Any]:
        """Confirm the devices shown as added by another device (``member-added``)."""
        service = self._service()
        group = self._snapshot
        ids = tuple(getattr(group, "unacked", ()) or ())
        if not ids:
            return {"message": "There are no new devices to confirm.", **self.refresh()}
        names = group.names() if hasattr(group, "names") else {}
        shown = ", ".join(sanitize_name(names.get(d) or short_id(d)) for d in ids)
        if not self._port.confirm("Confirm devices", f"Are these your devices?\n\n{shown}\n\nThey keep syncing and "
                                                     "get the new key when the sync password changes."):
            raise ApiError("cancelled", "Cancelled.")
        self._run(acknowledge_job(ids, service.install_id), "Saving…")
        return {"message": f"Confirmed: {shown}.", **self.refresh()}

    def change_password(self, password: str, confirm: str) -> dict[str, Any]:
        return self._rotate(password, confirm, (), "The sync password was changed.")

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
            raise ApiError("invalid", "That device is no longer in this sync group.")
        name = member.name
        if self._snapshot is not None and getattr(self._snapshot, "folder_path", None):
            self._require_strong(password, confirm)
            return self._rotate(password, confirm, (device_id,), f"{name} was removed from sync.",
                                lead=f"Remove {name} from sync?\n\nThe sync password changes, so {name} cannot read "
                                     "anything new. It keeps what it already has. If the device was lost, also sign "
                                     "it out of your cloud account.")
        if not self._port.confirm("Remove device?", remove_wifi_device_text(name)):
            raise ApiError("cancelled", "Cancelled.")
        self._run(remove_lan_peer_job(device_id, service.install_id, service.lan_transport), "Removing…")
        return {"message": f"{name} was removed from Wi-Fi sync on this PC. Remove it on your other PCs too.",
                **self.refresh()}

    def orphans(self) -> dict[str, Any]:
        orphans = orphan_members(self._snapshot, now=time.time())
        if not orphans:
            return {"devices": [], "message": "Every device in this sync group has a recent sync file."}
        return {"devices": [{"id": m.device_id, "name": m.name, "detail": m.detail} for m in orphans],
                "intro": rotation_intro(self._snapshot)}

    def remove_orphans(self, ids: list[str], password: str, confirm: str) -> dict[str, Any]:
        orphans = orphan_members(self._snapshot, now=time.time())
        chosen = [m for m in orphans if m.device_id in set(ids or ())]
        if not chosen:
            raise ApiError("invalid", "Choose at least one device.")
        names = ", ".join(m.name for m in chosen)
        return self._rotate(password, confirm, tuple(m.device_id for m in chosen), f"Removed: {names}.",
                            lead=f"Remove {names} from sync?")

    def leave(self) -> dict[str, Any]:
        service = self._service()
        if not self._port.confirm("Leave sync", leave_text(self._snapshot)):
            raise ApiError("cancelled", "Cancelled.")
        self._run(leave_job(service.install_id), "Leaving…")
        return {"message": "This PC left sync. Remove it on one of your other devices.", **self.refresh()}

    def reset(self) -> dict[str, Any]:
        service = self._service()
        if not self._port.confirm("Reset sync on this PC", RESET_TEXT_1):
            raise ApiError("cancelled", "Cancelled.")
        if not self._port.confirm("Reset sync on this PC", RESET_TEXT_2):
            raise ApiError("cancelled", "Cancelled.")
        if not self._busy.acquire(blocking=False):
            raise ApiError("busy", "Another sync action is still running.")
        done = threading.Event()
        box: dict[str, Any] = {}
        try:
            self._busy_text = "Resetting sync on this PC…"
            self._bus.emit("sync.status", {})
            if not service.reset(lambda cleared: (box.__setitem__("cleared", cleared), done.set())):
                raise ApiError("stopped", STOPPED)
            if not done.wait(self._timeout):
                raise ApiError("timeout", "Sync is taking too long. Try again in a moment.")
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
            return fixed, f"Wi-Fi sync now uses {fixed}: the saved address {host} no longer belongs to this PC.", None
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
                    "addresses": choices, "message": CHOOSE_ADDRESS.format(saved=host)}
        saved = {"value": value, "label": f"{host} (saved)"}
        if saved_virtual and candidates:
            best = obvious_candidate(candidates) or candidates[0]
            best_value = f"{best.address}:{port}"
            ordered = [c for c in choices if c["value"] == best_value]
            ordered += [saved] + [c for c in choices if c["value"] != best_value]
            return {"choose_address": True, "current": best_value, "addresses": ordered,
                    "message": CHOOSE_VIRTUAL.format(saved=host)}
        return {"choose_address": True, "current": value, "addresses": [saved, *choices],
                "message": CHOOSE_KEEP.format(saved=host)}

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
        offer = self._run(begin_pairing_job(host, port, service.install_id), "Preparing a code…")
        service.arm_enrollment(offer)
        listen_state = getattr(service, "lan_listen_state", None)
        if callable(listen_state):
            try:
                self._run(_noop, "Preparing a code…")  # queued behind the arming job: the listener is settled now
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
                "size": size, "modules": size // (scale // 2), "address": value, "hint": PAIR_HINT,
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
            # The inviter answers at once (the phone waits only ~5 s), so instead of an Accept step the page shows
            # who paired, with an Undo that removes it (Remove a device).
            peer = getattr(service, "enrollment_peer", lambda _o: None)(offer_id)
            fingerprint = paired_fingerprint(getattr(peer, "fingerprint", ""))
            name = short_id(str(device_id))
            detail = f" (key {fingerprint})" if fingerprint else ""
            return {"state": "paired", "device": {"id": str(device_id), "name": name, "fingerprint": fingerprint},
                    "message": f"Paired: {name}{detail}. If you don't recognise it, choose Undo."}
        left = float(offer.expires_at) - time.time()
        if left <= 0:
            offers.pop(offer_id, None)
            return {"state": "expired", "countdown": "Expired"}
        return {"state": "waiting", "countdown": countdown_text(left)}

    def qr_copy(self, offer_id: str) -> dict[str, Any]:
        entry = self._offers.get(offer_id)
        if entry is None or self.service is None or float(entry[0].expires_at) <= time.time():
            raise ApiError("invalid", "This pairing code has closed.")
        self._controller.clipboard.copy(entry[1])
        return {"message": "Code text copied."}

    def qr_close(self, offer_id: str) -> dict[str, Any]:
        self._offers.pop(offer_id, None)
        service = self.service
        if service is not None:
            service.cancel_enrollment(offer_id)
        return {}

    def join_qr(self, text: str) -> dict[str, Any]:
        service = self._service()
        if not str(text or "").strip():
            raise ApiError("invalid", "Paste the code text from the other device.")
        endpoint = None
        value, _problem = validate_lan_endpoint(getattr(self._controller.settings, "sync_lan_endpoint", "") or "")
        if value is not None:
            from ..sync.transport import LANEndpoint

            host, _, port = value.rpartition(":")
            endpoint = LANEndpoint(host.strip("[]"), int(port))
        self._confirm_handover()  # the paired device receives this PC's items on the first sync
        self._run(enroll_job(str(text).strip(), service.install_id, endpoint), "Pairing…")
        return {"message": "This PC joined the other device's sync.", **self.refresh()}

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
        return {"value": suggestion, "intro": WIFI_INTRO, "choices": choices}

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
            raise ApiError("invalid", "The setting could not be saved.") from None
        if self.service is not None:
            self._run(_noop, "Updating Wi-Fi sync…")  # the listener follows the setting
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
            raise ApiError("invalid", "Turn on Wi-Fi sync first.")
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
        lines = []
        if shown == "Public":
            lines.append("Windows treats this network as Public; set it to Private in Windows Settings › Network "
                         "& internet if this is your home network. Other devices cannot connect until then.")
        elif shown == "Domain":
            lines.append("Windows treats this network as a work (Domain) network, where the Private rule does not "
                         "apply. Ask your administrator to allow LocalGateKeys, or use your home network.")
        blocked = str(getattr(status, "blocked_by", "") or "")
        if blocked:
            lines.append(f"The Windows Firewall rule \u201c{blocked}\u201d blocks this program and wins over any "
                         "allow rule. Remove it, or allow the app, in Windows Defender Firewall > Allow an app "
                         "through firewall.")
        supported = bool(getattr(status, "supported", False))
        return {"supported": supported, "allowed": bool(getattr(status, "allowed", False)), "profile": shown,
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
            raise ApiError("unavailable", "Windows Firewall settings are only available on Windows.")
        view = self._firewall_view(before)
        if not view["can_allow"]:
            raise ApiError("invalid", view["advice"] or "Windows Firewall cannot be changed for this network.")
        result = firewall.allow_inbound(port, status=before)
        if result.cancelled:
            raise ApiError("cancelled", result.message)
        if not result.ok:
            raise ApiError("firewall_failed", result.message)
        after = self._firewall_view(firewall.firewall_status(port, interface=interface))
        if not after["allowed"]:
            message = ("The rule was added, but Windows Firewall still does not allow LocalGateKeys on this "
                       "network. " + after["advice"]).strip()
            return {"message": message, **after}
        return {"message": result.message, **after}
