"""Emergency access for the WebView UI (sub-plan 08, Task 3): the owner's plan and requests, the heir's screen.

Owner (Recovery centre › Emergency access): make a plan (re-asks the master password and the typed recovery
phrase), print the shard sheets (``heir.sheet_facts`` → ``HeirSheet.svelte``) or save one ``.lgkheir`` file
per holder, see requests with Deny / Grant now.  The shard packages are held in memory only until the page
closes them or the vault locks: the owner keeps no shard.  The plan syncs to the owner's other devices
(``sync/vault_bridge.py`` namespace ``heir``), so each of them can deny or grant once its shared folder is chosen.

The scheduled-backup timer calls ``timer_check`` (at most every 10 minutes, and soon after each unlock): on
every owner device it reads the requests (which writes a deleted deny again) and shows a toast for each new
one; on the device that made the plan it also writes the heir folder's daily backup (and right after a plan
is made).

Heir ("I was given access"): add shards (file, dropped file text or scanned QR text), pick the shared folder,
ask for access, and restore as a new profile once allowed.  The requester's keys live in the requester's own
vault, so it must be unlocked (the free plan is enough).
"""
from __future__ import annotations

import base64
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .. import heir, heir_flow
from ..api.result import ApiError
from ..i18n import t
from ..secret_text import SecretText, is_blank_secret, secrets_match

#: Seconds between two timer looks at the heir folder (requests, missing denies, the daily backup).  The timer
#: ticks every 60 s, so 9 minutes keeps a deleted deny written again within the promised 10 minutes.
BACKUP_LOOK_EVERY = 540
_ERRORS = {
    "no-folder": "heir.err.noFolder", "no-plan": "heir.err.noPlan", "no-request": "heir.err.noRequest",
    "denied": "heir.err.denied", "stale-plan": "heir.err.stalePlan", "no-backup": "heir.err.noBackup",
    "check-failed": "heir.err.checkFailed", "malformed": "heir.err.malformed", "exists": "heir.err.exists",
    "mixed-plans": "heir.err.mixedPlans", "duplicate": "heir.err.duplicate", "invalid": "heir.err.invalid",
    "need-more": "heir.err.needMore", "waiting": "heir.err.waiting", "wrong-phrase": "heir.err.wrongPhrase",
}


def _thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True, name="lgk-heir-backup").start()


def _api_error(exc: heir_flow.HeirFlowError | heir.HeirError) -> ApiError:
    reason = exc.reason
    key = _ERRORS.get(reason, "heir.err.malformed")
    params = {"count": getattr(exc, "missing", 0)} if reason == "need-more" else \
        {"count": getattr(exc, "days_left", 0)} if reason == "waiting" else {}
    return ApiError(reason.replace("-", "_"), t(key, **params))


def _safe_name(text: str) -> str:
    return "".join(c for c in text if c.isalnum() or c in " -_").strip()[:32] or "holder"


class HeirService:
    def __init__(self, controller: Any, port: Any, dialogs: Any, *, bus: Any = None,
                 spawn: Callable[[Callable[[], None]], None] = _thread,
                 clock: Callable[[], float] = time.time) -> None:
        from .secrets import SecretService

        self._controller = controller
        self._port = port
        self._dialogs = dialogs
        self._auth = SecretService(controller, port)
        self._spawn = spawn
        self._clock = clock
        # handle -> {"plan", "packages"}: the packages of a plan just made, until printed/saved and closed.
        self._issued: dict[str, dict[str, Any]] = {}
        self._shards: dict[int, bytes] = {}
        self._folder: str = ""
        self._received_loaded = False  # the holder's shards and folder read from the vault this unlock
        self._bus = bus
        self._running = False  # a heir backup is being written
        self._looking = False  # a look at the folder (requests, missing denies) is running
        self._looked = 0.0
        # Requests already announced in this unlock (a new unlock announces the open ones again).
        self._announced: set[str] = set()
        self.last_backup_error: str = ""
        controller.on_lock.append(self._drop)

    def _drop(self) -> None:
        self._issued.clear()
        self._shards.clear()
        self._folder = ""
        self._received_loaded = False
        self._announced.clear()
        self._looked = 0.0

    # --------------------------------------------------------------- helpers
    def _session(self) -> tuple[Any, Any]:
        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        lease = controller.guard.lease()
        controller.require_lease(lease)
        return controller.session, lease

    def _reauth(self, title: str, lease: Any) -> Callable[[], bool]:
        def reauthenticate() -> bool:
            self._auth.reauthenticate(title, lease, allow_hello=False)  # raises ApiError when not authorized
            self._controller.require_lease(lease)
            return True

        return reauthenticate

    @staticmethod
    def _plan_summary(plan: heir.HeirPlan) -> dict[str, Any]:
        return {"plan_id": plan.plan_id, "k": plan.k, "n": plan.n, "wait_days": plan.wait_days,
                "holders": [h.nickname for h in plan.holders], "folder": str(plan.folder or ""),
                "owner": plan.owner, "created": time.strftime("%Y-%m-%d", time.gmtime(plan.created)),
                "stale": plan.stale, "home": plan.home}

    # ------------------------------------------------------------------ owner
    def view(self) -> dict[str, Any]:
        session, _lease = self._session()
        try:
            plan = heir.load_plan(session)
        except heir.HeirError as exc:
            raise _api_error(exc) from None
        requests = []
        if plan is not None:
            for request in heir_flow.pending_requests(session):
                requests.append({"id": request.request_id, "holder": request.holder, "days_left": request.days_left,
                                 "granted": request.granted,
                                 "created": time.strftime("%Y-%m-%d", time.gmtime(request.created))})
        allowed = getattr(session, "pro_features", None)
        return {"plan": self._plan_summary(plan) if plan is not None else None, "requests": requests,
                "pro": allowed is None or heir.FEATURE in allowed, "collusion": t("heir.collusionWarning"),
                "limits": {"min_k": 2, "max_n": 5, "min_wait": heir.MIN_WAIT_DAYS, "max_wait": heir.MAX_WAIT_DAYS},
                "has_phrase": bool(session.has_recovery_phrase()), "backup_error": self.last_backup_error,
                "folder_reachable": self._reachable(plan)}

    @staticmethod
    def _reachable(plan: heir.HeirPlan | None) -> bool:
        """Whether the plan's chosen heir folder is there (review M4); ``True`` when none is chosen."""
        if plan is None or plan.folder is None:
            return True
        try:
            return Path(plan.folder).is_dir()
        except OSError:
            return False

    def choose_folder(self) -> dict[str, Any]:
        chosen = self._dialogs.choose_folder(t("heir.chooseFolder"))
        if not chosen:
            raise ApiError("cancelled", t("heir.noFolderChosen"))
        return {"folder": str(chosen)}

    def create(self, *, k: int, holders: list[str], wait_days: int, folder: str, owner: str,
               phrase: str) -> dict[str, Any]:
        from ..vault import ProFeatureRequired, RecoveryPhraseError, VaultError
        from .licence_view import pro_required

        session, lease = self._session()
        if not folder or not Path(folder).is_dir():
            raise ApiError("no_folder", t("heir.err.noFolder"))
        if not phrase.strip():
            raise ApiError("invalid", t("heir.enterPhrase"))
        try:
            plan, packages = heir.create_plan(session, k=k, n=len(holders), holders=holders, wait_days=wait_days,
                                              folder=Path(folder), phrase=phrase.strip(),
                                              reauthenticate=self._reauth(t("heir.confirmCreate"), lease),
                                              owner=owner)
        except ProFeatureRequired as exc:
            raise pro_required(self._port, exc) from None
        except heir.HeirError as exc:
            raise _api_error(exc) from None
        except (RecoveryPhraseError, VaultError) as exc:
            raise ApiError("invalid", str(exc)) from None
        except PermissionError:
            raise ApiError("cancelled", t("error.cancelled")) from None
        self._issued.clear()
        handle = f"h{int(self._clock() * 1000)}"
        self._issued[handle] = {"plan": plan, "packages": packages}
        self._start_backup(force=True)
        return {"handle": handle, "plan": self._plan_summary(plan), "message": t("heir.planMade")}

    def _issued_for(self, handle: str) -> dict[str, Any]:
        issued = self._issued.get(str(handle))
        if issued is None:
            raise ApiError("stale", t("heir.shardsGone"))
        return issued

    def sheet(self, handle: str) -> dict[str, Any]:
        issued = self._issued_for(handle)
        return heir.sheet_facts(issued["plan"], issued["packages"])

    def save_files(self, handle: str) -> dict[str, Any]:
        issued = self._issued_for(handle)
        chosen = self._dialogs.choose_folder(t("heir.saveShardsTitle"))
        if not chosen:
            raise ApiError("cancelled", t("heir.noFolderChosen"))
        directory = Path(chosen)
        written = 0
        try:
            for data in issued["packages"]:
                shard = heir.read_package(data)
                base = f"{_safe_name(shard.holder)}-shard-{shard.index}"
                for attempt in range(100):
                    target = directory / (f"{base}.lgkheir" if attempt == 0 else f"{base} ({attempt}).lgkheir")
                    try:
                        with open(target, "xb") as handle_out:  # never replaces a file
                            handle_out.write(data)
                        break
                    except FileExistsError:
                        continue
                written += 1
        except OSError:
            raise ApiError("invalid", t("heir.saveFailed")) from None
        return {"message": t("heir.shardsSaved", count=written, folder=str(directory))}

    def done(self, handle: str) -> dict[str, Any]:
        self._issued.pop(str(handle), None)
        return {}

    def _request(self, session: Any, request_id: str) -> heir_flow.Request:
        for request in heir_flow.pending_requests(session):
            if request.request_id == request_id:
                return request
        raise ApiError("not_found", t("heir.err.noRequest"))

    def deny(self, request_id: str) -> dict[str, Any]:
        session, lease = self._session()
        request = self._request(session, request_id)
        try:
            heir_flow.deny(session, request)
        except (heir_flow.HeirFlowError, heir.HeirError) as exc:
            raise _api_error(exc) from None
        self._controller.require_lease(lease)
        return {"message": t("heir.denied", holder=request.holder)}

    def grant(self, request_id: str, phrase: str) -> dict[str, Any]:
        from ..vault import RecoveryPhraseError, VaultError

        session, lease = self._session()
        request = self._request(session, request_id)
        if not phrase.strip():
            raise ApiError("invalid", t("heir.enterPhrase"))
        if not self._port.confirm(t("heir.grantTitle"), t("heir.grantConfirm", holder=request.holder)):
            raise ApiError("cancelled", t("error.cancelled"))
        try:
            heir_flow.grant_now(session, request, phrase=phrase.strip(),
                                reauthenticate=self._reauth(t("heir.grantTitle"), lease))
        except (heir_flow.HeirFlowError, heir.HeirError) as exc:
            raise _api_error(exc) from None
        except RecoveryPhraseError as exc:
            raise ApiError("invalid", str(exc)) from None
        except VaultError as exc:
            raise ApiError("invalid", str(exc)) from None
        except PermissionError:
            raise ApiError("cancelled", t("error.cancelled")) from None
        return {"message": t("heir.granted", holder=request.holder)}

    # --------------------------------------------------- the heir folder's backup
    def backup_now(self) -> dict[str, Any]:
        session, _lease = self._session()
        if heir_flow.backup_target(session) is None:
            raise ApiError("no_plan", t("heir.err.noPlan"))
        self._start_backup(force=True)
        return {"message": t("heir.backupStarted")}

    def set_folder(self) -> dict[str, Any]:
        """Choose this device's shared folder for the stored plan (a plan received by sync has none yet)."""
        session, lease = self._session()
        chosen = self._dialogs.choose_folder(t("heir.chooseFolder"))
        if not chosen:
            raise ApiError("cancelled", t("heir.noFolderChosen"))
        if not Path(chosen).is_dir():
            raise ApiError("no_folder", t("heir.err.noFolder"))
        try:
            plan = heir.set_plan_folder(session, Path(chosen))
        except heir.HeirError as exc:
            raise _api_error(exc) from None
        self._controller.require_lease(lease)
        self._looked = 0.0  # look at the folder on the next timer tick
        return {"message": t("heir.folderSet"), "plan": self._plan_summary(plan)}

    def timer_check(self) -> bool:
        """The scheduled-backup timer's look (at most every 10 minutes): read the requests on any owner device
        (a refused request's deleted deny is written again), announce new ones, and on the device that made
        the plan write the daily heir backup.  The folder is read on a worker thread."""
        now = self._clock()
        if now - self._looked < BACKUP_LOOK_EVERY:
            return False
        started = self._start(force_backup=False, look=True)
        if started:
            self._looked = now  # a look that could not start is tried again on the next tick
        return started

    def _announce(self, pending: list[heir_flow.Request]) -> None:
        if getattr(pending, "flooded", False) and "flooded" not in self._announced and self._bus is not None:
            self._announced.add("flooded")
            self._bus.emit("toast", {"kind": "warning", "message": t("heir.folderFlooded"),
                                     "action": {"label": t("heir.review"), "route": "recovery",
                                                "params": {"initial": "heir"}}})
        for request in pending:
            if request.request_id in self._announced or request.granted:
                continue
            self._announced.add(request.request_id)
            if self._bus is None:
                continue
            self._bus.emit("toast", {
                "kind": "warning",
                "message": t("heir.requestNotice", holder=request.holder, count=request.days_left),
                "action": {"label": t("heir.review"), "route": "recovery", "params": {"initial": "heir"}}})

    @staticmethod
    def _log(where: str, exc: BaseException) -> None:
        try:
            from ..error_log import log_exception

            log_exception(where, exc)
        except Exception:  # noqa: BLE001, S110 - logging never takes the app down
            pass

    def _start_backup(self, *, force: bool) -> bool:
        return self._start(force_backup=force, look=False)

    def _start(self, *, force_backup: bool, look: bool) -> bool:
        """Start the look (``look``) and the heir backup when due on worker threads of their own, so a long or
        stuck backup never holds back the look that writes a deleted deny again (bug 2026-11-10)."""
        controller = self._controller
        if not controller.is_unlocked():
            return False
        session = controller.session
        from ..duress import is_decoy

        if is_decoy(session):
            return False  # a duress session never looks at the heir folder nor writes a backup (sub-plan 08)
        try:
            material = heir.owner_material(session)
        except heir.HeirError:
            return False
        if material is None:
            return False
        target = heir_flow.backup_target(session)
        profile = controller.profiles.active_profile()
        if target is None or profile is None:
            target = None
        if look:
            if self._looking:
                return False
            looked = self._spawn_flag("_looking", lambda: self._look(material))
            if target is not None and not self._running:
                self._start_write(target, controller, profile)
            return looked
        if target is None or self._running:
            return False
        return self._start_write(target, controller, profile, force=force_backup)

    def _look(self, material: Any) -> None:
        try:
            self._announce(heir_flow.pending_for(material))
        except Exception as exc:  # noqa: BLE001 - a failed look is logged, never shown as a backup error
            self._log("heir-look", exc)

    def _start_write(self, target: Any, controller: Any, profile: Any, *, force: bool = False) -> bool:
        profile_dir = controller.profiles.profile_dir(profile.id)
        name = profile.name

        def write() -> None:
            try:
                if force or heir_flow.backup_due(target):
                    heir_flow.write_backup(target, profile_dir=profile_dir, profile_name=name)
                    self.last_backup_error = ""
            except Exception as exc:  # noqa: BLE001 - shown on the page and logged; never takes the app down
                self.last_backup_error = t("heir.backupFailed")
                self._log("heir-backup", exc)

        return self._spawn_flag("_running", write)

    def _spawn_flag(self, flag: str, fn: Callable[[], None]) -> bool:
        """Run ``fn`` on a worker with ``flag`` set while it runs; ``False`` when no thread could start."""
        setattr(self, flag, True)

        def work() -> None:
            try:
                fn()
            finally:
                setattr(self, flag, False)

        try:
            self._spawn(work)
        except Exception:  # noqa: BLE001 - no thread: try again on the next look
            setattr(self, flag, False)
            return False
        return True

    # ------------------------------------------------------------------ heir
    def _identity(self, session: Any, *, create: bool) -> heir_flow.RequesterIdentity | None:
        record = session.heir_identity_record()
        if record is not None:
            try:
                return heir_flow.RequesterIdentity.from_record(record)
            except heir_flow.HeirFlowError as exc:
                raise _api_error(exc) from None
        if not create:
            return None
        identity = heir_flow.RequesterIdentity.generate()
        session.set_heir_identity_record(identity.to_record())
        return identity

    def _load_received(self, session: Any) -> None:
        """Read the holder's shards and folder from the vault once per unlock (they outlive a restart)."""
        if self._received_loaded:
            return
        self._received_loaded = True
        record = session.heir_received_record() or {}
        for text in record.get("shards") or []:
            try:
                data = base64.b64decode(text, validate=True)
                self._shards[heir.read_package(data).index] = data
            except (ValueError, TypeError, heir.HeirError):
                continue
        folder = record.get("folder")
        if isinstance(folder, str) and folder and not self._folder:
            self._folder = folder

    def _save_received(self, session: Any) -> None:
        record = None
        if self._shards or self._folder:
            record = {"shards": [base64.b64encode(v).decode("ascii") for _i, v in sorted(self._shards.items())],
                      "folder": self._folder or ""}
        session.set_heir_received_record(record)

    def receive_view(self) -> dict[str, Any]:
        session, _lease = self._session()
        self._load_received(session)
        shards = [heir.read_package(data) for _index, data in sorted(self._shards.items())]
        plan = None
        status = None
        if shards:
            first = shards[0]
            plan = {"plan_id": first.plan_id, "owner": first.owner, "k": first.k, "n": first.n,
                    "wait_days": first.wait_days}
            identity = self._identity(session, create=False)
            if self._folder and identity is not None:
                try:
                    found = heir_flow.request_status(self._folder, list(self._shards.values()), identity)
                    status = {"state": found.state, "days_left": found.days_left, "missing": found.missing,
                              "granted": found.granted}
                except (heir_flow.HeirFlowError, heir.HeirError) as exc:
                    status = {"state": "error", "message": str(_api_error(exc))}
            elif self._folder:
                status = {"state": "none", "days_left": 0, "missing": 0, "granted": False}
        return {"shards": [{"index": s.index, "holder": s.holder} for s in shards], "plan": plan,
                "folder": self._folder, "status": status}

    def _add(self, data: bytes) -> dict[str, Any]:
        session, _lease = self._session()
        self._load_received(session)
        try:
            shard = heir.read_package(data)
        except heir.HeirError as exc:
            raise _api_error(exc) from None
        if self._shards:
            try:
                heir.check_shards([*(v for i, v in self._shards.items() if i != shard.index), data])
            except heir.HeirError as exc:
                raise _api_error(exc) from None
        self._shards[shard.index] = bytes(data)
        self._save_received(session)
        return {"message": t("heir.shardAdded", holder=shard.holder)}

    def shard_add_file(self) -> dict[str, Any]:
        self._session()
        chosen = self._dialogs.open_file(t("heir.addShardTitle"))
        if not chosen:
            raise ApiError("cancelled", t("heir.noFileChosen"))
        try:
            path = Path(chosen)
            if path.stat().st_size > heir.MAX_PACKAGE:
                raise ApiError("malformed", t("heir.err.malformed"))
            data = path.read_bytes()
        except OSError:
            raise ApiError("malformed", t("heir.err.malformed")) from None
        return self._add(data)

    def shard_add_text(self, text: str) -> dict[str, Any]:
        self._session()
        text = text.strip()
        if text.startswith(heir.QR_PREFIX):
            try:
                data = heir.package_from_qr_text(text)
            except heir.HeirError as exc:
                raise _api_error(exc) from None
        else:
            data = text.encode("utf-8")
        return self._add(data)

    def shards_clear(self) -> dict[str, Any]:
        session, _lease = self._session()
        self._load_received(session)
        self._shards.clear()
        self._save_received(session)
        return {}

    def choose_receive_folder(self) -> dict[str, Any]:
        session, _lease = self._session()
        self._load_received(session)
        chosen = self._dialogs.choose_folder(t("heir.chooseSharedFolder"))
        if not chosen:
            raise ApiError("cancelled", t("heir.noFolderChosen"))
        self._folder = str(chosen)
        self._save_received(session)
        return {"folder": self._folder}

    def request(self) -> dict[str, Any]:
        session, lease = self._session()
        self._load_received(session)
        if not self._shards:
            raise ApiError("need_more", t("heir.addShardFirst"))
        if not self._folder:
            raise ApiError("no_folder", t("heir.err.noFolder"))
        identity = self._identity(session, create=True)
        if identity is None:
            raise ApiError("malformed", t("heir.err.malformed"))
        first = next(iter(sorted(self._shards.items())))[1]
        try:
            heir_flow.request_access(self._folder, first, identity)
        except (heir_flow.HeirFlowError, heir.HeirError) as exc:
            raise _api_error(exc) from None
        self._controller.require_lease(lease)
        return {"message": t("heir.requestSent", count=heir.read_package(first).wait_days)}

    def restore(self, profile_name: str, new_password: str | SecretText,
                confirm: str | SecretText) -> dict[str, Any]:
        from ..profiles import ProfileError

        session, lease = self._session()
        self._load_received(session)
        if not profile_name.strip() or is_blank_secret(new_password):
            raise ApiError("invalid", t("heir.enterNameAndPassword"))
        if not secrets_match(new_password, confirm):
            raise ApiError("invalid", t("masterSheet.mismatch"))
        if not self._shards or not self._folder:
            raise ApiError("invalid", t("heir.addShardFirst"))
        identity = self._identity(session, create=False)
        if identity is None:
            raise ApiError("no_request", t("heir.err.noRequest"))
        profiles = self._controller.profiles
        try:
            record = profiles.allocate_restore_profile(profile_name.strip())
            destination = profiles.restore_profile_path(record)
        except ProfileError as exc:
            raise ApiError("invalid", str(exc)) from None
        try:
            heir_flow.combine_and_restore(self._folder, list(self._shards.values()), identity,
                                          destination=destination, new_password=new_password)
        except (heir_flow.HeirFlowError, heir.HeirError) as exc:
            raise _api_error(exc) from None
        except (ValueError, OSError) as exc:
            raise ApiError("invalid", str(exc) or t("heir.err.malformed")) from None
        try:
            registered = profiles.register_restored_profile(record)
        except ProfileError as exc:
            raise ApiError("invalid", str(exc)) from None
        self._shards.clear()
        self._folder = ""
        self._save_received(session)
        self._controller.require_lease(lease)
        return {"message": t("heir.restored", name=registered.name), "restored": True}
