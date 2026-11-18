"""Settings › Unlocking › Duress password (sub-plan 08, Task 4), and the other devices' duress markers.

The page shows the same section in every session.  In a duress session it reads "not set up"; setting one up
there runs the usual checks (passwords match, the master password is right, not too close) and then ends with
the plain "Couldn't save the change. Try again later." and writes nothing (Ruling T4b).  Nothing here tells the
page which kind of session is open.
"""
from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .. import duress
from ..api.result import ApiError
from ..i18n import t
from ..secret_text import SecretText, secrets_match
from ..vault import InvalidMasterPassword, ProFeatureRequired, UnlockThrottled, VaultError

#: How often the timer looks for markers in the sync folder (the schedule timer ticks every minute).
LOOK_EVERY = 10 * 60
MAX_CANDIDATES = 500
#: Markers already shown, per profile, so one is not shown again after a restart (``(device, time)`` pairs).
SEEN_FILE = "alerts-seen.json"
SEEN_LIMIT = 64


def _read_seen(path: Path | None) -> set[tuple[str, int]]:
    try:
        raw = json.loads(path.read_bytes()[:65536]) if path is not None and path.exists() else []
    except (OSError, ValueError):
        return set()
    rows = raw if isinstance(raw, list) else []
    return {(row[0], row[1]) for row in rows
            if isinstance(row, list) and len(row) == 2 and isinstance(row[0], str) and type(row[1]) is int}


def _write_seen(path: Path | None, shown: set[tuple[str, int]]) -> None:
    if path is None:
        return
    from ..config import atomic_write_json

    rows = sorted(shown, key=lambda row: row[1])[-SEEN_LIMIT:]
    try:
        atomic_write_json(path, [list(row) for row in rows])
    except OSError:
        pass  # shown again after a restart: harmless


def _thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, name="lgk-duress-look", daemon=True).start()


class DuressService:
    def __init__(self, controller: Any, port: Any, *, bus: Any = None,
                 spawn: Callable[[Callable[[], None]], None] = _thread,
                 clock: Callable[[], float] = time.time) -> None:
        self._controller = controller
        self._port = port
        self._bus = bus
        self._spawn = spawn
        self._clock = clock
        self._looked = 0.0
        self._running = False
        # Markers already shown in this run of the app: (device id, time).
        self._shown: set[tuple[str, int]] = set()
        controller.on_unlock.append(self._unlocked)

    def _unlocked(self) -> None:
        self._looked = 0.0  # look on the next timer tick after every unlock

    # --------------------------------------------------------------- helpers
    def _session(self) -> tuple[Any, Any]:
        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        lease = controller.guard.lease()
        controller.require_lease(lease)
        return controller.session, lease

    @staticmethod
    def _sync_state(session: Any) -> Any:
        from ..sync.vault_bridge import load_sync_state

        try:
            return load_sync_state(session)
        except Exception:  # noqa: BLE001 - no usable sync state: no folder
            return None

    def _marker(self, session: Any) -> duress.MarkerIdentity | None:
        state = self._sync_state(session)
        if state is None or not state.folder_path:
            return None
        try:
            return duress.MarkerIdentity.create(state.identity(), state.group_id, state.folder_path)
        except Exception:  # noqa: BLE001 - a damaged identity: set up without the marker
            return None

    # ------------------------------------------------------------------ page
    def view(self) -> dict[str, Any]:
        session, _lease = self._session()
        allowed = getattr(session, "pro_features", None)
        decoy = duress.is_decoy(session)
        configured = not decoy and duress.configured(session.path)
        hours = (duress.lock_hours(session) if configured else None) or duress.DEFAULT_LOCK_HOURS
        state = None if decoy else self._sync_state(session)
        try:
            items = duress.copy_candidates(session)[:MAX_CANDIDATES]
        except Exception:  # noqa: BLE001 - the list is a convenience
            items = []
        return {"pro": allowed is None or duress.FEATURE in allowed, "configured": configured, "lock_hours": hours,
                "min_hours": duress.MIN_LOCK_HOURS, "max_hours": duress.MAX_LOCK_HOURS,
                "max_items": duress.MAX_COPIED_ITEMS, "folder": bool(state is not None and state.folder_path),
                "items": items}

    def setup(self, current: str | SecretText, password: str | SecretText, confirm: str | SecretText,
              lock_hours: int, item_ids: list[str]) -> dict[str, Any]:
        """The passwords stay the caller's: the bridge wipes them once this returns."""
        session, lease = self._session()
        if not secrets_match(password, confirm):
            raise ApiError("mismatch", t("duress.err.mismatch"))
        if len(item_ids) > duress.MAX_COPIED_ITEMS:
            raise ApiError("too_many", t("duress.err.tooMany", count=duress.MAX_COPIED_ITEMS))
        try:
            duress.setup(session, password, lock_hours=lock_hours, master_password=current, items=item_ids,
                         marker=self._marker(session))
        except duress.DuressError as exc:
            raise ApiError(exc.code, str(exc)) from None
        except ProFeatureRequired as exc:
            raise ApiError("pro_required", str(exc)) from None
        except UnlockThrottled as exc:
            raise ApiError("throttled", str(exc)) from None
        except InvalidMasterPassword as exc:
            raise ApiError("wrong_password", str(exc)) from None
        except VaultError as exc:
            raise ApiError("vault_error", str(exc)) from None
        except OSError:
            raise ApiError("vault_error", t("controller.localgatekeysCouldNotReadOr")) from None
        self._controller.require_lease(lease)
        return {"message": t("duress.setUpDone", count=lock_hours), **self.view()}

    def remove(self) -> dict[str, Any]:
        session, lease = self._session()
        if duress.is_decoy(session):
            raise ApiError("generic", t("duress.err.generic"))
        if not duress.configured(session.path):
            raise ApiError("missing", t("duress.err.missing"))
        if not self._port.confirm(t("duress.removeTitle"), t("duress.removeText")):
            raise ApiError("cancelled", t("error.cancelled"))
        self._controller.require_lease(lease)
        try:
            duress.remove(session)
        except VaultError as exc:
            raise ApiError("vault_error", str(exc)) from None
        return {"message": t("duress.removed"), **self.view()}

    # ------------------------------------------------------------ the timer
    def timer_check(self) -> bool:
        """Look for the duress markers of the owner's other devices in the sync folder (at most every 10 minutes);
        each one is shown once per run of the app.  The folder is read on a worker thread."""
        controller = self._controller
        if self._running or not controller.is_unlocked():
            return False
        session = controller.session
        if duress.is_decoy(session):
            return False
        now = self._clock()
        if now - self._looked < LOOK_EVERY:
            return False
        self._looked = now
        state = self._sync_state(session)
        if state is None or not state.folder_path:
            return False
        trusted: dict[str, Any] = dict(state.view_signers)
        names: dict[str, str | None] = {}
        if state.keyring:
            try:
                from ..sync.group import GroupKey
                from ..sync.keyring import member_names, member_signing_keys, parse_keyring

                ring = parse_keyring(state.keyring)  # the last keyring this device accepted
                trusted.update(member_signing_keys(ring))
                names = member_names(ring, GroupKey(state.group_id, state.epoch, state.key))
            except Exception:  # noqa: BLE001 - pinned view signers still count
                names = {}
        folder, group, own = state.folder_path, state.group_id, state.device_id
        profile = controller.profiles.active_profile()
        seen_path = Path(controller.profiles.profile_dir(profile.id)) / SEEN_FILE if profile is not None else None
        self._running = True

        def work() -> None:
            try:
                self._shown.update(_read_seen(seen_path))
                for marker in duress.read_markers(folder, trusted, group_id=group, exclude={own}, now=now):
                    key = (marker.device_id, marker.time)
                    if key in self._shown or self._bus is None:
                        continue
                    self._shown.add(key)
                    _write_seen(seen_path, self._shown)
                    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(marker.time))
                    device = names.get(marker.device_id) or t("duress.unknownDevice")
                    self._bus.emit("notice", {"kind": "error", "title": t("duress.usedOnTitle"),
                                              "message": t("duress.usedOn", device=device, time=when)})
            except Exception as exc:  # noqa: BLE001 - logged; a failed look never takes the app down
                try:
                    from ..error_log import log_exception

                    log_exception("duress-look", exc)
                except Exception:  # noqa: BLE001, S110
                    pass
            finally:
                self._running = False

        try:
            self._spawn(work)
        except Exception:  # noqa: BLE001 - no thread: try again on the next look
            self._running = False
            return False
        return True
