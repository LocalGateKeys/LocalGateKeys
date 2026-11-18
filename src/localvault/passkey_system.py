"""Passkey ceremonies for the Windows passkey provider (pipe scope ``system_passkey``).

Windows' plugin passkey manager activates ``LocalGateKeysPasskeyProvider.exe``,
which verifies the request signature and forwards a CTAP2-derived request over
the agent pipe. Only that pinned peer reaches :meth:`SystemPasskeyMixin.dispatch_system`
(``pipe_transport``), and it reaches nothing else. The rules (design note
``docs/design/WINDOWS_PASSKEY_PROVIDER.md`` §5.3 and §7):

* every request needs ``system_protocol == 1`` and a lower-case GUID
  ``transaction_id``; everything is refused (``disabled``) unless both
  ``windows_passkey_provider`` and ``passkeys_enabled`` are on;
* there is no page origin: the RP ID comes from Windows, so the dialog names it
  and the calling app (a display hint only, never policy). Public-suffix RP IDs
  are refused by the parser;
* create checks the free-tier item limit before any prompt (upgrade sheet,
  ``item_limit``); an excluded credential already in the vault ends as
  ``invalid_state`` after the prompt, with no new passkey;
* get offers only usable passkeys of that RP that are in the allow list (or,
  with an empty list, the discoverable ones); none ends as ``not_found`` with no
  window at all;
* a locked vault raises the unlock window once; declined is ``locked_declined``;
  every prompt that ends without a credential starts a per-RP cooldown during
  which the same answer comes back without a window, so a caller cannot loop it;
* every create and every get shows the approval dialog, then verifies the user
  (Windows Hello or the master password) unless the request said
  ``discouraged``; ``required`` is never answered without that verification;
* one prompt at a time (``_remote_busy``, shared with the browser path);
* ``passkey_cancel_system`` runs on the pipe thread and ends the open prompt of
  its transaction; an approval later than ``SYSTEM_PASSKEY_DEADLINE`` or after a
  cancel is dropped, so nothing is stored for a request Windows gave up on.

Private keys never leave this process: replies carry authenticator data,
signatures, credential IDs and user handles only, and error replies carry a
fixed code only.
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .app.ui_port import UiPortHost, ui_port_of
from .passkey_broker import PASSKEY_COOLDOWN
from .passkeys import (
    PasskeyError,
    b64u_encode,
    create_credential_from_hash,
    get_assertion_from_hash,
    parse_system_create,
    parse_system_get,
    usable_record,
)
from .pipe_transport import SYSTEM_PASSKEY_ACTIONS
from .session_guard import StaleSession
from .vault import ItemLimitReached, VaultError

SYSTEM_PROTOCOL = 1
SYSTEM_PASSKEY_DEADLINE = 25.0        # the provider gives up at 30 s
# How long run_on_ui may wait for the vault lock; past the deadline the request is dropped anyway.
SYSTEM_RUN_TIMEOUT = 35.0
_TRANSACTION_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# Cancels that arrived before (or without) their request: remembered briefly, bounded.
_CANCELLED_TTL = 60.0
_CANCELLED_MAX = 64
_STATE_LOCK = threading.Lock()

__all__ = ["SYSTEM_PASSKEY_ACTIONS", "SYSTEM_PASSKEY_DEADLINE", "SYSTEM_PROTOCOL", "SystemPasskeyMixin"]


def _error(code: str) -> dict[str, Any]:
    return {"ok": False, "error": code}


@dataclass
class _Transaction:
    id: str
    cancel: threading.Event = field(default_factory=threading.Event)
    started: float = field(default_factory=lambda: time.monotonic())

    def remaining(self) -> float:
        return SYSTEM_PASSKEY_DEADLINE - (time.monotonic() - self.started)

    def over(self) -> bool:
        """Cancelled by the provider or past the deadline: nothing may be created or signed."""
        return self.cancel.is_set() or self.remaining() <= 0


@dataclass
class _SystemState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    open: dict[str, _Transaction] = field(default_factory=dict)
    cancelled: dict[str, float] = field(default_factory=dict)  # early cancels: id -> expiry
    cooldowns: dict[str, tuple[float, str]] = field(default_factory=dict)  # rp_id -> (until, code)


def _caller(value: Any) -> dict[str, str]:
    """The caller hint as plain strings (cleaned again by the dialog); anything else is dropped."""
    if not isinstance(value, dict):
        return {}
    return {key: value[key][:1024] for key in ("image", "title") if isinstance(value.get(key), str)}


class SystemPasskeyMixin(UiPortHost):
    """Mixed into the browser broker next to ``PasskeyBrokerMixin``; see the module notes."""

    # -- the browser extension steps aside ---------------------------------------
    def _system_provider_active(self) -> bool:
        """True when the browser passkey actions answer ``system_provider``.

        Only when ``windows_passkey_provider`` is on and the last ``--state`` Windows reported was ``enabled``:
        the page then calls the browser's own WebAuthn, which Windows routes to the provider. Anything else (off,
        not registered, not turned on in Windows Settings, unknown) keeps the extension's own passkey path, so the
        user always has one. Decided from the app's settings and cache only, never from the request. A cached state
        older than 30 s counts as unknown while a background ``--state`` refresh runs (an app timer normally keeps
        it fresh), so turning LocalGateKeys off in Windows Settings is picked up within one refresh.
        """
        if getattr(self.settings, "windows_passkey_provider", False) is not True:
            return False
        from . import windows_passkey_provider as provider

        registration = provider.REGISTRATION
        registration.refresh_later()
        return registration.enabled()

    # -- state ----------------------------------------------------------------
    def _system_state(self) -> _SystemState:
        state = self.__dict__.get("_system_passkey_state")
        if state is None:
            with _STATE_LOCK:
                state = self.__dict__.setdefault("_system_passkey_state", _SystemState())
        return state

    def _system_begin(self, transaction_id: str) -> _Transaction | None:
        """Open a transaction; None when its id is already open (a duplicate)."""
        state = self._system_state()
        with state.lock:
            if transaction_id in state.open:
                return None
            txn = _Transaction(transaction_id)
            now = time.monotonic()
            if state.cancelled.pop(transaction_id, 0.0) > now:
                txn.cancel.set()  # the cancel overtook its request
            state.open[transaction_id] = txn
            return txn

    def _system_end(self, txn: _Transaction) -> None:
        state = self._system_state()
        with state.lock:
            if state.open.get(txn.id) is txn:
                del state.open[txn.id]

    def _system_cooling(self, rp_id: str) -> str | None:
        state = self._system_state()
        now = time.monotonic()
        with state.lock:
            for key in [key for key, (until, _code) in state.cooldowns.items() if until <= now]:
                del state.cooldowns[key]
            entry = state.cooldowns.get(rp_id)
        return entry[1] if entry else None

    def _system_cool(self, rp_id: str, code: str) -> None:
        state = self._system_state()
        with state.lock:
            state.cooldowns[rp_id] = (time.monotonic() + PASSKEY_COOLDOWN, code)

    # -- entry point (pipe thread) -----------------------------------------------
    def dispatch_system(self, request: dict[str, Any], pid: int) -> dict[str, Any]:
        """Serve one request from the pinned passkey provider. Never raises; replies carry a fixed code."""
        try:
            return self._dispatch_system(request)
        except Exception:  # noqa: BLE001 - a fixed code only: no exception text (or secret) leaves
            return _error("invalid_request")

    def _dispatch_system(self, request: Any) -> dict[str, Any]:
        if not isinstance(request, dict):
            return _error("invalid_request")
        action = request.get("action")
        if action not in SYSTEM_PASSKEY_ACTIONS:
            return _error("unsupported_action")
        settings = self.settings
        if not (getattr(settings, "windows_passkey_provider", False) is True
                and getattr(settings, "passkeys_enabled", True) is True):
            from .pipe_transport import _system_refusal

            _system_refusal("setting_off" if getattr(settings, "windows_passkey_provider", False) is not True
                            else "passkeys_off")
            return _error("disabled")
        protocol = request.get("system_protocol")
        if type(protocol) is not int or protocol != SYSTEM_PROTOCOL:
            return _error("invalid_request")
        transaction_id = request.get("transaction_id")
        if not isinstance(transaction_id, str) or not _TRANSACTION_RE.fullmatch(transaction_id):
            return _error("invalid_request")
        # Not behind run_on_ui and exempt from _remote_busy: these must answer while a prompt is open.
        if action == "passkey_cancel_system":
            return self._passkey_cancel_system(request)
        if action == "passkey_lock_status_system":
            return self._passkey_lock_status_system()
        if action == "passkey_credentials_system":
            try:
                return self.run_on_ui(self._passkey_credentials_system, timeout=SYSTEM_RUN_TIMEOUT)
            except TimeoutError:
                return _error("busy")
        txn = self._system_begin(transaction_id)
        if txn is None:
            return _error("busy")
        handler = self._passkey_create_system if action == "passkey_create_system" else self._passkey_get_system

        def run() -> dict[str, Any]:
            if txn.over():
                return _error("user_cancelled")
            if self._remote_busy:
                return _error("busy")
            self._remote_busy = True
            try:
                return handler(request, txn)
            except StaleSession:
                return _error("session_changed")
            except ItemLimitReached as exc:
                self._system_show_upgrade(exc.limit, exc.count)
                return _error("item_limit")
            except (ValueError, TypeError, VaultError):
                return _error("invalid_request")
            finally:
                self._remote_busy = False

        try:
            return self.run_on_ui(run, timeout=SYSTEM_RUN_TIMEOUT)
        except TimeoutError:
            return _error("busy")
        finally:
            self._system_end(txn)

    # -- small actions --------------------------------------------------------------
    def _passkey_cancel_system(self, request: dict[str, Any]) -> dict[str, Any]:
        """End the open prompt of ``transaction_id``. An unknown id is remembered briefly and still answers ok."""
        transaction_id = str(request.get("transaction_id", ""))
        state = self._system_state()
        now = time.monotonic()
        with state.lock:
            txn = state.open.get(transaction_id)
            if txn is not None:
                txn.cancel.set()
            else:
                for key in [key for key, until in state.cancelled.items() if until <= now]:
                    del state.cancelled[key]
                if len(state.cancelled) < _CANCELLED_MAX:
                    state.cancelled[transaction_id] = now + _CANCELLED_TTL
        return {"ok": True}

    def _passkey_lock_status_system(self) -> dict[str, Any]:
        """For Windows' GetLockStatus: no prompt, no vault data, no vault lock."""
        return {"ok": True, "locked": not self._session_available()}

    def _passkey_credentials_system(self) -> dict[str, Any]:
        """Names and IDs for Windows' metadata cache (note §5.4); never key material."""
        if not self._session_available():
            return _error("locked")
        entries = self.session.item_service.passkey_metadata()
        allowed = ("credential_id", "rp_id", "rp_name", "user_id", "user_name", "user_display_name")
        return {"ok": True, "credentials": [{key: str(entry.get(key, "")) for key in allowed} for entry in entries]}

    # -- helpers ----------------------------------------------------------------------
    def passkey_prompt_system(self, mode: str, *, rp_id: str, accounts: list[dict[str, Any]], excluded: bool,
                              caller: dict[str, str], txn: _Transaction) -> tuple[str, str | None]:
        """The browser path's approval surface, system variant. ("approve", item_id|None) or ("cancel", None)."""
        choice, item_id = ui_port_of(self).ask_passkey(
            mode, origin="", rp_id=rp_id, profile_name=self.active_profile.name, accounts=accounts,
            excluded=excluded, surface="system", caller=caller, cancel=txn.cancel,
            timeout=max(0.0, txn.remaining()))
        return (choice, item_id) if choice == "approve" else ("cancel", None)

    def _system_show_upgrade(self, limit: int, count: int) -> None:
        try:
            message = str(ItemLimitReached(limit, count))
            ui_port_of(self).show_upgrade(limit=int(limit), message=message, on_enter=lambda: None)
        except Exception:  # noqa: BLE001, S110 - the sheet is best effort; the refusal is what matters
            pass

    def _system_unlock(self, rp_id: str, txn: _Transaction, state: dict[str, Any]) -> str | None:
        """None when the vault is unlocked (after one unlock window if needed), else the error code."""
        if self._session_available():
            return None
        state["prompted"] = True
        # The wait ends at a cancel or the deadline, so _remote_busy is not held after Windows gave up.
        unlocked = bool(self.ensure_unlocked(stop=txn.over))
        if txn.over():  # a late unlock never runs the request
            return "user_cancelled"
        if not unlocked or not self._session_available():
            return "locked_declined"
        return None

    def _system_verify(self, rp_id: str, user_verification: str, lease: Any) -> bool | None:
        """The UV flag, or None when the request may not be answered (failed, cancelled or not verified)."""
        verified = self._passkey_verify(rp_id, user_verification, lease)
        if user_verification == "required" and verified is not True:
            return None  # "required" is never signed without verification
        return verified

    def _system_ceremony(self, rp_id: str, run: Any) -> dict[str, Any]:
        """Cooldown and focus bookkeeping shared by create and get (see ``_passkey_ceremony``)."""
        cooling = self._system_cooling(rp_id)
        if cooling is not None:
            return _error(cooling)
        window = self._passkey_foreground()
        state: dict[str, Any] = {"prompted": False}
        result: dict[str, Any] | None = None
        try:
            result = run(state)
            return result
        finally:
            if state["prompted"]:
                if result is None or result.get("ok") is not True:
                    code = "locked_declined" if result and result.get("error") == "locked_declined" \
                        else "user_cancelled"
                    self._system_cool(rp_id, code)
                if window:
                    self._passkey_return_focus(window)

    # -- ceremonies (run_on_ui, _remote_busy held) -------------------------------------
    def _passkey_create_system(self, request: dict[str, Any], txn: _Transaction | None = None) -> dict[str, Any]:
        txn = txn or _Transaction(str(request.get("transaction_id", "")))
        try:
            opts = parse_system_create(request)
        except PasskeyError as exc:
            return _error(exc.code if exc.code in ("invalid_request", "not_supported") else "invalid_request")
        caller = _caller(request.get("caller"))

        def run(state: dict[str, Any]) -> dict[str, Any]:
            locked = self._system_unlock(opts.rp_id, txn, state)
            if locked is not None:
                return _error(locked)
            lease = self.guard.lease()
            full = self._item_limit_full()
            if full is not None:
                limit = int(full.get("limit", 0))
                self._system_show_upgrade(limit, limit)
                return _error("item_limit")
            records = self.session.item_service.passkey_records(opts.rp_id)
            existing = {record["credential_id"] for record in records}
            for record in records:
                record.clear()
            excluded = any(b64u_encode(credential_id) in existing for credential_id in opts.exclude_ids)
            account = {"id": None, "title": opts.rp_name or opts.rp_id, "user_name": opts.user_name}
            state["prompted"] = True
            choice, _ = self.passkey_prompt_system("create", rp_id=opts.rp_id, accounts=[account],
                                                   excluded=excluded, caller=caller, txn=txn)
            self.require_lease(lease)
            if choice != "approve" or txn.over():
                return _error("user_cancelled")
            if excluded:
                return _error("invalid_state")
            verified = self._system_verify(opts.rp_id, opts.user_verification, lease)
            if verified is None or txn.over():
                return _error("user_cancelled")
            self.require_lease(lease)
            fields, response = create_credential_from_hash(opts, user_verified=verified)
            try:
                if txn.over():  # the last moment before anything is stored
                    return _error("user_cancelled")
                self.session.item_service.create_passkey(fields.pop("title"), **fields)
            except ItemLimitReached:
                raise
            except VaultError:
                self._passkey_save_failed()
                return _error("user_cancelled")
            finally:
                fields.clear()
            self.refresh_entries()
            self._touch_secret()
            return {"ok": True, **response}

        return self._system_ceremony(opts.rp_id, run)

    def _passkey_get_system(self, request: dict[str, Any], txn: _Transaction | None = None) -> dict[str, Any]:
        txn = txn or _Transaction(str(request.get("transaction_id", "")))
        try:
            opts = parse_system_get(request)
        except PasskeyError:
            return _error("invalid_request")
        caller = _caller(request.get("caller"))

        def run(state: dict[str, Any]) -> dict[str, Any]:
            locked = self._system_unlock(opts.rp_id, txn, state)
            if locked is not None:
                return _error(locked)
            lease = self.guard.lease()
            allowed = {b64u_encode(credential_id) for credential_id in opts.allow_ids}
            records = self.session.item_service.passkey_records(opts.rp_id)
            try:
                candidates = [record for record in records
                              if usable_record(record) and (record.get("credential_id") in allowed if allowed
                                                            else bool(record.get("discoverable", True)))]
                if not candidates:
                    return _error("not_found")
                accounts = [{"id": record["id"], "title": record["title"],
                             "user_name": record.get("user_name", "")} for record in candidates]
                state["prompted"] = True
                choice, item_id = self.passkey_prompt_system("get", rp_id=opts.rp_id, accounts=accounts,
                                                             excluded=False, caller=caller, txn=txn)
                self.require_lease(lease)
                chosen = next((record for record in candidates if record["id"] == item_id), None)
                if choice != "approve" or chosen is None or txn.over():
                    return _error("user_cancelled")
                verified = self._system_verify(opts.rp_id, opts.user_verification, lease)
                if verified is None or txn.over():
                    return _error("user_cancelled")
                self.require_lease(lease)
                assertion = get_assertion_from_hash(opts, chosen, user_verified=verified)
            finally:
                for record in records:
                    record.clear()
            self._touch_secret()
            return {"ok": True, **assertion}

        return self._system_ceremony(opts.rp_id, run)
