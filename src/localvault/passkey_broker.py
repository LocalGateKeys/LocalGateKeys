"""Passkey (WebAuthn) ceremonies for the browser broker.

Mixed into :class:`localvault.browser_broker.BrowserBroker`, which owns the
transport checks (protocol pins, browser-derived origin and document
context, one interactive prompt at a time).  This module adds the policy:

* ``system_provider`` (``windows_passkey_provider`` on and enabled in
  Windows) answers both actions at once, before anything else: the page
  calls the browser's own WebAuthn so Windows routes it to the provider;
* every ``fallback`` hands the request to the browser's own authenticator,
  so a site the user signs in to elsewhere never sees a LocalGateKeys prompt;
* a get with no matching stored passkey falls back *without* a dialog;
* while the vault is locked every request falls back at once: a page needs
  no user gesture for ``navigator.credentials``, so it must not be able to
  raise the unlock window (whose Windows Hello can start by itself). At
  most a passive notice per origin and ``PASSKEY_COOLDOWN`` asks the user
  to unlock LocalGateKeys to use saved passkeys;
* every create and every get that has a candidate shows a desktop dialog
  naming the site and profile, and nothing is signed without that click;
* unless the site asks for ``userVerification: "discouraged"`` the user is
  also verified (Windows Hello or the master password);
* after any prompt that ends without a credential (Cancel, "Use browser",
  an existing passkey, failed verification) the same
  origin gets ``fallback`` with no prompt for ``PASSKEY_COOLDOWN`` seconds,
  so a page cannot loop the dialog;
* focus goes back to the window that was in front (the browser) once a
  prompt closes, because the browser refuses WebAuthn calls from a page
  that does not have focus, and a fallback must reach its own dialog;
* an AI agent's approved passkey sign-in (agent_gate) only narrows a get
  to the approved login's passkeys and is used by it; the dialog and the
  verification above still run (the agent approval replaces neither);
* an approval that arrives after ``PASSKEY_DEADLINE`` seconds is dropped:
  the extension has given up by then, and a passkey the site never
  received must not be stored;
* two-step save (known limitation 2, orphan passkeys): a create from an
  extension that announces ``passkey_confirm`` (set by its service worker,
  never by the page) is saved *unconfirmed* and answered as before. The
  page sends ``passkey_confirm_browser`` before it hands the credential to
  the site's code, or ``passkey_discard_browser`` when it cannot (aborted,
  timed out, frame gone); both carry only the operation id, and the app
  acts only when the browser-derived context equals the create's exactly,
  so a page can settle nothing but its own create, and the reply never
  reaches the page. An unconfirmed passkey is not offered for sign-in, not
  in the Windows provider's list and not synced. It is removed for good
  (no trash, no history) only on an explicit discard. With no report at
  all it is kept and becomes an ordinary passkey when
  ``PASSKEY_CONFIRM_WINDOW`` seconds have passed since the reply, on lock,
  or at the next unlock (a crash in between): the page may have received
  it, and a passkey the site registered must not vanish from the vault.
  An extension without ``passkey_confirm``
  keeps the old behaviour: the passkey is saved confirmed at once. A
  confirmation is counted when it reaches the broker, before it waits for
  the vault lock, so a busy vault never turns a received passkey into a
  deleted one.
* a get from a cross-origin frame (known limitation 4) carries ``top_origin``:
  the top-level document's origin, which the extension's service worker read
  from the browser's frame tree (never from the page), bound as a fifth
  element into the browser context so an approval under one top site cannot
  serve another. Only a get may carry it (anything else is
  ``invalid_request``), and only with ``publickey_get_allowed`` (the frame's
  permissions policy allows ``publickey-credentials-get``; without it the
  browser answers). The rpId is still checked against the frame's own
  origin, never the top site's; clientDataJSON says ``crossOrigin: true``
  with ``topOrigin``, and the dialog names both sites. Same-origin frames
  and top-level pages send neither field and keep today's bytes.

The private key never leaves the agent: replies carry signatures only.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any

from .app.ui_port import UiPortHost, ui_port_of
from .identity_fill import validate_identity_context
from .origin import canonicalize_origin
from .passkeys import (
    PasskeyError,
    b64u_encode,
    create_credential,
    get_assertion,
    parse_create_options,
    parse_get_options,
    usable_record,
)
from .vault import VaultError

PASSKEY_PROTOCOL = 1
# A page reports the outcome of its own create (two-step save, see above).
PASSKEY_OUTCOME_ACTIONS = frozenset({"passkey_confirm_browser", "passkey_discard_browser"})
PASSKEY_ACTIONS = frozenset({"passkey_create_browser", "passkey_get_browser"}) | PASSKEY_OUTCOME_ACTIONS
# Seconds after the create reply within which a confirm-capable extension must confirm.
PASSKEY_CONFIRM_WINDOW = 15.0
# A confirm or discard whose save fails is tried again this many times, this many seconds apart; after that
# the passkey is left to the next unlock, which keeps it as an ordinary passkey.
PASSKEY_APPLY_RETRIES = 3
PASSKEY_APPLY_RETRY_DELAY = 2.0
# How long the lock waits for the vault to settle an unconfirmed passkey (else the next unlock does).
PASSKEY_LOCK_WAIT = 2.0
PASSKEY_COOLDOWN = 10.0
# The extension waits 90 s for an interactive reply; past this the page has
# (nearly) given up, so nothing is created or signed.
PASSKEY_DEADLINE = 80.0
LOCKED_NOTICE = "Unlock LocalGateKeys to use your saved passkeys."


def _error(code: str) -> dict[str, Any]:
    return {"ok": False, "error": code}


def passkey_top_origin(request: dict[str, Any]) -> str | None:
    """The canonical ``top_origin`` of a cross-origin-frame request, None when absent; raises ValueError
    when present but not exactly a canonical origin."""
    top = request.get("top_origin")
    if top is None:
        return None
    if not isinstance(top, str) or canonicalize_origin(top) != top:
        raise ValueError("top_origin must be a canonical origin")
    return top


def validate_passkey_context(request: dict[str, Any], context: str, origin: str) -> None:
    """The structured browser context of a passkey action (raises ValueError).

    Same-origin frames and top-level pages: exactly the four-element identity context. A get from a
    cross-origin frame: those four elements plus the top origin, which must equal ``top_origin``. Any
    other action with a top origin, or a five-element context without one, is refused.
    """
    top = passkey_top_origin(request)
    if top is None:
        validate_identity_context(context, origin)
        return
    if request.get("action") != "passkey_get_browser":
        raise ValueError("only a passkey get may come from a cross-origin frame")
    try:
        value = json.loads(context)
    except (TypeError, ValueError) as exc:
        raise ValueError("passkey browser context is malformed") from exc
    if not isinstance(value, list) or len(value) != 5 or value[4] != top:
        raise ValueError("passkey browser context does not bind the top origin")
    validate_identity_context(json.dumps(value[:4], separators=(",", ":")), origin)


class PasskeyBrokerMixin(UiPortHost):
    def passkey_prompt(self, mode: str, *, origin: str, rp_id: str, accounts: list[dict[str, Any]],
                       excluded: bool, top_origin: str | None = None) -> tuple[str, str | None]:
        """Ask the user. Returns ("approve", item_id|None), ("browser", None) or ("cancel", None)."""
        extra = {"top_origin": top_origin} if top_origin is not None else {}
        return ui_port_of(self).ask_passkey(mode, origin=origin, rp_id=rp_id,
                                            profile_name=self.active_profile.name, accounts=accounts,
                                            excluded=excluded, **extra)

    def _passkey_save_failed(self) -> None:
        ui_port_of(self).notify("error", "Passkey not saved",
                                "LocalGateKeys could not save this passkey, so the website did not receive one.")

    def _passkey_foreground(self) -> int | None:
        try:
            import win32gui  # type: ignore[import-not-found]
            return int(win32gui.GetForegroundWindow()) or None
        except Exception:  # noqa: BLE001 - best effort; no window to return to
            return None

    def _passkey_return_focus(self, hwnd: int) -> None:
        try:
            from .uia import _restore_foreground
            _restore_foreground(hwnd)
        except Exception:  # noqa: BLE001 - Windows may refuse; the page then sees its own error
            return

    def _passkey_cooldowns(self) -> dict[str, float]:
        return self.__dict__.setdefault("_passkey_cooldown", {})

    def _passkey_cooling(self, origin: str) -> bool:
        cooldowns = self._passkey_cooldowns()
        now = time.monotonic()
        for key in [key for key, until in cooldowns.items() if until <= now]:
            del cooldowns[key]
        return origin in cooldowns

    def _passkey_ready(self, origin: str) -> bool:
        return bool(getattr(self.settings, "passkeys_enabled", True)) and not self._passkey_cooling(origin)

    def _passkey_locked(self, origin: str) -> bool:
        """True (after at most a passive notice) when the vault is locked: the request falls back, unprompted."""
        if self._session_available():
            return False
        notices = self.__dict__.setdefault("_passkey_locked_notice", {})
        now = time.monotonic()
        for key in [key for key, until in notices.items() if until <= now]:
            del notices[key]
        if origin not in notices:
            notices[origin] = now + PASSKEY_COOLDOWN
            try:
                ui_port_of(self).notify("info", "Passkeys", LOCKED_NOTICE)
            except Exception:  # noqa: BLE001, S110 - the notice is best effort; the fallback is what matters
                pass
        return True

    def _passkey_verify(self, rp_id: str, user_verification: str, lease: Any) -> bool | None:
        """True/False = the UV flag; None = the user failed or cancelled verification."""
        if user_verification == "discouraged":
            return False
        # fresh: the UV flag never rests on the routine grace another action (reveal, copy) left behind.
        return True if self.reauthenticate(f"Confirm passkey for {rp_id}", lease, allow_hello=True,
                                           fresh=True) else None

    def _passkey_ceremony(self, origin: str, run: Any) -> dict[str, Any]:
        """Run one ceremony with the prompt bookkeeping shared by create and get.

        ``run(state)`` sets ``state["prompted"]`` before showing a dialog. No
        unlock prompt is ever shown: a locked vault falls back before this.
        """
        window = self._passkey_foreground()
        state = {"prompted": False, "started": time.monotonic()}
        result: dict[str, Any] | None = None
        try:
            result = run(state)
            return result
        finally:
            if state["prompted"]:
                if result is not None and result.get("ok") is not True:
                    self._passkey_cooldowns()[origin] = time.monotonic() + PASSKEY_COOLDOWN
                if window:
                    self._passkey_return_focus(window)

    @staticmethod
    def _passkey_late(state: dict[str, Any]) -> bool:
        return time.monotonic() - state["started"] > PASSKEY_DEADLINE

    def _passkey_create_browser(self, request: dict[str, Any], origin: str, context: str) -> dict[str, Any]:
        # The Windows passkey provider is on: the page hands the call to the
        # browser (and so to Windows) at once. No cooldown, no locked notice.
        if self._system_provider_active():
            return _error("system_provider")
        # Registration needs a user activation in the page (the extension's
        # isolated world reads navigator.userActivation.isActive). Without one
        # the browser's own authenticator handles it: a page cannot raise the
        # desktop dialog over and over on its own.
        if request.get("user_activation") is not True:
            return _error("fallback")
        if not self._passkey_ready(origin):
            return _error("fallback")
        try:
            opts = parse_create_options(origin, request.get("options"))
        except PasskeyError as exc:
            return _error(exc.code)
        if self._passkey_locked(origin):
            return _error("fallback")

        def run(state: dict[str, Any]) -> dict[str, Any]:
            if not self._session_available():  # never ensure_unlocked: no unlock window without a gesture
                return _error("fallback")
            lease = self.guard.lease()
            records = self.session.item_service.passkey_records(opts.rp_id)
            existing = {record["credential_id"] for record in records}
            for record in records:
                record.clear()
            excluded = any(b64u_encode(credential_id) in existing for credential_id in opts.exclude_ids)
            account = {"id": None, "title": opts.rp_name or opts.rp_id, "user_name": opts.user_name}
            state["prompted"] = True
            choice, _ = self.passkey_prompt("create", origin=origin, rp_id=opts.rp_id, accounts=[account],
                                            excluded=excluded)
            self.require_lease(lease)
            if choice == "browser":
                return _error("fallback")
            if choice != "approve":
                return _error("user_cancelled")
            if excluded:
                return _error("invalid_state")
            verified = self._passkey_verify(opts.rp_id, opts.user_verification, lease)
            if verified is None or self._passkey_late(state):
                return _error("user_cancelled")
            # Set by the extension's service worker, never by the page: this extension confirms or discards.
            confirmable = request.get("passkey_confirm") is True
            fields, response = create_credential(origin, opts, user_verified=verified)
            try:
                item_id = self.session.item_service.create_passkey(fields.pop("title"), unconfirmed=confirmable,
                                                                   **fields)
            except VaultError:
                self._passkey_save_failed()
                return _error("user_cancelled")
            finally:
                fields.clear()
            if confirmable:
                self._passkey_await_confirm(context, item_id)
            self.refresh_entries()
            self._touch_secret()
            return {"ok": True, "passkey_protocol": PASSKEY_PROTOCOL, "credential": response}

        return self._passkey_ceremony(origin, run)

    # -- two-step save: confirm / discard / expiry of unconfirmed passkeys ------------------------------
    def _passkey_pending(self) -> dict[str, list[dict[str, Any]]]:
        """Browser context of a create -> its unconfirmed passkeys (normally one)."""
        return self.__dict__.setdefault("_passkey_pending_creates", {})

    def _passkey_pending_lock(self) -> Any:
        lock = self.__dict__.get("_passkey_pending_guard")
        if lock is None:
            lock = self.__dict__.setdefault("_passkey_pending_guard", threading.Lock())
        return lock

    def _passkey_await_confirm(self, context: str, item_id: str) -> None:
        entry = {"item_id": item_id, "deadline": time.monotonic() + PASSKEY_CONFIRM_WINDOW,
                 "stamp": self.guard.stamp(), "outcome": None, "context": context, "tries": 0}
        with self._passkey_pending_lock():
            self._passkey_pending().setdefault(context, []).append(entry)
        self._passkey_schedule(PASSKEY_CONFIRM_WINDOW)

    def _passkey_schedule(self, delay: float) -> None:
        """Run the expiry after *delay* seconds on a timer thread (tests replace this)."""
        timer = threading.Timer(max(0.0, delay), self._passkey_timer_fired)
        timer.daemon = True
        timer.start()

    def _passkey_timer_fired(self) -> None:
        try:
            self.run_on_ui(self._passkey_expire, timeout=30)
        except Exception:  # noqa: BLE001 - the vault is busy or gone: try again while anything waits
            with self._passkey_pending_lock():
                waiting = bool(self._passkey_pending())
            if waiting:
                self._passkey_schedule(5.0)

    def _passkey_note_outcome(self, request: Any) -> None:
        """Record a confirm/discard the moment it reaches the broker, before it waits for the vault lock.

        Only the create's own browser context matches (the key is the whole context string). The first
        outcome stands: once confirmed, a passkey is never discarded.
        """
        if not isinstance(request, dict):
            return
        action, context = request.get("action"), request.get("context")
        if action not in PASSKEY_OUTCOME_ACTIONS or not isinstance(context, str):
            return
        outcome = "confirm" if action == "passkey_confirm_browser" else "discard"
        with self._passkey_pending_lock():
            for entry in self._passkey_pending().get(context, ()):
                if entry["outcome"] is None:
                    entry["outcome"] = outcome

    def _passkey_take(self, context: str | None, *, now: float | None, force: bool) -> list[dict[str, Any]]:
        """Remove and return the entries to settle now: *context*'s that have an outcome, or (no *context*)
        every entry with an outcome, past its deadline, or (*force*) all."""
        taken: list[dict[str, Any]] = []
        with self._passkey_pending_lock():
            pending = self._passkey_pending()
            for key in [context] if context is not None else list(pending):
                entries = pending.get(key, [])
                keep = []
                for entry in entries:
                    due = (entry["outcome"] is not None or force
                           or (context is None and now is not None and entry["deadline"] <= now))
                    (taken if due else keep).append(entry)
                if keep:
                    pending[key] = keep
                else:
                    pending.pop(key, None)
        return taken

    def _passkey_apply(self, entries: list[dict[str, Any]]) -> int:
        """Confirm or remove each taken entry's passkey (under the vault lock). Returns how many passkeys were
        actually confirmed or removed: an entry of another session (stamp mismatch), one already confirmed or
        gone, and one whose save failed (tried again later) do not count (scan core 3, L3)."""
        if not entries:
            return 0
        if not self._session_available():
            return 0  # locked or switched: the next unlock keeps what is still unconfirmed
        stamp = self.guard.stamp()
        service = self.session.item_service
        changed = 0
        for entry in entries:
            if entry["stamp"] != stamp:
                continue
            try:
                # Only an explicit discard removes. No report at all (window over, lock) keeps the
                # passkey: the page may have received it, and a site that registered a passkey the
                # vault then dropped is worse than an unused entry the user can delete.
                if entry["outcome"] == "discard":
                    done = service.remove_unconfirmed_passkey(entry["item_id"])
                else:
                    done = service.confirm_passkey(entry["item_id"])
            except (VaultError, ValueError):
                # Not saved: try again shortly rather than leave a passkey the site may already use hidden
                # from sign-in until the next unlock (which keeps it as an ordinary passkey).
                self._passkey_retry(entry)
                continue
            changed += 1 if done else 0
        if changed:
            self.refresh_entries()
        return changed

    def _passkey_retry(self, entry: dict[str, Any]) -> None:
        tries = int(entry.get("tries", 0)) + 1
        if tries > PASSKEY_APPLY_RETRIES:
            return
        again = {**entry, "tries": tries, "deadline": time.monotonic() + PASSKEY_APPLY_RETRY_DELAY}
        if again["outcome"] is None:
            again["outcome"] = "confirm"  # its window is over: settled as kept
        with self._passkey_pending_lock():
            self._passkey_pending().setdefault(str(entry.get("context", "")), []).append(again)
        self._passkey_schedule(PASSKEY_APPLY_RETRY_DELAY)

    def _passkey_outcome(self, request: dict[str, Any], context: str) -> dict[str, Any]:
        # Normally noted already by dispatch_remote; noting again is harmless (the first outcome stands).
        self._passkey_note_outcome({"action": request.get("action"), "context": context})
        taken = self._passkey_take(context, now=None, force=False)
        if not taken:
            # The same answer for an unknown operation and for another page's: nothing about it is revealed.
            return _error("not_found")
        if self._passkey_apply(taken):
            return {"ok": True}
        # This page's own operation, but nothing changed: another session (locked or switched since), already
        # confirmed (a user edit) or gone, or the save failed and is tried again later. Never reported as saved.
        return _error("not_changed")

    def _passkey_confirm_browser(self, request: dict[str, Any], origin: str, context: str) -> dict[str, Any]:
        return self._passkey_outcome(request, context)

    def _passkey_discard_browser(self, request: dict[str, Any], origin: str, context: str) -> dict[str, Any]:
        return self._passkey_outcome(request, context)

    def _passkey_expire(self, now: float | None = None) -> None:
        """Settle what is due: outcomes already noted, and unconfirmed passkeys past their window (kept)."""
        now = time.monotonic() if now is None else now
        self._passkey_apply(self._passkey_take(None, now=now, force=False))
        with self._passkey_pending_lock():
            deadlines = [entry["deadline"] for entries in self._passkey_pending().values() for entry in entries]
        if deadlines:
            self._passkey_schedule(max(0.0, min(deadlines) - time.monotonic()) + 0.05)

    def _passkey_before_lock(self) -> None:
        """Lock hook: settle every unconfirmed passkey of this session: a noted discard removes, anything else
        keeps it as an ordinary passkey."""
        with self._passkey_pending_lock():
            if not self._passkey_pending():
                return
        try:
            self.run_on_ui(lambda: self._passkey_apply(self._passkey_take(None, now=None, force=True)),
                           timeout=PASSKEY_LOCK_WAIT)
        except Exception:  # noqa: BLE001, S110 - the lock must go ahead; the next unlock keeps the rest
            pass
        with self._passkey_pending_lock():
            self._passkey_pending().clear()

    def _passkey_after_unlock(self) -> None:
        """Unlock hook: keep (confirm) passkeys left unconfirmed by a crash, off the unlocking thread."""
        try:  # a read-only look first: nearly always there is nothing to settle and no thread is started
            if not self._session_available() or not self.session.item_service.unconfirmed_passkey_ids():
                return
        except Exception:  # noqa: BLE001, S110 - unsure: let the locked purge below decide
            pass

        def run() -> None:
            try:
                self.run_on_ui(self._passkey_purge_orphans, timeout=30)
            except Exception:  # noqa: BLE001, S110 - best effort; they stay hidden and unsynced until next time
                pass
        threading.Thread(target=run, name="lgk-passkey-purge", daemon=True).start()

    def _passkey_purge_orphans(self) -> int:
        """Confirm (keep) every unconfirmed passkey this process is not waiting on: after a crash nobody can
        say whether the page received it. Returns how many were confirmed."""
        if not self._session_available():
            return 0
        stamp = self.guard.stamp()
        with self._passkey_pending_lock():
            waiting = {entry["item_id"] for entries in self._passkey_pending().values() for entry in entries
                       if entry["stamp"] == stamp}
        service = self.session.item_service
        removed = 0
        for item_id in service.unconfirmed_passkey_ids():
            if item_id in waiting:
                continue
            try:
                removed += 1 if service.confirm_passkey(item_id) else 0
            except (VaultError, ValueError):
                continue
        if removed:
            self.refresh_entries()
        return removed

    def _agent_passkey_grant(self, origin: str, candidates: list[dict[str, Any]]) -> Any:
        """An AI agent's approved passkey sign-in for this page (agent_gate), taken for this one assertion, or None.

        The grant only narrows the offer to the approved login's passkeys; the dialog and user verification below
        run exactly as for any passkey sign-in (the agent's approval replaces neither).
        """
        gate = getattr(getattr(self, "agent_gate_service", None), "gate", None)
        take = getattr(gate, "take_passkey_for_origin", None)
        if not callable(take):
            return None
        return take(origin, [str(record.get("credential_id", "")) for record in candidates])

    def _passkey_get_browser(self, request: dict[str, Any], origin: str, context: str) -> dict[str, Any]:
        if self._system_provider_active():
            return _error("system_provider")
        # A cross-origin frame (dispatch checked the top origin against the context). Without the
        # frame's publickey-credentials-get permission the browser answers, and refuses as the standard says.
        top_origin = passkey_top_origin(request)
        if top_origin is not None and request.get("publickey_get_allowed") is not True:
            return _error("fallback")
        # A dismissed dialog cools down only this pairing: a top page that frames the site cannot silence the
        # site's own pages, or its frames under other top sites.
        cooldown = origin if top_origin is None else json.dumps([origin, top_origin], separators=(",", ":"))
        if not self._passkey_ready(cooldown):
            return _error("fallback")
        try:
            opts = parse_get_options(origin, request.get("options"))
        except PasskeyError as exc:
            return _error(exc.code)
        if self._passkey_locked(origin):
            return _error("fallback")
        agent: dict[str, Any] = {}

        def run(state: dict[str, Any]) -> dict[str, Any]:
            if not self._session_available():  # never ensure_unlocked: no unlock window without a gesture
                return _error("fallback")
            lease = self.guard.lease()
            allowed = {b64u_encode(credential_id) for credential_id in opts.allow_ids}
            records = self.session.item_service.passkey_records(opts.rp_id)
            try:
                candidates = [record for record in records
                              if usable_record(record) and (record["credential_id"] in allowed if allowed
                                                            else record.get("discoverable", True))]
                if not candidates:
                    return _error("fallback")
                # An agent's grant was approved for the site's own page: a framed copy under another top site
                # gets the ordinary dialog and leaves the grant alone.
                grant = self._agent_passkey_grant(origin, candidates) if top_origin is None else None
                if grant is not None:
                    agent["grant"] = grant
                    candidates = [record for record in candidates if record["credential_id"] in grant.passkey_ids]
                accounts = [{"id": record["id"], "title": record["title"],
                             "user_name": record.get("user_name", "")} for record in candidates]
                state["prompted"] = True
                extra = {"top_origin": top_origin} if top_origin is not None else {}
                choice, item_id = self.passkey_prompt("get", origin=origin, rp_id=opts.rp_id, accounts=accounts,
                                                      excluded=False, **extra)
                self.require_lease(lease)
                if choice == "browser":
                    return _error("fallback")
                chosen = next((record for record in candidates if record["id"] == item_id), None)
                if choice != "approve" or chosen is None:
                    return _error("user_cancelled")
                verified = self._passkey_verify(opts.rp_id, opts.user_verification, lease)
                if verified is None or self._passkey_late(state):
                    return _error("user_cancelled")
                assertion = get_assertion(origin, opts, chosen, user_verified=verified, top_origin=top_origin)
            finally:
                for record in records:
                    record.clear()
            self._touch_secret()
            return {"ok": True, "passkey_protocol": PASSKEY_PROTOCOL, "credential": assertion}

        result: dict[str, Any] | None = None
        try:
            result = self._passkey_ceremony(cooldown, run)
            return result
        finally:
            grant = agent.get("grant")
            if grant is not None:
                # The agent learns only whether the page got an assertion; the grant is used either way.
                self.agent_gate_service.gate.finish(  # type: ignore[attr-defined]
                    grant, "passkey" if result is not None and result.get("ok") is True else "none")
