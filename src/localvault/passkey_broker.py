"""Passkey (WebAuthn) ceremonies for the browser broker.

Mixed into :class:`localvault.browser_broker.BrowserBroker`, which owns the
transport checks (protocol pins, browser-derived origin and document
context, one interactive prompt at a time).  This module adds the policy:

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
* an approval that arrives after ``PASSKEY_DEADLINE`` seconds is dropped:
  the extension has given up by then, and a passkey the site never
  received must not be stored.

The private key never leaves the agent: replies carry signatures only.
"""
from __future__ import annotations

import time
from typing import Any

from .app.ui_port import UiPortHost, ui_port_of
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
PASSKEY_ACTIONS = frozenset({"passkey_create_browser", "passkey_get_browser"})
PASSKEY_COOLDOWN = 10.0
# The extension waits 90 s for an interactive reply; past this the page has
# (nearly) given up, so nothing is created or signed.
PASSKEY_DEADLINE = 80.0
LOCKED_NOTICE = "Unlock LocalGateKeys to use your saved passkeys."


def _error(code: str) -> dict[str, Any]:
    return {"ok": False, "error": code}


class PasskeyBrokerMixin(UiPortHost):
    def passkey_prompt(self, mode: str, *, origin: str, rp_id: str, accounts: list[dict[str, Any]],
                       excluded: bool) -> tuple[str, str | None]:
        """Ask the user. Returns ("approve", item_id|None), ("browser", None) or ("cancel", None)."""
        return ui_port_of(self).ask_passkey(mode, origin=origin, rp_id=rp_id,
                                            profile_name=self.active_profile.name, accounts=accounts,
                                            excluded=excluded)

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
        return True if self.reauthenticate(f"Confirm passkey for {rp_id}", lease, allow_hello=True) else None

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
            fields, response = create_credential(origin, opts, user_verified=verified)
            try:
                self.session.item_service.create_passkey(fields.pop("title"), **fields)
            except VaultError:
                self._passkey_save_failed()
                return _error("user_cancelled")
            finally:
                fields.clear()
            self.refresh_entries()
            self._touch_secret()
            return {"ok": True, "passkey_protocol": PASSKEY_PROTOCOL, "credential": response}

        return self._passkey_ceremony(origin, run)

    def _passkey_get_browser(self, request: dict[str, Any], origin: str, context: str) -> dict[str, Any]:
        if not self._passkey_ready(origin):
            return _error("fallback")
        try:
            opts = parse_get_options(origin, request.get("options"))
        except PasskeyError as exc:
            return _error(exc.code)
        if self._passkey_locked(origin):
            return _error("fallback")

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
                accounts = [{"id": record["id"], "title": record["title"],
                             "user_name": record.get("user_name", "")} for record in candidates]
                state["prompted"] = True
                choice, item_id = self.passkey_prompt("get", origin=origin, rp_id=opts.rp_id, accounts=accounts,
                                                      excluded=False)
                self.require_lease(lease)
                if choice == "browser":
                    return _error("fallback")
                chosen = next((record for record in candidates if record["id"] == item_id), None)
                if choice != "approve" or chosen is None:
                    return _error("user_cancelled")
                verified = self._passkey_verify(opts.rp_id, opts.user_verification, lease)
                if verified is None or self._passkey_late(state):
                    return _error("user_cancelled")
                assertion = get_assertion(origin, opts, chosen, user_verified=verified)
            finally:
                for record in records:
                    record.clear()
            self._touch_secret()
            return {"ok": True, "passkey_protocol": PASSKEY_PROTOCOL, "credential": assertion}

        return self._passkey_ceremony(origin, run)
