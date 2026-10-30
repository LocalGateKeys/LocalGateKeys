"""A login's extra content for the WebView UI.

Password history, recovery codes, custom fields, autofill rules and Google
Authenticator import, following ``FeatureUI.entry_details`` / ``history_clicked``
(docs/superpowers/specs/2026-10-17-webview-items-dataflow.md §5, §7).
``session.set_details`` replaces every detail field, so each save re-reads the
current values and changes only its own field.
"""
from __future__ import annotations

import secrets
import threading
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote, urlencode

from ..access_policy import normalized_policy
from ..api.result import ApiError
from ..totp import TotpError, match_migration_account, parse_migration_uri
from ..vault import VaultError
from ..i18n import t

ENABLE_SIGN_IN_TEXT = ("loginExtras.localgatekeysMaySubmitASupported")
USE_NEXT_TEXT = "loginExtras.copyAndRemoveTheFirst"


class LoginExtrasService:
    def __init__(self, controller: Any, port: Any, editor: Any) -> None:
        from .secrets import SecretService

        self._controller = controller
        self._port = port
        self._editor = editor
        self._auth = SecretService(controller, port)
        self._imports: dict[str, list[dict[str, Any]]] = {}
        # set_details rewrites every detail field: concurrent saves (pywebview
        # worker threads) must not interleave read-modify-write cycles.
        self._write_lock = threading.RLock()
        controller.on_lock.append(self._imports.clear)

    # -------------------------------------------------------------- helpers
    def _session_lease(self) -> tuple[Any, Any]:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        lease = self._controller.guard.lease()
        self._controller.require_lease(lease)
        return self._controller.session, lease

    @staticmethod
    def _detail(session: Any, ref: dict[str, Any]) -> dict[str, Any]:
        if ref.get("source") != "credential":
            raise ApiError("invalid", t("loginExtras.chooseALogin"))
        detail = session.credential_detail(ref["id"])
        if detail is None:
            raise ApiError("not_found", t("loginExtras.credentialIsNoLongerAvailable"))
        return detail

    def _save_details(self, session: Any, lease: Any, entry_id: str, **changes: Any) -> None:
        with self._write_lock:
            self._save_details_locked(session, lease, entry_id, **changes)

    def _save_details_locked(self, session: Any, lease: Any, entry_id: str, **changes: Any) -> None:
        detail = session.credential_detail(entry_id)
        if detail is None:
            raise ApiError("not_found", t("loginExtras.credentialIsNoLongerAvailable"))
        try:
            current = {
                "favorite": bool(detail.get("favorite")), "tags": list(detail.get("tags") or []),
                "notes": str(detail.get("notes") or ""), "totp": detail.get("totp") or None,
                "recovery_codes": list(detail.get("recovery_codes") or []),
                "custom_fields": [dict(f) for f in detail.get("custom_fields") or []],
                "policy": normalized_policy(detail.get("policy")),
            }
            current.update(changes)
            self._controller.require_lease(lease)
            session.set_details(entry_id, **current)
        except VaultError as exc:
            raise ApiError("invalid", str(exc)) from None
        finally:
            detail.clear()
        self._controller.touch()

    # ------------------------------------------------------------- strict
    @staticmethod
    def _strict(detail: dict[str, Any]) -> bool:
        return bool(normalized_policy(detail.get("policy")).get("require_master_password"))

    def _reauth_for(self, strict: bool, title: str, lease: Any, *, routine: bool = True) -> None:
        """A strict login ("Always ask for the master password") always asks for the master password,
        never Windows Hello or the routine grace (``SecretService.reauthenticate(allow_hello=False)``
        neither reads nor sets it), like ``SecretService.copy``. Other logins ask only for ``routine``
        secrets and then accept Hello or the grace."""
        if strict:
            self._auth.reauthenticate(title, lease, allow_hello=False)
        elif routine:
            self._auth.reauthenticate(title, lease, allow_hello=True)

    def _authorized_detail(self, session: Any, ref: dict[str, Any], lease: Any, title: str, *,
                           routine: bool = True) -> tuple[dict[str, Any], bool]:
        """The credential detail after the re-authentication its policy needs; the caller clears it."""
        detail = self._detail(session, ref)
        strict = self._strict(detail)
        detail.clear()
        self._reauth_for(strict, title, lease, routine=routine)
        self._controller.require_lease(lease)
        detail = self._detail(session, ref)
        if self._strict(detail) and not strict:
            detail.clear()
            raise ApiError("changed", t("loginExtras.thisLoginSAccessRules"))
        return detail, strict

    # -------------------------------------------------------------- history
    def _history(self, session: Any, entry_id: str, revision: int) -> list[dict[str, Any]]:
        values = session.password_history(entry_id)
        again = session.credential_detail(entry_id) or {}
        if again.get("revision") != revision:
            raise ApiError("changed", t("loginExtras.thisCredentialChangedCloseAnd"))
        return values

    def _revision_after_auth(self, ref: dict[str, Any], title: str) -> tuple[Any, Any, Any]:
        session, lease = self._session_lease()
        detail, _strict = self._authorized_detail(session, ref, lease, title)
        revision = detail.get("revision")
        detail.clear()
        return session, lease, revision

    def history(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, _lease, revision = self._revision_after_auth(
            ref, t("loginExtras.enterYourMasterPasswordTo"))
        values = self._history(session, ref["id"], revision)
        try:
            return {"rows": [{"index": i, "changed_at": int(v.get("changed_at") or 0)} for i, v in enumerate(values)],
                    "revision": revision}
        finally:
            for value in values:
                value.clear()

    def history_copy(self, ref: dict[str, Any], index: int, changed_at: int) -> dict[str, Any]:
        session, lease, revision = self._revision_after_auth(
            ref, t("loginExtras.enterYourMasterPasswordTo2"))
        values = self._history(session, ref["id"], revision)
        try:
            if not (0 <= index < len(values)) or int(values[index].get("changed_at") or 0) != int(changed_at):
                raise ApiError("changed", t("loginExtras.passwordHistoryChangedCloseAnd"))
            self._controller.require_lease(lease)
            self._controller.clipboard.copy(values[index]["password"])
            self._controller.touch()
        finally:
            for value in values:
                value.clear()
        return {"message": t("loginExtras.previousPasswordCopied")}

    def history_restore(self, ref: dict[str, Any], index: int, changed_at: int) -> dict[str, Any]:
        """Make a previous password current again; the password it replaces goes into history."""
        session, lease, revision = self._revision_after_auth(
            ref, t("loginExtras.enterYourMasterPasswordTo3"))
        values = self._history(session, ref["id"], revision)
        try:
            if not (0 <= index < len(values)) or int(values[index].get("changed_at") or 0) != int(changed_at):
                raise ApiError("changed", t("loginExtras.passwordHistoryChangedCloseAnd2"))
            self._controller.require_lease(lease)
            try:
                session.update_entry_fields(ref["id"], password=values[index]["password"], expected_revision=revision)
            except Exception as exc:  # noqa: BLE001 - a VaultError text is safe to show
                raise ApiError("changed", str(exc) or t("loginExtras.thePasswordWasNotRestored")) from None
            self._controller.touch()
        finally:
            for value in values:
                value.clear()
        return {"message": t("loginExtras.previousPasswordRestoredTheOne")}

    # -------------------------------------------------------- recovery codes
    def recovery_codes(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, lease = self._session_lease()
        detail, _strict = self._authorized_detail(session, ref, lease, t("loginExtras.confirmToRevealRecoveryCodes"))
        try:
            return {"codes": list(detail.get("recovery_codes") or [])}
        finally:
            detail.clear()

    def recovery_count(self, ref: dict[str, Any]) -> dict[str, Any]:
        """The count shown on selection; a strict login's stays hidden, so selecting it never prompts."""
        session, _lease = self._session_lease()
        detail = self._detail(session, ref)
        try:
            strict = self._strict(detail)
            count = len(detail.get("recovery_codes") or [])
        finally:
            detail.clear()
        if strict:
            return {"count": None, "locked": True,
                    "text": t("loginExtras.lockedThisLoginAlwaysAsks")}
        text = (t("loginExtras.codesHidden", count=count) if count
                else t("loginExtras.noSavedCodesRevealTo"))
        return {"count": count, "text": text}

    def recovery_codes_save(self, ref: dict[str, Any], codes: list[str]) -> dict[str, Any]:
        session, lease = self._session_lease()
        detail, _strict = self._authorized_detail(session, ref, lease,
                                                  t("loginExtras.enterYourMasterPasswordTo4"), routine=False)
        detail.clear()
        cleaned = [str(c).strip() for c in codes if str(c).strip()]
        self._save_details(session, lease, ref["id"], recovery_codes=cleaned)
        return {"message": t("loginExtras.recoveryCodesSaved")}

    def recovery_use_next(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, lease = self._session_lease()
        detail, _strict = self._authorized_detail(session, ref, lease,
                                                  t("loginExtras.enterYourMasterPasswordTo5"), routine=False)
        codes = list(detail.get("recovery_codes") or [])
        detail.clear()
        if not codes:
            raise ApiError("empty", t("loginExtras.saveRecoveryCodesFirst"))
        first = codes[0]
        if not self._port.confirm(t("loginExtras.useNextRecoveryCode"), t(USE_NEXT_TEXT)):
            raise ApiError("cancelled", t("error.cancelled"))
        self._controller.require_lease(lease)
        with self._write_lock:
            again = self._detail(session, ref)
            current = list(again.get("recovery_codes") or [])
            again.clear()
            if not current or current[0] != first:
                raise ApiError("changed", t("loginExtras.theSavedCodesChangedOpen"))
            self._controller.clipboard.copy(first)
            try:
                session.consume_recovery_code(ref["id"], 0)
            except VaultError as exc:
                self._controller.clipboard.clear()
                raise ApiError("changed", str(exc)) from None
        self._controller.touch()
        return {"message": t("loginExtras.recoveryCodeCopiedAndRemoved")}

    # --------------------------------------------------------- custom fields
    def custom_fields(self, ref: dict[str, Any], *, reveal: bool) -> dict[str, Any]:
        """Visible fields (with ``reveal`` also hidden values); a strict login asks for the master password either way."""
        session, lease = self._session_lease()
        title = t("loginExtras.confirmToRevealHiddenFields") if reveal else t("loginExtras.openSensitiveCredential")
        detail, _strict = self._authorized_detail(session, ref, lease, title, routine=reveal)
        try:
            return {"fields": [{"index": i, "name": str(f.get("name", "")),
                                "value": str(f.get("value", "")) if reveal or not f.get("hidden", True) else None,
                                "hidden": f.get("hidden", True) is True}
                               for i, f in enumerate(detail.get("custom_fields") or [])]}
        finally:
            detail.clear()

    def custom_fields_save(self, ref: dict[str, Any], fields: list[dict[str, Any]], *,
                           removed: Iterable[int] = ()) -> dict[str, Any]:
        """A field sent with ``value: None`` keeps the stored value of its original row ``index``
        (hidden values are write-only); renaming a hidden field keeps its own value. Unticking Hidden on
        a kept hidden value would show it on the next load, so that needs the reveal re-authentication.

        The save replaces the whole list, so every stored row must be accounted for: sent with its
        ``index`` or listed in *removed* (the rows the user deleted). A page that never loaded the
        stored rows cannot wipe them by saving only a new one."""
        session, lease = self._session_lease()
        detail, strict = self._authorized_detail(session, ref, lease,
                                                 t("loginExtras.enterYourMasterPasswordTo6"), routine=False)
        revision = detail.get("revision")
        stored = [(str(f.get("value", "")), f.get("hidden", True) is True) for f in detail.get("custom_fields") or []]
        detail.clear()
        kept = {field.get("index") for field in fields
                if isinstance(field.get("index"), int) and not isinstance(field.get("index"), bool)}
        if set(range(len(stored))) - kept - set(removed):
            stored.clear()
            raise ApiError("changed", t("loginExtras.theCustomFieldsChangedOpen"))
        merged, unhides = [], False
        for field in fields:
            name = str(field.get("name", "")).strip()
            if not name:
                continue
            hidden = field.get("hidden", True) is True
            value = field.get("value")
            if value is None:
                index = field.get("index")
                if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(stored):
                    raise ApiError("changed", t("loginExtras.theCustomFieldsChangedOpen"))
                value, was_hidden = stored[index]
                unhides = unhides or (was_hidden and not hidden)
            merged.append({"name": name, "value": str(value), "hidden": hidden})
        stored.clear()
        if unhides and not strict:  # a strict login has just asked for the master password
            self._auth.reauthenticate(t("loginExtras.confirmToRevealHiddenFields"), lease, allow_hello=True)
        with self._write_lock:
            again = self._detail(session, ref)
            current = again.get("revision")
            again.clear()
            if current != revision:
                raise ApiError("changed", t("loginExtras.theCustomFieldsChangedOpen"))
            self._save_details(session, lease, ref["id"], custom_fields=merged)
        return {"message": t("loginExtras.customFieldsSaved")}

    # ----------------------------------------------------------------- policy
    def policy(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, _lease = self._session_lease()
        detail = self._detail(session, ref)
        try:
            return {"policy": normalized_policy(detail.get("policy"))}
        finally:
            detail.clear()

    def policy_save(self, ref: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
        """Any rule change on a strict login, turning strict off included, needs the master password (no Hello)."""
        session, lease = self._session_lease()
        detail, _strict = self._authorized_detail(session, ref, lease,
                                                  t("loginExtras.enterYourMasterPasswordTo7"),
                                                  routine=False)
        before = normalized_policy(detail.get("policy"))
        detail.clear()
        after = normalized_policy({**before, **{k: v for k, v in changes.items() if k in before}})
        if after.get("sign_in") == "enabled" and before.get("sign_in") != "enabled":
            if not self._port.confirm(t("loginExtras.enableSignInForThis"), t(ENABLE_SIGN_IN_TEXT)):
                raise ApiError("cancelled", t("error.cancelled"))
        with self._write_lock:
            again = self._detail(session, ref)
            current = normalized_policy(again.get("policy"))
            again.clear()
            if current != before:
                raise ApiError("changed", t("loginExtras.thisLoginSRulesChanged"))
            self._save_details(session, lease, ref["id"], policy=after)
        revoked = 0
        if after != before:
            revoke = getattr(self._controller.guard, "revoke_entry_grants", None)
            revoked = int(revoke(ref["id"])) if callable(revoke) else 0
        if revoked:
            return {"message": t("loginExtras.policySavedRevoked", count=revoked)}
        return {"message": t("loginExtras.accessPolicySavedItApplies")}

    # -------------------------------------------------- Google Authenticator
    def ga_parse(self, text: str, *, label: str = "", origin: str = "") -> dict[str, Any]:
        try:
            found = parse_migration_uri(text)
        except TotpError as exc:
            raise ApiError("invalid", str(exc)) from None
        accounts = list(found.get("accounts") or [])
        token = secrets.token_urlsafe(12)
        self._imports[token] = accounts
        best = match_migration_account(accounts, label, origin)
        best_index = next((i for i, a in enumerate(accounts) if a is best), None)
        return {
            "token": token,
            "accounts": [{"index": i, "issuer": str(a.get("issuer") or ""), "label": str(a.get("label") or "")}
                         for i, a in enumerate(accounts)],
            "skipped": [{"issuer": str(s.get("issuer") or ""), "label": str(s.get("label") or ""),
                         "reason": str(s.get("reason") or "")} for s in found.get("skipped") or []],
            "best": best_index,
            "batch": {"index": int(found.get("batch_index") or 0), "size": int(found.get("batch_size") or 1)},
        }

    def ga_apply(self, draft_id: str, token: str, index: int) -> dict[str, Any]:
        accounts = self._imports.pop(token, None)
        if accounts is None or not (0 <= index < len(accounts)):
            for item in accounts or []:
                item.clear()
            raise ApiError("invalid", t("loginExtras.chooseAnAccountFirst"))
        account = accounts[index]
        query = urlencode({"secret": account["secret"], "issuer": account["issuer"], "digits": account["digits"],
                           "period": account["period"], "algorithm": account["algorithm"]})
        uri = f"otpauth://totp/{quote(str(account['label']))}?{query}"
        for item in accounts:
            item.clear()
        return self._editor.update(draft_id, {"totp_text": uri})
