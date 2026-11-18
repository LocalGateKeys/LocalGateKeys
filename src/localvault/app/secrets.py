"""Secret actions for the WebView UI: re-authentication, reveal, copy, 2FA, favorite, trash, open website.

Every flow mirrors the Tk app (``agent._copy_selected_login_field``,
``detail_pane._toggle_password``, ``copy_selected_totp_clicked``,
``delete_selected_clicked``, ``runtime_actions.reauthenticate``): a lease is
taken first and re-checked after every prompt, and the credential ``revision``
pins the exact item the user selected.
"""
from __future__ import annotations

import time
import webbrowser
from typing import Any

from ..access_policy import enforced_policy
from ..api.result import ApiError
from ..collections import display_name
from ..i18n import t
from ..item_schema import validate_bookmark_url, web_page_address
from ..session_guard import StaleSession
from ..shell.overview_model import age_text
from ..totp import TotpError, generate_totp
from ..travel import hidden_id_set, visible_collections
from ..vault import FactorMismatch, FactorRequired, InvalidMasterPassword, VaultError
from .catalog import _summary_title, kind_label
from .presentation import safe_typed_fields
from .setting_links import clipboard_result

ROUTINE_REAUTH_GRACE_SECONDS = 120
REVEAL_SECONDS = 30
SESSION_CHANGED = "secrets.sessionChangedOrExpiredAction"
OPEN_WEBSITE_TEXT = ("secrets.thisOpensTheSelectedUrl")


def _format_code(code: str) -> str:
    half = len(code) // 2
    return f"{code[:half]} {code[half:]}"


def live_code(config: dict[str, Any]) -> dict[str, Any]:
    """The current code for a 2FA setup (shown, not copied); clears ``config``."""
    period = int(config.get("period", 30) or 30)
    try:
        code, remaining = generate_totp(config["secret"], digits=int(config.get("digits", 6)),
                                        period=period, algorithm=str(config.get("algorithm", "SHA1")))
    except (TotpError, ValueError):
        raise ApiError("invalid_totp", t("secrets.invalidSetupKey")) from None
    finally:
        config.clear()
    return {"code": _format_code(code), "remaining": remaining, "period": period}


COPY_ONCE_SECONDS = 10


def refuse_travel_hidden(session: Any, item_id: Any) -> None:
    """Item endpoints refuse an id travel mode hides on this device (a stale selection, a deep link, a palette
    entry kept from before travel mode was turned on), like list and search leave it out (contract 2.3)."""
    if str(item_id) in hidden_id_set(session):
        raise ApiError("not_found", t("travel.hiddenItem"))


def _copy_once_used(controller: Any) -> set[str]:
    """Logins whose secret was copied once in this unlock session (access rule "copy once"); cleared on lock."""
    used = getattr(controller, "_copy_once_used", None)
    if not isinstance(used, set):
        used = set()
        controller._copy_once_used = used
        hooks = getattr(controller, "on_lock", None)
        if isinstance(hooks, list):
            hooks.append(used.clear)
    return used

class SecretService:
    def __init__(self, controller: Any, port: Any, *, hello: Any = None) -> None:
        self._controller = controller
        self._port = port
        self._hello = hello  # the browser host passes Hello wrapped so the vault lock is free while it waits

    # -------------------------------------------------------------- helpers
    def _session_and_lease(self) -> tuple[Any, Any]:
        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        try:
            lease = controller.guard.lease()
            controller.require_lease(lease)
        except StaleSession:
            raise ApiError("session_changed", t(SESSION_CHANGED)) from None
        return controller.session, lease

    def _require(self, lease: Any) -> None:
        try:
            self._controller.require_lease(lease)
        except StaleSession:
            raise ApiError("session_changed", t(SESSION_CHANGED)) from None

    @staticmethod
    def _credential(session: Any, ref: dict[str, Any]) -> dict[str, Any]:
        if ref.get("source") != "credential":
            raise ApiError("not_login", t("secrets.selectALoginBeforeCopying"))
        refuse_travel_hidden(session, ref["id"])
        detail = session.credential_detail(ref["id"])
        if detail is None:
            raise ApiError("not_found", t("share.thisItemNoLongerExists"))
        if not isinstance(detail.get("revision"), int):
            detail.clear()
            raise ApiError("changed", t("secrets.thisCredentialCannotBeVerified"))
        return detail

    def reauthenticate(self, title: str, lease: Any, *, allow_hello: bool = False, fresh: bool = False) -> None:
        """Re-authentication; ``allow_hello`` lets Windows Hello stand in for the master password. Raises when not authorized.

        ``fresh`` always asks (Hello or password) and skips the routine grace another action left: a passkey's
        user-verification flag must come from a check made for that ceremony.
        """
        controller = self._controller
        self._require(lease)
        now = controller._clock()
        if allow_hello:
            stamp, until = controller.routine_reauth
            if not fresh and stamp == controller.guard.stamp() and now < until:
                controller.touch()
                return
            hello = self._hello or getattr(controller, "hello_reauth", None)
            if hello is not None and hello(title, lease):
                self._require(lease)
                controller.touch()
                controller.routine_reauth = (controller.guard.stamp(), now + ROUTINE_REAUTH_GRACE_SECONDS)
                return
        profile = controller.profiles.active_profile()
        # The port hands over a SecretText this method owns: it is wiped however the check ends.
        password = self._port.ask_password(
            title, t("secrets.profileEnterTheMasterPassword", v1=profile.name if profile else ''))
        try:
            self._require(lease)
            if password is None:
                raise ApiError("cancelled", t("error.cancelled"))
            from .factors import YubiKeyFailure, verify_password_with_factors

            try:
                # A v4 vault's key file / YubiKey are the ones the session holds since its unlock; a session
                # opened by Windows Hello, a security key or the camera holds none and asks for them now.
                verify_password_with_factors(controller, controller.session, password)
            except YubiKeyFailure as exc:
                raise exc.api_error() from None
            except (FactorRequired, FactorMismatch) as exc:
                self._port.notify("error", t("unlockMethods.notAuthorized"), str(exc))
                code = "factor_required" if isinstance(exc, FactorRequired) else "factor_mismatch"
                raise ApiError(code, str(exc)) from None
            except (InvalidMasterPassword, VaultError):
                self._port.notify("error", t("unlockMethods.notAuthorized"), t("unlockMethods.masterPasswordDidNotMatch"))
                raise ApiError("not_authorized", t("unlockMethods.masterPasswordDidNotMatch")) from None
        finally:
            if password is not None:
                password.wipe()
        self._require(lease)
        controller.touch()
        if allow_hello:
            controller.routine_reauth = (controller.guard.stamp(), now + ROUTINE_REAUTH_GRACE_SECONDS)

    def _clipboard_result(self, copied: str) -> dict[str, Any]:
        return clipboard_result(copied, self._controller.clipboard)

    def _copy_secret(self, value: str, lease: Any, *, once_id: str | None = None) -> None:
        self._require(lease)
        if once_id is not None:
            # Access rule "copy once": a short clipboard life, and the next copy of this login's secrets in
            # this unlock session asks for the master password (contract 4.1).
            copy_for = getattr(self._controller.clipboard, "copy_for", None)
            if callable(copy_for):
                copy_for(value, COPY_ONCE_SECONDS)
            else:
                self._controller.clipboard.copy(value)
            _copy_once_used(self._controller).add(once_id)
        else:
            self._controller.clipboard.copy(value)
        self._controller.touch()

    def _copy_once_gate(self, ref: dict[str, Any], copy_once: bool, lease: Any) -> bool:
        """Strict re-authentication for a further copy of a "copy once" login; True when the rule applies."""
        if not copy_once:
            return False
        if ref["id"] in _copy_once_used(self._controller):
            self.reauthenticate(t("access.copyAgain"), lease, allow_hello=False)
        return True

    # --------------------------------------------------------------- detail
    def detail(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, _lease = self._session_and_lease()
        refuse_travel_hidden(session, ref["id"])
        summary = next((s for s in session.item_service.all_metadata_summaries() if str(s.id) == ref["id"]), None)
        if summary is None:
            raise ApiError("not_found", t("share.thisItemNoLongerExists"))
        title = _summary_title(summary) or "Untitled"
        subtitle = self._subtitle(session, summary)
        tags = [str(t) for t in getattr(summary, "tags", ()) or ()]
        if ref["source"] == "typed":
            item = session.item_service.get_item(ref["id"]) or {}
            fields = safe_typed_fields(str(summary.kind), item.get("payload"))
            return {"kind": str(summary.kind), "title": title, "subtitle": subtitle,
                    "fields": [list(row) for row in fields], "tags": tags,
                    "favorite": bool(getattr(summary, "favorite", False))}
        detail = self._credential(session, ref)
        try:
            policy = enforced_policy(detail)
            strict = bool(policy.get("require_master_password"))
            scope = detail.get("scope") if isinstance(detail.get("scope"), dict) else {}
            kind = str(detail.get("kind", "web"))
            origin = str(scope.get("origin") or "") if kind == "web" else ""
            target = web_page_address(scope) if kind == "web" else str(scope.get("exe_path") or "")
            return {
                "kind": kind, "title": title, "subtitle": subtitle, "username": str(detail.get("username") or ""),
                "has_password": True, "has_totp": isinstance(detail.get("totp"), dict) and bool(detail["totp"].get("secret")),
                "strict": strict, "notes": None if strict else str(detail.get("notes") or ""),
                "tags": tags, "target": target, "origin": origin or None,
                "favorite": bool(detail.get("favorite")),
                "actions": (["open_website"] if origin else []) + (["fill"] if kind == "desktop" else []) + ["edit"],
            }
        finally:
            detail.clear()

    @staticmethod
    def _subtitle(session: Any, summary: Any) -> str:
        parts = [kind_label(str(summary.kind))]
        ids = tuple(getattr(summary, "collection_ids", ()) or ())
        if ids:
            try:
                names = {str(c.get("id")): display_name(str(c.get("name", "")))
                         for c in visible_collections(session, session.collections.list())}
                if names.get(str(ids[0])):
                    parts.append(names[str(ids[0])])
            except Exception:  # noqa: BLE001
                pass
        updated = int(getattr(summary, "updated_at", 0) or 0)
        if updated:
            parts.append(f"updated {age_text(max(0.0, time.time() - updated))}")
        return " · ".join(parts)

    # --------------------------------------------------------------- reveal
    def reveal_password(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, lease = self._session_and_lease()
        detail = self._credential(session, ref)
        revision = detail["revision"]
        strict = bool(enforced_policy(detail).get("require_master_password"))
        detail.clear()
        self.reauthenticate(t("secrets.confirmToRevealThisPassword"), lease, allow_hello=not strict)
        self._require(lease)
        try:
            password = session.credential_secret(ref["id"], expected_revision=revision)
        except VaultError as exc:
            raise ApiError("changed", str(exc)) from None
        self._controller.touch()
        return {"password": password, "mask_after": REVEAL_SECONDS}

    # ----------------------------------------------------------------- copy
    def copy(self, ref: dict[str, Any], field: str) -> dict[str, Any]:
        if field == "totp":
            return self._copy_totp(ref)
        if field not in ("username", "password"):
            raise ApiError("invalid", t("secrets.unknownField"))
        session, lease = self._session_and_lease()
        detail = self._credential(session, ref)
        revision = detail["revision"]
        rules = enforced_policy(detail)
        strict = bool(rules.get("require_master_password"))
        username = str(detail.get("username") or "")
        detail.clear()
        once = field == "password" and rules.get("copy_once") is True
        if once and ref["id"] in _copy_once_used(self._controller):
            self._copy_once_gate(ref, True, lease)
        elif field == "password" or strict:
            title = t("secrets.confirmToCopyThisPassword") if field == "password" and not strict else t("loginExtras.openSensitiveCredential")
            self.reauthenticate(title, lease, allow_hello=not strict)
        self._require(lease)
        if field == "password":
            try:
                value = session.credential_secret(ref["id"], expected_revision=revision)
            except VaultError as exc:
                raise ApiError("changed", str(exc)) from None
        else:
            again = session.credential_detail(ref["id"]) or {}
            current = again.get("revision")
            again.clear()
            if current != revision:
                raise ApiError("changed", t("secrets.thisCredentialChangedSelectIt"))
            value = username
        if not value:
            raise ApiError("empty", t("secrets.noIsSavedForThis", field=field))
        if once:
            self._copy_secret(value, lease, once_id=ref["id"])
            return {"message": t("access.copyOnceCleared"), "clear_after": COPY_ONCE_SECONDS}
        self._copy_secret(value, lease)
        return self._clipboard_result(f"{field.capitalize()} copied.")

    def _totp_config(self, session: Any, ref: dict[str, Any]) -> tuple[dict[str, Any] | None, bool]:
        config, strict, _once = self._totp_rules(session, ref)
        return config, strict

    def _totp_rules(self, session: Any, ref: dict[str, Any]) -> tuple[dict[str, Any] | None, bool, bool]:
        detail = self._credential(session, ref)
        try:
            totp = detail.get("totp")
            rules = enforced_policy(detail)
            strict = bool(rules.get("require_master_password"))
            return ((dict(totp) if isinstance(totp, dict) and totp.get("secret") else None), strict,
                    rules.get("copy_once") is True)
        finally:
            detail.clear()

    def totp(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, _lease = self._session_and_lease()
        config, strict = self._totp_config(session, ref)
        if config is None:
            raise ApiError("no_totp", t("security.notSetUp"))
        if strict:
            config.clear()
            raise ApiError("strict", t("detailPane.hiddenClick"))
        return live_code(config)

    def _copy_totp(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, lease = self._session_and_lease()
        if ref.get("source") != "credential":
            raise ApiError("not_login", t("secrets.selectALoginBeforeCopying2"))
        config, strict, once = self._totp_rules(session, ref)
        if config is None:
            raise ApiError("no_totp", t("secrets.thisLoginHasNoTwo"))
        try:
            if once and ref["id"] in _copy_once_used(self._controller):
                self._copy_once_gate(ref, True, lease)
            elif strict:
                self.reauthenticate(t("loginExtras.openSensitiveCredential"), lease, allow_hello=False)
            try:
                code, remaining = generate_totp(config["secret"], digits=int(config.get("digits", 6)),
                                                period=int(config.get("period", 30)),
                                                algorithm=str(config.get("algorithm", "SHA1")))
            except (TotpError, ValueError):
                raise ApiError("invalid_totp",
                               t("secrets.theSavedTwoFactorSetup")) from None
        finally:
            config.clear()
        self._copy_secret(code, lease, once_id=ref["id"] if once else None)
        return self._clipboard_result(t("secrets.twoFactorCodeCopiedIt", remaining=remaining))

    # ------------------------------------------------------- item actions
    def set_favorite(self, ref: dict[str, Any], value: bool) -> dict[str, Any]:
        session, lease = self._session_and_lease()
        self._require(lease)
        try:
            if ref["source"] == "typed":
                session.item_service.set_metadata(ref["id"], favorite=bool(value))
            else:
                session.set_favorite(ref["id"], bool(value))
        except VaultError as exc:
            raise ApiError("vault_error", str(exc)) from None
        return {"message": t("secrets.addedToFavorites") if value else t("secrets.removedFromFavorites")}

    def trash(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, lease = self._session_and_lease()
        summary = next((s for s in session.item_service.all_metadata_summaries() if str(s.id) == ref["id"]), None)
        if summary is None:
            raise ApiError("not_found", t("share.thisItemNoLongerExists"))
        name = _summary_title(summary) or t("secrets.thisItem")
        if not self._port.confirm(t("secrets.moveToTrash"),
                                  t("secrets.moveToTheTrashYou", name=name)):
            raise ApiError("cancelled", t("error.cancelled"))
        self._require(lease)
        try:
            if ref["source"] == "typed":
                session.item_service.delete_item(ref["id"])
            else:
                session.delete(ref["id"])
        except VaultError as exc:
            raise ApiError("vault_error", str(exc)) from None
        self._controller.touch()
        return {"message": t("secrets.movedToTrash", name=name), "undo": {"ids": [str(ref["id"])]}}

    def open_website(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, lease = self._session_and_lease()
        detail = self._credential(session, ref)
        try:
            scope = detail.get("scope") if isinstance(detail.get("scope"), dict) else {}
            origin = web_page_address(scope)
        finally:
            detail.clear()
        if not origin:
            raise ApiError("no_website", t("secrets.thisLoginHasNoWebsite"))
        try:
            url = validate_bookmark_url(origin)
        except ValueError as exc:
            raise ApiError("invalid", str(exc)) from None
        if not self._port.confirm(t("secrets.openWebsite"), t(OPEN_WEBSITE_TEXT).format(url=url)):
            raise ApiError("cancelled", t("error.cancelled"))
        self._require(lease)
        webbrowser.open(url)
        return {"message": ""}
