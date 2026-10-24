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

from ..access_policy import normalized_policy
from ..api.result import ApiError
from ..item_schema import validate_bookmark_url
from ..session_guard import StaleSession
from ..shell.overview_model import age_text
from ..totp import TotpError, generate_totp
from ..vault import InvalidMasterPassword, VaultError
from .catalog import _summary_title, kind_label
from .presentation import safe_typed_fields
from .setting_links import clipboard_result

ROUTINE_REAUTH_GRACE_SECONDS = 120
REVEAL_SECONDS = 30
SESSION_CHANGED = "Session changed or expired. Action cancelled; unlock and try again."
OPEN_WEBSITE_TEXT = ("This opens the selected URL in your normal browser and may contact the site over the "
                     "network:\n\n{url}\n\nNo background fetch is performed by LocalGateKeys.")


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
        raise ApiError("invalid_totp", "Invalid setup key") from None
    finally:
        config.clear()
    return {"code": _format_code(code), "remaining": remaining, "period": period}


class SecretService:
    def __init__(self, controller: Any, port: Any, *, hello: Any = None) -> None:
        self._controller = controller
        self._port = port
        self._hello = hello  # the browser host passes Hello wrapped so the vault lock is free while it waits

    # -------------------------------------------------------------- helpers
    def _session_and_lease(self) -> tuple[Any, Any]:
        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", "Unlock this profile first.")
        try:
            lease = controller.guard.lease()
            controller.require_lease(lease)
        except StaleSession:
            raise ApiError("session_changed", SESSION_CHANGED) from None
        return controller.session, lease

    def _require(self, lease: Any) -> None:
        try:
            self._controller.require_lease(lease)
        except StaleSession:
            raise ApiError("session_changed", SESSION_CHANGED) from None

    @staticmethod
    def _credential(session: Any, ref: dict[str, Any]) -> dict[str, Any]:
        if ref.get("source") != "credential":
            raise ApiError("not_login", "Select a login before copying credentials.")
        detail = session.credential_detail(ref["id"])
        if detail is None:
            raise ApiError("not_found", "This item no longer exists.")
        if not isinstance(detail.get("revision"), int):
            detail.clear()
            raise ApiError("changed", "This credential cannot be verified. Reopen the vault and try again.")
        return detail

    def reauthenticate(self, title: str, lease: Any, *, allow_hello: bool = False) -> None:
        """Re-authentication; ``allow_hello`` lets Windows Hello stand in for the master password. Raises when not authorized."""
        controller = self._controller
        self._require(lease)
        now = controller._clock()
        if allow_hello:
            stamp, until = controller.routine_reauth
            if stamp == controller.guard.stamp() and now < until:
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
            title, f"Profile: {profile.name if profile else ''}\nEnter the master password again:")
        try:
            self._require(lease)
            if password is None:
                raise ApiError("cancelled", "Cancelled.")
            try:
                controller.session.verify_master_password(password)
            except (InvalidMasterPassword, VaultError):
                self._port.notify("error", "Not authorized", "Master password did not match, or the vault changed.")
                raise ApiError("not_authorized", "Master password did not match, or the vault changed.") from None
        finally:
            if password is not None:
                password.wipe()
        self._require(lease)
        controller.touch()
        if allow_hello:
            controller.routine_reauth = (controller.guard.stamp(), now + ROUTINE_REAUTH_GRACE_SECONDS)

    def _clipboard_result(self, copied: str) -> dict[str, Any]:
        return clipboard_result(copied, self._controller.clipboard)

    def _copy_secret(self, value: str, lease: Any) -> None:
        self._require(lease)
        self._controller.clipboard.copy(value)
        self._controller.touch()

    # --------------------------------------------------------------- detail
    def detail(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, _lease = self._session_and_lease()
        summary = next((s for s in session.item_service.all_metadata_summaries() if str(s.id) == ref["id"]), None)
        if summary is None:
            raise ApiError("not_found", "This item no longer exists.")
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
            policy = normalized_policy(detail.get("policy"))
            strict = bool(policy.get("require_master_password"))
            scope = detail.get("scope") if isinstance(detail.get("scope"), dict) else {}
            kind = str(detail.get("kind", "web"))
            origin = str(scope.get("origin") or "") if kind == "web" else ""
            target = origin if kind == "web" else str(scope.get("exe_path") or "")
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
                names = {str(c.get("id")): str(c.get("name", "")) for c in session.collections.list()}
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
        strict = bool(normalized_policy(detail.get("policy")).get("require_master_password"))
        detail.clear()
        self.reauthenticate("Confirm to reveal this password", lease, allow_hello=not strict)
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
            raise ApiError("invalid", "Unknown field.")
        session, lease = self._session_and_lease()
        detail = self._credential(session, ref)
        revision = detail["revision"]
        strict = bool(normalized_policy(detail.get("policy")).get("require_master_password"))
        username = str(detail.get("username") or "")
        detail.clear()
        if field == "password" or strict:
            title = "Confirm to copy this password" if field == "password" and not strict else "Open sensitive credential"
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
                raise ApiError("changed", "This credential changed. Select it again before copying.")
            value = username
        if not value:
            raise ApiError("empty", f"No {field} is saved for this login.")
        self._copy_secret(value, lease)
        return self._clipboard_result(f"{field.capitalize()} copied.")

    def _totp_config(self, session: Any, ref: dict[str, Any]) -> tuple[dict[str, Any] | None, bool]:
        detail = self._credential(session, ref)
        try:
            totp = detail.get("totp")
            strict = bool(normalized_policy(detail.get("policy")).get("require_master_password"))
            return (dict(totp) if isinstance(totp, dict) and totp.get("secret") else None), strict
        finally:
            detail.clear()

    def totp(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, _lease = self._session_and_lease()
        config, strict = self._totp_config(session, ref)
        if config is None:
            raise ApiError("no_totp", "Not set up")
        if strict:
            config.clear()
            raise ApiError("strict", "Hidden · click to show")
        return live_code(config)

    def _copy_totp(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, lease = self._session_and_lease()
        if ref.get("source") != "credential":
            raise ApiError("not_login", "Select a login before copying its two-factor code.")
        config, strict = self._totp_config(session, ref)
        if config is None:
            raise ApiError("no_totp", "This login has no two-factor setup key saved.")
        try:
            if strict:
                self.reauthenticate("Open sensitive credential", lease, allow_hello=False)
            try:
                code, remaining = generate_totp(config["secret"], digits=int(config.get("digits", 6)),
                                                period=int(config.get("period", 30)),
                                                algorithm=str(config.get("algorithm", "SHA1")))
            except (TotpError, ValueError):
                raise ApiError("invalid_totp",
                               "The saved two-factor setup key is invalid. Open the login to fix it.") from None
        finally:
            config.clear()
        self._copy_secret(code, lease)
        return self._clipboard_result(f"Two-factor code copied; it changes in {remaining}s.")

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
        return {"message": "Added to favorites." if value else "Removed from favorites."}

    def trash(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, lease = self._session_and_lease()
        summary = next((s for s in session.item_service.all_metadata_summaries() if str(s.id) == ref["id"]), None)
        if summary is None:
            raise ApiError("not_found", "This item no longer exists.")
        name = _summary_title(summary) or "this item"
        if not self._port.confirm("Move to trash?",
                                  f"Move {name} to the trash? You can restore it from Trash later."):
            raise ApiError("cancelled", "Cancelled.")
        self._require(lease)
        try:
            if ref["source"] == "typed":
                session.item_service.delete_item(ref["id"])
            else:
                session.delete(ref["id"])
        except VaultError as exc:
            raise ApiError("vault_error", str(exc)) from None
        self._controller.touch()
        return {"message": f"Moved {name} to Trash.", "undo": {"ids": [str(ref["id"])]}}

    def open_website(self, ref: dict[str, Any]) -> dict[str, Any]:
        session, lease = self._session_and_lease()
        detail = self._credential(session, ref)
        try:
            scope = detail.get("scope") if isinstance(detail.get("scope"), dict) else {}
            origin = str(scope.get("origin") or "")
        finally:
            detail.clear()
        if not origin:
            raise ApiError("no_website", "This login has no website address.")
        try:
            url = validate_bookmark_url(origin)
        except ValueError as exc:
            raise ApiError("invalid", str(exc)) from None
        if not self._port.confirm("Open website?", OPEN_WEBSITE_TEXT.format(url=url)):
            raise ApiError("cancelled", "Cancelled.")
        self._require(lease)
        webbrowser.open(url)
        return {"message": ""}
