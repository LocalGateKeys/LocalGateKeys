"""Copy for the passkey approval dialog (save / sign in).

The broker (:mod:`localvault.passkey_broker`, and :mod:`localvault.passkey_system`
for requests from the Windows passkey provider) decides everything; the WebView
page shows this text (``web.ui_port.WebUiPort.ask_passkey``).
"""
from __future__ import annotations

from typing import Any

from .i18n import t
from .passkeys import PasskeyError, _name

BROWSER_LABEL = "Use browser or another device"
CANCEL_LABEL = "Cancel"
CALLER_MAX = 80


def _caller_part(value: Any) -> str:
    """One caller field (image or window title) as a single clean line: a display hint, never policy."""
    if not isinstance(value, str):
        return ""
    try:
        return _name(value[:1024])[:CALLER_MAX]
    except PasskeyError:
        return ""


def caller_label(caller: Any) -> str:
    """``image "title"`` of the app that asked Windows, as the provider reported it ("" when unknown).

    The window title is the calling app's own text (it may read "Site: ..."), so it is quoted, with any double
    quote inside it turned into a single one, and can never pass for one of the dialog's own lines.
    """
    if not isinstance(caller, dict):
        return ""
    image = _caller_part(caller.get("image"))
    title = _caller_part(caller.get("title")).replace('"', "'")
    parts = [part for part in (image, f'"{title}"' if title else "") if part]
    return " ".join(parts)


def dialog_text(mode: str, *, origin: str, rp_id: str, profile_name: str, accounts: list[dict[str, Any]],
                excluded: bool, surface: str = "browser", caller: Any = None,
                top_origin: str | None = None) -> dict[str, str]:
    """Return the dialog copy: title, body and the three button labels.

    ``surface="system"`` is a request from the Windows passkey provider: there
    is no page origin, the body names the calling app instead, and there is no
    "Use browser" button (``browser_label`` is empty).

    ``top_origin`` (a sign-in from a frame of another site; both origins are
    canonical, so neither can add a line) adds one translated line naming the
    frame's site that receives the sign-in and the site in the address bar.
    """
    system = surface == "system"
    if system:
        lines = [f"Site: {rp_id}"]
        app = caller_label(caller)
        if app:
            lines.append(f"App: {app}")
        lines.append(f"Profile: {profile_name}")
    else:
        lines = [f"Site: {rp_id}", f"Page: {origin}", f"Profile: {profile_name}"]
        if top_origin:
            lines.insert(2, t("passkeyModal.shownInside", page=origin, top=top_origin))
    if mode == "create":
        title, approve = "Save a passkey?", "Save in LocalGateKeys"
        user_name = accounts[0].get("user_name") if accounts else ""
        if user_name:
            lines.append(f"Account: {user_name}")
        lines.append("")
        lines.append("The app or website gets a new passkey. Its private key stays in this vault." if system else
                     "The website gets a new passkey. Its private key stays in this vault.")
        if excluded:
            lines.append("This account already has a LocalGateKeys passkey on this site.")
    else:
        title, approve = "Sign in with a passkey?", "Sign in"
        if len(accounts) == 1:
            lines.append(f"Account: {accounts[0].get('title', '')}")
        else:
            lines.append("")
            lines.append("Choose an account:")
    return {"title": title, "body": "\n".join(lines), "approve_label": approve,
            "browser_label": "" if system else BROWSER_LABEL, "cancel_label": CANCEL_LABEL}
