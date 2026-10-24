"""Copy for the passkey approval dialog (save / sign in).

The broker (:mod:`localvault.passkey_broker`) decides everything; the WebView
page shows this text (``web.ui_port.WebUiPort.ask_passkey``).
"""
from __future__ import annotations

from typing import Any

BROWSER_LABEL = "Use browser or another device"
CANCEL_LABEL = "Cancel"


def dialog_text(mode: str, *, origin: str, rp_id: str, profile_name: str, accounts: list[dict[str, Any]],
                excluded: bool) -> dict[str, str]:
    """Return the dialog copy: title, body and the three button labels."""
    lines = [f"Site: {rp_id}", f"Page: {origin}", f"Profile: {profile_name}"]
    if mode == "create":
        title, approve = "Save a passkey?", "Save in LocalGateKeys"
        user_name = accounts[0].get("user_name") if accounts else ""
        if user_name:
            lines.append(f"Account: {user_name}")
        lines.append("")
        lines.append("The website gets a new passkey. Its private key stays in this vault.")
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
            "browser_label": BROWSER_LABEL, "cancel_label": CANCEL_LABEL}
