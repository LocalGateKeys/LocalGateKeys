"""Licence and upgrade wording and the licence view-model (no UI toolkit)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .. import licensing
from ..licensing import FREE_ITEM_LIMIT, LicenseStatus

# The Paddle checkout on the website; the "Buy Pro" button stays hidden while empty.
PURCHASE_URL = "https://localgatekeys.app/buy"


PRO_PITCH = ("LocalGateKeys Pro: unlimited items, device sync, two-factor codes and attachments — "
             "US$4.99 once, lifetime updates.")


def limit_headline(limit: int = FREE_ITEM_LIMIT) -> str:
    return f"The free plan holds up to {limit} items."


@dataclass(frozen=True)
class LicenceView:
    headline: str
    detail_lines: tuple[str, ...]
    can_remove: bool
    warning: bool


def _holder_lines(st: LicenseStatus) -> tuple[str, ...]:
    lic = st.license
    if lic is None:
        return ()
    # Paddle's checkout asks for no name, so the name is often the email itself.
    holder = lic.email if lic.name == lic.email else f"{lic.name} ({lic.email})"
    return (f"Licensed to: {holder}",
            f"Updates until: {lic.updates_until.isoformat()}")


def _usage_lines(st: LicenseStatus, item_count: int | None) -> tuple[str, ...]:
    if item_count is None or licensing.item_limit(st) is None:
        return ()
    return (f"Free plan: {item_count} of {FREE_ITEM_LIMIT} items used",)


def licence_view(st: LicenseStatus, item_count: int | None = None) -> LicenceView:
    """Pure description of a licence status for the licence screen.

    *item_count* is the unlocked vault's live item count; states limited to the
    free plan then show how much of it is used.
    """

    holder = _holder_lines(st)
    usage = _usage_lines(st, item_count)
    if st.state == "pro":
        return LicenceView("LocalGateKeys Pro", holder, True, False)
    if st.state == "unconfigured":
        return LicenceView("Pro features are enabled in this build",
                           ("No licence is needed in this build.",),
                           False, False)
    if st.state == "expired_for_this_build":
        return LicenceView(
            "Licence does not cover this version",
            holder + ("This version was released after your updates ended, so Pro is off here; "
                      "an older version, or a licence with newer updates, restores it.",) + usage,
            True, True)
    if st.state == "revoked":
        return LicenceView("Licence revoked",
                           holder + (st.message or "This licence has been revoked.",) + usage, True, True)
    if st.state == "invalid":
        return LicenceView("Licence could not be verified",
                           (st.message or "The installed licence could not be verified.",) + usage,
                           True, True)
    return LicenceView("Free", (usage or (limit_headline(),)) + (PRO_PITCH,), False, False)


_LICENCE_PROBLEM_STATES = ("expired_for_this_build", "revoked", "invalid")


def upgrade_prompt_text(st: LicenseStatus, limit: int = FREE_ITEM_LIMIT) -> tuple[str, str]:
    """Return (headline, body) for the dialog shown when the free item limit is reached.

    When an installed licence is expired, revoked or invalid, say so instead of
    pitching Pro to someone who already bought it.
    """
    if st.state in _LICENCE_PROBLEM_STATES:
        return st.message or limit_headline(limit), (
            f"Pro is off until this is resolved, so the free plan applies: up to {limit} items, and no "
            "device sync or new two-factor codes and attachments. Your vault and data are not affected.")
    return limit_headline(limit), PRO_PITCH


def install_result_text(st: LicenseStatus, lic: licensing.License) -> str:
    """Message shown after a successful install, reflecting the resulting status."""
    if st.state in ("pro", "unconfigured"):
        return f"Licence installed for {lic.name}."
    return f"Licence installed, but Pro is not active. {st.message}"


def pro_required(port: Any, exc: Exception) -> Any:
    """Show the upgrade prompt for a Pro-only feature and return the API error to raise.

    ``exc`` is a ``vault.ProFeatureRequired``; its message already says that
    existing data keeps working.
    """
    from ..api.result import ApiError

    message = str(exc)
    try:
        port.show_upgrade(limit=FREE_ITEM_LIMIT, message=message, on_enter=lambda: None)
    except Exception:  # noqa: BLE001, S110 - the error below still tells the user
        pass
    return ApiError("pro_required", message)
