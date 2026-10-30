"""Licence and upgrade wording and the licence view-model (no UI toolkit)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .. import licensing
from ..licensing import FREE_ITEM_LIMIT, LicenseStatus
from ..i18n import t

# The Paddle checkout on the website; the "Buy Pro" button stays hidden while empty.
PURCHASE_URL = "https://localgatekeys.app/buy"


PRO_PITCH = ("licenceView.localgatekeysProUnlimitedItemsDevice")


def limit_headline(limit: int = FREE_ITEM_LIMIT) -> str:
    return t("licenceView.theFreePlanHoldsUp", limit=limit)


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
    return (t("licenceView.licensedTo", holder=holder),
            t("licenceView.updatesUntil", v1=lic.updates_until.isoformat()))


def _usage_lines(st: LicenseStatus, item_count: int | None) -> tuple[str, ...]:
    if item_count is None or licensing.item_limit(st) is None:
        return ()
    return (t("licenceView.freePlanOfItemsUsed", item_count=item_count, FREE_ITEM_LIMIT=FREE_ITEM_LIMIT),)


def licence_view(st: LicenseStatus, item_count: int | None = None) -> LicenceView:
    """Pure description of a licence status for the licence screen.

    *item_count* is the unlocked vault's live item count; states limited to the
    free plan then show how much of it is used.
    """

    holder = _holder_lines(st)
    usage = _usage_lines(st, item_count)
    if st.state == "pro":
        return LicenceView(t("licenceView.localgatekeysPro"), holder, True, False)
    if st.state == "unconfigured":
        return LicenceView(t("licenceView.proFeaturesAreEnabledIn"),
                           (t("licenceView.noLicenceIsNeededIn"),),
                           False, False)
    if st.state == "expired_for_this_build":
        return LicenceView(
            t("status.licence.expiredBuild"),
            holder + (t("licenceView.thisVersionWasReleasedAfter"),) + usage,
            True, True)
    if st.state == "revoked":
        return LicenceView(t("status.licence.revoked"),
                           holder + (st.message or t("licenceView.thisLicenceHasBeenRevoked"),) + usage, True, True)
    if st.state == "invalid":
        return LicenceView(t("licenceView.licenceCouldNotBeVerified"),
                           (st.message or t("licenceView.theInstalledLicenceCouldNot"),) + usage,
                           True, True)
    return LicenceView(t("licenceView.free"), (usage or (limit_headline(),)) + (t(PRO_PITCH),), False, False)


_LICENCE_PROBLEM_STATES = ("expired_for_this_build", "revoked", "invalid")


def upgrade_prompt_text(st: LicenseStatus, limit: int = FREE_ITEM_LIMIT) -> tuple[str, str]:
    """Return (headline, body) for the dialog shown when the free item limit is reached.

    When an installed licence is expired, revoked or invalid, say so instead of
    pitching Pro to someone who already bought it.
    """
    if st.state in _LICENCE_PROBLEM_STATES:
        return st.message or limit_headline(limit), (
            t("licenceView.proIsOffUntilThis", limit=limit))
    return limit_headline(limit), t(PRO_PITCH)


def install_result_text(st: LicenseStatus, lic: licensing.License) -> str:
    """Message shown after a successful install, reflecting the resulting status."""
    if st.state in ("pro", "unconfigured"):
        return t("licenceView.licenceInstalledFor", name=lic.name)
    return t("licenceView.licenceInstalledButProIs", message=st.message)


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
