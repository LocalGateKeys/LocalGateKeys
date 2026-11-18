"""The "LocalGateKeys has moved to the Microsoft Store" notice of the last installer build.

From 0.4.12 on, LocalGateKeys for Windows ships only through the Microsoft
Store. The Inno Setup build gets no more updates, so it tells its users, after
unlock and in Settings, to switch. The vault in ``%LOCALAPPDATA%\\LocalGateKeys``
is not virtualized by the MSIX package (see docs/store/MSIX_FEASIBILITY.md), so
the Store app opens the same vault; the two builds must not be installed at the
same time, hence "uninstall this version first".

Only unpackaged frozen Windows builds (the installer) show it: Store and
sideloaded MSIX builds, and source runs, never do. Showing it uses no network;
"Open Microsoft Store" hands off to the Store app (or the browser), and
LocalGateKeys itself sends nothing.
"""
from __future__ import annotations

import os
import threading
from datetime import UTC, date, datetime, timedelta
from typing import Any, Callable

from .. import distribution
from ..api.result import ApiError
from ..i18n import t

STORE_PRODUCT_ID = "9PNWCNLQ6597"
STORE_APP_URI = f"ms-windows-store://pdp/?ProductId={STORE_PRODUCT_ID}"
STORE_WEB_URL = f"https://apps.microsoft.com/detail/{STORE_PRODUCT_ID}"
SNOOZE_DAYS = 3


def applies() -> bool:
    """Whether this is the installer build (frozen, unpackaged, Windows)."""

    return distribution.is_installer_build()


def snooze_date(today: date | None = None) -> str:
    today = today or datetime.now(UTC).date()
    return (today + timedelta(days=SNOOZE_DAYS)).isoformat()


def _snoozed(until: str, today: date | None = None) -> bool:
    today = today or datetime.now(UTC).date()
    try:
        return today < date.fromisoformat(until)
    except (TypeError, ValueError):
        return False


class StoreMoveService:
    def __init__(self, controller: Any, *, opener: Callable[[str], None] | None = None,
                 is_applicable: Callable[[], bool] = applies) -> None:
        self._controller = controller
        self._opener = opener or getattr(os, "startfile", None)
        self._applies = is_applicable
        self._lock = threading.Lock()

    def available(self) -> bool:
        return self._applies()

    def notice(self) -> dict[str, Any]:
        """After unlock: is the notice due? Shown until the user switches; "Later" hides it for a few days."""

        if not self._applies() or _snoozed(self._controller.settings.store_move_snoozed_until):
            return {"due": False}
        return {"due": True, "title": t("storeMove.title"), "text": t("storeMove.text")}

    def answer(self, open_store: bool) -> dict[str, Any]:
        with self._lock:
            settings = self._controller.settings
            settings.store_move_snoozed_until = snooze_date()
            try:
                settings.save()
            except OSError:
                pass  # a lost snooze only shows the notice again at the next unlock
        return self.open() if open_store else {}

    def open(self) -> dict[str, Any]:
        """Open the LocalGateKeys page in the Store app, or on the web if the Store app is missing."""

        if not self._applies() or self._opener is None:
            raise ApiError("invalid", t("storeMove.notAvailable"))
        for target in (STORE_APP_URI, STORE_WEB_URL):
            try:
                self._opener(target)
                return {}
            except OSError:
                continue
        raise ApiError("invalid", t("storeMove.couldNotOpen", url=STORE_WEB_URL))
