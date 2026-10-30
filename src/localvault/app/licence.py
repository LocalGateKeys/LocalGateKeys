"""Licence screen and item limit for the WebView UI (``licensing_ui`` and ``pro_gate`` without Tk).

Licences are offline: a pasted ``LGK1-`` key or a ``.lgklicense`` file chosen
in a Python dialog. After unlock, install or removal the vault's encrypted
licence copy is reconciled and the free plan's item limit re-applied.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from .. import licensing
from ..api.result import ApiError
from .licence_view import PRO_PITCH, PURCHASE_URL, install_result_text, licence_view, upgrade_prompt_text
from ..i18n import t

_log = logging.getLogger(__name__)


class LicenceService:
    def __init__(self, controller: Any, port: Any, dialogs: Any) -> None:
        self._controller = controller
        self._port = port
        self._dialogs = dialogs
        # Called after the plan may have changed (unlock, install, remove);
        # device sync starts or stops from here.
        self.on_plan_change: list[Callable[[], None]] = []
        controller.on_unlock.append(self.after_unlock)

    def after_unlock(self) -> None:
        """Restore the licence from the vault copy (or store it there), then apply the item limit."""
        controller = self._controller
        session = controller.session if controller.is_unlocked() else None
        if session is None:
            return  # the licence file is in place; the next unlock reconciles the vault copy
        # Apply the current file's limit before the lease check, so a stale lease
        # never leaves a session unlimited (e.g. after removing the licence).
        self._apply_item_limit(session)
        try:
            controller.require_lease(controller.guard.lease())
        except Exception:  # noqa: BLE001 - locked or replaced meanwhile: write nothing
            return
        try:
            licensing.reconcile_vault_copy(session)
        except Exception:  # noqa: BLE001 - a licence problem never blocks unlock
            _log.warning("Licence vault copy could not be reconciled", exc_info=True)
        # Reconciling may have restored the licence file from the vault copy.
        self._apply_item_limit(session)
        self._plan_changed()

    def _plan_changed(self) -> None:
        for callback in list(self.on_plan_change):
            try:
                callback()
            except Exception:  # noqa: BLE001 - a listener never breaks licensing
                _log.warning("Plan change listener failed", exc_info=True)

    @staticmethod
    def _apply_item_limit(session: Any) -> None:
        """Apply the item limit and the Pro-only features of the current licence."""
        try:
            session.item_limit = licensing.item_limit()
            session.pro_features = licensing.pro_features()
        except Exception:  # noqa: BLE001
            session.item_limit = licensing.FREE_ITEM_LIMIT
            session.pro_features = frozenset()
            _log.warning("Item limit could not be applied", exc_info=True)

    def _count(self) -> int | None:
        controller = self._controller
        if not controller.is_unlocked():
            return None
        try:
            return int(controller.session.live_item_count())
        except Exception:  # noqa: BLE001
            return None

    def view(self) -> dict[str, Any]:
        st = licensing.status()
        view = licence_view(st, self._count())
        headline, body = upgrade_prompt_text(st)
        return {"headline": view.headline, "details": list(view.detail_lines), "can_remove": view.can_remove,
                "warning": view.warning, "pitch": t(PRO_PITCH), "purchase_url": PURCHASE_URL or "",
                "upgrade": {"headline": headline, "body": body}, "pro": st.pro_enabled}

    def install(self, text: str) -> dict[str, Any]:
        text = str(text or "").strip()
        if not text:
            raise ApiError("invalid", t("licencePage.pasteKey"))
        try:
            lic = licensing.install_license(text)
        except licensing.LicenseError as exc:
            raise ApiError("invalid", str(exc)) from None
        except Exception:  # noqa: BLE001
            _log.warning("Licence install failed", exc_info=True)
            raise ApiError("invalid", t("licence.theLicenceCouldNotBe")) from None
        self.after_unlock()
        return {"message": install_result_text(licensing.status(), lic), **self.view()}

    def install_file(self) -> dict[str, Any]:
        path = self._dialogs.open_file(t("licence.openLicenceFile"))
        if not path:
            raise ApiError("cancelled", t("recovery.noFileWasChosen"))
        try:
            with open(path, encoding="utf-8") as handle:
                text = handle.read(65_536)
        except (OSError, UnicodeDecodeError):
            raise ApiError("invalid", t("licence.thatFileCouldNotBe")) from None
        return self.install(text)

    def remove(self) -> dict[str, Any]:
        if not self._port.confirm(t("licencePage.remove"),
                                  t("licence.removeTheLicenceFromThis")):
            raise ApiError("cancelled", t("error.cancelled"))
        try:
            licensing.remove_license()
        except Exception:  # noqa: BLE001
            _log.warning("Licence removal failed", exc_info=True)
            raise ApiError("invalid", t("licence.theLicenceCouldNotBe2")) from None
        self.after_unlock()
        return {"message": t("licence.licenceRemoved"), **self.view()}
