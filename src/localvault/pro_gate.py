"""Free plan item limit and licence wiring shared by the UI entry points.

Legacy Tk-era wiring; the WebView app applies the item limit and the Pro-only
features (sync, two-factor codes, attachments) in ``app/licence.py``.  The free
plan limits how many live items a vault holds. ``VaultSession.item_limit`` carries that limit and the vault refuses new
items with ``ItemLimitReached``; this mixin keeps the limit in step with the
licence and turns a refusal into the upgrade dialog.
"""
from __future__ import annotations

import logging

from . import licensing
from .app.ui_port import UiPortHost, ui_port_of
from .vault import ItemLimitReached

_log = logging.getLogger(__name__)


class ProGateMixin(UiPortHost):
    # --- licence <-> vault ----------------------------------------------------------------

    def _apply_item_limit(self) -> None:
        """Set the unlocked session's item limit from the current licence."""
        session = getattr(self, "session", None)
        if session is None:
            return
        session.item_limit = licensing.item_limit()

    def _licence_after_unlock(self) -> None:
        """Restore the licence from the vault copy (or store it there), then apply the limit.

        A licence problem never blocks unlock: failures are logged and the limit
        still comes from whatever licence status is readable.
        """
        session = getattr(self, "session", None)
        if session is None:
            return
        try:
            licensing.reconcile_vault_copy(session)
        except Exception:
            _log.warning("Licence vault copy could not be reconciled", exc_info=True)
        self._apply_item_limit()

    def _licence_changed(self) -> None:
        """After a licence install or removal: sync the vault copy when unlocked, refresh the status."""
        session = getattr(self, "session", None)
        if session is not None and getattr(session, "is_unlocked", False):
            self._licence_after_unlock()
        refresh = getattr(self, "_refresh_licence_status", None)
        if refresh is not None:
            refresh()

    # --- item limit -----------------------------------------------------------------------

    def _item_slot_available(self) -> bool:
        """Pre-check before starting a create flow; shows the upgrade dialog when full."""
        session = getattr(self, "session", None)
        limit = getattr(session, "item_limit", None)
        if session is None or limit is None:
            return True
        try:
            count = int(session.live_item_count())
        except Exception:
            return True  # the vault re-checks on create
        if count < limit:
            return True
        self._handle_item_limit(ItemLimitReached(limit, count))
        return False

    def _handle_item_limit(self, exc: ItemLimitReached) -> None:
        status_var = getattr(self, "status_var", None)
        if status_var is not None:
            try:
                status_var.set(str(exc))
            except Exception:
                _log.debug("Status line unavailable", exc_info=True)
        try:
            self._show_upgrade_prompt(exc)
        except Exception:
            _log.warning("Could not show the upgrade prompt", exc_info=True)

    def _show_upgrade_prompt(self, exc: ItemLimitReached) -> None:
        ui_port_of(self).show_upgrade(limit=exc.limit, message=str(exc), on_enter=self.licence_clicked)
