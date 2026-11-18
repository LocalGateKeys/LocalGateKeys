"""Privacy proof page (feature pack 2026-11-15, section 5): facts, claims and the network ledger.

The document is built from secret-free facts and ``net_ledger.view()`` and signed with the sync device
identity's Ed25519 key when sync is set up (``privacy_proof.sign``); otherwise it is unsigned.  No new key
is ever created here.
"""
from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import privacy_proof
from ..api.result import ApiError
from ..i18n import t
from ..version import APP_VERSION

# Claims Windows has guard tests for (contract 5.1).  ``breach_prefix_only`` is left out: no test in
# tests/ asserts that only the 5-character hash prefix is sent.
CLAIMS = ("connections_listed", "no_item_content_sent")


def _iso(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class PrivacyProofService:
    def __init__(self, controller: Any, port: Any, dialogs: Any) -> None:
        self._controller = controller
        self._port = port
        self._dialogs = dialogs

    def _session(self) -> Any:
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        self._controller.require_lease(self._controller.guard.lease())
        return self._controller.session

    # ------------------------------------------------------------------ facts
    @staticmethod
    def _sync_state(session: Any) -> Any:
        from ..sync.vault_bridge import load_sync_state

        try:
            return load_sync_state(session)
        except Exception:  # noqa: BLE001 - a malformed state is reported as sync off, never signed
            return None

    @staticmethod
    def _items(session: Any) -> int:
        """Live logins and items the user can see: travel-hidden ones are not counted (finding W-L7)."""
        from ..travel import hidden_id_set

        ids: list[str] = []
        try:
            ids += [str(entry.get("id")) for entry in session.all_entries()]
        except Exception:  # noqa: BLE001, S110 - a count that cannot be read is left out
            pass
        try:
            ids += [str(item.get("id")) for item in session.items.list_items()]
        except Exception:  # noqa: BLE001, S110 - a count that cannot be read is left out
            pass
        hidden = hidden_id_set(session)
        return sum(1 for item_id in ids if item_id not in hidden)

    @staticmethod
    def _shares(session: Any) -> int:
        try:
            from ..sync.share_group import list_share_groups

            return len(list_share_groups(session))
        except Exception:  # noqa: BLE001, S110 - a count that cannot be read is left out
            return 0

    def _facts(self, session: Any, state: Any) -> dict[str, Any]:
        settings = self._controller.settings
        sync, devices = "off", 0
        if state is not None:
            folder = bool(getattr(state, "folder_path", None))
            # A removed Wi-Fi peer stays listed as revoked (its id stays reserved): not a device.
            lan = tuple(p for p in getattr(state, "lan_peers", ()) or ()
                        if not (isinstance(p, dict) and p.get("revoked") is True))
            sync = "both" if folder and lan else "folder" if folder else "wifi" if lan else "off"
            own = str((getattr(state, "device_identity", None) or {}).get("device_id", ""))
            peers = {str(m) for m in getattr(state, "members", ()) or ()}
            peers |= {str(p.get("device_id")) for p in lan if isinstance(p, dict) and p.get("device_id")}
            peers.discard(own)
            devices = len(peers)
        strict = bool(getattr(settings, "strict_offline_mode", True))
        return {"sync": sync, "devices": devices, "shares": self._shares(session), "items": self._items(session),
                "breach_checks": bool(getattr(settings, "breach_check_enabled", False)),
                "strict_offline": strict,
                # Update checks only run when the user asks; strict offline mode blocks them without a confirm.
                "update_check": not strict}

    @staticmethod
    def _network() -> dict[str, Any]:
        from .. import net_ledger

        view = net_ledger.view()
        entries, counts, oldest = [], {}, None
        for row in view.get("entries") or []:
            at = _iso(row.get("at"))
            purpose = str(row.get("purpose", ""))[:300]
            if at is None:
                continue
            oldest = at if oldest is None or at < oldest else oldest
            if purpose in net_ledger.SITE_PURPOSES or purpose in net_ledger.LOCAL_PURPOSES:
                # Website icons and LAN peers: counts only, never a site host or an address.
                counts[purpose[:64]] = counts.get(purpose[:64], 0) + int(row.get("count", 1) or 1)
            elif len(entries) < 1000:
                entries.append({"purpose": purpose, "host": str(row.get("host", ""))[:300],
                                "result": str(row.get("result", ""))[:300], "at": at})
        for row in view.get("earlier") or []:
            purpose = str(row.get("purpose", ""))[:64]
            counts[purpose] = counts.get(purpose, 0) + int(row.get("count", 0) or 0)
        return {"available": True, "since": oldest, "entries": entries, "counts": counts}

    # --------------------------------------------------------------- document
    def _build(self) -> tuple[dict[str, Any], str | None]:
        session = self._session()
        state = self._sync_state(session)
        document: dict[str, Any] = {
            "format": privacy_proof.FORMAT, "version": privacy_proof.VERSION, "generated_at": _now(),
            "app": {"platform": "windows", "version": APP_VERSION},
            "facts": self._facts(session, state), "claims": list(CLAIMS),
            "network": self._network(), "signature": None,
        }
        identity = getattr(state, "device_identity", None) if state is not None else None
        if identity:
            try:
                raw = base64.b64decode(str(identity["signing_private"]), validate=True)
                document = privacy_proof.sign(document, raw, str(identity["device_id"]))
            except Exception:  # noqa: BLE001 - never invent a key: leave it unsigned
                document["signature"] = None
        fingerprint = None
        if document["signature"] is not None:
            fingerprint = privacy_proof.fingerprint(base64.b64decode(document["signature"]["public_key"]))
        return document, fingerprint

    def get(self) -> dict[str, Any]:
        document, fingerprint = self._build()
        since = document["network"]["since"]
        date = since[:10] if since else document["generated_at"][:10]
        return {"document": document, "signed": document["signature"] is not None, "fingerprint": fingerprint,
                "since": since,
                "claims": [{"id": c, "text": t(f"privacy.claim.{c}", date=date)} for c in document["claims"]]}

    def export(self) -> dict[str, Any]:
        document, fingerprint = self._build()
        default = privacy_proof.file_name(datetime.now().strftime("%Y-%m-%d"))
        target = self._dialogs.save_file(t("privacy.export"), default)
        if not target:
            raise ApiError("cancelled", t("error.cancelled"))
        path = Path(target)
        path.write_bytes(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n")
        return {"path": str(path), "file_name": path.name, "signed": document["signature"] is not None,
                "fingerprint": fingerprint, "message": t("privacy.exported", file=path.name)}


__all__ = ["CLAIMS", "PrivacyProofService"]
