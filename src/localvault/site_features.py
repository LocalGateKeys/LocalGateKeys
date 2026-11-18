"""Which sites offer two-factor codes (TOTP) or passkeys, from the bundled ``assets/site_features.json``.

Keys of the data file are registrable domains (see ``origin.base_domain``); ``supports`` reduces any host the same
way before looking it up, so ``login.github.com`` finds ``github.com``.
"""
from __future__ import annotations

import functools
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .origin import OriginError, base_domain

SITE_FEATURES_PATH = Path(__file__).resolve().parent / "assets" / "site_features.json"
FEATURES = ("passkey", "totp")


class SiteFeatures:
    def __init__(self, sites: Mapping[str, Any] | None = None) -> None:
        self._sites: dict[str, frozenset[str]] = {}
        for domain, features in (sites or {}).items():
            if isinstance(domain, str) and isinstance(features, (list, tuple)):
                self._sites[domain.lower()] = frozenset(f for f in features if f in FEATURES)

    def supports(self, host: str, feature: str) -> bool:
        try:
            domain = base_domain(str(host).strip().lower())
        except (OriginError, ValueError):
            return False
        return feature in self._sites.get(domain, frozenset())


def load(path: Path | None = None) -> SiteFeatures:
    """Read the data file; a missing or malformed file gives an empty map (no hints).

    The bundled file never changes while the app runs, so its default load is parsed once.
    """
    return _load_default() if path is None else _read(path)


@functools.lru_cache(maxsize=1)
def _load_default() -> SiteFeatures:
    return _read(SITE_FEATURES_PATH)


def _read(path: Path) -> SiteFeatures:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        sites = data.get("sites") if isinstance(data, dict) else None
    except (OSError, ValueError):
        return SiteFeatures()
    return SiteFeatures(sites if isinstance(sites, dict) else None)


def passkey_domains(session: Any) -> frozenset[str]:
    """Registrable domains that already have a live passkey item."""
    from .item_service import ItemService

    domains: set[str] = set()
    for item in ItemService(session).list_items(kinds=["passkey"]):
        payload = item.get("payload")
        rp_id = str(payload.get("relying_party_id", "")) if isinstance(payload, Mapping) else ""
        if rp_id:
            try:
                domains.add(base_domain(rp_id.strip().lower()))
            except (OriginError, ValueError):
                continue
    return frozenset(domains)


__all__ = ["SiteFeatures", "load", "passkey_domains"]
