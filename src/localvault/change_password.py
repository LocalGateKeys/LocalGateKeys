"""Password change assistant (sub-plan 12, Task 2): where to send the user to change a password.

Only builds a URL for the browser to open. Nothing here fetches or automates a third-party site: the
``/.well-known/change-password`` path (W3C "A Well-Known URL for Changing Passwords") is checked only by opening it,
and a site that lacks it redirects or shows its own page.

Order: a curated override (``assets/change_urls.json``, source ``"site-features"``), then the well-known URL of an
https origin (``"well-known"``), then the item's login URL with a note (``"login-url"``). ``("", "login-url")``
means there is nothing to open; the UI disables the action instead of opening a dead link.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CHANGE_URLS_PATH = Path(__file__).resolve().parent / "assets" / "change_urls.json"
WELL_KNOWN_PATH = "/.well-known/change-password"
SOURCES = ("well-known", "site-features", "login-url")


@lru_cache(maxsize=1)
def _overrides() -> dict[str, str]:
    try:
        raw = json.loads(CHANGE_URLS_PATH.read_text(encoding="utf-8"))
        sites = raw.get("sites", {})
        return {str(k).lower(): str(v) for k, v in sites.items()
                if isinstance(v, str) and v.startswith("https://")}
    except (OSError, ValueError, AttributeError):
        return {}


def _field(entry: Any, name: str) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def _urls(entry: Any) -> list[str]:
    found: list[str] = []
    for name in ("origin", "url", "login_url"):
        value = _field(entry, name)
        if isinstance(value, str) and value.strip():
            found.append(value.strip())
    scope = _field(entry, "scope")
    if isinstance(scope, Mapping):
        for value in [scope.get("origin"), *(scope.get("urls") or [])]:
            text = value.get("url") if isinstance(value, Mapping) else value
            if isinstance(text, str) and text.strip():
                found.append(text.strip())
    return found


def _https_origin(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if parts.scheme != "https" or not parts.hostname:
        return ""
    port = f":{parts.port}" if parts.port and parts.port != 443 else ""
    return f"https://{parts.hostname.lower()}{port}"


def _override(host: str) -> str:
    table = _overrides()
    labels = host.split(".")
    for n in range(len(labels) - 1):
        hit = table.get(".".join(labels[n:]))
        if hit:
            return hit
    return ""


def change_url(entry: Any) -> tuple[str, str]:
    """``(url, source)`` for the item's change-password page; ``source`` is one of ``SOURCES``."""
    urls = _urls(entry)
    for url in urls:
        origin = _https_origin(url)
        if origin:
            hit = _override(urlsplit(origin).hostname or "")
            if hit:
                return hit, "site-features"
            return origin + WELL_KNOWN_PATH, "well-known"
    for url in urls:
        if urlsplit(url).scheme in ("http", "https"):
            return url, "login-url"
    return "", "login-url"
