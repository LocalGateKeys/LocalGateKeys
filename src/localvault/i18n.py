"""UI string catalogs: language resolution, lookup, plural rules."""

from __future__ import annotations

import json
import locale
import os
import sys
from pathlib import Path
from typing import Any

SUPPORTED: tuple[str, ...] = ("en", "es", "it", "pl", "zh-Hans", "ja", "de", "pt-BR", "ko", "nl")
PSEUDO = "en-XA"
CATALOG_DIR = Path(__file__).parent / "assets" / "i18n"

_current = "en"
_cache: dict[str, dict[str, Any]] = {}


def dev_enabled() -> bool:
    """The pseudo-locale is offered only in development builds."""
    return os.environ.get("LOCALGATEKEYS_DEV") == "1"


def os_locale() -> str | None:
    """The OS UI locale, e.g. ``de-DE``, or None when unknown."""
    name: str | None = None
    if sys.platform == "win32":
        try:
            import ctypes

            buf = ctypes.create_unicode_buffer(85)
            if ctypes.windll.kernel32.GetUserDefaultLocaleName(buf, 85):
                name = buf.value
        except (AttributeError, OSError):
            name = None
    if not name:
        try:
            name = locale.getlocale()[0]
        except (ValueError, TypeError):
            name = None
    return name.replace("_", "-") if name else None


def resolve(setting: str, os_locale: str | None) -> str:
    """Pick a supported code from the setting, falling back to the OS locale, then en."""
    if setting in SUPPORTED:
        return setting
    if setting == PSEUDO and dev_enabled():
        return PSEUDO
    if not os_locale:
        return "en"
    tag = os_locale.replace("_", "-")
    lang = tag.partition("-")[0]
    lang = lang.lower()
    if lang == "zh":
        return "zh-Hans"
    if lang == "pt":
        return "pt-BR"
    return lang if lang in SUPPORTED else "en"


def set_language(code: str) -> None:
    """Select the active language; LOCALGATEKEYS_LANG overrides it."""
    global _current
    code = os.environ.get("LOCALGATEKEYS_LANG") or code
    _current = code if code in SUPPORTED or code == PSEUDO else "en"


def current() -> str:
    return _current


def _load(code: str) -> dict[str, Any]:
    if code not in _cache:
        try:
            data = json.loads((CATALOG_DIR / f"{code}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        _cache[code] = data if isinstance(data, dict) else {}
    return _cache[code]


def catalog(code: str | None = None) -> dict[str, object]:
    """The catalog for ``code`` merged over English."""
    code = code or _current
    merged = dict(_load("en"))
    if code != "en":
        merged.update(_load(code))
    return merged


def plural_category(code: str, n: int) -> str:
    if code in ("ja", "zh-Hans", "ko"):
        return "other"
    if code == "pl":
        if n == 1:
            return "one"
        if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
            return "few"
        return "many"
    if code == "pt-BR":
        return "one" if n in (0, 1) else "other"
    return "one" if n == 1 else "other"


class _Params(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def t(key: str, **params: Any) -> str:
    value = catalog().get(key)
    if value is None:
        return key
    if isinstance(value, dict):
        try:
            category = plural_category(_current, int(params.get("count", 0)))
        except (TypeError, ValueError):
            category = "other"
        value = value.get(category) or value.get("other") or key
    if not isinstance(value, str):
        return key
    try:
        return value.format_map(_Params(params))
    except (ValueError, IndexError, AttributeError, TypeError, KeyError):
        return value
