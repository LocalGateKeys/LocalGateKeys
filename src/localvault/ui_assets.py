from __future__ import annotations

import ctypes
import sys
from functools import cache
from pathlib import Path

APP_NAME = "LocalGateKeys"
SLOGAN = "YOUR KEYS. YOUR CONTROL."
BRAND_DESCRIPTOR = "PRIVATE  |  SECURE  |  YOURS"
BADGE_CAPTION = "Secrets stay in the encrypted vault on this PC."

ASSET_DIR = Path(__file__).resolve().parent / "assets"
WORDMARK_ASSET = "localgatekeys_wordmark.png"
MARK_ASSET = "localgatekeys_mark.png"
BADGE_ASSET = "local_encrypted_badge.png"


def asset_root() -> Path:
    """Return the repository/frozen root containing the top-level assets."""

    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        return Path(frozen_root) / "assets"
    return Path(__file__).resolve().parents[2] / "assets"


def sidebar_asset_path(relative_name: str) -> Path:
    """Resolve one canonical sidebar-v1 asset in source or frozen builds."""

    bundle_root = asset_root() / "ui" / "sidebar-v1"
    candidate = (bundle_root / relative_name).resolve()
    try:
        candidate.relative_to(bundle_root.resolve())
    except ValueError as exc:
        raise ValueError("sidebar asset path must stay within the sidebar-v1 bundle") from exc
    return candidate


def sidebar_logo_path() -> Path:
    """Return the byte-identical 512x512 sidebar logo master path."""

    return sidebar_asset_path("reference/localgatekeys-navigation-logo-master.png")


def asset_path(name: str) -> Path:
    return ASSET_DIR / name


def enable_dpi_awareness() -> bool:
    """Make the Windows process system-DPI-aware before creating any Tk root.

    The desktop executable also embeds the matching manifest. This runtime
    path covers source runs and launchers that import ``agent.main`` directly.
    System awareness keeps Tk's existing monitor scale and point-size behavior
    on the primary monitor while preventing Windows from bitmap-stretching the
    complete application window.
    """

    if sys.platform != "win32":
        return False

    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        is_aware = user32.IsProcessDPIAware
        is_aware.argtypes = ()
        is_aware.restype = ctypes.c_bool
        if is_aware():
            return True
        set_legacy = user32.SetProcessDPIAware
        set_legacy.argtypes = ()
        set_legacy.restype = ctypes.c_bool
        return bool(set_legacy())
    except (AttributeError, OSError, TypeError):
        return False


@cache
def _load_pil_source(name: str):
    from PIL import Image

    return Image.open(asset_path(name)).convert("RGBA")


def load_pil_asset(name: str, size: tuple[int, int] | None = None):
    image = _load_pil_source(name).copy()
    if size is not None:
        image.thumbnail(size)
    return image

