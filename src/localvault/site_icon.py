"""Site icons the browser extension captures: checked and re-encoded as a small PNG before they are saved."""
from __future__ import annotations

import io

MAX_SITE_ICON_DIMENSION = 256


class IconDecodeError(ValueError):
    """Icon bytes are unsupported, malformed, or exceed a processing limit."""


def normalize_site_icon(data: bytes) -> bytes:
    """Check an icon the browser extension captured and re-encode it as a
    small PNG. Raises IconDecodeError for anything unexpected."""
    if not isinstance(data, (bytes, bytearray)) or not data or len(data) > 64 * 1024:
        raise IconDecodeError("Site icon is missing or too large")
    try:
        from PIL import Image
    except Exception as exc:  # pragma: no cover - Pillow ships with the Windows build
        raise IconDecodeError("Image decoding is unavailable") from exc
    try:
        # Only the PNG plugin may parse bytes a web page supplied.
        probe = Image.open(io.BytesIO(bytes(data)), formats=("PNG",))
        if probe.format != "PNG":
            raise IconDecodeError("Site icon must be a PNG image")
        width, height = probe.size
        if not (0 < width <= MAX_SITE_ICON_DIMENSION and 0 < height <= MAX_SITE_ICON_DIMENSION):
            raise IconDecodeError("Site icon dimensions are out of range")
        image = probe.convert("RGBA")
    except IconDecodeError:
        raise
    except Exception as exc:
        raise IconDecodeError("Site icon could not be decoded") from exc
    if image.size != (64, 64):
        resampling = getattr(Image, "Resampling", Image)
        image.thumbnail((64, 64), getattr(resampling, "LANCZOS", 1))
    out = io.BytesIO()
    image.save(out, format="PNG", optimize=True)
    return out.getvalue()
