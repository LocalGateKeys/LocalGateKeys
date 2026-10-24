"""Generate every LocalGateKeys icon raster from the vault-dial brand masters.

The vector sources live in ``assets/brand``: ``localgatekeys-icon.svg`` is the
full mark, ``localgatekeys-icon-small.svg`` drops the dial ticks and enlarges
the keyhole so the mark stays legible at tray sizes.  Each SVG is rendered once
to a committed 1024 px PNG master (``--render`` redoes that with headless
Edge or Chrome); everything else is resized from those masters with Pillow, so
the outputs are deterministic and testable without a browser.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "assets" / "brand"
FULL_MASTER = BRAND / "localgatekeys-icon-1024.png"
SMALL_MASTER = BRAND / "localgatekeys-icon-small-1024.png"
# At or below this edge length the small-size master is used.
SMALL_MAX = 36

APP_SIZES = (16, 20, 24, 32, 40, 48, 64, 96, 128, 256)
FIELD_FILL_SIZES = (24, 30, 32, 36, 42, 48, 64, 96, 128)
EXTENSION_SIZES = (16, 32, 48, 128)
LOGO_SIZE = 512

BROWSERS = (
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
)


def icon_image(size: int) -> Image.Image:
    """Return the RGBA icon at ``size`` px from the appropriate master."""
    master = SMALL_MASTER if size <= SMALL_MAX else FULL_MASTER
    with Image.open(master) as source:
        return source.convert("RGBA").resize((size, size), Image.Resampling.LANCZOS)


def _save(image: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, format="PNG", optimize=True)


def render_masters() -> None:
    browser = next((path for path in BROWSERS if path.is_file()), None)
    if browser is None:
        raise SystemExit("--render needs Microsoft Edge or Google Chrome")
    with tempfile.TemporaryDirectory() as profile:
        for svg, png in (
            (BRAND / "localgatekeys-icon.svg", FULL_MASTER),
            (BRAND / "localgatekeys-icon-small.svg", SMALL_MASTER),
        ):
            subprocess.run(
                [
                    str(browser), "--headless=new", "--disable-gpu", "--hide-scrollbars",
                    "--default-background-color=00000000", "--force-device-scale-factor=4",
                    "--window-size=256,256", f"--user-data-dir={profile}",
                    f"--screenshot={png}", svg.resolve().as_uri(),
                ],
                check=True,
                env={**os.environ},
            )


def generate() -> None:
    icons = ROOT / "assets" / "icons"
    for size in APP_SIZES:
        _save(icon_image(size), icons / f"app_{size}.png")
    for size in FIELD_FILL_SIZES:
        _save(icon_image(size), icons / f"field_fill_{size}.png")
    for size in EXTENSION_SIZES:
        _save(icon_image(size), ROOT / "browser-extension" / "icons" / f"icon{size}.png")

    largest, *rest = (icon_image(size) for size in reversed(APP_SIZES))
    largest.save(
        icons / "localgatekeys.ico",
        format="ICO",
        sizes=[(size, size) for size in reversed(APP_SIZES)],
        append_images=rest,
    )

    logo = icon_image(LOGO_SIZE)
    _save(logo, ROOT / "assets" / "localgatekeys-mark.png")
    for copy in (
        ROOT / "assets" / "ui" / "sidebar-v1" / "reference" / "localgatekeys-navigation-logo-master.png",
        ROOT / "docs" / "design" / "sidebar-v1" / "reference" / "localgatekeys-navigation-logo-master.png",
    ):
        shutil.copyfile(ROOT / "assets" / "localgatekeys-mark.png", copy)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--render", action="store_true", help="re-render the 1024 px masters from the SVGs first")
    args = parser.parse_args()
    if args.render:
        render_masters()
    generate()


if __name__ == "__main__":
    main()
