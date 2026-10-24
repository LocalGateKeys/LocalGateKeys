"""Render the MSIX tile and Store logos from the brand icons.

Usage: python scripts/generate_msix_assets.py <output Assets dir> [--qualified]

With ``--qualified`` the files carry MRT scale/target-size qualifiers
(``Square44x44Logo.scale-200.png``) and must be indexed into resources.pri by
makepri; without it each logo is written once under its plain name.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
ICON = ROOT / "assets" / "brand" / "localgatekeys-icon-1024.png"
SMALL_ICON = ROOT / "assets" / "brand" / "localgatekeys-icon-small-1024.png"

# name -> (width, height, source, fraction of the short side the mark fills)
LOGOS = {
    "StoreLogo": (50, 50, ICON, 0.9),
    "Square150x150Logo": (150, 150, ICON, 0.66),
    "Wide310x150Logo": (310, 150, ICON, 0.66),
    "Square44x44Logo": (44, 44, SMALL_ICON, 1.0),
}
SCALES = (100, 125, 150, 200, 400)
# Square44x44Logo is also used, unplated, for taskbar and Start list icons.
TARGET_SIZES = (16, 24, 32, 48, 256)


def render(width: int, height: int, source: Path, fill: float) -> Image.Image:
    canvas = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    side = max(1, round(min(width, height) * fill))
    mark = Image.open(source).convert("RGBA").resize((side, side), Image.Resampling.LANCZOS)
    canvas.alpha_composite(mark, ((width - side) // 2, (height - side) // 2))
    return canvas


def write_assets(directory: Path, *, qualified: bool) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, (width, height, source, fill) in LOGOS.items():
        if not qualified:
            path = directory / f"{name}.png"
            render(width, height, source, fill).save(path)
            written.append(path)
            continue
        for scale in SCALES:
            path = directory / f"{name}.scale-{scale}.png"
            render(round(width * scale / 100), round(height * scale / 100), source, fill).save(path)
            written.append(path)
    if qualified:
        for size in TARGET_SIZES:
            for suffix in ("", "_altform-unplated"):
                path = directory / f"Square44x44Logo.targetsize-{size}{suffix}.png"
                render(size, size, SMALL_ICON, 1.0).save(path)
                written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output", type=Path)
    parser.add_argument("--qualified", action="store_true")
    args = parser.parse_args(argv)
    written = write_assets(args.output, qualified=args.qualified)
    print(f"Wrote {len(written)} MSIX logo files to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
