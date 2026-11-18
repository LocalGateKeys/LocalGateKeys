"""Writes the Android logo vector drawables from the website logo (website/public/brand/icon.svg).

    .venv/Scripts/python.exe scripts/make_android_brand.py

Outputs (overwritten, deterministic):
  android/app/src/main/res/drawable/brand_mark.xml          the whole tile (unlock screen, privacy cover, Pro sheet)
  android/app/src/main/res/drawable/ic_launcher_background.xml   the tile's gradient, full bleed
  android/app/src/main/res/drawable/ic_launcher_foreground.xml   ring, face and keyhole inside the 66 dp safe zone

VectorDrawable has no stroke-dasharray, transforms on gradients or objectBoundingBox units, so the SVG's geometry is
written out here in plain viewport coordinates. If icon.svg changes, update the numbers below.
"""

from __future__ import annotations

import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "android" / "app" / "src" / "main" / "res" / "drawable"

C = 128.0  # centre of the 256 x 256 logo
RING_R, RING_W = 84.0, 28.0
FACE_R = 62.0
# The arc: stroke-dasharray "180 400" on the r=84 circle, rotated -200 degrees. A circle's stroke starts at 3 o'clock
# and runs clockwise, so the dash covers 160 deg .. 160 + 180/84 rad.
ARC_START = math.radians(-200.0) % (2 * math.pi)
ARC_SPAN = 180.0 / RING_R


def n(v: float) -> str:
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s == "-0" else s


def circle(cx: float, cy: float, r: float) -> str:
    return f"M{n(cx - r)},{n(cy)} a{n(r)},{n(r)} 0 1,0 {n(2 * r)},0 a{n(r)},{n(r)} 0 1,0 {n(-2 * r)},0 Z"


def rounded_rect(x: float, y: float, size: float, r: float) -> str:
    e = x + size
    b = y + size
    return (
        f"M{n(x + r)},{n(y)} H{n(e - r)} A{n(r)},{n(r)} 0 0,1 {n(e)},{n(y + r)} V{n(b - r)} "
        f"A{n(r)},{n(r)} 0 0,1 {n(e - r)},{n(b)} H{n(x + r)} A{n(r)},{n(r)} 0 0,1 {n(x)},{n(b - r)} "
        f"V{n(y + r)} A{n(r)},{n(r)} 0 0,1 {n(x + r)},{n(y)} Z"
    )


def rotate(dx: float, dy: float, deg: float) -> tuple[float, float]:
    a = math.radians(deg)
    return dx * math.cos(a) - dy * math.sin(a), dx * math.sin(a) + dy * math.cos(a)


def linear(sx: float, sy: float, ex: float, ey: float, stops: list[tuple[float, str]]) -> str:
    items = "".join(f'\n                    <item android:offset="{n(o)}" android:color="{c}" />' for o, c in stops)
    return (
        f'\n            <aapt:attr name="{{attr}}">\n                <gradient android:type="linear" '
        f'android:startX="{n(sx)}" android:startY="{n(sy)}" android:endX="{n(ex)}" android:endY="{n(ey)}">'
        f"{items}\n                </gradient>\n            </aapt:attr>"
    )


def radial(cx: float, cy: float, r: float, stops: list[tuple[float, str]]) -> str:
    items = "".join(f'\n                    <item android:offset="{n(o)}" android:color="{c}" />' for o, c in stops)
    return (
        f'\n            <aapt:attr name="{{attr}}">\n                <gradient android:type="radial" '
        f'android:centerX="{n(cx)}" android:centerY="{n(cy)}" android:gradientRadius="{n(r)}">'
        f"{items}\n                </gradient>\n            </aapt:attr>"
    )


TILE_STOPS = [(0, "#FF173A6E"), (1, "#FF050B18")]
ARC_STOPS = [(0, "#FF67E8F9"), (0.55, "#FF3B82F6"), (1, "#FF1D3FBF")]
FACE_STOPS = [(0, "#FF2A4E8C"), (1, "#FF0A1630")]


def path(d: str, *, fill: str | None = None, stroke: str | None = None, width: float = 0, cap: str = "") -> str:
    attrs = [f'android:pathData="{d}"']
    body = ""
    if fill and fill.startswith("#"):
        attrs.append(f'android:fillColor="{fill}"')
    elif fill:
        body += fill.replace("{attr}", "android:fillColor")
    if stroke and stroke.startswith("#"):
        attrs.append(f'android:strokeColor="{stroke}"')
    elif stroke:
        body += stroke.replace("{attr}", "android:strokeColor")
    if stroke:
        attrs.append(f'android:strokeWidth="{n(width)}"')
    if cap:
        attrs.append(f'android:strokeLineCap="{cap}"')
    head = "    <path\n        " + "\n        ".join(attrs)
    return head + (">" + body + "\n    </path>\n" if body else " />\n")


def dial(o: float) -> str:
    """Ring, arc, face and keyhole, shifted by o in both directions."""
    cx = cy = C + o
    # Arc gradient: objectBoundingBox (0,0)-(1,1) of the r=84 circle, then the circle's -200 degree rotation.
    gx0, gy0 = rotate(-RING_R, -RING_R, -200)
    gx1, gy1 = rotate(RING_R, RING_R, -200)
    a0, a1 = ARC_START, ARC_START + ARC_SPAN
    p0 = (cx + RING_R * math.cos(a0), cy + RING_R * math.sin(a0))
    p1 = (cx + RING_R * math.cos(a1), cy + RING_R * math.sin(a1))
    arc = f"M{n(p0[0])},{n(p0[1])} A{n(RING_R)},{n(RING_R)} 0 0,1 {n(p1[0])},{n(p1[1])}"
    face_box = cx - FACE_R  # radial cx .4, cy .35, r .75 of the face's bounding box
    # Keyhole: translate(128 125) scale(.48) of a circle (0,-36) r40 and the trapezoid (-24,-8) (24,-8) (40,94) (-40,94).
    k = 0.48
    kx, ky = cx, 125.0 + o

    def kp(x: float, y: float) -> str:
        return f"{n(kx + k * x)},{n(ky + k * y)}"

    return (
        path(circle(cx, cy, RING_R), stroke="#FF1B3566", width=RING_W)
        + path(arc, stroke=linear(cx + gx0, cy + gy0, cx + gx1, cy + gy1, ARC_STOPS), width=RING_W, cap="round")
        + path(circle(cx, cy, FACE_R), fill=radial(face_box + 0.4 * 2 * FACE_R, face_box + 0.35 * 2 * FACE_R, 0.75 * 2 * FACE_R, FACE_STOPS))
        + path(circle(kx, ky + k * -36, k * 40), fill="#FFF4F8FF")
        + path(f"M{kp(-24, -8)} L{kp(24, -8)} L{kp(40, 94)} L{kp(-40, 94)} Z", fill="#FFF4F8FF")
    )


def vector(size_dp: float, viewport: float, body: str) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<!-- Generated by scripts/make_android_brand.py from website/public/brand/icon.svg. Do not edit. -->\n"
        '<vector xmlns:android="http://schemas.android.com/apk/res/android"\n'
        '    xmlns:aapt="http://schemas.android.com/aapt"\n'
        f'    android:width="{n(size_dp)}dp"\n    android:height="{n(size_dp)}dp"\n'
        f'    android:viewportWidth="{n(viewport)}"\n    android:viewportHeight="{n(viewport)}">\n'
        + body
        + "</vector>\n"
    )


def brand_mark() -> str:
    body = (
        path(rounded_rect(0, 0, 256, 58), fill=linear(0, 0, 256, 256, TILE_STOPS))
        + path(rounded_rect(1.5, 1.5, 253, 56.5), stroke="#17FFFFFF", width=3)
        + dial(0)
    )
    return vector(256, 256, body)


# Adaptive icon: 108 dp, the launcher masks it and shows the middle 72 dp; the logo keeps to the 66 dp safe zone.
# The ring's outer diameter (2 * (84 + 14) = 196 logo units) becomes 52 dp, so the viewport is 196 * 108 / 52.
FG_VIEWPORT = round(196 * 108 / 52)
FG_OFFSET = (FG_VIEWPORT - 256) / 2


def launcher_foreground() -> str:
    return vector(108, FG_VIEWPORT, dial(FG_OFFSET))


def launcher_background() -> str:
    return vector(108, 108, path("M0,0 H108 V108 H0 Z", fill=linear(0, 0, 108, 108, TILE_STOPS)))


def main() -> None:
    RES.mkdir(parents=True, exist_ok=True)
    for name, text in (
        ("brand_mark.xml", brand_mark()),
        ("ic_launcher_foreground.xml", launcher_foreground()),
        ("ic_launcher_background.xml", launcher_background()),
    ):
        (RES / name).write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {RES / name}")


if __name__ == "__main__":
    main()
