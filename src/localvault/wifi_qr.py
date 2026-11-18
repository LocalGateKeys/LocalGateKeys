"""Wi-Fi network QR text (ZXing "WIFI:" format).

Reference: https://github.com/zxing/zxing/wiki/Barcode-Contents#wi-fi-network-config-android-ios-11
Vectors shared with Swift and Kotlin: tests/vectors/wifi_qr/cases.json.
"""
from __future__ import annotations

_T_FOR_SECURITY = {"none": "nopass", "wep": "WEP", "wpa": "WPA", "wpa2": "WPA", "wpa3": "WPA"}


def _escape(value: str) -> str:
    # Backslash first, then the other specials; per the ZXing format they are \ ; , : "
    out = value.replace("\\", "\\\\")
    for ch in (";", ",", ":", '"'):
        out = out.replace(ch, "\\" + ch)
    return out


def wifi_qr_text(ssid: str, password: str, security: str, hidden: bool) -> str | None:
    """QR payload for a Wi-Fi network, or None for types a plain QR cannot express (enterprise, unknown)."""
    kind = _T_FOR_SECURITY.get(security)
    if kind is None:
        return None
    text = f"WIFI:T:{kind};S:{_escape(ssid)};"
    if kind != "nopass":
        text += f"P:{_escape(password)};"
    if hidden:
        text += "H:true;"
    return text + ";"
