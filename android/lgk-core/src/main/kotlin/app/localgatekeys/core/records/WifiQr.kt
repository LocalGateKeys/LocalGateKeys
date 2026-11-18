package app.localgatekeys.core.records

/**
 * Wi-Fi network QR text, the ZXing "WIFI:" format
 * (https://github.com/zxing/zxing/wiki/Barcode-Contents#wi-fi-network-config-android-ios-11).
 * Mirror of Python `wifi_qr.wifi_qr_text` and Swift `WifiQR`; vectors in `tests/vectors/wifi_qr/cases.json`.
 */
object WifiQr {
    /**
     * QR payload for a Wi-Fi item, or null for types a plain QR cannot express (enterprise, unknown). [security] is the
     * item's raw value (`none`, `wep`, `wpa`, `wpa2`, `wpa3`, ...).
     */
    fun text(ssid: String, password: String, security: String, hidden: Boolean): String? {
        val kind = when (security) {
            "none" -> "nopass"
            "wep" -> "WEP"
            "wpa", "wpa2", "wpa3" -> "WPA"
            else -> return null
        }
        return buildString {
            append("WIFI:T:").append(kind).append(";S:").append(escape(ssid)).append(';')
            if (kind != "nopass") append("P:").append(escape(password)).append(';')
            if (hidden) append("H:true;")
            append(';')
        }
    }

    /** Backslash-escapes `\ ; , : "` (the backslash first, so it is not escaped twice). */
    private fun escape(value: String): String = buildString {
        for (ch in value) {
            if (ch == '\\' || ch == ';' || ch == ',' || ch == ':' || ch == '"') append('\\')
            append(ch)
        }
    }
}
