package app.localgatekeys.android.editor

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt

/** Wi-Fi security choices as people read them (`EditorKind.choiceLabel` in the iPhone editor; Task 8's EditorKind uses this). */
object WifiSecurity {
    fun label(value: String, t: Txt): String = when (value) {
        "none" -> t.s(R.string.wifi_security_none)
        "wep" -> "WEP"
        "wpa" -> "WPA"
        "wpa2" -> "WPA2"
        "wpa3" -> "WPA3"
        "wpa2-enterprise" -> "WPA2 Enterprise"
        "wpa3-enterprise" -> "WPA3 Enterprise"
        else -> value
    }
}
