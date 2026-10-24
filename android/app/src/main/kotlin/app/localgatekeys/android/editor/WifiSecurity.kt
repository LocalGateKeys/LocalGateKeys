package app.localgatekeys.android.editor

/** Wi-Fi security choices as people read them (`EditorKind.choiceLabel` in the iPhone editor; Task 8's EditorKind uses this). */
object WifiSecurity {
    fun label(value: String): String = when (value) {
        "none" -> "None (open)"
        "wep" -> "WEP"
        "wpa" -> "WPA"
        "wpa2" -> "WPA2"
        "wpa3" -> "WPA3"
        "wpa2-enterprise" -> "WPA2 Enterprise"
        "wpa3-enterprise" -> "WPA3 Enterprise"
        else -> value
    }
}
