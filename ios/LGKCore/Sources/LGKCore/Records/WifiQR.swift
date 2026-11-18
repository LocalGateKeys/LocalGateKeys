/// Wi-Fi network QR text, the ZXing "WIFI:" format
/// (https://github.com/zxing/zxing/wiki/Barcode-Contents#wi-fi-network-config-android-ios-11).
/// Mirror of Python `wifi_qr.wifi_qr_text`; vectors in `tests/vectors/wifi_qr/cases.json`.
public enum WifiQR {
    /// QR payload for a Wi-Fi item, or nil for types a plain QR cannot express (enterprise, unknown).
    /// `security` is the item's raw value (`none`, `wep`, `wpa`, `wpa2`, `wpa3`, ...).
    public static func text(ssid: String, password: String, security: String, hidden: Bool) -> String? {
        let kind: String
        switch security {
        case "none": kind = "nopass"
        case "wep": kind = "WEP"
        case "wpa", "wpa2", "wpa3": kind = "WPA"
        default: return nil
        }
        var text = "WIFI:T:\(kind);S:\(escape(ssid));"
        if kind != "nopass" { text += "P:\(escape(password));" }
        if hidden { text += "H:true;" }
        return text + ";"
    }

    /// Backslash-escapes `\ ; , : "` (the backslash first, so it is not escaped twice).
    private static func escape(_ value: String) -> String {
        var out = ""
        for ch in value.unicodeScalars {
            if ch == "\\" || ch == ";" || ch == "," || ch == ":" || ch == "\"" { out.unicodeScalars.append("\\") }
            out.unicodeScalars.append(ch)
        }
        return out
    }
}
