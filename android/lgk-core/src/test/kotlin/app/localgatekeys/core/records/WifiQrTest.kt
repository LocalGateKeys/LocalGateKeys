package app.localgatekeys.core.records

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The shared Wi-Fi QR vectors (tests/vectors/wifi_qr/cases.json, copied to test resources). Mirror of Swift `WifiQRTests`. */
class WifiQrTest {
    private val cases: List<JsonValue> = CanonicalJson.parse(
        javaClass.getResourceAsStream("/wifi_qr_cases.json")!!.use { it.readBytes() },
    ).arr()

    @Test fun vectors() {
        assertTrue(cases.size >= 9)
        for (c in cases) {
            val f = c.obj().fields
            val expected = (f.getValue("text") as? JsonValue.Str)?.v
            val hidden = (f.getValue("hidden") as JsonValue.Bool).v
            assertEquals(
                expected,
                WifiQr.text(f.getValue("ssid").str(), f.getValue("password").str(), f.getValue("security").str(), hidden),
                "vector ${f.getValue("name").str()}",
            )
        }
    }

    @Test fun unknownSecurityHasNoQr() {
        assertNull(WifiQr.text("a", "b", "bogus", false))
    }
}
