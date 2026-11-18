package app.localgatekeys.android.security

import app.localgatekeys.android.i18n.EnglishTxt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HealthReportTest {
    private val txt = EnglishTxt()

    @Test fun rows_hold_the_kdf_memory_in_mib_and_unknowns() {
        val rows = HealthReport.rows(HealthReport.Facts(generatedAt = 1_800_000_000, build = "1.2.3"), txt)
        assertEquals(11, rows.size)
        assertEquals("Key derivation" to "Argon2id, 128 MiB memory, 4 passes, 4 lanes", rows[1])
        assertEquals("Generated" to "2027-01-15 08:00 UTC", rows[0])
        assertEquals("not recorded", rows.first { it.first == "Devices paired" }.second)
        assertEquals("1.2.3", rows.first { it.first == "Build" }.second)
    }

    @Test fun no_item_title_reaches_the_report() {
        // The report takes only facts; nothing in it can carry a title, even when the vault has one.
        val text = HealthReport.rows(HealthReport.Facts(generatedAt = 0, restoreTest = "Last backup restore test: never run"), txt).toString()
        assertFalse(text.contains("Secret title"))
        assertTrue(text.contains("MiB"))
    }

    @Test fun factors_follow_the_real_settings() {
        assertEquals("phone screen lock", HealthReport.factorsText(false, true, true, true, txt))
        assertEquals("app password", HealthReport.factorsText(true, false, false, false, txt))
        assertEquals("app password, fingerprint or face, key file, YubiKey", HealthReport.factorsText(true, true, true, true, txt))
    }
}
