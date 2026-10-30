package app.localgatekeys.android.settings

import app.localgatekeys.android.i18n.EnglishTxt
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Port of ios/LocalGateKeysTests/SettingsTests.swift (Ruling 6) and MinorFixesTests `test_autofill_status_*` and
 * `test_initials_*`.
 */
class SettingsTest {
    private val st = SettingsText(EnglishTxt())
    private val assets = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot not set"), "android/app/src/main/assets")

    /** Swift test_acknowledgements_ship_both_licences, over what the Android app ships. */
    @Test fun acknowledgements_ship_every_licence() {
        val list = Acknowledgement.all { File(assets, it).readText() }
        assertEquals(
            listOf("argon2kt", "phc-winner-argon2", "Bouncy Castle", "AndroidX and Jetpack Compose", "Kotlin and kotlinx.coroutines", "ZXing"),
            list.map { it.name },
        )
        assertEquals(listOf("MIT", "CC0-1.0", "MIT", "Apache-2.0", "Apache-2.0", "Apache-2.0"), list.map { it.licence })
        assertTrue(list[0].text.contains("MIT License"))
        assertTrue(list[1].text.contains("CC0 1.0"))
        assertTrue(list[2].text.contains("The Legion of the Bouncy Castle"))
        for (a in list.drop(3)) assertTrue(a.name, a.text.contains("Apache License"))
        assertFalse("toString leaves the long text out", list[3].toString().contains("Apache License"))
    }

    /** Swift test_about_text (the Safari help is iPhone-only). */
    @Test fun about_text() {
        assertEquals("Data not collected — LocalGateKeys has no analytics and no servers.", st.dataNotCollected)
        assertEquals("https://localgatekeys.app/legal/app/privacy.html", SettingsText.PRIVACY_POLICY_URL)
        assertEquals("https://localgatekeys.app/legal/app/eula.html", SettingsText.LICENCE_AGREEMENT_URL)
        assertEquals("0.1.0 (1)", st.version("0.1.0", "1"))
        assertEquals("0.1.0", st.version("0.1.0", ""))
        assertEquals("Pro is active", st.proStatus(true))
        assertEquals("Free (up to 4 items)", st.proStatus(false))
        assertEquals("Erase this phone's vault", st.eraseButton)
        assertEquals("Deletes the vault on this phone only. Your PC and the sync folder are not changed.", st.eraseFooter)
    }

    @Test fun sync_status_text() {
        val time: (Long) -> String = { "12:34" }
        assertEquals("Not set up", st.syncStatus(false, null, time))
        assertEquals("On", st.syncStatus(true, null, time))
        assertEquals("Last synced 12:34", st.syncStatus(true, 1_790_000_000, time))
    }

    /** Swift test_extension_interface_style_follows_appearance: the app's theme follows the Appearance setting. */
    @Test fun theme_follows_appearance() {
        assertTrue(Appearance.SYSTEM.isDark(systemDark = true))
        assertFalse(Appearance.SYSTEM.isDark(systemDark = false))
        assertFalse(Appearance.LIGHT.isDark(systemDark = true))
        assertTrue(Appearance.DARK.isDark(systemDark = false))
    }

    /** MinorFixesTests test_autofill_status_is_rechecked_and_open_errors_are_shown. */
    @Test fun autofill_status_is_rechecked_and_open_errors_are_shown() = runBlocking {
        var enabled = false
        var openError: Exception? = UnsupportedOperationException()
        val m = AutofillStatusModel(isEnabled = { enabled }, open = { openError?.let { throw it } }, t = EnglishTxt())
        assertNull(m.enabled.value)
        assertEquals("…", m.statusText(m.enabled.value))
        m.refresh()
        assertEquals(false, m.enabled.value)
        assertEquals("Off", m.statusText(m.enabled.value))
        m.openSettings()
        assertEquals(EnglishTxt().s(app.localgatekeys.android.R.string.autofill_open_failed), m.openError.value)
        // Back from system settings (the screen resumed): checked again, and the error goes.
        enabled = true; openError = null
        m.refresh()
        assertEquals(true, m.enabled.value)
        assertEquals("On", m.statusText(m.enabled.value))
        assertNull(m.openError.value)
        m.openSettings()
        assertNull(m.openError.value)
    }

    /** MinorFixesTests test_initials_are_normalised_on_submit_not_while_typing. */
    @Test fun initials_are_normalised_on_submit_not_while_typing() {
        val settings = AppSettings(MemoryStore())
        val field = InitialsField(settings)
        assertEquals("", field.text)
        for (prefix in listOf("J", "Jo", "John", "John ", "John D", "John Doe")) {
            field.text = prefix
            assertEquals("typing is never rewritten", prefix, field.text)
        }
        assertEquals("nothing stored until submit", "", settings.initials)
        field.submit()
        assertEquals("JD", settings.initials)
        assertEquals("JD", field.text)
        field.text = "  "; field.submit()
        assertEquals("", settings.initials)
        assertEquals("", InitialsField(settings).text)
    }
}
