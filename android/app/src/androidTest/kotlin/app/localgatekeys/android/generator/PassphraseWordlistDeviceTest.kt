package app.localgatekeys.android.generator

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The packaged list is in the APK's assets and LgkApp installs it: passphrases use the desktop list, not the fallback. */
class PassphraseWordlistDeviceTest {
    @Test fun the_app_reads_the_packaged_desktop_list() {
        // LgkApp.onCreate has run (the instrumented app's Application) and installed the asset reader.
        InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val words = PassphraseWordlist.packaged
        assertEquals(5017, words.size)
        assertTrue(words.first() == "abacus")
        assertTrue(words != PassphraseWordlist.FALLBACK)
    }
}
