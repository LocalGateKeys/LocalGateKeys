package app.localgatekeys.android.i18n

import android.app.LocaleManager
import android.os.Build
import androidx.appcompat.app.AppCompatDelegate
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import app.localgatekeys.android.MainActivity
import org.junit.Assert.assertEquals
import org.junit.Test

class LanguageSwitchTest {
    // On Android 13+ AppCompat reaches the system LocaleManager only through a live activity, as the picker does.
    @Test
    fun switches_to_german_and_back() {
        val inst = InstrumentationRegistry.getInstrumentation()
        ActivityScenario.launch(MainActivity::class.java).use {
            try {
                inst.runOnMainSync { LanguageOptions.apply("de") }
                inst.waitForIdleSync()
                assertEquals("de", appLocales())
                inst.runOnMainSync { LanguageOptions.apply("") }
                inst.waitForIdleSync()
                assertEquals("", appLocales())
            } finally {
                inst.runOnMainSync { LanguageOptions.apply("") }
            }
        }
    }

    private fun appLocales(): String {
        if (Build.VERSION.SDK_INT >= 33) {
            val lm = InstrumentationRegistry.getInstrumentation().targetContext.getSystemService(LocaleManager::class.java)
            return lm.applicationLocales.toLanguageTags()
        }
        var tags = ""
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            tags = AppCompatDelegate.getApplicationLocales().toLanguageTags()
        }
        return tags
    }
}
