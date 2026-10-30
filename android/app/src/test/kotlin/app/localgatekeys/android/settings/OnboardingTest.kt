package app.localgatekeys.android.settings

import app.localgatekeys.android.i18n.EnglishTxt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Workstream 4 on Android: skip all → card; finish all → no card; Hide stays hidden; Settings reopens. */
class OnboardingTest {
    private val store = MemoryStore()
    private val settings = AppSettings(store)

    @Test fun first_run_opens_the_pages_at_the_first_open_step() {
        val o = Onboarding(settings, EnglishTxt())
        assertTrue(o.pagesOpen.value)
        assertEquals(SetupStep.UNLOCK, o.firstPage())
        assertNull("no card while the pages show", o.cardText())
        assertEquals(listOf(SetupStep.CREATE, SetupStep.UNLOCK, SetupStep.IMPORT, SetupStep.APP_PASSWORD, SetupStep.AUTOFILL), SetupStep.entries)
    }

    @Test fun skip_setup_leaves_the_card_with_the_steps_left() {
        val o = Onboarding(settings, EnglishTxt())
        o.closePages()
        assertFalse(o.pagesOpen.value)
        assertEquals("Finish setting up · 1 of 5", o.cardText())
        assertFalse("not shown again by itself", Onboarding(settings, EnglishTxt()).pagesOpen.value)
    }

    @Test fun finishing_every_step_removes_the_card() {
        val o = Onboarding(settings, EnglishTxt())
        o.complete(SetupStep.UNLOCK)
        assertEquals(SetupStep.IMPORT, o.next(SetupStep.UNLOCK))
        for (s in listOf(SetupStep.IMPORT, SetupStep.APP_PASSWORD, SetupStep.AUTOFILL)) o.complete(s)
        assertNull(o.next(SetupStep.UNLOCK))
        o.closePages()
        assertNull(o.cardText())
        val again = Onboarding(settings, EnglishTxt())
        assertTrue(again.remaining.isEmpty())
        assertEquals(setOf("unlock", "import", "app-password", "autofill"), settings.setupDone)
    }

    @Test fun hide_stays_hidden_until_show_setup_again() {
        val o = Onboarding(settings, EnglishTxt())
        o.complete(SetupStep.IMPORT)
        o.closePages()
        assertEquals("Finish setting up · 2 of 5", o.cardText())
        o.hideCard()
        assertNull(o.cardText())
        assertNull(Onboarding(settings, EnglishTxt()).cardText())
        val reopened = Onboarding(settings, EnglishTxt())
        reopened.showAgain()
        assertTrue(reopened.pagesOpen.value)
        assertEquals("the pages skip what is done", SetupStep.UNLOCK, reopened.firstPage())
        assertEquals(SetupStep.APP_PASSWORD, reopened.next(SetupStep.UNLOCK))
        reopened.closePages()
        assertEquals("Finish setting up · 2 of 5", reopened.cardText())
    }

    @Test fun progress_is_local_settings_only() {
        assertTrue(AppSettings.Key.SETUP_DONE in AppSettings.Key.all)
        assertTrue(AppSettings.Key.SETUP_SEEN in AppSettings.Key.all)
        assertTrue(AppSettings.Key.SETUP_CARD_HIDDEN in AppSettings.Key.all)
    }
}
