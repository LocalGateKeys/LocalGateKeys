package app.localgatekeys.android.share

import androidx.test.ext.junit.runners.AndroidJUnit4
import app.localgatekeys.core.share.Share
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Share's code parsing on the device's own regex engine (ICU), which rejects some JVM-only syntax: a `(?U)` flag here
 * passed every JVM test and crashed the app whenever an item opened.
 */
@RunWith(AndroidJUnit4::class)
class ShareRegexDeviceTest {
    @Test fun the_code_splits_on_spaces_dots_commas_dashes_and_unicode_spaces() {
        val words = "abandon ability able about above absent"
        assertEquals(words, Share.normalizeCode("Abandon-ability.able,about · above absent"))
        assertEquals(words, Share.normalizeCode("  abandon ability　able  about\tabove\nabsent "))
    }
}
