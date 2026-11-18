package app.localgatekeys.android.widget

import app.localgatekeys.android.widget.CodesWidgetUpdates.Companion.SCREEN_LOCKED_POLL_MILLIS
import app.localgatekeys.android.widget.CodesWidgetUpdates.Companion.screenLockedPollDelay
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ScreenLockedPollTest {
    @Test
    fun lockedVaultNeverPolls() = assertNull(screenLockedPollDelay(null, 1_000_000))

    @Test
    fun pastDeadlineNeverPolls() = assertNull(screenLockedPollDelay(1_000, 1_000_000))

    @Test
    fun pollsWhileOpen() = assertEquals(SCREEN_LOCKED_POLL_MILLIS, screenLockedPollDelay(2_000, 1_000_000))

    @Test
    fun lastPollLandsJustAfterDeadline() = assertEquals(5_100L, screenLockedPollDelay(1_005, 1_000_000))

    @Test
    fun noDeadlineKeepsPolling() = assertEquals(SCREEN_LOCKED_POLL_MILLIS, screenLockedPollDelay(Long.MAX_VALUE, 1_000_000))

    @Test
    fun codesShownRefreshIsCapped() {
        assertEquals(CodesWidgetUpdates.CODES_SHOWN_MAX_DELAY_MILLIS, CodesWidgetUpdates.codesShownDelay(29_900))
        assertEquals(CodesWidgetUpdates.CODES_SHOWN_MAX_DELAY_MILLIS, CodesWidgetUpdates.codesShownDelay(null))
        assertEquals(5_100L, CodesWidgetUpdates.codesShownDelay(5_100))
    }
}
