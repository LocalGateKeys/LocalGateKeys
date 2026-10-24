package app.localgatekeys.android.ui.unlock

import androidx.lifecycle.Lifecycle
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Port of ios/LocalGateKeysTests/PrivacyCoverTests.swift. iOS scene phases map to the activity's lifecycle state:
 * active = RESUMED, inactive = STARTED (paused: a dialog or the recents screen), background = CREATED (stopped).
 */
class PrivacyCoverTest {
    @Test fun cover_shows_when_not_active_and_hides_on_active() {
        assertFalse(PrivacyCover.covers(Lifecycle.State.RESUMED))
        assertTrue(PrivacyCover.covers(Lifecycle.State.STARTED))
        assertTrue(PrivacyCover.covers(Lifecycle.State.CREATED))
        assertFalse(PrivacyCover.covers(Lifecycle.State.RESUMED))
        assertTrue(PrivacyCover.covers(Lifecycle.State.STARTED))
    }

    @Test fun not_yet_resumed_or_destroyed_is_covered() {
        assertTrue(PrivacyCover.covers(Lifecycle.State.INITIALIZED))
        assertTrue(PrivacyCover.covers(Lifecycle.State.DESTROYED))
    }
}
