package app.localgatekeys.core.sync

import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

class PeerSeenAtTest {
    @BeforeTest fun reset() = PeerSeenAt.clear()

    @Test fun a_newer_clean_exchange_wins_over_the_saved_time() {
        PeerSeenAt.note("g", "desk", 500)
        assertEquals(mapOf("desk" to 500L, "other" to 50L), PeerSeenAt.merged("g", mapOf("desk" to 100L, "other" to 50L)))
    }

    @Test fun an_older_time_or_another_group_changes_nothing() {
        PeerSeenAt.note("g", "desk", 10)
        PeerSeenAt.note("h", "desk", 900)
        assertEquals(mapOf("desk" to 100L), PeerSeenAt.merged("g", mapOf("desk" to 100L)))
    }
}
