package app.localgatekeys.core.sync

import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.SystemRandomSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

/** Workstream 6: per-peer last sync times, local only, updated only for accepted changes. */
class PeerSyncedAtTest {
    private val state = SyncGroupState(
        "g".repeat(32), 1, ByteArray(32), DeviceIdentity.generate(random = SystemRandomSource()), "install",
    )

    @Test fun accepted_peers_get_the_time() {
        val s = state.syncedWith(listOf("a", "b"), 100).syncedWith(listOf("b"), 200)
        assertEquals(mapOf("a" to 100L, "b" to 200L), s.peerSyncedAt)
        assertSame(s, s.syncedWith(emptyList(), 300))
        assertEquals(s, s.copy())
    }

    @Test fun keeps_the_most_recent_peers() {
        val s = state.syncedWith((1..5).map { "p$it" }, 10).syncedWith(listOf("new"), 20).let { it.syncedWith(emptyList(), 0) }
        assertEquals(setOf("p1", "p2", "p3", "p4", "p5", "new"), s.peerSyncedAt.keys)
        val capped = state.syncedWith(listOf("old"), 1).syncedWith(listOf("x", "y"), 5, limit = 2)
        assertEquals(setOf("x", "y"), capped.peerSyncedAt.keys)
    }
}
