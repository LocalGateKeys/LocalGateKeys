package app.localgatekeys.core.activity

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ActivityChainTest {
    // The same vector as tests/test_activity_chain.py::test_shared_vector (Windows activity.py).
    private val first = ActivityChain.Event("00000000-0000-4000-8000-000000000001", "agent.request", 1_762_905_600,
        prevHash = ActivityChain.GENESIS)
    private val firstHash = "a41a74612fea40f020a620bfc5388089682665bc54d23e81c8b379376f6dc1c8"
    private val second = ActivityChain.Event("00000000-0000-4000-8000-000000000002", "agent.fill", 1_762_905_601,
        itemId = "00000000-0000-4000-8000-0000000000aa", count = 1, prevHash = firstHash)
    private val secondHash = "c524dbc6cca86059dab754117ff3de604fe472e98eef5493f9ca68e39dcf4012"

    @Test fun shared_vector_matches_windows() {
        assertEquals(firstHash, ActivityChain.hash(first))
        assertEquals(secondHash, ActivityChain.hash(second))
        assertEquals(firstHash, ActivityChain.link(listOf(first)))
    }

    @Test fun verify_finds_tampering_and_honours_the_checkpoint() {
        assertTrue(ActivityChain.verify(listOf(first, second), head = secondHash).ok)
        assertEquals(first.id, ActivityChain.verify(listOf(first.copy(result = "denied"), second)).firstBadId)
        assertFalse(ActivityChain.verify(listOf(first, second), head = firstHash).ok)
        assertTrue(ActivityChain.verify(listOf(second), checkpoint = firstHash).ok)
        assertFalse(ActivityChain.verify(listOf(second)).ok)
    }

    @Test fun truncation_emptying_and_stripping_are_caught_by_the_head() {
        assertFalse(ActivityChain.verify(listOf(first), head = secondHash).ok)
        assertFalse(ActivityChain.verify(emptyList(), head = secondHash).ok)
        val stripped = listOf(first.copy(prevHash = null), second.copy(prevHash = null))
        assertFalse(ActivityChain.verify(stripped, head = secondHash).ok)
    }
}
