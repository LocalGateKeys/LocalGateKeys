package app.localgatekeys.android.sync

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.sync.SyncStatusSummary.Dot
import app.localgatekeys.android.sync.SyncStatusSummary.Route
import app.localgatekeys.core.sync.SyncIssue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Workstream 6: the pill's text and colour states, and the sheet's device rows. */
class SyncStatusSummaryTest {
    private val now = 1_800_000_000L
    private val me = "me-device"

    private fun joined(members: List<String> = listOf("pc-1", "mac-2"), synced: Map<String, Long> = emptyMap()) =
        SyncCoordinator.Membership(joined = true, hasFolder = true, deviceId = me, members = members, peerSyncedAt = synced)

    @Test fun not_joined_has_no_pill() {
        assertNull(SyncStatusSummary.of(SyncCoordinator.Membership(), emptyList(), now, now, EnglishTxt()))
    }

    @Test fun green_when_synced_recently_without_problems() {
        val s = SyncStatusSummary.of(joined(synced = mapOf("pc-1" to now - 720)), emptyList(), now - 120, now, EnglishTxt())!!
        assertEquals("Synced 2 min ago · 3 devices", s.pill)
        assertEquals(Dot.GREEN, s.dot)
        assertEquals(listOf("mac-2", "pc-1"), s.devices.map { it.id })
        assertEquals(Route.FOLDER, s.devices[1].route)
        assertEquals(now - 720, s.devices[1].lastSynced)
        assertNull(s.devices[0].lastSynced)
    }

    @Test fun orange_when_older_than_a_day_or_a_peer_is_stale_or_a_warning() {
        assertEquals(Dot.ORANGE, SyncStatusSummary.of(joined(), emptyList(), now - 2 * 86_400, now, EnglishTxt())!!.dot)
        assertEquals(Dot.ORANGE, SyncStatusSummary.of(joined(), emptyList(), null, now, EnglishTxt())!!.dot)
        val stale = SyncStatusSummary.of(joined(synced = mapOf("pc-1" to now - 31 * 86_400)), emptyList(), now, now, EnglishTxt())!!
        assertEquals(Dot.ORANGE, stale.dot)
        assertEquals(EnglishTxt().s(SyncStatusSummary.NOT_SEEN), stale.devices.single { it.id == "pc-1" }.warning)
        val warn = SyncWording(EnglishTxt()).views(listOf(SyncIssue("peer-epoch-behind", "pc-1")))
        assertEquals(Dot.ORANGE, SyncStatusSummary.of(joined(), warn, now, now, EnglishTxt())!!.dot)
    }

    @Test fun red_on_an_error() {
        val err = SyncWording(EnglishTxt()).views(listOf(SyncIssue("keyring-missing")))
        assertEquals(Dot.RED, SyncStatusSummary.of(joined(), err, now, now, EnglishTxt())!!.dot)
    }

    @Test fun routes_and_texts() {
        assertEquals("just now", SyncStatusSummary.ago(5, EnglishTxt()))
        assertEquals("3 h ago", SyncStatusSummary.ago(3 * 3600 + 5, EnglishTxt()))
        assertEquals("1 day ago", SyncStatusSummary.ago(86_400, EnglishTxt()))
        assertEquals("Never", SyncStatusSummary.lastSyncedText(null, now, EnglishTxt()))
        val only = SyncStatusSummary.of(joined(members = emptyList()), emptyList(), now, now, EnglishTxt())!!
        assertEquals("Synced just now · 1 device", only.pill)
    }
}
