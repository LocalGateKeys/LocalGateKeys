package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.support.MergeVectors
import app.localgatekeys.core.support.MergeVectors.NOTE_UNICODE
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.SyncFixtures.PHONE
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Port of Swift `RunnerTests`. */
class RunnerTest {
    private val now = MergeVectors.T0 + 1000

    @Test
    fun run_folds_and_applies_ABC() {
        val r = SyncRunner.run(StoreSnapshot(), SyncFixtures.views(), PHONE, now)
        assertEquals(emptyList(), r.issues)
        val want = SyncFixtures.bridgeStoredStates()
        assertEquals(want, r.ownStates)
        assertTrue(r.conflicts > 0)
        assertEquals(want.count { !it.deleted }, r.records?.size)
        // Pure: running again over the result changes nothing.
        val again = SyncRunner.run(StoreSnapshot(records = r.records!!, meta = r.meta!!), SyncFixtures.views(), PHONE, now)
        assertEquals(r.records, again.records)
        assertEquals(r.meta, again.meta)
        assertEquals(0, again.applied)
    }

    @Test
    fun bad_and_newer_records_are_quarantined_not_the_view() {
        val vs = SyncFixtures.views().toMutableList()
        val b = vs[1]
        val states = b.states.toMutableList()
        // A newer schema on one record and a malformed wrapper on another.
        val i = states.indexOfFirst { it.itemId == NOTE_UNICODE }
        val w = obj(states[i].item) + ("schema" to JsonValue.Int(2))
        states[i] = ItemState(states[i].itemId, states[i].vv, false, null, JsonValue.Obj(w))
        val j = states.indexOfFirst { it.itemId == MergeVectors.DESKTOP }
        var w2 = obj(states[j].item) + ("extra" to JsonValue.Int(1))
        // DESKTOP is identical in every view, so put the bad copy under a new id only B has.
        val badId = "99999999-aaaa-4000-8000-000000000009"
        val rec = obj(w2["record"]) + ("id" to JsonValue.Str(badId))
        w2 = w2 + ("record" to JsonValue.Obj(rec))
        states.add(ItemState(badId, mapOf(MergeVectors.B to 1L), false, null, JsonValue.Obj(w2)))
        vs[1] = PeerView(b.deviceId, states)
        val r = SyncRunner.run(StoreSnapshot(), vs, PHONE, now)
        assertEquals(
            setOf(
                SyncIssue("update-needed", "${MergeVectors.B}:$NOTE_UNICODE"),
                SyncIssue("bad-peer-record", "${MergeVectors.B}:$badId"),
            ),
            r.issues.toSet(),
        )
        assertNull(r.records?.get(NOTE_UNICODE))
        assertNull(r.records?.get(badId))
        assertNotNull(r.records?.get(MergeVectors.BOOKMARK))
    }

    @Test
    fun licences_received_are_reported() {
        val o = obj(CanonicalJson.parse(Vectors.sync("license_state.json").readBytes()))
        val keys = mapOf(str(o["key_id"])!! to Base64Std.decodeStrict(str(o["public_key_b64"])!!))
        val sid = str(o["state_id"])!!
        val lic = ItemState(sid, mapOf(MergeVectors.A to 1L), false, null, o["wrapper"]!!)
        val view = PeerView(MergeVectors.A, listOf(lic))
        val r = SyncRunner.run(StoreSnapshot(), listOf(view), PHONE, now, keys)
        assertEquals(emptyList(), r.issues)
        assertEquals(listOf(obj(o["wrapper"])["record"]!!), r.licenses)
        assertEquals(listOf(sid), r.ownStates?.map { it.itemId }) // republished by the receiver
        // Without licence keys the licence is dropped without a report.
        val none = SyncRunner.run(StoreSnapshot(), listOf(view), PHONE, now)
        assertEquals(emptyList(), none.issues)
        assertEquals(emptyList(), none.licenses)
        assertEquals(emptyMap(), none.records)
    }

    @Test
    fun bad_view_and_local_data() {
        val dup = ItemState(MergeVectors.NOTE, mapOf(MergeVectors.A to 1L), true, 1, null)
        val r = SyncRunner.run(StoreSnapshot(), listOf(PeerView(MergeVectors.A, listOf(dup, dup))), PHONE, now)
        assertEquals(listOf(SyncIssue("bad-peer-data", MergeVectors.A)), r.issues)
        val bad = SyncRunner.run(StoreSnapshot(), emptyList(), "not valid!", now)
        assertEquals(listOf("local-data"), bad.issues.map { it.kind })
        assertNull(bad.ownStates)
    }
}
