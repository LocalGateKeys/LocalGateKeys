package app.localgatekeys.core.recovery

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.RecordException
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncRunner
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The `heir` sync namespace on a phone: the desktop's merge rules (desktop `vault_bridge` "heir" + tests/test_heir_flow.py sync cases). */
class HeirSyncTest {
    private val v = HeirVectors.data
    private val wrapper = v.getValue("wrapper")
    private val synced = v.getValue("synced") as JsonValue.Obj
    private val me = "phone-1"
    private val pc = "desktop-a"
    private val laptop = "desktop-b"
    private val now = 1_800_500_000L

    private fun state(item: JsonValue?, vv: Map<String, Long>, id: String = Heir.STATE_ID, deleted: Boolean = false) =
        ItemState(id, vv, deleted, if (deleted) now - 10 else null, item)

    private fun withRecord(edit: (MutableMap<String, JsonValue>) -> Unit): JsonValue {
        val r = LinkedHashMap(synced.fields)
        edit(r)
        return Wrapper.make(Namespace.HEIR, JsonValue.Obj(r))
    }

    private fun stored(report: app.localgatekeys.core.sync.RunReport) =
        ((report.records!![Heir.STATE_ID] as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields

    @Test fun the_desktop_wrapper_unwraps_and_bad_shapes_are_refused() {
        assertEquals(Wrapper.make(Namespace.HEIR, synced), wrapper)
        val (ns, record) = Wrapper.unwrap(state(wrapper, mapOf(pc to 1)), false)
        assertEquals(Namespace.HEIR, ns)
        assertEquals(synced, record)
        fun refused(item: JsonValue, id: String = Heir.STATE_ID, copy: Boolean = false) =
            assertFailsWith<RecordException> { Wrapper.unwrap(state(item, mapOf(pc to 1), id), copy) }.reason
        val w = (wrapper as JsonValue.Obj).fields
        assertEquals("bad-remote", refused(JsonValue.Obj(w + ("updated_at" to JsonValue.Int(1)))))
        assertEquals("bad-remote", refused(wrapper, id = "11111111-2222-4333-8444-555555555555"))
        assertEquals("bad-remote", refused(JsonValue.Obj(w + ("id" to JsonValue.Str(Heir.STATE_ID))), copy = true))
        assertEquals("bad-remote", refused(withRecord { it.remove("stale") }))
        assertEquals("bad-remote", refused(withRecord { it["folder"] = JsonValue.Null }))
        // A login under the plan's id is refused too.
        assertEquals("bad-remote", refused(Wrapper.make(Namespace.ENTRY, JsonValue.Obj(mapOf("id" to JsonValue.Str(Heir.STATE_ID), "kind" to JsonValue.Str("web"))))))
        assertNull(SyncRunner.check(state(wrapper, mapOf(pc to 1)), emptyMap()))
    }

    @Test fun a_plan_from_the_computer_is_stored_and_denies_merge_both_ways() {
        val first = SyncRunner.run(StoreSnapshot(), listOf(PeerView(pc, listOf(state(wrapper, mapOf(pc to 1))))), me, now)
        assertTrue(first.issues.isEmpty(), first.issues.toString())
        assertEquals(wrapper, first.records!![Heir.STATE_ID])
        assertEquals(mapOf(pc to 1L), first.meta!!.getValue(Heir.STATE_ID).vv)
        assertNotNull(first.ownStates!!.single { it.itemId == Heir.STATE_ID })
        // The phone denies a request: the record changes, the local view bumps it so it travels back.
        val mine = Heir.withDenied(synced, "11111111-2222-4333-8444-555555555555")
        val records = first.records!! + (Heir.STATE_ID to Wrapper.make(Namespace.HEIR, mine))
        val local = SyncMeta.localView(records, first.meta!!, me, now)
        assertEquals(mapOf(pc to 1L, me to 1L), local.states.getValue(Heir.STATE_ID).vv)
        // Meanwhile the laptop refused another one: concurrent edits merge (the union), never a stored copy.
        val other = withRecord { it["denied"] = JsonValue.Arr(listOf(JsonValue.Str("22222222-3333-4444-8555-666666666666"))) }
        val second = SyncRunner.run(
            StoreSnapshot(records, first.meta!!), listOf(PeerView(laptop, listOf(state(other, mapOf(pc to 1, laptop to 1))))), me, now,
        )
        assertTrue(second.issues.isEmpty(), second.issues.toString())
        assertEquals(1, second.records!!.size)
        val denied = (stored(second).getValue("denied") as JsonValue.Arr).items.map { it.str() }.toSet()
        assertEquals(setOf("7f301c5e-9d4b-4ea2-8f63-4c8a0b2d1e59", "11111111-2222-4333-8444-555555555555", "22222222-3333-4444-8555-666666666666"), denied)
        assertEquals(1, second.ownStates!!.size)
    }

    @Test fun a_merge_that_adds_to_the_remote_is_republished() {
        val mine = Heir.withDenied(synced, "11111111-2222-4333-8444-555555555555")
        val records = mapOf(Heir.STATE_ID to Wrapper.make(Namespace.HEIR, mine))
        val meta = mapOf(Heir.STATE_ID to SyncMeta.live(records.getValue(Heir.STATE_ID), mapOf(pc to 1L, me to 1L)))
        // The computer's newer version (stale now) does not know the phone's refusal.
        val newer = withRecord { it["stale"] = JsonValue.Bool(true) }
        val report = SyncRunner.run(StoreSnapshot(records, meta), listOf(PeerView(pc, listOf(state(newer, mapOf(pc to 2, me to 1))))), me, now)
        assertTrue(report.issues.isEmpty(), report.issues.toString())
        val r = stored(report)
        assertEquals(JsonValue.Bool(true), r["stale"])
        assertTrue(JsonValue.Str("11111111-2222-4333-8444-555555555555") in (r.getValue("denied") as JsonValue.Arr).items)
        assertEquals(mapOf(pc to 2L, me to 2L), report.meta!!.getValue(Heir.STATE_ID).vv)
    }

    @Test fun a_remote_that_rekeys_the_plan_is_quarantined_and_the_local_plan_kept() {
        val records = mapOf(Heir.STATE_ID to wrapper)
        val meta = mapOf(Heir.STATE_ID to SyncMeta.live(wrapper, mapOf(pc to 1L)))
        val merges = v.getValue("merges").arr().map { it.obj().fields }
        val rekeyed = merges.single { it.getValue("name").str() == "rekeyed-conflict" }.getValue("remote")
        val report = SyncRunner.run(
            StoreSnapshot(records, meta),
            listOf(PeerView(laptop, listOf(state(Wrapper.make(Namespace.HEIR, rekeyed), mapOf(pc to 1, laptop to 1))))), me, now,
        )
        assertEquals(listOf("bad-peer-record"), report.issues.map { it.kind })
        assertEquals(wrapper, report.records!![Heir.STATE_ID])
    }

    @Test fun another_plan_replaces_and_a_tombstone_removes() {
        val records = mapOf(Heir.STATE_ID to wrapper)
        val meta = mapOf(Heir.STATE_ID to SyncMeta.live(wrapper, mapOf(pc to 1L)))
        val merges = v.getValue("merges").arr().map { it.obj().fields }
        val newer = Wrapper.make(Namespace.HEIR, merges.single { it.getValue("name").str() == "another-plan-replaces" }.getValue("remote"))
        val replaced = SyncRunner.run(StoreSnapshot(records, meta), listOf(PeerView(pc, listOf(state(newer, mapOf(pc to 2))))), me, now)
        assertTrue(replaced.issues.isEmpty())
        assertEquals(newer, replaced.records!![Heir.STATE_ID])
        val removed = SyncRunner.run(StoreSnapshot(records, meta), listOf(PeerView(pc, listOf(state(null, mapOf(pc to 2), deleted = true)))), me, now)
        assertTrue(removed.issues.isEmpty(), removed.issues.toString())
        assertNull(removed.records!![Heir.STATE_ID])
        assertEquals(true, removed.meta!!.getValue(Heir.STATE_ID).deleted)
    }

    @Test fun a_damaged_stored_plan_is_never_published_and_the_publish_gate_leaves_it_out() {
        val damaged = withRecord { it["k"] = JsonValue.Int(9) }
        val view = SyncMeta.localView(mapOf(Heir.STATE_ID to damaged), emptyMap(), me, now)
        assertTrue(view.states.isEmpty())
        assertEquals(setOf(Heir.STATE_ID), view.skipped.keys)
        val elsewhere = SyncMeta.localView(mapOf("11111111-2222-4333-8444-555555555555" to wrapper), emptyMap(), me, now)
        assertEquals("invalid-id", elsewhere.skipped.values.single())
        val states = listOf(state(wrapper, mapOf(pc to 1)), state(null, mapOf(pc to 1), id = "abc", deleted = true))
        assertEquals(listOf("abc"), Heir.publishable(states, heir = false).map { it.itemId })
        assertEquals(2, Heir.publishable(states, heir = true).size)
    }
}
