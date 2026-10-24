package app.localgatekeys.core.engine

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.support.MergeVectors
import app.localgatekeys.core.support.MergeVectors.A
import app.localgatekeys.core.support.MergeVectors.B
import app.localgatekeys.core.support.MergeVectors.BOOKMARK
import app.localgatekeys.core.support.MergeVectors.C
import app.localgatekeys.core.support.MergeVectors.LOGIN_TIE
import app.localgatekeys.core.support.MergeVectors.NOTE_UNICODE
import app.localgatekeys.core.support.MergeVectors.arr
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.sha
import app.localgatekeys.core.support.MergeVectors.state
import app.localgatekeys.core.support.MergeVectors.str
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class EngineTest {
    private fun ids(s: List<ItemState>): List<String> = s.map { it.itemId }.sorted()

    private fun localOf(states: List<ItemState>): Map<String, ItemState> = states.associateBy { it.itemId }

    private fun apply(local: Map<String, ItemState>, out: MergeOutcome): Map<String, ItemState> {
        val m = HashMap(local)
        for (s in out.upserts + out.deletes + out.copies) m[s.itemId] = s
        return m
    }

    private fun sorted(m: Map<String, ItemState>): List<ItemState> = m.values.sortedBy { it.itemId }

    private fun live(id: String, vv: Map<String, Long>, item: JsonValue) = ItemState(id, vv, false, null, item)

    private fun tomb(id: String, vv: Map<String, Long>, at: Long?) = ItemState(id, vv, true, at, null)

    @Test
    fun merge_all_six_orders_match_expected_engine_states() {
        val em = MergeVectors.expectedMerge()
        val expected = arr(em["engine_states"]).map { state(it) }
        val views = MergeVectors.deviceStates()
        val orders = listOf(
            listOf("A", "B", "C"), listOf("A", "C", "B"), listOf("B", "A", "C"),
            listOf("B", "C", "A"), listOf("C", "A", "B"), listOf("C", "B", "A"),
        )
        val steps = obj(em["fold_steps"])
        for (order in orders) {
            var local = localOf(views.getValue(order[0]))
            for ((n, name) in order.drop(1).withIndex()) {
                val out = Engine.merge(local, views.getValue(name))
                val rec = arr(steps[order.joinToString("")]).drop(n).firstOrNull()
                if (rec != null) {
                    val r = obj(rec)
                    assertEquals(arr(r["upserts"]).mapNotNull { str(it) }, ids(out.upserts), "$order step $n")
                    assertEquals(arr(r["deletes"]).mapNotNull { str(it) }, ids(out.deletes), "$order step $n")
                    assertEquals(arr(r["copies"]).mapNotNull { str(it) }, ids(out.copies), "$order step $n")
                    assertEquals(arr(r["conflicts"]).mapNotNull { str(it) }, out.conflicts.map { it.first.itemId }.sorted())
                }
                local = apply(local, out)
            }
            val got = sorted(local)
            assertEquals(expected, got, "order ${order.joinToString("")}")
            for ((g, e) in got.zip(expected)) {
                if (g.item != null) {
                    assertContentEquals(CanonicalJson.encode(e.item!!, Dialect.UTF8), CanonicalJson.encode(g.item, Dialect.UTF8))
                }
            }
        }
        assertEquals(listOf("ABC", "CBA"), steps.keys.sorted())
    }

    @Test
    fun fold_matches_expected_engine_states_in_any_view_order() {
        val expected = arr(MergeVectors.expectedMerge()["engine_states"]).map { state(it) }
        val views = MergeVectors.deviceStates()
        for (first in listOf("A", "B", "C")) {
            val local = localOf(views.getValue(first))
            val peers = listOf("C", "A", "B").filter { it != first }.map { PeerView(it, views.getValue(it)) }
            val r = Engine.fold(local, peers)
            assertTrue(r.quarantined.isEmpty())
            assertTrue(r.badViews.isEmpty())
            assertEquals(expected, sorted(apply(local, r.outcome)), first)
        }
    }

    @Test
    fun fold_quarantines_one_record_and_drops_bad_views() {
        val views = MergeVectors.deviceStates()
        val local = localOf(views.getValue("A"))
        val b = views.getValue("B")
        val dup = PeerView("Z", listOf(b[0], b[0]))
        val r = Engine.fold(local, listOf(PeerView("B", b), dup)) { s ->
            if (s.itemId == NOTE_UNICODE) "bad-remote" else null
        }
        assertEquals(listOf("Z"), r.badViews)
        assertEquals(listOf(FoldQuarantine("B", NOTE_UNICODE, "bad-remote")), r.quarantined)
        assertFalse(r.outcome.upserts.any { it.itemId == NOTE_UNICODE })
        assertTrue(r.outcome.upserts.any { it.itemId == BOOKMARK })
    }

    @Test
    fun fold_copy_from_earlier_view_superseded_by_peer_copy() {
        val v = MergeVectors.deviceStates()
        val local = localOf(v.getValue("A"))
        // B's merge creates the copy; C (here a peer that already stores that copy) carries it.
        val first = Engine.fold(local, listOf(PeerView("B", v.getValue("B"))))
        val copy = first.outcome.copies[0]
        val stored = ItemState(copy.itemId, copy.vv.toMutableMap().also { it[C] = (it[C] ?: 0L) + 1 }, false, null, copy.item)
        val r = Engine.fold(
            local,
            listOf(PeerView("B", v.getValue("B")), PeerView("C", v.getValue("C") + stored)),
        )
        assertTrue(r.badViews.isEmpty())
        val all = r.outcome.upserts + r.outcome.copies
        assertEquals(stored, all.first { it.itemId == copy.itemId })
        assertFalse(r.outcome.copies.any { it.itemId == copy.itemId })
    }

    @Test
    fun fold_is_order_independent_and_idempotent() {
        val v = MergeVectors.deviceStates()
        val names = listOf("A", "B", "C")
        for (own in names) {
            val local = localOf(v.getValue(own))
            val peers = names.filter { it != own }.map { PeerView(it, v.getValue(it)) }
            val reference = Engine.fold(local, peers)
            // every permutation of the views, and the same views supplied twice
            val perms = listOf(peers, peers.reversed())
            for (p in perms) assertEquals(reference, Engine.fold(local, p), "$own permutation")
            assertEquals(reference, Engine.fold(local, peers + peers), "$own duplicated")
            assertEquals(reference, Engine.fold(local, peers.reversed() + peers), "$own duplicated reversed")
            // own-device views are ignored
            // (its content differs from local: a fresh item and a higher counter, so an unfiltered view would show)
            val extra = live("zz-own", mapOf(own to 9L), JsonValue.Obj(mapOf("updated_at" to JsonValue.Int(1))))
            val ownView = PeerView(own, v.getValue("A").map { it.with(mapOf(own to 9L), null) } + extra)
            assertEquals(reference, Engine.fold(local, peers + ownView, ownDeviceId = own), "$own own view")
            assertNotEquals(reference, Engine.fold(local, peers + ownView), "$own own view counts without the filter")
            // folding the result back in changes nothing
            val settled = apply(local, reference.outcome)
            val again = Engine.fold(settled, peers)
            assertTrue(again.outcome.upserts.isEmpty() && again.outcome.deletes.isEmpty() && again.outcome.copies.isEmpty(), "$own idempotent")
        }
        // all three devices against empty local, in all six orders
        val all = names.map { PeerView(it, v.getValue(it)) }
        val ref = Engine.fold(emptyMap(), all)
        val orders = listOf(
            listOf(0, 1, 2), listOf(0, 2, 1), listOf(1, 0, 2), listOf(1, 2, 0), listOf(2, 0, 1), listOf(2, 1, 0),
        )
        for (o in orders) assertEquals(ref, Engine.fold(emptyMap(), o.map { all[it] }), "order $o")
        // an invalid device id is reported once per view
        assertEquals(listOf("?"), Engine.fold(emptyMap(), listOf(PeerView("bad id", emptyList()))).badViews)
    }

    @Test
    fun conflict_copy_ids_match_vectors() {
        val em = MergeVectors.expectedMerge()
        val copies = arr(em["conflict_copies"])
        assertEquals(2, copies.size)
        for (c in copies) {
            val o = obj(c)
            assertEquals(str(o["content_digest"]), sha(o["loser_wrapper"]!!))
            assertEquals(str(o["copy_id"]), ConflictCopy.id(str(o["original_id"])!!, str(o["content_digest"])!!))
            assertEquals(str(o["content_digest"]), ConflictCopy.contentDigest(o["loser_wrapper"]!!))
        }
        assertFailsWith<EngineException> { ConflictCopy.id(LOGIN_TIE, "") }
        // Upper-case hyphenated uuid is still a uuid namespace; non-uuid ids hash through the URL namespace.
        assertEquals(ConflictCopy.id(LOGIN_TIE, "x"), ConflictCopy.id(LOGIN_TIE.uppercase(), "x"))
        assertNotEquals(ConflictCopy.id("lic:abc", "x"), ConflictCopy.id("lic:abd", "x"))
    }

    @Test
    fun canonical_sha256_per_state() {
        val em = MergeVectors.expectedMerge()
        for (key in listOf("engine_states", "bridge_stored_states")) {
            for (j in arr(em[key])) {
                val o = obj(j)
                if (o["item"] is JsonValue.Obj) {
                    assertEquals(str(o["canonical_sha256"]), sha(o["item"]!!), str(o["id"]) ?: "")
                } else {
                    assertEquals(JsonValue.Null, o["canonical_sha256"])
                }
            }
        }
    }

    @Test
    fun equal_vectors_merge_is_idempotent() {
        // Fuzz finding S-1 (2026-10-24): a no-op upsert and conflict must not repeat every round.
        val item = JsonValue.Obj(mapOf("updated_at" to JsonValue.Int(0), "v" to JsonValue.Int(0)))
        val alive = live("item-1", emptyMap(), item)
        val gone = tomb("item-1", emptyMap(), null)
        var out = Engine.merge(mapOf("item-1" to alive), listOf(gone))
        assertTrue(out.upserts.isEmpty() && out.deletes.isEmpty() && out.conflicts.isEmpty() && out.copies.isEmpty())
        out = Engine.merge(mapOf("item-1" to gone), listOf(alive))
        assertEquals(listOf(alive), out.upserts)
        assertEquals(1, out.conflicts.size)
        assertTrue(Engine.merge(mapOf("item-1" to alive), listOf(alive)).upserts.isEmpty())
    }

    @Test
    fun edit_beats_delete() {
        val item = JsonValue.Obj(mapOf("updated_at" to JsonValue.Int(5), "x" to JsonValue.Str("live")))
        val local = live("i", mapOf("b" to 1L, "c" to 0L), item)
        assertEquals(mapOf("b" to 1L), local.vv)
        val tomb = tomb("i", mapOf("c" to 1L), 9)
        // remote delete vs local edit: live side kept with the merged vector
        var out = Engine.merge(mapOf("i" to local), listOf(tomb))
        assertEquals(listOf(live("i", mapOf("b" to 1L, "c" to 1L), item)), out.upserts)
        assertEquals(emptyList(), out.deletes)
        assertEquals(1, out.conflicts.size)
        // local delete vs remote edit
        out = Engine.merge(mapOf("i" to tomb), listOf(local))
        assertEquals(listOf(mapOf("b" to 1L, "c" to 1L)), out.upserts.map { it.vv })
        assertEquals(item, out.upserts.first().item)
        // both deleted: max deleted_at, only when it differs from local
        val t2 = tomb("i", mapOf("b" to 1L), 12)
        out = Engine.merge(mapOf("i" to tomb), listOf(t2))
        assertEquals(listOf(tomb("i", mapOf("b" to 1L, "c" to 1L), 12)), out.deletes)
        out = Engine.merge(mapOf("i" to tomb), listOf(tomb))
        assertTrue(out.deletes.isEmpty() && out.upserts.isEmpty())
    }

    @Test
    fun updated_at_tie_breaks_by_digest() {
        val v = MergeVectors.deviceStates()
        val a = v.getValue("A").first { it.itemId == LOGIN_TIE }
        val b = v.getValue("B").first { it.itemId == LOGIN_TIE }
        val expectedWinner = if (sha(a.item!!) > sha(b.item!!)) a else b
        for ((l, r) in listOf(a to b, b to a)) {
            val out = Engine.merge(mapOf(l.itemId to l), listOf(r))
            assertEquals(1, out.upserts.size)
            assertEquals(expectedWinner.item, out.upserts[0].item)
            assertEquals(mapOf(A to 2L, B to 1L), out.upserts[0].vv)
            assertEquals(listOf("9e9a151e-b5a5-5e08-b722-1d16a2f77f8d"), out.copies.map { it.itemId })
            assertEquals(mapOf(A to 1L, B to 1L), out.copies[0].vv)
        }
        // a float / bool / negative updated_at counts as 0
        val x = live("i", mapOf("a" to 1L), JsonValue.Obj(mapOf("updated_at" to JsonValue.Float(9e9))))
        val y = live("i", mapOf("b" to 1L), JsonValue.Obj(mapOf("updated_at" to JsonValue.Int(1))))
        assertEquals(y.item, Engine.merge(mapOf("i" to x), listOf(y)).upserts.first().item)
    }

    @Test
    fun validation_and_version_vectors() {
        fun rejects(message: String? = null, block: () -> Unit) {
            val e = assertFailsWith<EngineException> { block() }
            if (message != null) assertEquals(message, e.message)
        }
        rejects("item_id must be 1..128 ASCII chars from [A-Za-z0-9._:-]") { ItemState("é", emptyMap(), true, null, null) }
        rejects("invalid counter for a: -1") { ItemState("i", mapOf("a" to -1L), true, null, null) }
        rejects("invalid counter for a: ${1L shl 53}") { ItemState("i", mapOf("a" to (1L shl 53)), true, null, null) }
        rejects("invalid device id: é") { ItemState("i", mapOf("é" to 1L), true, null, null) }
        rejects("deleted_at must be None or an int in 0..2**53-1") { ItemState("i", emptyMap(), true, -1, null) }
        rejects("item must be None exactly when deleted") { ItemState("i", emptyMap(), false, null, null) }
        rejects("item must be None exactly when deleted") {
            ItemState("i", emptyMap(), true, null, JsonValue.Obj(emptyMap()))
        }
        rejects("item must be a dict") { ItemState("i", emptyMap(), false, null, JsonValue.Arr(emptyList())) }
        rejects("integer out of range") {
            ItemState("i", emptyMap(), false, null, JsonValue.Obj(mapOf("n" to JsonValue.Int(Long.MIN_VALUE))))
        }
        rejects("non-finite float in item") {
            ItemState("i", emptyMap(), false, null, JsonValue.Obj(mapOf("n" to JsonValue.Float(Double.NaN))))
        }
        var deep: JsonValue = JsonValue.Null
        repeat(65) { deep = JsonValue.Arr(listOf(deep)) }
        rejects("item nesting too deep") {
            ItemState("i", emptyMap(), false, null, JsonValue.Obj(mapOf("d" to deep)))
        }
        assertEquals(VersionVector.Relation.EQUAL, VersionVector.compare(mapOf("a" to 1L), mapOf("a" to 1L, "b" to 0L)))
        assertEquals(VersionVector.Relation.A, VersionVector.compare(mapOf("a" to 2L), mapOf("a" to 1L)))
        assertEquals(VersionVector.Relation.CONCURRENT, VersionVector.compare(mapOf("a" to 1L), mapOf("b" to 1L)))
        assertEquals(VersionVector.Relation.B, VersionVector.compare(emptyMap(), mapOf("b" to 1L)))
        assertEquals(mapOf("a" to 1L, "b" to 1L), VersionVector.bump(mapOf("a" to 1L, "z" to 0L), "b"))
        rejects("counter for a overflows") { VersionVector.bump(mapOf("a" to (1L shl 53) - 1), "a") }
        assertEquals(mapOf("a" to 2L, "b" to 3L), VersionVector.max(mapOf("a" to 1L, "b" to 3L), mapOf("a" to 2L)))
        val s = tomb("i", emptyMap(), null)
        rejects("duplicate remote item id: i") { Engine.merge(emptyMap(), listOf(s, s)) }
        rejects("local state keyed j is inconsistent") { Engine.merge(mapOf("j" to s), emptyList()) }
    }

    @Test
    fun updated_at_boundaries_in_the_winner_rule() {
        fun withAt(dev: String, at: JsonValue, tag: String) =
            live("i", mapOf(dev to 1L), JsonValue.Obj(mapOf("updated_at" to at, "t" to JsonValue.Str(tag))))
        val big = withAt("a", JsonValue.Int(VersionVector.MAX_COUNTER), "big")
        val small = withAt("b", JsonValue.Int(1), "small")
        // 2^53-1 is a valid updated_at and beats 1 in both directions
        for ((l, r) in listOf(big to small, small to big)) {
            assertEquals(big.item, Engine.merge(mapOf("i" to l), listOf(r)).upserts.single().item)
        }
        // negative, > 2^53-1 and bool all count as 0, so they lose to 1 and tie with 0 (decided by digest)
        for (bad in listOf(JsonValue.Int(-5), JsonValue.Int(1L shl 53), JsonValue.Bool(true), JsonValue.Bool(false))) {
            val x = withAt("a", bad, "x")
            for ((l, r) in listOf(x to small, small to x)) {
                assertEquals(small.item, Engine.merge(mapOf("i" to l), listOf(r)).upserts.single().item, "$bad vs 1")
            }
            val zero = withAt("b", JsonValue.Int(0), "zero")
            val expected = if (sha(x.item!!) > sha(zero.item!!)) x else zero
            for ((l, r) in listOf(x to zero, zero to x)) {
                assertEquals(expected.item, Engine.merge(mapOf("i" to l), listOf(r)).upserts.single().item, "$bad vs 0")
            }
        }
    }

    @Test
    fun nesting_depth_64_accepted_65_rejected() {
        fun nested(levels: Int): JsonValue {
            var d: JsonValue = JsonValue.Null
            repeat(levels) { d = JsonValue.Arr(listOf(d)) }
            return JsonValue.Obj(mapOf("d" to d))
        }
        // the object is depth 0, so "d" holding 63 arrays reaches depth 64 (Null) and 64 arrays reaches 65
        ItemState("i", emptyMap(), false, null, nested(63))
        assertFailsWith<EngineException> { ItemState("i", emptyMap(), false, null, nested(64)) }
    }
}
