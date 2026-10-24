package app.localgatekeys.core.records

import app.localgatekeys.core.engine.Engine
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.MergeOutcome
import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.engine.VersionVector
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MergeVectors
import app.localgatekeys.core.support.MergeVectors.A
import app.localgatekeys.core.support.MergeVectors.NOTE
import app.localgatekeys.core.support.MergeVectors.T0
import app.localgatekeys.core.support.MergeVectors.arr
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Port of Swift `RecordsTests`; the device-view tests decode the committed A, B and C device view files. */
class RecordsTest {
    private val GROUP_ID = "5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64"
    private val phone = "d4444444-0000-4000-8000-00000000000d"

    private fun load(file: String): Map<String, JsonValue> = Vectors.json(Vectors.sync(file)).obj().fields

    private fun licenseKeys(): Map<String, ByteArray> {
        val o = load("license_state.json")
        return mapOf(str(o["key_id"])!! to Base64Std.decodeStrict(str(o["public_key_b64"])!!))
    }

    private fun reason(body: () -> Any?): String? = try {
        body()
        "accepted"
    } catch (e: RecordException) {
        e.reason
    }

    private fun outcome(upserts: List<ItemState> = emptyList(), deletes: List<ItemState> = emptyList(), copies: List<ItemState> = emptyList()) =
        MergeOutcome(upserts, deletes, emptyList(), copies)

    private fun canon(v: JsonValue): ByteArray = CanonicalJson.encode(v, Dialect.UTF8)

    // MARK: wrapper

    @Test
    fun schema_cases() {
        val rows = arr(load("schema_cases.json")["cases"])
        assertTrue(rows.size >= 10)
        for (row in rows) {
            val c = obj(row)
            val name = str(c["name"])!!
            val state = ItemState(str(c["item_id"])!!, mapOf("a" to 1L), false, null, c["wrapper"]!!)
            assertEquals(str(c["expect"]), reason { Wrapper.unwrap(state, false) }, name)
        }
    }

    @Test
    fun wrapper_make_rank_rule() {
        fun rec(u: JsonValue?): JsonValue {
            val m = linkedMapOf<String, JsonValue>("id" to JsonValue.Str("x"), "kind" to JsonValue.Str("note"))
            if (u != null) m["updated_at"] = u
            return JsonValue.Obj(m)
        }
        fun rank(w: JsonValue): JsonValue? = obj(w)["updated_at"]
        assertEquals(JsonValue.Int(5), rank(Wrapper.make(Namespace.ITEM, rec(JsonValue.Int(5)))))
        assertEquals(JsonValue.Int(0), rank(Wrapper.make(Namespace.ITEM, rec(JsonValue.Float(5.0)))))
        assertEquals(JsonValue.Int(0), rank(Wrapper.make(Namespace.ITEM, rec(JsonValue.Int(1L shl 53)))))
        assertEquals(JsonValue.Int(0), rank(Wrapper.make(Namespace.ITEM, rec(JsonValue.Int(-1)))))
        assertEquals(JsonValue.Int(0), rank(Wrapper.make(Namespace.ITEM, rec(null))))
        assertEquals(JsonValue.Int(0), rank(Wrapper.make(Namespace.LICENSE, rec(JsonValue.Int(5)))))
        assertEquals(JsonValue.Int(1), obj(Wrapper.make(Namespace.ENTRY, rec(null)))["schema"])
        assertEquals(JsonValue.Int((1L shl 53) - 1), rank(Wrapper.make(Namespace.ITEM, rec(JsonValue.Int((1L shl 53) - 1)))))
    }

    // MARK: licence

    @Test
    fun license_vector_verifies() {
        val o = load("license_state.json")
        val keys = licenseKeys()
        val info = License.verify(o["bundle"]!!, keys)
        assertEquals("lic-vector-0001", info.licenseId)
        assertEquals("Ada Lovelace", info.name)
        assertEquals("2027-09-21", info.updatesUntil)
        assertEquals(str(o["state_id"]), License.stateId(info.licenseId))
        val wrapper = Wrapper.make(Namespace.LICENSE, o["bundle"]!!)
        assertEquals(o["wrapper"], wrapper)
        assertEquals(str(o["wrapper_canonical_hex"]), Vectors.hexString(canon(wrapper)))
        assertEquals("unknown-key", assertFailsWith<LicenseException> { License.verify(o["bundle"]!!, emptyMap()) }.reason)
    }

    @Test
    fun license_cases() {
        val o = load("license_state.json")
        val keys = licenseKeys()
        val rows = arr(o["cases"])
        assertTrue(rows.size >= 10)
        for (row in rows) {
            val c = obj(row)
            val name = str(c["name"])!!
            val state = ItemState(str(c["state_id"])!!, mapOf(A to 1L), false, null, c["wrapper"]!!)
            val isCopy = c["copy"] == JsonValue.Bool(true)
            val out = outcome(upserts = if (isCopy) emptyList() else listOf(state), copies = if (isCopy) listOf(state) else emptyList())
            val got: String? = try {
                val r = SyncMeta.applyRemote(out, emptyMap(), emptyMap(), phone, T0, keys)
                if (r.records.isEmpty() && r.meta.isEmpty() && r.licenses.isEmpty()) {
                    "dropped"
                } else {
                    assertEquals(c["wrapper"], r.records[state.itemId], name)
                    assertEquals(listOf(obj(c["wrapper"])["record"]), r.licenses, name)
                    assertEquals(state.vv, r.meta[state.itemId]?.vv, name)
                    "accepted"
                }
            } catch (e: RecordException) {
                assertEquals(state.itemId, e.itemId, name)
                e.reason
            }
            assertEquals(str(c["expect"]), got, name)
        }
    }

    @Test
    fun license_is_never_deleted_and_republished() {
        val o = load("license_state.json")
        val keys = licenseKeys()
        val sid = str(o["state_id"])!!
        val s = ItemState(sid, mapOf(A to 1L), false, null, o["wrapper"]!!)
        val r = SyncMeta.applyRemote(outcome(upserts = listOf(s)), emptyMap(), emptyMap(), phone, T0, keys)
        val tomb = ItemState(sid, mapOf(A to 2L), true, T0, null)
        val r2 = SyncMeta.applyRemote(outcome(deletes = listOf(tomb)), r.records, r.meta, phone, T0, keys)
        assertEquals(o["wrapper"], r2.records[sid])
        assertEquals(false, r2.meta[sid]?.deleted)
        assertEquals(mapOf(A to 2L, phone to 1L), r2.meta[sid]?.vv)
        // Same id, other bytes: bad-remote.
        val other = obj(o["wrapper"]).toMutableMap()
        other["record"] = JsonValue.Obj(obj(other["record"]) + ("extra" to JsonValue.Int(1)))
        val s3 = ItemState(sid, mapOf(A to 3L), false, null, JsonValue.Obj(other))
        assertEquals("bad-remote", reason { SyncMeta.applyRemote(outcome(upserts = listOf(s3)), r2.records, r2.meta, phone, T0, keys) })
        // No licence keys in this build: dropped without a write.
        val r4 = SyncMeta.applyRemote(outcome(upserts = listOf(s)), emptyMap(), emptyMap(), phone, T0, emptyMap())
        assertTrue(r4.records.isEmpty() && r4.meta.isEmpty())
        // A licence that is no longer stored goes quiet: never tombstoned.
        val view = SyncMeta.localView(emptyMap(), r2.meta, phone, T0)
        assertNull(view.states[sid])
    }

    // MARK: suffix

    @Test
    fun suffix_truncates_by_code_points() {
        assertEquals("Bank (sync conflict)", ConflictSuffix.apply("Bank", 512))
        assertEquals("Bank (sync conflict)", ConflictSuffix.apply("Bank (sync conflict)", 512))
        val key = "🔑" // 1 code point, 2 UTF-16 units, 4 UTF-8 bytes
        val long = key.repeat(600)
        val out = ConflictSuffix.apply(long, 512)
        assertEquals(512, out.codePointCount(0, out.length))
        assertEquals(key.repeat(496) + " (sync conflict)", out)
        // An odd limit lands inside the emoji's UTF-16 pair: it must keep whole code points.
        val odd = ConflictSuffix.apply(long, 17)
        assertEquals(key + " (sync conflict)", odd)
        // e + combining acute: 2 code points, 1 grapheme.
        val comb = "é".repeat(10)
        val cut = ConflictSuffix.apply(comb, 21)
        assertEquals(21, cut.codePointCount(0, cut.length))
        assertEquals(listOf(0x65, 0x301, 0x65, 0x301, 0x65), cut.codePoints().limit(5).toArray().toList())
        assertEquals(" (sync conflict)", ConflictSuffix.apply("abc", 10))
        assertEquals(" (sync conflict)", ConflictSuffix.apply("x", 0))
        assertEquals(str(MergeVectors.expectedMerge()["conflict_suffix"]), ConflictSuffix.SUFFIX)
    }

    // MARK: sync meta

    private class Dev(val name: String, val id: String, val counter: Long, val written: Long)

    private val devices = listOf(
        Dev("A", MergeVectors.A, 7, 900), Dev("B", MergeVectors.B, 4, 880), Dev("C", MergeVectors.C, 3, 860),
    )

    private fun groupKey(): GroupKey {
        val epochs = obj(Vectors.json(Vectors.sync("expected.json")).obj().fields["epochs"])
        return GroupKey(GROUP_ID, 1, Vectors.hex(str(obj(epochs["1"])["group_key_hex"])!!))
    }

    private fun deviceFile(name: String): ByteArray = Vectors.sync("devices/$name.lgksync").readBytes()

    /** The states of a committed device view file, decoded under the epoch-1 group key. */
    private fun view(name: String): List<ItemState> {
        val d = devices.first { it.name == name }
        return ViewFile.decode(deviceFile(name), groupKey(), d.id).second
    }

    @Test
    fun untouched_records_republish_identically() {
        for (d in devices) {
            val name = d.name
            val v = view(name)
            val out = Engine.merge(emptyMap(), v)
            val applied = SyncMeta.applyRemote(out, emptyMap(), emptyMap(), phone, T0 + 1000, emptyMap())
            assertEquals(v.count { !it.deleted }, applied.records.size, name)
            val local = SyncMeta.localView(applied.records, applied.meta, phone, T0 + 1000)
            assertEquals(applied.meta, local.meta, "$name: an untouched record must not look edited")
            val mine = local.states.values.sortedBy { it.itemId }
            assertEquals(v.size, mine.size)
            for ((got, exp) in mine.zip(v)) {
                assertEquals(exp, got, "$name ${got.itemId}")
                if (got.item != null) assertContentEquals(canon(exp.item!!), canon(got.item))
            }
            // Re-encoding with the generator's nonces gives the device file byte for byte.
            val raw = ViewFile.encode(groupKey(), d.id, d.counter, mine, FixedClock(T0 + d.written), DetRand("view|$name"))
            assertContentEquals(deviceFile(name), raw, name)
        }
        // Float and int survive: 100.0 stays 100.0.
        val text = view("A").mapNotNull { it.item }.map { String(canon(it), Charsets.UTF_8) }
        assertTrue(text.any { it.contains("\"f_100\":100.0") })
    }

    @Test
    fun fold_of_ABC_matches_bridge_stored_states() {
        val views = devices.map { PeerView(it.id, view(it.name)) }
        val fold = Engine.fold(emptyMap(), views)
        assertTrue(fold.quarantined.isEmpty() && fold.badViews.isEmpty())
        val applied = SyncMeta.applyRemote(fold.outcome, emptyMap(), emptyMap(), phone, T0 + 1000, emptyMap())
        val local = SyncMeta.localView(applied.records, applied.meta, phone, T0 + 1000)
        val want = arr(MergeVectors.expectedMerge()["bridge_stored_states"]).map(MergeVectors::state)
        assertEquals(want, local.states.values.sortedBy { it.itemId })
    }

    @Test
    fun local_edit_bumps_own_counter_once() {
        val v = view("A")
        val applied = SyncMeta.applyRemote(Engine.merge(emptyMap(), v), emptyMap(), emptyMap(), phone, T0, emptyMap())
        val records = applied.records.toMutableMap()
        val id = NOTE
        val w = obj(records[id])
        val rec = obj(w["record"]).toMutableMap()
        rec["title"] = JsonValue.Str("Edited on the phone")
        rec["updated_at"] = JsonValue.Int(T0 + 5)
        val edited = Normalise.normalForm(Namespace.ITEM, JsonValue.Obj(rec))
        records[id] = Wrapper.make(Namespace.ITEM, edited)
        assertEquals(JsonValue.Int(T0 + 5), obj(records[id])["updated_at"])
        val first = SyncMeta.localView(records, applied.meta, phone, T0 + 10)
        val before = v.first { it.itemId == id }.vv
        assertEquals(VersionVector.bump(before, phone), first.states[id]?.vv)
        // A second view without further edits does not bump again.
        val second = SyncMeta.localView(records, first.meta, phone, T0 + 20)
        assertEquals(first.states[id]?.vv, second.states[id]?.vv)
        assertEquals(first.meta, second.meta)
        // Other records are untouched.
        for (s in v) if (s.itemId != id) assertEquals(s, second.states[s.itemId])
        // Deleting locally: one tombstone with a bumped vector and deleted_at = now.
        records.remove(id)
        val third = SyncMeta.localView(records, second.meta, phone, T0 + 30)
        val tomb = third.states.getValue(id)
        assertTrue(tomb.deleted)
        assertEquals(T0 + 30, tomb.deletedAt)
        assertEquals(2L, tomb.vv[phone])
        val fourth = SyncMeta.localView(records, third.meta, phone, T0 + 40)
        assertEquals(tomb, fourth.states[id])
        // Tombstones older than 365 days are pruned.
        val later = SyncMeta.localView(records, third.meta, phone, T0 + 30 + 365L * 86400 + 1)
        assertNull(later.states[id])
        assertNull(later.meta[id])
    }

    @Test
    fun apply_remote_rules() {
        val v = view("A")
        val base = SyncMeta.applyRemote(Engine.merge(emptyMap(), v), emptyMap(), emptyMap(), phone, T0, emptyMap())
        val id = NOTE
        // Remote tombstone: deleted_at capped at now; stale tombstones ignored.
        val tomb = ItemState(id, mapOf(A to 5L), true, T0 + 999, null)
        val r = SyncMeta.applyRemote(outcome(deletes = listOf(tomb)), base.records, base.meta, phone, T0 + 10, emptyMap())
        assertNull(r.records[id])
        assertEquals(SyncMeta(null, null, null, mapOf(A to 5L), true, T0 + 10), r.meta[id])
        assertEquals(1, r.deleted)
        val old = ItemState(id, mapOf(A to 5L), true, 1L, null)
        val r2 = SyncMeta.applyRemote(outcome(deletes = listOf(old)), base.records, base.meta, phone, T0, emptyMap())
        assertEquals(base.records, r2.records)
        // A local edit made after the view was taken: vault-changed, nothing applied.
        val changed = base.records.toMutableMap()
        val rec = obj(obj(changed[id])["record"]).toMutableMap()
        rec["title"] = JsonValue.Str("x")
        changed[id] = Wrapper.make(Namespace.ITEM, JsonValue.Obj(rec))
        assertEquals("vault-changed", reason { SyncMeta.applyRemote(outcome(deletes = listOf(tomb)), changed, base.meta, phone, T0, emptyMap()) })
        // Copies are stored with the suffix and the loser's vector.
        val loser = v.first { it.itemId == id }
        val copyId = "9e9a151e-b5a5-5e08-b722-1d16a2f77f8e"
        val cw = obj(loser.item).toMutableMap()
        cw["id"] = JsonValue.Str(copyId)
        val copy = ItemState(copyId, loser.vv, false, null, JsonValue.Obj(cw))
        val r3 = SyncMeta.applyRemote(outcome(copies = listOf(copy)), base.records, base.meta, phone, T0, emptyMap())
        val stored = obj(obj(r3.records[copy.itemId])["record"])
        assertEquals(JsonValue.Str(copy.itemId), stored["id"])
        assertTrue(str(stored["title"])!!.endsWith(" (sync conflict)"))
        assertNull(obj(r3.records[copy.itemId])["id"])
        assertEquals(loser.vv, r3.meta[copy.itemId]?.vv)
        assertNotNull(r3.meta[copy.itemId])
    }
}
