package app.localgatekeys.core.group

import app.localgatekeys.core.engine.Engine
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.FixedRandom
import app.localgatekeys.core.support.MergeVectors
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.fail

/** Port of Swift `GroupTests`. */
class GroupTest {
    companion object {
        const val GROUP_ID = "5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64"
        const val T0 = MergeVectors.T0
    }

    private class Dev(val name: String, val id: String, val counter: Long, val written: Long)

    private val devices = listOf(
        Dev("A", MergeVectors.A, 7, 900), Dev("B", MergeVectors.B, 4, 880), Dev("C", MergeVectors.C, 3, 860),
    )

    // ---- helpers ----

    private fun epoch1Hex(field: String): String {
        val epochs = obj(Vectors.json(Vectors.sync("expected.json")).obj().fields["epochs"])
        return str(obj(epochs["1"])[field])!!
    }

    private fun key(): GroupKey = GroupKey(GROUP_ID, 1, Vectors.hex(epoch1Hex("group_key_hex")))

    private fun file(name: String): ByteArray = Vectors.sync("devices/$name.lgksync").readBytes()

    private fun decodeAll(): Map<String, Pair<ViewHeader, List<ItemState>>> {
        val gk = key()
        return devices.associate { it.name to ViewFile.decode(file(it.name), gk, it.id) }
    }

    private fun reason(body: () -> Any?): String? = try {
        body()
        fail("expected SyncFormatException")
    } catch (e: SyncFormatException) {
        e.reason
    }

    private fun splitView(raw: ByteArray): Pair<ByteArray, List<JsonValue>> {
        val magic = ViewFile.MAGIC.size
        val end = (magic until raw.size).first { raw[it] == 0x0A.toByte() }
        val header = raw.copyOfRange(magic, end)
        val blob = raw.copyOfRange(end + 1, raw.size)
        val plain = CryptoBox.openGcm(Vectors.hex(epoch1Hex("file_key_hex")), blob.copyOfRange(0, 12), blob.copyOfRange(12, blob.size), header)
        return header to CanonicalJson.parse(plain).arr()
    }

    private fun rewrap(header: ByteArray, records: List<JsonValue>): ByteArray {
        val nonce = ByteArray(12) { 7 }
        val body = CryptoBox.sealGcm(
            Vectors.hex(epoch1Hex("file_key_hex")), nonce,
            CanonicalJson.encode(JsonValue.Arr(records), Dialect.UTF8), header,
        )
        return ViewFile.MAGIC + header + byteArrayOf(0x0A) + nonce + body
    }

    private fun withField(rec: JsonValue, k: String, v: JsonValue?): JsonValue {
        val m = obj(rec).toMutableMap()
        if (v == null) m.remove(k) else m[k] = v
        return JsonValue.Obj(m)
    }

    // ---- keys ----

    @Test
    fun record_and_file_keys_match_vectors() {
        val gk = key()
        assertEquals(epoch1Hex("record_key_hex"), Vectors.hexString(gk.recordKey))
        assertEquals(epoch1Hex("file_key_hex"), Vectors.hexString(gk.fileKey))
        assertEquals("4c474b53594e43310a", Vectors.hexString(ViewFile.MAGIC))
        assertEquals("bad-group-key", reason { GroupKey("bad id", 1, ByteArray(32)) })
        assertEquals("bad-group-key", reason { GroupKey("g", 0, ByteArray(32)) })
        assertEquals("bad-group-key", reason { GroupKey("g", 1, byteArrayOf(1, 2)) })
    }

    // ---- device files ----

    @Test
    fun decode_device_files_A_B_C() {
        val views = decodeAll()
        val inputs = MergeVectors.deviceStates()
        // States every other device dominates carry placeholder content in MergeVectors.
        val placeholders = setOf(
            "A" to MergeVectors.LOGIN_DELETED, "A" to MergeVectors.BOOKMARK, "B" to MergeVectors.LOGIN_DELETED,
            "C" to MergeVectors.LOGIN_EDITED, "C" to MergeVectors.LOGIN_TIE,
        )
        for (d in devices) {
            val v = views.getValue(d.name)
            assertEquals(ViewHeader(1, GROUP_ID, d.id, 1, d.counter, T0 + d.written), v.first)
            val want = inputs.getValue(d.name).sortedBy { it.itemId }
            assertEquals(want.map { it.itemId }, v.second.map { it.itemId }, d.name)
            for ((got, exp) in v.second.zip(want)) {
                assertEquals(exp.vv, got.vv, "${d.name} ${got.itemId}")
                assertEquals(exp.deleted, got.deleted)
                assertEquals(exp.deletedAt, got.deletedAt)
                if ((d.name to got.itemId) in placeholders) assertNotNull(got.item) else assertEquals(exp, got, "${d.name} ${got.itemId}")
            }
        }
    }

    @Test
    fun decoded_device_files_merge_in_all_six_orders() {
        val views = decodeAll().mapValues { it.value.second }
        val expected = MergeVectors.arr(MergeVectors.expectedMerge()["engine_states"]).map(MergeVectors::state)
        val orders = listOf("ABC", "ACB", "BAC", "BCA", "CAB", "CBA")
        for (order in orders) {
            val local = HashMap<String, ItemState>()
            for (s in views.getValue(order.substring(0, 1))) local[s.itemId] = s
            for (ch in order.drop(1)) {
                val out = Engine.merge(local, views.getValue(ch.toString()))
                for (s in out.upserts + out.deletes + out.copies) local[s.itemId] = s
            }
            val got = local.values.sortedBy { it.itemId }
            assertEquals(expected, got, order)
            for ((g, e) in got.zip(expected)) {
                if (g.item != null) {
                    assertContentEquals(CanonicalJson.encode(e.item!!, Dialect.UTF8), CanonicalJson.encode(g.item, Dialect.UTF8))
                }
            }
        }
    }

    @Test
    fun reencode_with_vector_nonces_is_byte_identical() {
        val gk = key()
        val views = decodeAll()
        for (d in devices) {
            val v = views.getValue(d.name)
            val out = ViewFile.encode(gk, d.id, d.counter, v.second.reversed(), FixedClock(T0 + d.written), DetRand("view|${d.name}"))
            assertContentEquals(file(d.name), out, d.name)
        }
    }

    @Test
    fun encode_decode_round_trip_and_encode_errors() {
        val gk = key()
        val states = decodeAll().getValue("B").second
        val sys = SystemRandomSource()
        val raw = ViewFile.encode(gk, "phone-1", 2, states, FixedClock(5), sys)
        val back = ViewFile.decode(raw, gk, null)
        assertEquals(states, back.second)
        assertEquals("phone-1", back.first.deviceId)
        assertEquals("nonce-reuse", reason { ViewFile.encode(gk, "phone-1", 2, states, FixedClock(5), FixedRandom(ByteArray(12) { 1 })) })
        assertEquals("duplicate-id", reason { ViewFile.encode(gk, "phone-1", 2, listOf(states[0], states[0]), FixedClock(5), sys) })
        assertEquals("bad-header", reason { ViewFile.encode(gk, "phone 1", 2, states, FixedClock(5), sys) })
        assertEquals("bad-header", reason { ViewFile.encode(gk, "p", -1, states, FixedClock(5), sys) })
        assertEquals("too-many-records", reason { ViewFile.encode(gk, "p", 1, states, FixedClock(5), sys, maxRecords = 2) })
        assertEquals("bad-nonce", reason { ViewFile.encode(gk, "p", 1, states, FixedClock(5), FixedRandom(byteArrayOf(1))) })
        // Empty view still round-trips.
        val empty = ViewFile.encode(gk, "p", 0, emptyList(), FixedClock(0), sys)
        assertEquals(emptyList(), ViewFile.decode(empty, gk, "p").second)
    }

    // ---- tampering ----

    @Test
    fun tampered_header_and_body() {
        val gk = key()
        val raw = file("A")
        val m = ViewFile.MAGIC.size
        val headerEnd = (m until raw.size).first { raw[it] == 0x0A.toByte() }
        val header = String(raw, m, headerEnd - m, Charsets.UTF_8)
        fun flip(i: Int): ByteArray = raw.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
        fun withHeader(h: String): ByteArray = ViewFile.MAGIC + h.toByteArray(Charsets.UTF_8) + raw.copyOfRange(headerEnd, raw.size)
        fun dec(r: ByteArray, k: GroupKey = gk, dev: String? = MergeVectors.A): String? = reason { ViewFile.decode(r, k, dev) }

        assertEquals("bad-magic", dec(flip(0)))
        assertEquals("bad-header", dec(flip(m)))
        assertEquals("bad-header", dec(raw.copyOfRange(0, headerEnd)))
        assertEquals("auth-failed", dec(withHeader(header.replace("\"counter\":7", "\"counter\":8"))))
        assertEquals("header-noncanonical", dec(withHeader(header.replace("\"counter\":7", "\"counter\": 7"))))
        assertEquals("bad-header", dec(withHeader(header.replace("\"counter\":7", "\"counter\":7.0"))))
        assertEquals("bad-header", dec(withHeader(header.replace("\"counter\":7", "\"counter\":true"))))
        assertEquals("bad-header", dec(withHeader(header.replace("\"format\":1", "\"format\":2"))))
        assertEquals("epoch-mismatch", dec(withHeader(header.replace("\"epoch\":1", "\"epoch\":2"))))
        assertEquals("group-mismatch", dec(withHeader(header.replace(GROUP_ID, "other-group"))))
        assertEquals("device-mismatch", dec(raw, gk, MergeVectors.B))
        assertEquals("auth-failed", dec(raw, GroupKey(GROUP_ID, 1, ByteArray(32) { 9 })))
        assertEquals("auth-failed", dec(flip(headerEnd + 1)))
        assertEquals("auth-failed", dec(flip(raw.size / 2 + headerEnd / 2)))
        assertEquals("auth-failed", dec(flip(raw.size - 1)))
        assertEquals("bad-payload", dec(raw.copyOfRange(0, headerEnd + 28)))
        assertEquals("too-large", reason { ViewFile.decode(raw, gk, null, maxBytes = raw.size - 1) })
        assertEquals("too-many-records", reason { ViewFile.decode(raw, gk, null, maxRecords = 2) })
    }

    @Test
    fun tampered_records() {
        val gk = key()
        val (header, recs) = splitView(file("C"))
        ViewFile.decode(rewrap(header, recs), gk, null)
        val live = recs[0]
        val tomb = recs.first { obj(it)["deleted"] == JsonValue.Bool(true) }
        fun check(r: List<JsonValue>, want: String) {
            assertEquals(want, reason { ViewFile.decode(rewrap(header, r), gk, null) }, want)
        }
        fun ct(rec: JsonValue): ByteArray = Base64Std.decodeStrict(str(obj(rec)["ct"])!!)
        val flipped = ct(live).also { it[20] = (it[20].toInt() xor 1).toByte() }

        check(listOf(live, live), "duplicate-id")
        check(listOf(JsonValue.Str("x")), "bad-payload")
        check(listOf(withField(live, "extra", JsonValue.Null)), "bad-fields")
        check(listOf(withField(live, "ct", null)), "bad-fields")
        check(listOf(withField(live, "deleted", JsonValue.Int(0))), "bad-fields")
        check(listOf(withField(live, "deleted_at", JsonValue.Int(-1))), "bad-fields")
        check(listOf(withField(live, "ct", JsonValue.Int(1))), "bad-fields")
        check(listOf(withField(live, "id", JsonValue.Str("not valid"))), "invalid-state")
        check(listOf(withField(live, "vv", JsonValue.Obj(mapOf("a" to JsonValue.Bool(true))))), "invalid-state")
        check(listOf(withField(live, "ct", JsonValue.Str(""))), "empty-ct")
        check(listOf(withField(live, "deleted_at", JsonValue.Int(5))), "invalid-state")
        check(listOf(withField(live, "ct", JsonValue.Str("AAAA="))), "bad-ct")
        check(listOf(withField(live, "ct", JsonValue.Str("AAAA"))), "bad-ct")
        check(listOf(withField(live, "ct", JsonValue.Str(Base64Std.encode(flipped)))), "auth-failed")
        check(listOf(withField(live, "vv", JsonValue.Obj(mapOf(MergeVectors.A to JsonValue.Int(9))))), "auth-failed")
        check(listOf(withField(tomb, "deleted_at", JsonValue.Int(1))), "auth-failed")
        check(listOf(withField(live, "id", JsonValue.Str("99999999-aaaa-4000-8000-000000000009"))), "auth-failed")

        // A key holder sealing bad plaintexts.
        fun sealed(id: String, deleted: Boolean, plain: ByteArray): JsonValue {
            val vv = JsonValue.Obj(mapOf("a" to JsonValue.Int(1)))
            val at: JsonValue = if (deleted) JsonValue.Int(1) else JsonValue.Null
            val aad = CanonicalJson.encode(
                JsonValue.Obj(
                    mapOf(
                        "label" to JsonValue.Str("lgk-sync-item-v1"), "id" to JsonValue.Str(id), "vv" to vv,
                        "deleted" to JsonValue.Bool(deleted), "deleted_at" to at, "epoch" to JsonValue.Int(1),
                    ),
                ),
                Dialect.UTF8,
            )
            val nonce = ByteArray(12) { 3 }
            val body = CryptoBox.sealGcm(gk.recordKey, nonce, plain, aad)
            return JsonValue.Obj(
                mapOf(
                    "id" to JsonValue.Str(id), "vv" to vv, "deleted" to JsonValue.Bool(deleted), "deleted_at" to at,
                    "ct" to JsonValue.Str(Base64Std.encode(nonce + body)),
                ),
            )
        }
        fun txt(s: String) = s.toByteArray(Charsets.UTF_8)
        check(listOf(sealed("i", true, byteArrayOf(0x7B, 0x7D))), "bad-item")
        check(listOf(sealed("i", false, txt("[1]"))), "bad-item")
        check(listOf(sealed("i", false, txt("{"))), "bad-item")
        check(listOf(sealed("i", false, txt("{\"a\":1,\"a\":2}"))), "bad-item")
        check(listOf(sealed("i", false, txt("{\"id\":\"j\"}"))), "id-mismatch")
        check(listOf(sealed("i", false, txt("{\"record\":{\"id\":\"j\"}}"))), "id-mismatch")
        ViewFile.decode(rewrap(header, listOf(sealed("i", false, txt("{\"id\":\"i\",\"record\":{\"id\":\"j\"}}")))), gk, null)
        val ok = ViewFile.decode(rewrap(header, listOf(sealed("i", true, ByteArray(0)))), gk, null)
        assertEquals(listOf(ItemState("i", mapOf("a" to 1L), true, 1L, null)), ok.second)
    }
}
