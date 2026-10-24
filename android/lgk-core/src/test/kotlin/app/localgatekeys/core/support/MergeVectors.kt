package app.localgatekeys.core.support

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Hex
import java.security.MessageDigest

/** expected_merge.json helpers (CanonicalJson only). Port of Swift `Support/MergeVectors.swift`. */
object MergeVectors {
    const val A = "a1111111-0000-4000-8000-00000000000a"
    const val B = "b2222222-0000-4000-8000-00000000000b"
    const val C = "c3333333-0000-4000-8000-00000000000c"
    const val LOGIN_EDITED = "11111111-aaaa-4000-8000-000000000001"
    const val NOTE = "22222222-aaaa-4000-8000-000000000002"
    const val DESKTOP = "33333333-aaaa-4000-8000-000000000003"
    const val LOGIN_DELETED = "44444444-aaaa-4000-8000-000000000004"
    const val BOOKMARK = "55555555-aaaa-4000-8000-000000000005"
    const val NOTE_UNICODE = "66666666-aaaa-4000-8000-000000000006"
    const val LOGIN_TIE = "77777777-aaaa-4000-8000-000000000007"
    const val T0: Long = 1_790_000_000

    fun expectedMerge(): Map<String, JsonValue> = Vectors.json(Vectors.sync("expected_merge.json")).obj().fields

    fun arr(v: JsonValue?): List<JsonValue> = (v as? JsonValue.Arr)?.items ?: emptyList()

    fun obj(v: JsonValue?): Map<String, JsonValue> = (v as? JsonValue.Obj)?.fields ?: emptyMap()

    fun str(v: JsonValue?): String? = (v as? JsonValue.Str)?.v

    fun state(j: JsonValue): ItemState {
        val o = obj(j)
        val vv = HashMap<String, Long>()
        for ((k, v) in obj(o["vv"])) if (v is JsonValue.Int) vv[k] = v.v
        val at = (o["deleted_at"] as? JsonValue.Int)?.v
        val deleted = (o["deleted"] as? JsonValue.Bool)?.v ?: false
        val raw = o["item"]
        val item = if (raw == null || raw == JsonValue.Null) null else raw
        return ItemState(str(o["id"])!!, vv, deleted, at, item)
    }

    fun sha(v: JsonValue): String =
        Hex.lower(MessageDigest.getInstance("SHA-256").digest(CanonicalJson.encode(v, Dialect.UTF8)))

    /**
     * The A/B/C engine inputs (scripts/make_sync_vectors.py device_states), rebuilt from the
     * plain-JSON states in expected_merge.json. States every other device dominates get placeholder
     * content: a dominated state never reaches the result.
     */
    fun deviceStates(): Map<String, List<ItemState>> {
        val em = expectedMerge()
        val final = HashMap<String, ItemState>()
        for (j in arr(em["engine_states"])) {
            val s = state(j)
            final[s.itemId] = s
        }
        val loser = HashMap<String, JsonValue>()
        for (c in arr(em["conflict_copies"])) {
            val o = obj(c)
            loser[str(o["original_id"])!!] = o["loser_wrapper"]!!
        }
        fun live(id: String, vv: Map<String, Long>, item: JsonValue) = ItemState(id, vv, false, null, item)
        fun tomb(id: String, vv: Map<String, Long>, at: Long) = ItemState(id, vv, true, T0 + at, null)
        fun placeholder(id: String, label: String): JsonValue = JsonValue.Obj(
            mapOf(
                "ns" to JsonValue.Str("entry"),
                "schema" to JsonValue.Int(1),
                "updated_at" to JsonValue.Int(0),
                "record" to JsonValue.Obj(mapOf("id" to JsonValue.Str(id), "label" to JsonValue.Str(label))),
            ),
        )
        fun f(id: String): JsonValue = final.getValue(id).item!!
        return mapOf(
            "A" to listOf(
                live(LOGIN_EDITED, mapOf(A to 2L), f(LOGIN_EDITED)),
                live(NOTE, mapOf(A to 1L), f(NOTE)),
                live(DESKTOP, mapOf(B to 1L), f(DESKTOP)),
                live(LOGIN_DELETED, mapOf(A to 1L), placeholder(LOGIN_DELETED, "doomed")),
                live(BOOKMARK, mapOf(A to 1L), placeholder(BOOKMARK, "bookmark base")),
                live(LOGIN_TIE, mapOf(A to 2L), f(LOGIN_TIE)),
            ),
            "B" to listOf(
                live(LOGIN_EDITED, mapOf(A to 1L, B to 1L), loser.getValue(LOGIN_EDITED)),
                live(NOTE, mapOf(A to 1L), f(NOTE)),
                live(DESKTOP, mapOf(B to 1L), f(DESKTOP)),
                live(LOGIN_DELETED, mapOf(A to 1L), placeholder(LOGIN_DELETED, "doomed")),
                live(BOOKMARK, mapOf(A to 1L, B to 1L), f(BOOKMARK)),
                live(NOTE_UNICODE, mapOf(B to 1L), f(NOTE_UNICODE)),
                live(LOGIN_TIE, mapOf(A to 1L, B to 1L), loser.getValue(LOGIN_TIE)),
            ),
            "C" to listOf(
                live(LOGIN_EDITED, mapOf(A to 1L), placeholder(LOGIN_EDITED, "login base")),
                live(NOTE, mapOf(A to 1L), f(NOTE)),
                live(DESKTOP, mapOf(B to 1L), f(DESKTOP)),
                tomb(LOGIN_DELETED, mapOf(A to 1L, C to 1L), 300),
                tomb(BOOKMARK, mapOf(A to 1L, C to 1L), 350),
                live(LOGIN_TIE, mapOf(A to 1L), placeholder(LOGIN_TIE, "tie base")),
            ),
        )
    }
}
