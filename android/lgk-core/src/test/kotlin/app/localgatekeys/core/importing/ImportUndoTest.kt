package app.localgatekeys.core.importing

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.support.Vectors
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.Test
import app.localgatekeys.core.support.assertEq
import app.localgatekeys.core.support.assertTr

class ImportUndoTest {
    private fun r(id: String, label: String, at: Long = 1) = mapOf("id" to JsonValue.Str(id), "label" to JsonValue.Str(label), "updated_at" to JsonValue.Int(at))

    @Test
    fun undoKeepsWhatChangedSince() {
        val before = mapOf("r1" to r("r1", "old"), "r2" to r("r2", "old"), "x" to r("x", "same"))
        val after = mapOf(
            "r1" to r("r1", "imported"), "r2" to r("r2", "imported"), "x" to r("x", "same"),
            "c1" to r("c1", "new"), "c2" to r("c2", "new"),
        )
        val j = ImportUndo.journal("id", 100, "bitwarden", before, after)
        assertEquals(setOf("c1", "c2"), j.created.keys)
        assertEquals(setOf("r1", "r2"), j.replaced.keys)
        assertEquals(j.toString(), ImportUndo.Journal.of(j.json()).toString())
        assertEquals(j.json(), ImportUndo.Journal.of(j.json())!!.json())
        val current = after + mapOf("c2" to r("c2", "edited"), "r2" to r("r2", "edited"))
        val plan = ImportUndo.plan(j, current, 200)
        assertEquals(listOf("c1"), plan.trash)
        assertEquals(setOf("r1"), plan.restore.keys)
        assertEquals(JsonValue.Int(200), plan.restore.getValue("r1")["updated_at"])
        assertEquals(listOf("c2", "r2"), plan.kept)
        assertTrue(j.usable(100 + ImportUndo.MAX_AGE_SECONDS))
        assertFalse(j.usable(101 + ImportUndo.MAX_AGE_SECONDS))
    }

    @Test
    fun undoVectors() {
        val root = Vectors.json(Vectors.optional("import/report/undo.json"))
        val list = (root as? JsonValue.Arr)?.items ?: ((root as JsonValue.Obj).fields["cases"] as JsonValue.Arr).items
        fun recs(v: JsonValue?): Map<String, Map<String, JsonValue>> = when (v) {
            is JsonValue.Obj -> v.fields.mapValues { (it.value as JsonValue.Obj).fields }
            is JsonValue.Arr -> v.items.associate { val f = (it as JsonValue.Obj).fields; (f.getValue("id") as JsonValue.Str).v to f }
            else -> emptyMap()
        }
        for (c in list.map { (it as JsonValue.Obj).fields }) {
            val journal = ImportUndo.Journal.of(c["journal"]) ?: error("journal")
            val now = (c["now"] as? JsonValue.Int)?.v ?: 0L
            val plan = ImportUndo.plan(journal, recs(c["current_records"]), now)
            val after = ImportUndo.applied(recs(c["current_records"]), plan)
            assertEq("${c["name"]} ids", recs(c["expected_after_undo"]).keys, after.keys)
            if (c["now"] != null) assertEq("${c["name"]}", recs(c["expected_after_undo"]), after)
            val kept = (c["expected_kept_ids"] as JsonValue.Arr).items.map { (it as JsonValue.Str).v }
            assertEq("${c["name"]} kept", kept.sorted(), plan.kept.sorted())
        }
    }
}
