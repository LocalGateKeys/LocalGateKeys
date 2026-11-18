package app.localgatekeys.core.importing

import app.localgatekeys.core.history.ItemHistory
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Scalars

/**
 * Undo of the last import (feature pack contract 2026-11-15 §6.1): one level, digest-checked. The journal (`last_import`
 * in the local store) names what the import created and what it replaced, with the digest each record had right after
 * the import. Anything changed since is kept.
 */
object ImportUndo {
    const val MAX_AGE_SECONDS = 7L * 86_400L

    data class Journal(
        val importId: String,
        val at: Long,
        val source: String,
        /** id -> digest written. */
        val created: Map<String, String>,
        /** id -> (record before the import, digest written). */
        val replaced: Map<String, Pair<Map<String, JsonValue>, String>>,
    ) {
        fun json(): JsonValue = JsonValue.Obj(
            mapOf(
                "import_id" to JsonValue.Str(importId),
                "at" to JsonValue.Int(at),
                "source" to JsonValue.Str(source),
                "created" to JsonValue.Obj(created.mapValues { JsonValue.Str(it.value) }),
                "replaced" to JsonValue.Obj(
                    replaced.mapValues { (_, v) -> JsonValue.Obj(mapOf("before" to JsonValue.Obj(v.first), "after" to JsonValue.Str(v.second))) },
                ),
            ),
        )

        /** Whether undo is still offered at [now] (7 days). */
        fun usable(now: Long): Boolean = now - at <= MAX_AGE_SECONDS && (created.isNotEmpty() || replaced.isNotEmpty())

        override fun toString(): String = "ImportUndo.Journal(created=${created.size}, replaced=${replaced.size})"

        companion object {
            fun of(v: JsonValue?): Journal? {
                val f = (v as? JsonValue.Obj)?.fields ?: return null
                val created = (f["created"] as? JsonValue.Obj)?.fields?.mapNotNull { (k, d) -> (d as? JsonValue.Str)?.v?.let { k to it } }?.toMap()
                    ?: return null
                val replaced = (f["replaced"] as? JsonValue.Obj)?.fields?.mapNotNull { (k, d) ->
                    val o = (d as? JsonValue.Obj)?.fields ?: return@mapNotNull null
                    val before = (o["before"] as? JsonValue.Obj)?.fields ?: return@mapNotNull null
                    val after = (o["after"] as? JsonValue.Str)?.v ?: return@mapNotNull null
                    k to (before to after)
                }?.toMap() ?: return null
                return Journal(
                    (f["import_id"] as? JsonValue.Str)?.v ?: return null, (f["at"] as? JsonValue.Int)?.v ?: return null,
                    (f["source"] as? JsonValue.Str)?.v ?: "", created, replaced,
                )
            }
        }
    }

    /**
     * The journal of an import that turned [before] into [after] (id -> record): ids new in [after] are created, ids
     * whose record changed are replaced.
     */
    fun journal(importId: String, at: Long, source: String, before: Map<String, Map<String, JsonValue>>, after: Map<String, Map<String, JsonValue>>): Journal {
        val created = LinkedHashMap<String, String>()
        val replaced = LinkedHashMap<String, Pair<Map<String, JsonValue>, String>>()
        for (id in after.keys.sortedWith(Scalars::compare)) {
            val now = after.getValue(id)
            val old = before[id]
            val d = ItemHistory.digest(JsonValue.Obj(now))
            if (old == null) created[id] = d else if (ItemHistory.digest(JsonValue.Obj(old)) != d) replaced[id] = old to d
        }
        return Journal(importId, at, source, created, replaced)
    }

    /** What undo does: [trash] moves to Recently deleted, [restore] gets its record back, [kept] changed since. */
    data class Plan(val trash: List<String>, val restore: Map<String, Map<String, JsonValue>>, val kept: List<String>)

    /** The undo of [journal] against [current] (id -> record, live records only). */
    fun plan(journal: Journal, current: Map<String, Map<String, JsonValue>>, now: Long): Plan {
        val trash = ArrayList<String>()
        val restore = LinkedHashMap<String, Map<String, JsonValue>>()
        val kept = ArrayList<String>()
        for ((id, digest) in journal.created.entries.sortedWith { a, b -> Scalars.compare(a.key, b.key) }) {
            val r = current[id] ?: continue
            if (ItemHistory.digest(JsonValue.Obj(r)) == digest) trash.add(id) else kept.add(id)
        }
        for ((id, v) in journal.replaced.entries.sortedWith { a, b -> Scalars.compare(a.key, b.key) }) {
            val r = current[id]
            if (r != null && ItemHistory.digest(JsonValue.Obj(r)) == v.second) {
                restore[id] = LinkedHashMap(v.first).apply { put("updated_at", JsonValue.Int(now)) }
            } else {
                kept.add(id)
            }
        }
        return Plan(trash, restore, kept)
    }

    /** [current] after [plan] (a pure view for tests and counts). */
    fun applied(current: Map<String, Map<String, JsonValue>>, plan: Plan): Map<String, Map<String, JsonValue>> {
        val out = LinkedHashMap(current)
        for (id in plan.trash) out.remove(id)
        out.putAll(plan.restore)
        return out
    }
}
