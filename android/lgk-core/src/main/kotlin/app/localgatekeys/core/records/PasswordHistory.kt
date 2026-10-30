package app.localgatekeys.core.records

import app.localgatekeys.core.json.JsonValue

/**
 * A login's `password_history` (`[{password, changed_at}]`, newest first), UX plan 2026-10-27 workstream 8 and owner
 * decision 3: the normaliser accepts up to [LIMIT] (10); writes ([push], [restore]) keep at most [WRITE_LIMIT] (5, until
 * every platform accepts 10) and drop entries older than [KEEP_SECONDS] (365 days).
 */
object PasswordHistory {
    /** What the normaliser accepts (a later release may write this many). */
    const val LIMIT = 10
    /** What this phone writes: Windows 0.4.9 refuses synced records with more than 5 (the iPhone's historyWriteLimit). */
    const val WRITE_LIMIT = 5
    const val KEEP_SECONDS = 365L * 86_400L

    /** One past password. [toString] leaves the password out. */
    data class Entry(val password: String, val changedAt: Long) {
        override fun toString(): String = "PasswordHistory.Entry(changedAt=$changedAt)"
    }

    /** The record's entries as stored (newest first); malformed rows are skipped. */
    fun entries(record: Map<String, JsonValue>): List<Entry> =
        ((record["password_history"] as? JsonValue.Arr)?.items ?: emptyList()).mapNotNull { row ->
            val r = (row as? JsonValue.Obj)?.fields ?: return@mapNotNull null
            val pw = (r["password"] as? JsonValue.Str)?.v ?: return@mapNotNull null
            val at = ((r["changed_at"] ?: r["replaced_at"]) as? JsonValue.Int)?.v ?: return@mapNotNull null
            Entry(pw, at)
        }

    private fun row(e: Entry): JsonValue =
        JsonValue.Obj(mapOf("password" to JsonValue.Str(e.password), "changed_at" to JsonValue.Int(e.changedAt)))

    private fun kept(entries: List<Entry>, now: Long): List<Entry> =
        entries.filter { now - it.changedAt <= KEEP_SECONDS }.take(WRITE_LIMIT)

    /**
     * [record] whose password changed from [old] to the record's current one at [now]: [old] goes to the front of the
     * history (not when empty or unchanged), then the history is capped. Returns the record unchanged otherwise.
     */
    fun push(record: Map<String, JsonValue>, old: String, now: Long): Map<String, JsonValue> {
        val current = (record["password"] as? JsonValue.Str)?.v ?: ""
        if (old.isEmpty() || old == current) return record
        val out = LinkedHashMap(record)
        out["password_history"] = JsonValue.Arr(kept(listOf(Entry(old, now)) + entries(record), now).map(::row))
        return out
    }

    /**
     * "Restore this password": entry [index] becomes the password again, the current one goes into the history (the
     * restored entry leaves it). Null when [index] is out of range.
     */
    fun restore(record: Map<String, JsonValue>, index: Int, now: Long): Map<String, JsonValue>? {
        val all = entries(record)
        if (index !in all.indices) return null
        val current = (record["password"] as? JsonValue.Str)?.v ?: ""
        val rest = all.filterIndexed { i, _ -> i != index }
        val history = if (current.isEmpty() || current == all[index].password) rest else listOf(Entry(current, now)) + rest
        val out = LinkedHashMap(record)
        out["password"] = JsonValue.Str(all[index].password)
        out["password_history"] = JsonValue.Arr(kept(history, now).map(::row))
        return out
    }
}
