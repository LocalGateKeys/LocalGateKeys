package app.localgatekeys.android.autofill

/**
 * The picker's order (UX refresh, section 5): the logins [FillMatcher.match] already offers for the target come first,
 * in its order (best first); every other login follows by title. Presentation only: nothing is added or removed.
 */
object FillPickerOrder {
    data class Row(val id: String, val title: String, val username: String)

    data class Split(val matches: List<Row>, val others: List<Row>)

    fun split(rows: List<Row>, matchIds: List<String>): Split {
        val byId = rows.associateBy { it.id }
        val matches = matchIds.distinct().mapNotNull { byId[it] }
        val taken = matches.map { it.id }.toSet()
        val others = rows.filter { it.id !in taken }.sortedBy { it.title.lowercase() }
        return Split(matches, others)
    }

    /** The search: title or username contains [query] (trimmed, any case); empty shows all. */
    fun filter(rows: List<Row>, query: String): List<Row> {
        val q = query.trim().lowercase()
        return if (q.isEmpty()) rows else rows.filter { it.title.lowercase().contains(q) || it.username.lowercase().contains(q) }
    }

    /** The letter in a row's tile. */
    fun initial(row: Row): String = row.title.ifEmpty { row.username }.trim().firstOrNull()?.uppercase() ?: "?"
}
