package app.localgatekeys.core.activity

import java.security.MessageDigest

/**
 * The hash-chained access log (Windows `activity.py`, Apple `ActivityChain.swift`): each event's `prevHash` is the
 * SHA-256 of the previous event's canonical JSON (keys sorted, no spaces, UTF-8 as is); the first kept event links
 * to the checkpoint left by pruning, or to 64 zeros. Byte-exact with Windows (shared vector in the tests).
 */
object ActivityChain {
    val GENESIS: String = "0".repeat(64)

    data class Event(
        val id: String,
        val eventType: String,
        val timestamp: Long,
        val itemId: String? = null,
        val result: String = "ok",
        val count: Long = 0,
        /** Null for an event recorded before the chain existed. */
        val prevHash: String? = null,
    )

    data class Report(val ok: Boolean, val firstBadId: String?)

    fun canonical(e: Event): String = buildString {
        append("{\"count\":").append(e.count)
        append(",\"event_type\":").append(quote(e.eventType))
        append(",\"id\":").append(quote(e.id))
        append(",\"item_id\":").append(e.itemId?.let(::quote) ?: "null")
        e.prevHash?.let { append(",\"prev_hash\":").append(quote(it)) }
        append(",\"result\":").append(quote(e.result))
        append(",\"timestamp\":").append(e.timestamp)
        append('}')
    }

    fun hash(e: Event): String =
        MessageDigest.getInstance("SHA-256").digest(canonical(e).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    fun link(after: List<Event>, checkpoint: String? = null): String =
        after.lastOrNull()?.let(::hash) ?: checkpoint ?: GENESIS

    fun verify(events: List<Event>, checkpoint: String? = null, head: String? = null): Report {
        var expected = checkpoint ?: GENESIS
        var chained = false
        events.forEachIndexed { index, event ->
            val prev = event.prevHash
            if (prev == null) {
                if (chained) return Report(false, event.id)
                expected = hash(event)
                return@forEachIndexed
            }
            chained = true
            if (prev != expected) return Report(false, if (index > 0) events[index - 1].id else event.id)
            expected = hash(event)
        }
        // Once a chain exists its head must match: catches a cut-off tail, an emptied log and stripped hashes.
        if (head != null && head != expected) return Report(false, events.lastOrNull()?.id)
        return Report(true, null)
    }

    private fun quote(s: String): String = buildString {
        append('"')
        for (c in s) {
            when (c) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                '\b' -> append("\\b")
                '\u000C' -> append("\\f")
                else -> if (c.code < 0x20) append("\\u%04x".format(c.code)) else append(c)
            }
        }
        append('"')
    }
}
