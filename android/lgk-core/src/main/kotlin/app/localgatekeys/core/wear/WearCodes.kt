package app.localgatekeys.core.wear

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue

/**
 * Sub-plan 06, Wear OS tile: the message the phone sends the watch over the Wearable Data Layer (paired, nearby
 * nodes only). Two-factor secrets are never sent: a [Replace] carries each pinned code's title, its current code and
 * how long that code stays valid; a [Forget] tells the watch to drop everything (vault locked or erased).
 *
 * Wire format (UTF-8 JSON, at most [MAX_BYTES]):
 * `{"v":1,"seq":N,"kind":"codes","at":sentAtMillis,"codes":[{"t":title,"c":"123456","ms":12345}]}` or
 * `{"v":1,"seq":N,"kind":"forget","why":"locked"|"immediately"}`.
 * Every message carries the whole state, so a lost message is repaired by the next one. `ms` is how long the code
 * stays valid after `at` (the phone's clock when it was sent).
 *
 * Parked with the Wear OS tile (2026-11-08): unused by :app, kept for the parked :wear module.
 */
object WearCodes {
    /** Phone to watch: [encode]d messages. */
    const val PATH_CODES = "/lgk/codes"

    /** Watch to phone: "send me the current state" (empty body). */
    const val PATH_REQUEST = "/lgk/codes/request"

    /** Declared by the watch app (`android_wear_capabilities`): the phone sends only to nodes that have it. */
    const val CAPABILITY_WATCH = "lgk_codes_tile"

    /** Declared by the phone app: the watch asks only nodes that have it. */
    const val CAPABILITY_PHONE = "lgk_codes_phone"

    const val MAX_CODES = 4
    const val MAX_BYTES = 4096
    const val MAX_TITLE = 40

    /** A code is never shown longer than this after it arrives, whatever its period. */
    const val MAX_VALID_MILLIS = 300_000L

    private const val VERSION = 1L
    private val CODE = Regex("[0-9]{4,10}")

    /** One pinned code as sent. [code] empty: the item gives no code (the tile shows a dash). Never shows the code. */
    class Code(val title: String, val code: String, val millisRemaining: Long) {
        override fun toString(): String = "WearCodes.Code(shown=${code.isNotEmpty()}, millisRemaining=$millisRemaining)"
        override fun equals(other: Any?): Boolean =
            other is Code && other.title == title && other.code == code && other.millisRemaining == millisRemaining
        override fun hashCode(): Int = (title.hashCode() * 31 + code.hashCode()) * 31 + millisRemaining.hashCode()
    }

    sealed interface Message {
        val seq: Long
    }

    /** The pinned codes at [sentAtMillis] (the phone's clock; empty list: nothing is pinned). */
    data class Replace(override val seq: Long, val codes: List<Code>, val sentAtMillis: Long = 0) : Message

    /** Drop every title and code. [immediately]: the phone's Auto-lock is "Immediately" (the tile says how to see codes). */
    data class Forget(override val seq: Long, val immediately: Boolean = false) : Message

    fun encode(message: Message): ByteArray {
        val fields = linkedMapOf<String, JsonValue>("v" to JsonValue.Int(VERSION), "seq" to JsonValue.Int(message.seq))
        when (message) {
            is Replace -> {
                fields["kind"] = JsonValue.Str("codes")
                fields["at"] = JsonValue.Int(message.sentAtMillis.coerceAtLeast(0))
                fields["codes"] = JsonValue.Arr(
                    message.codes.take(MAX_CODES).map { c ->
                        JsonValue.Obj(
                            mapOf(
                                "t" to JsonValue.Str(cleanTitle(c.title)),
                                "c" to JsonValue.Str(if (CODE.matches(c.code)) c.code else ""),
                                "ms" to JsonValue.Int(c.millisRemaining.coerceIn(0, MAX_VALID_MILLIS)),
                            ),
                        )
                    },
                )
            }
            is Forget -> {
                fields["kind"] = JsonValue.Str("forget")
                fields["why"] = JsonValue.Str(if (message.immediately) "immediately" else "locked")
            }
        }
        return CanonicalJson.encode(JsonValue.Obj(fields), Dialect.UTF8)
    }

    /** The message, or null for anything malformed, too large, of another version or with more than [MAX_CODES]. */
    fun decode(bytes: ByteArray): Message? {
        if (bytes.isEmpty() || bytes.size > MAX_BYTES) return null
        return try {
            val o = CanonicalJson.parse(bytes).obj().fields
            if (o["v"]?.long() != VERSION) return null
            val seq = o["seq"]?.long() ?: return null
            if (seq < 0) return null
            when (o["kind"]?.str()) {
                "forget" -> Forget(seq, immediately = o["why"]?.str() == "immediately")
                "codes" -> {
                    val at = o["at"]?.long() ?: return null
                    if (at < 0) return null
                    val list = o["codes"]?.arr() ?: return null
                    if (list.size > MAX_CODES) return null
                    Replace(seq, list.map { e ->
                        val f = e.obj().fields
                        val title = f["t"]?.str() ?: return null
                        val code = f["c"]?.str() ?: return null
                        val ms = f["ms"]?.long() ?: return null
                        if (title.length > MAX_TITLE || title.any { it.isISOControl() }) return null
                        if (code.isNotEmpty() && !CODE.matches(code)) return null
                        if (ms !in 0..MAX_VALID_MILLIS) return null
                        Code(title, code, ms)
                    }, at)
                }
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun cleanTitle(s: String): String =
        s.filterNot { it.isISOControl() }.let { if (it.length > MAX_TITLE) it.take(MAX_TITLE) else it }
            .let { if (it.isNotEmpty() && it.last().isHighSurrogate()) it.dropLast(1) else it }

    // ---- ordering (same rules as the Apple Watch: WatchMessage.ordering) ----------------------------------------

    private const val DAY_MILLIS = 86_400_000L

    /** The phone's next order: above the last one sent and at least the clock (ms), saturating. */
    fun nextSequence(last: Long, nowMillis: Long): Long {
        val bumped = if (last == Long.MAX_VALUE) Long.MAX_VALUE else last + 1
        return maxOf(bumped, nowMillis.coerceAtLeast(0))
    }

    /** A stored order the watch keeps: not negative and not more than a day ahead of its clock. */
    fun plausible(last: Long, nowMillis: Long): Boolean = last >= 0 && last <= nowMillis + DAY_MILLIS

    /**
     * Whether the watch applies [message] after [lastApplied] (null: none yet), and the order it keeps afterwards.
     * A forget is always applied (it can only remove codes) and its order becomes the last one, even when lower. A
     * replace must be newer than the last applied order. An implausible stored order is dropped first.
     */
    fun ordering(message: Message, lastApplied: Long?, nowMillis: Long): Pair<Boolean, Long?> {
        val last = lastApplied?.takeIf { plausible(it, nowMillis) }
        return when {
            message is Forget -> true to message.seq
            last == null || message.seq > last -> true to message.seq
            else -> false to last
        }
    }
}
