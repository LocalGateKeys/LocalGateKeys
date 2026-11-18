package app.localgatekeys.wear

import android.content.Context
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.wear.WearCodes

/** The few values the store keeps on disk (app-private preferences, never backed up). */
interface WatchPrefs {
    fun getString(key: String): String?
    fun getLong(key: String): Long?
    fun edit(strings: Map<String, String?>, longs: Map<String, Long?>)
}

/** Wall clock and a monotonic clock (elapsed since boot). */
interface WatchClock {
    fun wallMillis(): Long
    fun elapsedMillis(): Long
}

/**
 * What the watch knows from the phone (sub-plan 06, Wear OS tile).
 *
 * On disk: the order of the last applied message, the state (nothing yet, locked, or the pinned titles) and when it
 * arrived, so the tile can show the last known titles with their age when the phone is out of reach. The codes
 * themselves live only in this process's memory ([live]) and only until their validity ends: they never touch the
 * disk, and a process restart or a reboot drops them.
 *
 * Rules (as on the Apple Watch): a forget is always applied and clears everything, and its order becomes the last one
 * even when lower; a replace must be newer than the last applied order; an implausible stored order is dropped.
 */
class WatchCodesStore(private val prefs: WatchPrefs, private val clock: WatchClock) {

    /** The codes of the last applied replace, in memory only. Valid while both clocks are within each code's validity. */
    private class Live(
        val seq: Long,
        val codes: List<String>,
        val millis: List<Long>,
        val receivedWall: Long,
        val sentWall: Long,
        val receivedElapsed: Long,
    )

    /** Applies [message] if the ordering rules allow it. True when the state changed. */
    fun apply(message: WearCodes.Message): Boolean = synchronized(LOCK) {
        val now = clock.wallMillis()
        val (accept, last) = WearCodes.ordering(message, prefs.getLong(KEY_SEQ), now)
        if (!accept) {
            // Ignored, but a dropped (implausible) stored order is repaired at once.
            prefs.edit(emptyMap(), mapOf(KEY_SEQ to last))
            return false
        }
        when (message) {
            is WearCodes.Forget -> {
                live = null
                prefs.edit(
                    mapOf(KEY_KIND to if (message.immediately) KIND_IMMEDIATELY else KIND_LOCKED, KEY_TITLES to null),
                    mapOf(KEY_SEQ to last, KEY_AT to now),
                )
            }
            is WearCodes.Replace -> {
                val titles = CanonicalJson.encode(JsonValue.Arr(message.codes.map { JsonValue.Str(it.title) }), Dialect.UTF8)
                    .toString(Charsets.UTF_8)
                live = Live(
                    message.seq, message.codes.map { it.code }, message.codes.map { it.millisRemaining },
                    now, message.sentAtMillis, clock.elapsedMillis(),
                )
                prefs.edit(mapOf(KEY_KIND to KIND_CODES, KEY_TITLES to titles), mapOf(KEY_SEQ to last, KEY_AT to now))
            }
        }
        true
    }

    /** The tile's input now. Codes whose validity ended are dropped from memory. */
    fun input(): TileInput = synchronized(LOCK) {
        val now = clock.wallMillis()
        when (prefs.getString(KEY_KIND)) {
            KIND_LOCKED -> TileInput.Locked(immediately = false)
            KIND_IMMEDIATELY -> TileInput.Locked(immediately = true)
            KIND_CODES -> {
                val titles = titles() ?: return TileInput.NoData
                val at = prefs.getLong(KEY_AT) ?: now
                val current = live?.takeIf { it.seq == prefs.getLong(KEY_SEQ) && it.codes.size == titles.size }
                val codes = titles.mapIndexed { i, t -> PinnedCode(t, current?.let { codeAt(it, i) }, validForMillis = current?.let { remaining(it, i) } ?: 0) }
                if (current != null && codes.all { it.code == null || it.code.isEmpty() }) live = null
                TileInput.Known(codes, ageSeconds = ((now - at) / 1000).coerceAtLeast(0))
            }
            else -> TileInput.NoData
        }
    }

    /** Milliseconds the code at [i] stays valid (0: expired or none). Both clocks must agree, minus a margin. */
    private fun remaining(l: Live, i: Int): Long {
        val ms = l.millis[i]
        if (ms <= 0) return 0
        val wall = clock.wallMillis()
        val elapsed = clock.elapsedMillis() - l.receivedElapsed
        if (elapsed < 0 || wall < l.receivedWall) return 0 // a clock went back: fail closed
        // The phone's send time counts when it is a little earlier (delivery delay); a larger gap is clock skew.
        val start = if (l.receivedWall - l.sentWall in 0..MAX_DELAY_MILLIS) l.sentWall else l.receivedWall
        val byWall = start + ms - MARGIN_MILLIS - wall
        val byElapsed = ms - MARGIN_MILLIS - elapsed
        return minOf(byWall, byElapsed).coerceAtLeast(0)
    }

    private fun codeAt(l: Live, i: Int): String? {
        val code = l.codes[i]
        if (code.isEmpty()) return ""
        return if (remaining(l, i) > 0) code else null
    }

    private fun titles(): List<String>? = try {
        prefs.getString(KEY_TITLES)?.let { s ->
            CanonicalJson.parse(s.toByteArray(Charsets.UTF_8)).arr().map { it.str() }.take(WearCodes.MAX_CODES)
        }
    } catch (e: Exception) {
        null
    }

    companion object {
        private val LOCK = Any()

        /** Process memory only (shared by the listener and the tile service, which run in this app's process). */
        @Volatile private var live: Live? = null

        /** Bluetooth delivery takes time: a code is hidden this long before the phone says it changes. */
        const val MARGIN_MILLIS = 1_000L

        private const val MAX_DELAY_MILLIS = 10_000L

        private const val KEY_SEQ = "seq"
        private const val KEY_KIND = "kind"
        private const val KEY_TITLES = "titles"
        private const val KEY_AT = "at"
        private const val KIND_LOCKED = "locked"
        private const val KIND_IMMEDIATELY = "immediately"
        private const val KIND_CODES = "codes"

        /** For tests: forget the in-memory codes (a new process). */
        internal fun dropMemory() { live = null }

        fun of(context: Context): WatchCodesStore = WatchCodesStore(SharedWatchPrefs(context), SystemWatchClock)
    }
}

private class SharedWatchPrefs(context: Context) : WatchPrefs {
    private val prefs = context.applicationContext.getSharedPreferences("codes", Context.MODE_PRIVATE)
    override fun getString(key: String): String? = prefs.getString(key, null)
    override fun getLong(key: String): Long? = if (prefs.contains(key)) prefs.getLong(key, 0) else null
    override fun edit(strings: Map<String, String?>, longs: Map<String, Long?>) {
        val e = prefs.edit()
        strings.forEach { (k, v) -> if (v == null) e.remove(k) else e.putString(k, v) }
        longs.forEach { (k, v) -> if (v == null) e.remove(k) else e.putLong(k, v) }
        e.commit()
    }
}

private object SystemWatchClock : WatchClock {
    override fun wallMillis(): Long = System.currentTimeMillis()
    override fun elapsedMillis(): Long = android.os.SystemClock.elapsedRealtime()
}
