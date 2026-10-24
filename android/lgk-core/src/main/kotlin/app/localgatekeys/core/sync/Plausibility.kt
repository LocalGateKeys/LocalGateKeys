package app.localgatekeys.core.sync

/**
 * Plausibility of a REMOTE version vector next to the local one (desktop `engine.implausible_vv`, audit
 * 2026-10-24 M-6). A counter counts one device's edits of ONE item, so honest values stay tiny; a peer holding
 * the group key could otherwise publish 2^53-1 and make the next local edit of that item overflow.
 * Shared cases: `tests/vectors/sync/hardening_cases.json` (`vv`).
 */
object Plausibility {
    const val MAX_VV_COUNTER: Long = 1L shl 40
    const val MAX_UNKNOWN_VV_COUNTER: Long = 1L shl 20
    const val MAX_VV_STEP: Long = 1L shl 20
    const val MAX_VV_KEYS: Int = 512

    /**
     * `too-many-keys`, `implausible-counter` or null. A key that advances past the local counter must stay
     * within its bound ([MAX_VV_COUNTER] for a key in [known] or in the local vector, else
     * [MAX_UNKNOWN_VV_COUNTER]) or within [MAX_VV_STEP] of the local counter. A missing local vector is empty.
     */
    fun implausibleVv(remote: Map<String, Long>, local: Map<String, Long>?, known: Set<String>): String? {
        val base = local ?: emptyMap()
        if (remote.size > MAX_VV_KEYS) return "too-many-keys"
        for ((dev, n) in remote) {
            val b = base[dev] ?: 0L
            if (n <= b) continue
            val limit = if (dev in known || dev in base) MAX_VV_COUNTER else MAX_UNKNOWN_VV_COUNTER
            if (n > limit && n - b > MAX_VV_STEP) return "implausible-counter"
        }
        return null
    }
}
