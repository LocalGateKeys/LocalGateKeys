package app.localgatekeys.core.sync

/**
 * When each peer last finished a clean Wi-Fi exchange in this process, even one that changed nothing
 * (desktop ``lan_sync.peer_seen_at``). In memory only: a no-change sync writes nothing to the store.
 */
object PeerSeenAt {
    private val times = HashMap<Pair<String, String>, Long>()

    @Synchronized fun note(groupId: String, peerId: String, now: Long) {
        val key = groupId to peerId
        val at = maxOf(0L, now)
        if (at > (times[key] ?: -1L)) times[key] = at
    }

    /** [saved] with any newer in-memory time of the same group. */
    @Synchronized fun merged(groupId: String, saved: Map<String, Long>): Map<String, Long> {
        val out = HashMap(saved)
        for ((key, at) in times) if (key.first == groupId) out[key.second] = maxOf(at, out[key.second] ?: 0L)
        return out
    }

    @Synchronized fun clear() = times.clear()
}
