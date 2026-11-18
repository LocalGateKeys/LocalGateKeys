package app.localgatekeys.core.lan

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std

/**
 * Chunk buffers of one host responder, keyed by peer device id (desktop `lan_sync.LanInbox`, Swift `LanInbox`): one
 * transfer per peer each way, at most [MAX_TRANSFERS] per direction (the oldest is dropped), each dropped
 * [TRANSFER_TTL] seconds after it started. Not thread-safe: the owner holds its lock.
 */
class LanInbox {
    private class Incoming(val transfer: String, val total: Long, val size: Long, val started: Long) {
        val parts = ArrayList<ByteArray>()
        var received = 0L
    }

    internal class Outgoing(
        val transfer: String,
        val parts: List<ByteArray>,
        val size: Long,
        val groupKey: GroupKey,
        val started: Long,
    ) {
        var sent = 1
    }

    private val incoming = HashMap<String, Incoming>()
    private val outgoing = HashMap<String, Outgoing>()

    val incomingCount: Int get() = incoming.size
    val outgoingCount: Int get() = outgoing.size

    fun expire(now: Long) {
        incoming.values.removeAll { it.started < now - TRANSFER_TTL }
        outgoing.values.removeAll { it.started < now - TRANSFER_TTL }
    }

    /** Drops the oldest transfers past [MAX_TRANSFERS], never [keep] (the one just started). */
    private fun <V> bounded(table: HashMap<String, V>, keep: String, started: (V) -> Long) {
        while (table.size > MAX_TRANSFERS) {
            val oldest = table.entries.filter { it.key != keep }
                .minWithOrNull(compareBy<Map.Entry<String, V>>({ started(it.value) }, { it.key })) ?: break
            table.remove(oldest.key)
        }
    }

    /** `_receive_chunk`: buffers one chunk; returns the whole view after the last one, else null. */
    fun receive(peer: String, transfer: String, seq: Long, total: Long, size: Long, view: String, now: Long): ByteArray? {
        val data = try {
            Base64Std.decodeStrict(view)
        } catch (e: Base64Exception) {
            throw LanSyncException("bad-chunk")
        }
        if (data.isEmpty()) throw LanSyncException("bad-chunk")
        if (data.size > LanMessages.CHUNK_LIMIT) {
            incoming.remove(peer)
            throw LanSyncException("too-large")
        }
        if (seq == 0L) {
            incoming[peer] = Incoming(transfer, total, size, now)
            bounded(incoming, peer) { it.started } // as the desktop: may drop the oldest other transfer
        }
        val current = incoming[peer]
        if (current == null || current.transfer != transfer || current.parts.size.toLong() != seq ||
            current.total != total || current.size != size
        ) {
            incoming.remove(peer)
            throw LanSyncException("bad-chunk")
        }
        current.parts.add(data)
        current.received += data.size
        if (current.received > size) {
            incoming.remove(peer)
            throw LanSyncException("bad-chunk")
        }
        if (seq < total - 1) return null
        incoming.remove(peer)
        if (current.received != size) throw LanSyncException("bad-chunk")
        val out = java.io.ByteArrayOutputStream(size.toInt())
        for (p in current.parts) out.write(p)
        return out.toByteArray()
    }

    /** Keeps the rest of a view sent in several chunks for `next`. */
    internal fun store(out: Outgoing?, peer: String) {
        if (out == null) {
            outgoing.remove(peer)
        } else {
            outgoing[peer] = out
            bounded(outgoing, peer) { it.started }
        }
    }

    /** `_next_chunk`. */
    fun next(peer: String, transfer: String, seq: Long): LanMessage {
        val out = outgoing[peer]
        if (out == null || out.transfer != transfer || seq != out.sent.toLong()) {
            outgoing.remove(peer)
            return LanMessage.Error("bad-chunk")
        }
        val reply = viewMessage(out.groupKey, out.transfer, out.sent, out.parts, out.size)
        out.sent += 1
        if (out.sent >= out.parts.size) outgoing.remove(peer)
        return reply
    }

    companion object {
        /** Desktop `TRANSFER_TTL_SECONDS`. */
        const val TRANSFER_TTL: Long = 300

        /** Desktop `MAX_TRANSFERS`. */
        const val MAX_TRANSFERS = 2

        internal fun viewMessage(gk: GroupKey, transfer: String, seq: Int, parts: List<ByteArray>, size: Long): LanMessage =
            LanMessage.View(gk.groupId, gk.epoch, transfer, seq.toLong(), parts.size.toLong(), size, Base64Std.encode(parts[seq]))
    }
}
