package app.localgatekeys.core.support

import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.primitives.UnixClock
import java.security.MessageDigest

/**
 * `scripts/make_sync_vectors.py` DetRand: sha256("lgk-sync-vectors|rand|" + label + "|" + counter_be32) blocks;
 * each call starts a fresh block and drops the unused tail.
 */
class DetRand(label: String) : RandomSource {
    private val label = "lgk-sync-vectors|rand|$label".toByteArray(Charsets.UTF_8)
    private var counter = 0

    @Synchronized
    override fun bytes(count: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        while (out.size() < count) {
            val c = byteArrayOf((counter ushr 24).toByte(), (counter ushr 16).toByte(), (counter ushr 8).toByte(), counter.toByte())
            out.write(MessageDigest.getInstance("SHA-256").digest(label + "|".toByteArray() + c))
            counter++
        }
        return out.toByteArray().copyOf(count)
    }
}

/** Returns the same bytes on every call (truncated to the requested count). */
class FixedRandom(private val value: ByteArray) : RandomSource {
    override fun bytes(count: Int): ByteArray = value.copyOf(minOf(count, value.size))
}

class FixedClock(override val now: Long) : UnixClock

/** Hands out the queued byte strings in order; each call must ask for exactly the queued length. */
class QueueRandom(queue: List<ByteArray>) : RandomSource {
    private val queue = ArrayDeque(queue)

    val isEmpty: Boolean @Synchronized get() = queue.isEmpty()

    @Synchronized
    override fun bytes(count: Int): ByteArray {
        if (queue.isEmpty()) return SystemRandomSource().bytes(count)
        val v = queue.removeFirst()
        check(v.size == count) { "queued ${v.size} bytes, asked $count" }
        return v
    }
}
