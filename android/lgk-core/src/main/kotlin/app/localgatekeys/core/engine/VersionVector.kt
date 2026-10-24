package app.localgatekeys.core.engine

import app.localgatekeys.core.primitives.Identifier

/** Malformed input to the merge engine (desktop `EngineError`). Messages are verbatim from the Swift port. */
class EngineException(message: String) : Exception(message)

/** Version vectors: device id -> counter in 0..2^53-1; missing entries equal 0. */
object VersionVector {
    const val MAX_COUNTER: Long = (1L shl 53) - 1

    enum class Relation { EQUAL, A, B, CONCURRENT }

    internal fun check(vv: Map<String, Long>) {
        for ((dev, n) in vv) {
            if (!Identifier.isValid(dev)) throw EngineException("invalid device id: $dev")
            if (n < 0 || n > MAX_COUNTER) throw EngineException("invalid counter for $dev: $n")
        }
    }

    /** `Relation.A` means *a* dominates. */
    fun compare(a: Map<String, Long>, b: Map<String, Long>): Relation {
        check(a)
        check(b)
        var aAhead = false
        var bAhead = false
        for (dev in a.keys + b.keys) {
            val x = a[dev] ?: 0L
            val y = b[dev] ?: 0L
            if (x > y) aAhead = true else if (y > x) bAhead = true
        }
        return when {
            aAhead && bAhead -> Relation.CONCURRENT
            aAhead -> Relation.A
            bAhead -> Relation.B
            else -> Relation.EQUAL
        }
    }

    /** Vector for a local edit or delete by [device]: `vv[device] += 1`, zero entries dropped. */
    fun bump(vv: Map<String, Long>, device: String): Map<String, Long> {
        check(vv)
        check(mapOf(device to 1L))
        val n = (vv[device] ?: 0L) + 1
        if (n > MAX_COUNTER) throw EngineException("counter for $device overflows")
        val out = vv.filterValues { it != 0L }.toMutableMap()
        out[device] = n
        return out
    }

    /** Element-wise maximum, zero entries dropped. */
    fun max(a: Map<String, Long>, b: Map<String, Long>): Map<String, Long> {
        val out = HashMap<String, Long>()
        for (dev in a.keys + b.keys) {
            val n = maxOf(a[dev] ?: 0L, b[dev] ?: 0L)
            if (n != 0L) out[dev] = n
        }
        return out
    }
}
