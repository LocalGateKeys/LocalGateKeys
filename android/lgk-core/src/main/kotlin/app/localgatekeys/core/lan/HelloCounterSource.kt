package app.localgatekeys.core.lan

import app.localgatekeys.core.primitives.UnixClock

/**
 * Persistent hello-counter state, implemented by the app (encrypted store); tests use memory.
 *
 * Contract: reserving a block ([persistHelloCounter]) must be atomic and durable before any counter
 * of the block is used, so a crash can never lead to a reused counter. Only the main app performs LAN
 * sync and writes this store; the AutoFill extension never does.
 *
 * The app must create exactly ONE [HelloCounterSource] per store and share it between all [LanClient]s;
 * two sources over one store would hand out counters from separate blocks under separate locks.
 */
interface CounterStore {
    /** The last hello counter reserved and saved (0 when none). */
    fun persistedHelloCounter(): Long

    /** Saves the last counter of a newly reserved block; must be durable before it returns. */
    fun persistHelloCounter(last: Long)

    /** The last hello counter accepted from [peer] (0 when none). */
    fun lastAcceptedCounter(peer: String): Long

    /** Saves the last hello counter accepted from [peer]. */
    fun setLastAcceptedCounter(counter: Long, peer: String)
}

/**
 * Hello counters handed out from blocks persisted before use (desktop `lan_sync.transport_state`):
 * a block of [BLOCK_SIZE] starts at `max(persisted + 1, clock in microseconds, previous block end + 1)`
 * and its last value is saved before any of it is used, so a counter is never reused, also across
 * restarts and a clock set backwards. Create exactly one per [CounterStore] and share it.
 * Thread-safe: block state and store access are serialized by a lock.
 */
class HelloCounterSource(private val store: CounterStore, private val clock: UnixClock) {
    private var next: Long = 1
    private var last: Long = 0
    private val lock = Any()

    fun nextCounter(): Long = synchronized(lock) {
        if (next > last) {
            val persisted = store.persistedHelloCounter()
            val micro = try {
                Math.multiplyExact(clock.now, 1_000_000L)
            } catch (e: ArithmeticException) {
                Long.MAX_VALUE
            }
            val start = maxOf(persisted + 1, micro, last + 1) // wrapping adds, as Swift `&+`
            if (persisted >= Long.MAX_VALUE || start > Long.MAX_VALUE - BLOCK_SIZE) {
                throw LanTransportException(LanTransportException.Kind.REPLAY, "Outbound sync counter is exhausted")
            }
            val end = start + BLOCK_SIZE - 1
            store.persistHelloCounter(end)
            next = start
            last = end
        }
        val value = next
        next += 1
        value
    }

    /** Accepts [counter] from [peer] only when it is above the last accepted one, and saves it. */
    fun acceptInbound(counter: Long, peer: String) {
        synchronized(lock) {
            if (counter <= store.lastAcceptedCounter(peer)) {
                throw LanTransportException(LanTransportException.Kind.REPLAY, "Session hello counter did not increase")
            }
            store.setLastAcceptedCounter(counter, peer)
        }
    }

    companion object {
        const val BLOCK_SIZE: Long = 64
    }
}
