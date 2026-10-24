package app.localgatekeys.core.support

import app.localgatekeys.core.lan.CounterStore

/** In-memory [CounterStore]; tests read and seed the fields directly. */
class MemoryCounterStore : CounterStore {
    var hello: Long = 0
    val saves = ArrayList<Long>()
    val inbound = HashMap<String, Long>()

    @Synchronized override fun persistedHelloCounter(): Long = hello

    @Synchronized override fun persistHelloCounter(last: Long) {
        hello = last
        saves.add(last)
    }

    @Synchronized override fun lastAcceptedCounter(peer: String): Long = inbound[peer] ?: 0

    @Synchronized override fun setLastAcceptedCounter(counter: Long, peer: String) {
        inbound[peer] = counter
    }
}
