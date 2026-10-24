package app.localgatekeys.android.vault

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.CounterStore

/**
 * LAN hello counters in the sealed slots ([CounterStore]). Each write is a synchronous, fsynced file replace,
 * so a reserved block is durable before [persistHelloCounter] returns. Main app only.
 */
class VaultCounterStore(private val slots: SecretSlots) : CounterStore {
    private val lock = Any()

    override fun persistedHelloCounter(): Long = synchronized(lock) {
        val b = slots.read(Slot.HELLO_COUNTER) ?: return 0L
        try {
            if (b.size != 8) throw SecretSlotsException(SecretSlotsException.Kind.MALFORMED, "malformed hello counter")
            b.fold(0L) { acc, x -> (acc shl 8) or (x.toLong() and 0xFF) }
        } finally {
            b.fill(0)
        }
    }

    override fun persistHelloCounter(last: Long) {
        synchronized(lock) {
            slots.write(Slot.HELLO_COUNTER, ByteArray(8) { (last ushr ((7 - it) * 8)).toByte() })
        }
    }

    override fun lastAcceptedCounter(peer: String): Long = synchronized(lock) {
        parse(slots.read(Slot.PEER_COUNTERS))[peer] ?: 0L
    }

    override fun setLastAcceptedCounter(counter: Long, peer: String) {
        synchronized(lock) {
            // update() holds the per-file lock across read and write, so another store over the same file
            // cannot lose this peer's counter (or lose ours).
            slots.update(Slot.PEER_COUNTERS) { current ->
                val p = parse(current).toMutableMap()
                p[peer] = counter
                CanonicalJson.encode(JsonValue.Obj(p.mapValues { JsonValue.Int(it.value) }), Dialect.UTF8)
            }
        }
    }

    private fun parse(b: ByteArray?): Map<String, Long> {
        if (b == null) return emptyMap()
        try {
            val o = (CanonicalJson.parse(b) as? JsonValue.Obj ?: throw bad()).fields
            return o.mapValues { (it.value as? JsonValue.Int ?: throw bad()).v }
        } catch (e: JsonException) {
            throw bad()
        } finally {
            b.fill(0)
        }
    }

    private fun bad() = SecretSlotsException(SecretSlotsException.Kind.MALFORMED, "malformed peer counters")
}
