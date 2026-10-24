package app.localgatekeys.android.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.LanAddress
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.PinnedPeer

/**
 * The Wi-Fi transport as the coordinator uses it (Swift `LanTransporting`). Production: the socket transport (Task 11);
 * tests: fakes. Both calls block and run on an I/O thread; the coordinator calls them through `runInterruptible`, so an
 * implementation must give up promptly when its thread is interrupted (a cancelled join, or the vault locking).
 */
interface LanTransporting {
    /**
     * One LAN view exchange with the paired peer. Throws `LanSyncException` (desktop issue codes) or any transport
     * error (reported as `unreachable`).
     */
    fun exchangeViews(
        peer: PinnedPeer,
        identity: DeviceIdentity,
        groupKey: GroupKey,
        localStates: List<ItemState>,
        ownCounter: Long,
    ): List<ItemState>

    /**
     * The one enrollment request of a scanned offer; returns the inviter's reply bytes. [onConnected] is called once the
     * connection is up (the screen then stops offering Cancel). Throws [LanSocketException] when the dial fails.
     */
    fun enroll(endpoint: LanEndpoint, request: ByteArray, onConnected: () -> Unit): ByteArray

    companion object {
        /** Until Task 11: nothing can be reached. */
        val UNAVAILABLE = object : LanTransporting {
            override fun exchangeViews(
                peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: List<ItemState>, ownCounter: Long,
            ): List<ItemState> = throw LanSocketException("Wi-Fi sync is not available in this build")

            override fun enroll(endpoint: LanEndpoint, request: ByteArray, onConnected: () -> Unit): ByteArray =
                throw LanSocketException("Wi-Fi sync is not available in this build")
        }
    }
}

/**
 * What went wrong with one LAN connection, in the terms the Sync screen explains (Swift `LanFailure`, without the
 * iPhone's Local Network privacy case). Task 11's `LanDiagnostics` maps socket errors onto it.
 */
enum class LanFailure { REFUSED, UNREACHABLE, TIMED_OUT, CLOSED_BY_PEER, CANCELLED, OTHER }

/** A socket-level failure (Swift `LanSocketError`); [message] is diagnostic text, never shown verbatim. */
class LanSocketException(message: String, val kind: LanFailure = LanFailure.OTHER) : Exception(message)

/**
 * The enrollment dial to a scanned offer's address failed (nothing of the join was stored). [offSubnet]: the offer's
 * IPv4 host is outside this phone's Wi-Fi subnet (read before dialling).
 */
class EnrollConnectException(val failure: LanFailure, val endpoint: LanEndpoint, val offSubnet: IPv4Subnet? = null) :
    Exception("enroll failed: $failure") {
    override fun toString(): String =
        "EnrollConnectException(failure=$failure, endpoint=${SyncWording.hostPort(endpoint)}, offSubnet=$offSubnet)"
}

/** An IPv4 network: address and contiguous netmask (Swift `IPv4Subnet`). */
class IPv4Subnet private constructor(val network: Long, val prefixLength: Int) {
    val mask: Long get() = if (prefixLength == 0) 0L else (0xFFFF_FFFFL shl (32 - prefixLength)) and 0xFFFF_FFFFL

    /** True or false for an IPv4 host; null when the host is not IPv4 text (no verdict). */
    fun contains(host: String): Boolean? {
        val h = parse(host) ?: return null
        return (h and mask) == network
    }

    override fun equals(other: Any?): Boolean = other is IPv4Subnet && network == other.network && prefixLength == other.prefixLength

    override fun hashCode(): Int = network.hashCode() * 31 + prefixLength

    /** `a.b.c.d/len`, as the pairing failure text shows it. */
    override fun toString(): String = "${format(network)}/$prefixLength"

    companion object {
        /** Null when either text is not IPv4 or the netmask is not contiguous. */
        fun of(address: String, netmask: String): IPv4Subnet? {
            val a = parse(address) ?: return null
            val m = parse(netmask) ?: return null
            val ones = java.lang.Long.bitCount(m)
            val contiguous = if (ones == 0) 0L else (0xFFFF_FFFFL shl (32 - ones)) and 0xFFFF_FFFFL
            if (m != contiguous) return null
            return IPv4Subnet(a and m, ones)
        }

        /** The subnet when [host] is IPv4 and outside it (the case worth explaining after a failure), else null. */
        fun mismatch(host: String, subnet: IPv4Subnet?): IPv4Subnet? = subnet?.takeIf { it.contains(host) == false }

        fun parse(text: String): Long? {
            val v4 = LanAddress.parse(text) as? LanAddress.Parsed.V4 ?: return null
            return v4.bytes.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }
        }

        fun format(v: Long): String = listOf(24, 16, 8, 0).joinToString(".") { ((v shr it) and 0xFF).toString() }
    }
}
