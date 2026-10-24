package app.localgatekeys.android.sync

import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.NoRouteToHostException
import java.net.PortUnreachableException
import java.net.SocketTimeoutException
import java.nio.channels.ClosedByInterruptException

/** One IPv4 address of a network interface (Swift `IPv4Interface`). */
data class IPv4Interface(
    val name: String,
    val address: String,
    val netmask: String,
    val isUp: Boolean,
    val isLoopback: Boolean,
)

/**
 * Why a LAN connection failed, and on which Wi-Fi subnet this phone is (port of `ios/App/Sync/LanDiagnostics.swift`).
 * Pure logic; the sockets that use it are in SocketLanTransport.kt.
 *
 * Android has no Network.framework "waiting" state and no Local Network permission, so the Swift `verdict` /
 * `ConnectWait` have no counterpart: a connect either completes, fails with an errno, or runs into its timeout.
 */
object LanDiagnostics {
    /**
     * The failure an errno names (Swift `LanFailure.classify(NWError)`, POSIX part). Android's socket exceptions carry
     * the name in their message ("isConnected failed: ECONNREFUSED (Connection refused)").
     */
    fun classify(errno: String): LanFailure = when (errno) {
        "ECONNREFUSED" -> LanFailure.REFUSED
        "EHOSTUNREACH", "ENETUNREACH", "EHOSTDOWN", "ENETDOWN", "EADDRNOTAVAIL" -> LanFailure.UNREACHABLE
        "ETIMEDOUT" -> LanFailure.TIMED_OUT
        "ECONNRESET", "EPIPE", "ECONNABORTED", "ENOTCONN" -> LanFailure.CLOSED_BY_PEER
        "ECANCELED" -> LanFailure.CANCELLED
        else -> LanFailure.OTHER
    }

    private val errnoName = Regex("\\bE[A-Z0-9]{2,}\\b")

    /**
     * A socket exception's failure: the first errno name on it or its causes that means something, else its type and
     * the JVM's own wording (the desktop JVM and loopback tests carry no errno).
     */
    fun classify(error: Throwable): LanFailure {
        val chain = generateSequence(error) { it.cause }.take(8).toList()
        for (e in chain) {
            if (e is ClosedByInterruptException || e is InterruptedException) return LanFailure.CANCELLED
            for (m in errnoName.findAll(e.message ?: "")) {
                val kind = classify(m.value)
                if (kind != LanFailure.OTHER) return kind
            }
        }
        for (e in chain) {
            val text = (e.message ?: "").lowercase()
            when {
                e is SocketTimeoutException -> return LanFailure.TIMED_OUT
                e is InterruptedIOException -> return LanFailure.CANCELLED
                e is PortUnreachableException -> return LanFailure.REFUSED
                e is NoRouteToHostException -> return LanFailure.UNREACHABLE
                e is ConnectException && "refused" in text -> return LanFailure.REFUSED
                "connection reset" in text || "broken pipe" in text || "connection was aborted" in text -> return LanFailure.CLOSED_BY_PEER
            }
        }
        return LanFailure.OTHER
    }

    /** The dotted netmask of a prefix length (0 ... 32). */
    fun netmask(prefixLength: Int): String {
        val p = prefixLength.coerceIn(0, 32)
        val mask = if (p == 0) 0L else (0xFFFF_FFFFL shl (32 - p)) and 0xFFFF_FFFFL
        return IPv4Subnet.format(mask)
    }

    private fun isWifiOrEthernet(name: String): Boolean = name.startsWith("wlan") || name.startsWith("eth")

    /**
     * The Wi-Fi subnet: wlan0 when it is up with IPv4, else the first other up Wi-Fi (`wlan*`) or Ethernet (`eth*`)
     * interface (Swift: en0, else the first other `en*`). Never cellular (`rmnet*`, `ccmni*`), VPN tunnels (`tun*`),
     * hotspot (`ap*`) or bridges: null then.
     */
    fun wifiSubnet(interfaces: List<IPv4Interface>): IPv4Subnet? {
        val usable = interfaces.filter { it.isUp && !it.isLoopback && isWifiOrEthernet(it.name) }
        val pick = usable.firstOrNull { it.name == "wlan0" } ?: usable.firstOrNull()
        return pick?.let { IPv4Subnet.of(it.address, it.netmask) }
    }

    /** This device's IPv4 interface addresses (empty when they cannot be read). Needs no permission. */
    fun currentInterfaces(): List<IPv4Interface> = try {
        NetworkInterface.getNetworkInterfaces()?.toList().orEmpty().flatMap { ni ->
            val up = try { ni.isUp } catch (_: Exception) { false }
            val loop = try { ni.isLoopback } catch (_: Exception) { false }
            ni.interfaceAddresses.orEmpty().mapNotNull { ia ->
                val v4 = ia?.address as? Inet4Address ?: return@mapNotNull null
                val text = v4.hostAddress ?: return@mapNotNull null
                IPv4Interface(ni.name, text, netmask(ia.networkPrefixLength.toInt()), up, loop)
            }
        }
    } catch (_: Exception) {
        emptyList()
    }

    /** The phone's current Wi-Fi subnet, or null (no Wi-Fi, or IPv6 only). */
    fun currentWiFiSubnet(): IPv4Subnet? = wifiSubnet(currentInterfaces())
}
