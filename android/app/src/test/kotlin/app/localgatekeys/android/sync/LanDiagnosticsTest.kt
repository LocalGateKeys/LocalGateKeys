package app.localgatekeys.android.sync

import app.localgatekeys.core.lan.LanEndpoint
import java.io.IOException
import java.net.ConnectException
import java.net.InetAddress
import java.net.NoRouteToHostException
import java.net.PortUnreachableException
import java.net.ServerSocket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.nio.channels.ClosedByInterruptException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Port of `ios/LocalGateKeysTests/LanDiagnosticsTests.swift`. Android sockets report failures as Java exceptions whose
 * messages carry the errno name (bionic: "isConnected failed: ECONNREFUSED (Connection refused)"), so classification
 * goes by errno name, then by exception type.
 */
class LanDiagnosticsTest {
    // MARK: failure classification (Swift test_refused_and_unroutable_fail_at_once, test_failed_state_classification)

    @Test fun refused_and_unroutable_errno_names() {
        assertEquals(LanFailure.REFUSED, LanDiagnostics.classify("ECONNREFUSED"))
        assertEquals(LanFailure.UNREACHABLE, LanDiagnostics.classify("EHOSTUNREACH"))
        assertEquals(LanFailure.UNREACHABLE, LanDiagnostics.classify("ENETUNREACH"))
        assertEquals(LanFailure.UNREACHABLE, LanDiagnostics.classify("EHOSTDOWN"))
        assertEquals(LanFailure.UNREACHABLE, LanDiagnostics.classify("ENETDOWN"))
        assertEquals(LanFailure.UNREACHABLE, LanDiagnostics.classify("EADDRNOTAVAIL"))
        assertEquals(LanFailure.TIMED_OUT, LanDiagnostics.classify("ETIMEDOUT"))
    }

    @Test fun failed_state_classification() {
        assertEquals(LanFailure.REFUSED, LanDiagnostics.classify("ECONNREFUSED"))
        assertEquals(LanFailure.CLOSED_BY_PEER, LanDiagnostics.classify("ECONNRESET"))
        assertEquals(LanFailure.CLOSED_BY_PEER, LanDiagnostics.classify("EPIPE"))
        assertEquals(LanFailure.CLOSED_BY_PEER, LanDiagnostics.classify("ECONNABORTED"))
        assertEquals(LanFailure.CLOSED_BY_PEER, LanDiagnostics.classify("ENOTCONN"))
        assertEquals(LanFailure.CANCELLED, LanDiagnostics.classify("ECANCELED"))
        assertEquals(LanFailure.OTHER, LanDiagnostics.classify("EACCES"))
        assertEquals(LanFailure.OTHER, LanDiagnostics.classify("not an errno"))
    }

    @Test fun android_socket_exceptions_are_classified_by_their_errno() {
        // The messages bionic's libcore puts on connect, read and write failures.
        assertEquals(
            LanFailure.REFUSED,
            LanDiagnostics.classify(
                ConnectException(
                    "failed to connect to /192.168.1.20 (port 47821) from /192.168.1.9 (port 40112) after 5000ms: " +
                        "isConnected failed: ECONNREFUSED (Connection refused)",
                ),
            ),
        )
        assertEquals(
            LanFailure.UNREACHABLE,
            LanDiagnostics.classify(NoRouteToHostException("failed to connect to /192.168.60.11: connect failed: EHOSTUNREACH (No route to host)")),
        )
        assertEquals(LanFailure.UNREACHABLE, LanDiagnostics.classify(ConnectException("connect failed: ENETUNREACH (Network is unreachable)")))
        assertEquals(LanFailure.CLOSED_BY_PEER, LanDiagnostics.classify(SocketException("recvfrom failed: ECONNRESET (Connection reset by peer)")))
        assertEquals(LanFailure.CLOSED_BY_PEER, LanDiagnostics.classify(SocketException("sendto failed: EPIPE (Broken pipe)")))
        assertEquals(LanFailure.OTHER, LanDiagnostics.classify(SocketException("socket failed: EACCES (Permission denied)")))
        // The errno can sit on a cause (android.system.ErrnoException under the IOException).
        assertEquals(
            LanFailure.UNREACHABLE,
            LanDiagnostics.classify(IOException("connect failed", Exception("connect failed: ENETUNREACH (Network is unreachable)"))),
        )
    }

    @Test fun java_socket_exceptions_without_an_errno() {
        // What the desktop JVM (and the unit tests' loopback sockets) report.
        assertEquals(LanFailure.REFUSED, LanDiagnostics.classify(ConnectException("Connection refused: no further information")))
        assertEquals(LanFailure.REFUSED, LanDiagnostics.classify(PortUnreachableException()))
        assertEquals(LanFailure.UNREACHABLE, LanDiagnostics.classify(NoRouteToHostException()))
        assertEquals(LanFailure.TIMED_OUT, LanDiagnostics.classify(SocketTimeoutException("Read timed out")))
        assertEquals(LanFailure.CLOSED_BY_PEER, LanDiagnostics.classify(SocketException("Connection reset")))
        assertEquals(LanFailure.CLOSED_BY_PEER, LanDiagnostics.classify(IOException("Broken pipe")))
        assertEquals(
            LanFailure.CLOSED_BY_PEER,
            LanDiagnostics.classify(IOException("An established connection was aborted by the software in your host machine")),
        )
        assertEquals(LanFailure.CANCELLED, LanDiagnostics.classify(ClosedByInterruptException()))
        assertEquals(LanFailure.CANCELLED, LanDiagnostics.classify(InterruptedException()))
        assertEquals(LanFailure.OTHER, LanDiagnostics.classify(IOException("something else")))
    }

    // MARK: subnet (Swift test_subnet_contains_and_describes, test_offer_outside_the_subnet_is_flagged)

    @Test fun subnet_contains_and_describes() {
        val s = IPv4Subnet.of("192.168.1.37", "255.255.255.0")!!
        assertEquals("192.168.1.0/24", s.toString())
        assertEquals(true, s.contains("192.168.1.5"))
        assertEquals(false, s.contains("192.168.60.11"))
        assertEquals(false, s.contains("10.0.0.1"))
        assertNull(s.contains("fe80::1")) // not IPv4: no verdict
        assertNull(s.contains("not an address"))
        val wide = IPv4Subnet.of("10.20.30.40", "255.255.240.0")!!
        assertEquals("10.20.16.0/20", wide.toString())
        assertEquals(true, wide.contains("10.20.31.1"))
        assertEquals(false, wide.contains("10.20.32.1"))
        assertNull(IPv4Subnet.of("192.168.1.1", "255.0.255.0")) // not a contiguous mask
    }

    @Test fun offer_outside_the_subnet_is_flagged() {
        val s = IPv4Subnet.of("192.168.1.37", "255.255.255.0")!!
        assertEquals(s, IPv4Subnet.mismatch("192.168.60.11", s))
        assertNull(IPv4Subnet.mismatch("192.168.1.200", s))
        assertNull(IPv4Subnet.mismatch("fe80::1", s))
        assertNull(IPv4Subnet.mismatch("192.168.60.11", null))
    }

    @Test fun netmask_from_prefix_length() {
        assertEquals("255.255.255.0", LanDiagnostics.netmask(24))
        assertEquals("255.255.240.0", LanDiagnostics.netmask(20))
        assertEquals("0.0.0.0", LanDiagnostics.netmask(0))
        assertEquals("255.255.255.255", LanDiagnostics.netmask(32))
    }

    // MARK: Wi-Fi interface (Swift test_wifi_interface_choice; Android names: wlan* Wi-Fi, eth* Ethernet)

    @Test fun wifi_interface_choice() {
        fun i(n: String, a: String, up: Boolean = true, loop: Boolean = false) = IPv4Interface(n, a, "255.255.255.0", up, loop)
        assertEquals(
            "192.168.1.0/24",
            LanDiagnostics.wifiSubnet(listOf(i("lo", "127.0.0.1", loop = true), i("rmnet_data0", "10.1.1.1"), i("wlan0", "192.168.1.9")))
                .toString(),
        )
        // wlan0 down: the first other up, non-loopback Wi-Fi or Ethernet interface.
        assertEquals(
            "172.16.4.0/24",
            LanDiagnostics.wifiSubnet(listOf(i("lo", "127.0.0.1", loop = true), i("wlan0", "192.168.1.9", up = false), i("wlan1", "172.16.4.2")))
                .toString(),
        )
        assertEquals("10.0.2.0/24", LanDiagnostics.wifiSubnet(listOf(i("rmnet0", "10.9.9.9"), i("eth0", "10.0.2.15"))).toString())
        assertNull(LanDiagnostics.wifiSubnet(listOf(i("lo", "127.0.0.1", loop = true))))
        // Never cellular, a VPN tunnel or a hotspot bridge.
        assertNull(
            LanDiagnostics.wifiSubnet(
                listOf(i("rmnet_data0", "10.1.1.1"), i("ccmni0", "10.2.2.2"), i("tun0", "10.8.0.2"), i("ap0", "192.168.43.1"), i("bridge0", "192.168.2.1")),
            ),
        )
    }

    @Test fun current_interfaces_never_throw() {
        // Whatever this machine has; only that reading them works and returns IPv4 text.
        for (iface in LanDiagnostics.currentInterfaces()) assertTrue(iface.toString(), IPv4Subnet.parse(iface.address) != null)
        LanDiagnostics.currentWiFiSubnet()
    }

    // MARK: a real closed port fails fast (Swift test_closed_local_port_fails_fast_as_refused)

    @Test fun closed_local_port_fails_fast_as_refused() {
        // Bind then close a listener so the port is known to be closed.
        val port = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
        val endpoint = LanEndpoint("127.0.0.1", port)
        val started = System.nanoTime()
        try {
            ChannelLanDialer(timeoutMs = 5000).dial(endpoint).close()
            fail("connected to a closed port")
        } catch (e: LanSocketException) {
            assertEquals(e.message, LanFailure.REFUSED, e.kind)
        }
        assertTrue((System.nanoTime() - started) / 1_000_000 < 5_000)
    }
}
