package app.localgatekeys.android.sync

import android.Manifest
import android.content.pm.PackageManager
import android.security.NetworkSecurityPolicy
import androidx.test.platform.app.InstrumentationRegistry
import app.localgatekeys.core.lan.Enrollment
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.LanTransport
import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The socket transport on the phone itself: a dial bound to the Wi-Fi network ([WifiNetworkBinder]) reaches a responder
 * in this process on the emulator's own Wi-Fi address (nothing leaves the emulator), and the app's network policy.
 */
class SocketLanTransportDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun wifi_bound_enrollment_reaches_a_local_responder() {
        val wifi = LanDiagnostics.currentInterfaces().firstOrNull { it.isUp && !it.isLoopback && it.name.startsWith("wlan") }
        assumeTrue("the emulator has no Wi-Fi interface", wifi != null)
        val binder = WifiNetworkBinder(context)
        assertNotNull("no Wi-Fi network", binder.localNetwork())
        val host = wifi!!.address
        val server = ServerSocket()
        server.bind(InetSocketAddress(InetAddress.getByName(host), 0))
        val request = Enrollment.REQUEST_MAGIC + byteArrayOf(1, 2, 3)
        var seen: ByteArray? = null
        val peer = Thread {
            server.accept().use { s ->
                val d = DataInputStream(s.getInputStream())
                val header = ByteArray(4).also { d.readFully(it) }
                val n = ((header[0].toInt() and 0xFF) shl 24) or ((header[1].toInt() and 0xFF) shl 16) or
                    ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
                seen = ByteArray(n).also { d.readFully(it) }
                s.getOutputStream().write(LanTransport.encodeFrame("reply".toByteArray()))
                s.getOutputStream().flush()
            }
        }.apply { start() }
        try {
            val dialer = ChannelLanDialer(5_000, bind = binder::bind)
            val reply = SocketEnroller(dialer).enroll(LanEndpoint(host, server.localPort), request)
            assertArrayEquals("reply".toByteArray(), reply)
            peer.join(5_000)
            assertArrayEquals(request, seen)
        } finally {
            server.close()
        }
    }

    @Test fun the_wifi_subnet_is_read() {
        val wifi = LanDiagnostics.currentInterfaces().firstOrNull { it.isUp && !it.isLoopback && it.name.startsWith("wlan") }
        assumeTrue(wifi != null)
        val subnet = LanDiagnostics.currentWiFiSubnet()
        assertNotNull(subnet)
        assertEquals(true, subnet!!.contains(wifi!!.address))
    }

    @Test fun no_cleartext_and_only_the_permissions_sync_needs() {
        assertFalse(NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted)
        assertFalse(NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted("192.168.1.20"))
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        val requested = info.requestedPermissions.orEmpty().toSet()
        for (p in listOf(Manifest.permission.INTERNET, Manifest.permission.ACCESS_NETWORK_STATE, Manifest.permission.CAMERA)) {
            assert(p in requested) { "$p missing" }
        }
        // No location, no Wi-Fi state, no nearby-devices permission: the LAN address comes from the QR code.
        for (p in listOf(
            Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.ACCESS_WIFI_STATE, "android.permission.NEARBY_WIFI_DEVICES",
        )) {
            assertFalse("$p requested", p in requested)
        }
    }
}
