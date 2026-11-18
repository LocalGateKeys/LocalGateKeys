package app.localgatekeys.android.sync

import android.content.Context
import android.net.Network
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import app.localgatekeys.core.lan.Discovery
import app.localgatekeys.core.lan.LanAddress
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.Executor
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import javax.jmdns.JmDNS
import javax.jmdns.ServiceInfo

/** Announces `_lgksync._tcp` [name] at [port] with the TXT record [txt]; returns what withdraws it (null: none). */
internal fun interface ServiceAnnouncer {
    fun announce(name: String, port: Int, txt: Map<String, String>): AutoCloseable?
}

/** Which announcer a phone at [sdk] uses: NsdManager can be bound to the Wi-Fi network from API 33 only. */
internal enum class AnnouncerKind {
    /** API 33+: the system's NsdManager, registered on the Wi-Fi network ([NsdServiceInfo.setNetwork]). */
    NSD_ON_WIFI_NETWORK,

    /** API 29-32: JmDNS bound to the Wi-Fi IPv4 address only, with a Wi-Fi multicast lock held while announced. */
    JMDNS_ON_WIFI_ADDRESS,
    ;

    companion object {
        fun forSdk(sdk: Int): AnnouncerKind = if (sdk >= 33) NSD_ON_WIFI_NETWORK else JMDNS_ON_WIFI_ADDRESS

        /** The announcer for [sdk]; each factory is called only when chosen. */
        fun choose(sdk: Int, nsd: () -> ServiceAnnouncer, jmdns: () -> ServiceAnnouncer): ServiceAnnouncer =
            when (forSdk(sdk)) {
                NSD_ON_WIFI_NETWORK -> nsd()
                JMDNS_ON_WIFI_ADDRESS -> jmdns()
            }
    }
}

/**
 * The phone host's network seams: the Wi-Fi IPv4 address ([LanDiagnostics.wifiAddress]: wlan0, else another Wi-Fi or
 * Ethernet interface, never cellular, VPN or hotspot; private LAN addresses only) and the announcement of
 * `_lgksync._tcp` with the Mac's TXT record (`v`, `t`), on the Wi-Fi network only: from API 33 through NsdManager
 * registered on the Wi-Fi [network]; before that (NsdManager would announce on every interface) through JmDNS bound to
 * the Wi-Fi IPv4 address, holding a Wi-Fi multicast lock while announced (CHANGE_WIFI_MULTICAST_STATE, API 32 and
 * lower). No runtime permission.
 */
class AndroidHostPlatform internal constructor(
    private val network: () -> Network?,
    sdk: Int,
    nsdFactory: (AndroidHostPlatform) -> ServiceAnnouncer,
    jmdnsFactory: (AndroidHostPlatform) -> ServiceAnnouncer,
) : HostPlatform {
    constructor(context: Context, network: () -> Network?) : this(
        network,
        Build.VERSION.SDK_INT,
        nsdFactory = { NsdAnnouncer(context.applicationContext.getSystemService(NsdManager::class.java), it.network) },
        jmdnsFactory = { platform ->
            val wifi = context.applicationContext.getSystemService(WifiManager::class.java)
            JmdnsAnnouncer(
                address = { platform.wifiAddress()?.let { InetAddress.getByName(it) as? Inet4Address } },
                multicastLock = { wifiMulticastLock(wifi) },
                open = ::openJmdns,
                executor = mdnsExecutor,
            )
        },
    )

    private val announcer: ServiceAnnouncer by lazy {
        AnnouncerKind.choose(sdk, nsd = { nsdFactory(this) }, jmdns = { jmdnsFactory(this) })
    }

    override fun wifiAddress(): String? = LanDiagnostics.wifiAddress(LanDiagnostics.currentInterfaces())?.takeIf { LanAddress.isLan(it) }

    override fun announce(name: String, port: Int, txt: Map<String, String>): AutoCloseable? = try {
        announcer.announce(name, port, txt)
    } catch (e: Exception) {
        null // announcing is best effort: paired devices still reach the saved address
    }

    override fun toString(): String = "AndroidHostPlatform"

    internal companion object {
        /** One background thread for every JmDNS start and stop (they block for seconds), in call order; idles out. */
        val mdnsExecutor: Executor by lazy {
            ThreadPoolExecutor(1, 1, 30, TimeUnit.SECONDS, LinkedBlockingQueue()) { r ->
                Thread(r, "lgk-mdns").apply { isDaemon = true }
            }.apply { allowCoreThreadTimeOut(true) }
        }

        private fun wifiMulticastLock(wifi: WifiManager?): AutoCloseable? {
            val lock = wifi?.createMulticastLock("lgk-host") ?: return null
            lock.setReferenceCounted(false)
            lock.acquire()
            return AutoCloseable { if (lock.isHeld) lock.release() }
        }

        /** Blocking: a JmDNS responder on [address] only, announcing the service. Closes itself when registering fails. */
        private fun openJmdns(address: InetAddress, name: String, port: Int, txt: Map<String, String>): AutoCloseable {
            // The host name is the neutral instance name (no reverse lookup of the address, nothing about the phone).
            val jmdns = JmDNS.create(address, name)
            try {
                jmdns.registerService(ServiceInfo.create("${Discovery.SERVICE_TYPE}.local.", name, port, 0, 0, txt))
            } catch (e: Exception) {
                try { jmdns.close() } catch (_: Exception) {}
                throw e
            }
            return AutoCloseable {
                try {
                    jmdns.unregisterAllServices()
                } finally {
                    jmdns.close()
                }
            }
        }
    }
}

/** API 33+: NsdManager on the Wi-Fi network (when [network] is known). */
internal class NsdAnnouncer(private val nsd: NsdManager?, private val network: () -> Network?) : ServiceAnnouncer {
    override fun announce(name: String, port: Int, txt: Map<String, String>): AutoCloseable? {
        val manager = nsd ?: return null
        val info = NsdServiceInfo().apply {
            serviceName = name
            serviceType = Discovery.SERVICE_TYPE
            this.port = port
            for ((k, v) in txt) setAttribute(k, v)
            if (Build.VERSION.SDK_INT >= 33) network()?.let { setNetwork(it) }
        }
        val listener = object : NsdManager.RegistrationListener {
            override fun onServiceRegistered(serviceInfo: NsdServiceInfo) {}
            override fun onRegistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
            override fun onServiceUnregistered(serviceInfo: NsdServiceInfo) {}
            override fun onUnregistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
        }
        return try {
            manager.registerService(info, NsdManager.PROTOCOL_DNS_SD, listener)
            AutoCloseable {
                try {
                    manager.unregisterService(listener)
                } catch (e: IllegalArgumentException) {
                    // never registered (the registration failed): nothing to withdraw
                }
            }
        } catch (e: Exception) {
            null
        }
    }
}

/**
 * API 29-32: a JmDNS responder bound to the Wi-Fi IPv4 address ([address]) only, with the Wi-Fi multicast lock
 * ([multicastLock]) held from before it starts until after it stopped. Starting and stopping block (probing, goodbye
 * packets), so both run on [executor] in call order; [announce] returns at once. Closing is safe at any time: before
 * the start ran (it is skipped), after a failed start (nothing left to stop) or twice.
 */
internal class JmdnsAnnouncer(
    private val address: () -> InetAddress?,
    private val multicastLock: () -> AutoCloseable?,
    private val open: (InetAddress, String, Int, Map<String, String>) -> AutoCloseable,
    private val executor: Executor,
) : ServiceAnnouncer {
    override fun announce(name: String, port: Int, txt: Map<String, String>): AutoCloseable? {
        val inet = address() ?: return null
        val handle = Handle()
        executor.execute { handle.start(inet, name, port, txt) }
        return handle
    }

    private inner class Handle : AutoCloseable {
        @Volatile private var closed = false
        // Touched only on the executor's thread.
        private var lock: AutoCloseable? = null
        private var responder: AutoCloseable? = null

        fun start(inet: InetAddress, name: String, port: Int, txt: Map<String, String>) {
            if (closed) return
            try {
                lock = multicastLock()
                responder = open(inet, name, port, txt)
            } catch (e: Exception) {
                stopNow() // best effort: no announcement, and the lock is not left held
            }
        }

        fun stopNow() {
            val r = responder
            responder = null
            val l = lock
            lock = null
            try { r?.close() } catch (_: Exception) {}
            try { l?.close() } catch (_: Exception) {}
        }

        override fun close() {
            if (closed) return
            closed = true
            try {
                executor.execute { stopNow() }
            } catch (_: Exception) {
                stopNow() // the thread is gone: stop here rather than leave the lock held
            }
        }
    }
}
