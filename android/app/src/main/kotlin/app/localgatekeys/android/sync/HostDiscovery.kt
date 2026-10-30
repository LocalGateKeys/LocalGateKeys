package app.localgatekeys.android.sync

import android.content.Context
import android.net.Network
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import app.localgatekeys.core.lan.Discovery
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

// Finding the paired host by Bonjour / mDNS when its pinned address does not answer (plan 2026-10-29-sync-ip-change,
// section 3). The browse only says where to dial; the session hello still checks the pinned keys.

/**
 * Browses one DNS-SD service type and returns the resolved announcements (host address text, port, TXT record).
 * Production: [NsdServiceBrowser]; tests: a fake. Blocks up to about [timeoutMs] plus the resolves; an interrupted
 * thread stops it at once with [LanSocketException] CANCELLED.
 */
fun interface ServiceBrowser {
    fun browse(serviceType: String, timeoutMs: Long): List<Discovery.Announcement>
}

/**
 * [ServiceBrowser] over [NsdManager] (no runtime permission on API 29-36; INTERNET is declared). From API 33 the browse
 * is limited to the Wi-Fi network ([network], from [WifiNetworkBinder.localNetwork]); before that NsdManager browses
 * the default interfaces. Services found during the window are resolved one after another (the pre-34 resolve API
 * allows one at a time), each within [RESOLVE_MS], at most [MAX_RESOLVES]
 * within [RESOLVE_BUDGET_MS], newest first.
 */
class NsdServiceBrowser(context: Context, private val network: () -> Network?) : ServiceBrowser {
    private val nsd: NsdManager? = context.applicationContext.getSystemService(NsdManager::class.java)
    private val direct = Executor { it.run() }

    override fun browse(serviceType: String, timeoutMs: Long): List<Discovery.Announcement> {
        val manager = nsd ?: return emptyList()
        val found = LinkedHashMap<String, NsdServiceInfo>()
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) {}
            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {}
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
            override fun onServiceFound(info: NsdServiceInfo) {
                synchronized(found) { if (found.size < MAX_RESOLVES) found.putIfAbsent(info.serviceName, info) }
            }
            override fun onServiceLost(info: NsdServiceInfo) {}
        }
        val net = network()
        try {
            if (Build.VERSION.SDK_INT >= 33 && net != null) {
                manager.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, net, direct, listener)
            } else {
                manager.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, listener)
            }
        } catch (_: Exception) {
            return emptyList()
        }
        try {
            sleepInterruptibly(timeoutMs)
        } finally {
            try { manager.stopServiceDiscovery(listener) } catch (_: Exception) { }
        }
        // Newest first: a flood of junk announced before the real host can't push it out of the resolve budget.
        val services = synchronized(found) { found.values.toList() }.asReversed()
        val deadline = System.nanoTime() + RESOLVE_BUDGET_MS * 1_000_000L
        val out = ArrayList<Discovery.Announcement>()
        for (info in services) {
            if (System.nanoTime() >= deadline) break
            resolve(manager, info)?.let(out::add)
        }
        return out
    }

    @Suppress("DEPRECATION") // resolveService / host: the one API on 29-33; its successor needs 34.
    private fun resolve(manager: NsdManager, info: NsdServiceInfo): Discovery.Announcement? {
        val done = CountDownLatch(1)
        val result = AtomicReference<NsdServiceInfo?>(null)
        val listener = object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) = done.countDown()
            override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                result.set(serviceInfo)
                done.countDown()
            }
        }
        try {
            manager.resolveService(info, listener)
        } catch (_: Exception) {
            return null
        }
        val ok = try {
            done.await(RESOLVE_MS, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            stopResolution(manager, listener)
            Thread.currentThread().interrupt()
            throw LanSocketException("cancelled", LanFailure.CANCELLED)
        }
        if (!ok) {
            stopResolution(manager, listener)
            return null
        }
        val r = result.get() ?: return null
        val host = r.host?.hostAddress ?: return null
        val txt = r.attributes.mapNotNull { (k, v) -> v?.let { k to String(it, Charsets.UTF_8) } }.toMap()
        return Discovery.Announcement(host, r.port, txt)
    }

    private fun stopResolution(manager: NsdManager, listener: NsdManager.ResolveListener) {
        if (Build.VERSION.SDK_INT >= 34) {
            try { manager.stopServiceResolution(listener) } catch (_: Exception) { }
        }
    }

    override fun toString(): String = "NsdServiceBrowser"

    companion object {
        const val RESOLVE_MS = 1_000L
        const val MAX_RESOLVES = 16
        const val RESOLVE_BUDGET_MS = 6_000L

        internal fun sleepInterruptibly(ms: Long) {
            try {
                Thread.sleep(ms)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                throw LanSocketException("cancelled", LanFailure.CANCELLED)
            }
        }
    }
}
