package app.localgatekeys.android.sync

import java.net.InetAddress
import java.util.concurrent.Executor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/** The announcer choice (API 33+: NsdManager on the Wi-Fi network; 29-32: JmDNS on the Wi-Fi address) and JmDNS's lifecycle. */
class AndroidHostPlatformTest {
    private class Recording(val label: String, val log: MutableList<String>) : ServiceAnnouncer {
        override fun announce(name: String, port: Int, txt: Map<String, String>): AutoCloseable {
            log += "$label announce $name $port ${txt.toSortedMap()}"
            return AutoCloseable { log += "$label close" }
        }
    }

    private fun platform(sdk: Int, log: MutableList<String>) = AndroidHostPlatform(
        network = { null },
        sdk = sdk,
        nsdFactory = { log += "nsd made"; Recording("nsd", log) },
        jmdnsFactory = { log += "jmdns made"; Recording("jmdns", log) },
    )

    @Test fun api_level_picks_the_announcer() {
        assertEquals(AnnouncerKind.JMDNS_ON_WIFI_ADDRESS, AnnouncerKind.forSdk(29))
        assertEquals(AnnouncerKind.JMDNS_ON_WIFI_ADDRESS, AnnouncerKind.forSdk(30))
        assertEquals(AnnouncerKind.JMDNS_ON_WIFI_ADDRESS, AnnouncerKind.forSdk(31))
        assertEquals(AnnouncerKind.JMDNS_ON_WIFI_ADDRESS, AnnouncerKind.forSdk(32))
        assertEquals(AnnouncerKind.NSD_ON_WIFI_NETWORK, AnnouncerKind.forSdk(33))
        assertEquals(AnnouncerKind.NSD_ON_WIFI_NETWORK, AnnouncerKind.forSdk(36))
    }

    @Test fun before_api_33_only_jmdns_is_made_and_used() {
        for (sdk in 29..32) {
            val log = mutableListOf<String>()
            val p = platform(sdk, log)
            assertEquals(emptyList<String>(), log) // nothing is made before the first announcement
            p.announce("LocalGateKeys-ab12", 4242, mapOf("v" to "1", "t" to "tag"))!!.close()
            p.announce("LocalGateKeys-cd34", 4243, mapOf("v" to "1", "t" to "tag2"))!!.close()
            assertEquals(
                listOf(
                    "jmdns made",
                    "jmdns announce LocalGateKeys-ab12 4242 {t=tag, v=1}", "jmdns close",
                    "jmdns announce LocalGateKeys-cd34 4243 {t=tag2, v=1}", "jmdns close",
                ),
                log,
            )
        }
    }

    @Test fun from_api_33_only_nsd_is_made_and_used() {
        for (sdk in listOf(33, 34, 36)) {
            val log = mutableListOf<String>()
            platform(sdk, log).announce("LocalGateKeys-ab12", 4242, mapOf("v" to "1", "t" to "tag"))!!.close()
            assertEquals(listOf("nsd made", "nsd announce LocalGateKeys-ab12 4242 {t=tag, v=1}", "nsd close"), log)
        }
    }

    @Test fun an_announcer_that_throws_announces_nothing() {
        val p = AndroidHostPlatform({ null }, 30, { error("unused") }, { ServiceAnnouncer { _, _, _ -> throw IllegalStateException("boom") } })
        assertNull(p.announce("LocalGateKeys-ab12", 1, emptyMap()))
    }

    /** Runs queued tasks only when asked, like the background thread getting to them later. */
    private class Queue : Executor {
        val tasks = ArrayDeque<Runnable>()
        override fun execute(command: Runnable) { tasks.addLast(command) }
        fun runAll() { while (tasks.isNotEmpty()) tasks.removeFirst().run() }
    }

    private val wifi: InetAddress = InetAddress.getByAddress(byteArrayOf(192.toByte(), 168.toByte(), 1, 23))

    private fun jmdns(log: MutableList<String>, queue: Executor, openFails: Boolean = false, lockFails: Boolean = false, address: InetAddress? = wifi) =
        JmdnsAnnouncer(
            address = { address },
            multicastLock = {
                if (lockFails) throw SecurityException("no permission")
                log += "lock"
                AutoCloseable { log += "unlock" }
            },
            open = { inet, name, port, txt ->
                if (openFails) throw java.io.IOException("no multicast")
                log += "open ${inet.hostAddress} $name $port ${txt.toSortedMap()}"
                AutoCloseable { log += "stop" }
            },
            executor = queue,
        )

    @Test fun jmdns_binds_the_wifi_address_under_the_lock_and_releases_it_after_stopping() {
        val log = mutableListOf<String>()
        val q = Queue()
        val handle = jmdns(log, q).announce("LocalGateKeys-ab12", 4242, mapOf("v" to "1", "t" to "tag"))
        assertNotNull(handle)
        assertEquals(emptyList<String>(), log) // nothing blocks the caller: the work is queued
        q.runAll()
        assertEquals(listOf("lock", "open 192.168.1.23 LocalGateKeys-ab12 4242 {t=tag, v=1}"), log)
        handle!!.close()
        handle.close() // twice is harmless
        q.runAll()
        assertEquals(listOf("lock", "open 192.168.1.23 LocalGateKeys-ab12 4242 {t=tag, v=1}", "stop", "unlock"), log)
    }

    @Test fun jmdns_closed_before_it_started_never_starts() {
        val log = mutableListOf<String>()
        val q = Queue()
        jmdns(log, q).announce("n", 1, emptyMap())!!.close()
        q.runAll()
        assertEquals(emptyList<String>(), log)
    }

    @Test fun jmdns_that_fails_to_start_releases_the_lock_and_closes_safely() {
        val log = mutableListOf<String>()
        val q = Queue()
        val handle = jmdns(log, q, openFails = true).announce("n", 1, emptyMap())!!
        q.runAll()
        assertEquals(listOf("lock", "unlock"), log)
        handle.close()
        q.runAll()
        assertEquals(listOf("lock", "unlock"), log)
    }

    @Test fun jmdns_without_the_lock_does_not_start_and_closes_safely() {
        val log = mutableListOf<String>()
        val q = Queue()
        val handle = jmdns(log, q, lockFails = true).announce("n", 1, emptyMap())!!
        q.runAll()
        handle.close()
        q.runAll()
        assertEquals(emptyList<String>(), log)
    }

    @Test fun jmdns_without_a_wifi_address_announces_nothing() {
        val log = mutableListOf<String>()
        val q = Queue()
        assertNull(jmdns(log, q, address = null).announce("n", 1, emptyMap()))
        assertEquals(0, q.tasks.size)
    }

    @Test fun jmdns_close_survives_an_executor_that_refuses_work() {
        val log = mutableListOf<String>()
        var accept = true
        val ex = Executor { if (accept) it.run() else throw java.util.concurrent.RejectedExecutionException() }
        val handle = jmdns(log, ex).announce("n", 1, emptyMap())!!
        accept = false
        handle.close()
        assertEquals(listOf("lock", "open 192.168.1.23 n 1 {}", "stop", "unlock"), log)
    }
}
