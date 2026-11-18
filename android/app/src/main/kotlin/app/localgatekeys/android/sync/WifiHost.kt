package app.localgatekeys.android.sync

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.lan.Discovery
import app.localgatekeys.core.lan.HelloCounterSource
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.LanHostServer
import app.localgatekeys.core.lan.LanHostService
import app.localgatekeys.core.lan.MonotonicClock
import app.localgatekeys.core.lan.SystemMonotonicClock
import app.localgatekeys.core.sync.ShareGroups
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.SyncIssue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetAddress

/** The host's network seams: the app's Wi-Fi address and NSD announcement (tests: a fake on loopback). */
interface HostPlatform {
    /** This phone's Wi-Fi IPv4 address to listen on (a numeric literal); null when it is not on Wi-Fi. */
    fun wifiAddress(): String?

    /** Announces [name] (`_lgksync._tcp`) at [port] with the TXT record [txt]; returns what withdraws it (null: none). */
    fun announce(name: String, port: Int, txt: Map<String, String>): AutoCloseable?

    /** The socket address for [address] (a numeric literal: no lookup). Tests bind loopback while naming a LAN address. */
    fun bindAddress(address: String): InetAddress = InetAddress.getByName(address)
}

/**
 * Wi-Fi host mode (design 2026-11-13, the Mac's `LanHost` + `MacSyncScheduler` hosting rules): this phone listens for
 * the devices paired with it, shows a pairing QR code and serves sync to any joiner (desktop, Mac, iPhone, Android).
 *
 * * Off by default ([setEnabled], saved by the app). It listens only while the app is in front ([foreground]) and the
 *   vault is unlocked (the coordinator's gate), and stops on background, lock or the setting turned off.
 * * It listens on the Wi-Fi IPv4 address with a system-chosen port (the same port again when it can) and follows the
 *   address when it changes; the service is announced over NSD with the Mac's TXT record and a new neutral name.
 * * Pro: full hosting. Free (licence-only, as the Mac): it listens only while a pairing code is shown and for
 *   [LISTEN_WINDOW_SECONDS] after it closes or after Sync now; served peers' views are merged for licence states only.
 * * Peers are stored without an endpoint and are never dialled (they always connect to this phone).
 *
 * Main thread only (the coordinator's thread); the listener runs on its own threads and reports back to [scope].
 */
class WifiHost(
    private val coordinator: SyncCoordinator,
    private val counters: HelloCounterSource,
    private val platform: HostPlatform,
    scope: CoroutineScope,
    private val readEnabled: () -> Boolean,
    private val writeEnabled: (Boolean) -> Unit,
    private val monotonic: MonotonicClock = SystemMonotonicClock,
    private val tickMillis: Long = 1_000,
    /** The port this phone last listened on (saved across unlocks and restarts); null: none yet. */
    private val readPort: () -> Int? = { null },
    private val writePort: (Int) -> Unit = {},
) {
    enum class Problem { NO_WIFI, COULD_NOT_LISTEN, STOPPED, NOT_LISTENING }

    data class Status(
        val enabled: Boolean = false,
        val listening: Boolean = false,
        val endpoint: LanEndpoint? = null,
        val problem: Problem? = null,
        /** The last start followed this phone's address to a new one. */
        val followed: Boolean = false,
        /** Free: licence-only hosting inside the listen window. */
        val licenceOnly: Boolean = true,
        /** A pairing code could not be made (the reason code, `SyncWording.errorText`). */
        val showError: String? = null,
    )

    enum class ShowResult { SHOWN, NOT_LISTENING, FAILED }

    private val deps = coordinator.deps
    private val job = SupervisorJob(scope.coroutineContext[Job])
    private val scope = CoroutineScope(scope.coroutineContext + job)

    val pairing = HostPairing(coordinator.store, deps.random, deps.clock, monotonic)

    private val _status = MutableStateFlow(Status(enabled = readEnabled()))
    val status: StateFlow<Status> = _status.asStateFlow()

    /** Pro on this phone (read every tick and at every start); the app sets it. */
    var isPro: () -> Boolean = { false }

    /** Puts the pairing code text on the clipboard (the app's secret clipboard, cleared by itself). */
    var copy: (String) -> Unit = {}

    /** The app is in front (process lifecycle). */
    var foreground: Boolean = false
        set(value) {
            if (field == value) return
            field = value
            if (value) clearProblem()
            update()
        }

    @Volatile
    private var licenceOnlyFlag = true
    private var server: LanHostServer? = null
    private var service: LanHostService? = null
    private var announcement: AutoCloseable? = null
    private var announcedFor: String? = null
    private var lastAnnounceCheck: Double? = null
    private var instanceName = ""
    /** Bumped by every start and stop: a bind that finishes after another start or a stop is dropped. */
    private var generation = 0
    private var starting: Job? = null
    private var ticker: Job? = null
    /** Licence-only: the end of the listen window (monotonic seconds; null: closed). */
    private var listenUntil: Double? = null
    private var lastPort = 0
    private var shut = false

    init {
        pairing.onPaired = { this.scope.launch { pairedDevice() } }
    }

    private val wanted: Boolean get() = !shut && _status.value.enabled && foreground && coordinator.gate.isOpen

    val isListening: Boolean get() = server != null

    /** "Host Wi-Fi sync on this phone" turned on or off (saved). */
    fun setEnabled(on: Boolean) {
        if (shut) return
        writeEnabled(on)
        _status.value = _status.value.copy(enabled = on, problem = null, showError = null)
        update()
    }

    /** Re-reads every input (enabled, front, unlocked, Pro) and starts or stops listening to match. */
    fun update() {
        if (!wanted) {
            stop()
            ticker?.cancel(); ticker = null
            return
        }
        if (ticker == null) {
            ticker = scope.launch {
                while (isActive) {
                    delay(tickMillis)
                    tick()
                }
            }
        }
        readPro()
        followListenWindow()
        startIfWanted()
    }

    /** Every second while wanted: pairing countdowns, the announcement, the listen window and the address. */
    fun tick() {
        if (!wanted) {
            update()
            return
        }
        readPro()
        if (server != null) {
            pairing.tick()
            refreshAnnouncement(force = false)
        }
        followListenWindow()
        checkAddress()
        if (server == null && _status.value.problem != Problem.COULD_NOT_LISTEN) startIfWanted()
    }

    /** "Sync now" (and the run after a device was added): a free host listens for [LISTEN_WINDOW_SECONDS]. */
    fun syncNow() {
        if (!wanted) return
        readPro()
        if (licenceOnlyFlag) openListenWindow()
    }

    /** The vault locked: stop, and nothing listens again for this unlock. */
    fun shutdown() {
        shut = true
        stop()
        ticker?.cancel(); ticker = null
        job.cancel()
    }

    // MARK: pairing

    /**
     * "Show QR code": a new offer at the listening address (a Wi-Fi group is created when there is none). A free host
     * that is not listening opens its listen window and waits for the listener first.
     */
    suspend fun showQr(): ShowResult {
        if (!wanted) return ShowResult.NOT_LISTENING.also { setProblem(Problem.NOT_LISTENING) }
        readPro()
        if (server == null) {
            if (licenceOnlyFlag) openListenWindow() else startIfWanted()
            starting?.join()
        }
        val srv = server
        val ep = _status.value.endpoint
        if (srv == null || ep == null || !wanted) return ShowResult.NOT_LISTENING.also { if (_status.value.problem == null) setProblem(Problem.NOT_LISTENING) }
        val mine = generation
        val handler = try {
            withContext(deps.io) { pairing.begin(ep, deps.slots.installId()) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: SyncActionException) {
            _status.value = _status.value.copy(showError = e.reason)
            return ShowResult.FAILED
        } catch (e: Exception) {
            _status.value = _status.value.copy(showError = "")
            return ShowResult.FAILED
        }
        if (generation != mine || server !== srv) {
            pairing.close()
            return ShowResult.NOT_LISTENING
        }
        srv.enrollment = handler
        _status.value = _status.value.copy(showError = null)
        followListenWindow()
        refreshAnnouncement(force = true) // a Wi-Fi group may have just been made
        return ShowResult.SHOWN
    }

    /** "Copy code text": true when the open offer's text went to the clipboard. */
    fun copyCode(): Boolean {
        val text = pairing.copyCodeText() ?: return false
        copy(text)
        return true
    }

    /** Close the pairing sheet: the offer is disarmed (later requests get no answer). */
    fun closePairing() {
        server?.enrollment = null
        pairing.close()
        followListenWindow()
    }

    /** Undo the device just added (revoked). */
    suspend fun undo(): Boolean {
        val ok = withContext(deps.io) { pairing.undo() }
        if (ok) coordinator.hostServed()
        return ok
    }

    /** "Remove…" on a paired device: revoked (it stays listed, so its id cannot come back). */
    suspend fun remove(deviceId: String): Boolean {
        val ok = withContext(deps.io) {
            try {
                val snap = coordinator.store.load()
                val state = snap.sync ?: return@withContext false
                val (revoked, found) = app.localgatekeys.core.lan.LanPeers.revoking(deviceId, state)
                if (!found) return@withContext false
                coordinator.store.commit(StoreChange(snap.revision, snap.records, snap.meta, revoked))
                true
            } catch (e: Exception) {
                false
            }
        }
        if (ok) coordinator.hostServed()
        return ok
    }

    private fun pairedDevice() {
        if (!coordinator.gate.isOpen) return
        coordinator.hostServed()
        // As the Mac: the host syncs after a device was added (a free host keeps listening for a while).
        scope.launch { coordinator.sync(SyncCoordinator.Trigger.MANUAL) }
    }

    // MARK: runs

    /**
     * After each coordinator run (on its thread): the issues seen while serving peers (reported once), the witness
     * memory saved, and the announcement renewed (a run may have rotated the key: new epoch, new tag).
     */
    suspend fun afterRun(): List<SyncIssue> {
        val svc = service ?: return emptyList()
        val issues = withContext(deps.io) {
            val report = svc.takeReport()?.issues ?: emptyList()
            if (coordinator.gate.isOpen) flushWitness()
            report
        }
        if (server != null) refreshAnnouncement(force = true)
        return issues
    }

    private fun flushWitness() {
        try {
            val store = coordinator.store
            val snap = store.load()
            val state = snap.sync ?: return
            val peers = state.lanPeers.filter { !it.revoked }.map { it.deviceId }
            val flushed = coordinator.witnessMemory.flush(state, peers) ?: return
            store.commit(StoreChange(snap.revision, snap.records, snap.meta, flushed))
            coordinator.witnessMemory.markSaved(flushed.peerGenerations.keys, deps.clock.now)
        } catch (e: Exception) {
            // Witness bookkeeping never fails the run; the next run tries again.
        }
    }

    // MARK: listening

    private fun readPro() {
        val pro = try {
            isPro()
        } catch (e: Exception) {
            false
        }
        licenceOnlyFlag = !pro
        if (pro) listenUntil = null
        if (_status.value.licenceOnly != !pro) _status.value = _status.value.copy(licenceOnly = !pro)
    }

    /** True when the host may listen: always with Pro; while free, while a pairing code is shown or the window is open. */
    fun mayListen(): Boolean {
        if (!licenceOnlyFlag) return true
        if (pairing.isShown) return true
        val until = listenUntil ?: return false
        return monotonic.seconds() < until
    }

    private fun openListenWindow() {
        val until = monotonic.seconds() + LISTEN_WINDOW_SECONDS
        if ((listenUntil ?: Double.NEGATIVE_INFINITY) < until) listenUntil = until
        startIfWanted()
    }

    /** A shown code keeps the window open until [LISTEN_WINDOW_SECONDS] after it closes; outside it a free host stops quietly. */
    private fun followListenWindow() {
        if (!licenceOnlyFlag) return
        if (pairing.isShown) {
            val until = monotonic.seconds() + LISTEN_WINDOW_SECONDS
            if ((listenUntil ?: Double.NEGATIVE_INFINITY) < until) listenUntil = until
            return
        }
        if (mayListen()) return
        listenUntil = null
        if (server != null || starting != null) stop()
    }

    /** Follows this phone's address: a new Wi-Fi address means listening there instead; none means stopped until it returns. */
    private fun checkAddress() {
        val listening = _status.value.endpoint ?: return
        if (server == null) return
        val current = platform.wifiAddress()
        if (current == listening.host) return
        stop()
        if (current == null) {
            setProblem(Problem.STOPPED)
        } else {
            startIfWanted(followed = true)
        }
    }

    private fun startIfWanted(followed: Boolean = false) {
        if (!wanted || !mayListen() || server != null || starting != null) return
        val address = platform.wifiAddress()
        if (address == null) {
            // "Stopped" (the listening address went away) stays until Wi-Fi is back.
            if (_status.value.problem != Problem.STOPPED) setProblem(Problem.NO_WIFI)
            return
        }
        generation += 1
        val mine = generation
        // The same port every time (paired devices dial their saved address first): the last one, else the desktop's.
        val port = if (lastPort > 0) lastPort else readPort()?.takeIf { it in 1..65535 } ?: FIRST_PORT
        starting = scope.launch {
            val bound = try {
                // Not cancellable: a listener bound after a stop or a lock is always stopped below.
                withContext(deps.io + NonCancellable) { bind(address, port) }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                null
            }
            if (generation != mine) {
                bound?.server?.stop()
                return@launch
            }
            starting = null
            if (bound == null) {
                setProblem(Problem.COULD_NOT_LISTEN)
                return@launch
            }
            val (svc, srv, endpoint) = bound
            // Locked, turned off, sent to the background or out of the window while binding: never keep this listener.
            if (!wanted || !mayListen()) {
                srv.stop()
                return@launch
            }
            service = svc
            server = srv
            if (readPort() != endpoint.port) writePort(endpoint.port)
            lastPort = endpoint.port
            instanceName = Discovery.instanceName(deps.random)
            _status.value = _status.value.copy(listening = true, endpoint = endpoint, problem = null, followed = followed)
            refreshAnnouncement(force = true)
        }
    }

    private data class Bound(val service: LanHostService, val server: LanHostServer, val endpoint: LanEndpoint)

    /** Blocking: the service over the gated store, the listener bound on [address] ([port] again when free, else any). */
    private fun bind(address: String, port: Int): Bound {
        val installId = deps.slots.installId()
        val svc = LanHostService(
            // The host-side merge's commits are a sync in item history, not edits (scan A-L3).
            app.localgatekeys.android.history.CommitOrigin.recording("sync", coordinator.store), installId, counters, deps.random, deps.clock, deps.licenseKeys, coordinator.witnessMemory,
            attachments = deps.attachments, licenceOnly = { licenceOnlyFlag },
            // Personal collections (sub-plan 07): this host answers `features` and merges collection states with the
            // peers that listed them, with the share records of the snapshot each merge uses.
            collections = true, collectionShares = { ShareGroups.collectionShares(it) },
        )
        val srv = LanHostServer(svc, monotonic, onServed = { scope.launch { if (coordinator.gate.isOpen) coordinator.hostServed() } })
        val inet = platform.bindAddress(address)
        val bound = try {
            srv.start(inet, port)
        } catch (e: IOException) {
            if (port == 0) throw e
            srv.start(inet, 0)
        }
        return Bound(svc, srv, LanEndpoint(address, bound))
    }

    /** Renews the NSD announcement when the UTC day, the group or its key epoch changed (read at most once a minute). */
    private fun refreshAnnouncement(force: Boolean) {
        val srv = server ?: return
        val endpoint = _status.value.endpoint ?: return
        val t = monotonic.seconds()
        val last = lastAnnounceCheck
        if (!force && last != null && t - last < ANNOUNCE_CHECK_SECONDS) return
        lastAnnounceCheck = t
        val mine = generation
        scope.launch {
            val made = try {
                withContext(deps.io) { announcementData() }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                null
            }
            if (generation != mine || server !== srv) return@launch
            val key = made?.second
            if (key == announcedFor) return@launch
            announcement?.closeQuietly()
            announcement = null
            announcedFor = key
            if (made != null) announcement = platform.announce(instanceName, endpoint.port, made.first)
        }
    }

    /** The TXT record of this phone's group at the current UTC day and what it was made from; null while in no group. */
    private fun announcementData(): Pair<Map<String, String>, String>? {
        val state = coordinator.store.load().sync ?: return null
        val gk = GroupKey(state.groupId, state.epoch, state.key)
        val now = deps.clock.now
        return Discovery.txtRecord(gk, state.deviceId, now) to "${Discovery.utcDay(now)}|${state.groupId}|${state.epoch}"
    }

    private fun stop() {
        generation += 1
        // Never cancelled: a bind in flight finishes and is dropped (stopped) by its generation check.
        starting = null
        pairing.close()
        announcement?.closeQuietly()
        announcement = null
        announcedFor = null
        lastAnnounceCheck = null
        val srv = server
        server = null
        service = null
        srv?.stop()
        val s = _status.value
        if (s.listening || s.endpoint != null || s.followed) _status.value = s.copy(listening = false, endpoint = null, followed = false)
    }

    private fun setProblem(p: Problem) {
        if (_status.value.problem != p) _status.value = _status.value.copy(problem = p)
    }

    private fun clearProblem() {
        if (_status.value.problem != null) _status.value = _status.value.copy(problem = null)
    }

    private fun AutoCloseable.closeQuietly() {
        try {
            close()
        } catch (e: Exception) {
            // already withdrawn
        }
    }

    override fun toString(): String = "WifiHost(listening=${server != null})"

    companion object {
        /** Desktop `LICENCE_ONLY_LISTEN_SECONDS`: how long a free host keeps listening after Sync now or a pairing code. */
        const val LISTEN_WINDOW_SECONDS = 120.0

        /** How often the announcement re-reads the group state (the UTC day and the key epoch). */
        const val ANNOUNCE_CHECK_SECONDS = 60.0

        /** The first port tried when none is saved: the desktop's DEFAULT_LAN_PORT (a system port when it is taken). */
        const val FIRST_PORT = 47821
    }
}
