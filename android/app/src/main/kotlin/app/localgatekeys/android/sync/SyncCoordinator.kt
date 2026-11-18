package app.localgatekeys.android.sync

import app.localgatekeys.android.history.CommitOrigin
import app.localgatekeys.android.R
import app.localgatekeys.core.sync.PeerSeenAt
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.trash.LocalDataHosting
import app.localgatekeys.core.lan.LanFeatures
import app.localgatekeys.core.lan.LanPeer
import app.localgatekeys.core.lan.LanPeerNotAnswering
import app.localgatekeys.core.sync.ShareGroups
import app.localgatekeys.core.sync.CollectionShares
import app.localgatekeys.core.lan.BlobFetch
import app.localgatekeys.core.sync.AttachmentRef
import app.localgatekeys.core.sync.AttachmentSync
import app.localgatekeys.core.sync.Documents
import app.localgatekeys.android.vault.Slot
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.keyring.KeyringException
import app.localgatekeys.core.lan.Enrollment
import app.localgatekeys.core.lan.LanAddress
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.LanExchange
import app.localgatekeys.core.lan.LanPublish
import app.localgatekeys.core.lan.LanSyncException
import app.localgatekeys.core.lan.PairingException
import app.localgatekeys.core.lan.PairingOffer
import app.localgatekeys.core.lan.PinnedPeer
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.recovery.Heir
import app.localgatekeys.core.sync.FolderAccess
import app.localgatekeys.core.sync.FolderAccessException
import app.localgatekeys.core.sync.FolderLayout
import app.localgatekeys.core.sync.FolderSync
import app.localgatekeys.core.sync.FolderSyncException
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.KeptIdentity
import app.localgatekeys.core.sync.Removal
import app.localgatekeys.core.sync.RunReport
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import app.localgatekeys.core.sync.SyncIssue
import app.localgatekeys.core.sync.SyncRunner
import app.localgatekeys.core.sync.Witness
import app.localgatekeys.core.sync.WitnessMemory
import kotlin.coroutines.ContinuationInterceptor
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.MainCoroutineDispatcher
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext

/** What one sync run found (Swift `SyncRunResult`). */
data class SyncRunResult(
    val issues: List<SyncIssue> = emptyList(),
    val conflicts: Int = 0,
    val ran: Boolean = false,
    /** The run ended with the store still open: republish the autofill identities (through the ordered chain). */
    val publish: Boolean = false,
    /**
     * The share groups' runs after the personal group (sub-plan 07); null when none ran (no share, or no Recently
     * deleted to put a share's deletes in yet: then each group says so).
     */
    val shares: ShareRuns.Runs? = null,
)

/**
 * What share runs need from the app for one coordinator run (sub-plan 07): Pro (read once, when the run starts) and
 * Recently deleted, which takes every live item a share commit removes.
 */
class ShareHost(val isPro: Boolean, val local: LocalDataHosting) {
    override fun toString(): String = "ShareHost(pro=$isPro)"
}

/**
 * The Sync screen's state machine (port of `ios/App/Sync/SyncCoordinator.swift`): `IDLE` -> `SYNCING` -> `IDLE`, or
 * `IDLE` -> `JOINING` -> (`SYNCING`) -> `IDLE`.
 *
 * * Sync runs on unlock (APP_OPEN), on coming back to the app (FOREGROUND), on pull-to-refresh, 2 s after the last local edit, and on "Sync now".
 * * Never two runs at once: a request while one runs is folded into ONE more run after it.
 * * The store is only ever written through [ItemStore.commit] inside the core folder transport, or after a complete
 *   LAN exchange; a failed run leaves it untouched. No failure escapes to the caller: runs report through [issues],
 *   actions through [actionError].
 * * [shutdown] (the vault locked) closes the [gate]: from then on nothing is read or committed, the edit timer and the
 *   run, join and identity update in flight are cancelled.
 *
 * Threading, like the iPhone's @MainActor: all state lives on [scope]'s thread (the main thread in the app). Suspend
 * calls hop there themselves; the non-suspend ones must be made there (checked on the main dispatcher). Blocking
 * store, slot, folder and socket work runs on [SyncDependencies.io].
 */
class SyncCoordinator(store: ItemStore, val deps: SyncDependencies, scope: CoroutineScope, private val t: Txt) {
    /** The sync wording in the language of the running Activity (see `SwitchableTxt`). */
    private val words = SyncWording(t)

    enum class Phase { IDLE, SYNCING, JOINING }
    enum class Trigger {
        APP_OPEN, FOREGROUND, PULL_TO_REFRESH, LOCAL_EDIT, MANUAL,

        /** The run a join or leave asked for while it was working: part of that action, so never held back. */
        AFTER_ACTION;

        /** Started by the app, not the person: held back while "Sync automatically" is off. */
        val isAutomatic: Boolean get() = this == APP_OPEN || this == FOREGROUND || this == LOCAL_EDIT
    }

    /** What the Sync screen shows about this vault's group. [hasFolderUri]: the picked folder's URI is stored. */
    data class Membership(
        val joined: Boolean = false,
        val hasFolder: Boolean = false,
        val hasFolderUri: Boolean = false,
        val peer: PinnedPeer? = null,
        val deviceId: String? = null,
        /** The group's other folder members (sorted; not this device). */
        val members: List<String> = emptyList(),
        /** Peer id -> when this device last accepted its changes (Unix seconds; workstream 6). */
        val peerSyncedAt: Map<String, Long> = emptyMap(),
        /** Member id -> its name in the stored keyring (null: unreadable). Names come from peers: sanitize before showing. */
        val names: Map<String, String?> = emptyMap(),
        /** Members added by another device that this phone has not confirmed ("These are my devices"); sorted. */
        val unconfirmed: List<String> = emptyList(),
        /** Devices paired with this phone as a Wi-Fi host (revoked ones too; names come from peers: sanitize). */
        val lanPeers: List<LanPeer> = emptyList(),
    ) {
        /** The peer's public keys are not shown either. */
        override fun toString(): String =
            "Membership(joined=$joined, hasFolder=$hasFolder, hasFolderUri=$hasFolderUri, peer=${peer?.deviceId}, deviceId=$deviceId, " +
                "members=${members.size})"
    }

    val gate = SessionGate()

    /** Every read and write of the coordinator goes through this gated view. */
    val store: ItemStore = GatedStore(store, gate)

    /**
     * The unlock session's rollback-witness memory (desktop `witness_memory`): the highest generation checked from each
     * peer, saved throttled by LAN runs and flushed at the end of every run (so before the vault locks).
     */
    val witnessMemory = WitnessMemory()

    /**
     * "This was me": the user restored this vault on purpose (`vault-rollback`). Only for the explicit button, after
     * the user confirmed and re-authenticated; nothing calls it automatically (no acknowledgement after a restore).
     * Raises the generation above what the peers witnessed and clears the warning in one commit.
     */
    suspend fun acknowledgeVaultRollback(): Boolean = onConfined {
        withContext(deps.io) {
            try {
                Witness.acknowledgeVaultRollback(store)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                false
            }
        }
    }

    /** The user dismissed `peer-vault-rollback` for [peerId]: accept that device's older copy. */
    suspend fun forgetPeerGeneration(peerId: String): Boolean = onConfined {
        withContext(deps.io) {
            try {
                Witness.forgetPeerGeneration(store, peerId, witnessMemory)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                false
            }
        }
    }

    private val job = SupervisorJob(scope.coroutineContext[Job])
    private val scope = CoroutineScope(scope.coroutineContext + job)

    private val _phase = MutableStateFlow(Phase.IDLE)
    val phase: StateFlow<Phase> = _phase.asStateFlow()
    private val _membership = MutableStateFlow(Membership())
    val membership: StateFlow<Membership> = _membership.asStateFlow()
    private val _issues = MutableStateFlow<List<SyncWording.IssueView>>(emptyList())
    val issues: StateFlow<List<SyncWording.IssueView>> = _issues.asStateFlow()
    private val _lastSyncedAt = MutableStateFlow<Long?>(null)
    val lastSyncedAt: StateFlow<Long?> = _lastSyncedAt.asStateFlow()

    /** Conflict copies made since unlock (the desktop shows the same count). */
    private val _conflictCopies = MutableStateFlow(0)
    val conflictCopies: StateFlow<Int> = _conflictCopies.asStateFlow()

    /** Bumped after every run, so lists reload. */
    private val _completedRuns = MutableStateFlow(0)
    val completedRuns: StateFlow<Int> = _completedRuns.asStateFlow()

    /** Text for the last refused action (join, leave, reset), desktop `error_text` wording. */
    private val _actionError = MutableStateFlow<String?>(null)
    val actionError: StateFlow<String?> = _actionError.asStateFlow()

    /** Text for the last completed action. */
    private val _actionInfo = MutableStateFlow<String?>(null)
    val actionInfo: StateFlow<String?> = _actionInfo.asStateFlow()

    /** The address a QR join is dialling (spinner text); null otherwise. */
    private val _connecting = MutableStateFlow<LanEndpoint?>(null)
    val connecting: StateFlow<LanEndpoint?> = _connecting.asStateFlow()

    /**
     * The 6-digit verification code of the QR join in flight, shown while the inviting device waits for its user's
     * Accept (the same code is shown there); null otherwise.
     */
    private val _verificationCode = MutableStateFlow<String?>(null)
    val verificationCode: StateFlow<String?> = _verificationCode.asStateFlow()

    // Shared collections (sub-plan 07): each share group syncs through its own folder after the personal group.

    /** The last run's issues of each share group (group id -> issues; empty: it synced). Words: [SyncWording.shareStatus]. */
    private val _shareIssues = MutableStateFlow<Map<String, List<SyncIssue>>>(emptyMap())
    val shareIssues: StateFlow<Map<String, List<SyncIssue>>> = _shareIssues.asStateFlow()

    /**
     * Collections this device was removed from since unlock (collection id -> the `share-removed` issue): the share group
     * is gone, so the status stays with the collection, whose items went to Recently deleted.
     */
    private val _removedShares = MutableStateFlow<Map<String, SyncIssue>>(emptyMap())
    val removedShares: StateFlow<Map<String, SyncIssue>> = _removedShares.asStateFlow()

    /** The reason code of the last refused share action ([ShareRuns.reason]); null after one that worked. */
    private val _shareActionReason = MutableStateFlow<String?>(null)
    val shareActionReason: StateFlow<String?> = _shareActionReason.asStateFlow()

    /** After a member removal: false when the removal notice or the rotated keyring could not be written to the folder. */
    private val _shareRemovalWritten = MutableStateFlow(true)
    val shareRemovalWritten: StateFlow<Boolean> = _shareRemovalWritten.asStateFlow()

    /** After a share upgrade: false when the upgraded keyring could not be written to the folder yet. */
    private val _shareUpgradeWritten = MutableStateFlow(true)
    val shareUpgradeWritten: StateFlow<Boolean> = _shareUpgradeWritten.asStateFlow()

    /**
     * Pro on this device, read on the coordinator's thread when a run or a share action starts: creating, joining and
     * syncing a shared collection need Pro. The app sets it at unlock; the default runs no share.
     */
    var isPro: () -> Boolean = { false }

    /**
     * Recently deleted for shared collections (this unlock's local data). Null: no share runs, since a share's deletes
     * and a removal would have nowhere to go (each share group says so).
     */
    var shareTrash: LocalDataHosting? = null

    /**
     * This unlock's Wi-Fi host (the phone listens for its paired devices); null when the app made none. Stopped by
     * [shutdown]; a person-started run opens a free host's listen window, and each run reports what it served.
     */
    var host: WifiHost? = null

    /** The host served a peer outside a run (a merge may have changed the vault): lists reload, membership is re-read. */
    fun hostServed() {
        assertConfined()
        if (!gate.isOpen) return
        _completedRuns.value += 1
        refreshIdentities()
        scope.launch { refreshMembership() }
    }

    /** The status of share group [groupId]'s last run: null when it synced or has not run since unlock ([shareRan]). */
    fun shareStatus(groupId: String): SyncWording.ShareStatus? = words.shareStatus(_shareIssues.value[groupId] ?: emptyList())

    /** Whether share group [groupId] was run (or held back, with its reason) since unlock. */
    fun shareRan(groupId: String): Boolean = _shareIssues.value[groupId] != null

    val isBusy: Boolean get() = _phase.value != Phase.IDLE

    private var syncAfterAction = false
    private var runner: Job? = null
    private var rerun = false
    private var editJob: Job? = null
    private var wrongPasswords = 0
    private var backoffUntil = 0L
    /** The latest identity update; each one waits for the one before. */
    private var identityJob: Job? = null
    /** The QR join's enrollment in flight ([cancelJoin]). */
    private var joinJob: Deferred<Unit>? = null
    /** The join, attach, leave or reset in flight: it runs in the coordinator's scope, so its bookkeeping always runs. */
    private var actionJob: Deferred<Boolean>? = null
    /** Numbers each QR join, so a late "connected" hop never clears a later join's address. */
    private var joinSerial = 0

    /** The thread every call runs on (Main.immediate when the scope is on the main dispatcher). */
    private val confined: CoroutineDispatcher = (scope.coroutineContext[ContinuationInterceptor] as? CoroutineDispatcher)
        .let { d -> if (d is MainCoroutineDispatcher) d.immediate else d ?: error("SyncCoordinator needs a scope with a dispatcher") }

    init {
        this.scope.launch { refreshMembership() }
    }

    /** Suspend entry points hop to the coordinator's thread, so its state is only ever touched there. */
    private suspend fun <T> onConfined(block: suspend () -> T): T = withContext(confined) { block() }

    /** Non-suspend entry points must already be on the main thread (checked when the scope is on the main dispatcher). */
    private fun assertConfined() {
        if (confined is MainCoroutineDispatcher) {
            check(!confined.isDispatchNeeded(EmptyCoroutineContext)) { "SyncCoordinator must be called on the main thread" }
        }
    }

    /**
     * The work in flight when [shutdown] ran. A cancelled action stops waiting for its blocking step at once (and drops
     * its reference), so [shutdownAndWait] after a plain [shutdown] (the lock comes first) still waits for these.
     */
    private val stopping = ArrayList<Job>()

    /** The vault locked: stop the edit timer and the work in flight; nothing reads or commits after this. */
    fun shutdown() {
        assertConfined()
        for (j in listOfNotNull(joinJob, actionJob, runner, identityJob)) if (stopping.none { it === j }) stopping.add(j)
        gate.close()
        host?.shutdown()
        editJob?.cancel(); editJob = null
        joinJob?.cancel()
        runner?.cancel()
        identityJob?.cancel()
        job.cancel()
    }

    /**
     * [shutdown], then waits for the join, run and identity update in flight to finish, including those a [shutdown]
     * before it stopped (erase: the lock shuts the coordinator down first).
     */
    suspend fun shutdownAndWait(): Unit = onConfined {
        shutdown()
        val all = stopping.toList()
        for (j in all) j.join()
        stopping.removeAll { it.isCompleted }
    }

    /** A setting that changes what autofill offers: republish the identities, in order. */
    fun identitySettingsChanged() = refreshIdentities()

    /** Republishes the autofill identities after the update queued before it (after settings changes and local commits). */
    fun refreshIdentities() {
        assertConfined()
        val previous = identityJob
        identityJob = scope.launch {
            previous?.join()
            if (!gate.isOpen || !isActive) return@launch
            deps.autoFill.syncDidFinish(store)
        }
    }

    /** Waits for the identity updates queued so far (tests). */
    suspend fun identitiesSettled(): Unit = onConfined {
        identityJob?.join()
    }

    /** Numbers each membership refresh, so a slower older one never overwrites a newer one. */
    private var refreshSerial = 0L
    private var appliedSerial = 0L

    /** Re-reads what the screen shows about the group (off the coordinator's thread). Locked: nothing is read. */
    suspend fun refreshMembership(): Unit = onConfined {
        if (!gate.isOpen) return@onConfined
        val serial = ++refreshSerial
        val m = withContext(deps.io) {
            val snap = try {
                store.load()
            } catch (e: Exception) {
                null
            }
            val state = snap?.sync
            // Ruling 16: a pinned peer whose group is not this store's (a join stopped by a lock between pin and commit)
            // is not trusted, and is removed while the slots are writable (state re-read under the pin lock).
            if (snap != null && gate.isOpen) dropStalePeer(store, deps)
            Membership(
                joined = state != null,
                hasFolder = state?.hasFolder ?: false,
                // The URI is kept and the app still holds its permission (revoked in settings: choose it again).
                hasFolderUri = readSlotOrNull(deps, Slot.FOLDER_URI)?.let { folderAvailable(deps, it) } ?: false,
                peer = trustedPeerOrNull(deps, state),
                deviceId = state?.deviceId,
                members = state?.members?.filter { it != state.deviceId }?.sorted() ?: emptyList(),
                peerSyncedAt = state?.let { PeerSeenAt.merged(it.groupId, it.peerSyncedAt) } ?: emptyMap(),
                names = state?.let { FolderSync.storedMemberNames(it) } ?: emptyMap(),
                unconfirmed = state?.unackedMembers?.filter { it != state.deviceId } ?: emptyList(),
                lanPeers = state?.lanPeers ?: emptyList(),
            )
        }
        if (gate.isOpen && serial > appliedSerial) {
            appliedSerial = serial
            _membership.value = m
        }
    }

    // MARK: sync

    /** Runs one sync, or joins the one in flight and asks it for one more run. */
    suspend fun sync(trigger: Trigger = Trigger.MANUAL): Unit = onConfined {
        if (!gate.isOpen) return@onConfined
        if (trigger.isAutomatic && !deps.autoSync()) return@onConfined
        // A person-started run: a free host listens for a while, so a paired device can connect.
        if (trigger == Trigger.MANUAL || trigger == Trigger.PULL_TO_REFRESH) host?.syncNow()
        if (_phase.value == Phase.JOINING) { // run once the join/leave has finished
            syncAfterAction = true
            return@onConfined
        }
        runner?.let {
            rerun = true
            it.join()
            return@onConfined
        }
        val task = scope.launch(start = CoroutineStart.LAZY) { runLoop() }
        runner = task
        task.start()
        task.join()
    }

    /** After a local edit: sync once the user has stopped editing for [SyncDependencies.editDebounceMillis]. */
    fun noteLocalEdit() {
        assertConfined()
        refreshIdentities()
        editJob?.cancel()
        if (!gate.isOpen) return
        editJob = scope.launch {
            deps.sleep(deps.editDebounceMillis)
            sync(Trigger.LOCAL_EDIT)
        }
    }

    private suspend fun runLoop() {
        try {
            do {
                rerun = false
                _phase.value = Phase.SYNCING
                val ran = runAll(store, deps, witnessMemory, shareHost(), proNow())
                // What the host saw while serving peers since the last run (reported once), as the Mac's host issues.
                val served = host?.afterRun() ?: emptyList()
                val result = if (served.isEmpty()) ran else ran.copy(issues = ran.issues + served)
                apply(result)
                publish(result)
            } while (rerun && gate.isOpen && currentCoroutineContext().isActive)
        } finally {
            _phase.value = Phase.IDLE
            runner = null
        }
    }

    /** Queues the identity update after the ones before it and waits for it, so a finished sync has published. */
    private suspend fun publish(result: SyncRunResult) {
        if (!result.publish || !gate.isOpen) return
        refreshIdentities()
        identityJob?.join()
    }

    private suspend fun apply(result: SyncRunResult) {
        if (!gate.isOpen) return
        // A verified signed removal notice: the app checks the erase setting (it may erase, which ends this coordinator).
        if (result.issues.any { it.kind == SyncWording.REMOVAL_NOTICE_KIND }) deps.onRemovalNotice()
        refreshMembership()
        if (!gate.isOpen) return
        if (result.ran) {
            // A host that refused this phone synced nothing: "Last synced" keeps its time and
            // "The first sync is running" goes away.
            if (result.issues.none { it.kind == NOT_ACCEPTED }) {
                _lastSyncedAt.value = deps.clock.now
            } else if (_actionInfo.value == t.s(R.string.sync_joined_info)) {
                _actionInfo.value = null
            }
            _conflictCopies.value += result.conflicts
            val m = _membership.value
            _issues.value = words.views(result.issues, ownID = m.deviceId, folder = m.hasFolder)
        } else {
            _issues.value = emptyList()
        }
        result.shares?.let { shares ->
            if (!result.ran) _conflictCopies.value += shares.conflicts // a joined run counted them in `conflicts`
            _shareIssues.value = shares.issues
            // The group of a removal is gone: its status stays with the collection.
            val removed = shares.issues.values.flatten().filter { it.kind == "share-removed" }
            if (removed.isNotEmpty()) _removedShares.value = _removedShares.value + removed.associateBy { it.detail }
        }
        _completedRuns.value += 1
    }

    /** The share host of one run: null without Recently deleted (no share runs then; each group reports `item-error`). */
    private fun shareHost(): ShareHost? {
        val local = shareTrash ?: return null
        return ShareHost(proNow(), local)
    }

    private fun proNow(): Boolean = try {
        isPro()
    } catch (e: Exception) {
        false
    }

    // MARK: joining

    /** Wi-Fi: scanned (or pasted) QR text -> enrollment -> pin the inviter -> first sync. */
    suspend fun joinByQr(text: String): Boolean = onConfined { runAction { joinByQrWork(text) } }

    private suspend fun joinByQrWork(text: String): Boolean {
        _connecting.value = try {
            PairingOffer.parseQr(text.trim()).endpoint
        } catch (e: Exception) {
            null
        }
        joinSerial += 1
        val serial = joinSerial
        val onConnected: () -> Unit = { scope.launch { if (joinSerial == serial) _connecting.value = null } }
        // Only while this join is still running: a late hop never shows the code of a finished join.
        val onCode: (String) -> Unit = { code ->
            scope.launch { if (joinSerial == serial && _phase.value == Phase.JOINING && joinJob != null) _verificationCode.value = code }
        }
        val store = store
        val deps = deps
        val task = scope.async(deps.io) { enroll(text, store, deps, onConnected, onCode) }
        joinJob = task
        // null: joined. A cancelled join (Cancel, or the lock) is not a cancelled caller: only the join stopped.
        val failure: Exception? = try {
            task.await()
            null
        } catch (e: CancellationException) {
            if (!currentCoroutineContext().isActive) { // the coordinator shut down (lock): runAction resets the phase
                joinJob = null; _connecting.value = null; _verificationCode.value = null
                throw e
            }
            JoinCancelled()
        } catch (e: Exception) {
            e
        }
        joinJob = null; _connecting.value = null; _verificationCode.value = null
        when {
            failure == null -> {
                _phase.value = Phase.IDLE
                syncAfterAction = false // the first sync below includes any edit made meanwhile
                _actionInfo.value = t.s(R.string.sync_joined_info)
                refreshMembership()
                sync(Trigger.MANUAL)
                return true
            }
            failure is JoinCancelled || (failure is EnrollConnectException && failure.failure == LanFailure.CANCELLED) -> {
                _phase.value = Phase.IDLE
                _actionInfo.value = t.s(R.string.sync_enroll_cancelled)
                refreshMembership()
                runPendingSync()
                return false
            }
            else -> {
                fail(failure)
                return false
            }
        }
    }

    /**
     * Find again (plan 2026-10-29-sync-ip-change, section 4): the PC's fresh pairing QR, scanned when its pinned address
     * and discovery both failed. Only the address changes, and only when the QR's group, device id, signing key and
     * exchange key equal the pinned host's: nothing is enrolled, nothing else is stored. Another device's QR is refused.
     */
    suspend fun findAgain(text: String): Boolean = onConfined {
        if (!beginAction()) return@onConfined false
        val found: LanEndpoint = try {
            val state = store.load().sync ?: throw SyncActionException("not-joined")
            val deps = deps
            withContext(deps.io) {
                synchronized(PIN_LOCK) {
                    val peer = trustedPeerOrNull(deps, state) ?: throw SyncActionException("find-again-not-paired")
                    val endpoint = addressFromOffer(peer, text, deps.clock.now)
                    if (endpoint != peer.endpoint) deps.slots.setPairedPeer(peer.copy(endpoint = endpoint))
                    endpoint
                }
            }
        } catch (e: CancellationException) {
            _phase.value = Phase.IDLE
            throw e
        } catch (e: Exception) {
            fail(if (e is SyncActionException) e else SyncActionException("find-again-failed"))
            return@onConfined false
        }
        _phase.value = Phase.IDLE
        _issues.value = _issues.value.filter { it.kind != "unreachable" }
        _actionInfo.value = words.foundAgainText(found)
        refreshMembership()
        sync(Trigger.MANUAL)
        true
    }

    /**
     * Stops a QR join that is still connecting (the Cancel button next to "Connecting to ..."). Once the connection is
     * up ([connecting] is null) it does nothing: the join completes or fails on its own.
     */
    fun cancelJoin() {
        assertConfined()
        if (_connecting.value == null) return
        joinJob?.cancel()
    }

    /** Cloud folder: picked folder URI + sync password -> join (new member), or attach when already in the group by QR. */
    suspend fun joinFolder(uri: String, password: String): Boolean = onConfined {
        val now = deps.clock.now
        // The wrong-password back-off guards only paths that check the password; re-picking the folder of a group
        // this phone already syncs through does not.
        if (now < backoffUntil && !withContext(deps.io) { isRepick(store, deps) }) {
            _actionError.value = words.passwordBackoffText
            releaseUnusedFoldersNow()
            false
        } else {
            var started = false
            val ok = runAction {
                started = true
                joinFolderAndReport(uri, password, now)
            }
            if (!started) releaseUnusedFoldersNow() // refused as busy: the picked folder is not used
            ok
        }
    }

    /**
     * Gives up the permission of every folder but the one this vault syncs through (the folder slot), e.g. after the
     * password sheet was cancelled. Does nothing while locked or while a join is using a picked folder.
     */
    suspend fun releaseUnusedFolders(): Unit = onConfined {
        if (actionJob == null) releaseUnusedFoldersNow()
    }

    private suspend fun releaseUnusedFoldersNow() {
        if (gate.isOpen) withContext(deps.io) { keepOnlyStoredFolder(deps, store) }
    }

    private suspend fun joinFolderAndReport(uri: String, password: String, now: Long): Boolean = try {
        joinFolderAndReportWork(uri, password, now)
    } finally {
        // Joined, attached or refused: only the folder in the slot keeps its permission (the picked one if it was stored).
        withContext(NonCancellable) { releaseUnusedFoldersNow() }
    }

    private suspend fun joinFolderAndReportWork(uri: String, password: String, now: Long): Boolean {
        try {
            val result = withContext(deps.io) { joinFolderWork(uri, password, store, deps) }
            wrongPasswords = 0
            _phase.value = Phase.IDLE
            apply(result)
            publish(result)
            _actionInfo.value = t.s(R.string.sync_now_cloud_info)
            runPendingSync()
            return true
        } catch (e: CancellationException) {
            throw e
        } catch (e: FolderSyncException) {
            if (e.reason == "password") {
                wrongPasswords += 1
                if (wrongPasswords >= MAX_PASSWORD_ATTEMPTS) {
                    wrongPasswords = 0
                    backoffUntil = now + PASSWORD_BACKOFF_SECONDS
                }
            }
            fail(e)
            return false
        } catch (e: Exception) {
            fail(e)
            return false
        }
    }

    /**
     * Cloud folder: start a NEW group in the picked folder with this vault as its first member (iOS `createFolder`).
     * Only for a vault in no group. Refusals (`folder-in-use`, `weak-password`, `already-joined`, ...) show in
     * [actionError]; on success the same message as a join.
     *
     * [add]: give this vault's Wi-Fi-only group the folder instead (desktop "Add a cloud folder to this group…"), with a
     * new sync password; [freshKey] after the user confirmed a new key because a Wi-Fi device was removed (audit M9).
     */
    suspend fun createFolder(uri: String, password: String, add: Boolean = false, freshKey: Boolean = false): Boolean = onConfined {
        var started = false
        val ok = runAction {
            started = true
            try {
                try {
                    val result = withContext(deps.io) { createFolderWork(uri, password, store, deps, add, freshKey) }
                    _phase.value = Phase.IDLE
                    apply(result)
                    publish(result)
                    _actionInfo.value = t.s(R.string.sync_now_cloud_info)
                    runPendingSync()
                    true
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    fail(e)
                    false
                }
            } finally {
                withContext(NonCancellable) { releaseUnusedFoldersNow() }
            }
        }
        if (!started) releaseUnusedFoldersNow()
        ok
    }

    // MARK: rollback warnings (ios/App/Sync/SyncCoordinator.swift acknowledgeRollback / dismissPeerRollback)

    /**
     * "This was me — keep this copy" after the user confirmed: [reauthenticate] asks for the owner's fingerprint, face or
     * screen lock, then the warning is acknowledged ([acknowledgeVaultRollback]). False when no warning is open, the
     * coordinator is busy, the owner check failed, or nothing was written.
     */
    suspend fun acknowledgeRollback(reauthenticate: suspend () -> Boolean): Boolean = onConfined {
        val open = try {
            withContext(deps.io) { (store.load().sync?.rollbackSuspected ?: 0) > 0 }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            false
        }
        if (!open) return@onConfined false
        runAction {
            val confirmed = try {
                reauthenticate()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                false
            }
            val done = confirmed && gate.isOpen && acknowledgeVaultRollback()
            _phase.value = Phase.IDLE
            if (done) {
                _issues.value = _issues.value.filter { it.kind != "vault-rollback" }
                _actionInfo.value = words.text(SyncIssue("rollback-acknowledged"))
            }
            runPendingSync()
            done
        }
    }

    /** Dismiss on a `peer-vault-rollback` message: accept that device's older copy and drop the message. */
    suspend fun dismissPeerRollback(peerId: String): Boolean = onConfined {
        if (peerId.isEmpty()) return@onConfined false
        runAction {
            forgetPeerGeneration(peerId)
            _phase.value = Phase.IDLE
            _issues.value = _issues.value.filter { !(it.kind == "peer-vault-rollback" && it.detail == peerId) }
            runPendingSync()
            true
        }
    }

    // MARK: removing devices (cloud folder; desktop `remove_device` / `remove_orphans`)

    /**
     * Removes [deviceIds] from the cloud-folder group in ONE rotation with a NEW sync password ([newPassword], which the
     * screen had entered twice): epoch + 1, the new key goes only to this phone and the confirmed members kept, and
     * each removed device gets a signed removal notice (it erases itself if it comes online with its setting on).
     * Unconfirmed members lose access too, without a notice. The screen checks Pro first. Refusals (`weak-password`,
     * `password-reused`, `keyring-changed`, `stale-trust`, ...) leave everything as it was and show in [actionError].
     */
    suspend fun removeDevices(deviceIds: List<String>, newPassword: String, keep: List<String>? = null): Boolean = onConfined {
        runAction { removeDevicesWork(deviceIds, newPassword, keep) }
    }

    /** Drops the last action's message (the Remove sheet opens without a stale error). */
    fun clearActionError() {
        _actionError.value = null
    }

    private suspend fun removeDevicesWork(deviceIds: List<String>, newPassword: String, keep: List<String>?): Boolean {
        val names = _membership.value.names
        try {
            val result = withContext(deps.io) { rotateWork(store, deps, deviceIds, newPassword, keep) }
            _phase.value = Phase.IDLE
            apply(result)
            publish(result)
            val shown = deviceIds.map { words.deviceLabel(it, names) }
            _actionInfo.value = if (shown.size == 1) {
                t.s(R.string.sync_device_removed_from_sync, shown[0])
            } else {
                t.s(R.string.sync_removed_list, shown.joinToString(", "))
            }
            runPendingSync()
            return true
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            fail(e)
            return false
        }
    }

    /** "These are my devices": the members added by another device that the screen showed ([deviceIds]) are confirmed. */
    suspend fun confirmMembers(deviceIds: List<String>): Boolean = onConfined {
        if (!gate.isOpen) return@onConfined false
        val ok = withContext(deps.io) {
            try {
                FolderSync.acknowledgeMembers(store, deps.slots.installId(), deviceIds) > 0
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                false
            }
        }
        refreshMembership()
        ok
    }

    // MARK: shared collections (sub-plan 07; desktop `CollectionShareService`, the iPhone's share actions)
    //
    // Each action runs under the coordinator's action lock (never beside a sync run, so never interleaved with a run's
    // store writes), on the I/O dispatcher (Argon2id and the folder block). Create, join and join again need Pro (checked
    // before any folder access or key derivation); approve, remove and leave do not. A refusal sets
    // [shareActionReason] and changes nothing. Share passwords are only passed through, never kept.

    /**
     * Share [collectionId] through the picked folder [folderUri], with this device as its owner named [deviceName].
     * [password] is what the other people type to join; [membersCanEdit] is fixed for the life of the share.
     */
    suspend fun createShare(
        collectionId: String,
        folderUri: String,
        password: String,
        deviceName: String,
        membersCanEdit: Boolean,
    ): ShareGroups.Group? {
        val mode = if (membersCanEdit) "edit" else "read"
        return shareAction { store, deps, pro ->
            ShareRuns.create(store, deps, pro, collectionId, folderUri, password, deviceName, mode)
        }
    }

    /** Join the shared collection in the picked folder [folderUri] as [deviceName]; it waits for the owner's approval. */
    suspend fun joinShare(folderUri: String, password: String, deviceName: String): ShareGroups.Group? =
        shareAction { store, deps, pro -> ShareRuns.join(store, deps, pro, folderUri, password, deviceName) }

    /** Join again after someone else's join at the same moment won (`superseded`: the status offers Join again). */
    suspend fun rejoinShare(groupId: String, password: String, deviceName: String): ShareGroups.Group? =
        shareAction { store, deps, pro -> ShareRuns.rejoin(store, deps, pro, groupId, password, deviceName) }

    /** The owner lets the waiting [deviceIds] in (each shown by name first). Returns the members approved. */
    suspend fun approveShare(groupId: String, deviceIds: List<String>): List<ShareGroups.Member>? =
        shareAction { store, deps, _ -> ShareRuns.approve(store, deps, groupId, deviceIds) }

    /**
     * The owner upgrades share v1 [groupId] to share v2 (approval gating) with a share password typed twice ([again] must
     * match). Works without Pro. True once upgraded, false when refused ([shareActionReason]); [shareUpgradeWritten]
     * says whether the folder got the new keyring now.
     */
    suspend fun upgradeShare(groupId: String, password: String, again: String): Boolean = onConfined {
        if (password != again) {
            _shareActionReason.value = "password-mismatch"
            return@onConfined false
        }
        val written = shareAction { store, deps, _ -> ShareRuns.upgrade(store, deps, groupId, password) }
            ?: return@onConfined false
        _shareUpgradeWritten.value = written
        true
    }

    /**
     * The owner removes [deviceId] with a new share password ([again] must match; the removed person knows the old one).
     * True once removed; [shareRemovalWritten] says whether the folder got the notice and the new keyring.
     */
    suspend fun removeShareMember(groupId: String, deviceId: String, newPassword: String, again: String): Boolean = onConfined {
        if (newPassword != again) {
            _shareActionReason.value = "password-mismatch"
            return@onConfined false
        }
        val written = shareAction { store, deps, _ -> ShareRuns.removeMember(store, deps, groupId, deviceId, newPassword) }
            ?: return@onConfined false
        _shareRemovalWritten.value = written
        true
    }

    /** Leave a shared collection (a member), or stop sharing it (the owner): the collection and its items stay here. */
    suspend fun leaveShare(groupId: String): Boolean = onConfined {
        shareAction(syncAfter = false) { store, _, _ -> ShareRuns.leave(store, groupId) } ?: return@onConfined false
        _shareIssues.value = _shareIssues.value - groupId
        // The share's folder is no longer used: the app gives up its permission to it.
        releaseUnusedFoldersNow()
        true
    }

    /**
     * Forget the share link of [collectionId] that another of this person's devices published (final review finding 4):
     * for a device that was lost or reset. The run after it publishes the link's tombstone; a device that still holds the
     * share publishes its link again. Works without Pro.
     */
    suspend fun forgetShareLink(collectionId: String): Boolean = onConfined {
        shareAction { store, _, _ -> ShareRuns.forgetLink(store, collectionId) } ?: return@onConfined false
        true
    }

    /**
     * One share action: the action lock, the work on the I/O dispatcher, then ([syncAfter]) a run so the share's folder
     * is read and written now. Null when refused ([shareActionReason]).
     */
    private suspend fun <T : Any> shareAction(
        syncAfter: Boolean = true,
        work: (ItemStore, SyncDependencies, Boolean) -> T,
    ): T? = onConfined {
        _shareActionReason.value = null
        _shareRemovalWritten.value = true
        _shareUpgradeWritten.value = true
        var value: T? = null
        var started = false
        runAction {
            started = true
            val pro = try {
                isPro()
            } catch (e: Exception) {
                false
            }
            val store = store
            val deps = deps
            val done = try {
                // Not interruptible: a share action's store commit and folder writes are never cut short.
                value = withContext(deps.io) { work(store, deps, pro) }
                true
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _shareActionReason.value = ShareRuns.reason(e)
                false
            }
            _phase.value = Phase.IDLE
            refreshMembership()
            if (done && syncAfter) {
                syncAfterAction = false // the run below includes any edit made meanwhile
                sync(Trigger.MANUAL)
            } else {
                runPendingSync()
            }
            done
        }
        if (!started) _shareActionReason.value = "busy"
        value
    }

    // MARK: leave and reset (each after two confirmations in the UI)

    /**
     * Stops syncing and forgets the paired device and folder; items and their sync history stay. This device's identity
     * is kept, so joining the same group again shows it under its old id ([clear]).
     */
    suspend fun leave() {
        onConfined { runAction { clearAction(history = false) } }
    }

    /** Forgets the group, its keys, the sync history and any kept identity; items stay. */
    suspend fun reset() {
        onConfined { runAction { clearAction(history = true) } }
    }

    private suspend fun clearAction(history: Boolean): Boolean {
        try {
            val cleared = withContext(deps.io) { clear(store, deps, history) }
            _phase.value = Phase.IDLE
            _actionInfo.value = if (history) words.resetResultText(cleared) else words.leftText
            _issues.value = emptyList()
            refreshMembership()
            return true
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            fail(e)
            return false
        }
    }

    // MARK: helpers

    /**
     * Runs a join/attach/leave/reset [body] in the coordinator's scope: a caller that stops waiting (its screen went
     * away) stops only waiting; the work and its bookkeeping (phase, membership, first sync, messages) always finish,
     * and no other action starts meanwhile. Only [shutdown] cancels it.
     */
    private suspend fun runAction(body: suspend () -> Boolean): Boolean {
        if (!beginAction()) return false
        val work = scope.async(start = CoroutineStart.LAZY) {
            try {
                body()
            } finally {
                if (_phase.value == Phase.JOINING) _phase.value = Phase.IDLE
                actionJob = null
            }
        }
        actionJob = work
        work.start()
        return try {
            work.await()
        } catch (e: CancellationException) {
            currentCoroutineContext().ensureActive() // the caller itself was cancelled: rethrow
            // The work was cancelled (shutdown), possibly before it started: its finally may not have run.
            if (actionJob === work && work.isCompleted) {
                actionJob = null
                if (_phase.value == Phase.JOINING) _phase.value = Phase.IDLE
            }
            false
        }
    }

    private fun beginAction(): Boolean {
        if (_phase.value != Phase.IDLE || runner != null || actionJob != null) {
            _actionError.value = words.errorText("busy")
            return false
        }
        _actionError.value = null; _actionInfo.value = null
        _phase.value = Phase.JOINING
        return true
    }

    private suspend fun fail(error: Exception) {
        _phase.value = Phase.IDLE
        _actionError.value = text(error)
        refreshMembership()
        runPendingSync()
    }

    /** An edit sync that arrived during a join runs now. */
    private fun runPendingSync() {
        if (!syncAfterAction) return
        syncAfterAction = false
        scope.launch { sync(Trigger.AFTER_ACTION) }
    }

    /** The join's own job was cancelled (its result, not its caller's). */
    private class JoinCancelled : Exception("join cancelled")

    /** Never shows the store or the slots. */
    override fun toString(): String = "SyncCoordinator(phase=${_phase.value}, open=${gate.isOpen})"

    companion object {
        const val MAX_PASSWORD_ATTEMPTS = 5

        /** A Wi-Fi host closed the connection right after this phone's hello: almost always, it no longer accepts this phone. */
        const val NOT_ACCEPTED = "not-accepted"
        const val PASSWORD_BACKOFF_SECONDS = 30L

        /** Rule 5's refusal: the other device could not pair this device under its kept id; a new one is used next time. */
        const val REJOIN_REFUSED = "rejoin-refused"

        private fun readSlotOrNull(deps: SyncDependencies, slot: Slot): ByteArray? = try {
            deps.slots.read(slot)
        } catch (e: Exception) {
            null
        }

        /** The folder slot's URI still opens (its permission is held); false when that cannot be told. */
        private fun folderAvailable(deps: SyncDependencies, raw: ByteArray): Boolean = try {
            deps.folders.isAvailable(raw.toString(Charsets.UTF_8))
        } catch (e: Exception) {
            false
        }

        /**
         * Keeps only the permission of the folder in the slot and those of the shared collections' folders ([store]'s
         * share records, sub-plan 07). A slot or share store that cannot be read keeps everything.
         */
        fun keepOnlyStoredFolder(deps: SyncDependencies, store: ItemStore? = null) {
            val raw = try {
                deps.slots.read(Slot.FOLDER_URI)
            } catch (e: Exception) {
                return
            }
            keepFolders(deps, store, raw?.toString(Charsets.UTF_8))
        }

        /** Gives up every folder permission but [personal]'s (null: none) and the share folders' of [store]. */
        private fun keepFolders(deps: SyncDependencies, store: ItemStore?, personal: String?) {
            val shared = if (store == null) {
                emptySet()
            } else {
                val snap = try {
                    store.load()
                } catch (e: Exception) {
                    return
                }
                ShareRuns.folderUris(snap) ?: return
            }
            try {
                if (shared.isEmpty()) deps.folders.keepOnly(personal) else deps.folders.keepOnlyAll(shared + listOfNotNull(personal))
            } catch (e: Exception) {
                // best effort: a permission that stays is released at the next join, leave or reset
            }
        }

        /**
         * The Wi-Fi-paired peer's signing key (device id -> base64), the only key its folder view may be signed with
         * (desktop `_paired_keys`, audit M-7; Swift `pairedKeys(deps)`). Ruling 16: only a pin of [state]'s group counts;
         * an unreadable pairing leaves the first-use pin in charge.
         */
        fun pairedKeys(deps: SyncDependencies, state: SyncGroupState?): Map<String, String> {
            val peer = trustedPeerOrNull(deps, state) ?: return emptyMap()
            return mapOf(peer.deviceId to Base64Std.encode(peer.signingPublic))
        }

        private fun pairedPeerOrNull(deps: SyncDependencies): PinnedPeer? = try {
            deps.slots.pairedPeer()
        } catch (e: Exception) {
            null
        }

        /** Ruling 16: the pinned peer counts only for the store's own group; anything else is a leftover. */
        private fun trustedPeerOrNull(deps: SyncDependencies, state: SyncGroupState?): PinnedPeer? =
            if (state == null) null else pairedPeerOrNull(deps)?.takeIf { it.groupId == state.groupId }

        /**
         * Held by a join from its pin to its commit, and by [dropStalePeer] from its state read to its delete: the cleanup
         * only ever sees the store before the pin or after the commit (process-wide: one vault per process).
         */
        private val PIN_LOCK = Any()

        /** Deletes a readable pinned peer that does not belong to the store's group (or to no group). Never throws. */
        private fun dropStalePeer(store: ItemStore, deps: SyncDependencies) {
            synchronized(PIN_LOCK) {
                val state = try {
                    store.load().sync
                } catch (e: Exception) {
                    return
                }
                val peer = pairedPeerOrNull(deps) ?: return
                if (state != null && peer.groupId == state.groupId) return
                try {
                    deps.slots.delete(Slot.PAIRED_PEER)
                } catch (_: Exception) {
                }
            }
        }

        private fun detail(e: Throwable): String = e.message ?: e.javaClass.simpleName

        /** False once the vault has locked (gate closed) or the run was cancelled: stop before the next step. */
        suspend fun stillOpen(store: ItemStore): Boolean =
            currentCoroutineContext().isActive && ((store as? GatedStore)?.gate?.isOpen ?: true)

        /**
         * One full run off the coordinator's thread: the personal group (the folder when the group uses one, then the
         * paired LAN peer), then every share group ([shareHost]; sub-plan 07), whether or not this vault is in a personal
         * group. Between steps it stops as soon as the vault locks, so nothing is read, refreshed or committed after.
         */
        suspend fun runAll(
            store: ItemStore,
            deps: SyncDependencies,
            memory: WitnessMemory? = null,
            shareHost: ShareHost? = null,
            /** Pro now, for the shares' status when they cannot run ([ShareRuns.notRun]). */
            isPro: Boolean = shareHost?.isPro ?: true,
        ): SyncRunResult = withContext(deps.io) {
            val snapshot = try {
                store.load()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return@withContext SyncRunResult(issues = listOf(SyncIssue("local-data", detail(e))), ran = true)
            }
            // Not joined: no personal run, but unlock (app open) still publishes the identities. A watch file left from a
            // group this vault left must not erase it later (desktop `run_once`).
            val state = snapshot.sync
            var out = if (state != null) {
                personalRun(store, deps, state, memory)
            } else {
                deps.removalWatch?.delete()
                SyncRunResult()
            }
            if (snapshot.shares != null && stillOpen(store)) {
                out = if (shareHost == null) {
                    out.copy(shares = ShareRuns.notRun(snapshot, isPro))
                } else {
                    val shares = ShareRuns.runAll(store, deps, shareHost.isPro, shareHost.local)
                    out.copy(conflicts = out.conflicts + shares.conflicts, shares = shares)
                }
            }
            out.copy(publish = stillOpen(store))
        }

        /** The personal group's run ([runAll]): the folder, then the paired LAN peer, then the witness flush. */
        private suspend fun personalRun(store: ItemStore, deps: SyncDependencies, state: SyncGroupState, memory: WitnessMemory?): SyncRunResult {
            val issues = ArrayList<SyncIssue>()
            var conflicts = 0
            val installId = try {
                deps.slots.installId()
            } catch (e: Exception) {
                issues.add(SyncIssue("state-corrupt", detail(e)))
                return SyncRunResult(issues, ran = true)
            }
            if (state.hasFolder) {
                if (!stillOpen(store)) return SyncRunResult(issues, conflicts, ran = true)
                // Blocking (SAF, cloud providers): already on the I/O dispatcher.
                val report = folderRun(store, deps, installId, state, memory)
                issues.addAll(report.issues); conflicts += report.conflicts
                // Rule 2: a verified removal notice for this id: its identity is never kept for a rejoin.
                if (report.issues.any { it.kind == SyncWording.REMOVAL_NOTICE_KIND }) dropKeptIdentity(deps, state.deviceId)
            }
            val peer = try {
                // Ruling 16: a peer pinned for another group (a join stopped between pin and commit) is ignored.
                deps.slots.pairedPeer()?.takeIf { it.groupId == state.groupId }
            } catch (e: Exception) {
                issues.add(SyncIssue("identity-mismatch", detail(e)))
                null
            }
            if (peer != null) {
                if (!stillOpen(store)) return SyncRunResult(issues, conflicts, ran = true)
                val report = lanRun(store, deps, installId, peer, memory)
                issues.addAll(report.issues); conflicts += report.conflicts
            }
            // Peer generations the LAN save throttle held back are saved at the end of every run (desktop service
            // `flush_witness`), so a lock loses no checked value.
            if (memory != null && stillOpen(store)) flushWitness(store, memory, peer?.deviceId, deps.clock.now)
            return SyncRunResult(issues, conflicts, ran = true)
        }

        /** Desktop `lan_sync.flush_witness`: commit every in-memory peer generation above the stored one. */
        fun flushWitness(store: ItemStore, memory: WitnessMemory, lanPeer: String?, now: Long): Boolean = try {
            val snapshot = store.load()
            val state = snapshot.sync
            val flushed = state?.let { memory.flush(it, listOfNotNull(lanPeer)) }
            if (flushed == null) {
                false
            } else {
                store.commit(StoreChange(snapshot.revision, snapshot.records, snapshot.meta, flushed))
                memory.markSaved(flushed.peerGenerations.keys, now)
                true
            }
        } catch (e: Exception) {
            false // witness bookkeeping never fails the run; the next run tries again
        }

        /** One folder run. [state]: the group state the run starts from (decides the trusted pairing, Ruling 16); read when null. */
        fun folderRun(
            store: ItemStore,
            deps: SyncDependencies,
            installId: String,
            state: SyncGroupState? = null,
            memory: WitnessMemory? = null,
        ): RunReport {
            val raw = try {
                deps.slots.read(Slot.FOLDER_URI)
            } catch (e: Exception) {
                return RunReport(issues = listOf(SyncIssue("folder-missing", detail(e))))
            } ?: return RunReport(issues = listOf(SyncIssue("folder-missing", "no folder chosen on this device")))
            // Personal collections on every personal run, with this vault's share records (sub-plan 07): no run without
            // them (a share store that cannot be read still gives its fail-closed read-only set).
            val shares = try {
                ShareRuns.collectionShares(store)
            } catch (e: Exception) {
                return RunReport(issues = listOf(SyncIssue("local-data", detail(e))))
            }
            return try {
                val folder = deps.folders.open(raw.toString(Charsets.UTF_8))
                val start = state ?: try {
                    store.load().sync
                } catch (e: Exception) {
                    null
                }
                val uri = raw.toString(Charsets.UTF_8)
                CommitOrigin.with("sync") {
                    FolderSync(
                        folder, installId, deps.licenseKeys, pairedKeys(deps, start), attachments = deps.attachments,
                        removalWatch = deps.removalWatch?.store(uri), collections = true, collectionShares = shares,
                    ).runOnce(store, deps.random, deps.clock, memory)
                }
            } catch (e: Exception) {
                RunReport(issues = listOf(SyncIssue("folder-missing", detail(e))))
            }
        }

        /**
         * One LAN sync with the paired peer (desktop `lan_sync.sync_with` + `run_merge`). Nothing is committed unless the
         * whole exchange succeeded.
         */
        suspend fun lanRun(
            store: ItemStore,
            deps: SyncDependencies,
            installId: String,
            peer: PinnedPeer,
            memory: WitnessMemory? = null,
        ): RunReport {
            fun fail(kind: String, detail: String = "") = RunReport(issues = listOf(SyncIssue(kind, detail)))
            val now = deps.clock.now
            val loaded = try {
                store.load()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return fail("local-data", detail(e))
            }
            val state = loaded.sync ?: return fail("not-joined")
            if (state.installId != installId) return fail("rejoin-required", "install-mismatch")
            if (peer.groupId != state.groupId || peer.deviceId == state.deviceId) return fail("peer-mismatch", peer.deviceId)
            // Only the paired peer, only at a private LAN address.
            val endpoint = peer.endpoint ?: return fail("no-endpoint", peer.deviceId)
            if (!LanAddress.isLan(endpoint.host)) return fail("unreachable", "${endpoint.host} is not a private LAN address")
            val groupKey: GroupKey
            val local: List<ItemState>
            // Attachment sync: documents go only to a peer that answered a `blob-get` (desktop `attachment_peers`).
            val vault = deps.attachments
            val documents = vault != null && peer.deviceId in state.attachmentPeers
            // Personal collections (sub-plan 07): collection states only with a peer that listed `collections` (decided
            // from the state read before the exchange); this vault's share records apply on every run (read-only share
            // items are never changed by another of this person's devices).
            val collections = peer.deviceId in state.collectionPeers
            val shares = ShareGroups.collectionShares(loaded)
            // Desktop `_local_view` (mobile sync review H-1): the vector bumps and tombstones this view publishes are saved
            // before anything is sent. The peer may keep the states even when this run fails afterwards, so a vector it
            // holds must never be handed out again for other content (a later delete would come back, or an edit would
            // turn into a conflict copy). A commit that loses to a local save ends the run with `busy`.
            val snapshot = try {
                saveLocalView(store, loaded, state.deviceId, now, collections, shares)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return fail("local-data", detail(e))
            } ?: return fail("busy", "items changed while syncing")
            try {
                groupKey = GroupKey(state.groupId, state.epoch, state.key)
                local = lanLocalView(snapshot, state, peer.deviceId, documents, now, collections, shares)
            } catch (e: Exception) {
                return fail("local-data", detail(e))
            }
            // Rollback witnesses (desktop `sync_with`): format 2 only to a peer that showed support.
            val lanIds = listOf(peer.deviceId)
            val ownGeneration = Witness.generation(snapshot)
            val inline = ownGeneration != null && peer.deviceId in state.witnessPeers
            val publish = ownGeneration?.let {
                LanPublish(
                    inline, it,
                    Witness.ownWitness(memory?.merged(state) ?: state.peerGenerations, Witness.witnessIds(state, lanIds), state.deviceId),
                )
            }
            var moved: LanEndpoint? = null
            val exchange: LanExchange = try {
                runInterruptible {
                    // A peer not known to read collection states is asked once per exchange, after the views and before
                    // the witness (desktop `_exchange_features`).
                    deps.lan.exchangeWitnessing(peer, state.identity, groupKey, local, state.ownCounter, publish, askFeatures = !collections) {
                        moved = it
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: LanSyncException) {
                if (inline && e.reason == "peer-refused" && e.detail == "bad-view") refusedFormat2(store, snapshot, peer.deviceId, memory, now)
                return fail(if (e.reason == "bad-message") "bad-reply" else e.reason, e.detail)
            } catch (e: LanPeerNotAnswering) {
                // Closed right after the hello: the host no longer accepts this phone (removed there, or it left or
                // reset sync); it says nothing on purpose, so this is the only sign (live check 2026-11-18).
                return fail(if (e.closedByPeer) NOT_ACCEPTED else "unreachable", detail(e))
            } catch (e: Exception) {
                return fail("unreachable", detail(e))
            }
            // The host answered at a new address with its pinned keys: dial it there next time (only while the same
            // peer is still paired; a Leave or a new pairing during the run wins).
            // Every LAN session of this device is sealed (protocol version 3, it never sends a clear-text hello): pin the
            // peer once (`"hello":3` in its entry, spec 2.5). A failed save never costs the finished exchange.
            try {
                deps.slots.markPairedPeerSealed(peer.deviceId)
            } catch (_: Exception) {
            }
            moved?.let { e ->
                try {
                    if (deps.slots.pairedPeer() == peer) deps.slots.setPairedPeer(peer.copy(endpoint = e))
                } catch (_: Exception) {
                }
            }
            val peerStates = exchange.states
            // The phone always initiates, so it fetches the files the peer's documents name (or probes once).
            var attachmentPeers = state.attachmentPeers
            val fileIssues = ArrayList<SyncIssue>()
            if (vault != null) {
                val reached = moved?.let { peer.copy(endpoint = it) } ?: peer
                val missing = AttachmentSync.uniqueRefs(Documents.refs(peerStates)).first.filter { !vault.has(it) }
                val fetched = try {
                    runInterruptible {
                        deps.lan.fetchBlobs(reached, state.identity, groupKey, missing, probe = missing.isEmpty() && !documents)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    BlobFetch()
                }
                fileIssues.addAll(fetched.issues)
                fileIssues.addAll(Documents.importMissing(vault, peerStates) { fetched.blobs[it.blob] })
                when (fetched.capable) {
                    true -> if (peer.deviceId !in attachmentPeers) attachmentPeers = (attachmentPeers + peer.deviceId).sorted()
                    false -> attachmentPeers = attachmentPeers - peer.deviceId
                    null -> {}
                }
            }
            // Emergency access (sub-plan 08): ask a peer not yet known to read the plan once (desktop `_probe_heir`).
            var heirPeers = state.heirPeers
            if (peer.deviceId !in heirPeers) {
                val reached = moved?.let { peer.copy(endpoint = it) } ?: peer
                val answer = try {
                    runInterruptible { deps.lan.probeHeir(reached, state.identity, groupKey) }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    null
                }
                // Pruned on each add (review M3): devices that left the group are dropped, so the cap never keeps a new one out.
                if (answer == true) heirPeers = (heirPeers.filter { it in state.members } + peer.deviceId).sorted()
            }
            val present: ((AttachmentRef) -> Boolean)? = vault?.let { v -> { ref: AttachmentRef -> v.has(ref) } }
            var report = SyncRunner.run(
                snapshot, listOf(PeerView(peer.deviceId, peerStates)), state.deviceId, now, deps.licenseKeys, documents = present,
                collections = collections, shares = shares,
            )
            report = report.copy(issues = fileIssues + report.issues)
            if (inline) memory?.clearRefusals(peer.deviceId) // a format-2 exchange went through
            val witnessIssues = ArrayList<SyncIssue>()
            exchange.issue?.let { witnessIssues.add(it) }
            var witnessState: SyncGroupState? = null
            val obs = exchange.observation
            if (obs != null && ownGeneration != null) {
                val (found, changed) = Witness.applyLan(state, ownGeneration, listOf(obs), memory, lanIds, now)
                witnessIssues.addAll(found)
                witnessState = changed
            }
            report = report.copy(issues = report.issues + witnessIssues)
            val records = report.records ?: snapshot.records
            val meta = report.meta ?: snapshot.meta
            val peersChanged = attachmentPeers != state.attachmentPeers || heirPeers != state.heirPeers
            if (records != snapshot.records || meta != snapshot.meta || witnessState != null || peersChanged) {
                // Workstream 6: the peer's changes were accepted now (local only; no extra commit when nothing changed).
                val merged = records != snapshot.records || meta != snapshot.meta
                val base = (witnessState ?: snapshot.sync)?.let {
                    if (peersChanged) it.copy(attachmentPeers = attachmentPeers, heirPeers = heirPeers) else it
                }
                val synced = if (merged) base?.syncedWith(listOf(peer.deviceId), now) else base
                try {
                    CommitOrigin.with("sync") { store.commit(StoreChange(snapshot.revision, records, meta, synced)) }
                    if (witnessState != null) memory?.markSaved(witnessState.peerGenerations.keys, now)
                } catch (e: Exception) {
                    report = report.copy(issues = report.issues + SyncIssue("busy", detail(e)))
                }
            }
            // The peer's `features` answer is recorded after the merge commit: true or false; no answer records nothing
            // (asked again next time).
            val reads = exchange.collections
            if (!collections && reads != null && stillOpen(store)) LanFeatures.setPeer(peer.deviceId, reads, store)
            PeerSeenAt.note(state.groupId, peer.deviceId, now)
            return report.copy(wrote = true)
        }

        /**
         * A `bad-view` refusal of a format-2 view (desktop `_refused`): only [Witness.FORMAT_REFUSALS_TO_DROP] in a row
         * (no good format-2 exchange between, counted in the session's memory) drop the peer from `witnessPeers`, so one
         * damaged transfer never switches a capable peer back to format 1.
         */
        private fun refusedFormat2(store: ItemStore, snapshot: StoreSnapshot, peerId: String, memory: WitnessMemory?, now: Long) {
            val state = snapshot.sync ?: return
            val count = memory?.refused(state, peerId) ?: Witness.FORMAT_REFUSALS_TO_DROP
            if (count < Witness.FORMAT_REFUSALS_TO_DROP) return
            memory?.clearRefusals(peerId)
            val generation = Witness.generation(snapshot) ?: return
            val (_, changed) = Witness.applyLan(state, generation, emptyList(), memory, listOf(peerId), now, dropCapable = peerId)
            if (changed == null) return
            try {
                store.commit(StoreChange(snapshot.revision, snapshot.records, snapshot.meta, changed))
            } catch (_: Exception) {
            }
        }

        /**
         * The enrollment of a scanned offer, then the inviter pinned and the group state committed (I/O thread).
         * [onCode] receives the 6-digit verification code (desktop `on_code`): for a version-1 offer before the request is
         * sent; for a version-2 offer (`LAN_SYNC_V3.md` 3) only once the inviter's reveal matched the QR's commitment.
         * The inviting device shows the same code next to Accept and answers only after Accept (or `declined`).
         */
        suspend fun enroll(
            text: String,
            store: ItemStore,
            deps: SyncDependencies,
            onConnected: () -> Unit = {},
            onCode: (String) -> Unit = {},
        ) {
            val snapshot = store.load()
            if (snapshot.sync != null) throw SyncActionException("already-joined")
            val offer = try {
                PairingOffer.parseQr(text.trim())
            } catch (e: Exception) {
                throw SyncActionException("bad-offer")
            }
            if (!LanAddress.isLan(offer.endpoint.host)) throw SyncActionException("bad-offer")
            // Rule 3: the identity Leave kept, when this offer is of its group; any other group gets a new one.
            val kept = keptIdentityOrNull(deps)?.takeIf { it.groupId == offer.groupId && it.deviceId != offer.inviterDeviceId }
            val identity = kept?.identity ?: deps.newIdentity(deps.random)
            val request: ByteArray
            val code: String?
            val sealed = offer.commit != null
            try {
                // A phone never listens: it announces no endpoint and always initiates. The name is the generic one it also
                // gives itself in the keyring; the inviting device shows it on its Accept prompt.
                request = Enrollment.buildRequest(offer, identity, deps.deviceName, null, deps.random, deps.clock)
                // A version-2 offer: the code needs the inviter's reveal, which comes only after the request.
                code = if (sealed) null else Enrollment.verificationCode(offer, identity, null, deps.deviceName)
            } catch (e: PairingException) {
                throw SyncActionException(if (e.kind == PairingException.Kind.EXPIRED) "offer-used-or-expired" else "bad-offer")
            } catch (e: Exception) {
                throw SyncActionException("bad-offer")
            }
            // Read before dialling: an address outside this Wi-Fi is still tried (it may be routed), but if the dial
            // fails the message says which address the PC should put in its code.
            val offSubnet = IPv4Subnet.mismatch(offer.endpoint.host, deps.localSubnet())
            code?.let(onCode)
            // Version-2 offer: the one reveal frame is checked against the QR's commitment; only then the code shows.
            var reveal: ByteArray? = null
            var revealRefused = false
            val onInterim: (ByteArray) -> Unit = { frame ->
                try {
                    if (!sealed || reveal != null) throw PairingException(PairingException.Kind.MALFORMED, "Unexpected enrollment reveal")
                    val opened = Enrollment.openReveal(offer, frame)
                    val shown = Enrollment.verificationCode(offer, identity, null, deps.deviceName, opened)
                    reveal = opened
                    onCode(shown)
                } catch (e: Exception) {
                    revealRefused = true
                    throw e
                }
            }
            // The reply comes once the user chose Accept on the inviting device: the connection waits up to
            // Enrollment.ENROLL_REPLY_SECONDS for it (ChannelLanDialer.enrollReplyMs, Ruling 17 amended).
            val reply = try {
                runInterruptible { deps.lan.enroll(offer.endpoint, request, onConnected, onInterim) }
            } catch (e: Exception) {
                // A reveal that does not match the QR (or a second one): refused, like desktop `enroll_from_qr`.
                if (revealRefused && e !is CancellationException) throw SyncActionException("refused")
                val cancelled = e is CancellationException || !currentCoroutineContext().isActive
                val kind = (e as? LanSocketException)?.kind ?: LanFailure.OTHER
                throw EnrollConnectException(if (cancelled) LanFailure.CANCELLED else kind, offer.endpoint, offSubnet)
            }
            val groupKey = try {
                Enrollment.openReply(offer, identity, reply, deps.deviceName, null, reveal)
            } catch (e: PairingException) {
                if (kept != null && e.kind == PairingException.Kind.REFUSED && e.detail == "refused") {
                    // Rule 5: the plain refusal to a pairing under the kept id (a host on a released build refuses every
                    // known id). The kept identity goes; the next pairing makes a new one, as before.
                    dropKeptIdentity(deps, kept.deviceId)
                    throw SyncActionException(REJOIN_REFUSED)
                }
                throw SyncActionException(
                    when {
                        e.kind != PairingException.Kind.REFUSED -> "refused"
                        e.detail == "used-or-expired" -> "offer-used-or-expired"
                        e.detail == "full" -> "too-many-peers"
                        e.detail == "declined" -> "declined" // Decline, or no Accept within 60 s
                        e.detail == "update-needed" -> "update-needed" // this phone sent an older request
                        else -> "refused"
                    },
                )
            } catch (e: Exception) {
                throw SyncActionException("refused")
            }
            // Cancelled meanwhile (the lock): nothing of the join is stored.
            currentCoroutineContext().ensureActive()
            val installId = deps.slots.installId()
            val joined = SyncGroupState(groupKey.groupId, groupKey.epoch, groupKey.key, identity, installId, hasFolder = false)
            // The kept id continues its counters, so peers take nothing from it for a replay or a rollback.
            val state = if (kept != null && joined.groupId == kept.groupId) kept.continuing(joined) else joined
            // Ruling 16: never pin after the lock (a pin without its commit would be a stale peer).
            if (!stillOpen(store)) throw SyncActionException("locked")
            synchronized(PIN_LOCK) {
                if ((store as? GatedStore)?.gate?.isOpen == false) throw SyncActionException("locked")
                // A version-2 offer pins the sealed hello at once (spec 2.5); a version-1 offer: the first sealed sync does.
                deps.slots.setPairedPeer(offer.inviterPeer, sealed = sealed, fresh = true)
                try {
                    val now = store.load()
                    if (now.sync != null) throw SyncActionException("already-joined")
                    store.commit(StoreChange(now.revision, now.records, now.meta, state))
                } catch (e: Exception) {
                    try {
                        deps.slots.delete(Slot.PAIRED_PEER)
                    } catch (_: Exception) {
                    }
                    throw e
                }
            }
            // Rule 2: it is the live identity again.
            if (kept != null) dropKeptIdentity(deps, kept.deviceId)
        }

        /** True when [joinFolderWork] would take the "choose the folder again" branch (no password). Never creates the slot. */
        fun isRepick(store: ItemStore, deps: SyncDependencies): Boolean {
            val state = try {
                store.load().sync
            } catch (e: Exception) {
                null
            } ?: return false
            if (!state.hasFolder) return false
            val raw = readSlotOrNull(deps, Slot.INSTALL_ID) ?: return false
            return state.installId == raw.toString(Charsets.UTF_8)
        }

        /** Join, attach or re-pick by the store's state (I/O thread); throws a refusal. */
        suspend fun joinFolderWork(uri: String, password: String, store: ItemStore, deps: SyncDependencies): SyncRunResult {
            val folder: FolderAccess = try {
                deps.folders.open(uri)
            } catch (e: Exception) {
                throw SyncActionException("folder-missing")
            }
            val installId = deps.slots.installId()
            val snapshot: StoreSnapshot = store.load()
            val state = snapshot.sync
            val fs = FolderSync(
                folder, installId, deps.licenseKeys, pairedKeys(deps, state), removalWatch = deps.removalWatch?.store(uri),
                collections = true, collectionShares = ShareRuns.collectionShares(store),
            )
            val uriBytes = uri.toByteArray(Charsets.UTF_8)
            val report = if (state != null && state.hasFolder && state.installId == installId) {
                // Already syncing through a folder (e.g. the URI was lost): the picked folder must hold this group's key
                // file; then only the URI is stored. No password, no join.
                val raw = try {
                    folder.read(FolderLayout.KEYRING_PATH, 256 * 1024 + 1)
                } catch (e: FolderAccessException) {
                    throw SyncActionException(if (e.kind == FolderAccessException.Kind.NOT_FOUND) "no-group" else "keyring-unreadable")
                } catch (e: Exception) {
                    throw SyncActionException("keyring-unreadable")
                }
                // A shared collection's keyring is not this group's (and not a damaged one): `share-group`.
                val ring = try {
                    Keyring.parse(raw)
                } catch (e: KeyringException) {
                    throw SyncActionException(if (e.reason == "share-group") "share-group" else "keyring-corrupt")
                } catch (e: Exception) {
                    throw SyncActionException("keyring-corrupt")
                }
                if ((ring as? JsonValue.Obj)?.fields?.get("group_id") != JsonValue.Str(state.groupId)) {
                    throw SyncActionException("folder-has-other-group")
                }
                deps.slots.write(Slot.FOLDER_URI, uriBytes)
                CommitOrigin.with("sync") { fs.runOnce(store, deps.random, deps.clock) }
            } else if (state != null && !state.hasFolder && state.installId == installId) {
                // Already in the group over Wi-Fi: an empty folder gets the copy that fits ("Create one" is not offered here).
                try {
                    fs.attach(store, password, deps.deviceName, deps.random, deps.clock)
                } catch (e: FolderSyncException) {
                    throw if (e.reason == "no-group") SyncActionException("no-group-paired") else e
                }
            } else {
                // Rules 3 and 6: a kept identity of this folder's group rejoins under its id when it may; either way it
                // is used up once this group is joined (a fresh identity is the live one then).
                val kept = if (state == null) keptIdentityOrNull(deps) else null
                fs.join(store, password, deps.deviceName, deps.random, deps.clock, kept).also {
                    if (kept != null && joinedGroupOrNull(store) == kept.groupId) dropKeptIdentity(deps, kept.deviceId)
                }
            }
            // After a join the group already uses the folder; if this write fails, "Choose the folder again" (the
            // branch above) stores it without joining.
            deps.slots.write(Slot.FOLDER_URI, uriBytes)
            val issues = ArrayList(report.issues)
            var conflicts = report.conflicts
            // A QR peer keeps syncing after an attach.
            if (stillOpen(store)) {
                // The join already happened: a store that cannot be read now only means no LAN step this time.
                val after = try {
                    store.load().sync
                } catch (e: Exception) {
                    null
                }
                val peer = trustedPeerOrNull(deps, after)
                if (peer != null) {
                    val lan = lanRun(store, deps, installId, peer)
                    issues.addAll(lan.issues); conflicts += lan.conflicts
                }
            }
            return SyncRunResult(issues, conflicts, ran = true, publish = stillOpen(store))
        }

        /** A new group in the picked folder (I/O thread); throws a refusal. The URI is stored once the group exists. */
        suspend fun createFolderWork(
            uri: String, password: String, store: ItemStore, deps: SyncDependencies, add: Boolean = false, freshKey: Boolean = false,
        ): SyncRunResult {
            if (!add && store.load().sync != null) throw SyncActionException("already-joined")
            val folder: FolderAccess = try {
                deps.folders.open(uri)
            } catch (e: Exception) {
                throw SyncActionException("folder-missing")
            }
            val installId = deps.slots.installId()
            val fs = FolderSync(
                folder, installId, deps.licenseKeys, emptyMap(), removalWatch = deps.removalWatch?.store(uri),
                collections = true, collectionShares = ShareRuns.collectionShares(store),
            )
            val report = if (add) {
                fs.addFolderToGroup(store, password, deps.deviceName, freshKey, deps.random, deps.clock, deps.strongSyncPassword)
            } else {
                fs.create(store, password, deps.deviceName, deps.random, deps.clock, deps.strongSyncPassword)
            }
            deps.slots.write(Slot.FOLDER_URI, uri.toByteArray(Charsets.UTF_8))
            return SyncRunResult(report.issues, report.conflicts, ran = true, publish = stillOpen(store))
        }

        /** The rotation of [removeDevices] (I/O thread): the folder in the slot, then one [FolderSync.rotate]. */
        suspend fun rotateWork(store: ItemStore, deps: SyncDependencies, deviceIds: List<String>, newPassword: String, keep: List<String>? = null): SyncRunResult {
            val raw = deps.slots.read(Slot.FOLDER_URI) ?: throw SyncActionException("folder-missing")
            val uri = raw.toString(Charsets.UTF_8)
            val folder: FolderAccess = try {
                deps.folders.open(uri)
            } catch (e: Exception) {
                throw SyncActionException("folder-missing")
            }
            val installId = deps.slots.installId()
            val state = store.load().sync ?: throw SyncActionException("not-joined")
            if (!state.hasFolder) throw SyncActionException("folder-missing")
            val fs = FolderSync(
                folder, installId, deps.licenseKeys, pairedKeys(deps, state), attachments = deps.attachments,
                removalWatch = deps.removalWatch?.store(uri), collections = true, collectionShares = ShareRuns.collectionShares(store),
            )
            val report = try {
                fs.rotate(store, newPassword, deviceIds, keep, deps.random, deps.clock, deps.strongSyncPassword)
            } finally {
                forgetDroppedPeer(store, deps)
            }
            return SyncRunResult(report.issues, report.conflicts, ran = true, publish = stillOpen(store))
        }

        /** The paired Wi-Fi peer is forgotten once it is no longer a member (removed, or dropped unconfirmed). */
        private fun forgetDroppedPeer(store: ItemStore, deps: SyncDependencies) {
            try {
                val state = store.load().sync ?: return
                if (state.membersEpoch != state.epoch || state.members.isEmpty()) return // member list not current
                val members = state.members
                val peer = deps.slots.pairedPeer() ?: return
                if (peer.deviceId !in members) deps.slots.delete(Slot.PAIRED_PEER)
            } catch (e: Exception) {
                // best effort: a stale peer only shows peer-epoch-behind
            }
        }

        /**
         * Leave (history false) or reset (true); items always stay. True when there was something to clear. Leave keeps
         * this device's identity first ([keepIdentity], rule 1); Reset drops any kept one (rule 2).
         */
        fun clear(store: ItemStore, deps: SyncDependencies, history: Boolean): Boolean {
            val snap = store.load()
            if (history) deps.slots.delete(Slot.KEPT_IDENTITY) else snap.sync?.let { keepIdentity(it, deps) }
            val had = snap.sync != null || (history && snap.meta.isNotEmpty())
            if (had) store.commit(StoreChange(snap.revision, snap.records, if (history) emptyMap() else snap.meta, null))
            // Left sync: a removal notice written later must never erase this vault.
            deps.removalWatch?.delete()
            deps.slots.delete(Slot.PAIRED_PEER)
            deps.slots.delete(Slot.FOLDER_URI)
            // The folder is no longer used: the app gives up its permission to it (the shared collections' stay).
            keepFolders(deps, store, null)
            // Peer counters are per pinned peer and that pairing is gone, so they are dropped. The hello counter is this
            // device's own monotonic counter: it is kept, because resetting it would let a re-paired peer (or a recorded
            // old session) see a counter it already accepted (replay window).
            deps.slots.delete(Slot.PEER_COUNTERS)
            return had
        }

        /**
         * Leave sync (design 2026-11-17, rule 1): keeps [state]'s identity and counters ([KeptIdentity]) in the vault's
         * sealed slots before the group state is cleared, replacing one kept before. Nothing is kept (and an older one is
         * dropped) for a state of another installation (a restored vault gets a new id) or one that says this device was
         * removed ([removedFrom], rule 2). Best effort: a Leave never fails over it; the next join then makes a new
         * identity, as before.
         */
        private fun keepIdentity(state: SyncGroupState, deps: SyncDependencies) {
            try {
                val installId = deps.slots.installId()
                if (state.installId != installId || removedFrom(state, deps, installId)) {
                    deps.slots.delete(Slot.KEPT_IDENTITY)
                } else {
                    deps.slots.setKeptIdentity(KeptIdentity.of(state))
                }
            } catch (e: Exception) {
                // best effort (see above)
            }
        }

        /**
         * True when [state] says this device was removed from its group: the accepted keyring's member list (current)
         * no longer names it, or the folder holds a removal notice for it that verifies against the watch file (as the
         * removal guard checks it). A check that cannot be made says false; a rejoin checks the folder again.
         */
        private fun removedFrom(state: SyncGroupState, deps: SyncDependencies, installId: String): Boolean {
            if (state.hasFolder && state.membersEpoch == state.epoch && state.members.isNotEmpty() && state.deviceId !in state.members) {
                return true
            }
            val watch = deps.removalWatch?.load() ?: return false
            if (watch.groupId != state.groupId || watch.deviceId != state.deviceId) return false
            return try {
                Removal.check(watch, installId, deps.folders.open(watch.folder)) != null
            } catch (e: Exception) {
                false
            }
        }

        private fun keptIdentityOrNull(deps: SyncDependencies): KeptIdentity? = try {
            deps.slots.keptIdentity()
        } catch (e: Exception) {
            null
        }

        /** Drops the kept identity when it is [deviceId]'s (rule 2). Best effort: never throws. */
        private fun dropKeptIdentity(deps: SyncDependencies, deviceId: String) {
            try {
                if (deps.slots.keptIdentity()?.deviceId == deviceId) deps.slots.delete(Slot.KEPT_IDENTITY)
            } catch (e: Exception) {
                // a kept identity that stays is only used for its own group, where a later join or Leave replaces it
            }
        }

        private fun joinedGroupOrNull(store: ItemStore): String? = try {
            store.load().sync?.groupId
        } catch (e: Exception) {
            null
        }

        /**
         * The address in a scanned pairing QR, accepted only for the pinned [peer]: same group, same device id, same
         * signing and exchange keys, a LAN address. Throws [SyncActionException] `bad-offer` or `find-again-mismatch`.
         * The offer's enrollment secrets are never used or kept.
         */
        /**
         * Find again: only the address of a QR from the ALREADY paired host. Group, device id, both public keys and the
         * certificate fingerprint must all match the pinned peer (keys compared in constant time); the code must not
         * have expired ([now], when given); the address must be on the local network. Nothing is enrolled.
         */
        fun addressFromOffer(peer: PinnedPeer, text: String, now: Long? = null): LanEndpoint {
            val offer = try {
                PairingOffer.parseQr(text.trim())
            } catch (e: Exception) {
                throw SyncActionException("bad-offer")
            }
            // Every key is compared before any is judged, so the time taken does not say which one differed.
            val signing = java.security.MessageDigest.isEqual(offer.inviterSigningPublic, peer.signingPublic)
            val exchange = java.security.MessageDigest.isEqual(offer.inviterExchangePublic, peer.exchangePublic)
            val fingerprint = java.security.MessageDigest.isEqual(offer.certificateFingerprint.toByteArray(), peer.fingerprint.toByteArray())
            val same = offer.groupId == peer.groupId && offer.inviterDeviceId == peer.deviceId && signing && exchange && fingerprint
            if (!same) throw SyncActionException("find-again-mismatch")
            if (now != null && offer.expiresAt < now) throw SyncActionException("offer-used-or-expired")
            if (!LanAddress.isLan(offer.endpoint.host) || offer.endpoint.port !in 1..65535) throw SyncActionException("bad-offer")
            return offer.endpoint
        }

    }

    private fun text(error: Throwable): String = when (error) {
        is EnrollConnectException -> words.enrollFailureText(error)
        is SyncActionException -> words.errorText(error.reason)
        is FolderSyncException -> words.errorText(error.reason)
        is LanSyncException -> words.errorText(error.reason)
        is KeyringException -> words.errorText(error.reason)
        else -> words.stepFailedText
    }
}

/**
 * Saves the meta [SyncMeta.localView] builds for [snapshot] (each local edit's vector bump and each delete's tombstone;
 * records and group state unchanged) under the snapshot's revision, before the view is sent anywhere (desktop
 * `_local_view`; mobile sync review H-1). Returns the snapshot to send and merge from: [snapshot] itself when the view
 * changes no meta, else the reloaded store. Null when a local save got in between (the commit lost the base-revision
 * race, or the store changed again before the reload): the run stops with `busy` and nothing is sent. A view that
 * cannot be built throws (`local-data`).
 */
internal fun saveLocalView(
    store: ItemStore,
    snapshot: StoreSnapshot,
    device: String,
    now: Long,
    collections: Boolean = false,
    shares: CollectionShares = CollectionShares.NONE,
): StoreSnapshot? {
    val view = SyncMeta.localView(snapshot.records, snapshot.meta, device, now, collections, shares)
    if (view.meta == snapshot.meta) return snapshot
    try {
        store.commit(StoreChange(snapshot.revision, snapshot.records, view.meta, snapshot.sync))
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        return null
    }
    val saved = store.load()
    // Another save landed between the commit and the reload: its own bumps are not saved yet, so this run stops.
    if (saved.records != snapshot.records || saved.meta != view.meta || saved.sync != snapshot.sync) return null
    return saved
}

/**
 * What one Wi-Fi run offers [peerId]: this store's local view, documents only when [documents], and the emergency
 * access plan only to a peer that answered `heir-hello` (desktop `heir_peers`); collection states only with
 * [collections] (sub-plan 07), [shares] naming the links this device speaks for.
 */
internal fun lanLocalView(
    snapshot: StoreSnapshot,
    state: SyncGroupState,
    peerId: String,
    documents: Boolean,
    now: Long,
    collections: Boolean = false,
    shares: CollectionShares = CollectionShares.NONE,
): List<ItemState> =
    Heir.publishable(
        Documents.publishable(
            SyncMeta.localView(snapshot.records, snapshot.meta, state.deviceId, now, collections, shares).states.values
                .sortedWith { a, b -> Scalars.compare(a.itemId, b.itemId) },
            documents,
        ),
        peerId in state.heirPeers,
    )
