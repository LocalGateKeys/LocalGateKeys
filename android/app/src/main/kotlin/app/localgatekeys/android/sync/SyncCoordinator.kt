package app.localgatekeys.android.sync

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
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
import app.localgatekeys.core.sync.FolderAccess
import app.localgatekeys.core.sync.FolderAccessException
import app.localgatekeys.core.sync.FolderLayout
import app.localgatekeys.core.sync.FolderSync
import app.localgatekeys.core.sync.FolderSyncException
import app.localgatekeys.core.sync.ItemStore
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
)

/**
 * The Sync screen's state machine (port of `ios/App/Sync/SyncCoordinator.swift`): `IDLE` -> `SYNCING` -> `IDLE`, or
 * `IDLE` -> `JOINING` -> (`SYNCING`) -> `IDLE`.
 *
 * * Sync runs on unlock (APP_OPEN), on pull-to-refresh, 2 s after the last local edit, and on "Sync now".
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
    enum class Trigger { APP_OPEN, PULL_TO_REFRESH, LOCAL_EDIT, MANUAL }

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
                peerSyncedAt = state?.peerSyncedAt ?: emptyMap(),
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
                val result = runAll(store, deps, witnessMemory)
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
        refreshMembership()
        if (!gate.isOpen) return
        if (result.ran) {
            _lastSyncedAt.value = deps.clock.now
            _conflictCopies.value += result.conflicts
            val m = _membership.value
            _issues.value = words.views(result.issues, ownID = m.deviceId, folder = m.hasFolder)
        } else {
            _issues.value = emptyList()
        }
        _completedRuns.value += 1
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
        if (gate.isOpen) withContext(deps.io) { keepOnlyStoredFolder(deps) }
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

    // MARK: leave and reset (each after two confirmations in the UI)

    /** Stops syncing and forgets the paired device and folder; items and their sync history stay. */
    suspend fun leave() {
        onConfined { runAction { clearAction(history = false) } }
    }

    /** Forgets the group, its keys and the sync history; items stay. */
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
        scope.launch { sync(Trigger.LOCAL_EDIT) }
    }

    /** The join's own job was cancelled (its result, not its caller's). */
    private class JoinCancelled : Exception("join cancelled")

    /** Never shows the store or the slots. */
    override fun toString(): String = "SyncCoordinator(phase=${_phase.value}, open=${gate.isOpen})"

    companion object {
        const val MAX_PASSWORD_ATTEMPTS = 5
        const val PASSWORD_BACKOFF_SECONDS = 30L

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

        /** Keeps only the permission of the folder in the slot. A slot that cannot be read keeps everything. */
        fun keepOnlyStoredFolder(deps: SyncDependencies) {
            val raw = try {
                deps.slots.read(Slot.FOLDER_URI)
            } catch (e: Exception) {
                return
            }
            try {
                deps.folders.keepOnly(raw?.toString(Charsets.UTF_8))
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
         * One full run off the coordinator's thread: the folder (when the group uses one), then the paired LAN peer.
         * Between steps it stops as soon as the vault locks, so nothing is read, refreshed or committed after.
         */
        suspend fun runAll(store: ItemStore, deps: SyncDependencies, memory: WitnessMemory? = null): SyncRunResult = withContext(deps.io) {
            val snapshot = try {
                store.load()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return@withContext SyncRunResult(issues = listOf(SyncIssue("local-data", detail(e))), ran = true)
            }
            // Not joined: nothing to sync, but unlock (app open) still publishes the identities.
            val state = snapshot.sync ?: return@withContext SyncRunResult(publish = stillOpen(store))
            val issues = ArrayList<SyncIssue>()
            var conflicts = 0
            val installId = try {
                deps.slots.installId()
            } catch (e: Exception) {
                issues.add(SyncIssue("state-corrupt", detail(e)))
                return@withContext SyncRunResult(issues, ran = true, publish = stillOpen(store))
            }
            if (state.hasFolder) {
                if (!stillOpen(store)) return@withContext SyncRunResult(issues, conflicts, ran = true)
                // Blocking (SAF, cloud providers): already on the I/O dispatcher.
                val report = folderRun(store, deps, installId, state, memory)
                issues.addAll(report.issues); conflicts += report.conflicts
            }
            val peer = try {
                // Ruling 16: a peer pinned for another group (a join stopped between pin and commit) is ignored.
                deps.slots.pairedPeer()?.takeIf { it.groupId == state.groupId }
            } catch (e: Exception) {
                issues.add(SyncIssue("identity-mismatch", detail(e)))
                null
            }
            if (peer != null) {
                if (!stillOpen(store)) return@withContext SyncRunResult(issues, conflicts, ran = true)
                val report = lanRun(store, deps, installId, peer, memory)
                issues.addAll(report.issues); conflicts += report.conflicts
            }
            // Peer generations the LAN save throttle held back are saved at the end of every run (desktop service
            // `flush_witness`), so a lock loses no checked value.
            if (memory != null && stillOpen(store)) flushWitness(store, memory, peer?.deviceId, deps.clock.now)
            SyncRunResult(issues, conflicts, ran = true, publish = stillOpen(store))
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
            return try {
                val folder = deps.folders.open(raw.toString(Charsets.UTF_8))
                val start = state ?: try {
                    store.load().sync
                } catch (e: Exception) {
                    null
                }
                FolderSync(folder, installId, deps.licenseKeys, pairedKeys(deps, start), attachments = deps.attachments)
                    .runOnce(store, deps.random, deps.clock, memory)
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
            val snapshot = try {
                store.load()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return fail("local-data", detail(e))
            }
            val state = snapshot.sync ?: return fail("not-joined")
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
            try {
                groupKey = GroupKey(state.groupId, state.epoch, state.key)
                local = Documents.publishable(
                    SyncMeta.localView(snapshot.records, snapshot.meta, state.deviceId, now).states.values
                        .sortedWith { a, b -> Scalars.compare(a.itemId, b.itemId) },
                    documents,
                )
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
                    deps.lan.exchangeWitnessing(peer, state.identity, groupKey, local, state.ownCounter, publish) { moved = it }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: LanSyncException) {
                if (inline && e.reason == "peer-refused" && e.detail == "bad-view") refusedFormat2(store, snapshot, peer.deviceId, memory, now)
                return fail(if (e.reason == "bad-message") "bad-reply" else e.reason, e.detail)
            } catch (e: Exception) {
                return fail("unreachable", detail(e))
            }
            // The host answered at a new address with its pinned keys: dial it there next time (only while the same
            // peer is still paired; a Leave or a new pairing during the run wins).
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
            val present: ((AttachmentRef) -> Boolean)? = vault?.let { v -> { ref: AttachmentRef -> v.has(ref) } }
            var report = SyncRunner.run(
                snapshot, listOf(PeerView(peer.deviceId, peerStates)), state.deviceId, now, deps.licenseKeys, documents = present,
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
            val peersChanged = attachmentPeers != state.attachmentPeers
            if (records != snapshot.records || meta != snapshot.meta || witnessState != null || peersChanged) {
                // Workstream 6: the peer's changes were accepted now (local only; no extra commit when nothing changed).
                val merged = records != snapshot.records || meta != snapshot.meta
                val base = (witnessState ?: snapshot.sync)?.let { if (peersChanged) it.copy(attachmentPeers = attachmentPeers) else it }
                val synced = if (merged) base?.syncedWith(listOf(peer.deviceId), now) else base
                try {
                    store.commit(StoreChange(snapshot.revision, records, meta, synced))
                    if (witnessState != null) memory?.markSaved(witnessState.peerGenerations.keys, now)
                } catch (e: Exception) {
                    report = report.copy(issues = report.issues + SyncIssue("busy", detail(e)))
                }
            }
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
         * [onCode] receives the 6-digit verification code before the request is sent (desktop `on_code`): the inviting
         * device shows the same code next to Accept and answers only after Accept (or `declined`).
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
            val identity = deps.newIdentity(deps.random)
            val request: ByteArray
            val code: String
            try {
                // A phone never listens: it announces no endpoint and always initiates. The name is the generic one it also
                // gives itself in the keyring; the inviting device shows it on its Accept prompt.
                request = Enrollment.buildRequest(offer, identity, deps.deviceName, null, deps.random, deps.clock)
                code = Enrollment.verificationCode(offer, identity, null, deps.deviceName)
            } catch (e: PairingException) {
                throw SyncActionException(if (e.kind == PairingException.Kind.EXPIRED) "offer-used-or-expired" else "bad-offer")
            } catch (e: Exception) {
                throw SyncActionException("bad-offer")
            }
            // Read before dialling: an address outside this Wi-Fi is still tried (it may be routed), but if the dial
            // fails the message says which address the PC should put in its code.
            val offSubnet = IPv4Subnet.mismatch(offer.endpoint.host, deps.localSubnet())
            onCode(code)
            // The reply comes once the user chose Accept on the inviting device: the connection waits up to
            // Enrollment.ENROLL_REPLY_SECONDS for it (ChannelLanDialer.enrollReplyMs, Ruling 17 amended).
            val reply = try {
                runInterruptible { deps.lan.enroll(offer.endpoint, request, onConnected) }
            } catch (e: Exception) {
                val cancelled = e is CancellationException || !currentCoroutineContext().isActive
                val kind = (e as? LanSocketException)?.kind ?: LanFailure.OTHER
                throw EnrollConnectException(if (cancelled) LanFailure.CANCELLED else kind, offer.endpoint, offSubnet)
            }
            val groupKey = try {
                Enrollment.openReply(offer, identity, reply, deps.deviceName, null)
            } catch (e: PairingException) {
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
            val state = SyncGroupState(groupKey.groupId, groupKey.epoch, groupKey.key, identity, installId, hasFolder = false)
            // Ruling 16: never pin after the lock (a pin without its commit would be a stale peer).
            if (!stillOpen(store)) throw SyncActionException("locked")
            synchronized(PIN_LOCK) {
                if ((store as? GatedStore)?.gate?.isOpen == false) throw SyncActionException("locked")
                deps.slots.setPairedPeer(offer.inviterPeer)
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
            val fs = FolderSync(folder, installId, deps.licenseKeys, pairedKeys(deps, state))
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
                val ring = try {
                    Keyring.parse(raw)
                } catch (e: Exception) {
                    throw SyncActionException("keyring-corrupt")
                }
                if ((ring as? JsonValue.Obj)?.fields?.get("group_id") != JsonValue.Str(state.groupId)) {
                    throw SyncActionException("folder-has-other-group")
                }
                deps.slots.write(Slot.FOLDER_URI, uriBytes)
                fs.runOnce(store, deps.random, deps.clock)
            } else if (state != null && !state.hasFolder && state.installId == installId) {
                fs.attach(store, password, deps.deviceName, deps.random, deps.clock)
            } else {
                fs.join(store, password, deps.deviceName, deps.random, deps.clock)
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

        /** Leave (history false) or reset (true); items always stay. True when there was something to clear. */
        fun clear(store: ItemStore, deps: SyncDependencies, history: Boolean): Boolean {
            val snap = store.load()
            val had = snap.sync != null || (history && snap.meta.isNotEmpty())
            if (had) store.commit(StoreChange(snap.revision, snap.records, if (history) emptyMap() else snap.meta, null))
            deps.slots.delete(Slot.PAIRED_PEER)
            deps.slots.delete(Slot.FOLDER_URI)
            // The folder is no longer used: the app gives up its permission to it.
            try {
                deps.folders.keepOnly(null)
            } catch (e: Exception) {
                // best effort (the slot is gone, so the next join releases it)
            }
            // Peer counters are per pinned peer and that pairing is gone, so they are dropped. The hello counter is this
            // device's own monotonic counter: it is kept, because resetting it would let a re-paired peer (or a recorded
            // old session) see a counter it already accepted (replay window).
            deps.slots.delete(Slot.PEER_COUNTERS)
            return had
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
