package app.localgatekeys.android.sync

import app.localgatekeys.android.history.CommitOrigin
import app.localgatekeys.android.trash.LocalDataHosting
import app.localgatekeys.core.keyring.KeyringException
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.sync.CollectionCatalogException
import app.localgatekeys.core.sync.CollectionShares
import app.localgatekeys.core.sync.FolderAccess
import app.localgatekeys.core.sync.FolderAccessException
import app.localgatekeys.core.sync.FolderLayout
import app.localgatekeys.core.sync.FolderSync
import app.localgatekeys.core.sync.FolderSyncException
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.RunReport
import app.localgatekeys.core.sync.ShareAccess
import app.localgatekeys.core.sync.ShareGroupException
import app.localgatekeys.core.sync.ShareGroups
import app.localgatekeys.core.sync.ShareProRequiredException
import app.localgatekeys.core.sync.ShareRecord
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncIssue
import app.localgatekeys.core.sync.itemRecords
import kotlin.coroutines.cancellation.CancellationException

/**
 * Shared collections on Android (sub-plan 07 Task 5m; the port of the iPhone's `ShareSync`, desktop
 * `SyncService._run_shares` and `CollectionShareService`). A shared collection is its own share group
 * (`ShareGroups`) syncing through its own cloud folder (`FolderSync(share=)`), a SAF tree URI kept with the share record
 * as its UTF-8 bytes. The coordinator runs every share after the personal group; its share actions call these under its
 * action lock. Every share commit goes through [ShareTrashingStore], so a share's deletes and a removal land in Recently
 * deleted. Share passwords are only ever arguments: never stored, logged or put in an error.
 *
 * Blocking: every function here runs on the I/O dispatcher.
 */
object ShareRuns {
    /**
     * Detail of a share run's own Recently deleted refusal (a normal run, not a removal): [SyncWording.shareStatus] words
     * it as the sync trash message.
     */
    const val RUN_DETAIL = "share-run"

    /** The most keyring bytes read from a share folder (desktop `MAX_KEYRING_BYTES`, plus one to see it is too large). */
    const val KEYRING_READ_LIMIT = 256 * 1024 + 1

    /** The result of every share run of one coordinator run. */
    data class Runs(
        /** Share group id -> that group's issues (none: it synced); "" for share groups that cannot be read. */
        val issues: Map<String, List<SyncIssue>> = emptyMap(),
        val conflicts: Int = 0,
    )

    /** A share record's folder reference as the URI the app picked (and the reverse). */
    fun folderUri(folder: ByteArray): String = folder.toString(Charsets.UTF_8)

    fun folderRef(uri: String): ByteArray = uri.toByteArray(Charsets.UTF_8)

    /**
     * What personal sync needs from this vault's share groups ([ShareGroups.collectionShares], which fails closed on a
     * damaged share store), on every personal folder run. Throws when the store cannot be read: no run goes ahead without
     * its read-only protection (the Wi-Fi run reads it from the snapshot it merges).
     */
    fun collectionShares(store: ItemStore): CollectionShares = ShareGroups.collectionShares(store.load())

    /**
     * The folder URIs of every share record (their permissions are kept with the personal folder's); null when the share
     * records cannot be read (then no permission is given up).
     */
    fun folderUris(snapshot: StoreSnapshot): Set<String>? = try {
        ShareGroups.records(snapshot).values.mapNotNull { r -> r.folder?.let { folderUri(it) } }.toSet()
    } catch (e: Exception) {
        null
    }

    /**
     * Every share group with a folder, one after the other in group id order, after the personal group. On a free device
     * each run does its keyring step only (a repair, an adoption, a removal: security actions, final review A2) and
     * reports `pro-required`; no view is read or written. A failing share never stops the others; nothing runs once the
     * vault locks. [local] is Recently deleted (it takes every live item a share commit removes).
     */
    suspend fun runAll(store: ItemStore, deps: SyncDependencies, isPro: Boolean, local: LocalDataHosting): Runs {
        val issues = LinkedHashMap<String, List<SyncIssue>>()
        var conflicts = 0
        val records: Map<String, ShareRecord> = try {
            ShareGroups.records(store.load())
        } catch (e: CancellationException) {
            throw e
        } catch (e: ShareGroupException) {
            return Runs(mapOf("" to listOf(SyncIssue("state-corrupt", e.reason))))
        } catch (e: Exception) {
            return Runs(mapOf("" to listOf(SyncIssue("local-data", e.message ?: e.javaClass.simpleName))))
        }
        if (records.isEmpty()) return Runs()
        val installId = try {
            deps.slots.installId()
        } catch (e: Exception) {
            return Runs(records.keys.associateWith { listOf(SyncIssue("state-corrupt", "install id")) })
        }
        for ((gid, record) in records.entries.sortedBy { it.key }) {
            if (!SyncCoordinator.stillOpen(store)) break
            val folder = record.folder
            if (folder == null) {
                issues[gid] = listOf(SyncIssue("folder-missing", gid))
                continue
            }
            val report = run(store, deps, installId, gid, folder, isPro, local)
            issues[gid] = report.issues
            conflicts += report.conflicts
        }
        return Runs(issues, conflicts)
    }

    /**
     * Share runs with no Recently deleted to put a share's deletes in (not open yet, or it could not be read): none runs,
     * and each group says so (`item-error`, the run's own detail), so a share that never ran never looks synced. A free
     * device says `pro-required` instead (5g review R4), as its runs would.
     */
    fun notRun(snapshot: StoreSnapshot, isPro: Boolean = true): Runs {
        val records = try {
            ShareGroups.records(snapshot)
        } catch (e: Exception) {
            return Runs(mapOf("" to listOf(SyncIssue("state-corrupt", "share groups"))))
        }
        if (!isPro) return Runs(records.keys.associateWith { listOf(SyncIssue("pro-required", it)) })
        return Runs(records.keys.associateWith { listOf(SyncIssue(ShareTrashRefusal.UNAVAILABLE, RUN_DETAIL)) })
    }

    /** One share group's run over its own folder ([folder]: the record's folder reference). */
    fun run(
        store: ItemStore,
        deps: SyncDependencies,
        installId: String,
        groupId: String,
        folder: ByteArray,
        isPro: Boolean,
        local: LocalDataHosting,
    ): RunReport {
        val access = try {
            deps.folders.open(folderUri(folder))
        } catch (e: Exception) {
            return stop("folder-missing", e.message ?: e.javaClass.simpleName)
        }
        if ((store as? GatedStore)?.gate?.isOpen == false) return RunReport()
        val trashing = ShareTrashingStore(store, local) { deps.clock.now }
        val trash = trashing.shareTrash()
        val before = try {
            store.load()
        } catch (e: Exception) {
            null
        }
        val fs = try {
            FolderSync(access, installId, share = FolderSync.Share(groupId, isPro, trash))
        } catch (e: Exception) {
            return stop("state-corrupt", groupId)
        }
        val report = CommitOrigin.with("sync") { fs.runOnce(trashing, deps.random, deps.clock) }
        // A share item brought back from Recently deleted (the run restored it into the store) leaves it.
        if (before != null && trash.records.isNotEmpty()) {
            val after = try {
                store.load()
            } catch (e: Exception) {
                null
            }
            if (after != null) {
                val back = (liveIds(after) - liveIds(before)).intersect(trash.records.keys)
                trashing.leave(back)
            }
        }
        return report.copy(issues = report.issues.map { runIssue(it) })
    }

    /** A share commit that Recently deleted refused is that refusal (`trash-full`, `item-error`), never `busy`. */
    fun runIssue(issue: SyncIssue): SyncIssue {
        if (issue.kind != "busy") return issue
        for (kind in listOf(ShareTrashRefusal.FULL, ShareTrashRefusal.UNAVAILABLE)) {
            if (issue.detail.startsWith("$kind:")) return SyncIssue(kind, RUN_DETAIL)
        }
        return issue
    }

    private fun stop(kind: String, detail: String = "") = RunReport(issues = listOf(SyncIssue(kind, detail)))

    /**
     * The items the store holds a record of. Presence only: a share run writes a brought-back record but leaves the
     * personal meta alone, which the personal run has already made a tombstone for an item in Recently deleted.
     */
    fun liveIds(snapshot: StoreSnapshot): Set<String> = snapshot.itemRecords.keys

    // ---- actions (each under the coordinator's action lock, on the I/O dispatcher) ----

    private fun open(uri: String, deps: SyncDependencies): FolderAccess = try {
        deps.folders.open(uri)
    } catch (e: Exception) {
        throw SyncActionException("folder-missing")
    }

    /** The folder's keyring bytes: `no-share` when there is none, `keyring-unreadable` when it cannot be read. */
    private fun keyring(folder: FolderAccess): ByteArray = try {
        folder.read(FolderLayout.KEYRING_PATH, KEYRING_READ_LIMIT)
    } catch (e: FolderAccessException) {
        throw SyncActionException(if (e.kind == FolderAccessException.Kind.NOT_FOUND) "no-share" else "keyring-unreadable")
    } catch (e: Exception) {
        throw SyncActionException("keyring-unreadable")
    }

    private fun record(store: ItemStore, groupId: String): ShareRecord =
        ShareGroups.records(store.load())[groupId] ?: throw ShareGroupException("not-joined", "this vault is not in that share group")

    /** [groupId]'s own folder (`folder-missing` without one). */
    private fun ownFolder(store: ItemStore, deps: SyncDependencies, groupId: String): FolderAccess {
        val folder = record(store, groupId).folder ?: throw SyncActionException("folder-missing")
        return open(folderUri(folder), deps)
    }

    /**
     * Share [collectionId] through the folder [uri] (desktop `CollectionShareService.share`). Pro first, then
     * `folder-in-use` when the folder already holds a sync group's keyring (or cannot be checked); the keyring is written
     * at once and a failed write undoes the share (`leave`, `folder-error`; `share-undo-failed` if even that fails).
     */
    fun create(
        store: ItemStore,
        deps: SyncDependencies,
        isPro: Boolean,
        collectionId: String,
        uri: String,
        password: String,
        deviceName: String,
        mode: String,
        /** Tests of the upgrade make a share v1 with [ShareKeyring.LEGACY_SHARE_FORMAT]; the app always makes share v2. */
        shareFormat: Long = ShareKeyring.SHARE_FORMAT,
    ): ShareGroups.Group {
        ShareAccess.requirePro(ShareAccess.Action.CREATE, isPro)
        val access = open(uri, deps)
        val fs = FolderSync(access, deps.slots.installId())
        if (fs.holdsKeyring()) throw SyncActionException("folder-in-use")
        val group = ShareGroups.create(
            store, collectionId, password, deviceName, mode, fs.installId, isPro, deps.random, deps.clock, deps.strongSharePassword,
            folder = folderRef(uri), shareFormat = shareFormat,
        )
        if (!fs.writeShareKeyring(store, group.groupId)) {
            // Undone, once more if the vault changed meanwhile; a share that cannot be undone is said so (the screen
            // offers Stop sharing), never left to start working at the next run behind a "failed".
            try {
                ShareGroups.leave(store, group.groupId)
            } catch (e: Exception) {
                try {
                    ShareGroups.leave(store, group.groupId)
                } catch (e2: Exception) {
                    throw SyncActionException("share-undo-failed")
                }
            }
            throw SyncActionException("folder-error")
        }
        return group
    }

    /**
     * Join the shared collection in the folder [uri] (desktop `CollectionShareService.join`). Pro first; a refused join
     * (`password`, `not-share`, `collection-exists`...) stores nothing. The grown keyring is written now when the folder
     * allows it; the share run writes it otherwise.
     */
    fun join(store: ItemStore, deps: SyncDependencies, isPro: Boolean, uri: String, password: String, deviceName: String): ShareGroups.Group {
        ShareAccess.requirePro(ShareAccess.Action.JOIN, isPro)
        val access = open(uri, deps)
        val raw = keyring(access)
        val fs = FolderSync(access, deps.slots.installId())
        val group = ShareGroups.join(
            store, raw, password, deviceName, fs.installId, isPro, deps.random, deps.clock, folder = folderRef(uri),
        )
        fs.writeShareKeyring(store, group.groupId)
        return group
    }

    /** Join [groupId] again after someone else's join at the same moment won (`superseded`), from its own folder. */
    fun rejoin(store: ItemStore, deps: SyncDependencies, isPro: Boolean, groupId: String, password: String, deviceName: String): ShareGroups.Group {
        ShareAccess.requirePro(ShareAccess.Action.JOIN, isPro)
        val access = ownFolder(store, deps, groupId)
        val raw = keyring(access)
        val fs = FolderSync(access, deps.slots.installId())
        val group = ShareGroups.rejoin(store, groupId, raw, password, deviceName, fs.installId, isPro, deps.random, deps.clock)
        fs.writeShareKeyring(store, groupId)
        return group
    }

    /** The owner lets [deviceIds] in (works without Pro); the new keyring is written now when the folder allows it. */
    fun approve(store: ItemStore, deps: SyncDependencies, groupId: String, deviceIds: List<String>): List<ShareGroups.Member> {
        val members = ShareGroups.approve(store, groupId, deviceIds, deps.random)
        try {
            FolderSync(ownFolder(store, deps, groupId), deps.slots.installId()).writeShareKeyring(store, groupId)
        } catch (e: Exception) {
            // the share run writes it
        }
        return members
    }

    /**
     * The owner upgrades share v1 [groupId] to share v2 (approval gating) with a share password (works without Pro; the
     * current one may be kept). Approved members keep access; the new keyring is written now when the folder allows it,
     * the share run writes it otherwise. Returns whether it was written now (desktop `upgrade`: "could not be updated
     * yet" when not).
     */
    fun upgrade(store: ItemStore, deps: SyncDependencies, groupId: String, password: String): Boolean {
        ShareGroups.upgrade(store, groupId, password, deps.random, deps.strongSharePassword)
        return try {
            FolderSync(ownFolder(store, deps, groupId), deps.slots.installId()).writeShareKeyring(store, groupId)
        } catch (e: Exception) {
            false // the share run writes it
        }
    }

    /**
     * The owner removes [deviceId] with a new share password (works without Pro). The folder is opened first, so a
     * missing folder changes nothing; then the rotation, the owner's removal notice and the rotated keyring. Returns
     * whether both files were written (false: the removal stands, the share run writes the keyring later, but the
     * removed person sees "can no longer open" instead of the removal).
     */
    fun removeMember(store: ItemStore, deps: SyncDependencies, groupId: String, deviceId: String, newPassword: String): Boolean {
        val fs = FolderSync(ownFolder(store, deps, groupId), deps.slots.installId())
        val notice = ShareGroups.removeMember(store, groupId, deviceId, newPassword, deps.random, deps.clock, deps.strongSharePassword)
        val published = fs.publishShareNotice(deviceId, notice)
        val written = fs.writeShareKeyring(store, groupId)
        return published && written
    }

    /** Forget [groupId] here (works without Pro): the collection and its items stay, no longer shared. */
    fun leave(store: ItemStore, groupId: String) {
        ShareGroups.leave(store, groupId)
    }

    /** Forget the share link of [collectionId] another of this person's devices published ([ShareGroups.forgetLink]). */
    fun forgetLink(store: ItemStore, collectionId: String) {
        ShareGroups.forgetLink(store, collectionId)
    }

    /** The stable reason code of a refused share action (the share screen words it). */
    fun reason(error: Throwable): String = when (error) {
        is ShareGroupException -> error.reason
        is KeyringException -> error.reason
        is ShareProRequiredException -> "pro-required"
        is SyncActionException -> error.reason
        is FolderSyncException -> error.reason
        is CollectionCatalogException -> error.failure.code
        is ShareTrashRefusal -> error.kind
        else -> "error"
    }
}
