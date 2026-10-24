package app.localgatekeys.android.backup

import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.pro.LicenseKeys
import app.localgatekeys.android.sync.SyncActionException
import app.localgatekeys.android.vault.LocalStoreException
import app.localgatekeys.core.backup.PhoneBackup
import app.localgatekeys.core.engine.ConflictCopy
import app.localgatekeys.core.engine.Engine
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.Plausibility
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncRunner

/** The backup cannot be restored here. [reason] is [SAME_DEVICE], [UNREADABLE] or [LOCKED]. */
class PhoneRestoreException(val reason: String) : Exception(messageFor(reason)) {
    companion object {
        const val SAME_DEVICE = "same-device"
        const val UNREADABLE = "unreadable"
        const val LOCKED = "locked"

        private fun messageFor(reason: String): String = when (reason) {
            // Desktop "This backup was made on this computer, so there is nothing to restore." with the platform word.
            SAME_DEVICE -> "This backup was made on this phone, so there is nothing to restore."
            UNREADABLE -> BackupText.UNREADABLE
            else -> "The vault is locked."
        }
    }
}

/**
 * What a restore would do (desktop `RestorePlan`). The counts come from merging the final view (after the free-plan
 * cap), so they match what [PhoneRestore.restore] writes. Holds the backup's states: dropped with the screen on lock.
 */
class RestorePlan internal constructor(
    val new: Int,
    val updated: Int,
    val unchanged: Int,
    val heldBack: Int,
    val skipped: Int,
    val deleted: Int,
    internal val view: PeerView,
) {
    /** Counts only: the states hold plaintext secrets. */
    override fun toString(): String =
        "RestorePlan(new=$new, updated=$updated, unchanged=$unchanged, heldBack=$heldBack, skipped=$skipped, deleted=$deleted)"
}

/**
 * What a restore did (desktop `RestoreReport`). [failure]: a sync issue kind that stopped the whole restore (nothing
 * was written: `busy` when the vault changed meanwhile, `apply-failed` / `local-data` otherwise), or null.
 * [licenseRestored]: a valid licence arrived that this phone did not hold before.
 */
data class RestoreReport(
    val new: Int = 0,
    val updated: Int = 0,
    val heldBack: Int = 0,
    val skipped: Int = 0,
    val deleted: Int = 0,
    val failure: String? = null,
    val licenseRestored: Boolean = false,
)

/**
 * Restores a phone backup into this phone's vault through the sync merge (a port of the desktop's
 * `sync/phone_restore.py`, the rules the spec's section 6 names):
 *
 * - The backup's states enter as ONE remote view, so a backup never overwrites a newer (or equal) version, a tombstone
 *   deletes only what it dominates, and a failed apply writes nothing.
 * - A backup made under this phone's own device id ([BackupDevice]) is refused.
 * - States the merge would refuse (`SyncRunner.check`: malformed, or a newer wrapper schema) are left out first and
 *   counted as skipped, so they never take a free slot; so are states whose version vector is implausible next to this
 *   phone's ([Plausibility.implausibleVv], audit M-6: a crafted backup must not make the next local edit overflow).
 * - Free plan: new live items beyond the free slots are held back, newest `updated_at` first (ties by id); a state
 *   whose merge makes a conflict copy counts as a new item, ranked after the plain new ones, and is held back when its
 *   copy does not fit (this phone keeps its own version). Updates of items already here are never capped.
 * - Ruling B: two-factor keys are restored as they are (restoring your own data is not adding a code).
 *
 * [store] is the sync coordinator's gated store: after a lock nothing is read or committed ([PhoneRestoreException.LOCKED]).
 * Blocking: call off the main thread.
 */
class PhoneRestore(
    private val store: ItemStore,
    private val isPro: () -> Boolean,
    private val clock: UnixClock,
    private val installId: () -> String,
    private val licenseKeys: Map<String, ByteArray> = LicenseKeys.production,
    /** The Wi-Fi-paired peer's device id, or null (desktop `_known_devices` adds its LAN peers). */
    private val pairedPeerId: () -> String? = { null },
) {
    fun plan(backup: PhoneBackup): RestorePlan {
        val snap = load()
        val now = clock.now
        val device = BackupDevice.id(snap, installId)
        if (backup.deviceId == device) throw PhoneRestoreException(PhoneRestoreException.SAME_DEVICE)
        val local = localStates(snap, device, now)
        val byId = LinkedHashMap<String, ItemState>()
        for (s in backup.states) byId[s.itemId] = s
        // Records the merge would refuse never reach it, so they take no free slot; nor do states with an implausible
        // version vector (the run would quarantine them anyway). Desktop plan_restore.
        val known = knownDevices(snap, device, backup.deviceId)
        val unreadable = byId.values.filter {
            SyncRunner.check(it, licenseKeys) != null || Plausibility.implausibleVv(it.vv, local[it.itemId]?.vv, known) != null
        }.map { it.itemId }.toSet()
        byId.keys.removeAll(unreadable)

        val held = HashSet<String>()
        val slots = if (isPro()) null else maxOf(0, ItemLimit.FREE_ITEMS - ItemLimit.liveCount(snap))
        if (slots != null) {
            val t = tally(local, byId.values.toList())
            val order = compareBy<String>({ -rank(byId.getValue(it)) }, { it })
            val rankedNew = t.new.sortedWith(order)
            held.addAll(rankedNew.drop(slots))
            var remaining = maxOf(0, slots - rankedNew.size)
            for (id in t.copies.keys.sortedWith(order)) {
                val n = t.copies.getValue(id)
                if (n <= remaining) remaining -= n else held.add(id)
            }
        }
        val final = byId.values.filter { it.itemId !in held }
        val t = tally(local, final)
        val touched = t.new + t.updated + t.copies.keys
        val content = final.count { isContent(it) }
        return RestorePlan(
            new = t.new.size + t.copies.values.sum(),
            updated = t.updated.size,
            unchanged = content - touched.size,
            heldBack = held.size,
            skipped = unreadable.size,
            deleted = t.deleted.size,
            view = PeerView(backup.deviceId, final),
        )
    }

    /** Merges the planned view in one run and commits it; the counts are what was applied. */
    fun restore(plan: RestorePlan): RestoreReport {
        val snap = load()
        val now = clock.now
        val device = BackupDevice.id(snap, installId)
        val before = contentIds(snap)
        val hadLicense = ItemLimit.validLicense(snap, licenseKeys) != null
        val report = SyncRunner.run(snap, listOf(plan.view), device, now, licenseKeys, knownDevices(snap, device, plan.view.deviceId))
        val fatal = report.issues.map { it.kind }.firstOrNull { it !in QUARANTINE_KINDS }
        val records = report.records
        val meta = report.meta
        if (fatal != null || records == null || meta == null) {
            return RestoreReport(heldBack = plan.heldBack, skipped = plan.skipped, failure = fatal ?: "apply-failed")
        }
        val after = StoreSnapshot(records, meta, snap.sync, snap.revision)
        if (records != snap.records || meta != snap.meta) {
            try {
                store.commit(StoreChange(snap.revision, records, meta, snap.sync))
            } catch (e: SyncActionException) {
                throw PhoneRestoreException(PhoneRestoreException.LOCKED)
            } catch (e: LocalStoreException) {
                val kind = if (e.kind == LocalStoreException.Kind.STALE) "busy" else "apply-failed"
                return RestoreReport(heldBack = plan.heldBack, skipped = plan.skipped, failure = kind)
            }
        }
        val new = (contentIds(after) - before).size
        return RestoreReport(
            new = new,
            updated = maxOf(0, report.applied - new),
            heldBack = plan.heldBack,
            skipped = plan.skipped + report.issues.count { it.kind in QUARANTINE_KINDS },
            deleted = report.deleted,
            licenseRestored = !hadLicense && ItemLimit.validLicense(after, licenseKeys) != null,
        )
    }

    /**
     * Desktop `runner._known_devices`: this phone, the backup's device, every device the stored group state knows and
     * the Wi-Fi-paired peer (an unreadable pairing adds nothing).
     */
    private fun knownDevices(snap: StoreSnapshot, device: String, backupDevice: String): Set<String> {
        val out = hashSetOf(device, backupDevice)
        val st = snap.sync ?: return out
        out.addAll(st.members); out.addAll(st.lastSeen.keys); out.add(st.deviceId)
        try {
            pairedPeerId()?.let { out.add(it) }
        } catch (e: Exception) {
            // unreadable: the pairing's counters get the unknown-device bound
        }
        return out
    }

    private fun load(): StoreSnapshot = try {
        store.load()
    } catch (e: SyncActionException) {
        throw PhoneRestoreException(PhoneRestoreException.LOCKED)
    } catch (e: Exception) {
        throw PhoneRestoreException(PhoneRestoreException.UNREADABLE)
    }

    private fun localStates(snap: StoreSnapshot, device: String, now: Long): Map<String, ItemState> = try {
        SyncMeta.localView(snap.records, snap.meta, device, now).states
    } catch (e: Exception) {
        throw PhoneRestoreException(PhoneRestoreException.UNREADABLE)
    }

    private class Tally(val new: Set<String>, val updated: Set<String>, val copies: Map<String, Int>, val deleted: Set<String>)

    /** (new ids, updated ids, conflict copies per backup state id, deleted ids) of merging [states] into [local]. */
    private fun tally(local: Map<String, ItemState>, states: List<ItemState>): Tally {
        val out = Engine.merge(local, states)
        val upserts = out.upserts.filter { isContent(it) }.map { it.itemId }
        val new = upserts.filter { local[it] == null || local.getValue(it).deleted }.toSet()
        val deleted = out.deletes.filter { s -> local[s.itemId]?.let { isContent(it) } == true }.map { it.itemId }.toSet()
        val cause = HashMap<String, String>()
        for ((loc, remote) in out.conflicts) {
            for (side in listOf(loc, remote)) {
                val item = side.item ?: continue
                cause[ConflictCopy.id(remote.itemId, ConflictCopy.contentDigest(item))] = remote.itemId
            }
        }
        val copies = HashMap<String, Int>()
        for (s in out.copies) {
            if (ns(s) !in CONTENT_NS) continue
            val origin = cause[s.itemId] ?: continue
            copies[origin] = (copies[origin] ?: 0) + 1
        }
        return Tally(new, upserts.toSet() - new, copies, deleted)
    }

    override fun toString(): String = "PhoneRestore"

    private companion object {
        /** Run issue kinds that skip one record while the rest is applied (desktop `QUARANTINE_KINDS`). */
        val QUARANTINE_KINDS = setOf("bad-peer-record", "update-needed", "implausible-vv")
        val CONTENT_NS = setOf("entry", "item")

        fun ns(s: ItemState): String? = ((s.item as? JsonValue.Obj)?.fields?.get("ns") as? JsonValue.Str)?.v

        fun isContent(s: ItemState): Boolean = !s.deleted && ns(s) in CONTENT_NS

        /** The wrapper's int `updated_at` (desktop `_updated_at`), else 0. */
        fun rank(s: ItemState): Long = ((s.item as? JsonValue.Obj)?.fields?.get("updated_at") as? JsonValue.Int)?.v ?: 0L

        fun contentIds(snap: StoreSnapshot): Set<String> = snap.records.filter { (_, w) ->
            ((w as? JsonValue.Obj)?.fields?.get("ns") as? JsonValue.Str)?.v in CONTENT_NS
        }.keys
    }
}
