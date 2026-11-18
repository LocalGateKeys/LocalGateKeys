package app.localgatekeys.android.recovery

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.android.vault.Slot
import app.localgatekeys.core.crypto.Bip39
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.recovery.Heir
import app.localgatekeys.core.recovery.HeirException
import app.localgatekeys.core.recovery.HeirFlow
import app.localgatekeys.core.recovery.HeirFlowException
import app.localgatekeys.core.recovery.HeirFolder
import app.localgatekeys.core.recovery.HeirPlan
import app.localgatekeys.core.recovery.HeirStatus
import app.localgatekeys.core.recovery.Pending
import app.localgatekeys.core.recovery.RequesterIdentity
import app.localgatekeys.core.recovery.Shard
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange

/**
 * Emergency access on a phone (sub-plan 08, Task 5a), over one unlocked vault. Blocking: call off the main thread.
 *
 * - As one of the owner's devices: the plan arrives by sync (record `heir:plan`). With this phone's heir folder chosen,
 *   it lists the requests that prove a shard (rewriting a lost deny), denies (the refusal is kept in the plan, which
 *   syncs) and grants now with the typed recovery phrase after the owner confirms. Plans are made on the computer.
 * - As a holder: the shards given to this person and their own requester keys stay in this vault's sealed slots. It
 *   asks for access, follows the status, and once access is open shows the owner's recovery phrase, checked against the
 *   plan's HKDF check first.
 */
class EmergencyAccess(
    private val store: ItemStore,
    private val slots: SecretSlots,
    /** The heir folder for a stored tree URI, or null when it is not available any more. */
    private val openFolder: (String) -> HeirFolder?,
    private val clock: UnixClock,
    private val random: RandomSource,
    /** A local edit of the plan (a refusal) for sync to publish. */
    private val onLocalEdit: () -> Unit = {},
) {
    fun folderUri(): String? = slots.read(Slot.HEIR_FOLDER_URI)?.toString(Charsets.UTF_8)

    fun setFolder(uri: String) = slots.write(Slot.HEIR_FOLDER_URI, uri.toByteArray(Charsets.UTF_8))

    /** Review M4: "not chosen" (`no-folder`) and "chosen but gone" (`folder-unavailable`) are told apart. */
    private fun folder(): HeirFolder {
        val uri = folderUri() ?: throw HeirFlowException("no-folder")
        return openFolder(uri) ?: throw HeirFlowException("folder-unavailable")
    }

    /** False when a folder was chosen but can no longer be opened (unplugged, permission gone). */
    fun folderReachable(): Boolean = folderUri()?.let { openFolder(it) != null } ?: true

    // ---- the owner's plan ------------------------------------------------------------------

    /** The synced plan record, or null (none, removed, or not a plan). */
    fun planRecord(): JsonValue.Obj? {
        val snap = store.load()
        if (snap.meta[Heir.STATE_ID]?.deleted == true) return null
        val w = (snap.records[Heir.STATE_ID] as? JsonValue.Obj)?.fields ?: return null
        if (w["ns"] != JsonValue.Str(Namespace.HEIR.wire)) return null
        return w["record"] as? JsonValue.Obj
    }

    /** The plan, or null; a damaged record throws [HeirException] `malformed`. */
    fun plan(): HeirPlan? = planRecord()?.let { Heir.parsePlan(it) }

    private fun requirePlan(): HeirPlan = plan() ?: throw HeirFlowException("no-plan")

    /** The open requests (a refused one whose deny went missing gets it written again). */
    fun pending(): Pending = HeirFlow.pendingFor(requirePlan(), folder(), clock.now, random)

    /**
     * Refuses a request, in the desktop's order (`add_denied` first): the refusal is kept in the plan (it syncs to the
     * owner's other devices, which write the deny file again if this one is lost), then the deny file is written.
     */
    fun deny(requestId: String) {
        val plan = requirePlan()
        val folder = folder()
        val snap = store.load()
        val record = planRecord() ?: throw HeirFlowException("no-plan")
        val records = LinkedHashMap(snap.records)
        records[Heir.STATE_ID] = Wrapper.make(Namespace.HEIR, Heir.withDenied(record, requestId))
        store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
        onLocalEdit()
        HeirFlow.deny(plan, folder, requestId, clock.now, random)
    }

    /** Grant now with the typed [phrase] (the caller has re-authenticated the owner). */
    fun grant(requestId: String, phrase: String): String = HeirFlow.grantNow(requirePlan(), folder(), requestId, phrase, clock.now, random)

    // ---- the holder's side -----------------------------------------------------------------

    /** The shard packages held (in the order added). */
    fun packages(): List<ByteArray> {
        val raw = slots.read(Slot.HEIR_SHARDS) ?: return emptyList()
        return try {
            (CanonicalJson.parse(raw) as JsonValue.Arr).items.map { Base64Std.decodeStrict((it as JsonValue.Str).v) }
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun shards(): List<Shard> = packages().mapNotNull {
        try {
            Heir.readPackage(it)
        } catch (e: HeirException) {
            null
        }
    }

    /** Adds a shard file's bytes; refused when it is not one, or of another plan than those held, or held already. */
    fun addPackage(data: ByteArray): Shard {
        val all = packages() + data
        val checked = Heir.checkShards(all)
        slots.write(Slot.HEIR_SHARDS, CanonicalJson.encode(JsonValue.Arr(all.map { JsonValue.Str(Base64Std.encode(it)) }), Dialect.UTF8))
        return checked.last()
    }

    /** Adds a scanned or pasted `lgkheir:` code. */
    fun addText(text: String): Shard = addPackage(Heir.packageFromQrText(text.trim()))

    fun clearShards() {
        slots.delete(Slot.HEIR_SHARDS)
    }

    private fun identity(): RequesterIdentity {
        slots.read(Slot.HEIR_IDENTITY)?.let { raw ->
            try {
                return RequesterIdentity.fromRecord(CanonicalJson.parse(raw))
            } catch (e: Exception) {
                // damaged: a new identity (an earlier request then simply stays unanswered)
            }
        }
        val made = RequesterIdentity.generate(random)
        slots.write(Slot.HEIR_IDENTITY, CanonicalJson.encode(made.toRecord(), Dialect.UTF8))
        return made
    }

    private fun held(): List<ByteArray> = packages().also { if (it.isEmpty()) throw HeirFlowException("need-more", missing = 2) }

    /** Writes an access request for the plan of the shards held. */
    fun request(): String = HeirFlow.requestAccess(folder(), held()[0], identity(), clock.now, random)

    fun status(): HeirStatus = HeirFlow.requestStatus(folder(), held(), identity(), clock.now)

    /** The owner's recovery phrase once access is open, after the plan's check (the caller shows it, keeps nothing). */
    fun recoverPhrase(): String {
        val entropy = HeirFlow.recoverEntropy(folder(), held(), identity(), clock.now)
        try {
            return Bip39.phrase(entropy)
        } finally {
            entropy.fill(0)
        }
    }

    companion object {
        /** What a refusal says, in the person's language (never a secret). */
        fun message(e: Throwable, t: Txt): String = when (e) {
            is HeirFlowException -> when (e.reason) {
                "no-folder" -> t.s(R.string.heir_err_no_folder)
                "folder-unavailable" -> t.s(R.string.heir_err_folder_unavailable)
                "no-plan" -> t.s(R.string.heir_no_plan)
                "no-request" -> t.s(R.string.heir_err_no_request)
                "denied" -> t.s(R.string.heir_err_denied)
                "waiting" -> t.s(R.string.heir_state_waiting, e.daysLeft)
                "need-more" -> t.s(R.string.heir_state_need_more, e.missing)
                "no-backup" -> t.s(R.string.heir_state_no_backup)
                "check-failed" -> t.s(R.string.heir_err_check_failed)
                "stale-plan" -> t.s(R.string.heir_err_stale_plan)
                "wrong-phrase" -> t.s(R.string.heir_err_wrong_phrase)
                "mixed-plans" -> t.s(R.string.heir_err_mixed_plans)
                "duplicate" -> t.s(R.string.heir_err_duplicate)
                else -> t.s(R.string.heir_err_malformed)
            }
            is HeirException -> when (e.reason) {
                "mixed-plans" -> t.s(R.string.heir_err_mixed_plans)
                "duplicate" -> t.s(R.string.heir_err_duplicate)
                "check-failed" -> t.s(R.string.heir_err_check_failed)
                else -> t.s(R.string.heir_err_malformed)
            }
            else -> t.s(R.string.heir_err_no_folder)
        }

        /** The requester's status line. */
        fun statusText(s: HeirStatus, t: Txt): String = when (s.state) {
            "none" -> t.s(R.string.heir_state_none)
            "denied" -> t.s(R.string.heir_state_denied)
            "need-more" -> t.s(R.string.heir_state_need_more, s.missing)
            "waiting" -> t.s(R.string.heir_state_waiting, s.daysLeft)
            "no-backup" -> t.s(R.string.heir_state_no_backup)
            "ready" -> t.s(R.string.heir_state_ready)
            else -> t.s(R.string.heir_state_none)
        }
    }
}

/**
 * The owner's look at the heir folder (desktop `HeirService.timer_check`): after unlock and after each sync run, the
 * open requests are read (a refused request's lost deny is written again) and each new one is announced once per app
 * run, with a one-time warning when the folder holds too many request files to read them all.
 */
class HeirNotices {
    private val announced = HashSet<String>()
    private var floodShown = false

    /** The notices to show now (none without a plan or a folder; a failed look is silent and tried again later). */
    @Synchronized
    fun check(access: EmergencyAccess, t: Txt): List<String> {
        val pending = try {
            if (access.plan() == null || access.folderUri() == null) return emptyList()
            access.pending()
        } catch (e: Exception) {
            return emptyList()
        }
        val out = ArrayList<String>()
        for (r in pending.requests) {
            if (r.granted || !announced.add(r.requestId)) continue
            out += t.s(R.string.heir_request_notice, r.holder, r.daysLeft)
        }
        if (pending.flooded && !floodShown) {
            floodShown = true
            out += t.s(R.string.heir_flooded)
        }
        return out
    }
}
