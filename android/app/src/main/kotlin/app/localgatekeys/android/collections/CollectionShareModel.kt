package app.localgatekeys.android.collections

import app.localgatekeys.android.R
import app.localgatekeys.android.backup.BackupPasswordCheck
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.sync.ShareRuns
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncWording
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.core.sync.CollectionShares
import app.localgatekeys.core.sync.ShareGroups
import app.localgatekeys.core.sync.ShareRecord
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncIssue
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext

/**
 * The Share sheet of one collection and the Join sheet (sub-plan 07 Task 5m; the iPhone's `CollectionShareModel`, desktop
 * `app/collection_share.py` `CollectionShareService.view` and its actions). The summary is read from the store's share
 * records and the coordinator's last share runs: role, mode, the fixed-mode hint, folder, members with their state,
 * waiting and removed names, the status and the owner-loss help. It never holds a key, a keyring or a stored password:
 * the password fields are what the person is typing, and every action empties them as soon as it has read them.
 *
 * Actions go through the coordinator ([SyncCoordinator.createShare] and the other share actions), which runs them under
 * its action lock. Creating and joining need Pro: on the free plan [State.showUpgrade] is set instead. Sharing asks the
 * device owner first ([confirmOwner]: fingerprint, face or screen lock; desktop `_confirm_handover`, create only).
 * [reload] reads the store: call it off the main thread.
 */
class CollectionShareModel(
    collectionId: String?,
    private val sync: SyncCoordinator,
    private val t: Txt,
    /** The display name of a stored folder URI (nothing is opened); null when unknown. */
    private val folderName: (String) -> String? = { null },
    private val confirmOwner: suspend () -> Boolean,
    /** Where an action's store reads run (never the main thread). */
    private val io: CoroutineDispatcher = Dispatchers.IO,
) {
    private val words = SyncWording(t)

    enum class MemberState { OWNER, MEMBER, PENDING }

    data class Member(
        val id: String,
        val name: String,
        val state: MemberState,
        val stateText: String,
        val isSelf: Boolean,
        /** Only the owner removes, never itself. */
        val removable: Boolean,
    )

    data class Removed(val id: Int, val name: String, val at: Long)

    /** What the Share sheet shows (desktop `view`). Never a key, a keyring or a password. */
    data class Summary(
        val collectionId: String,
        val collectionName: String,
        val isPro: Boolean,
        val shared: Boolean,
        /** The share group (null while not shared). */
        val groupId: String?,
        val isOwner: Boolean,
        /** "edit" or "read" (null while not shared). */
        val mode: String?,
        val modeText: String?,
        val folder: String,
        val members: List<Member>,
        /** Waiting for the owner's approval (the owner only). */
        val pending: List<Member>,
        /** People the owner removed (the owner only). */
        val removed: List<Removed>,
        /** The last share run's most important issue, or this device's removal while not shared. */
        val status: SyncWording.ShareStatus?,
        /**
         * Not shared here, but another of this person's devices shares it (a received share link): Forget share link is
         * offered instead of Share (final review finding 4). Null otherwise.
         */
        val linked: CollectionShares.Link? = null,
        /** Shared here and from another of this person's devices too (re-review wave B, B1): the sheet warns. */
        val sharedTwice: Boolean = false,
        /**
         * Share v1 on the owner's device (desktop `view` `upgrade`): the sheet offers the upgrade to share v2, where only
         * approved devices can open the items.
         */
        val canUpgrade: Boolean = false,
    )

    /** A folder picked for Share or Join (its SAF tree URI, permission held), before the action uses it. */
    data class PickedFolder(val uri: String, val name: String)

    data class State(
        /** The collection shown (null: the Join sheet before a join worked). */
        val collectionId: String? = null,
        val summary: Summary? = null,
        /** The last action's result. */
        val message: String? = null,
        /** The last refusal. */
        val error: String? = null,
        /** The free plan tried to share or join: the upgrade sheet. */
        val showUpgrade: Boolean = false,
        val busy: Boolean = false,
        val picked: PickedFolder? = null,
        /** Waiting people ticked for Let them in. */
        val selectedPending: Set<String> = emptySet(),
    )

    /** What the person is typing. Never printed. */
    data class Fields(
        val name: String = "",
        val password: String = "",
        val passwordAgain: String = "",
        val membersCanEdit: Boolean = false,
        val newPassword: String = "",
        val newPasswordAgain: String = "",
    ) {
        override fun toString(): String = "Fields(name=${name.length}, membersCanEdit=$membersCanEdit)"
    }

    private val _state = MutableStateFlow(State(collectionId = collectionId))
    val state: StateFlow<State> = _state.asStateFlow()
    private val _fields = MutableStateFlow(Fields())
    val fields: StateFlow<Fields> = _fields.asStateFlow()

    val collectionId: String? get() = _state.value.collectionId
    val summary: Summary? get() = _state.value.summary
    val message: String? get() = _state.value.message
    val error: String? get() = _state.value.error
    val picked: PickedFolder? get() = _state.value.picked

    var name: String
        get() = _fields.value.name
        set(v) = _fields.update { it.copy(name = v) }
    var password: String
        get() = _fields.value.password
        set(v) = _fields.update { it.copy(password = v) }
    var passwordAgain: String
        get() = _fields.value.passwordAgain
        set(v) = _fields.update { it.copy(passwordAgain = v) }
    var membersCanEdit: Boolean
        get() = _fields.value.membersCanEdit
        set(v) = _fields.update { it.copy(membersCanEdit = v) }
    var newPassword: String
        get() = _fields.value.newPassword
        set(v) = _fields.update { it.copy(newPassword = v) }
    var newPasswordAgain: String
        get() = _fields.value.newPasswordAgain
        set(v) = _fields.update { it.copy(newPasswordAgain = v) }
    var selectedPending: Set<String>
        get() = _state.value.selectedPending
        set(v) = _state.update { it.copy(selectedPending = v) }

    fun dismissUpgrade() = _state.update { it.copy(showUpgrade = false) }

    // ---- reading ----

    /** Re-reads the summary (blocking: off the main thread). */
    fun reload() {
        val cid = _state.value.collectionId
        if (cid == null) {
            _state.update { it.copy(summary = null) }
            return
        }
        try {
            val s = makeSummary(
                cid, sync.store.load(), sync.shareIssues.value, sync.removedShares.value, isPro(), folderName, t,
            )
            _state.update { st ->
                st.copy(
                    summary = s, error = if (s == null) reasonText("no-collection", t) else st.error,
                    selectedPending = st.selectedPending.intersect(s?.pending?.map { it.id }?.toSet() ?: emptySet()),
                )
            }
        } catch (e: Exception) {
            _state.update { it.copy(summary = null, error = reasonText(ShareRuns.reason(e), t), selectedPending = emptySet()) }
        }
    }

    /** [reload] on [io]: the actions call it after every change. */
    private suspend fun reloaded() = withContext(io) { reload() }

    private fun isPro(): Boolean = try {
        sync.isPro()
    } catch (e: Exception) {
        false
    }

    // ---- actions ----

    /** A folder picked in the system picker (its permission persisted). */
    fun pick(uri: String, name: String) = _state.update { it.copy(picked = PickedFolder(uri, name), error = null) }

    /** The picked folder could not be used (no persistable permission). */
    fun pickFailed() = _state.update { it.copy(picked = null, error = words.errorText("folder-error")) }

    /** The free plan: the upgrade sheet, and true. */
    private fun needsUpgrade(): Boolean {
        if (isPro()) return false
        _state.update { it.copy(showUpgrade = true) }
        return true
    }

    private fun start(): Boolean {
        if (_state.value.busy) return false
        _state.update { it.copy(busy = true, error = null, message = null) }
        return true
    }

    private fun done() = _state.update { it.copy(busy = false) }

    private fun fail(text: String): Boolean {
        _state.update { it.copy(error = text) }
        return false
    }

    /** Share the collection through the picked folder with the password typed twice and the edit choice. */
    suspend fun share(): Boolean {
        val f = _fields.value
        clearPasswords()
        val cid = _state.value.collectionId ?: return false
        if (!start()) return false
        try {
            if (needsUpgrade()) return false
            val picked = _state.value.picked ?: return fail(t.s(R.string.collection_share_choose_folder_first))
            passwordProblem(f.password, f.passwordAgain, t)?.let { return fail(it) }
            // The owner check comes last, right before the items are handed over; refused: nothing is shared.
            if (!confirmOwner()) return fail(t.s(R.string.collection_share_owner_not_confirmed))
            sync.createShare(cid, picked.uri, f.password, memberName(f.name, t), f.membersCanEdit) ?: return refused()
            _state.update { it.copy(picked = null) }
            reloaded()
            _state.update { it.copy(message = t.s(R.string.collection_share_shared_done, it.summary?.collectionName ?: "")) }
            return true
        } finally {
            done()
        }
    }

    /** Join the shared collection in the picked folder; the sheet then shows that collection. */
    suspend fun join(): Boolean {
        val f = _fields.value
        clearPasswords()
        if (!start()) return false
        try {
            if (needsUpgrade()) return false
            val picked = _state.value.picked ?: return fail(t.s(R.string.collection_share_choose_folder_first))
            if (f.password.isEmpty()) return fail(t.s(R.string.collection_share_enter_password))
            val group = sync.joinShare(picked.uri, f.password, memberName(f.name, t)) ?: return refused()
            _state.update { it.copy(picked = null, collectionId = group.collectionId) }
            reloaded()
            val shown = words.sanitize(_state.value.summary?.collectionName ?: group.name)
            _state.update { it.copy(message = t.s(R.string.collection_share_joined_done, shown)) }
            return true
        } finally {
            done()
        }
    }

    /** Join again after a lost join (`superseded`), from the same folder. */
    suspend fun rejoin(): Boolean {
        val f = _fields.value
        clearPasswords()
        val gid = _state.value.summary?.groupId ?: return false
        if (!start()) return false
        try {
            if (needsUpgrade()) return false
            if (f.password.isEmpty()) return fail(t.s(R.string.collection_share_enter_password))
            sync.rejoinShare(gid, f.password, memberName(f.name, t)) ?: return refused()
            reloaded()
            _state.update { it.copy(message = t.s(R.string.collection_share_joined_done, it.summary?.collectionName ?: "")) }
            return true
        } finally {
            done()
        }
    }

    /** The names of the ticked waiting people, as the confirmation shows them (null: nobody ticked). */
    val approvalNames: String?
        get() {
            val s = _state.value
            val chosen = (s.summary?.pending ?: emptyList()).filter { it.id in s.selectedPending }
            return if (chosen.isEmpty()) null else chosen.joinToString(", ") { it.name }
        }

    /** Let the ticked waiting people in (after the confirmation that names them). */
    suspend fun approve(): Boolean {
        val s = _state.value
        val gid = s.summary?.groupId ?: return false
        val names = approvalNames ?: return false
        val ids = (s.summary.pending).map { it.id }.filter { it in s.selectedPending }
        if (!start()) return false
        try {
            sync.approveShare(gid, ids) ?: return refused()
            _state.update { it.copy(selectedPending = emptySet()) }
            reloaded()
            _state.update { it.copy(message = t.s(R.string.collection_share_approved_done, names)) }
            return true
        } finally {
            done()
        }
    }

    /** Remove [memberId] with a new share password typed twice (the owner; works without Pro). */
    suspend fun remove(memberId: String): Boolean {
        val f = _fields.value
        clearPasswords()
        val summary = _state.value.summary ?: return false
        val gid = summary.groupId ?: return false
        if (!start()) return false
        try {
            val member = summary.members.firstOrNull { it.id == memberId }
            if (member == null || !member.removable) return fail(t.s(R.string.collection_share_not_a_member))
            passwordProblem(f.newPassword, f.newPasswordAgain, t)?.let { return fail(it) }
            if (!sync.removeShareMember(gid, memberId, f.newPassword, f.newPasswordAgain)) return refused()
            val written = sync.shareRemovalWritten.value
            reloaded()
            val doneText = t.s(R.string.collection_share_removed_done, member.name)
            _state.update {
                it.copy(message = if (written) doneText else doneText + " " + t.s(R.string.collection_share_removed_not_written))
            }
            return true
        } finally {
            done()
        }
    }

    /**
     * Upgrade the owner's share v1 to share v2 with the share password typed twice (the current one or a new one; works
     * without Pro). Desktop `CollectionShareService.upgrade`.
     */
    suspend fun upgrade(): Boolean {
        val f = _fields.value
        clearPasswords()
        val summary = _state.value.summary ?: return false
        val gid = summary.groupId ?: return false
        if (!start()) return false
        try {
            if (!summary.isOwner) return fail(t.s(R.string.collection_share_not_owner))
            if (!summary.canUpgrade) return fail(t.s(R.string.collection_share_already_upgraded))
            passwordProblem(f.password, f.passwordAgain, t)?.let { return fail(it) }
            if (!sync.upgradeShare(gid, f.password, f.passwordAgain)) return refused()
            val written = sync.shareUpgradeWritten.value
            reloaded()
            val doneText = t.s(R.string.collection_share_upgraded_done)
            // As the desktop: the folder could not take the new keyring now (the share run writes it later).
            _state.update {
                it.copy(message = if (written) doneText else doneText + " " + t.s(R.string.collection_share_removed_not_written))
            }
            return true
        } finally {
            done()
        }
    }

    /** Leave (a member) or stop sharing (the owner): the collection and its items stay here. */
    suspend fun leave(): Boolean {
        val summary = _state.value.summary ?: return false
        val gid = summary.groupId ?: return false
        if (!start()) return false
        try {
            if (!sync.leaveShare(gid)) return refused()
            reloaded()
            val name = words.sanitize(summary.collectionName)
            _state.update {
                it.copy(message = t.s(if (summary.isOwner) R.string.collection_share_stopped_done else R.string.collection_share_left_done, name))
            }
            return true
        } finally {
            done()
        }
    }

    /**
     * Forget the share link another of this person's devices published (final review finding 4; the screen asks first):
     * for a device that was lost or reset. The collection and its items stay; a device that still holds the share
     * publishes its link again.
     */
    suspend fun forgetLink(): Boolean {
        val summary = _state.value.summary ?: return false
        if (summary.shared || summary.linked == null) return false
        if (!start()) return false
        try {
            if (!sync.forgetShareLink(summary.collectionId)) return refused()
            reloaded()
            _state.update { it.copy(message = t.s(R.string.collection_share_forget_link_done, words.sanitize(summary.collectionName))) }
            return true
        } finally {
            done()
        }
    }

    /** Forgets the last result and refusal (a new step starts, such as opening Remove). */
    fun dismissMessages() = _state.update { it.copy(error = null, message = null) }

    /** Empties every password field (also when the sheet closes). */
    fun clearPasswords() = _fields.update { it.copy(password = "", passwordAgain = "", newPassword = "", newPasswordAgain = "") }

    private suspend fun refused(): Boolean {
        val reason = sync.shareActionReason.value ?: "error"
        _state.update { it.copy(showUpgrade = it.showUpgrade || reason == "pro-required", error = reasonText(reason, t)) }
        reloaded()
        return false
    }

    override fun toString(): String = "CollectionShareModel(collection=${_state.value.collectionId != null}, busy=${_state.value.busy})"

    companion object {
        /** The summary of [collectionId] (null: no such collection). Throws on a damaged share store. */
        fun makeSummary(
            collectionId: String,
            snapshot: StoreSnapshot,
            issues: Map<String, List<SyncIssue>>,
            removedShares: Map<String, SyncIssue>,
            isPro: Boolean,
            folderName: (String) -> String?,
            t: Txt,
        ): Summary? {
            val words = SyncWording(t)
            val row = CollectionCatalog.collections(snapshot).firstOrNull { it.id == collectionId } ?: return null
            val record = ShareGroups.records(snapshot).values.firstOrNull { it.collectionId == collectionId }
                ?: return Summary(
                    collectionId, row.name, isPro, shared = false, groupId = null, isOwner = false, mode = null, modeText = null,
                    folder = "", members = emptyList(), pending = emptyList(), removed = emptyList(),
                    status = removedShares[collectionId]?.let { words.shareStatus(it) },
                    linked = ShareGroups.receivedLink(snapshot, collectionId),
                )
            val group = ShareGroups.group(record)
            val own = record.state.deviceId
            val isOwner = record.role == ShareRecord.Role.OWNER
            val members = group.members.map { m ->
                val state = when {
                    m.deviceId == group.owner -> MemberState.OWNER
                    m.approved -> MemberState.MEMBER
                    else -> MemberState.PENDING
                }
                Member(m.deviceId, displayName(m.name, t), state, stateText(state, t), m.deviceId == own, isOwner && m.deviceId != own)
            }
            val removed = if (isOwner) record.removed.mapIndexed { i, r -> Removed(i, displayName(r.name, t), r.at) } else emptyList()
            return Summary(
                collectionId, row.name, isPro, shared = true, groupId = record.groupId, isOwner = isOwner, mode = group.sharedMode,
                modeText = t.s(if (group.sharedMode == "edit") R.string.collection_share_mode_edit else R.string.collection_share_mode_read),
                folder = record.folder?.let { folderName(ShareRuns.folderUri(it)) } ?: "",
                members = members, pending = if (isOwner) members.filter { it.state == MemberState.PENDING } else emptyList(),
                removed = removed, status = words.shareStatus(issues[record.groupId] ?: emptyList()),
                sharedTwice = ShareGroups.sharedTwice(snapshot, collectionId),
                canUpgrade = isOwner && group.version == 1,
            )
        }

        /**
         * The share password rule (desktop `check_sync_password`: 12+ characters, a Strong rating, both entries equal),
         * with the backup password's words.
         */
        fun passwordProblem(password: String, again: String, t: Txt): String? = BackupPasswordCheck.problem(password, again, t)

        /**
         * The name the others see for this device (desktop `_member_name`): what was typed, cleaned, at most 64 UTF-8
         * bytes; else the phone's generic name (data, never translated).
         */
        fun memberName(typed: String, t: Txt): String {
            val trimmed = typed.trim()
            if (trimmed.isEmpty()) return SyncWording.DEVICE_NAME
            val unnamed = t.s(R.string.sync_unnamed_device)
            var name = SyncWording(t).sanitize(trimmed, limit = 40)
            if (name == unnamed && trimmed != unnamed) return SyncWording.DEVICE_NAME // nothing printable was typed
            while (name.isNotEmpty() && name.toByteArray(Charsets.UTF_8).size > 64) {
                name = name.substring(0, name.offsetByCodePoints(name.length, -1)).trimEnd()
            }
            return name.ifEmpty { SyncWording.DEVICE_NAME }
        }

        /** A member's name as shown: cleaned, or "Unnamed device". */
        fun displayName(name: String?, t: Txt): String =
            if (name.isNullOrBlank()) t.s(R.string.sync_unnamed_device) else SyncWording(t).sanitize(name)

        fun stateText(state: MemberState, t: Txt): String = t.s(
            when (state) {
                MemberState.OWNER -> R.string.collection_share_state_owner
                MemberState.MEMBER -> R.string.collection_share_state_member
                MemberState.PENDING -> R.string.collection_share_state_pending
            },
        )

        /** A refused share action's reason code ([ShareRuns.reason], or this model's own) as shown (desktop `ERROR_COPY`). */
        fun reasonText(reason: String, t: Txt): String {
            val words = SyncWording(t)
            val id = when (reason) {
                "already-shared" -> R.string.collection_share_already_shared
                "no-collection" -> R.string.collection_share_no_collection
                "not-share", "personal-group" -> R.string.collection_share_not_a_share
                "already-joined" -> R.string.collection_share_already_joined
                "collection-exists" -> R.string.collection_share_collection_exists
                "not-owner" -> R.string.collection_share_not_owner
                "not-pending" -> R.string.collection_share_not_pending
                "not-joined" -> R.string.collection_share_not_shared
                "not-member" -> R.string.collection_share_not_a_member
                "password" -> R.string.collection_share_wrong_password
                "password-reused" -> R.string.collection_share_password_reused
                "too-many-members" -> R.string.collection_share_too_many_members
                "no-link" -> R.string.collection_share_not_shared
                "shared-here" -> R.string.collection_share_forget_link_shared_here
                "folder-in-use" -> R.string.collection_share_folder_in_use
                "folder-error" -> R.string.collection_share_folder_not_writable
                "no-share" -> R.string.collection_share_no_share_in_folder
                "keyring-unreadable" -> R.string.collection_share_folder_unreadable
                "share-undo-failed" -> R.string.collection_share_undo_failed
                "password-mismatch" -> R.string.sync_the_two_passwords_do_not
                "collection-limit" -> R.string.collection_share_failed
                "already-upgraded" -> R.string.collection_share_already_upgraded
                "newer-format", "update-required" -> R.string.collection_share_update_required
                "pro-required", "folder-missing" -> return words.shareCopy(SyncIssue(reason)) ?: words.errorText(reason)
                else -> return words.errorText(reason)
            }
            return t.s(id)
        }
    }
}
