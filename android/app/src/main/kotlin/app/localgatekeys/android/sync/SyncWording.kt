package app.localgatekeys.android.sync

import androidx.annotation.StringRes
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.sync.SyncIssue

/**
 * The desktop's Sync screen copy (`src/localvault/sync_ui.py` `ISSUE_COPY`, `ERROR_COPY`, `issue_text`, leave/reset
 * texts) as the iPhone keeps it (`ios/App/Sync/SyncWording.swift`). The text lives in `strings.xml` with "phone" where
 * the desktop says "PC" (the Global Constraints' platform word for "iPhone"); the tables here map the stable issue and
 * reason codes to those resources, so nothing translated is ever compared or stored.
 */
class SyncWording(private val t: Txt) {
    // Wi-Fi pairing (phone only: "the PC" here is the inviting desktop, never rewritten)

    /** Shown under the verification code while the inviting device waits for its user's Accept. */
    val verificationCodeHint: String get() = t.s(R.string.sync_verification_code_hint)

    /** The iPhone's texts with "this phone"; the iPhone-only Local Network privacy case does not exist on Android. */
    fun enrollFailureText(e: EnrollConnectException): String {
        val at = hostPort(e.endpoint)
        when (e.failure) {
            LanFailure.CLOSED_BY_PEER -> return t.s(R.string.sync_enroll_closed, at)
            LanFailure.CANCELLED -> return t.s(R.string.sync_enroll_cancelled)
            else -> {}
        }
        val subnet = e.offSubnet
        if (subnet != null) return t.s(R.string.sync_enroll_off_subnet, e.endpoint.host, subnet)
        return when (e.failure) {
            LanFailure.REFUSED -> t.s(R.string.sync_enroll_refused, at)
            LanFailure.UNREACHABLE -> t.s(R.string.sync_enroll_unreachable, at)
            LanFailure.TIMED_OUT -> t.s(R.string.sync_enroll_timed_out, at)
            else -> t.s(R.string.sync_enroll_other, at)
        }
    }

    fun resetResultText(cleared: Boolean): String = t.s(if (cleared) R.string.sync_reset_done else R.string.sync_there_was_nothing_to_reset)

    val leftText: String get() = t.s(R.string.sync_left_text)
    val passwordBackoffText: String get() = t.s(R.string.sync_password_backoff)
    val stepFailedText: String get() = t.s(R.string.sync_sync_could_not_finish_that)
    val cantFindPc: String get() = t.s(R.string.sync_page_cant_find_pc)
    val cantFindPcHint: String get() = t.s(R.string.sync_cant_find_pc_hint)
    val findAgain: String get() = t.s(R.string.sync_page_find_again)

    /** After Find again saved the PC's new address. */
    fun foundAgainText(endpoint: LanEndpoint): String = t.s(R.string.sync_found_again, hostPort(endpoint))

    // Rendering (desktop issue_text / _issue_views)

    enum class Severity { ERROR, WARNING, NOTICE }

    /** [detail]: the peer id of a `peer-vault-rollback` (its Dismiss button); empty for every other kind. */
    data class IssueView(val kind: String, val severity: Severity, val text: String, val resetOffered: Boolean, val detail: String = "") {
        val id: String get() = "$kind|$text"
    }

    /** Desktop `sanitize_name`: control/format characters dropped, whitespace collapsed, at most [limit] scalars. */
    fun sanitize(value: String, limit: Int = NAME_LIMIT): String {
        val out = StringBuilder()
        var i = 0
        while (i < value.length) {
            val cp = value.codePointAt(i)
            i += Character.charCount(cp)
            when (Character.getType(cp)) {
                Character.SPACE_SEPARATOR.toInt(), Character.LINE_SEPARATOR.toInt(), Character.PARAGRAPH_SEPARATOR.toInt() -> out.append(' ')
                Character.CONTROL.toInt() -> if (cp == '\r'.code || cp == '\n'.code || cp == '\t'.code) out.append(' ')
                Character.FORMAT.toInt(), Character.SURROGATE.toInt(), Character.PRIVATE_USE.toInt(), Character.UNASSIGNED.toInt() -> {}
                else -> out.appendCodePoint(cp)
            }
        }
        var text = out.split(' ').filter { it.isNotEmpty() }.joinToString(" ")
        if (text.isEmpty()) return t.s(R.string.sync_unnamed_device)
        if (text.codePointCount(0, text.length) > limit) {
            val kept = prefixScalars(text, maxOf(1, limit - 1))
            text = kept.trimEnd(' ') + "…"
        }
        return text
    }

    fun shortID(id: String): String = t.s(R.string.sync_device_short_id, prefixScalars(sanitize(id, limit = 9), 8))

    fun subject(kind: String, detail: String, names: Map<String, String>, ownID: String?): String {
        var k = kind
        var h = if (detail.isEmpty()) "" else head(detail)
        if (k == "bad-peer-record") h = trimSpaces(detail.substringBefore(':'))
        if (k == "device-mismatch" && !h.endsWith(DEVICE_SUFFIX)) k = "bad-peer-data"
        if (k in DEVICE_KINDS) {
            if (h.isEmpty()) return t.s(R.string.sync_another_device)
            // Code-point comparison (Kotlin String equality already is; device ids and names come from peers).
            if (ownID != null && h == ownID) return t.s(R.string.sync_subject_this_device)
            val name = if (k != "bad-name") names[h] else null
            if (!name.isNullOrEmpty()) return sanitize(name)
            return shortID(h)
        }
        if (k in FILE_KINDS) return if (h.isEmpty()) t.s(R.string.sync_a_sync_file) else t.s(R.string.sync_the_file_name, sanitize(h, limit = 60))
        if (k == "ignored-file") return if (detail.isEmpty()) t.s(R.string.sync_some_files) else sanitize(detail, limit = 120)
        return ""
    }

    /** The issue as the phone shows it (the desktop's `issue_text` with "phone" for "PC"). */
    fun text(issue: SyncIssue, names: Map<String, String> = emptyMap(), ownID: String? = null, folder: Boolean = false): String {
        val detail = issue.detail
        val kind = effectiveKind(kind = issue.kind, detail = detail)
        if (kind == "rejoin-required" && detail == "install-mismatch") return t.s(R.string.sync_issue_install_mismatch)
        if (kind == "member-dropped" && ownID != null && detail == ownID) return t.s(R.string.sync_issue_self_dropped)
        var template: Int = (if (kind == "epoch-behind" && folder) R.string.sync_issue_epoch_behind_folder else ISSUE_COPY[kind])
            ?: return t.s(R.string.sync_sync_reported_aproblem_details)
        val subject = subject(kind, detail, names, ownID)
        if (kind == "device-mismatch" && !head(detail).endsWith(DEVICE_SUFFIX)) template = R.string.sync_sent_data_signed_for_a
        val text = t.s(template, subject)
        if (text.isEmpty()) return text
        val first = Character.charCount(text.codePointAt(0))
        return text.substring(0, first).uppercase() + text.substring(first)
    }

    /** Deduplicated (kind + detail, then identical text) and sorted by importance (desktop `_issue_views`); stable. */
    fun views(issues: List<SyncIssue>, names: Map<String, String> = emptyMap(), ownID: String? = null, folder: Boolean = false): List<IssueView> {
        val seen = HashSet<String>()
        val texts = HashSet<String>()
        val out = ArrayList<IssueView>()
        for (issue in issues) {
            val kind = effectiveKind(issue.kind, issue.detail)
            if (!seen.add(kind + "\u0000" + issue.detail)) continue
            val text = text(issue, names, ownID, folder)
            if (!texts.add(text)) continue
            out.add(IssueView(kind, severity(kind), text, kind in RESET_KINDS, if (kind == "peer-vault-rollback") issue.detail else ""))
        }
        fun rank(v: IssueView): Int = PRIORITY.indexOf(v.kind).let { if (it < 0) PRIORITY.size else it }
        return out.sortedWith(compareBy<IssueView>({ it.severity.ordinal }, { rank(it) }))
    }

    /** Desktop `error_text` for a refused action (reason code). */
    fun errorText(reason: String): String {
        ERROR_COPY[reason]?.let { return t.s(it) }
        PHONE_ERROR_COPY[reason]?.let { return t.s(it) }
        if (ISSUE_COPY.containsKey(reason)) return text(SyncIssue(reason))
        return t.s(R.string.sync_sync_could_not_finish_that)
    }

    companion object {
        const val NAME_LIMIT = 40

        /** The name this phone puts in the keyring: generic, never the user's device name, and never translated (it is data). */
        const val DEVICE_NAME = "Android phone"

        const val DEVICE_SUFFIX = ".lgksync"

        // Dialog texts, shown through stringResource / Txt.
        @StringRes val ROLLBACK_TITLE = R.string.sync_this_vault_is_older_than
        @StringRes val ROLLBACK_ACTION = R.string.sync_this_was_me_keep_this
        @StringRes val ROLLBACK_CONFIRM_TITLE = R.string.sync_keep_this_copy_of_the
        @StringRes val ROLLBACK_CONFIRM_TEXT = R.string.sync_rollback_confirm_text
        @StringRes val PEER_ROLLBACK_DISMISS = R.string.toast_dismiss
        @StringRes val LEAVE_TEXT = R.string.sync_leave_text
        @StringRes val LEAVE_WIFI_TEXT = R.string.sync_leave_wifi_text

        /** Second confirmation of Leave (the desktop asks once; the phone asks twice like Reset). */
        @StringRes val LEAVE_TEXT_2 = R.string.sync_leave_text_2
        @StringRes val RESET_TEXT_1 = R.string.sync_reset_text_1
        @StringRes val RESET_TEXT_2 = R.string.sync_reset_text_2
        @StringRes val VERIFICATION_CODE_HINT = R.string.sync_verification_code_hint
        @StringRes val CANT_FIND_PC = R.string.sync_page_cant_find_pc
        @StringRes val CANT_FIND_PC_HINT = R.string.sync_cant_find_pc_hint
        @StringRes val FIND_AGAIN = R.string.sync_page_find_again

        /** The text ids behind the desktop's `ISSUE_COPY` / `ERROR_COPY` keys (phone wording, `%1$s` for the subject). */
        val ISSUE_COPY: Map<String, Int> = mapOf(
        "keyring-restored" to R.string.sync_issue_keyring_restored,
        "folder-has-other-group" to R.string.sync_issue_folder_has_other_group,
        "rotation-conflict" to R.string.sync_two_devices_changed_the_sync,
        "removed-or-conflict" to R.string.sync_this_device_may_have_been,
        "rejoin-required" to R.string.sync_issue_rejoin_required,
        "member-dropped" to R.string.sync_disappeared_from_the_member_list,
        "tampered" to R.string.sync_issue_tampered,
        "keyring-corrupt" to R.string.sync_issue_keyring_corrupt,
        "keyring-missing" to R.string.sync_issue_keyring_missing,
        "keyring-unreadable" to R.string.sync_the_key_file_in_the4,
        "unsafe-member" to R.string.sync_a_device_in_the_member,
        "bad-name" to R.string.sync_the_name_of_in_the,
        "state-corrupt" to R.string.sync_issue_state_corrupt,
        "identity-mismatch" to R.string.sync_issue_identity_mismatch,
        "not-joined" to R.string.sync_issue_not_joined,
        "stale-self" to R.string.sync_issue_stale_self,
        "stale-device" to R.string.sync_has_not_synced_for_over,
        "ignored-file" to R.string.sync_unknown_files_in_the_sync,
        "corrupt" to R.string.sync_is_damaged_or_could_not,
        "keyring-rollback" to R.string.sync_issue_keyring_rollback,
        "rollback" to R.string.sync_was_replaced_by_an_older,
        "suspicious-rewrite" to R.string.sync_was_rewritten_without_anew,
        "epoch-mismatch" to R.string.sync_was_written_with_another_sync,
        "device-mismatch" to R.string.sync_holds_data_of_adifferent,
        "unreadable" to R.string.sync_could_not_be_read_and,
        "folder-missing" to R.string.sync_the_sync_folder_is_not,
        "folder-unreadable" to R.string.sync_the_sync_folder_could_not,
        "write-failed" to R.string.sync_issue_write_failed,
        "too-large" to R.string.sync_the_sync_data_is_over,
        "counter-resynced" to R.string.sync_this_vault_was_restored_from,
        "signer-changed" to R.string.sync_has_adifferent_signing_key,
        "trash-full" to R.string.sync_sync_could_not_move_deleted,
        "history-quota" to R.string.sync_sync_could_not_keep_item,
        "bad-peer-data" to R.string.sync_data_from_could_not_be,
        "bad-peer-record" to R.string.sync_issue_bad_peer_record,
        "update-needed" to R.string.sync_issue_update_needed,
        "busy" to R.string.sync_items_changed_while_syncing_sync,
        "apply-failed" to R.string.sync_changes_from_your_other_devices,
        "local-data" to R.string.sync_issue_local_data,
        "error" to R.string.sync_sync_hit_an_unexpected_problem,
        "epoch-behind" to R.string.sync_issue_epoch_behind,
        "peer-epoch-behind" to R.string.sync_has_an_older_sync_key,
        "offer-used-or-expired" to R.string.sync_this_pairing_code_was_used,
        "too-many-peers" to R.string.sync_the_other_device_already_has,
        "peer-update-needed" to R.string.sync_issue_peer_update_needed,
        "lan-update-needed" to R.string.sync_issue_lan_update_needed,
        "lan-not-listening" to R.string.sync_wi_fi_sync_is_not,
        "listen-failed" to R.string.sync_wi_fi_sync_could_not,
        "no-endpoint" to R.string.sync_issue_no_endpoint,
        "unreachable" to R.string.sync_a_device_could_not_be,
        "unknown-peer" to R.string.sync_a_device_that_is_not,
        "peer-revoked" to R.string.sync_was_removed_from_sync_and,
        "peer-mismatch" to R.string.sync_did_not_match_its_pairing,
        "group-mismatch" to R.string.sync_belongs_to_adifferent_sync,
        "peer-not-joined" to R.string.sync_the_other_device_is_not,
        "peer-rejoin-required" to R.string.sync_the_other_device_must_join,
        "peer-refused" to R.string.sync_the_other_device_refused_to,
        "bad-reply" to R.string.sync_issue_bad_reply,
        "bad-chunk" to R.string.sync_issue_bad_chunk,
        "bad-message" to R.string.sync_issue_bad_message,
        "refused" to R.string.sync_the_other_device_refused_the,
        "bad-offer" to R.string.sync_that_is_not_avalid,
        "already-joined" to R.string.sync_this_vault_is_already_in,
        "vault-rollback" to R.string.sync_another_device_in_your_sync,
        "peer-vault-rollback" to R.string.sync_is_now_using_an_older,
        "witness-implausible" to R.string.sync_reported_an_impossible_version_number,
        "rollback-acknowledged" to R.string.sync_you_restored_an_older_backup,
        "attachment-missing" to R.string.sync_a_file_attached_on_another,
        "attachment-refused" to R.string.sync_a_file_from_another_device,
        )

        val ERROR_COPY: Map<String, Int> = mapOf(
        "password" to R.string.sync_that_sync_password_is_not,
        "password-reused" to R.string.sync_choose_anew_sync_password,
        "weak-password" to R.string.sync_the_sync_password_needs_at,
        "folder-in-use" to R.string.sync_this_folder_already_holds_a,
        "no-group" to R.string.sync_there_is_no_sync_group,
        "different-group" to R.string.sync_this_vault_already_syncs_with,
        "keyring-changed" to R.string.sync_another_device_changed_the_sync,
        "folder-error" to R.string.sync_the_folder_could_not_be,
        "folder-missing" to R.string.sync_that_folder_does_not_exist,
        "too-many-members" to R.string.sync_this_sync_group_already_has,
        "cannot-remove-self" to R.string.sync_error_cannot_remove_self,
        "already-joined" to R.string.sync_error_already_joined,
        "not-joined" to R.string.sync_this_vault_is_not_in,
        "rejoin-required" to R.string.sync_error_rejoin_required,
        "not-member" to R.string.sync_that_device_is_not_in,
        "missed-rotation" to R.string.sync_error_missed_rotation,
        "offer-used-or-expired" to R.string.sync_error_offer_used_or_expired,
        "unreachable" to R.string.sync_the_other_device_could_not,
        "too-many-peers" to R.string.sync_error_too_many_peers,
        "declined" to R.string.sync_the_other_device_declined_or,
        "update-needed" to R.string.sync_error_update_needed,
        "bad-offer" to R.string.sync_error_bad_offer,
        "refused" to R.string.sync_the_other_device_refused_the2,
        "not-our-offer" to R.string.sync_this_pairing_code_belongs_to,
        "already-has-folder" to R.string.sync_this_sync_group_already_uses,
        "folder-has-other-group" to R.string.sync_that_folder_holds_adifferent,
        "different-group-key" to R.string.sync_that_folder_ssync_group,
        "epoch-mismatch" to R.string.sync_error_epoch_mismatch,
        "already-member" to R.string.sync_error_already_member,
        )

        /** Phone-only refusals (Find again); not in the desktop's table, so kept apart from [ERROR_COPY]. */
        val PHONE_ERROR_COPY: Map<String, Int> = mapOf(
        "find-again-mismatch" to R.string.sync_phone_error_find_again_mismatch,
        "find-again-not-paired" to R.string.sync_phone_error_find_again_not_paired,
        "find-again-failed" to R.string.sync_phone_error_find_again_failed,
        )

    /** Shown with their own buttons (desktop `ROLLBACK_KINDS`). */
    val ROLLBACK_KINDS: Set<String> = setOf("vault-rollback", "peer-vault-rollback")

    val FILE_KINDS: Set<String> = setOf(
        "corrupt", "rollback", "suspicious-rewrite", "epoch-mismatch", "device-mismatch", "unreadable", "stale-device",
    )
    val DEVICE_KINDS: Set<String> = setOf(
        "member-dropped", "bad-name", "bad-peer-data", "bad-peer-record", "epoch-behind", "peer-epoch-behind", "no-endpoint",
        "peer-revoked", "peer-mismatch", "group-mismatch", "peer-update-needed", "signer-changed", "peer-vault-rollback", "witness-implausible",
    )

    /** Issues that stop sync until the user acts; the screen offers Reset sync. */
    val RESET_KINDS: Set<String> = setOf(
        "folder-has-other-group", "rotation-conflict", "removed-or-conflict", "state-corrupt", "keyring-corrupt", "tampered",
        "identity-mismatch", "keyring-rollback",
    )
    val ERROR_KINDS: Set<String> = RESET_KINDS + setOf(
        "vault-rollback",
        "rejoin-required", "keyring-missing", "keyring-unreadable", "folder-missing", "folder-unreadable", "write-failed",
        "epoch-behind", "error", "listen-failed", "local-data", "apply-failed", "too-large",
    )
    val NOTICE_KINDS: Set<String> = setOf(
        "counter-resynced", "keyring-restored", "busy", "ignored-file", "stale-self", "unreachable", "no-endpoint",
        "lan-not-listening", "not-joined", "peer-vault-rollback", "rollback-acknowledged", "witness-implausible", "attachment-missing",
    )
    val PRIORITY: List<String> = listOf(
        "vault-rollback", "state-corrupt", "folder-has-other-group", "rotation-conflict", "removed-or-conflict", "rejoin-required",
        "tampered", "keyring-rollback", "keyring-corrupt", "identity-mismatch", "keyring-missing", "keyring-unreadable", "folder-missing",
        "folder-unreadable", "epoch-behind", "listen-failed", "write-failed", "too-large", "trash-full",
        "history-quota", "member-dropped", "rollback", "suspicious-rewrite", "corrupt", "bad-peer-data",
        "bad-peer-record", "update-needed",
    )


        /** The 6-digit verification code as both screens show it: "123 456". */
        fun verificationCodeText(code: String): String = if (code.length != 6) code else code.substring(0, 3) + " " + code.substring(3)

        /** `host:port`, IPv6 in brackets. */
        fun hostPort(e: LanEndpoint): String = if (e.host.contains(':')) "[${e.host}]:${e.port}" else "${e.host}:${e.port}"

        fun severity(kind: String): Severity = when (kind) {
            in ERROR_KINDS -> Severity.ERROR
            in NOTICE_KINDS -> Severity.NOTICE
            else -> Severity.WARNING
        }

        /** Swift `.whitespaces`: horizontal whitespace (space separators and tab), not newlines. */
        private fun isHorizontalSpace(c: Char): Boolean = c == '\t' || Character.getType(c) == Character.SPACE_SEPARATOR.toInt()

        private fun trimSpaces(s: String): String = s.trim { isHorizontalSpace(it) }

        fun head(detail: String): String {
            val i = detail.indexOf(": ")
            return trimSpaces(if (i < 0) detail else detail.substring(0, i))
        }

        fun effectiveKind(kind: String, detail: String): String =
            if (kind == "rollback" && !head(detail).endsWith(DEVICE_SUFFIX)) "keyring-rollback" else kind

        private fun prefixScalars(s: String, n: Int): String {
            val count = s.codePointCount(0, s.length)
            return if (count <= n) s else s.substring(0, s.offsetByCodePoints(0, n))
        }
    }
}

/** The Sync screen's status line (`ios/App/Sync/SyncScreen.swift` statusText), with "phone" for "iPhone". */
class SyncStatus(private val t: Txt) {
    /**
     * [time] formats the last sync time (Unix seconds) short, in the phone's locale. [verificationCode]: the QR join's
     * code once shown (connected, waiting for Accept on the inviting device).
     */
    fun text(
        phase: SyncCoordinator.Phase, connecting: LanEndpoint?, joined: Boolean, lastSyncedAt: Long?, verificationCode: String? = null,
        time: (Long) -> String,
    ): String =
        when (phase) {
            SyncCoordinator.Phase.SYNCING -> t.s(R.string.sync_status_syncing)
            SyncCoordinator.Phase.JOINING -> when {
                connecting != null -> t.s(R.string.sync_status_connecting, SyncWording.hostPort(connecting))
                verificationCode != null -> t.s(R.string.sync_status_waiting_accept)
                else -> t.s(R.string.sync_joining)
            }
            SyncCoordinator.Phase.IDLE -> when {
                !joined -> t.s(R.string.sync_status_not_set_up)
                lastSyncedAt == null -> t.s(R.string.sync_status_not_synced)
                else -> t.s(R.string.sync_status_last_synced, time(lastSyncedAt))
            }
        }

    fun conflictText(count: Int): String? =
        if (count <= 0) null else t.plural(R.plurals.sync_status_conflict_copies, count, count)
}
