package app.localgatekeys.android.sync

import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.sync.SyncIssue

/**
 * The desktop's Sync screen copy (`src/localvault/sync_ui.py` `ISSUE_COPY`, `ERROR_COPY`, `issue_text`, leave/reset
 * texts) as the iPhone keeps it (`ios/App/Sync/SyncWording.swift`), byte for byte. The only change on display is
 * [onPhone], which says "phone" where the desktop says "PC" (the Global Constraints' platform word for "iPhone").
 */
object SyncWording {
    const val NAME_LIMIT = 40
    const val UNNAMED_DEVICE = "Unnamed device"

    /** The name this phone puts in the keyring: generic, never the user's device name (desktop "Windows PC"). */
    const val DEVICE_NAME = "Android phone"

    val ISSUE_COPY: Map<String, String> = mapOf(
        // keyring and membership (cloud folder)
        "keyring-restored" to "The sync folder had an older or altered key file. This PC put the trusted copy back; sync continues.",
        "folder-has-other-group" to "This sync folder now holds a different sync group. Sync stopped and nothing was written. Leave sync, or reset sync on this PC, then join the right folder.",
        "rotation-conflict" to "Two devices changed the sync password at the same time. Sync stopped. Join the folder again with the newest sync password.",
        "removed-or-conflict" to "This device may have been removed from sync. Re-join if that isn't expected.",
        "rejoin-required" to "This PC must join sync again (it missed a password change, or it was removed). Join the folder again with the current sync password.",
        "member-dropped" to "{subject} disappeared from the member list without a password change. If you did not remove it, change the sync password.",
        "tampered" to "The key file in the sync folder was altered. Sync stopped. If this keeps happening, reset sync on this PC and join again.",
        "keyring-corrupt" to "The key file in the sync folder is damaged. Reset sync on this PC, or restore the folder.",
        "keyring-missing" to "The key file in the sync folder is missing. Check the folder, or reset sync on this PC.",
        "keyring-unreadable" to "The key file in the sync folder could not be read. Check that the cloud app has downloaded it.",
        "unsafe-member" to "A device in the member list has a name that is not a safe file name; it is ignored.",
        "bad-name" to "The name of {subject} in the key file could not be read; it is shown as Unnamed device. Sync continues.",
        "state-corrupt" to "This vault's sync settings are damaged. Reset sync on this PC, then join again.",
        "identity-mismatch" to "This PC's sync identity does not match its pairing. Reset sync on this PC and pair again.",
        "not-joined" to "Sync is not set up on this PC.",
        // device files
        "stale-self" to "This PC had not synced for over a year. Items deleted elsewhere more than a year ago may come back; delete them again if they do.",
        "stale-device" to "{subject} has not synced for over a year and is ignored. Remove that device if it is gone.",
        "ignored-file" to "Unknown files in the sync folder were ignored ({subject}). Cloud apps sometimes make copies like these; you can delete them.",
        "corrupt" to "{subject} is damaged or could not be verified and was skipped. Nothing was changed.",
        "keyring-rollback" to "The key file in the sync folder was replaced by an older copy and could not be put back. Sync stopped. Check the folder, or reset sync on this PC and join again.",
        "rollback" to "{subject} was replaced by an older copy (for example from the cloud's file history) and was skipped.",
        "suspicious-rewrite" to "{subject} was rewritten without a new version number and was skipped. Someone with access to the folder may have altered it.",
        "epoch-mismatch" to "{subject} was written with another sync key and is ignored until that device syncs again.",
        "device-mismatch" to "{subject} holds data of a different device and was skipped.",
        "unreadable" to "{subject} could not be read and was skipped.",
        "folder-missing" to "The sync folder is not available. Check that the cloud app is running and the folder exists.",
        "folder-unreadable" to "The sync folder could not be read. Check that the cloud app is running.",
        "write-failed" to "This PC could not write its sync file. Check that the folder is available and not read-only.",
        "too-large" to "The sync data is over the sync limit (20,000 items or 64 MB). Some changes were not sent.",
        "counter-resynced" to "This vault was restored from an older copy; sync caught up automatically.",
        "signer-changed" to "{subject} has a different signing key in the sync folder's member list than before. If you did not set that device up again, remove devices you do not trust.",
        // merging
        "trash-full" to "Sync could not move deleted items to the trash because the trash is full. Empty the trash, then sync again.",
        "history-quota" to "Sync could not keep item history because the history limit was reached. Clear old history, then sync again.",
        "bad-peer-data" to "Data from {subject} could not be read and was skipped.",
        "bad-peer-record" to "One item from {subject} could not be read on this PC and was skipped; everything else synced. Updating LocalGateKeys on this PC usually fixes this.",
        "update-needed" to "One item needs a newer LocalGateKeys on this PC. Update LocalGateKeys; that item waits until then.",
        "busy" to "Items changed while syncing; sync tries again shortly.",
        "apply-failed" to "Changes from your other devices could not be saved. Sync tries again later.",
        "local-data" to "Some items on this PC could not be read for sync.",
        "error" to "Sync hit an unexpected problem. Details are in the error log.",
        // Wi-Fi
        "epoch-behind" to "This PC has an older sync key than {subject}. Leave sync on this PC, then pair it again.",
        "peer-epoch-behind" to "{subject} has an older sync key. Pair it again with Show QR code.",
        "offer-used-or-expired" to "This pairing code was used up or expired. Show a new code.",
        "too-many-peers" to "The other device already has the most paired devices. Remove one there first.",
        "peer-update-needed" to "{subject} runs an older LocalGateKeys and cannot sync over Wi-Fi with this PC. Update LocalGateKeys on that device.",
        "lan-update-needed" to "Another device runs a newer Wi-Fi sync. Update LocalGateKeys on this PC.",
        "lan-not-listening" to "Wi-Fi sync is not listening yet.",
        "listen-failed" to "Wi-Fi sync could not start listening. Check the address and port, and that no other app uses that port.",
        "no-endpoint" to "{subject} has no network address; it connects to this PC instead.",
        "unreachable" to "A device could not be reached on this network. Check that it is on the same Wi-Fi and that LocalGateKeys is unlocked there.",
        "unknown-peer" to "A device that is not paired tried to sync and was refused.",
        "peer-revoked" to "{subject} was removed from sync and was not contacted.",
        "peer-mismatch" to "{subject} did not match its pairing and was not synced.",
        "group-mismatch" to "{subject} belongs to a different sync group.",
        "peer-not-joined" to "The other device is not set up for sync.",
        "peer-rejoin-required" to "The other device must join sync again on that device.",
        "peer-refused" to "The other device refused to sync.",
        "bad-reply" to "Another device sent a reply this PC could not understand.",
        "bad-chunk" to "Another device sent data this PC could not understand.",
        "bad-message" to "Another device sent data this PC could not understand.",
        "refused" to "The other device refused the pairing.",
        "bad-offer" to "That is not a valid LocalGateKeys pairing code.",
        "already-joined" to "This vault is already in a sync group. Leave sync first.",
    )

    const val EPOCH_BEHIND_FOLDER_COPY =
        "This PC has an older sync key than {subject}. Let the cloud folder finish syncing, or join the folder again with the newest sync password."
    const val INSTALL_MISMATCH_COPY = "This vault was set up for sync on another PC. Join the folder again on this PC, or reset sync."
    const val SELF_DROPPED_COPY = "This PC was dropped from the member list. Join the folder again."
    const val GENERIC_COPY = "Sync reported a problem. Details are in the error log."
    const val DEVICE_SUFFIX = ".lgksync"

    val FILE_KINDS: Set<String> = setOf(
        "corrupt", "rollback", "suspicious-rewrite", "epoch-mismatch", "device-mismatch", "unreadable", "stale-device",
    )
    val DEVICE_KINDS: Set<String> = setOf(
        "member-dropped", "bad-name", "bad-peer-data", "bad-peer-record", "epoch-behind", "peer-epoch-behind", "no-endpoint",
        "peer-revoked", "peer-mismatch", "group-mismatch", "peer-update-needed", "signer-changed",
    )

    /** Issues that stop sync until the user acts; the screen offers Reset sync. */
    val RESET_KINDS: Set<String> = setOf(
        "folder-has-other-group", "rotation-conflict", "removed-or-conflict", "state-corrupt", "keyring-corrupt", "tampered",
        "identity-mismatch", "keyring-rollback",
    )
    val ERROR_KINDS: Set<String> = RESET_KINDS + setOf(
        "rejoin-required", "keyring-missing", "keyring-unreadable", "folder-missing", "folder-unreadable", "write-failed",
        "epoch-behind", "error", "listen-failed", "local-data", "apply-failed", "too-large",
    )
    val NOTICE_KINDS: Set<String> = setOf(
        "counter-resynced", "keyring-restored", "busy", "ignored-file", "stale-self", "unreachable", "no-endpoint",
        "lan-not-listening", "not-joined",
    )
    val PRIORITY: List<String> = listOf(
        "state-corrupt", "folder-has-other-group", "rotation-conflict", "removed-or-conflict", "rejoin-required",
        "tampered", "keyring-rollback", "keyring-corrupt", "identity-mismatch", "keyring-missing", "keyring-unreadable", "folder-missing",
        "folder-unreadable", "epoch-behind", "listen-failed", "write-failed", "too-large", "trash-full",
        "history-quota", "member-dropped", "rollback", "suspicious-rewrite", "corrupt", "bad-peer-data",
        "bad-peer-record", "update-needed",
    )

    val ERROR_COPY: Map<String, String> = mapOf(
        "password" to "That sync password is not right for this folder.",
        "password-reused" to "Choose a new sync password; it must differ from the current one.",
        "weak-password" to "The sync password needs at least 12 characters and a Strong rating.",
        "folder-in-use" to "This folder already holds a sync group. Use Join a folder instead.",
        "no-group" to "There is no sync group in this folder yet. Create one, or choose the folder your other device uses.",
        "different-group" to "This vault already syncs with another group. Leave sync first.",
        "keyring-changed" to "Another device changed the sync folder at the same moment. Try again.",
        "folder-error" to "The folder could not be used. Check that it exists and is writable.",
        "folder-missing" to "That folder does not exist or is not available.",
        "too-many-members" to "This sync group already has the most devices (16). Remove one first.",
        "cannot-remove-self" to "This PC cannot remove itself. Use Leave sync instead.",
        "already-joined" to "This vault is already in a sync group. Leave sync first.",
        "not-joined" to "This vault is not in a sync group.",
        "rejoin-required" to "This vault was set up for sync on another PC. Join the folder again on this PC.",
        "not-member" to "That device is not in this sync group.",
        "missed-rotation" to "This PC missed a password change. Join the folder again with the current sync password.",
        "offer-used-or-expired" to "This pairing code was used up or expired. Show a new code.",
        "unreachable" to "The other device could not be reached. Check that both are on the same Wi-Fi and that the other device shows its code.",
        "too-many-peers" to "The other device already has the most paired devices. Remove one there first.",
        "declined" to "The other device declined, or nobody chose Accept there in time. Show a new code there and choose Accept when both screens show the same code.",
        "update-needed" to "Update LocalGateKeys on this PC to pair with that device.",
        "bad-offer" to "That is not a valid LocalGateKeys pairing code.",
        "refused" to "The other device refused the pairing. Show a new code and try again.",
        "not-our-offer" to "This pairing code belongs to another sync group. Show a new code.",
        "already-has-folder" to "This sync group already uses a cloud folder.",
        "folder-has-other-group" to "That folder holds a different sync group. Choose another folder, or the folder your other device added to this group.",
        "different-group-key" to "That folder's sync group does not match this vault's group. Choose the folder your other device added to this group.",
        "epoch-mismatch" to "The sync key in that folder changed after this PC was paired. Leave sync on this PC, then use Join a folder with the current sync password.",
        "already-member" to "This PC is already in that folder's sync group.",
    )
    const val STEP_FAILED_COPY = "Sync could not finish that step. Details are in the error log."

    const val LEAVE_TEXT =
        "Leave sync on this PC?\n\nThis PC stops syncing. Your items stay on this PC. Its last sync file stays in the sync folder, so your other devices still receive the changes made here.\n\nOn one of your other devices, open Sync and remove this PC (Remove a device). That deletes its file and changes the sync password, so this PC can no longer read anything new."
    const val LEAVE_WIFI_TEXT =
        "Leave sync on this PC?\n\nThis PC stops Wi-Fi sync and forgets its paired devices. Your items stay on this PC.\n\nOn your other devices, remove this PC from their paired devices. To sync again, pair again with a QR code."

    /** Second confirmation of Leave (the desktop asks once; the phone asks twice like Reset). */
    const val LEAVE_TEXT_2 = "Are you sure? Leave sync on this PC now?"
    const val RESET_TEXT_1 =
        "Reset sync on this PC?\n\nThis forgets this vault's sync group, its keys and its sync history. Your items stay on this PC. To sync again you join a folder or pair again."
    const val RESET_TEXT_2 = "Are you sure? This cannot be undone. Reset sync on this PC now?"
    const val LEFT_TEXT = "This PC left sync. Remove it on one of your other devices."
    const val PASSWORD_BACKOFF_TEXT = "Too many wrong sync passwords. Wait 30 seconds, then try again."

    fun resetResultText(cleared: Boolean): String = if (cleared) "Sync was reset on this PC." else "There was nothing to reset."

    // Wi-Fi pairing (phone only: "the PC" here is the inviting desktop, never rewritten)

    /** Shown under the verification code while the inviting device waits for its user's Accept. */
    const val VERIFICATION_CODE_HINT = "Check that the other device shows this code, then choose Accept there."

    /** The 6-digit verification code as both screens show it: "123 456". */
    fun verificationCodeText(code: String): String = if (code.length != 6) code else code.substring(0, 3) + " " + code.substring(3)

    /** `host:port`, IPv6 in brackets. */
    fun hostPort(e: LanEndpoint): String = if (e.host.contains(':')) "[${e.host}]:${e.port}" else "${e.host}:${e.port}"

    /** The iPhone's texts with "this phone"; the iPhone-only Local Network privacy case does not exist on Android. */
    fun enrollFailureText(e: EnrollConnectException): String {
        val at = hostPort(e.endpoint)
        when (e.failure) {
            LanFailure.CLOSED_BY_PEER ->
                return "The PC at $at closed the connection: the code has probably expired or is no longer waiting. Show a new code on the PC and scan it again."
            LanFailure.CANCELLED -> return "Pairing was cancelled."
            else -> {}
        }
        val subnet = e.offSubnet
        if (subnet != null) {
            return "The code points to ${e.endpoint.host} but this phone is on $subnet. On the PC, set the sync address to its Wi-Fi IPv4 address (ipconfig) and show a new code."
        }
        return when (e.failure) {
            LanFailure.REFUSED -> "Nothing is listening at $at. Open Sync on the PC, choose Show QR code, and scan the new code."
            LanFailure.UNREACHABLE ->
                "$at cannot be reached from this phone. Check that the PC is on this Wi-Fi and that the code shows the PC's Wi-Fi address."
            LanFailure.TIMED_OUT ->
                "$at did not answer. Check that Windows Firewall allows LocalGateKeys on Private networks, and that the PC is on this Wi-Fi."
            else -> "Could not connect to $at. Check that the PC is on this Wi-Fi and shows its code."
        }
    }

    // Rendering (desktop issue_text / _issue_views)

    enum class Severity { ERROR, WARNING, NOTICE }

    data class IssueView(val kind: String, val severity: Severity, val text: String, val resetOffered: Boolean) {
        val id: String get() = "$kind|$text"
    }

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
        if (text.isEmpty()) return UNNAMED_DEVICE
        if (text.codePointCount(0, text.length) > limit) {
            val kept = prefixScalars(text, maxOf(1, limit - 1))
            text = kept.trimEnd(' ') + "…"
        }
        return text
    }

    private fun prefixScalars(s: String, n: Int): String {
        val count = s.codePointCount(0, s.length)
        return if (count <= n) s else s.substring(0, s.offsetByCodePoints(0, n))
    }

    fun shortID(id: String): String = "Device " + prefixScalars(sanitize(id, limit = 9), 8)

    fun subject(kind: String, detail: String, names: Map<String, String>, ownID: String?): String {
        var k = kind
        var h = if (detail.isEmpty()) "" else head(detail)
        if (k == "bad-peer-record") h = trimSpaces(detail.substringBefore(':'))
        if (k == "device-mismatch" && !h.endsWith(DEVICE_SUFFIX)) k = "bad-peer-data"
        if (k in DEVICE_KINDS) {
            if (h.isEmpty()) return "Another device"
            // Code-point comparison (Kotlin String equality already is; device ids and names come from peers).
            if (ownID != null && h == ownID) return "this PC"
            val name = if (k != "bad-name") names[h] else null
            if (!name.isNullOrEmpty()) return sanitize(name)
            return shortID(h)
        }
        if (k in FILE_KINDS) return if (h.isEmpty()) "A sync file" else "The file ${sanitize(h, limit = 60)}"
        if (k == "ignored-file") return if (detail.isEmpty()) "some files" else sanitize(detail, limit = 120)
        return ""
    }

    /** Desktop `issue_text` (with "PC" as on the desktop). */
    fun desktopText(issue: SyncIssue, names: Map<String, String> = emptyMap(), ownID: String? = null, folder: Boolean = false): String {
        val detail = issue.detail
        val kind = effectiveKind(issue.kind, detail)
        if (kind == "rejoin-required" && detail == "install-mismatch") return INSTALL_MISMATCH_COPY
        if (kind == "member-dropped" && ownID != null && detail == ownID) return SELF_DROPPED_COPY
        var template = (if (kind == "epoch-behind" && folder) EPOCH_BEHIND_FOLDER_COPY else ISSUE_COPY[kind]) ?: return GENERIC_COPY
        val subject = subject(kind, detail, names, ownID)
        if (kind == "device-mismatch" && !head(detail).endsWith(DEVICE_SUFFIX)) {
            template = "{subject} sent data signed for a different device; it was skipped."
        }
        val text = template.replace("{subject}", subject)
        if (text.isEmpty()) return text
        val first = Character.charCount(text.codePointAt(0))
        return text.substring(0, first).uppercase() + text.substring(first)
    }

    /** The desktop text as shown on the phone. */
    fun text(issue: SyncIssue, names: Map<String, String> = emptyMap(), ownID: String? = null, folder: Boolean = false): String =
        onPhone(desktopText(issue, names, ownID, folder))

    /** Deduplicated (kind + detail, then identical text) and sorted by importance (desktop `_issue_views`); stable. */
    fun views(issues: List<SyncIssue>, names: Map<String, String> = emptyMap(), ownID: String? = null, folder: Boolean = false): List<IssueView> {
        val seen = HashSet<String>()
        val texts = HashSet<String>()
        val out = ArrayList<IssueView>()
        for (issue in issues) {
            val kind = effectiveKind(issue.kind, issue.detail)
            if (!seen.add(kind + "\u0000" + issue.detail)) continue
            val t = text(issue, names, ownID, folder)
            if (!texts.add(t)) continue
            out.add(IssueView(kind, severity(kind), t, kind in RESET_KINDS))
        }
        fun rank(v: IssueView): Int = PRIORITY.indexOf(v.kind).let { if (it < 0) PRIORITY.size else it }
        return out.sortedWith(compareBy<IssueView>({ it.severity.ordinal }, { rank(it) }))
    }

    /** Desktop `error_text` for a refused action (reason code). */
    fun errorText(reason: String): String {
        ERROR_COPY[reason]?.let { return onPhone(it) }
        if (ISSUE_COPY.containsKey(reason)) return text(SyncIssue(reason))
        return STEP_FAILED_COPY
    }

    private val pcWord = Regex("\\bPC\\b")

    /** "PC" (the desktop's word for this device) reads "phone" here. */
    fun onPhone(text: String): String = pcWord.replace(text.replace("another PC", "another device"), "phone")
}

/** The Sync screen's status line (`ios/App/Sync/SyncScreen.swift` statusText), with "phone" for "iPhone". */
object SyncStatus {
    /**
     * [time] formats the last sync time (Unix seconds) short, in the phone's locale. [verificationCode]: the QR join's
     * code once shown (connected, waiting for Accept on the inviting device).
     */
    fun text(
        phase: SyncCoordinator.Phase, connecting: LanEndpoint?, joined: Boolean, lastSyncedAt: Long?, verificationCode: String? = null,
        time: (Long) -> String,
    ): String =
        when (phase) {
            SyncCoordinator.Phase.SYNCING -> "Syncing…"
            SyncCoordinator.Phase.JOINING -> when {
                connecting != null -> "Connecting to ${SyncWording.hostPort(connecting)}…"
                verificationCode != null -> "Waiting for Accept on the other device…"
                else -> "Joining…"
            }
            SyncCoordinator.Phase.IDLE -> when {
                !joined -> "Sync is not set up on this phone."
                lastSyncedAt == null -> "Not synced since you unlocked."
                else -> "Last synced ${time(lastSyncedAt)}."
            }
        }

    fun conflictText(count: Int): String? =
        if (count <= 0) null else "$count conflict ${if (count == 1) "copy" else "copies"} made since you unlocked."
}
