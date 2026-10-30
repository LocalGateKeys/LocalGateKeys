package app.localgatekeys.android.sync

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.sync.SyncCoordinator.Phase
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.sync.SyncIssue
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The desktop copy as the iPhone shows it (`ios/App/Sync/SyncWording.swift`), with "phone" for "PC": the table checks of
 * the Swift `test_issues_map_to_the_desktop_wording`, the rendering rules, and a verbatim comparison with the Swift tables.
 */
class SyncWordingTest {
    private val en = EnglishTxt()
    private val words = SyncWording(en)

    /** The desktop word "PC" read as "phone" (what the Swift tables say once adapted for this app). */
    private fun phone(text: String): String = Regex("\\bPC\\b").replace(text.replace("another PC", "another device"), "phone")

    private val swift: String = File(checkNotNull(System.getProperty("lgk.repoRoot")), "ios/App/Sync/SyncWording.swift").readText()

    /** `"key": "text",` entries of the Swift dictionary literal named [name]. */
    private fun swiftTable(name: String): Map<String, String> {
        val start = swift.indexOf("static let $name: [String: String] = [")
        check(start >= 0) { "$name not found" }
        val end = swift.indexOf("\n    ]", start)
        val body = swift.substring(start, end)
        return Regex("""^\s*"([^"]+)": "((?:[^"\\]|\\.)*)",\s*$""", RegexOption.MULTILINE).findAll(body)
            .associate { it.groupValues[1] to unescape(it.groupValues[2]) }
    }

    private fun swiftConstant(name: String): String {
        val m = Regex("""static let $name = "((?:[^"\\]|\\.)*)"""").find(swift) ?: error("$name not found")
        return unescape(m.groupValues[1])
    }

    private fun unescape(s: String) = s.replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\")

    private fun swiftSet(name: String): Set<String> {
        val start = swift.indexOf("static let $name")
        val end = swift.indexOf(']', start)
        return Regex(""""([^"]+)"""").findAll(swift.substring(start, end)).map { it.groupValues[1] }.toSet()
    }

    @Test fun tables_are_the_desktop_copy_verbatim() {
        val issues = swiftTable("issueCopy")
        val errors = swiftTable("errorCopy")
        assertTrue(issues.size >= 60)
        assertTrue(errors.size >= 27)
        // Same keys as the Swift tables; each text is the desktop copy with "phone" for "PC" ({subject} kept as the format argument).
        assertEquals(issues.keys, SyncWording.ISSUE_COPY.keys)
        assertEquals(errors.keys, SyncWording.ERROR_COPY.keys)
        for ((k, v) in issues) assertEquals(k, phone(v), en.s(SyncWording.ISSUE_COPY.getValue(k), "{subject}"))
        for ((k, v) in errors) assertEquals(k, phone(v), en.s(SyncWording.ERROR_COPY.getValue(k), "{subject}"))
        val constants = mapOf(
            "epochBehindFolderCopy" to R.string.sync_issue_epoch_behind_folder,
            "installMismatchCopy" to R.string.sync_issue_install_mismatch,
            "selfDroppedCopy" to R.string.sync_issue_self_dropped,
            "genericCopy" to R.string.sync_sync_reported_aproblem_details,
            "stepFailedCopy" to R.string.sync_sync_could_not_finish_that,
            "leaveText" to SyncWording.LEAVE_TEXT,
            "leaveWifiText" to SyncWording.LEAVE_WIFI_TEXT,
            "leaveText2" to SyncWording.LEAVE_TEXT_2,
            "resetText1" to SyncWording.RESET_TEXT_1,
            "resetText2" to SyncWording.RESET_TEXT_2,
            "leftText" to R.string.sync_left_text,
            "passwordBackoffText" to R.string.sync_password_backoff,
            "unnamedDevice" to R.string.sync_unnamed_device,
            "verificationCodeHint" to SyncWording.VERIFICATION_CODE_HINT,
            "rollbackTitle" to SyncWording.ROLLBACK_TITLE,
            "rollbackAction" to SyncWording.ROLLBACK_ACTION,
            "rollbackConfirmTitle" to SyncWording.ROLLBACK_CONFIRM_TITLE,
            "rollbackConfirmText" to SyncWording.ROLLBACK_CONFIRM_TEXT,
            "peerRollbackDismiss" to SyncWording.PEER_ROLLBACK_DISMISS,
        )
        assertEquals(swiftSet("rollbackKinds"), SyncWording.ROLLBACK_KINDS)
        for ((k, id) in constants) assertEquals(k, phone(swiftConstant(k)), en.s(id, "{subject}"))
        assertEquals(swiftSet("fileKinds"), SyncWording.FILE_KINDS)
        assertEquals(swiftSet("deviceKinds"), SyncWording.DEVICE_KINDS)
        assertEquals(swiftSet("resetKinds"), SyncWording.RESET_KINDS)
        assertEquals(swiftSet("noticeKinds"), SyncWording.NOTICE_KINDS)
        assertEquals(swiftSet("resetKinds") + swiftSet("errorKinds"), SyncWording.ERROR_KINDS)
        val priority = Regex(""""([^"]+)"""").findAll(swift.substring(swift.indexOf("static let priority"), swift.indexOf("]", swift.indexOf("static let priority"))))
            .map { it.groupValues[1] }.toList()
        assertEquals(priority, SyncWording.PRIORITY)
        assertEquals("Android phone", SyncWording.DEVICE_NAME)
    }

    @Test fun device_name_in_the_keyring_is_data_and_is_never_translated() {
        // The name written to the sync keyring is a constant: the language of the screen never reaches it.
        assertEquals("Android phone", SyncWording.DEVICE_NAME)
        assertEquals(".lgksync", SyncWording.DEVICE_SUFFIX)
    }

    @Test fun issue_texts_say_phone_for_pc() {
        assertEquals(
            "The key file in the sync folder is missing. Check the folder, or reset sync on this PC.",
            swiftTable("issueCopy").getValue("keyring-missing"),
        )
        assertEquals(
            "The key file in the sync folder is missing. Check the folder, or reset sync on this phone.",
            words.text(SyncIssue("keyring-missing")),
        )
        assertEquals("The file x.lgksync could not be read and was skipped.", words.text(SyncIssue("unreadable", "x.lgksync: io")))
        assertEquals(
            "The key file in the sync folder was replaced by an older copy and could not be put back. Sync stopped. Check the folder, or reset sync on this phone and join again.",
            words.text(SyncIssue("rollback", "keyring.lgkkeys: x")),
        )
        assertEquals(
            "This vault was set up for sync on another device. Join the folder again on this phone, or reset sync.",
            words.text(SyncIssue("rejoin-required", "install-mismatch")),
        )
        assertEquals(
            "This vault was set up for sync on another device. Join the folder again on this phone.",
            words.errorText("rejoin-required"),
        )
        assertEquals(
            "Unknown files in the sync folder were ignored (2 files: a (1).lgksync, b). Cloud apps sometimes make copies like these; you can delete them.",
            words.text(SyncIssue("ignored-file", "2 files: a (1).lgksync, b")),
        )
        assertEquals("Sync reported a problem. Details are in the error log.", words.text(SyncIssue("something-new")))
        val views = words.views(listOf(SyncIssue("busy"), SyncIssue("tampered"), SyncIssue("tampered"), SyncIssue("corrupt", "f.lgksync: x")))
        assertEquals(listOf("tampered", "corrupt", "busy"), views.map { it.kind })
        assertEquals(listOf(true, false, false), views.map { it.resetOffered })
        assertEquals(
            listOf(SyncWording.Severity.ERROR, SyncWording.Severity.WARNING, SyncWording.Severity.NOTICE),
            views.map { it.severity },
        )
    }

    @Test fun subjects_name_devices_and_files() {
        val own = "d4444444-0000-4000-8000-00000000000d"
        assertEquals(
            "This phone has an older sync key than Device a1111111. Leave sync on this phone, then pair it again.",
            words.text(SyncIssue("epoch-behind", "a1111111-0000-4000-8000-00000000000a")),
        )
        assertEquals(
            "This phone has an older sync key than Desk computer. Let the cloud folder finish syncing, or join the folder again with the newest sync password.",
            words.text(SyncIssue("epoch-behind", "a1"), names = mapOf("a1" to "Desk computer"), folder = true),
        )
        assertEquals("This phone was dropped from the member list. Join the folder again.", words.text(SyncIssue("member-dropped", own), ownID = own))
        assertEquals(
            "This phone disappeared from the member list without a password change. If you did not remove it, change the sync password.",
            words.text(SyncIssue("member-dropped", "$own: gone"), ownID = own),
        )
        assertEquals("Another device has no network address; it connects to this phone instead.", words.text(SyncIssue("no-endpoint")))
        assertEquals("A sync file is damaged or could not be verified and was skipped. Nothing was changed.", words.text(SyncIssue("corrupt")))
        assertEquals(
            "Device b2222222 sent data signed for a different device; it was skipped.",
            words.text(SyncIssue("device-mismatch", "b2222222-0000: x")),
        )
        assertEquals(
            "The file b.lgksync holds data of a different device and was skipped.",
            words.text(SyncIssue("device-mismatch", "b.lgksync: x")),
        )
        assertEquals(
            "One item from Device c3333333 could not be read on this phone and was skipped; everything else synced. Updating LocalGateKeys on this phone usually fixes this.",
            words.text(SyncIssue("bad-peer-record", "c3333333-0000:item-1")),
        )
        // bad-name never shows the unreadable name.
        assertEquals(
            "The name of Device a1 in the key file could not be read; it is shown as Unnamed device. Sync continues.",
            words.text(SyncIssue("bad-name", "a1"), names = mapOf("a1" to "Ignored")),
        )
    }

    @Test fun sanitize_matches_desktop_sanitize_name() {
        assertEquals("Unnamed device", words.sanitize(""))
        assertEquals("Unnamed device", words.sanitize("​\u0007"))
        assertEquals("a b c", words.sanitize("  a\tb\n c  "))
        assertEquals("ab", words.sanitize("a‍b"))
        val long = "x".repeat(39) + " y"
        assertEquals("x".repeat(39) + "…", words.sanitize(long))
        assertEquals("abcdefgh…", words.sanitize("abcdefgh ijkl", limit = 10))
        assertEquals("Device abcdefgh", words.shortID("abcdefghijkl"))
        assertEquals("Device 😀😀😀😀😀😀😀😀", words.shortID("😀".repeat(12)))
        assertEquals("a1111111", SyncWording.head("  a1111111 : rest: more"))
    }

    @Test fun error_text_falls_back_to_issue_copy_then_step_failed() {
        assertEquals("That sync password is not right for this folder.", words.errorText("password"))
        assertEquals("This phone cannot remove itself. Use Leave sync instead.", words.errorText("cannot-remove-self"))
        assertEquals("The key file in the sync folder is damaged. Reset sync on this phone, or restore the folder.", words.errorText("keyring-corrupt"))
        assertEquals("Items changed while syncing; sync tries again shortly.", words.errorText("busy"))
        assertEquals(en.s(R.string.sync_sync_could_not_finish_that), words.errorText("locked"))
        assertEquals("This phone left sync. Remove it on one of your other devices.", words.leftText)
        assertEquals("Sync was reset on this phone.", words.resetResultText(true))
        assertEquals("There was nothing to reset.", words.resetResultText(false))
        // "PCs" or "PCB" are not the word PC.
        assertEquals("phone, PCs, PCB, on another device", phone("PC, PCs, PCB, on another PC"))
    }

    @Test fun sync_v2_kinds_and_refusals_read_as_on_the_iphone() {
        // Swift SyncWording on main: signer-changed and peer-update-needed name the device, lan-update-needed does not.
        val dev = "a1111111-0000-4000-8000-00000000000a"
        assertTrue("signer-changed" in SyncWording.DEVICE_KINDS)
        assertTrue("peer-update-needed" in SyncWording.DEVICE_KINDS)
        assertFalse("lan-update-needed" in SyncWording.DEVICE_KINDS)
        assertEquals(
            "Work laptop has a different signing key in the sync folder's member list than before. If you did not set that device up again, remove devices you do not trust.",
            words.text(SyncIssue("signer-changed", "$dev: the keyring lists another signing key"), names = mapOf(dev to "Work laptop")),
        )
        assertEquals(
            "Device a1111111 runs an older LocalGateKeys and cannot sync over Wi-Fi with this phone. Update LocalGateKeys on that device.",
            words.text(SyncIssue("peer-update-needed", dev)),
        )
        assertEquals(
            "Another device runs a newer Wi-Fi sync. Update LocalGateKeys on this phone.",
            words.text(SyncIssue("lan-update-needed")),
        )
        assertEquals(SyncWording.Severity.WARNING, SyncWording.severity("signer-changed"))
        // QR join refusals (Enrollment v2).
        assertEquals(
            "The other device declined, or nobody chose Accept there in time. Show a new code there and choose Accept when both screens show the same code.",
            words.errorText("declined"),
        )
        assertEquals("Update LocalGateKeys on this phone to pair with that device.", words.errorText("update-needed"))
    }

    @Test fun verification_code_shows_in_two_groups_of_three() {
        assertEquals("123 456", SyncWording.verificationCodeText("123456"))
        assertEquals("012 345", SyncWording.verificationCodeText("012345"))
        assertEquals("12345", SyncWording.verificationCodeText("12345")) // anything else as it is
        assertEquals("Check that the other device shows this code, then choose Accept there.", EnglishTxt().s(SyncWording.VERIFICATION_CODE_HINT))
    }

    @Test fun enroll_failures_keep_the_pc_as_the_inviter() {
        val ep = LanEndpoint("192.168.1.20", 48201)
        fun t(kind: LanFailure, sub: IPv4Subnet? = null) = words.enrollFailureText(EnrollConnectException(kind, ep, sub))
        assertEquals("Pairing was cancelled.", t(LanFailure.CANCELLED))
        assertEquals("Could not connect to 192.168.1.20:48201. Check that the PC is on this Wi-Fi and shows its code.", t(LanFailure.OTHER))
        val sub = IPv4Subnet.of("10.0.0.7", "255.255.0.0")!!
        assertEquals("10.0.0.0/16", sub.toString())
        assertEquals(
            "The code points to 192.168.1.20 but this phone is on 10.0.0.0/16. On the PC, set the sync address to its Wi-Fi IPv4 address (ipconfig) and show a new code.",
            t(LanFailure.TIMED_OUT, sub),
        )
        assertEquals("Pairing was cancelled.", t(LanFailure.CANCELLED, sub))
        assertEquals("[fe80::1]:5", SyncWording.hostPort(LanEndpoint("fe80::1", 5)))
    }

    @Test fun ipv4_subnet_rules() {
        assertNull(IPv4Subnet.of("192.168.1.2", "255.0.255.0")) // not contiguous
        assertNull(IPv4Subnet.of("nope", "255.255.255.0"))
        val s = IPv4Subnet.of("192.168.1.77", "255.255.255.0")!!
        assertEquals(true, s.contains("192.168.1.20"))
        assertEquals(false, s.contains("192.168.2.20"))
        assertNull(s.contains("fe80::1"))
        assertNull(IPv4Subnet.mismatch("192.168.1.20", s))
        assertEquals(s, IPv4Subnet.mismatch("192.168.2.20", s))
        assertNull(IPv4Subnet.mismatch("fe80::1", s))
        assertNull(IPv4Subnet.mismatch("192.168.2.20", null))
        assertEquals("0.0.0.0/0", IPv4Subnet.of("1.2.3.4", "0.0.0.0").toString())
    }

    @Test fun status_text_follows_the_phase() {
        fun t(phase: Phase, joined: Boolean = true, at: Long? = null, connecting: LanEndpoint? = null, code: String? = null) =
            SyncStatus(en).text(phase, connecting, joined, at, verificationCode = code) { "10:42" }
        assertEquals("Syncing…", t(Phase.SYNCING))
        assertEquals("Joining…", t(Phase.JOINING))
        assertEquals("Connecting to 192.168.1.20:48201…", t(Phase.JOINING, connecting = LanEndpoint("192.168.1.20", 48201)))
        // Connected, the code shown: the inviting device waits for its user's Accept (Swift statusText on main).
        assertEquals("Waiting for Accept on the other device…", t(Phase.JOINING, code = "123456"))
        assertEquals(
            "Connecting to 192.168.1.20:48201…",
            t(Phase.JOINING, connecting = LanEndpoint("192.168.1.20", 48201), code = "123456"),
        )
        assertEquals("Sync is not set up on this phone.", t(Phase.IDLE, joined = false))
        assertEquals("Not synced since you unlocked.", t(Phase.IDLE))
        assertEquals("Last synced 10:42.", t(Phase.IDLE, at = 1_790_000_000))
        assertNull(SyncStatus(en).conflictText(0))
        assertEquals("1 conflict copy made since you unlocked.", SyncStatus(en).conflictText(1))
        assertEquals("3 conflict copies made since you unlocked.", SyncStatus(en).conflictText(3))
        assertFalse(words.text(SyncIssue("not-joined")).contains("PC"))
    }
}
