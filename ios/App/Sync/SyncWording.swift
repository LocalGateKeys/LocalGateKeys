import Foundation
import AppShared

/// The desktop's Sync screen copy (`src/localvault/sync_ui.py` `ISSUE_COPY`, `ERROR_COPY`, `issue_text`,
/// leave/reset texts), copied verbatim; `docs/SYNC.md` "What the Sync screen warnings mean" is the
/// shortened table of the same messages. The tables keep the desktop text byte for byte; the only
/// change on display is `onPhone`, which says "iPhone" where the desktop says "PC".
enum SyncWording {
    static let nameLimit = 40
    static let unnamedDevice = "Unnamed device"
    /// The name this phone puts in the keyring: generic, never the user's device name (desktop "Windows PC").
    static let deviceName = "iPhone"

    static let issueCopy: [String: String] = [
        // keyring and membership (cloud folder)
        "keyring-restored": "The sync folder had an older or altered key file. This PC put the trusted copy back; sync continues.",
        "folder-has-other-group": "This sync folder now holds a different sync group. Sync stopped and nothing was written. Leave sync, or reset sync on this PC, then join the right folder.",
        "rotation-conflict": "Two devices changed the sync password at the same time. Sync stopped. Join the folder again with the newest sync password.",
        "removed-or-conflict": "This device may have been removed from sync. Re-join if that isn't expected.",
        "rejoin-required": "This PC must join sync again (it missed a password change, or it was removed). Join the folder again with the current sync password.",
        "member-dropped": "{subject} disappeared from the member list without a password change. If you did not remove it, change the sync password.",
        "tampered": "The key file in the sync folder was altered. Sync stopped. If this keeps happening, reset sync on this PC and join again.",
        "keyring-corrupt": "The key file in the sync folder is damaged. Reset sync on this PC, or restore the folder.",
        "keyring-missing": "The key file in the sync folder is missing. Check the folder, or reset sync on this PC.",
        "keyring-unreadable": "The key file in the sync folder could not be read. Check that the cloud app has downloaded it.",
        "unsafe-member": "A device in the member list has a name that is not a safe file name; it is ignored.",
        "bad-name": "The name of {subject} in the key file could not be read; it is shown as Unnamed device. Sync continues.",
        "state-corrupt": "This vault's sync settings are damaged. Reset sync on this PC, then join again.",
        "identity-mismatch": "This PC's sync identity does not match its pairing. Reset sync on this PC and pair again.",
        "not-joined": "Sync is not set up on this PC.",
        // device files
        "stale-self": "This PC had not synced for over a year. Items deleted elsewhere more than a year ago may come back; delete them again if they do.",
        "stale-device": "{subject} has not synced for over a year and is ignored. Remove that device if it is gone.",
        "ignored-file": "Unknown files in the sync folder were ignored ({subject}). Cloud apps sometimes make copies like these; you can delete them.",
        "corrupt": "{subject} is damaged or could not be verified and was skipped. Nothing was changed.",
        "keyring-rollback": "The key file in the sync folder was replaced by an older copy and could not be put back. Sync stopped. Check the folder, or reset sync on this PC and join again.",
        "rollback": "{subject} was replaced by an older copy (for example from the cloud's file history) and was skipped.",
        "suspicious-rewrite": "{subject} was rewritten without a new version number and was skipped. Someone with access to the folder may have altered it.",
        "epoch-mismatch": "{subject} was written with another sync key and is ignored until that device syncs again.",
        "device-mismatch": "{subject} holds data of a different device and was skipped.",
        "unreadable": "{subject} could not be read and was skipped.",
        "folder-missing": "The sync folder is not available. Check that the cloud app is running and the folder exists.",
        "folder-unreadable": "The sync folder could not be read. Check that the cloud app is running.",
        "write-failed": "This PC could not write its sync file. Check that the folder is available and not read-only.",
        "too-large": "The sync data is over the sync limit (20,000 items or 64 MB). Some changes were not sent.",
        "counter-resynced": "This vault was restored from an older copy; sync caught up automatically.",
        "signer-changed": "{subject} has a different signing key in the sync folder's member list than before. If you did not set that device up again, remove devices you do not trust.",
        // merging
        "trash-full": "Sync could not move deleted items to the trash because the trash is full. Empty the trash, then sync again.",
        "history-quota": "Sync could not keep item history because the history limit was reached. Clear old history, then sync again.",
        "bad-peer-data": "Data from {subject} could not be read and was skipped.",
        "bad-peer-record": "One item from {subject} could not be read on this PC and was skipped; everything else synced. Updating LocalGateKeys on this PC usually fixes this.",
        "update-needed": "One item needs a newer LocalGateKeys on this PC. Update LocalGateKeys; that item waits until then.",
        "busy": "Items changed while syncing; sync tries again shortly.",
        "apply-failed": "Changes from your other devices could not be saved. Sync tries again later.",
        "local-data": "Some items on this PC could not be read for sync.",
        "error": "Sync hit an unexpected problem. Details are in the error log.",
        // Wi-Fi
        "epoch-behind": "This PC has an older sync key than {subject}. Leave sync on this PC, then pair it again.",
        "peer-epoch-behind": "{subject} has an older sync key. Pair it again with Show QR code.",
        "offer-used-or-expired": "This pairing code was used up or expired. Show a new code.",
        "too-many-peers": "The other device already has the most paired devices. Remove one there first.",
        "peer-update-needed": "{subject} runs an older LocalGateKeys and cannot sync over Wi-Fi with this PC. Update LocalGateKeys on that device.",
        "lan-update-needed": "Another device runs a newer Wi-Fi sync. Update LocalGateKeys on this PC.",
        "lan-not-listening": "Wi-Fi sync is not listening yet.",
        "listen-failed": "Wi-Fi sync could not start listening. Check the address and port, and that no other app uses that port.",
        "no-endpoint": "{subject} has no network address; it connects to this PC instead.",
        "unreachable": "A device could not be reached on this network. Check that it is on the same Wi-Fi and that LocalGateKeys is unlocked there.",
        "unknown-peer": "A device that is not paired tried to sync and was refused.",
        "peer-revoked": "{subject} was removed from sync and was not contacted.",
        "peer-mismatch": "{subject} did not match its pairing and was not synced.",
        "group-mismatch": "{subject} belongs to a different sync group.",
        "peer-not-joined": "The other device is not set up for sync.",
        "peer-rejoin-required": "The other device must join sync again on that device.",
        "peer-refused": "The other device refused to sync.",
        "bad-reply": "Another device sent a reply this PC could not understand.",
        "bad-chunk": "Another device sent data this PC could not understand.",
        "bad-message": "Another device sent data this PC could not understand.",
        "refused": "The other device refused the pairing.",
        "bad-offer": "That is not a valid LocalGateKeys pairing code.",
        "already-joined": "This vault is already in a sync group. Leave sync first.",
    ]

    static let epochBehindFolderCopy = "This PC has an older sync key than {subject}. Let the cloud folder finish syncing, or join the folder again with the newest sync password."
    static let installMismatchCopy = "This vault was set up for sync on another PC. Join the folder again on this PC, or reset sync."
    static let selfDroppedCopy = "This PC was dropped from the member list. Join the folder again."
    static let genericCopy = "Sync reported a problem. Details are in the error log."
    static let deviceSuffix = ".lgksync"

    static let fileKinds: Set<String> = ["corrupt", "rollback", "suspicious-rewrite", "epoch-mismatch", "device-mismatch",
                                         "unreadable", "stale-device"]
    static let deviceKinds: Set<String> = ["member-dropped", "bad-name", "bad-peer-data", "bad-peer-record", "epoch-behind",
                                           "peer-epoch-behind", "no-endpoint", "peer-revoked", "peer-mismatch", "group-mismatch",
                                           "peer-update-needed", "signer-changed"]
    /// Issues that stop sync until the user acts; the screen offers Reset sync.
    static let resetKinds: Set<String> = ["folder-has-other-group", "rotation-conflict", "removed-or-conflict", "state-corrupt",
                                          "keyring-corrupt", "tampered", "identity-mismatch", "keyring-rollback"]
    static let errorKinds: Set<String> = resetKinds.union([
        "rejoin-required", "keyring-missing", "keyring-unreadable", "folder-missing", "folder-unreadable",
        "write-failed", "epoch-behind", "error", "listen-failed", "local-data", "apply-failed", "too-large",
    ])
    static let noticeKinds: Set<String> = ["counter-resynced", "keyring-restored", "busy", "ignored-file", "stale-self",
                                           "unreachable", "no-endpoint", "lan-not-listening", "not-joined"]
    static let priority = [
        "state-corrupt", "folder-has-other-group", "rotation-conflict", "removed-or-conflict", "rejoin-required",
        "tampered", "keyring-rollback", "keyring-corrupt", "identity-mismatch", "keyring-missing", "keyring-unreadable", "folder-missing",
        "folder-unreadable", "epoch-behind", "listen-failed", "write-failed", "too-large", "trash-full",
        "history-quota", "member-dropped", "rollback", "suspicious-rewrite", "corrupt", "bad-peer-data",
        "bad-peer-record", "update-needed",
    ]

    static let errorCopy: [String: String] = [
        "password": "That sync password is not right for this folder.",
        "password-reused": "Choose a new sync password; it must differ from the current one.",
        "weak-password": "The sync password needs at least 12 characters and a Strong rating.",
        "folder-in-use": "This folder already holds a sync group. Use Join a folder instead.",
        "no-group": "There is no sync group in this folder yet. Create one, or choose the folder your other device uses.",
        "different-group": "This vault already syncs with another group. Leave sync first.",
        "keyring-changed": "Another device changed the sync folder at the same moment. Try again.",
        "folder-error": "The folder could not be used. Check that it exists and is writable.",
        "folder-missing": "That folder does not exist or is not available.",
        "too-many-members": "This sync group already has the most devices (16). Remove one first.",
        "cannot-remove-self": "This PC cannot remove itself. Use Leave sync instead.",
        "already-joined": "This vault is already in a sync group. Leave sync first.",
        "not-joined": "This vault is not in a sync group.",
        "rejoin-required": "This vault was set up for sync on another PC. Join the folder again on this PC.",
        "not-member": "That device is not in this sync group.",
        "missed-rotation": "This PC missed a password change. Join the folder again with the current sync password.",
        "offer-used-or-expired": "This pairing code was used up or expired. Show a new code.",
        "unreachable": "The other device could not be reached. Check that both are on the same Wi-Fi and that the other device shows its code.",
        "too-many-peers": "The other device already has the most paired devices. Remove one there first.",
        "declined": "The other device declined, or nobody chose Accept there in time. Show a new code there and choose Accept when both screens show the same code.",
        "update-needed": "Update LocalGateKeys on this PC to pair with that device.",
        "bad-offer": "That is not a valid LocalGateKeys pairing code.",
        "refused": "The other device refused the pairing. Show a new code and try again.",
        "not-our-offer": "This pairing code belongs to another sync group. Show a new code.",
        "already-has-folder": "This sync group already uses a cloud folder.",
        "folder-has-other-group": "That folder holds a different sync group. Choose another folder, or the folder your other device added to this group.",
        "different-group-key": "That folder's sync group does not match this vault's group. Choose the folder your other device added to this group.",
        "epoch-mismatch": "The sync key in that folder changed after this PC was paired. Leave sync on this PC, then use Join a folder with the current sync password.",
        "already-member": "This PC is already in that folder's sync group.",
    ]
    static let stepFailedCopy = "Sync could not finish that step. Details are in the error log."

    static let leaveText = "Leave sync on this PC?\n\nThis PC stops syncing. Your items stay on this PC. Its last sync file stays in the sync folder, so your other devices still receive the changes made here.\n\nOn one of your other devices, open Sync and remove this PC (Remove a device). That deletes its file and changes the sync password, so this PC can no longer read anything new."
    static let leaveWifiText = "Leave sync on this PC?\n\nThis PC stops Wi-Fi sync and forgets its paired devices. Your items stay on this PC.\n\nOn your other devices, remove this PC from their paired devices. To sync again, pair again with a QR code."
    /// Second confirmation of Leave (the desktop asks once; the phone asks twice like Reset).
    static let leaveText2 = "Are you sure? Leave sync on this PC now?"
    static let resetText1 = "Reset sync on this PC?\n\nThis forgets this vault's sync group, its keys and its sync history. Your items stay on this PC. To sync again you join a folder or pair again."
    static let resetText2 = "Are you sure? This cannot be undone. Reset sync on this PC now?"
    static let leftText = "This PC left sync. Remove it on one of your other devices."
    static func resetResultText(_ cleared: Bool) -> String { cleared ? "Sync was reset on this PC." : "There was nothing to reset." }
    static let passwordBackoffText = "Too many wrong sync passwords. Wait 30 seconds, then try again."

    // MARK: Wi-Fi pairing (phone only: "the PC" here is the inviting desktop, never rewritten)

    /// Shown under the verification code while the inviting device waits for its user's Accept.
    static let verificationCodeHint = "Check that the other device shows this code, then choose Accept there."

    /// The 6-digit verification code as both screens show it: "123 456".
    static func verificationCodeText(_ code: String) -> String {
        guard code.count == 6 else { return code }
        return String(code.prefix(3)) + " " + String(code.suffix(3))
    }

    /// `host:port`, IPv6 in brackets.
    static func hostPort(_ e: LanEndpoint) -> String { e.host.contains(":") ? "[\(e.host)]:\(e.port)" : "\(e.host):\(e.port)" }

    static func enrollFailureText(_ e: EnrollConnectError) -> String {
        let at = hostPort(e.endpoint)
        switch e.failure {
        case .localNetworkDenied:
            return "LocalGateKeys is not allowed to use the local network, so it could not reach \(at). Allow Local Network for LocalGateKeys in Settings › Privacy & Security › Local Network, then scan the code again."
        case .closedByPeer:
            return "The PC at \(at) closed the connection: the code has probably expired or is no longer waiting. Show a new code on the PC and scan it again."
        case .cancelled:
            return "Pairing was cancelled."
        default: break
        }
        if let subnet = e.offSubnet {
            return "The code points to \(e.endpoint.host) but this iPhone is on \(subnet). On the PC, set the sync address to its Wi-Fi IPv4 address (ipconfig) and show a new code."
        }
        switch e.failure {
        case .refused:
            return "Nothing is listening at \(at). Open Sync on the PC, choose Show QR code, and scan the new code."
        case .unreachable:
            return "\(at) cannot be reached from this iPhone. Check that the PC is on this Wi-Fi and that the code shows the PC's Wi-Fi address."
        case .timedOut:
            return "\(at) did not answer. Check that Windows Firewall allows LocalGateKeys on Private networks, and that the PC is on this Wi-Fi."
        default:
            return "Could not connect to \(at). Check that the PC is on this Wi-Fi and shows its code."
        }
    }

    // MARK: rendering (desktop issue_text / _issue_views)

    enum Severity: Int, Comparable { case error = 0, warning = 1, notice = 2
        static func < (a: Severity, b: Severity) -> Bool { a.rawValue < b.rawValue }
    }

    struct IssueView: Equatable, Identifiable {
        let kind: String
        let severity: Severity
        let text: String
        let resetOffered: Bool
        var id: String { kind + "|" + text }
    }

    static func severity(_ kind: String) -> Severity {
        if errorKinds.contains(kind) { return .error }
        if noticeKinds.contains(kind) { return .notice }
        return .warning
    }

    static func head(_ detail: String) -> String {
        guard let r = detail.range(of: ": ") else { return detail.trimmingCharacters(in: .whitespaces) }
        return String(detail[..<r.lowerBound]).trimmingCharacters(in: .whitespaces)
    }

    static func effectiveKind(_ kind: String, _ detail: String) -> String {
        if kind == "rollback" && !head(detail).hasSuffix(deviceSuffix) { return "keyring-rollback" }
        return kind
    }

    /// Desktop `sanitize_name`: control/format characters dropped, whitespace collapsed, at most `limit`.
    static func sanitize(_ value: String, limit: Int = nameLimit) -> String {
        var out = ""
        for ch in value.unicodeScalars {
            let cat = ch.properties.generalCategory
            switch cat {
            case .spaceSeparator, .lineSeparator, .paragraphSeparator: out.unicodeScalars.append(" ")
            case .control where ch == "\r" || ch == "\n" || ch == "\t": out.unicodeScalars.append(" ")
            case .control, .format, .surrogate, .privateUse, .unassigned: continue
            default: out.unicodeScalars.append(ch)
            }
        }
        var text = out.split(whereSeparator: { $0 == " " }).joined(separator: " ")
        if text.isEmpty { return unnamedDevice }
        if text.unicodeScalars.count > limit {
            let kept = String(String.UnicodeScalarView(text.unicodeScalars.prefix(max(1, limit - 1))))
            text = kept.replacingOccurrences(of: "\\s+$", with: "", options: .regularExpression) + "…"
        }
        return text
    }

    static func shortID(_ id: String) -> String {
        "Device \(String(String.UnicodeScalarView(sanitize(id, limit: 9).unicodeScalars.prefix(8))))"
    }

    static func subject(_ kind: String, _ detail: String, names: [String: String], ownID: String?) -> String {
        var kind = kind
        var head = detail.isEmpty ? "" : Self.head(detail)
        if kind == "bad-peer-record" { head = detail.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).first.map { String($0).trimmingCharacters(in: .whitespaces) } ?? "" }
        if kind == "device-mismatch" && !head.hasSuffix(deviceSuffix) { kind = "bad-peer-data" }
        if deviceKinds.contains(kind) {
            if head.isEmpty { return "Another device" }
            // Code-point comparison (device ids and names come from peers; Swift `==` is canonical equivalence).
            if let ownID, Scalars.equal(head, ownID) { return "this PC" }
            let name = kind != "bad-name" ? names.first(where: { Scalars.equal($0.key, head) })?.value : nil
            if let name, !name.isEmpty { return sanitize(name) }
            return shortID(head)
        }
        if fileKinds.contains(kind) { return head.isEmpty ? "A sync file" : "The file \(sanitize(head, limit: 60))" }
        if kind == "ignored-file" { return detail.isEmpty ? "some files" : sanitize(detail, limit: 120) }
        return ""
    }

    /// Desktop `issue_text` (with "PC" as on the desktop).
    static func desktopText(_ issue: SyncIssue, names: [String: String] = [:], ownID: String? = nil, folder: Bool = false) -> String {
        let detail = issue.detail
        let kind = effectiveKind(issue.kind, detail)
        if kind == "rejoin-required" && detail == "install-mismatch" { return installMismatchCopy }
        if kind == "member-dropped", let ownID, Scalars.equal(detail, ownID) { return selfDroppedCopy }
        guard var template = (kind == "epoch-behind" && folder) ? epochBehindFolderCopy : issueCopy[kind] else { return genericCopy }
        let subject = subject(kind, detail, names: names, ownID: ownID)
        if kind == "device-mismatch" && !head(detail).hasSuffix(deviceSuffix) {
            template = "{subject} sent data signed for a different device; it was skipped."
        }
        let text = template.replacingOccurrences(of: "{subject}", with: subject)
        guard let first = text.first else { return text }
        return first.uppercased() + text.dropFirst()
    }

    /// The desktop text as shown on the phone.
    static func text(_ issue: SyncIssue, names: [String: String] = [:], ownID: String? = nil, folder: Bool = false) -> String {
        onPhone(desktopText(issue, names: names, ownID: ownID, folder: folder))
    }

    /// Deduplicated (kind + detail, then identical text) and sorted by importance (desktop `_issue_views`).
    static func views(_ issues: [SyncIssue], names: [String: String] = [:], ownID: String? = nil, folder: Bool = false) -> [IssueView] {
        var seen = Set<String>(), texts = Set<String>()
        var out: [IssueView] = []
        for issue in issues {
            let kind = effectiveKind(issue.kind, issue.detail)
            guard seen.insert(kind + "\u{0}" + issue.detail).inserted else { continue }
            let text = text(issue, names: names, ownID: ownID, folder: folder)
            guard texts.insert(text).inserted else { continue }
            out.append(IssueView(kind: kind, severity: severity(kind), text: text, resetOffered: resetKinds.contains(kind)))
        }
        func rank(_ v: IssueView) -> (Int, Int) { (v.severity.rawValue, priority.firstIndex(of: v.kind) ?? priority.count) }
        return out.enumerated().sorted { rank($0.element) < rank($1.element) || (rank($0.element) == rank($1.element) && $0.offset < $1.offset) }.map(\.element)
    }

    /// Desktop `error_text` for a refused action (reason code).
    static func errorText(reason: String) -> String {
        if let t = errorCopy[reason] { return onPhone(t) }
        if issueCopy[reason] != nil { return text(SyncIssue(reason)) }
        return stepFailedCopy
    }

    /// "PC" (the desktop's word for this device) reads "iPhone" here.
    static func onPhone(_ text: String) -> String {
        text.replacingOccurrences(of: "another PC", with: "another device")
            .replacingOccurrences(of: "\\bPC\\b", with: "iPhone", options: .regularExpression)
    }
}
