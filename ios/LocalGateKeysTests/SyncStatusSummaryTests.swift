import XCTest
import AppShared
@testable import LocalGateKeys

/// UX plan workstream 6 (Android `SyncStatusSummaryTest`, Windows `test_sync_status_summary.py`): the pill text, the
/// dot colour for each state and the sheet's device rows.
final class SyncStatusSummaryTests: XCTestCase {
    let now: Int64 = 1_800_000_000

    func membership(peerSyncedAt: [String: Int64] = [:]) -> SyncCoordinator.Membership {
        var m = SyncCoordinator.Membership()
        m.joined = true; m.hasFolder = true; m.deviceID = "phone"
        m.members = ["desk", "laptop", "phone"]
        m.wifiPeers = ["desk"]
        m.names = ["desk": "Desk PC"]
        m.peerSyncedAt = peerSyncedAt
        return m
    }

    func issue(_ severity: SyncWording.Severity) -> SyncWording.IssueView {
        SyncWording.IssueView(kind: "k", severity: severity, text: "t", resetOffered: false)
    }

    func test_not_joined_has_no_pill() {
        XCTAssertNil(SyncStatusSummary.make(membership: .init(), issues: [], lastSyncedAt: nil, now: now))
    }

    func test_pill_text_and_device_rows() throws {
        let s = try XCTUnwrap(SyncStatusSummary.make(membership: membership(peerSyncedAt: ["desk": now - 600]), issues: [],
                                                     lastSyncedAt: now - 120, now: now))
        XCTAssertEqual(s.pill, "Synced 2 min ago · 3 devices")
        XCTAssertEqual(s.dot, .green)
        XCTAssertEqual(s.devices.map(\.id), ["desk", "laptop"])
        XCTAssertEqual(s.devices[0].name, "Desk PC · " + SyncWording.shortID("desk"))
        XCTAssertEqual(s.thisDeviceLabel, "This device: " + SyncWording.shortID("phone"))
        XCTAssertEqual(SyncWording.thisDevice(name: "My Phone", id: "phone"), "This device: My Phone · " + SyncWording.shortID("phone"))
        XCTAssertEqual(SyncWording.labeled(nil, "abc"), SyncWording.shortID("abc"))
        XCTAssertEqual(SyncWording.labeled("", "abc"), SyncWording.shortID("abc"))
        XCTAssertEqual(SyncWording.labeled("My\u{7}Phone", "abc"), "MyPhone · " + SyncWording.shortID("abc"))
        XCTAssertEqual(s.devices[0].route, .both)
        XCTAssertEqual(s.devices[0].lastSynced, now - 600)
        XCTAssertEqual(s.devices[1].route, .folder)
        XCTAssertEqual(s.devices[1].name, SyncWording.shortID("laptop"))
        XCTAssertNil(s.devices[1].lastSynced)
        XCTAssertEqual(SyncStatusSummary.lastSyncedText(nil, now: now), "Never")
    }

    func test_one_device_and_never_synced() throws {
        var m = SyncCoordinator.Membership()
        m.joined = true; m.deviceID = "phone"
        let s = try XCTUnwrap(SyncStatusSummary.make(membership: m, issues: [], lastSyncedAt: nil, now: now))
        XCTAssertEqual(s.pill, "Not synced yet · 1 device")
        XCTAssertEqual(s.dot, .orange)
    }

    func test_dot_colours() throws {
        let m = membership(peerSyncedAt: ["desk": now - 60])
        func dot(_ issues: [SyncWording.IssueView], last: Int64?, _ m: SyncCoordinator.Membership) throws -> SyncStatusSummary.Dot {
            try XCTUnwrap(SyncStatusSummary.make(membership: m, issues: issues, lastSyncedAt: last, now: now)).dot
        }
        XCTAssertEqual(try dot([], last: now - 60, m), .green)
        XCTAssertEqual(try dot([issue(.notice)], last: now - 60, m), .green)
        XCTAssertEqual(try dot([issue(.warning)], last: now - 60, m), .orange)
        XCTAssertEqual(try dot([], last: now - 2 * 86_400, m), .orange)   // older than a day
        XCTAssertEqual(try dot([issue(.error), issue(.warning)], last: now - 60, m), .red)
        // A peer not seen in 30 days.
        let stale = membership(peerSyncedAt: ["desk": now - 31 * 86_400])
        XCTAssertEqual(try dot([], last: now - 60, stale), .orange)
        let s = try XCTUnwrap(SyncStatusSummary.make(membership: stale, issues: [], lastSyncedAt: now - 60, now: now))
        XCTAssertEqual(s.devices[0].warning, "Not seen in 30 days")
    }

    func test_ago() {
        XCTAssertEqual(SyncStatusSummary.ago(-5), "just now")
        XCTAssertEqual(SyncStatusSummary.ago(59), "just now")
        XCTAssertEqual(SyncStatusSummary.ago(120), "2 min ago")
        XCTAssertEqual(SyncStatusSummary.ago(3 * 3600), "3 h ago")
        XCTAssertEqual(SyncStatusSummary.ago(86_400), "1 day ago")
        XCTAssertEqual(SyncStatusSummary.ago(4 * 86_400), "4 days ago")
    }

    func test_last_synced_text() {
        let text = SyncStatusSummary.lastSyncedText(now - 720, now: now, timeZone: TimeZone(identifier: "UTC")!,
                                                    locale: Locale(identifier: "en_GB"))
        XCTAssertTrue(text.hasPrefix("Last synced "), text)
        XCTAssertTrue(text.hasSuffix(" (12 min ago)"), text)
    }

    // MARK: shared collection statuses (sub-plan 07 Task 5g; desktop `collection_share._issue`)

    func test_share_statuses_have_their_own_copy_and_severity() throws {
        let merged = SyncWording.shareStatus(SyncIssue("keyring-merged", "keyring.lgkkeys"))
        XCTAssertEqual(merged.severity, .notice)
        XCTAssertEqual(merged.text, "Someone joined while you were letting others in. They are waiting for your approval below.")
        let pending = SyncWording.shareStatus(SyncIssue("awaiting-approval", "g"))
        XCTAssertEqual(pending.severity, .notice)
        XCTAssertEqual(pending.text, "Waiting for the person who shared this collection to let you in. Nothing syncs until then.")
        let superseded = SyncWording.shareStatus(SyncIssue("superseded", "g"))
        XCTAssertEqual(superseded.severity, .warning)
        XCTAssertTrue(superseded.joinAgain)
        XCTAssertEqual(SyncWording.joinAgainAction, "Join again")
        let tampered = SyncWording.shareStatus(SyncIssue("tampered", "x"))
        XCTAssertEqual(tampered.severity, .error)
        XCTAssertFalse(tampered.joinAgain)
        XCTAssertEqual(tampered.text, "The shared folder's key file was changed in a way LocalGateKeys does not accept. Syncing this collection stopped.")
        XCTAssertEqual(SyncWording.shareStatus(SyncIssue("pro-required", "g")).text,
                       "Shared collections need LocalGateKeys Pro. Items already shared with you stay on this iPhone and keep working.")
        XCTAssertEqual(SyncWording.shareStatus(SyncIssue("folder-missing", "g")).text,
                       "The shared folder is not available. Check that it still exists and is synced to this iPhone.")
        XCTAssertEqual(SyncWording.shareStatus(SyncIssue("rejoin-required", "not-member")).text,
                       "This iPhone can no longer open the shared collection. Ask the person who shared it whether you were removed, then join again.")
        // A share keyring from a later app version (share v2 spec): an error that asks for the update.
        let update = SyncWording.shareStatus(SyncIssue("update-required", "keyring.json"))
        XCTAssertEqual(update.severity, .error)
        XCTAssertFalse(update.joinAgain)
        XCTAssertEqual(update.text, "This shared collection needs a newer version of LocalGateKeys. Update the app to keep syncing it.")
        XCTAssertEqual(SyncWording.shareStatus([SyncIssue("pro-required"), SyncIssue("update-required")])?.kind, "update-required")
        for kind in ["pro-required", "folder-missing", "trash-full", "item-error", "share-removed", "rejoin-required"] {
            XCTAssertEqual(SyncWording.shareStatus(SyncIssue(kind)).severity, .warning, kind)
        }
        // Any other kind: the sync screen's copy.
        XCTAssertEqual(SyncWording.shareStatus(SyncIssue("write-failed")).text, SyncWording.text(SyncIssue("write-failed"), folder: true))
    }

    func test_share_trash_problems_are_never_busy() throws {
        // A removal that Recently deleted cannot take says so for the removal.
        XCTAssertEqual(SyncWording.shareStatus(SyncIssue("trash-full", "the trash cannot hold this collection's items")).text,
                       "You were removed from this shared collection, but the trash is full. Empty the trash so its items can be moved there.")
        XCTAssertEqual(SyncWording.shareStatus(SyncIssue("item-error", "Recently deleted is not available")).text,
                       "You were removed from this shared collection, but some of its items could not be moved to the trash. LocalGateKeys tries again at the next sync.")
        // A normal share run's commit that Recently deleted refused is that refusal, worded as the sync trash message.
        let full = ShareSync.runIssue(SyncIssue("busy", "\(ShareTrashRefusal.full)"))
        XCTAssertEqual(full, SyncIssue("trash-full", ShareSync.runDetail))
        XCTAssertEqual(SyncWording.shareStatus(full).text, SyncWording.text(SyncIssue("trash-full")))
        let closed = ShareSync.runIssue(SyncIssue("busy", "\(ShareTrashRefusal.unavailable)"))
        XCTAssertEqual(closed, SyncIssue("item-error", ShareSync.runDetail))
        XCTAssertEqual(SyncWording.shareStatus(closed).text, SyncWording.text(SyncIssue("apply-failed")))
        // A store that changed meanwhile stays `busy` (information: the next run tries again).
        let busy = ShareSync.runIssue(SyncIssue("busy", "store-changed: the vault changed"))
        XCTAssertEqual(busy.kind, "busy")
        XCTAssertEqual(SyncWording.shareStatus(busy).severity, .notice)
    }

    func test_a_share_status_is_its_most_important_issue() {
        XCTAssertNil(SyncWording.shareStatus([SyncIssue]()))
        let shown = SyncWording.shareStatus([SyncIssue("keyring-merged"), SyncIssue("folder-missing"), SyncIssue("tampered"),
                                             SyncIssue("superseded")])
        XCTAssertEqual(shown?.kind, "tampered")
        XCTAssertEqual(SyncWording.shareStatus([SyncIssue("keyring-merged"), SyncIssue("superseded"), SyncIssue("folder-missing")])?.kind,
                       "superseded")
        XCTAssertEqual(SyncWording.shareStatus([SyncIssue("keyring-merged")])?.severity, .notice)
    }
}
