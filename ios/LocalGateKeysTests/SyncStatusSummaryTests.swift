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
        XCTAssertEqual(s.devices[0].name, "Desk PC")
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
}
