import XCTest
import AppShared
@testable import LocalGateKeys

/// A scripted Bonjour browse: returns `found` (filtered by `wanted`, like the real browser) and counts calls.
final class FakeServiceBrowser: ServiceBrowsing, @unchecked Sendable {
    private let lock = NSLock()
    var found: [Discovery.Announcement]
    var error: Error?
    private(set) var browses = 0
    private(set) var lastSeconds: TimeInterval = 0
    init(_ found: [Discovery.Announcement] = []) { self.found = found }

    func browse(serviceType: String, seconds: TimeInterval,
                wanted: @escaping @Sendable ([String: String]) -> Bool) async throws -> [Discovery.Announcement] {
        XCTAssertEqual(serviceType, "_lgksync._tcp")
        lock.withLock { browses += 1; lastSeconds = seconds }
        if let error { throw error }
        return found.filter { wanted($0.txt) }
    }
}

/// Records each attempted peer address and answers from a per-host script.
final class ScriptedAttempts: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var hosts: [String] = []
    var outcome: [String: Error] = [:]
    var answers: Set<String> = []

    func attempt(_ peer: PinnedPeer) async throws -> [ItemState] {
        let host = peer.endpoint?.host ?? ""
        lock.withLock { hosts.append(host) }
        if answers.contains(host) { return [] }
        throw outcome[host] ?? LanPeerNotAnswering("refused")
    }
}

final class HostFinderTests: XCTestCase {
    let now: Int64 = 1_790_003_600
    let hostID = "a1111111-0000-4000-8000-00000000000a"
    var groupKey: GroupKey!
    var peer: PinnedPeer!

    override func setUpWithError() throws {
        groupKey = try SyncVectors.lanGroupKey()
        peer = PinnedPeer(deviceID: hostID, groupID: groupKey.groupID, signingPublic: [UInt8](repeating: 1, count: 32),
                          exchangePublic: [UInt8](repeating: 2, count: 32),
                          endpoint: try LanEndpoint(validating: "192.168.1.20", port: 47821))
    }

    func announce(_ host: String, port: Int = 47821, day: Int64 = 0, tag: String? = nil) -> Discovery.Announcement {
        let t = tag ?? Discovery.tag(groupKey, hostDeviceID: hostID, day: Discovery.utcDay(now - day * 86_400))
        return Discovery.Announcement(host: host, port: port, txt: ["v": "1", "t": t])
    }

    func run(_ browser: FakeServiceBrowser?, _ attempts: ScriptedAttempts) async throws -> HostFinder.Result {
        try await HostFinder.exchange(peer: peer, groupKey: groupKey, now: now, browser: browser, browseSeconds: 0) {
            try await attempts.attempt($0)
        }
    }

    func test_pinned_answers_no_browse() async throws {
        let browser = FakeServiceBrowser([announce("192.168.1.30")])
        let attempts = ScriptedAttempts(); attempts.answers = ["192.168.1.20"]
        let r = try await run(browser, attempts)
        XCTAssertNil(r.moved)
        XCTAssertEqual(browser.browses, 0)
        XCTAssertEqual(attempts.hosts, ["192.168.1.20"])
    }

    func test_pinned_fails_matching_announcement_is_dialled_and_reported() async throws {
        let browser = FakeServiceBrowser([announce("192.168.1.30", day: 1)])   // yesterday's tag still matches
        let attempts = ScriptedAttempts(); attempts.answers = ["192.168.1.30"]
        let r = try await run(browser, attempts)
        XCTAssertEqual(r.moved, try LanEndpoint(validating: "192.168.1.30", port: 47821))
        XCTAssertEqual(attempts.hosts, ["192.168.1.20", "192.168.1.30"])
        XCTAssertEqual(HostFinder.browseSeconds, 3)
    }

    func test_wrong_tag_and_non_lan_never_dialled() async throws {
        let browser = FakeServiceBrowser([announce("192.168.1.31", tag: "aaaaaaaaaaaaaaaa"), announce("192.168.1.32", day: 2),
                                          announce("8.8.8.8"), announce("127.0.0.1"), announce("169.254.3.4")])
        let attempts = ScriptedAttempts()
        do { _ = try await run(browser, attempts); XCTFail("expected the pinned failure") } catch is LanPeerNotAnswering {}
        XCTAssertEqual(attempts.hosts, ["192.168.1.20"])
    }

    func test_wrong_key_and_version_refusal_skip_other_errors_stop() async throws {
        let browser = FakeServiceBrowser([announce("192.168.1.33"), announce("192.168.1.34"), announce("192.168.1.35")])
        let attempts = ScriptedAttempts()
        attempts.outcome = ["192.168.1.33": LanTransportError.authentication("Session peer is not the expected paired device"),
                            "192.168.1.34": LanSyncError("peer-update-needed")]
        attempts.answers = ["192.168.1.35"]
        let r = try await run(browser, attempts)
        XCTAssertEqual(r.moved?.host, "192.168.1.35")
        XCTAssertEqual(attempts.hosts, ["192.168.1.20", "192.168.1.33", "192.168.1.34", "192.168.1.35"])

        // A signed refusal from the paired host (another group, say) stops the run.
        let stop = ScriptedAttempts(); stop.outcome = ["192.168.1.33": LanSyncError("group-mismatch")]
        do { _ = try await run(browser, stop); XCTFail() } catch let e as LanSyncError { XCTAssertEqual(e.reason, "group-mismatch") }
        XCTAssertEqual(stop.hosts, ["192.168.1.20", "192.168.1.33"])
    }

    func test_cap_of_four_and_pinned_not_redialled() async throws {
        let browser = FakeServiceBrowser([announce("192.168.1.20")] + (40..<48).map { announce("192.168.1.\($0)") })
        let attempts = ScriptedAttempts()
        do { _ = try await run(browser, attempts); XCTFail() } catch is LanPeerNotAnswering {}
        XCTAssertEqual(attempts.hosts, ["192.168.1.20", "192.168.1.40", "192.168.1.41", "192.168.1.42", "192.168.1.43"])
    }

    func test_no_browser_or_failed_browse_keeps_the_pinned_failure() async throws {
        let attempts = ScriptedAttempts()
        do { _ = try await run(nil, attempts); XCTFail() } catch is LanPeerNotAnswering {}
        let broken = FakeServiceBrowser(); broken.error = LanSocketError("browse failed")
        do { _ = try await run(broken, attempts); XCTFail() } catch is LanPeerNotAnswering {}
        // A refusal that is not "not answering" (a signed one from the pinned host) never browses.
        let browser = FakeServiceBrowser([announce("192.168.1.30")])
        let signed = ScriptedAttempts(); signed.outcome = ["192.168.1.20": LanSyncError("epoch-behind")]
        do { _ = try await run(browser, signed); XCTFail() } catch is LanSyncError {}
        XCTAssertEqual(browser.browses, 0)
    }
}

extension SyncCoordinatorTests {
    func test_lan_moved_host_address_is_stored_for_the_paired_peer() async throws {
        let store = LockedStore()
        let c = try await qrJoined(store)
        let before = try XCTUnwrap(try keychain.pairedPeer())
        let moved = try LanEndpoint(validating: "192.168.1.77", port: before.endpoint?.port ?? 47821)
        lan.movedTo = moved
        await c.sync(.manual)
        let after = try XCTUnwrap(try keychain.pairedPeer())
        XCTAssertEqual(after.endpoint, moved)
        XCTAssertEqual(after.deviceID, before.deviceID)
        XCTAssertEqual(after.signingPublic, before.signingPublic)
        XCTAssertEqual(after.exchangePublic, before.exchangePublic)

        // A failed exchange stores nothing.
        lan.movedTo = try LanEndpoint(validating: "192.168.1.78", port: moved.port)
        lan.exchange = { _ in throw LanSocketError("read timed out") }
        await c.sync(.manual)
        XCTAssertEqual(try keychain.pairedPeer()?.endpoint, moved)
    }
}
