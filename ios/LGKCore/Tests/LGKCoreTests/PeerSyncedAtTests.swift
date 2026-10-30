import XCTest
@testable import LGKCore

/// Workstream 6: per-peer last sync times (desktop `peer_synced_at`, Android `PeerSyncedAtTest`), local only,
/// updated only for accepted changes.
final class PeerSyncedAtTests: XCTestCase {
    func state() throws -> SyncGroupState {
        SyncGroupState(groupID: String(repeating: "g", count: 32), epoch: 1, key: [UInt8](repeating: 0, count: 32),
                       identity: try DeviceIdentity.generate(deviceID: "self-device", random: SystemRandomSource()),
                       installID: "install")
    }

    func test_accepted_peers_get_the_time() throws {
        let base = try state()
        XCTAssertEqual(base.peerSyncedAt, [:])
        let s = base.synced(with: ["a", "b"], now: 100).synced(with: ["b"], now: 200)
        XCTAssertEqual(s.peerSyncedAt, ["a": 100, "b": 200])
        XCTAssertEqual(s.synced(with: [String](), now: 300), s)
    }

    func test_own_id_is_never_recorded() throws {
        let base = try state()
        XCTAssertEqual(base.synced(with: ["self-device"], now: 5), base)
        XCTAssertEqual(base.synced(with: ["self-device", "x"], now: 5).peerSyncedAt, ["x": 5])
    }

    func test_times_are_clamped() throws {
        let s = try state().synced(with: ["a"], now: -4).synced(with: ["b"], now: .max)
        XCTAssertEqual(s.peerSyncedAt, ["a": 0, "b": SyncGroupState.maxSyncedAtValue])
    }

    func test_keeps_the_most_recent_peers() throws {
        let s = try state().synced(with: (1...5).map { "p\($0)" }, now: 10).synced(with: ["new"], now: 20)
        XCTAssertEqual(Set(s.peerSyncedAt.keys), ["p1", "p2", "p3", "p4", "p5", "new"])
        let capped = try state().synced(with: ["old"], now: 1).synced(with: ["x", "y"], now: 5, limit: 2)
        XCTAssertEqual(Set(capped.peerSyncedAt.keys), ["x", "y"])
    }
}
