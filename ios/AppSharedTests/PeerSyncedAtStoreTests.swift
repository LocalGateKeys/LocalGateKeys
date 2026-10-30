import XCTest
import LGKCore
@testable import AppShared

/// Workstream 6: the per-device last-synced times are stored with the sync state (desktop `peer_synced_at`),
/// written only when not empty, absent in older states and validated like the desktop.
final class PeerSyncedAtStoreTests: XCTestCase {
    func state() throws -> SyncGroupState {
        SyncGroupState(groupID: "grp", epoch: 2, key: Array(repeating: 7, count: 32),
                       identity: try DeviceIdentity.generate(deviceID: "phone-1", random: FixedRandom()),
                       installID: "inst", members: ["desk", "phone-1"])
    }

    func test_round_trip_only_when_set_and_old_states_decode() throws {
        let plain = try state()
        guard case .object(let p) = LocalStore.encodeSync(plain) else { return XCTFail() }
        XCTAssertNil(p["peer_synced_at"])   // the default is not written
        XCTAssertEqual(try LocalStore.decodeSync(.object(p)), plain)

        let synced = plain.synced(with: ["desk"], now: 1_700_000_000)
        guard case .object(var o) = LocalStore.encodeSync(synced) else { return XCTFail() }
        XCTAssertEqual(o["peer_synced_at"], .object(["desk": .int(1_700_000_000)]))
        XCTAssertEqual(try LocalStore.decodeSync(.object(o)), synced)

        o["peer_synced_at"] = .object(["desk": .int(-1)])
        XCTAssertThrowsError(try LocalStore.decodeSync(.object(o))) { XCTAssertEqual($0 as? LocalStoreError, .corrupt("peer_synced_at")) }
        o["peer_synced_at"] = .string("x")
        XCTAssertThrowsError(try LocalStore.decodeSync(.object(o)))
    }
}
