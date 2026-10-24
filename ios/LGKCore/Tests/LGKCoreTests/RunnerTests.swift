import XCTest
@testable import LGKCore

final class RunnerTests: XCTestCase {
    static let phone = RecordsTests.phone
    let now = EngineTests.T0 + 1000

    func views() throws -> [PeerView] {
        try GroupTests.devices.map { d in
            PeerView(deviceID: d.id, states: try ViewFile.decode(Array(Vectors.data("devices/\(d.name).lgksync")),
                                                                 key: KeyringTests.epochKey("1"), expectedDeviceID: d.id).states)
        }
    }

    func test_run_folds_and_applies_ABC() throws {
        let r = SyncRunner.run(store: StoreSnapshot(), views: try views(), device: Self.phone, now: now)
        XCTAssertEqual(r.issues, [])
        let want = try MergeVectors.arr(MergeVectors.expectedMerge()["bridge_stored_states"]).map(MergeVectors.state)
        XCTAssertEqual(r.ownStates, want)
        XCTAssertEqual(r.conflicts > 0, true)
        XCTAssertEqual(r.records?.count, want.filter { !$0.deleted }.count)
        // Pure: running again over the result changes nothing.
        let again = SyncRunner.run(store: StoreSnapshot(records: r.records!, meta: r.meta!), views: try views(),
                                   device: Self.phone, now: now)
        XCTAssertEqual(again.records, r.records)
        XCTAssertEqual(again.meta, r.meta)
        XCTAssertEqual(again.applied, 0)
    }

    func test_bad_and_newer_records_are_quarantined_not_the_view() throws {
        var vs = try views()
        let b = vs[1]
        var states = b.states
        // A newer schema on one record and a malformed wrapper on another.
        let i = states.firstIndex { $0.itemID == EngineTests.NOTE_UNICODE }!
        var w = MergeVectors.obj(states[i].item); w["schema"] = .int(2)
        states[i] = try ItemState(itemID: states[i].itemID, vv: states[i].vv, deleted: false, deletedAt: nil, item: .object(w))
        let j = states.firstIndex { $0.itemID == EngineTests.DESKTOP }!
        var w2 = MergeVectors.obj(states[j].item); w2["extra"] = .int(1)
        // DESKTOP is identical in every view, so put the bad copy under a new id only B has.
        var rec = MergeVectors.obj(w2["record"]); rec["id"] = .string("99999999-aaaa-4000-8000-000000000009"); w2["record"] = .object(rec)
        states.append(try ItemState(itemID: "99999999-aaaa-4000-8000-000000000009", vv: [EngineTests.B: 1], deleted: false,
                                    deletedAt: nil, item: .object(w2)))
        vs[1] = PeerView(deviceID: b.deviceID, states: states)
        let r = SyncRunner.run(store: StoreSnapshot(), views: vs, device: Self.phone, now: now)
        XCTAssertEqual(Set(r.issues), Set([SyncIssue("update-needed", "\(EngineTests.B):\(EngineTests.NOTE_UNICODE)"),
                                           SyncIssue("bad-peer-record", "\(EngineTests.B):99999999-aaaa-4000-8000-000000000009")]))
        XCTAssertNil(r.records?[EngineTests.NOTE_UNICODE])
        XCTAssertNil(r.records?["99999999-aaaa-4000-8000-000000000009"])
        XCTAssertNotNil(r.records?[EngineTests.BOOKMARK])
    }

    func test_licences_received_are_reported() throws {
        guard case .object(let o) = try CanonicalJSON.parse(Array(Vectors.data("license_state.json"))) else { return XCTFail() }
        let keys = [MergeVectors.str(o["key_id"])!: try Base64.decodeStrict(MergeVectors.str(o["public_key_b64"])!)]
        let sid = MergeVectors.str(o["state_id"])!
        let lic = try ItemState(itemID: sid, vv: [EngineTests.A: 1], deleted: false, deletedAt: nil, item: o["wrapper"]!)
        let view = PeerView(deviceID: EngineTests.A, states: [lic])
        let r = SyncRunner.run(store: StoreSnapshot(), views: [view], device: Self.phone, now: now, licenseKeys: keys)
        XCTAssertEqual(r.issues, [])
        XCTAssertEqual(r.licenses, [MergeVectors.obj(o["wrapper"])["record"]!])
        XCTAssertEqual(r.ownStates?.map(\.itemID), [sid])  // republished by the receiver
        // Without licence keys the licence is dropped without a report.
        let none = SyncRunner.run(store: StoreSnapshot(), views: [view], device: Self.phone, now: now)
        XCTAssertEqual(none.issues, [])
        XCTAssertEqual(none.licenses, [])
        XCTAssertEqual(none.records, [:])
    }

    func test_bad_view_and_local_data() throws {
        let dup = try ItemState(itemID: EngineTests.NOTE, vv: [EngineTests.A: 1], deleted: true, deletedAt: 1, item: nil)
        let r = SyncRunner.run(store: StoreSnapshot(), views: [PeerView(deviceID: EngineTests.A, states: [dup, dup])],
                               device: Self.phone, now: now)
        XCTAssertEqual(r.issues, [SyncIssue("bad-peer-data", EngineTests.A)])
        let bad = SyncRunner.run(store: StoreSnapshot(), views: [], device: "not valid!", now: now)
        XCTAssertEqual(bad.issues.map(\.kind), ["local-data"])
        XCTAssertNil(bad.ownStates)
    }
}
