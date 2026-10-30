import XCTest
import Foundation
@testable import LGKCore

/// Rollback witnesses (plan 2026-10-22 Part B, update 2026-10-29): view format 2, the witness rule, witness files,
/// the LAN `witness` message and the folder wiring. Mirrors `tests/test_sync_witness.py`,
/// `tests/test_sync_rollback_ack.py` and the witness cases of `tests/test_sync_folder_transport.py`; the vectors are
/// `tests/vectors/sync/witness/` (read only, never rewritten here).
final class WitnessTests: XCTestCase {
    static let A = EngineTests.A, B = EngineTests.B
    static let C = EngineTests.C
    static let T0 = EngineTests.T0

    func cases() throws -> [String: Any] { try Vectors.json("witness/cases.json") }
    func key() throws -> GroupKey { try FolderSyncTests.epoch1() }
    func i64(_ v: Any?) -> Int64? { (v as? NSNumber)?.int64Value }
    func gens(_ v: Any?) -> [String: Int64] {
        ((v as? [String: Any]) ?? [:]).reduce(into: [:]) { out, kv in out[kv.key] = i64(kv.value) }
    }
    func bytes(_ b64: Any?) throws -> [UInt8] {
        Array(try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(b64 as? String))))
    }

    // MARK: vectors

    func test_header_vectors_decode_as_expected() throws {
        let gk = try key()
        for c in try XCTUnwrap(try cases()["headers"] as? [[String: Any]]) {
            let name = c["name"] as? String ?? "?"
            let raw = try bytes(c["file_b64"])
            let got: String
            do { _ = try ViewFile.decode(raw, key: gk, expectedDeviceID: nil); got = "valid" } catch {
                got = (error as? SyncFormatError)?.reason ?? "\(error)"
            }
            XCTAssertEqual(got, c["expected"] as? String, name)
        }
    }

    func test_witness_file_match_vectors() throws {
        let gk = try key()
        let view = try ViewFile.decode(Array(try Vectors.data("devices/A.lgksync")), key: gk, expectedDeviceID: Self.A)
        for c in try XCTUnwrap(try cases()["witness_file_matches"] as? [[String: Any]]) {
            let name = c["name"] as? String ?? "?"
            let file = try ViewFile.decode(try bytes(c["witness_file_b64"]), key: gk, expectedDeviceID: nil)
            let got = Witness.observation(view.header, witnessFile: (header: file.header, records: file.states.count))
            if let want = c["expected"] as? [String: Any] {
                XCTAssertEqual(got, WitnessObservation(peerID: want["peer_id"] as! String,
                                                       vaultGeneration: i64(want["vault_generation"])!,
                                                       witness: gens(want["witness"])), name)
            } else {
                XCTAssertNil(got, name)
            }
        }
    }

    func test_check_vectors() throws {
        for c in try XCTUnwrap(try cases()["checks"] as? [[String: Any]]) {
            let name = c["name"] as? String ?? "?"
            let obs = ((c["observations"] as? [[String: Any]]) ?? []).map {
                WitnessObservation(peerID: $0["peer_id"] as! String, vaultGeneration: i64($0["vault_generation"])!,
                                   witness: gens($0["witness"]))
            }
            let r = Witness.check(ownID: c["own_id"] as! String, ownGeneration: i64(c["own_generation"])!,
                                  observations: obs, peerGenerations: gens(c["peer_generations"]),
                                  rollbackSuspected: i64(c["rollback_suspected"])!)
            let want = try XCTUnwrap(c["expected"] as? [String: Any])
            let issues = ((want["issues"] as? [[String]]) ?? []).map { SyncIssue($0[0], $0[1]) }
            XCTAssertEqual(r.issues, issues, name)
            XCTAssertEqual(r.peerGenerations, gens(want["peer_generations"]), name)
            XCTAssertEqual(r.rollbackSuspected, i64(want["rollback_suspected"]), name)
            XCTAssertEqual(r.capable, Set((want["capable"] as? [String]) ?? []), name)
        }
    }

    func test_constants_match_the_desktop() throws {
        let k = try XCTUnwrap(try cases()["constants"] as? [String: Any])
        XCTAssertEqual(i64(k["FORMAT_WITNESS"]), ViewFile.formatWitness)
        XCTAssertEqual(i64(k["MAX_WITNESS"]), Int64(ViewFile.maxWitness))
        XCTAssertEqual(i64(k["MAX_WITNESS_BYTES"]), Int64(Witness.maxWitnessBytes))
    }

    func test_devices_v2_carry_the_same_states_and_their_generations() throws {
        let gk = try key()
        let want: [String: (Int64, [String: Int64])] = ["A": (40, [Self.B: 12]), "B": (12, [Self.A: 40]), "C": (9, [:])]
        for d in GroupTests.devices {
            let v1 = try ViewFile.decode(Array(try Vectors.data("devices/\(d.name).lgksync")), key: gk, expectedDeviceID: d.id)
            let v2 = try ViewFile.decode(Array(try Vectors.data("witness/devices_v2/\(d.name).lgksync")), key: gk,
                                         expectedDeviceID: d.id)
            XCTAssertEqual(v1.header.format, 1)
            XCTAssertNil(v1.header.vaultGeneration)
            XCTAssertEqual(v1.header.witness, [:])
            XCTAssertEqual(v2.header.format, 2)
            XCTAssertEqual(v2.states, v1.states, d.name)
            XCTAssertEqual(v2.header.counter, v1.header.counter)
            XCTAssertEqual(v2.header.vaultGeneration, want[d.name]!.0, d.name)
            XCTAssertEqual(v2.header.witness, want[d.name]!.1, d.name)
        }
    }

    func test_sidecar_verifies_with_A_and_matches_A_view() throws {
        let gk = try key()
        let raw = Array(try Vectors.data("witness/sidecar/A.lgksync"))
        let file = try ViewFile.decode(raw, key: gk, expectedDeviceID: Self.A, maxBytes: Witness.maxWitnessBytes, maxRecords: 0)
        let signer = try ViewSignature.verify(Array(try Vectors.data("witness/sidecar/A.lgksig")), raw: raw, header: file.header)
        XCTAssertEqual(signer, try KeyringTests.identity("A").signingPublicKey)
        let view = try ViewFile.decode(Array(try Vectors.data("devices/A.lgksync")), key: gk, expectedDeviceID: Self.A)
        XCTAssertEqual(Witness.observation(view.header, witnessFile: (header: file.header, records: 0)),
                       WitnessObservation(peerID: Self.A, vaultGeneration: 40, witness: [Self.B: 12, Self.C: 9]))
    }

    func test_lan_witness_message_vector() throws {
        let msg = try LanMessages.parse(Array(try Vectors.data("witness/lan_witness_A.bin")))
        guard case let .witness(group, epoch, view) = msg else { return XCTFail("not a witness message") }
        XCTAssertEqual(group, GroupTests.groupID)
        XCTAssertEqual(epoch, 1)
        let file = try ViewFile.decode(try Base64.decodeStrict(view), key: try key(), expectedDeviceID: Self.A,
                                       maxBytes: Witness.maxWitnessBytes, maxRecords: 0)
        XCTAssertEqual(file.header.counter, 0)
        XCTAssertEqual(file.header.vaultGeneration, 40)
        XCTAssertEqual(file.header.witness, [Self.B: 12])
        // Re-encoding the parsed message gives the same canonical bytes.
        XCTAssertEqual(try LanMessages.encode(msg), Array(try Vectors.data("witness/lan_witness_A.bin")))
    }

    func test_lan_witness_message_shape() throws {
        func reason(_ s: String) -> String? {
            do { _ = try LanMessages.parse(Array(s.utf8)); return nil } catch { return (error as? LanSyncError)?.reason }
        }
        XCTAssertEqual(reason(#"{"epoch":1,"group_id":"g","type":"witness"}"#), "bad-message")
        XCTAssertEqual(reason(#"{"epoch":0,"group_id":"g","type":"witness","view":""}"#), "bad-message")
        let long = String(repeating: "A", count: 4 * ((Witness.maxWitnessBytes + 2) / 3) + 4)
        XCTAssertEqual(reason(#"{"epoch":1,"group_id":"g","type":"witness","view":"\#(long)"}"#), "too-large")
    }

    // MARK: format 2 encode / decode (desktop test_sync_group format-2 cases)

    func test_v2_header_round_trips_generation_and_witness() throws {
        let gk = try key()
        let raw = try ViewFile.encode(key: gk, deviceID: Self.A, counter: 3, states: [], now: FixedClock(now: Self.T0),
                                      random: DetRand("v2"), vaultGeneration: 41, witness: [Self.B: 7])
        let v = try ViewFile.decode(raw, key: gk, expectedDeviceID: Self.A)
        XCTAssertEqual(v.header.format, 2)
        XCTAssertEqual(v.header.vaultGeneration, 41)
        XCTAssertEqual(v.header.witness, [Self.B: 7])
        // Without a generation the bytes stay format 1.
        let v1 = try ViewFile.decode(try ViewFile.encode(key: gk, deviceID: Self.A, counter: 3, states: [],
                                                         now: FixedClock(now: Self.T0), random: DetRand("v1")),
                                     key: gk, expectedDeviceID: Self.A)
        XCTAssertEqual(v1.header.format, 1)
        XCTAssertNil(v1.header.vaultGeneration)
    }

    func test_v2_encoder_rejects_bad_witness() throws {
        let gk = try key()
        func reason(_ gen: Int64?, _ w: [String: Int64]?) -> String? {
            do {
                _ = try ViewFile.encode(key: gk, deviceID: Self.A, counter: 1, states: [], now: FixedClock(now: Self.T0),
                                        random: DetRand("bad"), vaultGeneration: gen, witness: w)
                return nil
            } catch { return (error as? SyncFormatError)?.reason }
        }
        XCTAssertEqual(reason(nil, [:]), "bad-header")
        XCTAssertEqual(reason(1, [Self.A: 1]), "bad-header")
        XCTAssertEqual(reason(1, ["bad id": 1]), "bad-header")
        XCTAssertEqual(reason(1, [Self.B: -1]), "bad-header")
        XCTAssertEqual(reason(1 << 53, [:]), "bad-header")
        var many: [String: Int64] = [:]
        for i in 0..<65 { many[String(format: "peer-%03d", i)] = 1 }
        XCTAssertEqual(reason(1, many), "bad-header")
    }

    // MARK: the rule (desktop test_sync_witness.py)

    func test_peer_going_backwards_is_reported_and_not_forgotten() {
        let r = Witness.check(ownID: Self.A, ownGeneration: 10,
                              observations: [WitnessObservation(peerID: Self.B, vaultGeneration: 30)],
                              peerGenerations: [Self.B: 50], rollbackSuspected: 0)
        XCTAssertEqual(r.issues, [SyncIssue("peer-vault-rollback", Self.B)])
        XCTAssertEqual(r.peerGenerations, [Self.B: 50])
    }

    func test_rollback_issue_is_sticky_until_acknowledged() {
        let r = Witness.check(ownID: Self.A, ownGeneration: 99, observations: [], peerGenerations: [:], rollbackSuspected: 50)
        XCTAssertEqual(r.issues, [SyncIssue("vault-rollback")])
        XCTAssertEqual(r.rollbackSuspected, 50)
    }

    func test_implausible_witness_is_reported_and_never_stored() {
        let far = WitnessObservation(peerID: Self.B, vaultGeneration: 1, witness: [Self.A: 10 + Witness.maxWitnessJump + 1])
        let r = Witness.check(ownID: Self.A, ownGeneration: 10, observations: [far], peerGenerations: [:], rollbackSuspected: 0)
        XCTAssertEqual(r.issues, [SyncIssue("witness-implausible", Self.B)])
        XCTAssertEqual(r.rollbackSuspected, 0)
        let edge = WitnessObservation(peerID: Self.B, vaultGeneration: 1, witness: [Self.A: 10 + Witness.maxWitnessJump])
        let e = Witness.check(ownID: Self.A, ownGeneration: 10, observations: [edge], peerGenerations: [:], rollbackSuspected: 0)
        XCTAssertEqual(e.rollbackSuspected, 10 + Witness.maxWitnessJump)
        // Not sticky: the next run without it reports nothing.
        XCTAssertEqual(Witness.check(ownID: Self.A, ownGeneration: 10, observations: [], peerGenerations: r.peerGenerations,
                                     rollbackSuspected: r.rollbackSuspected).issues, [])
    }

    func test_own_witness_drops_removed_members_and_caps_at_64() {
        var gens: [String: Int64] = [Self.A: 5, "gone": 3]
        for i in 0..<70 { gens[String(format: "peer-%03d", i)] = Int64(i) }
        let members = Set(gens.keys).subtracting(["gone"])
        let w = Witness.ownWitness(gens, members: members, ownID: Self.A)
        XCTAssertEqual(w.count, 64)
        XCTAssertNil(w[Self.A]); XCTAssertNil(w["gone"])
        XCTAssertEqual(w.keys.sorted().first, "peer-000")
    }

    // MARK: memory, save throttle and flush (desktop witness_memory / apply_witness / flush_witness)

    final class Clock: @unchecked Sendable {
        var t: Double = 1000
    }

    func lanStore(_ peers: [String] = [EngineTests.B]) throws -> MemoryStore {
        let identity = try KeyringTests.identity("A")
        let gk = try key()
        let state = SyncGroupState(groupID: gk.groupID, epoch: gk.epoch, key: gk.key, identity: identity,
                                   installID: FolderSyncTests.install, hasFolder: false, members: [identity.deviceID] + peers)
        return MemoryStore(StoreSnapshot(sync: state, revision: 20))
    }

    func test_apply_saves_new_peer_then_throttles_rises_and_flush_saves_them() throws {
        let store = try lanStore()
        let clock = Clock()
        let memory = WitnessMemory(now: { clock.t })
        XCTAssertEqual(Witness.apply(store: store, observations: [WitnessObservation(peerID: Self.B, vaultGeneration: 5)],
                                     memory: memory), [])
        XCTAssertEqual(store.commits, 1)   // a new peer and a new capability: saved at once
        XCTAssertEqual(store.snapshot.sync?.peerGenerations, [Self.B: 5])
        XCTAssertEqual(store.snapshot.sync?.witnessPeers, [Self.B])
        clock.t += 10
        _ = Witness.apply(store: store, observations: [WitnessObservation(peerID: Self.B, vaultGeneration: 6)], memory: memory)
        XCTAssertEqual(store.commits, 1)   // a rise within 10 minutes: kept in memory only
        XCTAssertEqual(store.snapshot.sync?.peerGenerations, [Self.B: 5])
        // The memory is what every check uses: a peer going back below the unsaved value is caught.
        XCTAssertEqual(Witness.apply(store: store, observations: [WitnessObservation(peerID: Self.B, vaultGeneration: 5)],
                                     memory: memory), [SyncIssue("peer-vault-rollback", Self.B)])
        XCTAssertTrue(Witness.flush(store: store, memory: memory))
        XCTAssertEqual(store.snapshot.sync?.peerGenerations, [Self.B: 6])
        XCTAssertFalse(Witness.flush(store: store, memory: memory))   // nothing above the stored value
        clock.t += Witness.saveIntervalSeconds
        _ = Witness.apply(store: store, observations: [WitnessObservation(peerID: Self.B, vaultGeneration: 7)], memory: memory)
        XCTAssertEqual(store.snapshot.sync?.peerGenerations, [Self.B: 7])   // due again: saved
    }

    func test_apply_saves_a_new_suspicion_at_once_and_drop_capable_removes_the_peer() throws {
        let store = try lanStore()
        let memory = WitnessMemory(now: { 0 })
        let issues = Witness.apply(store: store, observations: [
            WitnessObservation(peerID: Self.B, vaultGeneration: 3, witness: [Self.A: 60]),
        ], memory: memory)
        XCTAssertEqual(issues, [SyncIssue("vault-rollback")])
        XCTAssertEqual(store.snapshot.sync?.rollbackSuspected, 60)
        _ = Witness.apply(store: store, observations: [], memory: memory, dropCapable: Self.B)
        XCTAssertEqual(store.snapshot.sync?.witnessPeers, [])
    }

    // MARK: acknowledgement (desktop test_sync_rollback_ack.py)

    func test_acknowledge_raises_generation_above_witness_and_clears_issue() throws {
        let store = try lanStore()
        store.snapshot.sync?.rollbackSuspected = 50
        XCTAssertEqual(Witness.generation(store.snapshot), 20)
        XCTAssertTrue(try Witness.acknowledgeRollback(store: store))
        let state = try XCTUnwrap(store.snapshot.sync)
        XCTAssertEqual(state.rollbackSuspected, 0)
        XCTAssertGreaterThan(try XCTUnwrap(Witness.generation(store.snapshot)), 50)
        XCTAssertEqual(Witness.check(ownID: Self.A, ownGeneration: Witness.generation(store.snapshot)!,
                                     observations: [WitnessObservation(peerID: Self.B, vaultGeneration: 1, witness: [Self.A: 50])],
                                     peerGenerations: [:], rollbackSuspected: state.rollbackSuspected).issues, [])
        // Nothing suspected: nothing written.
        let commits = store.commits
        XCTAssertFalse(try Witness.acknowledgeRollback(store: store))
        XCTAssertEqual(store.commits, commits)
    }

    func test_forget_peer_generation_accepts_its_older_copy() throws {
        let store = try lanStore()
        store.snapshot.sync?.peerGenerations = [Self.B: 50]
        let memory = WitnessMemory(now: { 0 })
        XCTAssertTrue(try Witness.forgetPeerGeneration(store: store, peerID: Self.B, memory: memory))
        XCTAssertEqual(store.snapshot.sync?.peerGenerations, [:])
        XCTAssertEqual(Witness.apply(store: store, observations: [WitnessObservation(peerID: Self.B, vaultGeneration: 30)],
                                     memory: memory), [])
        XCTAssertFalse(try Witness.forgetPeerGeneration(store: store, peerID: "unknown"))
    }

    // MARK: folder (desktop test_sync_folder_transport witness cases)

    /// Writes vector device `who`'s view (its vector states) at `counter`, signed by it; with `generation` either
    /// inline (format 2) or as a format-1 view plus a signed witness file (`sidecar`), or plain format 1.
    func writePeer(_ folder: MemoryFolder, _ who: String, counter: Int64, generation: Int64?, witness: [String: Int64] = [:],
                   inline: Bool = false, sidecar: Bool = true) throws {
        let gk = try key()
        let identity = try KeyringTests.identity(who)
        let states = try ViewFile.decode(Array(try Vectors.data("devices/\(who).lgksync")), key: gk,
                                         expectedDeviceID: identity.deviceID).states
        let clock = FixedClock(now: Self.T0 + 950)
        let raw = try ViewFile.encode(key: gk, deviceID: identity.deviceID, counter: counter, states: states, now: clock,
                                      random: DetRand("peer|\(who)|\(counter)"),
                                      vaultGeneration: inline ? generation : nil, witness: inline ? witness : nil)
        folder.files[FolderSyncTests.devPath(identity.deviceID)] = raw
        folder.files[FolderLayout.signatureFile(identity.deviceID)!] =
            try ViewSignature.sign(raw, header: try ViewFile.decodeHeader(raw), identity: identity)
        folder.files[FolderLayout.witnessFile(identity.deviceID)!] = nil
        folder.files[FolderLayout.witnessSignatureFile(identity.deviceID)!] = nil
        if let generation, !inline, sidecar {
            let side = try ViewFile.encode(key: gk, deviceID: identity.deviceID, counter: counter, states: [], now: clock,
                                           random: DetRand("side|\(who)|\(counter)"), vaultGeneration: generation,
                                           witness: witness)
            folder.files[FolderLayout.witnessFile(identity.deviceID)!] = side
            folder.files[FolderLayout.witnessSignatureFile(identity.deviceID)!] =
                try ViewSignature.sign(side, header: try ViewFile.decodeHeader(side), identity: identity)
        }
    }

    /// The phone joined to the seeded epoch-1 folder (as `FolderSyncTests.joined`, known password-wrap key).
    func joined(_ label: String) throws -> (MemoryFolder, MemoryStore) {
        let folder = try FolderSyncTests.seededFolder()
        let store = MemoryStore()
        let fs = try FolderSync(access: folder, installID: FolderSyncTests.install)
        let pw = try KeyringTests.pwKey("1")
        _ = try fs.join(store: store, deviceName: "iPhone", random: DetRand("t10|\(label)"),
                        clock: FixedClock(now: Self.T0 + 1000)) { _ in pw }
        return (folder, store)
    }

    func run(_ fs: FolderSync, _ store: MemoryStore, _ n: Int) -> RunReport {
        fs.runOnce(store: store, random: DetRand("run\(n)"), clock: FixedClock(now: Self.T0 + 1000 + Int64(n)))
    }

    func test_own_view_stays_format1_with_a_signed_witness_file_until_every_member_supports_format2() throws {
        let (folder, store) = try joined("w1")
        let me = try XCTUnwrap(store.snapshot.sync).identity
        let gk = try key()
        let view = try ViewFile.decode(try XCTUnwrap(folder.files[FolderSyncTests.devPath(me.deviceID)]), key: gk,
                                       expectedDeviceID: me.deviceID)
        XCTAssertEqual(view.header.format, 1)
        let side = try XCTUnwrap(folder.files[FolderLayout.witnessFile(me.deviceID)!])
        let file = try ViewFile.decode(side, key: gk, expectedDeviceID: me.deviceID, maxRecords: 0)
        XCTAssertEqual(try ViewSignature.verify(try XCTUnwrap(folder.files[FolderLayout.witnessSignatureFile(me.deviceID)!]),
                                                raw: side, header: file.header), me.signingPublicKey)
        XCTAssertNotNil(Witness.observation(view.header, witnessFile: (header: file.header, records: 0)))
        // A deleted witness file is written again on its own (same counter, no commit).
        folder.files[FolderLayout.witnessFile(me.deviceID)!] = nil
        let commits = store.commits
        let fs = try FolderSync(access: folder, installID: FolderSyncTests.install)
        _ = run(fs, store, 1)
        XCTAssertEqual(store.commits, commits)
        XCTAssertNotNil(folder.files[FolderLayout.witnessFile(me.deviceID)!])
        XCTAssertEqual(try ViewFile.decode(folder.files[FolderSyncTests.devPath(me.deviceID)]!, key: gk,
                                           expectedDeviceID: me.deviceID).header.counter, view.header.counter)
    }

    func test_restored_store_is_flagged_by_peer_witness_until_acknowledged() throws {
        let (folder, store) = try joined("w2")
        let me = try XCTUnwrap(store.snapshot.sync).deviceID
        let own = try XCTUnwrap(Witness.generation(store.snapshot))
        // B saw a newer copy of this phone than the one it holds now.
        try writePeer(folder, "B", counter: 5, generation: 12, witness: [me: own + 40])
        let fs = try FolderSync(access: folder, installID: FolderSyncTests.install)
        let first = run(fs, store, 1)
        XCTAssertTrue(first.issues.contains(SyncIssue("vault-rollback")))
        XCTAssertEqual(store.snapshot.sync?.rollbackSuspected, own + 40)
        XCTAssertTrue(store.snapshot.sync?.witnessPeers.contains(Self.B) ?? false)
        XCTAssertEqual(store.snapshot.sync?.peerGenerations[Self.B], 12)
        // Ordinary saves never clear it.
        XCTAssertTrue(run(fs, store, 2).issues.contains(SyncIssue("vault-rollback")))
        XCTAssertTrue(try Witness.acknowledgeRollback(store: store))
        XCTAssertFalse(run(fs, store, 3).issues.contains(SyncIssue("vault-rollback")))
    }

    func test_peer_going_back_is_reported_by_the_folder_run() throws {
        let (folder, store) = try joined("w3")
        let fs = try FolderSync(access: folder, installID: FolderSyncTests.install)
        try writePeer(folder, "B", counter: 5, generation: 50, inline: true)
        XCTAssertFalse(run(fs, store, 1).issues.contains(SyncIssue("peer-vault-rollback", Self.B)))
        try writePeer(folder, "B", counter: 6, generation: 30, inline: true)
        XCTAssertTrue(run(fs, store, 2).issues.contains(SyncIssue("peer-vault-rollback", Self.B)))
        XCTAssertEqual(store.snapshot.sync?.peerGenerations[Self.B], 50)
    }

    func test_missing_witness_of_a_witnessing_peer_is_reported_after_one_grace_run() throws {
        let (folder, store) = try joined("w4")
        let fs = try FolderSync(access: folder, installID: FolderSyncTests.install)
        try writePeer(folder, "B", counter: 5, generation: 12)
        XCTAssertFalse(run(fs, store, 1).issues.contains(SyncIssue("witness-missing", Self.B)))
        XCTAssertEqual(store.snapshot.sync?.witnessCounters[Self.B], 5)
        try writePeer(folder, "B", counter: 6, generation: 13, sidecar: false)
        XCTAssertFalse(run(fs, store, 2).issues.contains(SyncIssue("witness-missing", Self.B)))   // grace
        XCTAssertTrue(run(fs, store, 3).issues.contains(SyncIssue("witness-missing", Self.B)))
    }

    func test_epoch_reset_clears_witness_counters_but_keeps_generations() throws {
        var s = SyncGroupState(groupID: "g", epoch: 1, key: [UInt8](repeating: 1, count: 32),
                               identity: try KeyringTests.identity("A"), installID: "i",
                               peerGenerations: [Self.B: 3], rollbackSuspected: 4, witnessPeers: [Self.B],
                               witnessCounters: [Self.B: 9])
        s = FolderSync.epochReset(s)
        XCTAssertEqual(s.witnessCounters, [:])
        XCTAssertEqual(s.peerGenerations, [Self.B: 3])
        XCTAssertEqual(s.rollbackSuspected, 4)
    }
}
