import XCTest
import Foundation
@testable import LGKCore

/// Audit 2026-10-24 M-6 / M-7 / R-4 (Kotlin `HardeningTest`, desktop `tests/test_secfix_sync_*.py`).
final class SyncHardeningTests: XCTestCase {
    static let T0 = EngineTests.T0
    static let A = EngineTests.A

    func cases() throws -> [String: JSONValue] {
        MergeVectors.obj(try CanonicalJSON.parse(Array(Vectors.data("hardening_cases.json"))))
    }

    func issues(_ r: RunReport) -> [String] { r.issues.map(\.kind) }

    func longMap(_ v: JSONValue?) -> [String: Int64]? {
        guard case .object(let o)? = v else { return nil }
        return o.compactMapValues { if case .int(let n) = $0 { return n }; return nil }
    }

    func strOrNil(_ v: JSONValue?) -> String? { MergeVectors.str(v) }

    // MARK: shared vectors

    func test_constants_match_the_desktop() throws {
        let c = MergeVectors.obj(try cases()["constants"])
        XCTAssertEqual(c["MAX_VV_COUNTER"], .int(Plausibility.maxVVCounter))
        XCTAssertEqual(c["MAX_UNKNOWN_VV_COUNTER"], .int(Plausibility.maxUnknownVVCounter))
        XCTAssertEqual(c["MAX_VV_STEP"], .int(Plausibility.maxVVStep))
        XCTAssertEqual(c["MAX_VV_KEYS"], .int(Int64(Plausibility.maxVVKeys)))
        XCTAssertEqual(c["MAX_FILE_COUNTER"], .int(FolderSync.maxFileCounter))
        XCTAssertEqual(c["MAX_COUNTER_JUMP"], .int(FolderSync.maxCounterJump))
    }

    func test_vv_cases_match_the_desktop() throws {
        let list = MergeVectors.arr(try cases()["vv"])
        XCTAssertFalse(list.isEmpty)
        for c in list {
            let o = MergeVectors.obj(c)
            let known = Set(MergeVectors.arr(o["known"]).compactMap { MergeVectors.str($0) })
            let got = Plausibility.implausibleVV(longMap(o["remote"])!, local: longMap(o["local"]), known: known)
            XCTAssertEqual(got, strOrNil(o["expected"]), "\(o)")
        }
    }

    func test_counter_cases_match_the_desktop() throws {
        for c in MergeVectors.arr(try cases()["counters"]) {
            let o = MergeVectors.obj(c)
            guard case .int(let counter)? = o["counter"] else { return XCTFail("counter") }
            var last: Int64?
            if case .int(let n)? = o["last"] { last = n }
            XCTAssertEqual(FolderSync.counterVerdict(counter, last: last), strOrNil(o["expected"]), "\(o)")
        }
    }

    func test_signature_vector_and_cases_match_the_desktop() throws {
        let raw = Array(try Vectors.data("devices/A.lgksync"))
        let header = try ViewFile.decodeHeader(raw)
        let sig = Array(try Vectors.data("signatures/A.lgksig"))
        let a = try KeyringTests.identity("A")
        XCTAssertEqual(try ViewSignature.verify(sig, raw: raw, header: header), a.signingPublicKey)
        // CryptoKit signs with hedged randomness: our own signature differs in bytes but verifies.
        let mine = try ViewSignature.sign(raw, header: header, identity: a)
        XCTAssertEqual(try ViewSignature.verify(mine, raw: raw, header: header), a.signingPublicKey)
        let list = MergeVectors.arr(try cases()["signatures"])
        XCTAssertGreaterThan(list.count, 10)
        for c in list {
            let o = MergeVectors.obj(c)
            let text = Array(MergeVectors.str(o["signature"])!.utf8)
            var got = "valid"
            do { _ = try ViewSignature.verify(text, raw: raw, header: header) } catch let e as SyncFormatError {
                got = e.reason
            }
            XCTAssertEqual(got, MergeVectors.str(o["expected"]), MergeVectors.str(o["name"]) ?? "")
        }
    }

    // MARK: runner

    func test_poisoned_vector_is_quarantined_and_the_rest_merges() throws {
        var views: [PeerView] = []
        for d in GroupTests.devices {
            let v = try ViewFile.decode(Array(try Vectors.data("devices/\(d.name).lgksync")), key: FolderSyncTests.epoch1(),
                                        expectedDeviceID: d.id)
            views.append(PeerView(deviceID: d.id, states: v.states))
        }
        let first = views[0]
        let bad = first.states[0]
        let poisoned = try ItemState(itemID: bad.itemID, vv: bad.vv.mapValues { _ in VersionVector.maxCounter },
                                     deleted: bad.deleted, deletedAt: bad.deletedAt, item: bad.item)
        views[0] = PeerView(deviceID: first.deviceID, states: [poisoned] + first.states.dropFirst())
        let r = SyncRunner.run(store: StoreSnapshot(), views: views, device: "d4444444-0000-4000-8000-00000000000d",
                               now: Self.T0 + 1000)
        XCTAssertTrue(r.issues.contains(SyncIssue("implausible-vv", "\(first.deviceID):\(bad.itemID)")))
        for s in r.ownStates ?? [] { XCTAssertTrue(s.vv.values.allSatisfy { $0 < 100 }, s.itemID) }
    }

    // MARK: folder

    func joined() throws -> (MemoryFolder, MemoryStore, FolderSync) {
        let folder = try FolderSyncTests.seededFolder()
        let store = MemoryStore()
        let fs = try FolderSync(access: folder, installID: FolderSyncTests.install)
        let pw = try KeyringTests.pwKey("1")
        _ = try fs.join(store: store, deviceName: "iPhone", random: DetRand("hardening|join"),
                        clock: FixedClock(now: Self.T0 + 1000)) { _ in pw }
        return (folder, store, fs)
    }

    func writeA(_ folder: MemoryFolder, counter: Int64, _ label: String) throws -> [UInt8] {
        let states = try ViewFile.decode(Array(try Vectors.data("devices/A.lgksync")), key: FolderSyncTests.epoch1(),
                                         expectedDeviceID: Self.A).states
        let raw = try ViewFile.encode(key: FolderSyncTests.epoch1(), deviceID: Self.A, counter: counter, states: states,
                                      now: FixedClock(now: Self.T0 + 1500), random: DetRand(label))
        folder.files[FolderSyncTests.devPath(Self.A)] = raw
        return raw
    }

    func signA(_ folder: MemoryFolder, _ raw: [UInt8], as who: String = "A") throws {
        folder.files[FolderLayout.signatureFile(Self.A)!] =
            try ViewSignature.sign(raw, header: try ViewFile.decodeHeader(raw), identity: try KeyringTests.identity(who))
    }

    func test_own_view_is_signed_and_pinned() throws {
        let (folder, store, _) = try joined()
        let st = try XCTUnwrap(store.snapshot.sync)
        let raw = folder.files[FolderSyncTests.devPath(st.deviceID)]!
        let sig = folder.files[FolderLayout.signatureFile(st.deviceID)!]!
        XCTAssertEqual(try ViewSignature.verify(sig, raw: raw, header: try ViewFile.decodeHeader(raw)), st.identity.signingPublicKey)
        XCTAssertEqual(st.viewSigners[st.deviceID], Base64.encode(st.identity.signingPublicKey))
    }

    func test_unsigned_views_of_older_peers_are_accepted_until_pinned() throws {
        let (folder, store, fs) = try joined()
        try FolderSyncTests.olderAppMembers(folder, store, [Self.A])   // A joined with an app from before keyring format 2
        _ = try writeA(folder, counter: 8, "a8")
        XCTAssertEqual(issues(fs.runOnce(store: store, random: DetRand("r1"), clock: FixedClock(now: Self.T0 + 1600))), [])
        XCTAssertEqual(store.snapshot.sync?.lastSeen[Self.A], 8)
        store.snapshot.sync!.viewSigners[Self.A] = Base64.encode(try KeyringTests.identity("A").signingPublicKey)
        let nine = try writeA(folder, counter: 9, "a9")
        XCTAssertEqual(issues(fs.runOnce(store: store, random: DetRand("r2"), clock: FixedClock(now: Self.T0 + 1700))),
                       ["view-unsigned"])
        try signA(folder, nine)
        XCTAssertEqual(issues(fs.runOnce(store: store, random: DetRand("r3"), clock: FixedClock(now: Self.T0 + 1800))), [])
        XCTAssertEqual(store.snapshot.sync?.lastSeen[Self.A], 9)
        let ten = try writeA(folder, counter: 10, "a10")
        try signA(folder, ten, as: "B")
        XCTAssertEqual(issues(fs.runOnce(store: store, random: DetRand("r4"), clock: FixedClock(now: Self.T0 + 1900))),
                       ["view-forged"])
    }

    func test_paired_key_outranks_the_pin_on_first_use() throws {
        // Desktop `paired_keys.get(dev) or signers.get(dev)`: for a member whose keyring entry has no key (older
        // app), the key learned at LAN pairing is the only one A may sign with.
        let (folder, store, _) = try joined()
        try FolderSyncTests.olderAppMembers(folder, store, [Self.A])
        let keyA = Base64.encode(try KeyringTests.identity("A").signingPublicKey)
        let fs = try FolderSync(access: folder, installID: FolderSyncTests.install, pairedKeys: [Self.A: keyA])
        let raw = try writeA(folder, counter: 8, "a8")
        try signA(folder, raw, as: "B")
        XCTAssertEqual(issues(fs.runOnce(store: store, random: DetRand("r1"), clock: FixedClock(now: Self.T0 + 1600))),
                       ["view-forged"])
        XCTAssertNil(store.snapshot.sync?.viewSigners[Self.A])
        // A wrong key pinned on first use does not win over the paired one.
        store.snapshot.sync!.viewSigners[Self.A] = Base64.encode(try KeyringTests.identity("B").signingPublicKey)
        try signA(folder, raw)
        XCTAssertEqual(issues(fs.runOnce(store: store, random: DetRand("r2"), clock: FixedClock(now: Self.T0 + 1700))), [])
        XCTAssertEqual(store.snapshot.sync?.lastSeen[Self.A], 8)
        XCTAssertEqual(store.snapshot.sync?.viewSigners[Self.A], keyA)
    }

    func test_huge_counter_of_an_unpinned_peer_is_refused() throws {
        let (folder, store, fs) = try joined()
        try FolderSyncTests.olderAppMembers(folder, store, [Self.A])
        _ = try writeA(folder, counter: VersionVector.maxCounter, "amax")
        XCTAssertEqual(issues(fs.runOnce(store: store, random: DetRand("r1"), clock: FixedClock(now: Self.T0 + 1600))),
                       ["implausible-counter"])
        XCTAssertEqual(store.snapshot.sync?.lastSeen[Self.A], 7)
    }

    func test_own_file_written_by_someone_else_is_reported_and_taken_back() throws {
        let (folder, store, fs) = try joined()
        let st = try XCTUnwrap(store.snapshot.sync)
        let me = st.deviceID
        let own = try ViewFile.decode(folder.files[FolderSyncTests.devPath(me)]!, key: FolderSyncTests.epoch1(),
                                      expectedDeviceID: me).states
        let forged = st.ownCounter + 3
        folder.files[FolderSyncTests.devPath(me)] = try ViewFile.encode(
            key: FolderSyncTests.epoch1(), deviceID: me, counter: forged, states: own,
            now: FixedClock(now: Self.T0 + 1100), random: DetRand("f"))
        let r = fs.runOnce(store: store, random: DetRand("r1"), clock: FixedClock(now: Self.T0 + 1200))
        XCTAssertEqual(issues(r), ["own-file-rewritten"])
        XCTAssertTrue(r.wrote)
        XCTAssertEqual(store.snapshot.sync?.ownCounter, forged + 1)
    }

    func test_own_counter_overflow_is_an_issue_not_a_crash() throws {
        let (folder, store, fs) = try joined()
        store.snapshot.sync!.ownCounter = VersionVector.maxCounter
        folder.files[FolderSyncTests.devPath(store.snapshot.sync!.deviceID)] = nil
        let r = fs.runOnce(store: store, random: DetRand("r1"), clock: FixedClock(now: Self.T0 + 1200))
        XCTAssertTrue(issues(r).contains("counter-exhausted"))
        XCTAssertFalse(r.wrote)
    }

    func test_keyring_key_outranks_a_paired_key_and_requires_a_signature() throws {
        // R-4: `keyring > LAN-paired > first-use pin`; a keyring key needs a valid signature even when nothing is pinned.
        let (folder, store, _) = try joined()
        let keyA = Base64.encode(try KeyringTests.identity("A").signingPublicKey)
        XCTAssertEqual(store.snapshot.sync?.viewSigners[Self.A], keyA)   // pinned from the keyring by the first run
        let wrongPaired = Base64.encode(try KeyringTests.identity("B").signingPublicKey)
        let fs = try FolderSync(access: folder, installID: FolderSyncTests.install, pairedKeys: [Self.A: wrongPaired])
        store.snapshot.sync!.viewSigners[Self.A] = nil
        let raw = try writeA(folder, counter: 8, "a8")
        XCTAssertEqual(issues(fs.runOnce(store: store, random: DetRand("r1"), clock: FixedClock(now: Self.T0 + 1600))),
                       ["view-unsigned"])
        try signA(folder, raw, as: "B")   // the paired key, but not the keyring's
        XCTAssertEqual(issues(fs.runOnce(store: store, random: DetRand("r2"), clock: FixedClock(now: Self.T0 + 1700))),
                       ["view-forged"])
        try signA(folder, raw)
        XCTAssertEqual(issues(fs.runOnce(store: store, random: DetRand("r3"), clock: FixedClock(now: Self.T0 + 1800))), [])
        XCTAssertEqual(store.snapshot.sync?.lastSeen[Self.A], 8)
        XCTAssertEqual(store.snapshot.sync?.viewSigners[Self.A], keyA)
    }

    func test_new_epoch_clears_peer_counters_and_keys() throws {
        let (_, store, _) = try joined()
        var st = try XCTUnwrap(store.snapshot.sync)
        st.viewSigners[Self.A] = "x"
        let reset = FolderSync.epochReset(st)
        XCTAssertEqual(reset.lastSeen, [:])
        XCTAssertEqual(reset.peerDigests, [:])
        XCTAssertEqual(Set(reset.viewSigners.keys), [st.deviceID])
    }
}
