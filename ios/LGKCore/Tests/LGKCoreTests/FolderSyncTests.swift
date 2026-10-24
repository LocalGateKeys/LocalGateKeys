import XCTest
import Foundation
@testable import LGKCore

/// In-memory folder: path -> bytes; directories exist when a file lies under them.
/// Test fake: used from one thread at a time (FolderSync is synchronous), hence `@unchecked`.
final class MemoryFolder: FolderAccess, @unchecked Sendable {
    var files: [String: [UInt8]] = [:]
    var writes: [String] = []

    func list(_ dir: String) throws -> [String] {
        let prefix = dir + "/"
        let names = files.keys.filter { $0.hasPrefix(prefix) }.map { String($0.dropFirst(prefix.count)) }
            .filter { !$0.contains("/") }
        if names.isEmpty && !exists(dir) { throw FolderAccessError.notFound(dir) }
        return names
    }
    func read(_ path: String, limit: Int) throws -> [UInt8] {
        guard let d = files[path] else { throw FolderAccessError.notFound(path) }
        return Array(d.prefix(limit))
    }
    func writeAtomic(_ path: String, _ data: [UInt8]) throws { files[path] = data; writes.append(path) }
    func remove(_ path: String) throws {
        guard files.removeValue(forKey: path) != nil else { throw FolderAccessError.notFound(path) }
    }
    func exists(_ path: String) -> Bool { files[path] != nil || files.keys.contains { $0.hasPrefix(path + "/") } }
}

/// In-memory store that counts commits.
final class MemoryStore: ItemStore, @unchecked Sendable {
    var snapshot: StoreSnapshot
    var commits = 0
    private let lock = NSLock()
    init(_ s: StoreSnapshot = StoreSnapshot()) { snapshot = s }
    func load() throws -> StoreSnapshot { lock.withLock { snapshot } }
    func commit(_ change: StoreChange) throws {
        lock.lock(); defer { lock.unlock() }
        guard change.baseRevision == snapshot.revision else { throw FolderSyncError("vault-changed") }
        commits += 1
        snapshot = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: snapshot.revision + 1)
    }
}

final class FolderSyncTests: XCTestCase {
    static let T0 = EngineTests.T0
    static let install = "ios-install-0001"
    static let keyringPath = "LocalGateKeys Sync/keyring.lgkkeys"
    static func devPath(_ id: String) -> String { "LocalGateKeys Sync/devices/\(id).lgksync" }

    static func seededFolder() throws -> MemoryFolder {
        let f = MemoryFolder()
        f.files[keyringPath] = Array(try Vectors.data("keyring_epoch1.json"))
        for d in GroupTests.devices { f.files[devPath(d.id)] = Array(try Vectors.data("devices/\(d.name).lgksync")) }
        return f
    }

    static func epoch1() throws -> GroupKey { try KeyringTests.epochKey("1") }

    func issues(_ r: RunReport) -> [String] { r.issues.map(\.kind) }

    /// Joins the seeded folder with the known password-wrap key (no Argon2id) at T0 + 1000.
    func joined(_ label: String = "phone") throws -> (MemoryFolder, MemoryStore, FolderSync, RunReport) {
        let folder = try Self.seededFolder()
        let store = MemoryStore()
        let fs = try FolderSync(access: folder, installID: Self.install)
        let pw = try KeyringTests.pwKey("1")
        let report = try fs.join(store: store, deviceName: "iPhone", random: DetRand("t10|\(label)"),
                                 clock: FixedClock(now: Self.T0 + 1000)) { _ in pw }
        return (folder, store, fs, report)
    }

    func storedStates(_ store: MemoryStore, device: String, now: Int64) throws -> [ItemState] {
        let v = try SyncMeta.localView(records: store.snapshot.records, meta: store.snapshot.meta, device: device, now: now)
        return v.states.values.sorted { $0.itemID < $1.itemID }
    }

    // MARK: join and merge

    func test_join_with_password_reads_ABC_and_matches_bridge_stored_states() throws {
        let folder = try Self.seededFolder()
        let store = MemoryStore()
        let fs = try FolderSync(access: folder, installID: Self.install)
        let password = KeyringTests.str(try KeyringTests.expected()["password_epoch1"])
        let report = try fs.join(store: store, password: password, deviceName: "iPhone", random: DetRand("t10|join"),
                                 clock: FixedClock(now: Self.T0 + 1000))
        XCTAssertEqual(report.issues, [])
        XCTAssertTrue(report.wrote)
        let state = try XCTUnwrap(store.snapshot.sync)
        let want = try MergeVectors.arr(MergeVectors.expectedMerge()["bridge_stored_states"]).map(MergeVectors.state)
        XCTAssertEqual(try storedStates(store, device: state.deviceID, now: Self.T0 + 1000), want)
        XCTAssertEqual(report.ownStates, want)
        // The keyring now lists the phone and is accepted by A; the phone's file decodes with counter 1.
        let ring = try Keyring.parse(folder.files[Self.keyringPath]!)
        XCTAssertEqual(try Keyring.accept(ring, trusted: Self.epoch1(), identity: KeyringTests.identity("A")), try Self.epoch1())
        XCTAssertEqual(Keyring.memberNames(ring, key: try Self.epoch1())[state.deviceID], "iPhone")
        let own = try ViewFile.decode(folder.files[Self.devPath(state.deviceID)]!, key: Self.epoch1(), expectedDeviceID: state.deviceID)
        XCTAssertEqual(own.header.counter, 1)
        XCTAssertEqual(own.states, want)
        XCTAssertEqual(state.ownCounter, 1)
        XCTAssertEqual(state.lastSeen, [EngineTests.A: 7, EngineTests.B: 4, EngineTests.C: 3])
        XCTAssertEqual(state.members, [EngineTests.A, EngineTests.B, EngineTests.C, state.deviceID].sorted())
        // A second run without changes neither commits nor writes.
        let commits = store.commits, writes = folder.writes.count
        let again = fs.runOnce(store: store, random: DetRand("again"), clock: FixedClock(now: Self.T0 + 1100))
        XCTAssertEqual(again.issues, [])
        XCTAssertFalse(again.wrote)
        XCTAssertEqual(store.commits, commits)
        XCTAssertEqual(folder.writes.count, writes)
    }

    func test_join_refusals() throws {
        let (folder, store, fs, _) = try joined()
        XCTAssertThrowsError(try fs.join(store: store, deviceName: "x", random: DetRand("x"), clock: FixedClock(now: Self.T0)) { _ in
            try KeyringTests.pwKey("1")
        }) { XCTAssertEqual(($0 as? FolderSyncError)?.reason, "already-joined") }
        let empty = MemoryFolder()
        let fs2 = try FolderSync(access: empty, installID: Self.install)
        XCTAssertThrowsError(try fs2.join(store: MemoryStore(), deviceName: "x", random: DetRand("x"),
                                          clock: FixedClock(now: Self.T0)) { _ in [] }) {
            XCTAssertEqual(($0 as? FolderSyncError)?.reason, "no-group")
        }
        _ = folder
        XCTAssertThrowsError(try FolderSync(access: empty, installID: "")) {
            XCTAssertEqual(($0 as? FolderSyncError)?.reason, "bad-install-id")
        }
    }

    // MARK: peer files

    func test_rollback_and_suspicious_rewrite_are_skipped() throws {
        let (folder, store, fs, _) = try joined()
        let a = try ViewFile.decode(folder.files[Self.devPath(EngineTests.A)]!, key: Self.epoch1(), expectedDeviceID: EngineTests.A)
        // Lower counter: rollback.
        folder.files[Self.devPath(EngineTests.A)] = try ViewFile.encode(key: Self.epoch1(), deviceID: EngineTests.A, counter: 6,
                                                                        states: a.states, now: FixedClock(now: Self.T0 + 950),
                                                                        random: DetRand("rb"))
        let commits = store.commits
        var r = fs.runOnce(store: store, random: DetRand("r1"), clock: FixedClock(now: Self.T0 + 1100))
        XCTAssertEqual(issues(r), ["rollback"])
        XCTAssertEqual(store.commits, commits)
        // Same counter, other bytes: suspicious-rewrite.
        folder.files[Self.devPath(EngineTests.A)] = try ViewFile.encode(key: Self.epoch1(), deviceID: EngineTests.A, counter: 7,
                                                                        states: a.states, now: FixedClock(now: Self.T0 + 900),
                                                                        random: DetRand("other-nonces"))
        r = fs.runOnce(store: store, random: DetRand("r2"), clock: FixedClock(now: Self.T0 + 1100))
        XCTAssertEqual(issues(r), ["suspicious-rewrite"])
        XCTAssertEqual(store.commits, commits)
        // A higher counter is accepted again.
        folder.files[Self.devPath(EngineTests.A)] = try ViewFile.encode(key: Self.epoch1(), deviceID: EngineTests.A, counter: 8,
                                                                        states: a.states, now: FixedClock(now: Self.T0 + 1050),
                                                                        random: DetRand("ok"))
        r = fs.runOnce(store: store, random: DetRand("r3"), clock: FixedClock(now: Self.T0 + 1100))
        XCTAssertEqual(r.issues, [])
        XCTAssertEqual(store.snapshot.sync?.lastSeen[EngineTests.A], 8)
    }

    func test_provider_copies_and_unknown_files_are_ignored() throws {
        let (folder, store, fs, _) = try joined()
        let aBytes = folder.files[Self.devPath(EngineTests.A)]!
        folder.files["LocalGateKeys Sync/devices/\(EngineTests.A) (1).lgksync"] = aBytes
        folder.files["LocalGateKeys Sync/devices/\(EngineTests.B)-DESKTOP-ABC.lgksync"] = aBytes
        folder.files["LocalGateKeys Sync/devices/.\(EngineTests.C).lgksync.abc123.tmp"] = [1, 2, 3]
        let r = fs.runOnce(store: store, random: DetRand("r"), clock: FixedClock(now: Self.T0 + 1100))
        XCTAssertEqual(issues(r), ["ignored-file"])
        XCTAssertEqual(r.issues[0].detail,
                       "2 files: \(EngineTests.A) (1).lgksync, \(EngineTests.B)-DESKTOP-ABC.lgksync")
        XCTAssertFalse(r.wrote)
    }

    func test_stale_device_is_skipped_entirely() throws {
        let (folder, store, fs, _) = try joined()
        let late = Self.T0 + 1000 + 366 * 86400
        // B writes an old file with a new item: the whole file is skipped.
        let b = try ViewFile.decode(folder.files[Self.devPath(EngineTests.B)]!, key: Self.epoch1(), expectedDeviceID: EngineTests.B)
        folder.files[Self.devPath(EngineTests.B)] = try ViewFile.encode(key: Self.epoch1(), deviceID: EngineTests.B, counter: 5,
                                                                        states: b.states, now: FixedClock(now: Self.T0 + 950),
                                                                        random: DetRand("stale"))
        let r = fs.runOnce(store: store, random: DetRand("r"), clock: FixedClock(now: late))
        XCTAssertTrue(issues(r).contains("stale-device"))
        XCTAssertEqual(store.snapshot.sync?.lastSeen[EngineTests.B], 5)
    }

    // MARK: Review Focus #2

    func test_failed_reads_leave_store_untouched() throws {
        // 1. Wrong sync password (real Argon2id): refused, no commit, folder unchanged.
        do {
            let folder = try Self.seededFolder()
            let before = folder.files
            let store = MemoryStore()
            let fs = try FolderSync(access: folder, installID: Self.install)
            XCTAssertThrowsError(try fs.join(store: store, password: "not the password", deviceName: "iPhone",
                                             random: DetRand("wrong"), clock: FixedClock(now: Self.T0 + 1000))) {
                XCTAssertEqual(($0 as? FolderSyncError)?.reason, "password")
            }
            XCTAssertEqual(store.commits, 0)
            XCTAssertEqual(store.snapshot, StoreSnapshot())
            XCTAssertEqual(folder.files, before)
        }
        let (folder, store, fs, _) = try joined()
        let synced = store.snapshot
        let baseline = store.commits  // the join and its first run
        let goodRing = folder.files[Self.keyringPath]!
        func assertUntouched(_ r: RunReport, _ kinds: [String], _ what: String, line: UInt = #line) {
            XCTAssertEqual(issues(r), kinds, what, line: line)
            XCTAssertEqual(store.commits, baseline, "\(what): no commit at all", line: line)
            XCTAssertEqual(store.snapshot, synced, what, line: line)
            XCTAssertFalse(r.wrote, what, line: line)
        }
        let clock = FixedClock(now: Self.T0 + 1100)
        // 2a. Tampered keyring that no longer parses.
        var bad = goodRing; bad[bad.count / 2] ^= 0x01
        folder.files[Self.keyringPath] = Array(bad.prefix(bad.count - 5))
        assertUntouched(fs.runOnce(store: store, random: DetRand("k1"), clock: clock), ["keyring-corrupt"], "garbage keyring")
        // 2b. Tampered keyring that parses but fails its MAC: restored from the stored copy; store unchanged.
        guard case .object(var o) = try Keyring.parse(goodRing), case .array(var ms)? = o["members"],
              case .object(var m0) = ms[0] else { return XCTFail() }
        m0["added_at"] = .int(1); ms[0] = .object(m0); o["members"] = .array(ms)
        folder.files[Self.keyringPath] = try CanonicalJSON.encode(.object(o), dialect: .utf8)
        assertUntouched(fs.runOnce(store: store, random: DetRand("k2"), clock: clock), ["keyring-restored"], "MAC tampered")
        XCTAssertEqual(folder.files[Self.keyringPath], goodRing)
        // 2c. A keyring of another group: never overwritten, nothing written.
        let other = Array(try Vectors.data("keyring_existing_epoch1.json"))
        folder.files[Self.keyringPath] = other
        let writes = folder.writes.count
        assertUntouched(fs.runOnce(store: store, random: DetRand("k3"), clock: clock), ["folder-has-other-group"], "other group")
        XCTAssertEqual(folder.files[Self.keyringPath], other)
        XCTAssertEqual(folder.writes.count, writes)
        folder.files[Self.keyringPath] = goodRing
        // 3. Corrupt device files (flipped byte, truncated, garbage): skipped, store unchanged.
        let a = folder.files[Self.devPath(EngineTests.A)]!
        var flipped = a; flipped[flipped.count - 3] ^= 0x40
        for (name, data) in [("flipped", flipped), ("truncated", Array(a.prefix(a.count / 2))), ("garbage", Array("hello".utf8))] {
            folder.files[Self.devPath(EngineTests.A)] = data
            assertUntouched(fs.runOnce(store: store, random: DetRand(name), clock: clock), ["corrupt"], name)
        }
        // A wrong-device file under A's name.
        folder.files[Self.devPath(EngineTests.A)] = folder.files[Self.devPath(EngineTests.B)]!
        assertUntouched(fs.runOnce(store: store, random: DetRand("dm"), clock: clock), ["device-mismatch"], "device mismatch")
    }

    // MARK: own file counter

    func test_own_file_counter_is_max_of_reserved_and_file_plus_one() throws {
        let (folder, store, fs, _) = try joined()
        let me = store.snapshot.sync!.deviceID
        // A local edit: the file is rewritten with counter 2, reserved in the same commit.
        var snap = store.snapshot
        var w = MergeVectors.obj(snap.records[EngineTests.NOTE]); var rec = MergeVectors.obj(w["record"])
        rec["title"] = .string("Edited on the phone"); rec["updated_at"] = .int(Self.T0 + 1050)
        w = MergeVectors.obj(Wrapper.make(ns: .item, record: try Normalise.normalForm(ns: .item, record: .object(rec))))
        snap.records[EngineTests.NOTE] = .object(w)
        store.snapshot = snap
        var r = fs.runOnce(store: store, random: DetRand("c2"), clock: FixedClock(now: Self.T0 + 1100))
        XCTAssertEqual(r.issues, []); XCTAssertTrue(r.wrote)
        var own = try ViewFile.decode(folder.files[Self.devPath(me)]!, key: Self.epoch1(), expectedDeviceID: me)
        XCTAssertEqual(own.header.counter, 2)
        XCTAssertEqual(store.snapshot.sync?.ownCounter, 2)
        // The store was restored from an older backup (reserved 2) while the file says 5: write 6.
        let states = own.states
        // That file was written (and signed) by this device itself.
        let five = try ViewFile.encode(key: Self.epoch1(), deviceID: me, counter: 5, states: states,
                                       now: FixedClock(now: Self.T0 + 1150), random: DetRand("five"))
        folder.files[Self.devPath(me)] = five
        folder.files[FolderLayout.signatureFile(me)!] = try ViewSignature.sign(
            five, header: try ViewFile.decodeHeader(five), identity: store.snapshot.sync!.identity)
        r = fs.runOnce(store: store, random: DetRand("c6"), clock: FixedClock(now: Self.T0 + 1200))
        XCTAssertEqual(issues(r), ["counter-resynced"]); XCTAssertTrue(r.wrote)
        own = try ViewFile.decode(folder.files[Self.devPath(me)]!, key: Self.epoch1(), expectedDeviceID: me)
        XCTAssertEqual(own.header.counter, 6)
        XCTAssertEqual(store.snapshot.sync?.ownCounter, 6)
        // A missing own file is written again above the reserved counter.
        folder.files[Self.devPath(me)] = nil
        r = fs.runOnce(store: store, random: DetRand("c7"), clock: FixedClock(now: Self.T0 + 1300))
        XCTAssertTrue(r.wrote)
        own = try ViewFile.decode(folder.files[Self.devPath(me)]!, key: Self.epoch1(), expectedDeviceID: me)
        XCTAssertEqual(own.header.counter, 7)
        // Leftover own temp files are swept.
        folder.files["LocalGateKeys Sync/devices/.\(me).lgksync.dead.tmp"] = [0]
        _ = fs.runOnce(store: store, random: DetRand("c8"), clock: FixedClock(now: Self.T0 + 1400))
        XCTAssertNil(folder.files["LocalGateKeys Sync/devices/.\(me).lgksync.dead.tmp"])
    }

    func test_bad_member_name_is_reported_and_run_continues() throws {
        let (folder, store, fs, _) = try joined()
        guard case .object(var o) = try Keyring.parse(folder.files[Self.keyringPath]!),
              case .array(var members)? = o["members"] else { return XCTFail() }
        // Re-seal B's name with garbage under a valid MAC.
        let gk = try Self.epoch1()
        for i in members.indices {
            guard case .object(var m) = members[i], m["device_id"] == .string(EngineTests.B) else { continue }
            m["name_ct"] = .string(try Keyring.sealName(gk, deviceID: EngineTests.A, name: "Wrong binding", random: DetRand("n")))
            members[i] = .object(m)
        }
        o["members"] = .array(members)
        let ring = try Keyring.finish(o, key: gk)
        folder.files[Self.keyringPath] = try CanonicalJSON.encode(ring, dialect: .utf8)
        let r = fs.runOnce(store: store, random: DetRand("bn"), clock: FixedClock(now: Self.T0 + 1100))
        XCTAssertEqual(r.issues, [SyncIssue("bad-name", EngineTests.B)])
    }

    // MARK: from_ios vectors (read by the desktop in Task 11)

    static let phoneLogin = "f1050000-0000-4000-8000-000000000101"
    static let phonePasskey = "f1050000-0000-4000-8000-000000000102"
    /// The desktop-made key from passkeys/records.json, so the phone-made passkey is reproducible.
    static let phonePasskeyKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggJAFr4R6ySgU2NEGD-pDv92Ax8nnc5g7dPnxMB-ag4uhRANCAARvaw4fOvc3kChJM_Bpa34YDtimWWrF2-Of20DTY7TibutHLx7hAnjZggvTyYrgq668kur1CSNCs1C59qhpNXaB"

    /// The full phone flow: join with the real password, merge A/B/C, create a web login and edit a note
    /// through the phone normaliser, create a passkey, run again. Deterministic (fixed randomness and clock).
    static func fromIOSFlow() throws -> (keyring: [UInt8], deviceID: String, file: [UInt8], store: MemoryStore) {
        let folder = try seededFolder()
        let store = MemoryStore()
        let fs = try FolderSync(access: folder, installID: install)
        let rand = DetRand("from-ios")
        let password = KeyringTests.str(try KeyringTests.expected()["password_epoch1"])
        let first = try fs.join(store: store, password: password, deviceName: "iPhone (iOS)", random: rand,
                                clock: FixedClock(now: T0 + 1000))
        guard first.issues.isEmpty, first.wrote else { throw FolderSyncError("first-run", "\(first.issues)") }
        var snap = store.snapshot
        let login: JSONValue = .object([
            "id": .string(phoneLogin), "kind": .string("web"), "label": .string("Créé sur l’iPhone"),
            "username": .string("phone.user"), "password": .string("from-ios-sample-pass"),
            "scope": .object(["origin": .string("https://Example.org:443")]),
            "created_at": .int(T0 + 1010), "updated_at": .int(T0 + 1010), "favorite": .bool(true),
            "tags": .array([.string("ios")]), "notes": .string("written by LGKCore"),
        ])
        snap.records[phoneLogin] = Wrapper.make(ns: .entry, record: try Normalise.normalForm(ns: .entry, record: login))
        var note = MergeVectors.obj(MergeVectors.obj(snap.records[EngineTests.NOTE])["record"])
        note["title"] = .string("Edited on the phone"); note["updated_at"] = .int(T0 + 1020)
        snap.records[EngineTests.NOTE] = Wrapper.make(ns: .item, record: try Normalise.normalForm(ns: .item, record: .object(note)))
        let made = PasskeyRecord.newPayload(rpID: "passkeys.example", rpName: "Passkeys Example", userName: "phone.user",
                                            userDisplayName: "Phone User", userHandle: Array("ios-user-handle".utf8),
                                            credentialID: Array(0x10..<0x20), key: PasskeyKey(pkcs8B64URL: phonePasskeyKey)!,
                                            today: "2026-10-18")
        let passkey: JSONValue = .object([
            "id": .string(phonePasskey), "kind": .string("passkey"), "title": .string(made.title),
            "created_at": .int(T0 + 1025), "updated_at": .int(T0 + 1025), "favorite": .bool(false), "tags": .array([]),
            "payload": made.fields,
        ])
        snap.records[phonePasskey] = Wrapper.make(ns: .item, record: try Normalise.normalForm(ns: .item, record: passkey))
        store.snapshot = snap
        let second = fs.runOnce(store: store, random: rand, clock: FixedClock(now: T0 + 1030))
        guard second.issues.isEmpty, second.wrote else { throw FolderSyncError("second-run", "\(second.issues)") }
        let id = store.snapshot.sync!.deviceID
        return (folder.files[keyringPath]!, id, folder.files[devPath(id)]!, store)
    }

    func test_writes_from_ios_vectors() throws {
        let out = try Self.fromIOSFlow()
        // Reproducible: the same flow gives the same bytes.
        let again = try Self.fromIOSFlow()
        XCTAssertEqual(again.keyring, out.keyring)
        XCTAssertEqual(again.file, out.file)
        XCTAssertEqual(again.deviceID, out.deviceID)
        XCTAssertEqual(out.deviceID, "bcc03464-25ca-4262-a442-c73dcd26f5c5")

        // The desktop's checks: the keyring is accepted with the epoch-1 key, the file decodes with the id.
        let gk = try Self.epoch1()
        let ring = try Keyring.parse(out.keyring)
        XCTAssertEqual(try Keyring.accept(ring, trusted: gk, identity: KeyringTests.identity("B")), gk)
        let view = try ViewFile.decode(out.file, key: gk, expectedDeviceID: out.deviceID)
        XCTAssertEqual(view.header.counter, 2)
        let received = Dictionary(uniqueKeysWithValues: try MergeVectors.arr(MergeVectors.expectedMerge()["bridge_stored_states"])
            .map(MergeVectors.state).map { ($0.itemID, $0) })
        var phoneEdited = 0
        for s in view.states {
            guard let item = s.item else {
                XCTAssertEqual(s, received[s.itemID], s.itemID)  // tombstones republished unchanged
                continue
            }
            let w = MergeVectors.obj(item)
            let ns = Namespace(rawValue: MergeVectors.str(w["ns"])!)!
            // Every live record of a phone-edited kind is the desktop normal form of itself (other kinds are
            // republished exactly as received; Task 11 checks them with the desktop's own normal_form).
            let kind = MergeVectors.str(MergeVectors.obj(w["record"])["kind"]) ?? ""
            if Normalise.phoneEntryKinds.contains(kind) || Normalise.phoneItemKinds.contains(kind) {
                XCTAssertEqual(try Normalise.normalForm(ns: ns, record: w["record"]!), w["record"]!, s.itemID)
            }
            if s.itemID == Self.phoneLogin || s.itemID == Self.phonePasskey || s.itemID == EngineTests.NOTE {
                phoneEdited += 1
                XCTAssertEqual(s.vv[out.deviceID], 1, s.itemID)
            } else {
                XCTAssertEqual(s, received[s.itemID], "\(s.itemID) must be republished unchanged")
                XCTAssertEqual(try CanonicalJSON.encode(item, dialect: .utf8),
                               try CanonicalJSON.encode(received[s.itemID]!.item!, dialect: .utf8))
            }
        }
        XCTAssertEqual(phoneEdited, 3)
        XCTAssertEqual(Set(view.states.map(\.itemID)), Set(received.keys).union([Self.phoneLogin, Self.phonePasskey]))

        if ProcessInfo.processInfo.environment["LGK_WRITE_FROM_IOS"] == "1" {
            let dir = Vectors.url("from_ios")
            let devices = dir.appendingPathComponent("devices", isDirectory: true)
            try FileManager.default.createDirectory(at: devices, withIntermediateDirectories: true)
            try Data(out.keyring).write(to: dir.appendingPathComponent("keyring.lgkkeys"), options: .atomic)
            try Data(out.file).write(to: devices.appendingPathComponent("\(out.deviceID).lgksync"), options: .atomic)
            XCTAssertEqual(Array(try Vectors.data("from_ios/keyring.lgkkeys")), out.keyring)
            XCTAssertEqual(Array(try Vectors.data("from_ios/devices/\(out.deviceID).lgksync")), out.file)
        }
    }
}
