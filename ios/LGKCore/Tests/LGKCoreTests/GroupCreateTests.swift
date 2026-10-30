import XCTest
import Foundation
import Crypto
@testable import LGKCore

/// A `FolderAccess` over a real temporary directory (atomic writes through a temp file and a replace).
final class TempDirFolder: FolderAccess, @unchecked Sendable {
    let root: URL
    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-folder-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }
    deinit { try? FileManager.default.removeItem(at: root) }
    func url(_ path: String) -> URL { path.isEmpty ? root : root.appendingPathComponent(path) }
    func list(_ dir: String) throws -> [String] {
        do { return try FileManager.default.contentsOfDirectory(atPath: url(dir).path) } catch {
            throw FolderAccessError.notFound(dir)
        }
    }
    func read(_ path: String, limit: Int) throws -> [UInt8] {
        guard let h = FileHandle(forReadingAtPath: url(path).path) else { throw FolderAccessError.notFound(path) }
        defer { try? h.close() }
        return Array((try? h.read(upToCount: limit)) ?? Data())
    }
    func writeAtomic(_ path: String, _ data: [UInt8]) throws {
        let target = url(path)
        try FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        let tmp = target.deletingLastPathComponent().appendingPathComponent(".\(target.lastPathComponent).\(UUID().uuidString).tmp")
        try Data(data).write(to: tmp)
        if FileManager.default.fileExists(atPath: target.path) {
            _ = try FileManager.default.replaceItemAt(target, withItemAt: tmp)
        } else {
            try FileManager.default.moveItem(at: tmp, to: target)
        }
    }
    func remove(_ path: String) throws {
        guard FileManager.default.fileExists(atPath: url(path).path) else { throw FolderAccessError.notFound(path) }
        try FileManager.default.removeItem(at: url(path))
    }
    func exists(_ path: String) -> Bool { FileManager.default.fileExists(atPath: url(path).path) }
}

final class GroupCreateTests: XCTestCase {
    static let now: Int64 = 1_790_001_000
    static let password = "correct horse battery staple 42"
    static let newPassword = "violet tram sundial 1987 pebble"

    /// Fast stand-in for Argon2id in the flow tests (the vector test uses the real Argon2id outputs).
    static let cheapKDF: Keyring.KeyDerivation = { pw, salt in Array(SHA256.hash(data: Array("cheap|".utf8) + Array(pw.utf8) + salt)) }
    static func cheapKey(_ password: String) -> (JSONValue) throws -> [UInt8] {
        { ring in try cheapKDF(password, try Keyring.b64(Keyring.obj(Keyring.obj(ring)["kdf"])["salt"], 16, "salt")) }
    }

    static func vector() throws -> [String: JSONValue] { KeyringTests.obj(try CanonicalJSON.parse(Array(Vectors.data("mac/keyring_write.json")))) }
    static func o(_ v: JSONValue?) -> [String: JSONValue] { KeyringTests.obj(v) }
    static func s(_ v: JSONValue?) -> String { KeyringTests.str(v) }
    static func reads(_ c: [String: JSONValue]) -> QueueRandom {
        guard case .array(let a)? = c["random_reads_hex"] else { return QueueRandom([]) }
        return QueueRandom(a.map { Vectors.hex(s($0)) })
    }
    /// The production Argon2id outputs the generator recorded, by `password|salt`.
    static func tableKDF(_ v: [String: JSONValue]) -> Keyring.KeyDerivation {
        let table = o(v["argon2"]).mapValues { Vectors.hex(s($0)) }
        return { pw, salt in
            guard let key = table["\(pw)|\(Base64.encode(salt))"] else { throw KeyringError("bad-kdf", "no vector key") }
            return key
        }
    }
    /// `ring` with `id`'s `signing_proof` and the `mac` covering it nulled (CryptoKit hedges Ed25519).
    static func withoutProof(_ ring: JSONValue, _ id: String) -> JSONValue {
        var r = o(KeyringTests.editMember(ring, KeyringTests.memberIndex(ring, id)) { $0["signing_proof"] = .null })
        r["mac"] = .null
        return .object(r)
    }

    func reason(_ f: () throws -> Any) -> String? {
        do { _ = try f(); return nil } catch let e as KeyringError { return e.reason } catch let e as FolderSyncError {
            return e.reason
        } catch { return "other: \(error)" }
    }

    // MARK: keyrings against the desktop

    func testKeyringReadableByPython() throws {
        let vec = try Self.vector()
        let kdf = Self.tableKDF(vec)
        let a = try KeyringTests.identity("A")
        let clock = FixedClock(now: Self.now)

        // create_group
        let create = Self.o(vec["create"])
        let rand = Self.reads(create)
        let (ring, gk) = try Keyring.create(password: Self.password, identity: a, name: Self.s(vec["name"]),
                                            groupID: Self.s(vec["group_id"]), random: rand, now: clock, derive: kdf)
        XCTAssertTrue(rand.isEmpty)
        XCTAssertEqual(gk.key, Vectors.hex(Self.s(create["group_key_hex"])))
        XCTAssertEqual(Self.withoutProof(ring, a.deviceID), Self.withoutProof(create["keyring"]!, a.deviceID))
        let bytes = try CanonicalJSON.encode(ring, dialect: .utf8)
        XCTAssertNoThrow(try Keyring.parse(bytes))   // verifies the Swift-made proof
        XCTAssertTrue(Keyring.macOK(ring, key: gk))
        XCTAssertEqual(try Keyring.unwrap(ring, passwordKey: try kdf(Self.password, try Keyring.b64(Self.o(Self.o(ring)["kdf"])["salt"], 16, "s"))), gk)
        XCTAssertEqual(Keyring.memberNames(ring, key: gk)[a.deviceID], .some(Self.s(vec["name"])))

        // rotate: removing a member and changing the password, from the desktop-joined keyring (byte-identical)
        let joined = Self.o(vec["join"])["keyring"]!
        for name in ["remove_member", "change_password"] {
            let c = Self.o(vec[name])
            let remove: [String] = { if case .array(let r)? = c["remove"] { return r.map { Self.s($0) } }; return [] }()
            let r = Self.reads(c)
            let (rotated, newKey) = try Keyring.rotate(joined, trusted: gk, identity: a, newPassword: Self.newPassword,
                                                       remove: remove, random: r, derive: kdf)
            XCTAssertTrue(r.isEmpty, name)
            XCTAssertEqual(try CanonicalJSON.encode(rotated, dialect: .utf8), try CanonicalJSON.encode(c["keyring"]!, dialect: .utf8), name)
            XCTAssertEqual(newKey.key, Vectors.hex(Self.s(c["group_key_hex"])))
            XCTAssertEqual(try Keyring.accept(rotated, trusted: gk, identity: a), newKey)
        }

        // create_for_existing_group
        let ex = Self.o(vec["existing"])
        let exKey = try GroupKey(groupID: Self.s(ex["group_id"]), epoch: 3, key: Vectors.hex(Self.s(ex["group_key_hex"])))
        let er = Self.reads(ex)
        let first = try Keyring.createForExistingGroup(exKey, password: Self.password, identity: a, name: Self.s(vec["name"]),
                                                       random: er, now: clock, derive: kdf)
        XCTAssertTrue(er.isEmpty)
        XCTAssertEqual(Self.withoutProof(first, a.deviceID), Self.withoutProof(ex["keyring"]!, a.deviceID))
        XCTAssertEqual(Self.o(first)["prev_mac"], .null)
        XCTAssertEqual(try Keyring.accept(first, trusted: exKey, identity: a), exKey)

        // Swift-written files for tests/test_sync_from_mac.py (re-written with LGK_WRITE_FROM_MAC=1).
        let dir = Vectors.url("mac/from_mac")
        if ProcessInfo.processInfo.environment["LGK_WRITE_FROM_MAC"] == "1" {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try Data(bytes).write(to: dir.appendingPathComponent("keyring_created.lgkkeys"))
            try Data(try CanonicalJSON.encode(first, dialect: .utf8)).write(to: dir.appendingPathComponent("keyring_existing.lgkkeys"))
            // A folder group made end to end with the production Argon2id.
            let folder = try TempDirFolder()
            let store = MemoryStore()
            let fs = try FolderSync(access: folder, installID: "mac-install-0001")
            let report = try fs.create(store: store, password: Self.password, deviceName: Self.s(vec["name"]),
                                       random: DetRand("from-mac"), clock: clock)
            XCTAssertEqual(report.issues, [])
            let out = dir.appendingPathComponent("folder")
            try? FileManager.default.removeItem(at: out)
            try FileManager.default.copyItem(at: folder.root, to: out)
        }
        // The committed Swift-written files still verify here.
        for file in ["keyring_created.lgkkeys", "keyring_existing.lgkkeys", "folder/LocalGateKeys Sync/keyring.lgkkeys"] {
            XCTAssertNoThrow(try Keyring.parse(Array(try Data(contentsOf: dir.appendingPathComponent(file)))), file)
        }
    }

    // MARK: folder groups

    func testCreateFolderGroupThenJoinFromSecondDevice() throws {
        let folder = try TempDirFolder()
        let mac = MemoryStore(), phone = MemoryStore()
        let fsMac = try FolderSync(access: folder, installID: "mac-install")
        let report = try fsMac.create(store: mac, password: Self.password, deviceName: "Mac", random: DetRand("mac"),
                                      clock: FixedClock(now: Self.now), derive: Self.cheapKDF)
        XCTAssertEqual(report.issues, [])
        let state = try XCTUnwrap(mac.snapshot.sync)
        XCTAssertTrue(state.hasFolder)
        XCTAssertEqual(state.epoch, 1)
        XCTAssertEqual(state.members, [state.deviceID])
        XCTAssertEqual(state.keyring, try folder.read(FolderLayout.keyringPath, limit: 1 << 20))
        XCTAssertTrue(folder.exists(FolderLayout.deviceFile(state.deviceID)!))
        XCTAssertTrue(folder.exists(FolderLayout.signatureFile(state.deviceID)!))
        let ring = try Keyring.parse(state.keyring!)
        XCTAssertEqual(Keyring.obj(ring)["prev_mac"], .null)
        XCTAssertEqual(Keyring.memberNames(ring, key: try state.groupKey())[state.deviceID], .some("Mac"))

        // Refusals: a vault already in a group, a folder that already holds one.
        XCTAssertEqual(reason { try fsMac.create(store: mac, password: Self.password, deviceName: "Mac", random: DetRand("x"),
                                                 clock: FixedClock(now: Self.now), derive: Self.cheapKDF) }, "already-joined")
        XCTAssertEqual(reason { try fsMac.create(store: MemoryStore(), password: Self.password, deviceName: "Mac",
                                                 random: DetRand("x"), clock: FixedClock(now: Self.now), derive: Self.cheapKDF) },
                       "folder-in-use")
        XCTAssertEqual(reason { try fsMac.create(store: MemoryStore(), password: "short", deviceName: "Mac",
                                                 random: DetRand("x"), clock: FixedClock(now: Self.now), derive: Self.cheapKDF) },
                       "folder-in-use")

        // A second device joins with the sync password, and both see each other.
        let fsPhone = try FolderSync(access: folder, installID: "phone-install")
        let joined = try fsPhone.join(store: phone, deviceName: "iPhone", random: DetRand("phone"),
                                      clock: FixedClock(now: Self.now + 10), passwordKey: Self.cheapKey(Self.password))
        XCTAssertEqual(joined.issues, [])
        let p = try XCTUnwrap(phone.snapshot.sync)
        XCTAssertEqual(p.groupID, state.groupID)
        XCTAssertEqual(p.key, state.key)
        XCTAssertEqual(Set(p.members), [state.deviceID, p.deviceID])
        let again = fsMac.runOnce(store: mac, random: DetRand("mac2"), clock: FixedClock(now: Self.now + 20))
        XCTAssertEqual(again.issues, [])
        XCTAssertEqual(Set(mac.snapshot.sync!.members), [state.deviceID, p.deviceID])

        // The Mac removes the phone: epoch 2, new password, the phone's files are gone and it is refused.
        let rotated = try fsMac.rotate(store: mac, newPassword: Self.newPassword, remove: [p.deviceID], keep: nil,
                                       random: DetRand("rot"), clock: FixedClock(now: Self.now + 30), derive: Self.cheapKDF)
        XCTAssertEqual(rotated.issues, [])
        let m2 = try XCTUnwrap(mac.snapshot.sync)
        XCTAssertEqual(m2.epoch, 2)
        XCTAssertEqual(m2.members, [m2.deviceID])
        XCTAssertFalse(folder.exists(FolderLayout.deviceFile(p.deviceID)!))
        XCTAssertFalse(folder.exists(FolderLayout.signatureFile(p.deviceID)!))
        let phoneRun = fsPhone.runOnce(store: phone, random: DetRand("p3"), clock: FixedClock(now: Self.now + 40))
        XCTAssertEqual(phoneRun.issues.map(\.kind), ["rejoin-required"])  // not listed at the new epoch
    }

    func testAddFolderToWiFiGroup() throws {
        let wifi = try SyncGroup.createWiFi(installID: "mac-install", random: DetRand("wifi"))
        XCTAssertFalse(wifi.hasFolder)
        XCTAssertEqual(wifi.epoch, 1)
        XCTAssertEqual(wifi.key.count, 32)
        XCTAssertNotNil(wifi.groupID.range(of: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                                           options: .regularExpression))
        XCTAssertNotEqual(wifi.groupID, wifi.deviceID)
        XCTAssertNotEqual(try SyncGroup.createWiFi(installID: "mac-install", random: SystemRandomSource()).groupID, wifi.groupID)

        // A paired Wi-Fi peer holding the same group key (from enrollment), with its own identity.
        var peerState = wifi
        peerState.identity = try DeviceIdentity.generate(random: DetRand("peer"))
        peerState.installID = "peer-install"
        let mac = MemoryStore(StoreSnapshot(sync: wifi)), peer = MemoryStore(StoreSnapshot(sync: peerState))
        let folder = try TempDirFolder()
        let fsMac = try FolderSync(access: folder, installID: "mac-install")
        XCTAssertEqual(fsMac.runOnce(store: mac, random: DetRand("r"), clock: FixedClock(now: Self.now)).issues.map(\.kind),
                       ["folder-missing"])
        let report = try fsMac.addFolder(toGroup: mac, password: Self.password, deviceName: "Mac", freshKey: false,
                                         random: DetRand("add"), clock: FixedClock(now: Self.now), derive: Self.cheapKDF)
        XCTAssertEqual(report.issues, [])
        let m = try XCTUnwrap(mac.snapshot.sync)
        XCTAssertTrue(m.hasFolder)
        XCTAssertEqual(m.epoch, 1); XCTAssertEqual(m.key, wifi.key); XCTAssertEqual(m.identity, wifi.identity)
        let ring = try Keyring.parse(try folder.read(FolderLayout.keyringPath, limit: 1 << 20))
        XCTAssertEqual(Keyring.obj(ring)["prev_mac"], .null)
        XCTAssertEqual(try Keyring.accept(ring, trusted: try wifi.groupKey(), identity: wifi.identity), try wifi.groupKey())
        XCTAssertEqual(reason { try fsMac.addFolder(toGroup: mac, password: Self.password, deviceName: "Mac", freshKey: false,
                                                    random: DetRand("x"), clock: FixedClock(now: Self.now), derive: Self.cheapKDF) },
                       "already-has-folder")

        // The peer adds the same folder: it attaches with the password and keeps its identity.
        let fsPeer = try FolderSync(access: folder, installID: "peer-install")
        let attached = try fsPeer.addFolder(toGroup: peer, password: Self.password, deviceName: "Laptop", freshKey: false,
                                            random: DetRand("peer-add"), clock: FixedClock(now: Self.now + 5), derive: Self.cheapKDF)
        XCTAssertEqual(attached.issues, [])
        XCTAssertEqual(peer.snapshot.sync!.identity, peerState.identity)
        XCTAssertEqual(Set(peer.snapshot.sync!.members), [wifi.deviceID, peerState.deviceID])

        // Audit M9: with a removed Wi-Fi peer the stored key may not protect a folder, unless a fresh key is chosen.
        var removed = try SyncGroup.createWiFi(installID: "mac-install", random: DetRand("wifi2"))
        removed.lanPeers = [LanPeer(deviceID: "gone-1", groupID: removed.groupID, signingPublic: Array(repeating: 1, count: 32),
                                    exchangePublic: Array(repeating: 2, count: 32), revoked: true)]
        let store = MemoryStore(StoreSnapshot(sync: removed))
        let other = try FolderSync(access: try TempDirFolder(), installID: "mac-install")
        XCTAssertEqual(reason { try other.addFolder(toGroup: store, password: Self.password, deviceName: "Mac", freshKey: false,
                                                    random: DetRand("x"), clock: FixedClock(now: Self.now), derive: Self.cheapKDF) },
                       "lan-peer-removed")
        XCTAssertEqual(store.commits, 0)
        _ = try other.addFolder(toGroup: store, password: Self.password, deviceName: "Mac", freshKey: true,
                                random: DetRand("fresh"), clock: FixedClock(now: Self.now), derive: Self.cheapKDF)
        XCTAssertEqual(store.snapshot.sync!.epoch, 2)
        XCTAssertNotEqual(store.snapshot.sync!.key, removed.key)
        XCTAssertEqual(store.snapshot.sync!.groupID, removed.groupID)
    }

    // MARK: limits and refusals

    func testMemberLimit16() throws {
        let a = try KeyringTests.identity("A")
        var (ring, gk) = try Keyring.create(password: Self.password, identity: a, name: "Mac", groupID: nil,
                                            random: DetRand("limit"), now: FixedClock(now: Self.now), derive: Self.cheapKDF)
        for i in 1..<Keyring.maxMembers {
            let id = try DeviceIdentity.generate(random: DetRand("member-\(i)"))
            (ring, _) = try Keyring.join(ring, identity: id, name: "Device \(i)", random: DetRand("j\(i)"),
                                         now: FixedClock(now: Self.now + Int64(i)), passwordKey: { try Self.cheapKey(Self.password)(ring) })
        }
        XCTAssertEqual(Keyring.arr(Keyring.obj(ring)["members"]).count, 16)
        XCTAssertNoThrow(try Keyring.parse(try CanonicalJSON.encode(ring, dialect: .utf8)))
        let extra = try DeviceIdentity.generate(random: DetRand("member-17"))
        XCTAssertEqual(reason { try Keyring.join(ring, identity: extra, name: "One too many", random: DetRand("j17"),
                                                 now: FixedClock(now: Self.now), passwordKey: { try Self.cheapKey(Self.password)(ring) }) },
                       "too-many-members")
        // A rotation keeps all 16 (and re-encrypts their names).
        let (rotated, newKey) = try Keyring.rotate(ring, trusted: gk, identity: a, newPassword: Self.newPassword, remove: [],
                                                   random: DetRand("rot16"), derive: Self.cheapKDF)
        XCTAssertEqual(Keyring.arr(Keyring.obj(rotated)["members"]).count, 16)
        XCTAssertFalse(Keyring.memberNames(rotated, key: newKey).values.contains(nil))
        gk = newKey
        XCTAssertEqual(try Keyring.accept(rotated, trusted: gk, identity: a), gk)
    }

    func testWrongPasswordRefused() throws {
        let folder = try TempDirFolder()
        let mac = MemoryStore()
        let fs = try FolderSync(access: folder, installID: "mac-install")
        XCTAssertEqual(reason { try fs.create(store: mac, password: "tooshort", deviceName: "Mac", random: DetRand("w"),
                                              clock: FixedClock(now: Self.now), derive: Self.cheapKDF) }, "weak-password")
        XCTAssertEqual(reason { try fs.create(store: mac, password: "aaaaaaaaaaaaaaaa", deviceName: "Mac", random: DetRand("w"),
                                              clock: FixedClock(now: Self.now), derive: Self.cheapKDF) }, "weak-password")
        XCTAssertEqual(reason { try fs.create(store: mac, password: Self.password, deviceName: "", random: DetRand("w"),
                                              clock: FixedClock(now: Self.now), derive: Self.cheapKDF) }, "bad-name")
        XCTAssertFalse(folder.exists(FolderLayout.keyringPath))
        XCTAssertEqual(mac.commits, 0)
        _ = try fs.create(store: mac, password: Self.password, deviceName: "Mac", random: DetRand("ok"),
                          clock: FixedClock(now: Self.now), derive: Self.cheapKDF)
        let before = try folder.read(FolderLayout.keyringPath, limit: 1 << 20)

        // A wrong password on the joining device: nothing written, nothing stored.
        let phone = MemoryStore()
        let fsPhone = try FolderSync(access: folder, installID: "phone-install")
        XCTAssertEqual(reason { try fsPhone.join(store: phone, deviceName: "iPhone", random: DetRand("p"),
                                                 clock: FixedClock(now: Self.now), passwordKey: Self.cheapKey("not the sync password 99")) },
                       "password")
        XCTAssertEqual(try folder.read(FolderLayout.keyringPath, limit: 1 << 20), before)
        XCTAssertEqual(phone.commits, 0)

        // Rotating: the current password again, a weak one, removing itself or a stranger.
        let commits = mac.commits
        for (pw, remove, want) in [(Self.password, [String](), "password-reused"), ("weak", [], "weak-password"),
                                   (Self.newPassword, [mac.snapshot.sync!.deviceID], "cannot-remove-self"),
                                   (Self.newPassword, ["not-a-member"], "not-member")] {
            XCTAssertEqual(reason { try fs.rotate(store: mac, newPassword: pw, remove: remove, keep: nil, random: DetRand("r"),
                                                  clock: FixedClock(now: Self.now), derive: Self.cheapKDF) }, want)
        }
        XCTAssertEqual(try folder.read(FolderLayout.keyringPath, limit: 1 << 20), before)
        XCTAssertEqual(mac.commits, commits)

        // Changing the password: the old one no longer opens the keyring, the new one does.
        _ = try fs.rotate(store: mac, newPassword: Self.newPassword, remove: [], keep: nil, random: DetRand("cp"),
                          clock: FixedClock(now: Self.now + 1), derive: Self.cheapKDF)
        let ring = try Keyring.parse(try folder.read(FolderLayout.keyringPath, limit: 1 << 20))
        XCTAssertEqual(reason { try Keyring.unwrap(ring, passwordKey: try Self.cheapKey(Self.password)(ring)) }, "password")
        XCTAssertEqual(try Keyring.unwrap(ring, passwordKey: try Self.cheapKey(Self.newPassword)(ring)).epoch, 2)
    }

    /// Audit M10: a device about to be removed adds a member it controls at the same epoch; a rotation with
    /// no explicit `keep` must not wrap the new key to it until the user confirms it.
    func testRotationSkipsUnconfirmedMembers() throws {
        func scenario(confirmC: Bool) throws -> (JSONValue, mac: String, b: String, c: String) {
            let folder = try TempDirFolder()
            let mac = MemoryStore(), laptop = MemoryStore()
            let fsMac = try FolderSync(access: folder, installID: "mac-install")
            _ = try fsMac.create(store: mac, password: Self.password, deviceName: "Mac", random: DetRand("m"),
                                 clock: FixedClock(now: Self.now), derive: Self.cheapKDF)
            let fsB = try FolderSync(access: folder, installID: "b-install")
            _ = try fsB.join(store: laptop, deviceName: "Laptop", random: DetRand("b"), clock: FixedClock(now: Self.now + 1),
                             passwordKey: Self.cheapKey(Self.password))
            let b = laptop.snapshot.sync!.deviceID
            _ = fsMac.runOnce(store: mac, random: DetRand("m1"), clock: FixedClock(now: Self.now + 2))
            XCTAssertEqual(mac.snapshot.sync!.unackedMembers, [b])
            XCTAssertEqual(try fsMac.acknowledgeMembers(store: mac, [b]), 1)
            // B (holding the group key) adds C, a member it controls, at the same epoch.
            let raw = try folder.read(FolderLayout.keyringPath, limit: 1 << 20)
            let ring = try Keyring.parse(raw)
            let c = try DeviceIdentity.generate(random: DetRand("c"))
            let (withC, _) = try Keyring.join(ring, identity: c, name: "Sock puppet", random: DetRand("cj"),
                                              now: FixedClock(now: Self.now + 3), passwordKey: { try Self.cheapKey(Self.password)(ring) })
            try folder.writeAtomic(FolderLayout.keyringPath, try CanonicalJSON.encode(withC, dialect: .utf8))
            _ = fsMac.runOnce(store: mac, random: DetRand("m2"), clock: FixedClock(now: Self.now + 4))
            XCTAssertEqual(mac.snapshot.sync!.unackedMembers, [c.deviceID])
            XCTAssertTrue(mac.snapshot.sync!.members.contains(c.deviceID))
            if confirmC { XCTAssertEqual(try fsMac.acknowledgeMembers(store: mac, [c.deviceID, "someone-else"]), 1) }
            _ = try fsMac.rotate(store: mac, newPassword: Self.newPassword, remove: [b], keep: nil, random: DetRand("rot"),
                                 clock: FixedClock(now: Self.now + 5), derive: Self.cheapKDF)
            XCTAssertEqual(mac.snapshot.sync!.unackedMembers, [])
            return (try Keyring.parse(try folder.read(FolderLayout.keyringPath, limit: 1 << 20)), mac.snapshot.sync!.deviceID, b, c.deviceID)
        }
        let (unconfirmed, mac, _, c) = try scenario(confirmC: false)
        XCTAssertEqual(FolderSync.memberIDs(unconfirmed), [mac])
        XCTAssertNil(Keyring.obj(Keyring.obj(unconfirmed)["device_wraps"])[c])
        let (confirmed, mac2, b2, c2) = try scenario(confirmC: true)
        XCTAssertEqual(FolderSync.memberIDs(confirmed), [mac2, c2])
        XCTAssertFalse(FolderSync.memberIDs(confirmed).contains(b2))
    }
}
