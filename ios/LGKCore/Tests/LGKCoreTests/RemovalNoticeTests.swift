import XCTest
import Foundation
import Crypto
@testable import LGKCore

/// A watch file in memory (what the apps keep next to the vault).
final class MemoryWatchStore: RemovalWatchStore, @unchecked Sendable {
    let folder = "/Users/Alex/Library/Mobile Documents/com~apple~CloudDocs/LGK"
    private let lock = NSLock()
    private var bytes: [UInt8]?
    private(set) var saves = 0
    func load() -> [UInt8]? { lock.withLock { bytes } }
    func save(_ data: [UInt8]) { lock.withLock { bytes = data; saves += 1 } }
    func forget() { lock.withLock { bytes = nil } }
}

/// Signed removal notices and the watch file against `tests/vectors/sync/removal` (desktop `removal.py`), then the
/// folder flow: the remover writes a notice, the removed device reports `removal-notice`, nobody else does.
final class RemovalNoticeTests: XCTestCase {
    static func load(_ name: String) throws -> [String: JSONValue] {
        KeyringTests.obj(try CanonicalJSON.parse(Array(Vectors.data("removal/\(name)"))))
    }
    static func o(_ v: JSONValue?) -> [String: JSONValue] { KeyringTests.obj(v) }
    static func s(_ v: JSONValue?) -> String { KeyringTests.str(v) }
    static func a(_ v: JSONValue?) -> [JSONValue] { if case .array(let x)? = v { return x }; return [] }
    static func i(_ v: JSONValue?) -> Int64 { if case .int(let n)? = v { return n }; return -1 }
    static func b64(_ v: JSONValue?) throws -> [UInt8] { try Base64.decodeStrict(s(v)) }

    /// A vector watch object as a `RemovalWatch`, field by field (not through `parse`, so bad keys stay as they are).
    static func watch(_ v: JSONValue?) -> RemovalWatch {
        let w = o(v)
        var signers: [String: String] = [:]
        for (id, key) in o(w["signers"]) { signers[id] = s(key) }
        return RemovalWatch(groupID: s(w["group_id"]), deviceID: s(w["device_id"]), epoch: i(w["epoch"]),
                            installID: s(w["install_id"]), folder: s(w["folder"]), signers: signers)
    }

    static func body(_ v: JSONValue?) -> RemovalNoticeBody {
        let n = o(v)
        return RemovalNoticeBody(groupID: s(n["group_id"]), deviceID: s(n["device_id"]), epoch: i(n["epoch"]),
                                 signer: s(n["signer"]), issuedAt: i(n["issued_at"]))
    }

    func testConstantsMatchTheDesktop() throws {
        let c = Self.o(try Self.load("notices.json")["constants"])
        XCTAssertEqual(RemovalNotice.format, Self.i(c["notice_format"]))
        XCTAssertEqual(RemovalNotice.label, Array(Self.s(c["notice_label"]).utf8))
        XCTAssertEqual(Int64(RemovalNotice.maxBytes), Self.i(c["max_notice_bytes"]))
        XCTAssertEqual(Int64(Keyring.maxKeyringBytes), Self.i(c["max_keyring_bytes"]))
        XCTAssertEqual(RemovalNotice.maxInt, Self.i(c["max_int"]))
        XCTAssertEqual(RemovalNotice.removedDirName, Self.s(c["removed_dir"]))
        XCTAssertEqual(RemovalNotice.suffix, Self.s(c["notice_suffix"]))
        let w = Self.o(try Self.load("watch.json")["constants"])
        XCTAssertEqual(RemovalWatch.version, Self.i(w["watch_version"]))
        XCTAssertEqual(RemovalWatch.suffix, Self.s(w["watch_suffix"]))
        XCTAssertEqual(Int64(RemovalWatch.maxBytes), Self.i(w["max_watch_bytes"]))
    }

    func testIdentitiesDeriveTheirPublicKeys() throws {
        for (name, value) in Self.o(try Self.load("notices.json")["identities"]) {
            let id = Self.o(value)
            let identity = try DeviceIdentity(deviceID: Self.s(id["device_id"]), signingPrivate: try Self.b64(id["signing_private_seed_b64"]),
                                              exchangePrivate: [UInt8](repeating: 7, count: 32))
            XCTAssertEqual(Base64.encode(identity.signingPublicKey), Self.s(id["signing_public_b64"]), name)
        }
    }

    /// Every case of notices.json: accepted with its fields, or refused with the desktop reason.
    func testEveryNoticeVector() throws {
        let v = try Self.load("notices.json")
        let watches = Self.o(v["watches"]), rings = Self.o(v["keyrings"])
        let cases = Self.a(v["cases"])
        XCTAssertEqual(cases.count, 80)
        var accepted = 0
        for c in cases {
            let co = Self.o(c)
            let name = Self.s(co["name"])
            let raw = try Self.b64(co["notice_b64"])
            guard watches[Self.s(co["watch"])] != nil, let ringEntry = rings[Self.s(co["folder_keyring"])] else {
                XCTFail("\(name): unknown watch or keyring"); continue
            }
            let watch = Self.watch(watches[Self.s(co["watch"])])
            let ring = try Self.b64(Self.o(ringEntry)["b64"])
            let expected = Self.o(co["expected"])
            do {
                let notice = try RemovalNotice.verify(raw, watch: watch, folderKeyring: ring)
                XCTAssertEqual(expected["accept"], .bool(true), name)
                XCTAssertEqual(notice, Self.body(expected["notice"]), name)
                accepted += 1
            } catch let e as RemovalError {
                XCTAssertEqual(expected["accept"], .bool(false), name)
                XCTAssertEqual(expected["reason"], .string(e.reason), name)
            }
        }
        XCTAssertEqual(accepted, 10)
    }

    /// `check` reads the notice and the keyring from the folder; another installation never accepts.
    func testCheckReadsTheFolder() throws {
        let v = try Self.load("notices.json")
        let valid = Self.o(Self.a(v["cases"]).first { Self.s(Self.o($0)["name"]) == "valid" })
        let watch = Self.watch(Self.o(v["watches"])["trusted_c"])
        let folder = MemoryFolder()
        folder.files[FolderLayout.keyringPath] = try Self.b64(Self.o(Self.o(v["keyrings"])["folder_epoch2"])["b64"])
        XCTAssertNil(RemovalNotice.check(watch, access: folder, installID: watch.installID))   // no notice yet
        folder.files[RemovalNotice.path(watch.deviceID)!] = try Self.b64(valid["notice_b64"])
        XCTAssertEqual(RemovalNotice.check(watch, access: folder, installID: watch.installID), Self.body(Self.o(valid["expected"])["notice"]))
        XCTAssertNil(RemovalNotice.check(watch, access: folder, installID: "another-install"))
        folder.files[FolderLayout.keyringPath] = try Self.b64(Self.o(Self.o(v["keyrings"])["trusted_epoch1"])["b64"])
        XCTAssertNil(RemovalNotice.check(watch, access: folder, installID: watch.installID))   // keyring still lists C
    }

    /// writer.json: path, body, signed message and (with the desktop's deterministic signature) the exact bytes; the
    /// notice CryptoKit signs differs only in its (hedged) signature, which verifies. Refusals: `bad-notice`.
    func testWriterMatchesTheDesktop() throws {
        let v = try Self.load("writer.json")
        let cases = Self.a(v["cases"])
        XCTAssertFalse(cases.isEmpty)
        for c in cases {
            let co = Self.o(c), inputs = Self.o(co["inputs"])
            let body = Self.body(co["inputs"])
            let what = Self.s(co["description"])
            XCTAssertEqual(RemovalNotice.path(body.deviceID), Self.s(co["path"]), what)
            XCTAssertEqual(try CanonicalJSON.encode(.object(RemovalNotice.body(body)), dialect: .utf8),
                           Array(Self.s(co["body_canonical"]).utf8), what)
            XCTAssertEqual(try RemovalNotice.message(body), Vectors.hex(Self.s(co["signed_message_hex"])), what)
            let desktopSig = try Self.b64(co["sig_b64"])
            let exact = try RemovalNotice.make(body) { _ in desktopSig }
            XCTAssertEqual(exact, Array(Self.s(co["notice_text"]).utf8), what)
            XCTAssertEqual(Vectors.hexString(Array(SHA256.hash(data: exact))), Self.s(co["notice_sha256"]), what)

            let identity = try DeviceIdentity(deviceID: body.signer, signingPrivate: try Self.b64(inputs["signing_private_seed_b64"]),
                                              exchangePrivate: [UInt8](repeating: 7, count: 32))
            XCTAssertTrue(DeviceIdentity.verify(signature: desktopSig, message: try RemovalNotice.message(body),
                                                publicKey: identity.signingPublicKey), what)
            let own = try RemovalNotice.make(identity: identity, groupID: body.groupID, deviceID: body.deviceID,
                                             epoch: body.epoch, issuedAt: body.issuedAt)
            let parsed = try RemovalNotice.parse(own)
            XCTAssertEqual(parsed.notice, body, what)
            XCTAssertTrue(DeviceIdentity.verify(signature: parsed.signature, message: parsed.message,
                                                publicKey: identity.signingPublicKey), what)
            let swapped = String(decoding: own, as: UTF8.self)
                .replacingOccurrences(of: Base64.encode(parsed.signature), with: Base64.encode(desktopSig))
            XCTAssertEqual(swapped, Self.s(co["notice_text"]), what)
        }
        let refusals = Self.a(v["refusals"])
        XCTAssertFalse(refusals.isEmpty)
        for r in refusals {
            let ro = Self.o(r)
            XCTAssertThrowsError(try RemovalNotice.make(Self.body(ro["inputs"])) { _ in [UInt8](repeating: 1, count: 64) },
                                 Self.s(ro["description"])) { error in
                XCTAssertEqual((error as? RemovalError)?.reason, Self.s(ro["error"]))
            }
        }
    }

    /// watch.json: file names, the canonical file, derive, parse and pinning.
    func testWatchVectors() throws {
        let v = try Self.load("watch.json")
        let rings = Self.o(try Self.load("notices.json")["keyrings"])
        for p in Self.a(v["paths"]) {
            XCTAssertEqual(RemovalWatch.fileName(forVault: Self.s(Self.o(p)["vault"])), Self.s(Self.o(p)["watch"]))
        }
        let example = Self.o(v["example"])
        let text = Array(Self.s(example["watch_text"]).utf8)
        XCTAssertEqual(Self.watch(example["parsed"]).encoded(), text)
        XCTAssertEqual(RemovalWatch.parse(text), Self.watch(example["parsed"]))

        let derive = Self.a(v["derive"])
        XCTAssertFalse(derive.isEmpty)
        for d in derive {
            let dob = Self.o(d), st = Self.o(dob["state"])
            let name = Self.s(dob["name"])
            let ring = try Self.b64(Self.o(rings[Self.s(st["keyring"])])["b64"])
            let w = RemovalWatch.derive(groupID: Self.s(st["group_id"]), deviceID: Self.s(st["device_id"]), epoch: Self.i(st["epoch"]),
                                        installID: Self.s(st["install_id"]), keyring: ring,
                                        unacked: Self.a(st["unacked_members"]).map { Self.s($0) }, folder: Self.s(dob["folder"]))
            XCTAssertEqual(w?.encoded(), Array(Self.s(dob["watch_text"]).utf8), name)
        }

        let parse = Self.a(v["parse"])
        XCTAssertFalse(parse.isEmpty)
        for p in parse {
            let po = Self.o(p)
            let name = Self.s(po["name"])
            let got = RemovalWatch.parse(try Self.b64(po["b64"]))
            if po["expected"] == .null { XCTAssertNil(got, name) } else { XCTAssertEqual(got, Self.watch(po["expected"]), name) }
        }

        let pinned = Self.a(v["pinned"])
        XCTAssertFalse(pinned.isEmpty)
        for p in pinned {
            let po = Self.o(p)
            let old: RemovalWatch? = po["old"] == .null ? nil : Self.watch(po["old"])
            XCTAssertEqual(RemovalWatch.pinned(Self.watch(po["fresh"]), old: old), Self.watch(po["expected"]), Self.s(po["name"]))
        }
    }

    // MARK: folder flow

    func testRemovedDeviceSeesTheNoticeAndRejoinedDeviceDoesNot() throws {
        let folder = try TempDirFolder()
        let mac = MemoryStore(), phone = MemoryStore()
        let now = GroupCreateTests.now
        let fsMac = try FolderSync(access: folder, installID: "mac-install")
        _ = try fsMac.create(store: mac, password: GroupCreateTests.password, deviceName: "Mac", random: DetRand("mac"),
                             clock: FixedClock(now: now), derive: GroupCreateTests.cheapKDF)
        let macID = try XCTUnwrap(mac.snapshot.sync).deviceID
        let watch = MemoryWatchStore()
        let fsPhone = try FolderSync(access: folder, installID: "phone-install", removalWatch: watch)
        _ = try fsPhone.join(store: phone, deviceName: "iPhone", random: DetRand("phone"), clock: FixedClock(now: now + 10),
                             passwordKey: GroupCreateTests.cheapKey(GroupCreateTests.password))
        let phoneID = try XCTUnwrap(phone.snapshot.sync).deviceID
        _ = fsMac.runOnce(store: mac, random: DetRand("m1"), clock: FixedClock(now: now + 20))
        // The phone's watch: its group, epoch 1, the Mac's key; never its own.
        let stored = try XCTUnwrap(watch.load().flatMap(RemovalWatch.parse))
        XCTAssertEqual(stored.deviceID, phoneID)
        XCTAssertEqual(stored.epoch, 1)
        XCTAssertEqual(stored.installID, "phone-install")
        XCTAssertEqual(stored.folder, watch.folder)
        XCTAssertEqual(Array(stored.signers.keys), [macID])
        let saves = watch.saves
        _ = fsPhone.runOnce(store: phone, random: DetRand("p1"), clock: FixedClock(now: now + 25))
        XCTAssertEqual(watch.saves, saves)   // unchanged content is not written again

        // The Mac removes the phone: a notice signed by the Mac for epoch 2.
        _ = try fsMac.rotate(store: mac, newPassword: GroupCreateTests.newPassword, remove: [phoneID], keep: nil,
                             random: DetRand("rot"), clock: FixedClock(now: now + 30), derive: GroupCreateTests.cheapKDF)
        let raw = try folder.read(try XCTUnwrap(RemovalNotice.path(phoneID)), limit: RemovalNotice.maxBytes + 1)
        let notice = try RemovalNotice.parse(raw).notice
        XCTAssertEqual(notice, RemovalNoticeBody(groupID: stored.groupID, deviceID: phoneID, epoch: 2, signer: macID, issuedAt: now + 30))
        XCTAssertNil(RemovalNotice.path(macID).flatMap { folder.exists($0) ? $0 : nil })   // none for the remover
        // The Mac's own run reports nothing about it.
        XCTAssertFalse(fsMac.runOnce(store: mac, random: DetRand("m2"), clock: FixedClock(now: now + 35)).issues
            .contains { $0.kind == RemovalNotice.issueKind })

        // The phone: rejoin-required, and the verified notice (signer: the Mac); the watch keeps epoch 1.
        let run = fsPhone.runOnce(store: phone, random: DetRand("p2"), clock: FixedClock(now: now + 40))
        XCTAssertEqual(run.issues.map(\.kind), ["rejoin-required", RemovalNotice.issueKind])
        XCTAssertEqual(run.issues.last?.detail, macID)
        let locked = try XCTUnwrap(watch.load().flatMap(RemovalWatch.parse))
        XCTAssertEqual(locked.epoch, 1)
        XCTAssertEqual(RemovalNotice.check(locked, access: folder, installID: "phone-install")?.signer, macID)
        XCTAssertNil(RemovalNotice.check(locked, access: folder, installID: "restored-install"))

        // Joined again with the new password: a new device id, so the old notice no longer applies.
        _ = try fsPhone.join(store: phone, deviceName: "iPhone", random: DetRand("phone-again"), clock: FixedClock(now: now + 50),
                             passwordKey: GroupCreateTests.cheapKey(GroupCreateTests.newPassword))
        let rejoined = fsPhone.runOnce(store: phone, random: DetRand("p3"), clock: FixedClock(now: now + 60))
        XCTAssertFalse(rejoined.issues.contains { $0.kind == RemovalNotice.issueKind })
        let fresh = try XCTUnwrap(watch.load().flatMap(RemovalWatch.parse))
        XCTAssertNotEqual(fresh.deviceID, phoneID)
        XCTAssertEqual(fresh.epoch, 2)
        XCTAssertNil(RemovalNotice.check(fresh, access: folder, installID: "phone-install"))

        // Left sync (no group in the store): the watch file goes.
        let snap = phone.snapshot
        try phone.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: nil))
        XCTAssertEqual(fsPhone.runOnce(store: phone, random: DetRand("p4"), clock: FixedClock(now: now + 70)).issues.map(\.kind), ["not-joined"])
        XCTAssertNil(watch.load())
    }

    /// A notice signed by a stranger's key in the Mac's name is refused (`bad-signature`), and a watch never lists an
    /// unconfirmed member as a signer.
    func testForgedSignerAndUnconfirmedMembersAreNoSigners() throws {
        let folder = try TempDirFolder()
        let mac = MemoryStore(), phone = MemoryStore()
        let now = GroupCreateTests.now
        let fsMac = try FolderSync(access: folder, installID: "mac-install")
        _ = try fsMac.create(store: mac, password: GroupCreateTests.password, deviceName: "Mac", random: DetRand("mac"),
                             clock: FixedClock(now: now), derive: GroupCreateTests.cheapKDF)
        let fsPhone = try FolderSync(access: folder, installID: "phone-install")
        _ = try fsPhone.join(store: phone, deviceName: "iPhone", random: DetRand("phone"), clock: FixedClock(now: now + 10),
                             passwordKey: GroupCreateTests.cheapKey(GroupCreateTests.password))
        let state = try XCTUnwrap(phone.snapshot.sync)
        // A forged notice by a stranger in the Mac's name, next to the real (still listing) keyring.
        let stranger = try DeviceIdentity.generate(deviceID: mac.snapshot.sync!.deviceID, random: DetRand("stranger"))
        let forged = try RemovalNotice.make(identity: stranger, groupID: state.groupID, deviceID: state.deviceID, epoch: 2, issuedAt: now)
        try folder.writeAtomic(RemovalNotice.path(state.deviceID)!, forged)
        let run = fsPhone.runOnce(store: phone, random: DetRand("p1"), clock: FixedClock(now: now + 20))
        XCTAssertFalse(run.issues.contains { $0.kind == RemovalNotice.issueKind })
        let w = try XCTUnwrap(RemovalWatch.derive(state, folder: "x"))
        XCTAssertThrowsError(try RemovalNotice.verify(forged, watch: w, folderKeyring: try folder.read(FolderLayout.keyringPath, limit: 1 << 20))) {
            XCTAssertEqual(($0 as? RemovalError)?.reason, "bad-signature")
        }
        // The phone's watch lists no unconfirmed member.
        var unconfirmed = state
        unconfirmed.unackedMembers = [mac.snapshot.sync!.deviceID]
        XCTAssertEqual(RemovalWatch.derive(unconfirmed, folder: "x")?.signers, [:])
    }

    /// A notice really signed by a member this Mac never confirmed (the phone, which joined on its own): its key is not
    /// in the Mac's watch, so the notice is refused as `unknown-signer` and no run reports a removal.
    func testNoticeFromAnUnconfirmedMemberIsRefused() throws {
        let folder = try TempDirFolder()
        let mac = MemoryStore(), phone = MemoryStore()
        let now = GroupCreateTests.now
        let macWatch = MemoryWatchStore()
        let fsMac = try FolderSync(access: folder, installID: "mac-install", removalWatch: macWatch)
        _ = try fsMac.create(store: mac, password: GroupCreateTests.password, deviceName: "Mac", random: DetRand("mac"),
                             clock: FixedClock(now: now), derive: GroupCreateTests.cheapKDF)
        let macID = try XCTUnwrap(mac.snapshot.sync).deviceID
        let fsPhone = try FolderSync(access: folder, installID: "phone-install")
        _ = try fsPhone.join(store: phone, deviceName: "iPhone", random: DetRand("phone"), clock: FixedClock(now: now + 10),
                             passwordKey: GroupCreateTests.cheapKey(GroupCreateTests.password))
        let phoneID = try XCTUnwrap(phone.snapshot.sync).deviceID
        _ = fsMac.runOnce(store: mac, random: DetRand("m1"), clock: FixedClock(now: now + 20))
        XCTAssertEqual(mac.snapshot.sync?.unackedMembers, [phoneID])
        // What the Mac's run keeps as its watch: epoch 1 and no signer (the phone is unconfirmed).
        let watch = try XCTUnwrap(RemovalWatch.derive(try XCTUnwrap(mac.snapshot.sync), folder: macWatch.folder))
        XCTAssertEqual(watch.epoch, 1)
        XCTAssertEqual(watch.signers, [:])
        if let stored = macWatch.load().flatMap(RemovalWatch.parse) { XCTAssertEqual(stored.signers, [:]) }

        // The phone (holding the group key) removes the Mac: a genuine notice with the phone's own key, epoch 2.
        _ = try fsPhone.rotate(store: phone, newPassword: GroupCreateTests.newPassword, remove: [macID], keep: nil,
                               random: DetRand("rot"), clock: FixedClock(now: now + 30), derive: GroupCreateTests.cheapKDF)
        let raw = try folder.read(try XCTUnwrap(RemovalNotice.path(macID)), limit: RemovalNotice.maxBytes + 1)
        let parsed = try RemovalNotice.parse(raw)
        XCTAssertEqual(parsed.notice.signer, phoneID)
        XCTAssertEqual(parsed.notice.epoch, 2)
        XCTAssertTrue(DeviceIdentity.verify(signature: parsed.signature, message: parsed.message,
                                            publicKey: try XCTUnwrap(phone.snapshot.sync).identity.signingPublicKey))
        let ring = try folder.read(FolderLayout.keyringPath, limit: 1 << 20)
        XCTAssertThrowsError(try RemovalNotice.verify(raw, watch: watch, folderKeyring: ring)) {
            XCTAssertEqual(($0 as? RemovalError)?.reason, "unknown-signer")
        }
        XCTAssertNil(RemovalNotice.check(watch, access: folder, installID: "mac-install"))
        let run = fsMac.runOnce(store: mac, random: DetRand("m2"), clock: FixedClock(now: now + 40))
        XCTAssertFalse(run.issues.contains { $0.kind == RemovalNotice.issueKind })
    }

    /// A notice with a real signer's key and a newer epoch is still refused (`keyring`) while the folder keyring at that
    /// epoch lists this device: a password change that kept the phone is no removal, and its run reports none.
    func testKeyringThatStillListsTheDeviceRefusesTheNotice() throws {
        let folder = try TempDirFolder()
        let mac = MemoryStore(), phone = MemoryStore()
        let now = GroupCreateTests.now
        let fsMac = try FolderSync(access: folder, installID: "mac-install")
        _ = try fsMac.create(store: mac, password: GroupCreateTests.password, deviceName: "Mac", random: DetRand("mac"),
                             clock: FixedClock(now: now), derive: GroupCreateTests.cheapKDF)
        let macID = try XCTUnwrap(mac.snapshot.sync).deviceID
        let phoneWatch = MemoryWatchStore()
        let fsPhone = try FolderSync(access: folder, installID: "phone-install", removalWatch: phoneWatch)
        _ = try fsPhone.join(store: phone, deviceName: "iPhone", random: DetRand("phone"), clock: FixedClock(now: now + 10),
                             passwordKey: GroupCreateTests.cheapKey(GroupCreateTests.password))
        let phoneID = try XCTUnwrap(phone.snapshot.sync).deviceID
        _ = fsPhone.runOnce(store: phone, random: DetRand("p1"), clock: FixedClock(now: now + 15))
        _ = fsMac.runOnce(store: mac, random: DetRand("m1"), clock: FixedClock(now: now + 20))
        XCTAssertEqual(try fsMac.acknowledgeMembers(store: mac, [phoneID]), 1)
        let watch = try XCTUnwrap(phoneWatch.load().flatMap(RemovalWatch.parse))
        XCTAssertEqual(watch.epoch, 1)
        XCTAssertEqual(Array(watch.signers.keys), [macID])

        // A password change that removes nobody: epoch 2, the phone still listed, no notice written.
        _ = try fsMac.rotate(store: mac, newPassword: GroupCreateTests.newPassword, remove: [], keep: nil,
                             random: DetRand("cp"), clock: FixedClock(now: now + 30), derive: GroupCreateTests.cheapKDF)
        XCTAssertEqual(mac.snapshot.sync?.epoch, 2)
        XCTAssertTrue(try XCTUnwrap(mac.snapshot.sync).members.contains(phoneID))
        XCTAssertFalse(folder.exists(try XCTUnwrap(RemovalNotice.path(phoneID))))

        // A notice for the phone at epoch 2, signed with the Mac's real key (a buggy or hostile member could write it).
        let macState = try XCTUnwrap(mac.snapshot.sync)
        let notice = try RemovalNotice.make(identity: macState.identity, groupID: macState.groupID, deviceID: phoneID,
                                            epoch: 2, issuedAt: now + 40)
        try folder.writeAtomic(try XCTUnwrap(RemovalNotice.path(phoneID)), notice)
        let ring = try folder.read(FolderLayout.keyringPath, limit: 1 << 20)
        XCTAssertThrowsError(try RemovalNotice.verify(notice, watch: watch, folderKeyring: ring)) {
            XCTAssertEqual(($0 as? RemovalError)?.reason, "keyring")
        }
        XCTAssertNil(RemovalNotice.check(watch, access: folder, installID: "phone-install"))
        let run = fsPhone.runOnce(store: phone, random: DetRand("p2"), clock: FixedClock(now: now + 50))
        XCTAssertFalse(run.issues.contains { $0.kind == RemovalNotice.issueKind })
    }
}
