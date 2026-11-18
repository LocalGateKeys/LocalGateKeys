import XCTest
@testable import LGKCore

/// The folder flow (port of tests/test_heir_flow.py, the parts an iPhone or Mac runs; Android `HeirFlowTest.kt` with
/// the same vectors) and byte parity with the desktop's files.
final class HeirFlowTests: XCTestCase {
    private typealias V = HeirVectors
    private var v: [String: JSONValue] { V.data }
    private var planID: String { V.s("plan_id") }
    private var created: Int64 { V.int(v["created"]) }
    private var dir: String { "LocalGateKeys Emergency/\(planID)" }
    private let random = SystemRandomSource()

    private func sub(_ k: String) -> [String: JSONValue] { V.obj(v[k]) }

    private var identity: RequesterIdentity {
        get throws {
            let r = sub("requester")
            return try RequesterIdentity(signingSeed: Vectors.hex(V.str(r["signing_seed"])), boxKey: Vectors.hex(V.str(r["box_key"])))
        }
    }

    private func planWith(_ edit: (inout [String: JSONValue]) -> Void) throws -> HeirPlan {
        var r = V.obj(v["synced"])
        edit(&r)
        return try Heir.parsePlan(.object(r))
    }

    private var plan: HeirPlan { get throws { try Heir.parsePlan(v["synced"]) } }
    private var fresh: HeirPlan { get throws { try planWith { $0["denied"] = .array([]) } } }

    private func descriptor(_ folder: MemoryFolder) {
        let d = sub("descriptor")
        folder.files["\(dir)/\(V.str(d["file"]))"] = Array(V.str(d["data"]).utf8)
    }

    private func reason(_ body: () throws -> Any) -> String? {
        do { _ = try body(); return nil } catch let e as HeirFlowError { return e.reason } catch { return "other" }
    }

    // MARK: byte parity with the files Python wrote

    func testRequestIsRemadeByteForByteAndVerifiesOnTheOwner() throws {
        let r = sub("request")
        let file = V.str(r["data"])
        let data = try HeirFlow.requestBytes(shard: V.packages[1], identity: try identity, requestID: V.str(r["id"]),
                                             created: V.int(r["created"]), sign: V.signature(of: file))
        XCTAssertEqual(data, Array(file.utf8))
        let folder = MemoryFolder()
        // Signed on this device (randomized signature): the owner still accepts it.
        folder.files["\(dir)/\(V.str(r["file"]))"] = try HeirFlow.requestBytes(shard: V.packages[1], identity: try identity,
                                                                              requestID: V.str(r["id"]), created: V.int(r["created"]))
        let pending = try HeirFlow.pending(plan: try fresh, folder: HeirFolder(access: folder), now: V.int(r["created"]), random: random)
        XCTAssertEqual(pending.requests.count, 1)
        XCTAssertEqual(pending.requests.first?.holder, "Anna")
        XCTAssertEqual(pending.requests.first?.daysLeft, 7)
        XCTAssertEqual(pending.requests.first?.requestID, V.str(r["id"]))
        let record = sub("requester")["record"]
        XCTAssertEqual(try RequesterIdentity.fromRecord(record).toRecord(), record)
    }

    func testDenyAndGrantAreRemadeByteForByteAndTheGrantOpens() throws {
        let r = sub("request"), d = sub("deny"), g = sub("grant")
        XCTAssertEqual(try HeirFlow.denyBytes(plan: try plan, requestID: V.str(r["id"]), now: V.int(d["created"]),
                                              packageID: V.str(d["id"]), sign: V.signature(of: V.str(d["data"]))),
                       Array(V.str(d["data"]).utf8))
        let folder = MemoryFolder()
        folder.files["\(dir)/\(V.str(r["file"]))"] = Array(V.str(r["data"]).utf8)
        let requests = try HeirFlow.pending(plan: try fresh, folder: HeirFolder(access: folder), now: created, random: random).requests
        XCTAssertEqual(requests.count, 1)
        let request = try XCTUnwrap(requests.first)
        let grant = try HeirFlow.grantBytes(plan: try plan, request: request, entropy: V.hex("entropy"), now: V.int(g["created"]),
                                            ephemeralKey: Vectors.hex(V.str(g["ephemeral"])), packageID: V.str(g["id"]),
                                            sign: V.signature(of: V.str(g["data"])))
        XCTAssertEqual(grant, Array(V.str(g["data"]).utf8))
        let opened = try XCTUnwrap(HeirFlow.readGrant(grant))
        XCTAssertEqual(HeirFlow.openGrant(opened, identity: try identity), V.hex("entropy"))
        let stranger = try RequesterIdentity(signingSeed: [UInt8](repeating: 1, count: 32), boxKey: [UInt8](repeating: 2, count: 32))
        XCTAssertNil(HeirFlow.openGrant(opened, identity: stranger))
    }

    func testReadsTheDesktopBackupDescriptor() throws {
        let folder = MemoryFolder()
        descriptor(folder)
        let list = HeirFlow.backups(HeirFolder(access: folder), dir, signer: try plan.signer, planID: planID)
        XCTAssertEqual(list.count, 1)
        XCTAssertEqual(list.first?.writtenAt, V.int(sub("descriptor")["written_at"]))
        XCTAssertEqual(list.first?.backupPublic, V.hex("backup_public"))
        XCTAssertTrue(HeirFlow.backups(HeirFolder(access: folder), dir, signer: [UInt8](repeating: 0, count: 32), planID: planID).isEmpty)
    }

    // MARK: the flow

    func testRequestWaitAndRecoverAfterTheWaitingPeriod() throws {
        let folder = MemoryFolder()
        let f = HeirFolder(access: folder)
        let two = Array(V.packages.prefix(2))
        let id = try identity
        XCTAssertEqual(try HeirFlow.requestStatus(f, packages: two, identity: id, now: created).state, "none")
        XCTAssertEqual(reason { try HeirFlow.recoverEntropy(f, packages: two, identity: id, now: self.created) }, "no-request")
        let now = created + 100
        try HeirFlow.requestAccess(f, shard: V.packages[0], identity: id, now: now, random: random)
        let pending = try HeirFlow.pending(plan: try fresh, folder: f, now: now, random: random)
        XCTAssertEqual(pending.requests.map(\.holder), ["Νίκος"])
        let one = try HeirFlow.requestStatus(f, packages: [V.packages[0]], identity: id, now: now)
        XCTAssertEqual(one, HeirStatus(state: "need-more", planID: planID, owner: V.s("owner"), k: 2, have: 1,
                                       requestID: pending.requests[0].requestID, missing: 1))
        let waiting = try HeirFlow.requestStatus(f, packages: two, identity: id, now: now + HeirFlow.day)
        XCTAssertEqual(waiting.state, "waiting")
        XCTAssertEqual(waiting.daysLeft, 6)
        do {
            _ = try HeirFlow.recoverEntropy(f, packages: two, identity: id, now: now + HeirFlow.day)
            XCTFail("waiting")
        } catch let e as HeirFlowError {
            XCTAssertEqual(e.daysLeft, 6)
        }
        let after = now + 7 * HeirFlow.day
        XCTAssertEqual(try HeirFlow.requestStatus(f, packages: two, identity: id, now: after).state, "no-backup")
        descriptor(folder)
        XCTAssertEqual(try HeirFlow.requestStatus(f, packages: two, identity: id, now: after).state, "ready")
        XCTAssertEqual(try HeirFlow.recoverEntropy(f, packages: two, identity: id, now: after), V.hex("entropy"))
    }

    /// A backup descriptor signed by the plan key, locked to `backupPublic` and written at `writtenAt`.
    private func ownDescriptor(_ folder: MemoryFolder, backupPublic: [UInt8], writtenAt: Int64, tag: String) throws {
        let payload: [String: JSONValue] = [
            "kind": .string(HeirFlow.backupKind), "plan_id": .string(planID),
            "file": .string("backup-20270116-080000-\(tag).lgk"), "size": .int(4096),
            "sha256": .string(String(repeating: "ab", count: 32)), "written_at": .int(writtenAt),
            "backup_public": .string(Envelope.b64e(backupPublic)),
        ]
        let data = try Envelope.seal(format: Heir.format, version: Heir.version,
                                     packageID: "00000000-0000-4000-8000-0000000000\(tag.prefix(2))", sender: "",
                                     payload: payload, seed: V.hex("signing_seed"))
        folder.files["\(dir)/backup-20270116-080000-\(tag).lgkheirbackup"] = data
    }

    /// Two shards, a request and the waiting period over: everything but the backup.
    private func waitedOut(_ folder: MemoryFolder) throws -> Int64 {
        try HeirFlow.requestAccess(HeirFolder(access: folder), shard: V.packages[0], identity: try identity, now: created + 100,
                                   random: random)
        return created + 100 + 7 * HeirFlow.day
    }

    /// Ruling T2-M1: once the owner replaces the phrase, stale shards open nothing, even when no backup exists.
    func testWithoutABackupNewerThanThePlanNothingIsRevealed() throws {
        let folder = MemoryFolder()
        let f = HeirFolder(access: folder)
        let after = try waitedOut(folder)
        let two = Array(V.packages.prefix(2)), id = try identity
        XCTAssertEqual(try HeirFlow.requestStatus(f, packages: two, identity: id, now: after).state, "no-backup")
        XCTAssertEqual(reason { try HeirFlow.recoverEntropy(f, packages: two, identity: id, now: after) }, "no-backup")
        // The right key, but older than the plan (a backup from before the phrase was replaced): still nothing.
        try ownDescriptor(folder, backupPublic: V.hex("backup_public"), writtenAt: created - 1, tag: "0a0b0c0d")
        XCTAssertEqual(try HeirFlow.requestStatus(f, packages: two, identity: id, now: after).state, "no-backup")
        XCTAssertEqual(reason { try HeirFlow.recoverEntropy(f, packages: two, identity: id, now: after) }, "no-backup")
    }

    func testABackupLockedToAnotherKeyRevealsNothing() throws {
        let folder = MemoryFolder()
        let f = HeirFolder(access: folder)
        let after = try waitedOut(folder)
        let two = Array(V.packages.prefix(2)), id = try identity
        // Newer than the plan and signed by the plan key, but locked to another backup key (the phrase was replaced).
        try ownDescriptor(folder, backupPublic: [UInt8](repeating: 7, count: 32), writtenAt: created + 10, tag: "1a1b1c1d")
        XCTAssertEqual(try HeirFlow.requestStatus(f, packages: two, identity: id, now: after).state, "ready")
        XCTAssertEqual(reason { try HeirFlow.recoverEntropy(f, packages: two, identity: id, now: after) }, "no-backup")
        // The owner's own key opens it.
        try ownDescriptor(folder, backupPublic: V.hex("backup_public"), writtenAt: created + 20, tag: "2a2b2c2d")
        XCTAssertEqual(try HeirFlow.recoverEntropy(f, packages: two, identity: id, now: after), V.hex("entropy"))
    }

    /// Ruling F-I1: a stale plan's look deletes the folder's backups, so the old shards open nothing.
    func testAStalePlanDeletesItsBackupsSoOldShardsOpenNothing() throws {
        let folder = MemoryFolder()
        let f = HeirFolder(access: folder)
        let after = try waitedOut(folder)
        let two = Array(V.packages.prefix(2)), id = try identity
        descriptor(folder)
        let name = V.str(sub("descriptor")["file"])
        let file = "\(dir)/\(name.dropLast(HeirFlow.descriptorSuffix.count))\(HeirFlow.backupSuffix)"
        folder.files[file] = [UInt8](repeating: 0, count: 8)
        folder.files["\(dir)/backup-notes.txt"] = [1]
        XCTAssertEqual(try HeirFlow.recoverEntropy(f, packages: two, identity: id, now: after), V.hex("entropy"))
        _ = try HeirFlow.pending(plan: try fresh, folder: f, now: after, random: random) // a current plan keeps them
        XCTAssertNotNil(folder.files[file])
        let stale = try planWith { $0["stale"] = .bool(true); $0["denied"] = .array([]) }
        _ = try HeirFlow.pending(plan: stale, folder: f, now: after, random: random)
        XCTAssertEqual(folder.files.keys.filter { $0.hasPrefix("\(dir)/backup-") }, ["\(dir)/backup-notes.txt"])
        XCTAssertEqual(try HeirFlow.requestStatus(f, packages: two, identity: id, now: after).state, "no-backup")
        XCTAssertEqual(reason { try HeirFlow.recoverEntropy(f, packages: two, identity: id, now: after) }, "no-backup")
    }

    func testDenyWinsWhateverItsTimeAndALostDenyIsWrittenAgain() throws {
        let folder = MemoryFolder()
        let f = HeirFolder(access: folder)
        let two = Array(V.packages.prefix(2)), id = try identity
        try HeirFlow.requestAccess(f, shard: V.packages[1], identity: id, now: created, random: random)
        let rid = try XCTUnwrap(try HeirFlow.pending(plan: try fresh, folder: f, now: created, random: random).requests.first).requestID
        // The owner's clock is 50 years ahead: the deny still wins.
        try HeirFlow.deny(plan: try fresh, folder: f, requestID: rid, now: created + 50 * 365 * HeirFlow.day, random: random)
        descriptor(folder)
        let later = created + 30 * HeirFlow.day
        XCTAssertEqual(try HeirFlow.requestStatus(f, packages: two, identity: id, now: later).state, "denied")
        XCTAssertEqual(reason { try HeirFlow.recoverEntropy(f, packages: two, identity: id, now: later) }, "denied")
        XCTAssertTrue(try HeirFlow.pending(plan: try fresh, folder: f, now: created, random: random).requests.isEmpty)
        // Deleted from the folder: the owner's plan remembers the refusal and writes it again.
        folder.files.removeValue(forKey: "\(dir)/deny-\(rid)\(HeirFlow.denySuffix)")
        XCTAssertEqual(try HeirFlow.requestStatus(f, packages: two, identity: id, now: later).state, "ready")
        let remembered = try Heir.parsePlan(try Heir.withDenied(v["synced"]!, requestID: rid))
        XCTAssertTrue(try HeirFlow.pending(plan: remembered, folder: f, now: created, random: random).requests.isEmpty)
        XCTAssertNotNil(folder.files["\(dir)/deny-\(rid)\(HeirFlow.denySuffix)"])
        XCTAssertEqual(try HeirFlow.requestStatus(f, packages: two, identity: id, now: later).state, "denied")
        // A deny by any other key is ignored.
        let other = MemoryFolder()
        let o = HeirFolder(access: other)
        try HeirFlow.requestAccess(o, shard: V.packages[1], identity: id, now: created, random: random)
        let rid2 = try XCTUnwrap(try HeirFlow.pending(plan: try fresh, folder: o, now: created, random: random).requests.first).requestID
        let forgerSeed = [UInt8](repeating: 3, count: 32)
        let forger = try planWith {
            $0["signing_key"] = .string(Envelope.b64e(forgerSeed))
            $0["signer"] = .string(Envelope.b64e((try? Envelope.publicKey(seed: forgerSeed)) ?? []))
        }
        try HeirFlow.deny(plan: forger, folder: o, requestID: rid2, now: created, random: random)
        XCTAssertEqual(try HeirFlow.requestStatus(o, packages: two, identity: id, now: created).state, "waiting")
    }

    func testRequestsWithoutAShardOfThisPlanAreNotListed() throws {
        let folder = MemoryFolder()
        let f = HeirFolder(access: folder)
        // A shard with a wrong share, signed by the plan key: its proof does not match the stored holder key.
        var bad = V.shares[2]; bad[3] ^= 1
        let forged = try Heir.sealPackage(planID: planID, share: bad, holder: "Ben", k: 2, n: 3, waitDays: 7, created: created,
                                          checkSalt: V.hex("check_salt"), check: V.hex("check"), owner: V.s("owner"),
                                          packageID: "3ebf9c51-405d-4b8a-bf6e-2d3c4b5a6f74", signingSeed: V.hex("signing_seed"))
        try HeirFlow.requestAccess(f, shard: forged, identity: try identity, now: created, random: random)
        folder.files["\(dir)/request-00000000-0000-4000-8000-000000000000.lgkheirreq"] = Array("junk".utf8)
        for i in 1...600 {
            folder.files["\(dir)/request-\(String(format: "0000%04x", i))-0000-4000-8000-000000000000.lgkheirreq"] = Array("{}".utf8)
        }
        try HeirFlow.requestAccess(f, shard: V.packages[0], identity: try identity, now: created, random: random)
        let listed = try HeirFlow.pending(plan: try fresh, folder: f, now: created, random: random)
        XCTAssertEqual(listed.requests.map(\.holder), ["Νίκος"])
        XCTAssertFalse(listed.flooded)
    }

    func testGrantNowOpensAccessEarlyWithOneShard() throws {
        let folder = MemoryFolder()
        let f = HeirFolder(access: folder)
        let id = try identity, p = try fresh
        let one = [V.packages[2]]
        try HeirFlow.requestAccess(f, shard: V.packages[2], identity: id, now: created, random: random)
        let rid = try XCTUnwrap(try HeirFlow.pending(plan: p, folder: f, now: created, random: random).requests.first).requestID
        let wrongPhrase = String(repeating: "abandon ", count: 23) + "art"
        XCTAssertEqual(reason { try HeirFlow.grantNow(plan: p, folder: f, requestID: rid, phrase: wrongPhrase, now: self.created, random: self.random) }, "wrong-phrase")
        XCTAssertEqual(reason { try HeirFlow.grantNow(plan: p, folder: f, requestID: rid, phrase: "not a phrase", now: self.created, random: self.random) }, "wrong-phrase")
        let path = try HeirFlow.grantNow(plan: p, folder: f, requestID: rid, phrase: V.s("phrase"), now: created, random: random)
        XCTAssertTrue(path.hasSuffix("grant-\(rid)\(HeirFlow.grantSuffix)"))
        XCTAssertFalse(String(decoding: folder.files[path] ?? [], as: UTF8.self).contains(V.s("entropy")))
        XCTAssertEqual(try HeirFlow.pending(plan: p, folder: f, now: created, random: random).requests.first?.granted, true)
        descriptor(folder)
        let status = try HeirFlow.requestStatus(f, packages: one, identity: id, now: created + 60)
        XCTAssertEqual(status.state, "ready")
        XCTAssertTrue(status.granted)
        XCTAssertEqual(try HeirFlow.recoverEntropy(f, packages: one, identity: id, now: created + 60), V.hex("entropy"))
        // Usable only by the requester it names.
        let other = try RequesterIdentity(signingSeed: [UInt8](repeating: 5, count: 32), boxKey: [UInt8](repeating: 6, count: 32))
        XCTAssertEqual(try HeirFlow.requestStatus(f, packages: one, identity: other, now: created + 60).state, "none")
        // A denied request cannot be granted, and a deny beats an earlier grant.
        try HeirFlow.deny(plan: p, folder: f, requestID: rid, now: created, random: random)
        XCTAssertEqual(reason { try HeirFlow.grantNow(plan: p, folder: f, requestID: rid, phrase: V.s("phrase"), now: self.created, random: self.random) }, "denied")
        XCTAssertEqual(try HeirFlow.requestStatus(f, packages: one, identity: id, now: created + 60).state, "denied")
        // A stale plan grants nothing.
        let g2 = HeirFolder(access: MemoryFolder())
        try HeirFlow.requestAccess(g2, shard: V.packages[2], identity: id, now: created, random: random)
        let rid2 = try XCTUnwrap(try HeirFlow.pending(plan: p, folder: g2, now: created, random: random).requests.first).requestID
        let stale = try planWith { $0["stale"] = .bool(true); $0["denied"] = .array([]) }
        XCTAssertEqual(reason { try HeirFlow.grantNow(plan: stale, folder: g2, requestID: rid2, phrase: V.s("phrase"), now: self.created, random: self.random) }, "stale-plan")
        XCTAssertEqual(reason { try HeirFlow.grantNow(plan: p, folder: g2, requestID: "11111111-2222-4333-8444-555555555555", phrase: V.s("phrase"), now: self.created, random: self.random) }, "no-request")
    }

    func testAGrantWithTheWrongSecretStopsAtTheHKDFCheck() throws {
        let folder = MemoryFolder()
        let f = HeirFolder(access: folder)
        let id = try identity
        try HeirFlow.requestAccess(f, shard: V.packages[0], identity: id, now: created, random: random)
        let request = try XCTUnwrap(try HeirFlow.pending(plan: try fresh, folder: f, now: created, random: random).requests.first)
        folder.files["\(dir)/grant-\(request.requestID)\(HeirFlow.grantSuffix)"] =
            try HeirFlow.grantBytes(plan: try plan, request: request, entropy: [UInt8](repeating: 0x42, count: 32), now: created,
                                    ephemeralKey: [UInt8](repeating: 7, count: 32), packageID: "4fc0ad62-516e-4c9b-80f7-3e4d5c6b7a85")
        descriptor(folder)
        XCTAssertEqual(try HeirFlow.requestStatus(f, packages: [V.packages[0]], identity: id, now: created).state, "ready")
        XCTAssertEqual(reason { try HeirFlow.recoverEntropy(f, packages: [V.packages[0]], identity: id, now: self.created) }, "check-failed")
    }

    func testThePickedFolderMayBeTheEmergencyFolder() throws {
        XCTAssertEqual(try HeirFlow.planDir(HeirFolder(access: MemoryFolder()), planID: planID), dir)
        XCTAssertEqual(try HeirFlow.planDir(HeirFolder(access: MemoryFolder(), rootName: HeirFlow.folderName), planID: planID), planID)
        let folder = MemoryFolder()
        let f = HeirFolder(access: folder, rootName: HeirFlow.folderName)
        let path = try HeirFlow.requestAccess(f, shard: V.packages[0], identity: try identity, now: created, random: random)
        XCTAssertTrue(path.hasPrefix("\(planID)/request-"))
        XCTAssertEqual(try HeirFlow.pending(plan: try fresh, folder: f, now: created, random: random).requests.count, 1)
    }

    func testHeirFileNames() {
        for name in ["LocalGateKeys Emergency", "a.lgkheir", "request-x.lgkheirreq", "backup-20270115-080000-0a1b2c3d.lgk",
                     "x.lgkheirbackup"] {
            XCTAssertTrue(HeirFlow.isHeirFile(name), name)
        }
        for name in ["backup.lgk", "device.lgksync", "backup-2027-0a1b2c3d.lgk"] { XCTAssertFalse(HeirFlow.isHeirFile(name), name) }
        XCTAssertTrue(HeirFlow.isDenyName("deny-6e2f0b4d-8c3a-4d91-be52-3b7f9a1c0d48 (1).lgkheirdeny"))
        XCTAssertFalse(HeirFlow.isDenyName("deny-6e2f0b4d-8c3a-4d91-be52-3b7f9a1c0d48/x.lgkheirdeny"))
    }

    func testRequesterIdentityRecordIsStrict() throws {
        let r = try RequesterIdentity.generate(random: random)
        let back = try RequesterIdentity.fromRecord(r.toRecord())
        XCTAssertEqual(r.signer, back.signer)
        XCTAssertEqual(r.boxPublic, back.boxPublic)
        var extra = V.obj(r.toRecord()); extra["x"] = .int(1)
        for bad: JSONValue in [.null, .object(["version": .int(2)]), .object(extra)] {
            XCTAssertThrowsError(try RequesterIdentity.fromRecord(bad))
        }
    }
}
