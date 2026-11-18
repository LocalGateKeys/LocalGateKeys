import XCTest
@testable import LGKCore

/// The shared heir vectors (`tests/vectors/heir/v1.json`, written by the desktop), read once.
enum HeirVectors {
    static let data: [String: JSONValue] = {
        guard let raw = try? Data(contentsOf: Vectors.shared("heir/v1.json")),
              case .object(let o)? = try? CanonicalJSON.parse(Array(raw)) else { return [:] }
        return o
    }()

    static func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
    static func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { return a }; return [] }
    static func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }
    static func int(_ v: JSONValue?) -> Int64 { if case .int(let i)? = v { return i }; return -1 }
    static func s(_ k: String) -> String { str(data[k]) }
    static func hex(_ k: String) -> [UInt8] { Vectors.hex(s(k)) }
    static var packages: [[UInt8]] { arr(data["packages"]).map { Array(str($0).utf8) } }
    static var shares: [[UInt8]] { arr(data["shares"]).map { Vectors.hex(str($0)) } }

    /// The desktop's (deterministic) signature of a vector file, so a re-made file can be compared byte for byte
    /// (Apple's own Ed25519 signatures are randomized).
    static func signature(of file: String) -> Envelope.Signer {
        let sig: [UInt8]
        if case .object(let o)? = try? CanonicalJSON.parse(Array(file.utf8)), case .string(let b)? = o["sig"],
           let d = try? Base64.decodeStrict(b) {
            sig = d
        } else {
            sig = []
        }
        return { _ in sig }
    }
}

/// `.lgkheir` packages and the plan record against tests/vectors/heir/v1.json (Android `HeirTest.kt`, same vectors).
final class HeirTests: XCTestCase {
    private typealias V = HeirVectors
    private var v: [String: JSONValue] { V.data }

    private func reason(_ body: () throws -> Any) -> String? {
        do { _ = try body(); return nil } catch let e as HeirError { return e.reason } catch { return "other" }
    }

    func testVectorsAreThere() {
        XCTAssertEqual(V.s("format"), "lgk-heir-vectors-v1")
        XCTAssertEqual(V.packages.count, 3)
    }

    func testNamesRefuseControlFormatAndPrivateUseButNotUnassigned() throws {
        // U+2FFFE is unassigned on every Unicode version: it stands for an emoji newer than this device's tables.
        let newer = String(Unicode.Scalar(0x2FFFE)!)
        XCTAssertEqual(try Heir.printable("  Anna \(newer) ", limit: 64), "Anna \(newer)")
        for bad in ["Anna\u{0007}", "Anna\u{200E}", "Anna\u{E000}"] {
            XCTAssertEqual(reason { try Heir.printable(bad, limit: 64) }, "invalid", bad)
        }
    }

    func testReadsEveryPackagePythonWrote() throws {
        let facts = V.arr(v["shards"]).map(V.obj)
        for (i, data) in V.packages.enumerated() {
            let shard = try Heir.readPackage(data)
            XCTAssertEqual(shard.index, Int(V.int(facts[i]["index"])))
            XCTAssertEqual(shard.holder, V.str(facts[i]["holder"]))
            XCTAssertEqual(shard.packageID, V.str(facts[i]["package_id"]))
            XCTAssertEqual(shard.planID, V.s("plan_id"))
            XCTAssertEqual(shard.owner, V.s("owner"))
            XCTAssertEqual(Int64(shard.k), V.int(v["k"]))
            XCTAssertEqual(shard.created, V.int(v["created"]))
            XCTAssertEqual(shard.share, V.shares[i])
            XCTAssertEqual(Base64.encode(shard.signer), V.s("signer"))
        }
    }

    func testAnyKPackagesCombineToTheEntropyAndItsPhrase() throws {
        let p = V.packages
        for pair in [[0, 1], [1, 2], [2, 0], [0, 1, 2]] {
            let entropy = try Heir.combinePackages(pair.map { p[$0] })
            XCTAssertEqual(entropy, V.hex("entropy"))
            XCTAssertEqual(try BIP39.phrase(entropy: Data(entropy)), V.s("phrase"))
        }
        do {
            _ = try Heir.combinePackages([p[0]])
            XCTFail("one shard")
        } catch let e as HeirError {
            XCTAssertEqual(e.reason, "need-more")
            XCTAssertEqual(e.missing, 1)
        }
        XCTAssertEqual(reason { try Heir.combinePackages([p[0], p[0]]) }, "duplicate")
        XCTAssertEqual(reason { try Heir.combinePackages([]) }, "need-more")
    }

    func testDerivesCheckBackupAndHolderKeysLikeTheDesktop() throws {
        let entropy = V.hex("entropy"), salt = V.hex("check_salt"), plan = V.s("plan_id")
        XCTAssertEqual(try Heir.entropyCheck(entropy, planID: plan, salt: salt), V.hex("check"))
        XCTAssertEqual(try Heir.backupPublicKey(entropy, planID: plan, salt: salt), V.hex("backup_public"))
        for (i, h) in V.arr(v["holder_keys"]).enumerated() {
            XCTAssertEqual(try Heir.holderKey(V.shares[i], planID: plan, salt: salt), Vectors.hex(V.str(h)))
        }
        XCTAssertTrue(Heir.verifyEntropy(planID: plan, salt: salt, check: V.hex("check"), entropy: entropy))
        var wrong = entropy; wrong[0] &+= 1
        XCTAssertFalse(Heir.verifyEntropy(planID: plan, salt: salt, check: V.hex("check"), entropy: wrong))
    }

    func testResealsEveryPackageByteForByte() throws {
        let holders = V.arr(v["holders"]).map(V.str)
        let ids = V.arr(v["package_ids"]).map(V.str)
        for (i, data) in V.packages.enumerated() {
            let again = try Heir.sealPackage(planID: V.s("plan_id"), share: V.shares[i], holder: holders[i],
                                             k: Int(V.int(v["k"])), n: Int(V.int(v["n"])),
                                             waitDays: Int(V.int(v["wait_days"])), created: V.int(v["created"]),
                                             checkSalt: V.hex("check_salt"), check: V.hex("check"), owner: V.s("owner"),
                                             packageID: ids[i], signingSeed: V.hex("signing_seed"),
                                             sign: V.signature(of: String(decoding: data, as: UTF8.self)))
            XCTAssertEqual(again, data, "package \(i)")
            // Signed on this device (a randomized signature): still a valid package of the same shard.
            let own = try Heir.sealPackage(planID: V.s("plan_id"), share: V.shares[i], holder: holders[i], k: 2, n: 3,
                                           waitDays: 7, created: V.int(v["created"]), checkSalt: V.hex("check_salt"),
                                           check: V.hex("check"), owner: V.s("owner"), packageID: ids[i],
                                           signingSeed: V.hex("signing_seed"))
            XCTAssertEqual(try Heir.readPackage(own).share, V.shares[i])
        }
    }

    func testSplitWithTheVectorCoefficientsGivesTheDesktopShares() throws {
        let out = try SSS.split(V.hex("entropy"), k: 2, n: 3, random: FixedRandom(value: V.hex("coefficients")))
        XCTAssertEqual(out, V.shares)
    }

    func testRefusesWhatTheDesktopRefuses() {
        let refused = V.arr(v["refused"]).map(V.obj)
        XCTAssertEqual(refused.count, 20)
        for c in refused {
            let name = V.str(c["name"])
            XCTAssertEqual(reason { try Heir.readPackage(Array(V.str(c["package"]).utf8)) }, V.str(c["reason"]), name)
        }
    }

    func testMixedPlansAndAForgedShareAreRefused() throws {
        let p = V.packages
        // A share re-signed under another key looks like another plan.
        let other = try Heir.sealPackage(planID: V.s("plan_id"), share: V.shares[1], holder: "Anna", k: 2, n: 3, waitDays: 7,
                                         created: V.int(v["created"]), checkSalt: V.hex("check_salt"), check: V.hex("check"),
                                         owner: V.s("owner"), packageID: "3ebf9c51-405d-4b8a-bf6e-2d3c4b5a6f74",
                                         signingSeed: [UInt8](repeating: 9, count: 32))
        XCTAssertEqual(reason { try Heir.combinePackages([p[0], other]) }, "mixed-plans")
        // A wrong share signed with the plan key fails the HKDF check.
        var wrong = V.shares[1]; wrong[5] ^= 1
        let forged = try Heir.sealPackage(planID: V.s("plan_id"), share: wrong, holder: "Anna", k: 2, n: 3, waitDays: 7,
                                          created: V.int(v["created"]), checkSalt: V.hex("check_salt"), check: V.hex("check"),
                                          owner: V.s("owner"), packageID: "3ebf9c51-405d-4b8a-bf6e-2d3c4b5a6f74",
                                          signingSeed: V.hex("signing_seed"))
        XCTAssertEqual(reason { try Heir.combinePackages([p[0], forged]) }, "check-failed")
    }

    func testQRTextRoundTripsAndMatchesTheDesktop() throws {
        let qr = V.arr(v["qr"]).map(V.str)
        for (i, data) in V.packages.enumerated() {
            XCTAssertEqual(try Heir.shardQRText(data), qr[i])
            XCTAssertEqual(try Heir.package(fromQRText: qr[i]), data)
        }
        let body = String(qr[0].dropFirst(Heir.qrPrefix.count))
        for bad in ["lgkheir:", "lgkheir:a", "lgkhier:" + body, qr[0] + "+", String(qr[0].dropLast(3))] {
            XCTAssertThrowsError(try Heir.package(fromQRText: bad), String(bad.prefix(12)))
        }
    }

    func testSyncedRecordAndMergesMatchTheDesktop() throws {
        XCTAssertEqual(try Heir.syncedRecord(v["record"]), v["synced"])
        let plan = try Heir.parsePlan(v["synced"])
        XCTAssertEqual(plan.holders, ["Νίκος", "Anna", "Ben"])
        XCTAssertFalse(plan.stale)
        let cases = V.arr(v["merges"]).map(V.obj)
        XCTAssertEqual(cases.count, 12)
        for c in cases {
            let name = V.str(c["name"])
            let local: JSONValue? = c["local"] == .null ? nil : c["local"]
            if let expected = c["reason"] {
                XCTAssertEqual(reason { try Heir.mergeSynced(local: local, remote: c["remote"]) }, V.str(expected), name)
            } else {
                XCTAssertEqual(try Heir.mergeSynced(local: local, remote: c["remote"]), c["stored"], name)
            }
        }
    }

    func testWithDeniedKeepsTheNewestAndMovesARepeatToTheEnd() throws {
        let synced = v["synced"]!
        let id = "11111111-2222-4333-8444-555555555555"
        let once = try Heir.withDenied(synced, requestID: id)
        XCTAssertEqual(V.arr(V.obj(once)["denied"]).last, .string(id))
        let again = try Heir.withDenied(try Heir.withDenied(once, requestID: "7f301c5e-9d4b-4ea2-8f63-4c8a0b2d1e59"), requestID: id)
        XCTAssertEqual(V.arr(V.obj(again)["denied"]), [.string("7f301c5e-9d4b-4ea2-8f63-4c8a0b2d1e59"), .string(id)])
        XCTAssertThrowsError(try Heir.withDenied(synced, requestID: "not-an-id"))
    }

    func testPrintableNamesFollowTheDesktop() throws {
        XCTAssertEqual(try Heir.printable("  Ann ", limit: 32), "Ann")
        XCTAssertEqual(try Heir.printable("e\u{301}", limit: 32), "é")
        XCTAssertThrowsError(try Heir.printable("", limit: 32))
        XCTAssertEqual(try Heir.printable(" ", limit: 64, allowEmpty: true), "")
        XCTAssertThrowsError(try Heir.printable("a\u{200B}b", limit: 32))
        XCTAssertThrowsError(try Heir.printable("a\u{0007}", limit: 32))
        XCTAssertEqual(try Heir.printable(String(repeating: "😀", count: 32), limit: 32), String(repeating: "😀", count: 32))
        XCTAssertThrowsError(try Heir.printable(String(repeating: "x", count: 33), limit: 32))
    }

    /// The `heir` namespace in sync: the wrapper ranks by `created`, a valid plan unwraps, a re-keying one is refused.
    func testWrapperAndSyncCheck() throws {
        let synced = v["synced"]!
        XCTAssertEqual(Wrapper.make(ns: .heir, record: synced), v["wrapper"])
        let state = try ItemState(itemID: Heir.stateID, vv: ["a": 1], deleted: false, deletedAt: nil, item: v["wrapper"])
        let (ns, record) = try Wrapper.unwrap(state, isCopy: false)
        XCTAssertEqual(ns, .heir)
        XCTAssertEqual(record, synced)
        XCTAssertNil(SyncRunner.check(state, licenseKeys: [:], heirLocal: synced))
        // Another plan id is a new plan; the same id with another key is refused.
        var rekeyed = V.obj(synced)
        rekeyed["holders"] = .array([.string("X"), .string("Y"), .string("Z")])
        let bad = try ItemState(itemID: Heir.stateID, vv: ["a": 1], deleted: false, deletedAt: nil,
                                item: Wrapper.make(ns: .heir, record: .object(rekeyed)))
        XCTAssertEqual(SyncRunner.check(bad, licenseKeys: [:], heirLocal: synced), "bad-remote")
        // Only the `heir:plan` id carries the namespace.
        let wrongID = try ItemState(itemID: "a1b2", vv: ["a": 1], deleted: false, deletedAt: nil, item: v["wrapper"])
        XCTAssertThrowsError(try Wrapper.unwrap(wrongID, isCopy: false))
        XCTAssertEqual(Heir.publishable([state], heir: false).count, 0)
        XCTAssertEqual(Heir.publishable([state], heir: true).count, 1)
    }

    func testApplyMergesDeniesAndBumpsWhenTheMergeDiffers() throws {
        let synced = v["synced"]!
        let localRecord = try Heir.withDenied(synced, requestID: "11111111-2222-4333-8444-555555555555")
        let local = Wrapper.make(ns: .heir, record: localRecord)
        let meta = [Heir.stateID: try SyncMeta.live(local, vv: ["me": 1])]
        let remote = try ItemState(itemID: Heir.stateID, vv: ["me": 1, "pc": 1], deleted: false, deletedAt: nil, item: v["wrapper"])
        let outcome = MergeOutcome(upserts: [remote], deletes: [], conflicts: [], copies: [])
        let result = try SyncMeta.applyRemote(outcome, records: [Heir.stateID: local], meta: meta, device: "me",
                                              now: 1_900_000_000, licenseKeys: [:])
        let stored = V.obj(V.obj(result.records[Heir.stateID])["record"])
        XCTAssertEqual(Set(V.arr(stored["denied"]).map(V.str)),
                       Set(V.arr(V.obj(synced)["denied"]).map(V.str)).union(["11111111-2222-4333-8444-555555555555"]))
        XCTAssertEqual(result.meta[Heir.stateID]?.vv["me"], 2)   // a local edit: it travels back
    }
}
