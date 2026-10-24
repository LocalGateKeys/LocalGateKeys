import XCTest
import Foundation
import Crypto
@testable import LGKCore

/// Keyring vectors (keyring.py). Argon2id runs at production cost, so only a few tests run it;
/// the rest use the raw Argon2id outputs from expected.json through the internal key-taking API.
final class KeyringTests: XCTestCase {
    static let A = "a1111111-0000-4000-8000-00000000000a"
    static let B = "b2222222-0000-4000-8000-00000000000b"
    static let C = "c3333333-0000-4000-8000-00000000000c"

    // MARK: helpers

    static func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
    static func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }

    static func expected() throws -> [String: JSONValue] {
        obj(try CanonicalJSON.parse(Array(Vectors.data("expected.json"))))
    }

    static func identity(_ who: String) throws -> DeviceIdentity {
        let ids = obj(obj(try CanonicalJSON.parse(Array(Vectors.data("identities.json"))))["devices"])
        let p = obj(obj(ids[who])["private"])
        return try DeviceIdentity(deviceID: str(p["device_id"]),
                                  signingPrivate: try Base64.decodeStrict(str(p["signing_private"])),
                                  exchangePrivate: try Base64.decodeStrict(str(p["exchange_private"])))
    }

    static func ring(_ name: String) throws -> JSONValue { try Keyring.parse(Array(Vectors.data(name))) }

    static func epochKey(_ e: String, existing: Bool = false) throws -> GroupKey {
        let x = try expected()
        let base = existing ? obj(x["existing_group"]) : x
        let gid = str(base["group_id"])
        let hex = str(obj(obj(base["epochs"])[e])["group_key_hex"])
        return try GroupKey(groupID: gid, epoch: Int64(e)!, key: Vectors.hex(hex))
    }

    static func pwKey(_ e: String, existing: Bool = false) throws -> [UInt8] {
        let x = try expected()
        let base = existing ? obj(x["existing_group"]) : x
        return Vectors.hex(str(obj(obj(base["epochs"])[e])["password_wrap_key_hex"]))
    }

    static func names(_ e: String, existing: Bool = false) throws -> [String: String?] {
        let x = try expected()
        let base = existing ? obj(x["existing_group"]) : x
        var out: [String: String?] = [:]
        for (k, v) in obj(obj(obj(base["epochs"])[e])["member_names"]) { out[k] = str(v) }
        return out
    }

    func reason(_ f: () throws -> Any) -> String? {
        do { _ = try f(); return nil } catch let e as KeyringError { return e.reason } catch { return "other: \(error)" }
    }

    // MARK: identities

    func test_identities_match_vectors() throws {
        let ids = Self.obj(Self.obj(try CanonicalJSON.parse(Array(Vectors.data("identities.json"))))["devices"])
        for who in ["A", "B", "C"] {
            let d = Self.obj(ids[who]); let id = try Self.identity(who)
            XCTAssertEqual(id.deviceID, Self.str(d["device_id"]))
            XCTAssertEqual(Base64.encode(id.signingPublicKey), Self.str(d["signing_public_b64"]))
            XCTAssertEqual(Base64.encode(id.exchangePublicKey), Self.str(d["exchange_public_b64"]))
            XCTAssertEqual(id.fingerprint, Self.str(d["fingerprint_sha256_of_signing_public"]))
        }
    }

    // MARK: structure and MAC

    func test_every_keyring_file_verifies() throws {
        let cases: [(String, String, Bool)] = [
            ("keyring_epoch1.json", "1", false), ("keyring_epoch2.json", "2", false),
            ("keyring_epoch1_ab.json", "1", false), ("keyring_existing_epoch1.json", "1", true),
            ("keyring_existing_epoch3.json", "3", true), ("keyring_attach.json", "1", true),
        ]
        for (file, e, existing) in cases {
            let raw = Array(try Vectors.data(file))
            let ring = try Keyring.parse(raw)
            XCTAssertEqual(try CanonicalJSON.encode(ring, dialect: .utf8), raw, file)
            XCTAssertTrue(Keyring.macOK(ring, key: try Self.epochKey(e, existing: existing)), file)
        }
        let x = try Self.expected()
        for e in ["1", "2"] {
            let gk = try Self.epochKey(e)
            XCTAssertEqual(Vectors.hexString(Keyring.macKey(gk)),
                           Self.str(Self.obj(Self.obj(x["epochs"])[e])["keyring_mac_key_hex"]))
            XCTAssertEqual(Vectors.hexString(Keyring.nameKey(gk)),
                           Self.str(Self.obj(Self.obj(x["epochs"])[e])["member_name_key_hex"]))
        }
    }

    func test_parse_rejects_malformed() throws {
        let good = Array(try Vectors.data("keyring_epoch1.json"))
        let text = String(decoding: good, as: UTF8.self)
        XCTAssertEqual(reason { try Keyring.parse(Array("{\"a\":1,\"a\":2}".utf8)) }, "bad-json")
        XCTAssertEqual(reason { try Keyring.parse(Array("[1]".utf8)) }, "bad-keyring")
        XCTAssertEqual(reason { try Keyring.parse(Array("{\"x\":NaN}".utf8)) }, "bad-json")
        XCTAssertEqual(reason { try Keyring.parse([UInt8](repeating: 0x20, count: 256 * 1024 + 1)) }, "too-large")
        XCTAssertEqual(reason { try Keyring.parse(Array(text.replacingOccurrences(of: "\"format\":1", with: "\"format\":1.0").utf8)) }, "bad-format")
        XCTAssertEqual(reason { try Keyring.parse(Array(text.replacingOccurrences(of: "\"epoch\":1", with: "\"epoch\":0").utf8)) }, "bad-epoch")
        XCTAssertEqual(reason { try Keyring.parse(Array(text.replacingOccurrences(of: "\"iterations\":4", with: "\"iterations\":3").utf8)) }, "bad-kdf")
        XCTAssertEqual(reason { try Keyring.parse(Array(text.replacingOccurrences(of: "\"format\":1,", with: "\"format\":1,\"extra\":1,").utf8)) }, "bad-fields")
        XCTAssertEqual(reason { try Keyring.parse(Array(text.replacingOccurrences(of: "\"prev_mac\":null", with: "\"prev_mac\":\"\(Base64.encode([UInt8](repeating: 1, count: 32)))\"").utf8)) }, "bad-fields")
        // Non-canonical base64 of the salt (strip padding).
        let salt = Self.str(Self.obj(Self.obj(try Self.ring("keyring_epoch1.json"))["kdf"])["salt"])
        XCTAssertEqual(reason { try Keyring.parse(Array(text.replacingOccurrences(of: salt, with: String(salt.dropLast(2))).utf8)) }, "bad-base64")
    }

    // MARK: password and device unwraps

    /// The two production-cost unwraps (one per password).
    func test_password_unwrap_with_both_passwords() throws {
        let x = try Self.expected()
        let g1 = try Keyring.unwrapWithPassword(try Self.ring("keyring_epoch1.json"), password: Self.str(x["password_epoch1"]))
        XCTAssertEqual(g1, try Self.epochKey("1"))
        let g2 = try Keyring.unwrapWithPassword(try Self.ring("keyring_epoch2.json"), password: Self.str(x["password_epoch2"]))
        XCTAssertEqual(g2, try Self.epochKey("2"))
    }

    func test_password_unwrap_with_known_keys() throws {
        XCTAssertEqual(try Keyring.unwrap(try Self.ring("keyring_epoch1.json"), passwordKey: try Self.pwKey("1")), try Self.epochKey("1"))
        XCTAssertEqual(try Keyring.unwrap(try Self.ring("keyring_epoch2.json"), passwordKey: try Self.pwKey("2")), try Self.epochKey("2"))
        XCTAssertEqual(try Keyring.unwrap(try Self.ring("keyring_existing_epoch1.json"), passwordKey: try Self.pwKey("1", existing: true)),
                       try Self.epochKey("1", existing: true))
        XCTAssertEqual(try Keyring.unwrap(try Self.ring("keyring_existing_epoch3.json"), passwordKey: try Self.pwKey("3", existing: true)),
                       try Self.epochKey("3", existing: true))
        XCTAssertEqual(reason { try Keyring.unwrap(try Self.ring("keyring_epoch1.json"), passwordKey: try Self.pwKey("2")) }, "password")
    }

    func test_device_wraps_for_all_devices() throws {
        let r1 = try Self.ring("keyring_epoch1.json")
        for who in ["A", "B", "C"] {
            XCTAssertEqual(try Keyring.unwrapDevice(r1, identity: try Self.identity(who)), try Self.epochKey("1"), who)
        }
        let r2 = try Self.ring("keyring_epoch2.json")
        for who in ["A", "B"] {
            XCTAssertEqual(try Keyring.unwrapDevice(r2, identity: try Self.identity(who)), try Self.epochKey("2"), who)
        }
        XCTAssertEqual(reason { try Keyring.unwrapDevice(r2, identity: try Self.identity("C")) }, "not-member")
        // Same device id, other exchange key.
        let c = try Self.identity("C")
        let fakeA = try DeviceIdentity(deviceID: Self.A, signingPrivate: c.signingPrivateKey, exchangePrivate: c.exchangePrivateKey)
        XCTAssertEqual(reason { try Keyring.unwrapDevice(r2, identity: fakeA) }, "key-mismatch")
    }

    // MARK: accept

    func test_accept_rotation_and_rejections() throws {
        let r1 = try Self.ring("keyring_epoch1.json"), r2 = try Self.ring("keyring_epoch2.json")
        let g1 = try Self.epochKey("1"), g2 = try Self.epochKey("2")
        for who in ["A", "B"] {
            XCTAssertEqual(try Keyring.accept(r2, trusted: g1, identity: try Self.identity(who)), g2, who)
            XCTAssertEqual(try Keyring.accept(r1, trusted: g1, identity: try Self.identity(who)), g1, who)
        }
        XCTAssertEqual(reason { try Keyring.accept(r2, trusted: g1, identity: try Self.identity("C")) }, "not-member")
        XCTAssertEqual(reason { try Keyring.accept(r1, trusted: g2, identity: try Self.identity("A")) }, "rollback")
        let other = try GroupKey(groupID: "other", epoch: 1, key: g1.key)
        XCTAssertEqual(reason { try Keyring.accept(r1, trusted: other, identity: try Self.identity("A")) }, "group-mismatch")
        let ex1 = try Self.epochKey("1", existing: true)
        XCTAssertEqual(reason { try Keyring.accept(try Self.ring("keyring_existing_epoch3.json"), trusted: ex1, identity: try Self.identity("A")) },
                       "missed-rotation")
        let wrong = try GroupKey(groupID: g1.groupID, epoch: 1, key: g2.key)
        XCTAssertEqual(reason { try Keyring.accept(r1, trusted: wrong, identity: try Self.identity("A")) }, "tampered")
        XCTAssertEqual(reason { try Keyring.accept(r2, trusted: wrong, identity: try Self.identity("A")) }, "tampered")
        // Body change after the MAC.
        guard case .object(var o) = r1 else { return XCTFail() }
        o["members"] = .array(Array(MergeVectors.arr(o["members"]).prefix(2)))
        var w = Self.obj(o["device_wraps"]); w[Self.C] = nil; o["device_wraps"] = .object(w)
        XCTAssertEqual(reason { try Keyring.accept(.object(o), trusted: g1, identity: try Self.identity("A")) }, "tampered")
    }

    func test_existing_and_attach_keyrings_accepted() throws {
        let ex1 = try Self.epochKey("1", existing: true), ex3 = try Self.epochKey("3", existing: true)
        let a = try Self.identity("A"), b = try Self.identity("B")
        XCTAssertEqual(try Keyring.accept(try Self.ring("keyring_existing_epoch1.json"), trusted: ex1, identity: a), ex1)
        XCTAssertEqual(try Keyring.accept(try Self.ring("keyring_existing_epoch3.json"), trusted: ex3, identity: a), ex3)
        let att = try Self.ring("keyring_attach.json")
        XCTAssertEqual(try Keyring.accept(att, trusted: ex1, identity: a), ex1)
        XCTAssertEqual(try Keyring.accept(att, trusted: ex1, identity: b), ex1)
        XCTAssertEqual(try Keyring.unwrapDevice(att, identity: b), ex1)
        XCTAssertEqual(Keyring.memberNames(att, key: ex1), try Self.names("1", existing: true).merging([Self.B: "Laptop (Windows)"]) { $1 })
    }

    // MARK: names

    func test_member_names_every_epoch() throws {
        XCTAssertEqual(Keyring.memberNames(try Self.ring("keyring_epoch1.json"), key: try Self.epochKey("1")), try Self.names("1"))
        XCTAssertEqual(Keyring.memberNames(try Self.ring("keyring_epoch2.json"), key: try Self.epochKey("2")), try Self.names("2"))
        XCTAssertEqual(Keyring.memberNames(try Self.ring("keyring_existing_epoch1.json"), key: try Self.epochKey("1", existing: true)),
                       try Self.names("1", existing: true))
        XCTAssertEqual(Keyring.memberNames(try Self.ring("keyring_existing_epoch3.json"), key: try Self.epochKey("3", existing: true)),
                       try Self.names("3", existing: true))
        // Wrong key reads as nil, never throws.
        let n = Keyring.memberNames(try Self.ring("keyring_epoch1.json"), key: try Self.epochKey("2").withEpoch1())
        XCTAssertEqual(n.count, 3); XCTAssertTrue(n.values.allSatisfy { $0 == nil })
    }

    // MARK: join and attach

    func test_join_output_verifies_on_desktop_rules() throws {
        let ab = try Self.ring("keyring_epoch1_ab.json")
        let g1 = try Self.epochKey("1")
        let me = try DeviceIdentity.generate(random: DetRand("swift-join-id"))
        let (joined, gk) = try Keyring.join(ab, password: Self.str(try Self.expected()["password_epoch1"]), identity: me,
                                            name: "iPhone", random: DetRand("swift-join"), now: FixedClock(now: 1790000500))
        XCTAssertEqual(gk, g1)
        // Re-parse the canonical bytes: structure + MAC as the desktop checks them.
        let bytes = try CanonicalJSON.encode(joined, dialect: .utf8)
        let back = try Keyring.parse(bytes)
        XCTAssertTrue(Keyring.macOK(back, key: g1))
        XCTAssertEqual(try Keyring.accept(back, trusted: g1, identity: me), g1)
        XCTAssertEqual(try Keyring.accept(back, trusted: g1, identity: try Self.identity("A")), g1)
        XCTAssertEqual(try Keyring.unwrapDevice(back, identity: me), g1)
        let o = Self.obj(back), old = Self.obj(ab)
        for k in ["password_wrap", "kdf", "prev_mac", "group_id", "epoch", "format"] { XCTAssertEqual(o[k], old[k], k) }
        let members = MergeVectors.arr(o["members"])
        XCTAssertEqual(members.count, 3)
        XCTAssertEqual(Array(members.prefix(2)), MergeVectors.arr(old["members"]))
        XCTAssertEqual(Self.obj(members[2])["added_at"], .int(1790000500))
        XCTAssertEqual(Keyring.memberNames(back, key: g1)[me.deviceID], "iPhone")
        // A second join of the same device is refused before any KDF work.
        XCTAssertEqual(reason { try Keyring.join(back, password: "x", identity: me, name: "iPhone",
                                                 random: DetRand("j2"), now: FixedClock(now: 0)) }, "already-member")
        XCTAssertEqual(reason { try Keyring.join(ab, password: "x", identity: me, name: "",
                                                 random: DetRand("j3"), now: FixedClock(now: 0)) }, "bad-name")
    }

    func test_attach_with_known_key() throws {
        let ex1 = try Self.epochKey("1", existing: true)
        let pw = try Self.pwKey("1", existing: true)
        let base = try Self.ring("keyring_existing_epoch1.json")
        let b = try Self.identity("B")
        let out = try Keyring.attach(base, passwordKey: pw, identity: b, name: "Laptop (Windows)", stored: ex1,
                                     random: DetRand("swift-attach"), now: FixedClock(now: 1790000060))
        let back = try Keyring.parse(try CanonicalJSON.encode(out, dialect: .utf8))
        XCTAssertEqual(try Keyring.accept(back, trusted: ex1, identity: b), ex1)
        XCTAssertEqual(Self.obj(back)["password_wrap"], Self.obj(base)["password_wrap"])
        // Idempotent with the vector keyring that already lists B.
        let att = try Self.ring("keyring_attach.json")
        XCTAssertEqual(try Keyring.attach(att, passwordKey: pw, identity: b, name: "Laptop (Windows)", stored: ex1,
                                          random: DetRand("x"), now: FixedClock(now: 0)), att)
        // C is not listed in the vector: a C impostor under B's id is already-member.
        let c = try Self.identity("C")
        let fakeB = try DeviceIdentity(deviceID: Self.B, signingPrivate: c.signingPrivateKey, exchangePrivate: c.exchangePrivateKey)
        XCTAssertEqual(reason { try Keyring.attach(att, passwordKey: pw, identity: fakeB, name: "x", stored: ex1,
                                                   random: DetRand("x"), now: FixedClock(now: 0)) }, "already-member")
        let ex3 = try Self.epochKey("3", existing: true)
        XCTAssertEqual(reason { try Keyring.attach(base, passwordKey: pw, identity: b, name: "x", stored: ex3,
                                                   random: DetRand("x"), now: FixedClock(now: 0)) }, "epoch-mismatch")
        let otherKey = try GroupKey(groupID: ex1.groupID, epoch: 1, key: ex3.key)
        XCTAssertEqual(reason { try Keyring.attach(base, passwordKey: pw, identity: b, name: "x", stored: otherKey,
                                                   random: DetRand("x"), now: FixedClock(now: 0)) }, "different-group-key")
    }
}

private extension GroupKey {
    func withEpoch1() throws -> GroupKey { try GroupKey(groupID: groupID, epoch: 1, key: key) }
}
