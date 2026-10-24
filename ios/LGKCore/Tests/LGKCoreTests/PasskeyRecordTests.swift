import XCTest
@testable import LGKCore

final class PasskeyRecordTests: XCTestCase {
    static let itemID = "9a550000-0000-4000-8000-000000000001"

    private func cases() throws -> [JSONValue] {
        guard case .array(let a) = try CanonicalJSON.parse(Array(Vectors.data("passkeys/records.json"))), !a.isEmpty else {
            throw CocoaError(.fileReadCorruptFile)
        }
        return a
    }

    private func field(_ v: JSONValue, _ k: String) -> JSONValue? {
        if case .object(let o) = v { return o[k] }
        return nil
    }

    static func item(_ payload: JSONValue, title: String = "Example (ada)") -> JSONValue {
        .object(["id": .string(itemID), "kind": .string("passkey"), "title": .string(title),
                 "created_at": .int(1_700_000_000), "updated_at": .int(1_700_000_000), "favorite": .bool(false),
                 "tags": .array([]), "payload": payload])
    }

    func test_passkey_is_a_phone_kind() {
        XCTAssertTrue(Normalise.phoneItemKinds.contains("passkey"))
    }

    func test_records_vectors_validity_and_usability() throws {
        for c in try cases() {
            guard case .string(let name)? = field(c, "name"), case .bool(let valid)? = field(c, "valid"),
                  case .bool(let usable)? = field(c, "usable"), let input = field(c, "input") else {
                return XCTFail("malformed vector")
            }
            let record = Self.item(input)
            do {
                let out = try Normalise.normalForm(ns: .item, record: record)
                XCTAssertTrue(valid, name)
                XCTAssertEqual(field(out, "payload"), field(c, "normalised"), name)
            } catch {
                XCTAssertFalse(valid, "\(name): \(error)")
            }
            let pk = try XCTUnwrap(PasskeyRecord.from(Wrapper.make(ns: .item, record: record), id: Self.itemID), name)
            XCTAssertEqual(pk.key != nil, usable, name)
            XCTAssertEqual(pk.itemID, Self.itemID)
            if usable {
                XCTAssertEqual(pk.rpID, "example.com", name)
                XCTAssertEqual(pk.userName, "ada")
                XCTAssertEqual(pk.title, "Example (ada)")
                XCTAssertEqual(pk.userHandle, Array("user-handle-1".utf8))
                XCTAssertEqual(pk.credentialID.count, 16)
            }
        }
    }

    func test_from_strips_credential_id() throws {
        let made = PasskeyRecord.newPayload(rpID: "example.com", rpName: "Example", userName: "ada", userDisplayName: "Ada",
                                            userHandle: [1, 2], credentialID: [UInt8](repeating: 9, count: 16),
                                            key: PasskeyKey.generate(), today: "2026-10-18")
        guard case .object(var p) = made.fields, case .string(let cred)? = p["credential_id"] else { return XCTFail() }
        p["credential_id"] = .string("  \(cred)\n")
        let pk = try XCTUnwrap(PasskeyRecord.from(Self.item(.object(p)), id: Self.itemID))
        XCTAssertEqual(pk.credentialID, [UInt8](repeating: 9, count: 16), "stripped, as the normaliser stores it")
        XCTAssertNotNil(pk.key)
    }

    func test_from_ignores_other_kinds() {
        var o: [String: JSONValue] = ["id": .string(Self.itemID), "kind": .string("note"), "title": .string("n"),
                                      "payload": .object(["body": .string("x")])]
        XCTAssertNil(PasskeyRecord.from(Wrapper.make(ns: .item, record: .object(o)), id: Self.itemID))
        o["kind"] = .string("web")
        XCTAssertNil(PasskeyRecord.from(Wrapper.make(ns: .entry, record: .object(o)), id: Self.itemID))
    }

    private func payload(rpName: String, userName: String, rpID: String = "example.com") -> (title: String, fields: JSONValue) {
        PasskeyRecord.newPayload(rpID: rpID, rpName: rpName, userName: userName, userDisplayName: "Ada Lovelace",
                                 userHandle: Array("user-handle-1".utf8), credentialID: [UInt8](repeating: 7, count: 16),
                                 key: PasskeyKey.generate(), today: "2026-10-18")
    }

    func test_new_payload_title_rules() {
        XCTAssertEqual(payload(rpName: "Example", userName: "ada").title, "Example (ada)")
        XCTAssertEqual(payload(rpName: "", userName: "ada").title, "example.com (ada)")
        XCTAssertEqual(payload(rpName: "Example", userName: "").title, "Example")
        XCTAssertEqual(payload(rpName: "", userName: "").title, "example.com")
    }

    func test_new_payload_fields_match_desktop_create_credential() throws {
        let p = payload(rpName: "Example", userName: "ada", rpID: " Example.COM ")
        guard case .object(let f) = p.fields else { return XCTFail() }
        XCTAssertEqual(f["relying_party_id"], .string("example.com"))
        XCTAssertEqual(f["algorithm"], .string("ES256"))
        XCTAssertEqual(f["discoverable"], .bool(true))
        XCTAssertEqual(f["created"], .string("2026-10-18"))
        XCTAssertEqual(f["user_handle"], .string(base64URLNoPad(Array("user-handle-1".utf8))))
        XCTAssertEqual(f["credential_id"], .string(base64URLNoPad([UInt8](repeating: 7, count: 16))))
        guard case .string(let k)? = f["private_key"] else { return XCTFail() }
        XCTAssertNotNil(PasskeyKey(pkcs8B64URL: k))
        XCTAssertFalse(k.contains("="))
    }

    func test_new_payload_normalises_identically() throws {
        let p = payload(rpName: "Example", userName: "ada")
        let record = Self.item(p.fields, title: p.title)
        let out = try Normalise.normalForm(ns: .item, record: record)
        XCTAssertEqual(try CanonicalJSON.encode(out, dialect: .utf8), try CanonicalJSON.encode(record, dialect: .utf8))
        let pk = try XCTUnwrap(PasskeyRecord.from(Wrapper.make(ns: .item, record: out), id: Self.itemID))
        XCTAssertNotNil(pk.key)
    }

    /// A passkey the phone only stores (desktop-made, an RS256 import, a garbage key) republishes exactly as
    /// received: the store keeps the wrapper bytes and the phone never normalises it unless it edits it.
    func test_untouched_passkey_republishes_identically() throws {
        for c in try cases() where field(c, "valid") == .bool(true) {
            let wrapper = Wrapper.make(ns: .item, record: Self.item(field(c, "input")!))
            let bytes = try CanonicalJSON.encode(wrapper, dialect: .utf8)
            let state = try ItemState(itemID: Self.itemID, vv: ["a": 1], deleted: false, deletedAt: nil, item: wrapper)
            let (ns, rec) = try Wrapper.unwrap(state, isCopy: false)
            XCTAssertEqual(try CanonicalJSON.encode(Wrapper.make(ns: ns, record: rec), dialect: .utf8), bytes)
            _ = PasskeyRecord.from(wrapper, id: Self.itemID)  // reading never rewrites
            XCTAssertEqual(try CanonicalJSON.encode(wrapper, dialect: .utf8), bytes)
        }
    }

    func test_normaliser_rejects_bad_passkey_payloads() {
        let base: [String: JSONValue] = ["relying_party_id": .string("example.com")]
        let bad: [[String: JSONValue]] = [
            base.merging(["extra": .string("x")]) { $1 },
            base.merging(["relying_party_id": .string("https://example.com")]) { $1 },
            base.merging(["algorithm": .string("HS256")]) { $1 },
            base.merging(["discoverable": .string("yes")]) { $1 },
            base.merging(["discoverable": .null]) { $1 },
            base.merging(["created": .string("2026-9-21")]) { $1 },
            base.merging(["user_handle": .string("a+b")]) { $1 },
            base.merging(["user_name": .null]) { $1 },
        ]
        for p in bad {
            XCTAssertThrowsError(try Normalise.normalForm(ns: .item, record: Self.item(.object(p))), "\(p)")
        }
        let okDates = ["20260921", "2026-W38", "2026W381", ""]
        for d in okDates {
            XCTAssertNoThrow(try Normalise.normalForm(ns: .item, record: Self.item(.object(base.merging(["created": .string(d)]) { $1 }))), d)
        }
        XCTAssertNoThrow(try Normalise.normalForm(ns: .item, record: Self.item(.object(base.merging(["created": .null, "algorithm": .null]) { $1 }))))
    }

    func test_normalise_rp_id_strips_and_casefolds() {
        XCTAssertEqual(PasskeyRecord.normaliseRPID(" Example.COM "), "example.com")
        XCTAssertEqual(PasskeyRecord.normaliseRPID("login.example.com"), "login.example.com")
    }
}
