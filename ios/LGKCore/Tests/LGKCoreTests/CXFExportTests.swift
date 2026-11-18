import XCTest
@testable import LGKCore

/// CXF export: the inverse of `CXFImport` (the Windows `tests/test_export_cxf.py` and Android `CxfExportTest` cases).
final class CXFExportTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_794_139_200)   // 2026-11-08 12:00 UTC

    private func b64u(_ d: Data) -> String { base64URLNoPad(Array(d)) }

    private func passkeyFields(_ der: Data) -> PasskeyFields {
        PasskeyFields(rpID: "pk.example.test", userName: "bob", userDisplayName: "Bob B", userHandle: Data([10, 11, 12]),
                      credentialID: Data([1, 2, 3, 4]), pkcs8: der)
    }

    private struct NotALogin: Error {}

    private func login(_ c: ImportCandidate) throws -> LoginFields {
        guard case .login(let f) = c.kind else { throw NotALogin() }
        return f
    }

    // MARK: round trip through CXFImport

    func testRoundTripLoginTotpNotePasskey() throws {
        let der = Data(try XCTUnwrap(decodeBase64URL(PasskeyKey.generate().pkcs8B64URL, maxBytes: 4096)))
        let items = [
            ImportCandidate(title: "Example Mail", kind: .login(LoginFields(
                url: "https://mail.example.test/login", username: "ada", password: "correct horse", notes: "in the drawer",
                otpauth: "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60")),
                urls: ["https://mail.example.test/login", "https://example.test"], created: 1_700_000_000),
            ImportCandidate(title: "Plain", kind: .login(LoginFields(url: "https://plain.test", username: "u", password: "p",
                                                                     notes: "", otpauth: nil))),
            ImportCandidate(title: "Empty", kind: .login(LoginFields(url: "", username: "", password: "", notes: "", otpauth: nil))),
            ImportCandidate(title: "Memo", kind: .note(NoteFields(notes: "remember the milk\nand bread"))),
            ImportCandidate(title: "Passkey Site", kind: .passkey(passkeyFields(der)), urls: ["https://pk.example.test"]),
        ]
        let data = try CXFExport.accountJSON(items, now: now)
        let r = try CXFImport.candidates(fromAccountJSON: data)
        XCTAssertEqual(r.unsupported, 0)
        XCTAssertEqual(r.candidates.map(\.title), ["Example Mail", "Plain", "Empty", "Memo", "Passkey Site"])

        let mail = try login(r.candidates[0])
        XCTAssertEqual(mail.url, "https://mail.example.test/login")
        XCTAssertEqual(mail.username, "ada")
        XCTAssertEqual(mail.password, "correct horse")
        XCTAssertEqual(mail.notes, "in the drawer")
        // The code merges back into the login, with its issuer, account and settings.
        XCTAssertEqual(mail.otpauth, "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8&period=60&algorithm=SHA256")

        XCTAssertEqual(try login(r.candidates[1]), LoginFields(url: "https://plain.test", username: "u", password: "p",
                                                                notes: "", otpauth: nil))
        // An empty login keeps its basic-auth, so it comes back as a login and not as a note.
        XCTAssertEqual(try login(r.candidates[2]), LoginFields(url: "", username: "", password: "", notes: "", otpauth: nil))
        XCTAssertEqual(r.candidates[3].kind, .note(NoteFields(notes: "remember the milk\nand bread")))
        XCTAssertEqual(r.candidates[4].kind, .passkey(passkeyFields(der)))
    }

    func testDocumentShape() throws {
        let der = Data(try XCTUnwrap(decodeBase64URL(PasskeyKey.generate().pkcs8B64URL, maxBytes: 4096)))
        let data = try CXFExport.accountJSON([
            ImportCandidate(title: "Plain", kind: .login(LoginFields(url: "https://plain.test", username: "u", password: "p",
                                                                     notes: "", otpauth: nil)), modified: 1_700_000_100),
            ImportCandidate(title: "PK", kind: .passkey(passkeyFields(der))),
        ], now: now)
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(root["username"] as? String, "LocalGateKeys")
        let items = try XCTUnwrap(root["items"] as? [[String: Any]])
        XCTAssertEqual(items.count, 2)
        XCTAssertEqual((items[0]["modifiedAt"] as? NSNumber)?.int64Value, 1_700_000_100)
        XCTAssertEqual((items[1]["modifiedAt"] as? NSNumber)?.int64Value, 1_794_139_200)
        let creds = try XCTUnwrap(items[0]["credentials"] as? [[String: Any]])
        XCTAssertEqual(creds.map { $0["type"] as? String }, ["basic-auth"])
        let password = try XCTUnwrap(creds[0]["password"] as? [String: Any])
        XCTAssertEqual(password["fieldType"] as? String, "concealed-string")
        let key = try XCTUnwrap((items[1]["credentials"] as? [[String: Any]])?.first?["key"] as? String)
        XCTAssertFalse(key.contains("=") || key.contains("+") || key.contains("/"), "base64url PKCS#8 DER, as CXF reads it")
        XCTAssertNotNil(PasskeyKey(pkcs8B64URL: key))
    }

    func testCardRefused() {
        XCTAssertThrowsError(try CXFExport.accountJSON([
            ImportCandidate(title: "Card", kind: .card(CardFields(notes: "", values: ["number": "4111"]))),
        ], now: now)) { XCTAssertEqual($0 as? CXFExport.Failure, .unsupportedKind) }
    }

    // MARK: from the vault

    private struct Vault {
        let snapshot: StoreSnapshot
        let key: String
    }

    private static let ids = ["login": "11111111-1111-4111-8111-111111111111", "other": "22222222-2222-4222-8222-222222222222",
                              "note": "33333333-3333-4333-8333-333333333333", "identity": "44444444-4444-4444-8444-444444444444",
                              "passkey": "55555555-5555-4555-8555-555555555555", "gone": "66666666-6666-4666-8666-666666666666",
                              "badPasskey": "77777777-7777-4777-8777-777777777777"]

    private func id(_ name: String) -> String { Self.ids[name]! }

    private func vault(passkeyNotes: String = "", loginFields: [JSONValue] = []) -> Vault {
        var records = [String: JSONValue]()
        var meta = [String: SyncMeta]()
        func put(_ id: String, _ ns: Namespace, _ fields: [String: JSONValue]) {
            var r: [String: JSONValue] = ["id": .string(id), "created_at": .int(1_700_000_000), "updated_at": .int(1_700_000_100)]
            r.merge(fields) { _, new in new }
            records[id] = Wrapper.make(ns: ns, record: .object(r))
        }
        func web(_ origin: String, _ user: String, _ pw: String, _ label: String) -> [String: JSONValue] {
            ["kind": .string("web"), "label": .string(label), "username": .string(user), "password": .string(pw),
             "scope": .object(["origin": .string(origin),
                               "urls": .array([.object(["url": .string(origin), "match": .string("exact_origin")])])])]
        }
        var a = web("https://a.test", "alice", "pw-alice", "A site")
        a["totp"] = .object(["secret": .string("JBSWY3DPEHPK3PXP"), "digits": .int(6), "period": .int(30), "algorithm": .string("SHA1")])
        a["custom_fields"] = .array(loginFields)
        put(id("login"), .entry, a)
        put(id("other"), .entry, web("https://b.test", "bob", "pw-bob", "B site"))
        put(id("note"), .item, ["kind": .string("note"), "title": .string("Memo"),
                                "payload": .object(["body": .string("the body"), "fields": .array([])])])
        put(id("identity"), .item, ["kind": .string("identity"), "title": .string("Me"),
                                    "payload": .object(["given_name": .string("Alice")])])
        let key = PasskeyKey.generate().pkcs8B64URL
        put(id("passkey"), .item, ["kind": .string("passkey"), "title": .string("PK site"), "payload": .object([
            "relying_party_id": .string("pk.example.test"), "credential_id": .string(base64URLNoPad([1, 2, 3])),
            "user_handle": .string(base64URLNoPad([9])), "private_key": .string(key), "algorithm": .string("ES256"),
            "user_name": .string("carol"), "user_display_name": .string("Carol"), "created": .string("2026-01-02"),
            "notes": .string(passkeyNotes),
        ])])
        put(id("gone"), .item, ["kind": .string("note"), "title": .string("Old"), "payload": .object(["body": .string("x")])])
        put(id("badPasskey"), .item, ["kind": .string("passkey"), "title": .string("Broken PK"), "payload": .object([
            "relying_party_id": .string("bad.example.test"), "credential_id": .string("!!!"),
            "private_key": .string(PasskeyKey.generate().pkcs8B64URL), "algorithm": .string("ES256"), "user_name": .string("dan"),
        ])])
        meta[id("gone")] = SyncMeta.tomb(vv: ["peer": 3], deletedAt: 1_700_000_200)
        return Vault(snapshot: StoreSnapshot(records: records, meta: meta), key: key)
    }

    private func export(_ v: Vault, _ names: [String], calls: inout [[String]], includeTOTP: Bool = true) throws -> CXFExport.Result {
        var seen = [[String]]()
        defer { calls = seen }
        return try CXFExport.export(snapshot: v.snapshot, ids: names.map { id($0) }, release: { ids in
            seen.append(ids)
            return CXFExport.privateKeys(snapshot: v.snapshot, ids: ids)
        }, now: now, includeTOTP: includeTOTP)
    }

    func testOnlySelectedItemsExported() throws {
        let v = vault()
        var calls = [[String]]()
        let result = try export(v, ["login", "note", "passkey"], calls: &calls)
        XCTAssertEqual(calls, [[id("passkey")]], "the keys are asked for once, for the selected passkey only")
        XCTAssertEqual(result.count, 3)
        XCTAssertEqual(result.diagnostics, [])
        let r = try CXFImport.candidates(fromAccountJSON: result.data)
        XCTAssertEqual(r.unsupported, 0)
        XCTAssertEqual(r.candidates.map(\.title), ["A site", "Memo", "PK site"])
        let a = try login(r.candidates[0])
        XCTAssertEqual([a.url, a.username, a.password], ["https://a.test", "alice", "pw-alice"])
        XCTAssertEqual(a.otpauth, "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
        XCTAssertEqual(r.candidates[1].kind, .note(NoteFields(notes: "the body")))
        guard case .passkey(let p) = r.candidates[2].kind else { return XCTFail("not a passkey") }
        XCTAssertEqual(b64u(p.pkcs8), v.key)
        XCTAssertEqual(p.userName, "carol")
        XCTAssertEqual(p.userDisplayName, "Carol")
        XCTAssertEqual(p.credentialID, Data([1, 2, 3]))
        XCTAssertEqual(p.userHandle, Data([9]))
        let text = String(decoding: result.data, as: UTF8.self)
        XCTAssertFalse(text.contains("pw-bob"), "an item that was not selected stays out")
    }

    func testNoPasskeySelectedDoesNotRelease() throws {
        var calls = [[String]]()
        let result = try export(vault(), ["other"], calls: &calls)
        XCTAssertEqual(calls, [])
        XCTAssertEqual(result.count, 1)
    }

    func testDeclinedReleaseMakesNothing() {
        struct Declined: Error {}
        let v = vault()
        XCTAssertThrowsError(try CXFExport.export(snapshot: v.snapshot, ids: [id("login"), id("passkey")],
                                                  release: { _ in throw Declined() }, now: now)) {
            XCTAssertTrue($0 is Declined)
        }
    }

    func testMissingKeyMakesNothing() throws {
        let v = vault()
        let plan = try CXFExport.plan(snapshot: v.snapshot, ids: [id("login"), id("passkey")])
        XCTAssertThrowsError(try CXFExport.finish(plan, released: [:], now: now)) {
            XCTAssertEqual($0 as? CXFExport.Failure, .passkeyKeyMissing(title: "PK site"))
        }
    }

    func testPlanHoldsNoPrivateKey() throws {
        let v = vault()
        let plan = try CXFExport.plan(snapshot: v.snapshot, ids: [id("passkey")])
        XCTAssertEqual(plan.passkeyIDs, [id("passkey")])
        for entry in plan.entries {
            if case .passkey(let f) = entry.candidate.kind { XCTAssertTrue(f.pkcs8.isEmpty) }
        }
        XCTAssertFalse(String(describing: plan).contains(v.key))
    }

    func testDescriptionsShowNoSecrets() throws {
        var calls = [[String]]()
        let result = try export(vault(), ["login", "passkey"], calls: &calls)
        let text = String(describing: result) + String(reflecting: result)
        XCTAssertFalse(text.contains("pw-alice"))
        XCTAssertFalse(text.contains("JBSWY3DPEHPK3PXP"))
        XCTAssertTrue(text.hasPrefix("CXFExport.Result(size: "))
    }

    func testUnsupportedAndDeletedItemsSkippedAndNamed() throws {
        var calls = [[String]]()
        let result = try export(vault(), ["identity", "gone", "note"], calls: &calls)
        XCTAssertEqual(result.count, 1)
        XCTAssertEqual(result.diagnostics, [CXFExport.Diagnostic(kind: .kindSkipped, title: "Me"),
                                            CXFExport.Diagnostic(kind: .kindSkipped, title: "")])
    }

    func testLeftOutFieldsAndPasskeyNotesNamed() throws {
        var calls = [[String]]()
        let v = vault(passkeyNotes: "kept on the device", loginFields: [.object(["name": .string("PIN"), "value": .string("pin-value-4821")])])
        let result = try export(v, ["login", "passkey"], calls: &calls)
        XCTAssertEqual(result.diagnostics, [CXFExport.Diagnostic(kind: .fieldsLeftOut, title: "A site"),
                                            CXFExport.Diagnostic(kind: .passkeyNotesLeftOut, title: "PK site")])
        let text = String(decoding: result.data, as: UTF8.self)
        XCTAssertFalse(text.contains("pin-value-4821"))
        XCTAssertFalse(text.contains("kept on the device"))
    }

    func testTotpLeftOutWhenNotRequested() throws {
        var calls = [[String]]()
        let result = try export(vault(), ["login"], calls: &calls, includeTOTP: false)
        XCTAssertFalse(String(decoding: result.data, as: UTF8.self).contains("JBSWY3DPEHPK3PXP"))
    }

    func testNothingChosenOrNothingExportable() {
        let v = vault()
        XCTAssertThrowsError(try CXFExport.plan(snapshot: v.snapshot, ids: [])) {
            XCTAssertEqual($0 as? CXFExport.Failure, .chooseItems)
        }
        XCTAssertThrowsError(try CXFExport.export(snapshot: v.snapshot, ids: [id("identity")], release: { _ in [:] }, now: now)) {
            XCTAssertEqual($0 as? CXFExport.Failure, .nothingToExport)
        }
    }

    func testUnreadableCredentialIDSkippedNotWrittenEmpty() throws {
        var calls = [[String]]()
        let result = try export(vault(), ["badPasskey", "passkey"], calls: &calls)
        XCTAssertEqual(calls, [[id("passkey")]], "the unreadable passkey's key is never released")
        XCTAssertEqual(result.count, 1)
        XCTAssertEqual(result.diagnostics, [CXFExport.Diagnostic(kind: .passkeyUnreadable, title: "Broken PK")])
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: result.data) as? [String: Any])
        let items = try XCTUnwrap(root["items"] as? [[String: Any]])
        let ids = items.flatMap { ($0["credentials"] as? [[String: Any]]) ?? [] }.compactMap { $0["credentialId"] as? String }
        XCTAssertEqual(ids, [base64URLNoPad([1, 2, 3])])
        XCTAssertEqual(try CXFImport.candidates(fromAccountJSON: result.data).unsupported, 0)
    }

    func testEmptyCredentialIDNeverWritten() throws {
        let der = Data(try XCTUnwrap(decodeBase64URL(PasskeyKey.generate().pkcs8B64URL, maxBytes: 4096)))
        let fields = PasskeyFields(rpID: "pk.example.test", userName: "bob", userDisplayName: "", userHandle: Data(),
                                   credentialID: Data(), pkcs8: der)
        XCTAssertThrowsError(try CXFExport.accountJSON([ImportCandidate(title: "PK", kind: .passkey(fields))], now: now)) {
            XCTAssertEqual($0 as? CXFExport.Failure, .passkeyUnreadable(title: "PK"))
        }
    }

    func testRepeatedIdsExportedOnce() throws {
        var calls = [[String]]()
        let result = try export(vault(), ["note", "note"], calls: &calls)
        XCTAssertEqual(result.count, 1)
    }
}
