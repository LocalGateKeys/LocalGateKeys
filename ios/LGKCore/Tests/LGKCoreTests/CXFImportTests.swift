import XCTest
import Crypto
@testable import LGKCore

final class CXFImportTests: XCTestCase {
    private func fixture() throws -> (candidates: [ImportCandidate], unsupported: Int) {
        try CXFImport.candidates(fromAccountJSON: Vectors.data("../cxf/apple-passwords-sample.json"))
    }

    private func b64u(_ d: Data) -> String { base64URLNoPad(Array(d)) }

    private func account(passkey: [String: Any]) throws -> Data {
        let item: [String: Any] = ["id": "x", "title": "T", "scope": ["urls": [String](), "androidApps": [String]()],
                                   "credentials": [passkey]]
        return try JSONSerialization.data(withJSONObject: ["items": [item]])
    }

    func testLoginWithTotpAndNote() throws {
        let r = try fixture()
        guard case .login(let f) = r.candidates[0].kind else { return XCTFail("not a login") }
        XCTAssertEqual(r.candidates[0].title, "Example Mail")
        XCTAssertEqual(f.url, "https://mail.example.test/login")
        XCTAssertEqual(f.username, "ada")
        XCTAssertEqual(f.password, "correct horse")
        XCTAssertEqual(f.notes, "recovery in drawer")
        XCTAssertEqual(f.otpauth, "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP&issuer=Example")
        XCTAssertEqual(r.candidates[0].urls, ["https://mail.example.test/login", "https://example.test"])
    }

    func testPasskeyFields() throws {
        let r = try fixture()
        guard case .passkey(let p) = r.candidates[1].kind else { return XCTFail("not a passkey") }
        XCTAssertEqual(p.rpID, "pk.example.test")
        XCTAssertEqual(p.userName, "bob")
        XCTAssertEqual(p.userDisplayName, "Bob B")
        XCTAssertEqual(p.credentialID, Data([1, 2, 3, 4, 5, 6, 7, 8]))
        XCTAssertEqual(p.userHandle, Data([10, 11, 12, 13, 14, 15]))
        XCTAssertNotNil(PasskeyKey(pkcs8B64URL: b64u(p.pkcs8)))
        XCTAssertEqual(b64u(p.pkcs8), try Self.fixtureKey())
    }

    func testItemWithPasswordAndPasskeyGivesTwoCandidates() throws {
        let r = try fixture()
        XCTAssertEqual(r.candidates.count, 3)
        // In item order, an item's passkeys before its login (as on Windows and Android).
        guard case .login(let f) = r.candidates[2].kind else { return XCTFail("not a login") }
        XCTAssertEqual(f.username, "bob")
        XCTAssertNil(f.otpauth)
        XCTAssertEqual(r.candidates[1].title, "Example Passkey Site")
        XCTAssertEqual(r.candidates[2].title, "Example Passkey Site")
    }

    func testCreditCardCountsUnsupported() throws {
        XCTAssertEqual(try fixture().unsupported, 1)
    }

    func testNonP256KeyUnsupported() throws {
        let der = Curve25519.Signing.PrivateKey().pkcs8DER
        let r = try CXFImport.candidates(fromAccountJSON: account(passkey: [
            "type": "passkey", "credentialId": "AQID", "rpId": "a.test", "username": "u",
            "userDisplayName": "U", "userHandle": "AQ", "key": b64u(der)]))
        XCTAssertEqual(r.candidates.count, 0)
        XCTAssertEqual(r.unsupported, 1)
    }

    func testCredentialIdOver1023BytesUnsupported() throws {
        let key = PasskeyKey.generate().pkcs8B64URL
        let r = try CXFImport.candidates(fromAccountJSON: account(passkey: [
            "type": "passkey", "credentialId": b64u(Data(repeating: 7, count: 1024)), "rpId": "a.test",
            "username": "u", "userDisplayName": "U", "userHandle": "AQ", "key": key]))
        XCTAssertEqual(r.candidates.count, 0)
        XCTAssertEqual(r.unsupported, 1)
    }

    private func login(totp: [String: Any]) throws -> (candidates: [ImportCandidate], unsupported: Int) {
        let item: [String: Any] = ["title": "T", "credentials": [
            ["type": "basic-auth", "username": ["value": "u"], "password": ["value": "p"]],
            totp.merging(["type": "totp"]) { a, _ in a }]]
        return try CXFImport.candidates(fromAccountJSON: JSONSerialization.data(withJSONObject: ["items": [item]]))
    }

    private func otp(_ r: (candidates: [ImportCandidate], unsupported: Int)) -> String? {
        guard case .login(let f) = r.candidates[0].kind else { return nil }
        return f.otpauth
    }

    /// As on Windows: the unreadable secret is kept on the login; the import review moves it to a hidden field.
    func testInvalidTotpSecretKeptForTheReview() throws {
        let r = try login(totp: ["secret": "!!!notbase32"])
        XCTAssertEqual(r.candidates.count, 1); XCTAssertEqual(otp(r), "otpauth://totp/u?secret=!!!NOTBASE32")
        XCTAssertEqual(r.unsupported, 0)
    }

    /// As on Windows: digits outside 6...8 fall back to 6, and the code is kept.
    func testTotpDigitsOutOfRangeFallBack() throws {
        let r = try login(totp: ["secret": "JBSWY3DPEHPK3PXP", "digits": 12, "period": true])
        XCTAssertEqual(otp(r), "otpauth://totp/u?secret=JBSWY3DPEHPK3PXP"); XCTAssertEqual(r.unsupported, 0)
    }

    func testTotpLabelPercentEncodedRoundTrips() throws {
        let r = try login(totp: ["secret": "JBSWY3DPEHPK3PXP", "issuer": "Ex & Co", "username": "a b@x.test"])
        let u = try XCTUnwrap(otp(r))
        XCTAssertTrue(u.contains("Ex%20%26%20Co:a%20b@x.test"))
        XCTAssertNoThrow(try TOTP.parseOtpauthURI(u)); XCTAssertEqual(r.unsupported, 0)
    }

    func testLowercaseTotpSecret() throws {
        let r = try login(totp: ["secret": "jbswy3dpehpk3pxp"])
        XCTAssertTrue(try XCTUnwrap(otp(r)).contains("secret=JBSWY3DPEHPK3PXP")); XCTAssertEqual(r.unsupported, 0)
    }

    func testPasskeyUserNameVariantAndStdBase64Padded() throws {
        let key = PasskeyKey.generate().pkcs8B64URL
        let r = try CXFImport.candidates(fromAccountJSON: account(passkey: [
            "type": "passkey", "credentialId": "+/8=", "rpId": "a.test", "userName": "uu",
            "userDisplayName": "U", "key": key]))
        guard case .passkey(let p) = r.candidates[0].kind else { return XCTFail() }
        XCTAssertEqual(p.userName, "uu"); XCTAssertEqual(p.credentialID, Data([0xFB, 0xFF])); XCTAssertEqual(p.userHandle, Data())
    }

    func testMalformedUserHandleUnsupported() throws {
        let key = PasskeyKey.generate().pkcs8B64URL
        for h in ["!!!", b64u(Data(repeating: 1, count: 65))] {
            let r = try CXFImport.candidates(fromAccountJSON: account(passkey: [
                "type": "passkey", "credentialId": "AQID", "rpId": "a.test", "username": "u",
                "userDisplayName": "U", "userHandle": h, "key": key]))
            XCTAssertEqual(r.candidates.count, 0); XCTAssertEqual(r.unsupported, 1)
        }
    }

    // MARK: parity with Windows (tests/test_importer_cxf.py) and Android (CxfImportTest)

    private func parse(_ items: [Any]) throws -> (candidates: [ImportCandidate], unsupported: Int) {
        let root: [String: Any] = ["id": "QQ", "items": items]
        return try CXFImport.candidates(fromAccountJSON: JSONSerialization.data(withJSONObject: root))
    }

    func testOrphanTotpBecomesLoginHoldingTheCode() throws {
        let r = try parse([["id": "a", "title": "Codes", "scope": ["urls": ["https://c.test"]],
                            "credentials": [["type": "totp", "secret": "JBSWY3DPEHPK3PXP"]]]])
        XCTAssertEqual(r.unsupported, 0)
        XCTAssertEqual(r.candidates.count, 1)
        guard case .login(let f) = r.candidates[0].kind else { return XCTFail("not a login") }
        XCTAssertEqual([f.username, f.password], ["", ""])
        XCTAssertEqual(r.candidates[0].urls, ["https://c.test"])
        XCTAssertTrue(try XCTUnwrap(f.otpauth).contains("secret=JBSWY3DPEHPK3PXP"))
    }

    func testOrphanNoteBecomesNote() throws {
        let r = try parse([["id": "a", "title": "Memo", "credentials": [["type": "note", "content": ["value": "hello"]]]]])
        XCTAssertEqual(r.candidates.map(\.kind), [.note(NoteFields(notes: "hello"))])
        XCTAssertEqual(r.candidates.map(\.title), ["Memo"])
    }

    func testSecondBasicAuthIsSkipped() throws {
        let r = try parse([["id": "a", "title": "Two", "scope": ["urls": ["https://two.test"]], "credentials": [
            ["type": "basic-auth", "username": "a", "password": "p1"], ["type": "basic-auth", "username": "b", "password": "p2"]]]])
        XCTAssertEqual(r.candidates.count, 1)
        guard case .login(let f) = r.candidates[0].kind else { return XCTFail("not a login") }
        XCTAssertEqual(f.username, "a")
        XCTAssertEqual(r.unsupported, 1)
    }

    func testExtraTotpBecomesCodeOnlyLoginAndNotesJoin() throws {
        let r = try parse([["id": "a", "title": "Many", "scope": ["urls": ["https://m.test", "https://n.test"]], "credentials": [
            ["type": "basic-auth", "username": "u", "password": "p"],
            ["type": "totp", "secret": "JBSWY3DPEHPK3PXP"], ["type": "totp", "secret": "GEZDGNBVGY3TQOJQ"],
            ["type": "note", "content": "one"], ["type": "note", "content": ["value": "two"]]]]])
        XCTAssertEqual(r.unsupported, 0)
        XCTAssertEqual(r.candidates.count, 2)
        guard case .login(let first) = r.candidates[0].kind, case .login(let extra) = r.candidates[1].kind else {
            return XCTFail("not two logins")
        }
        XCTAssertEqual(first.notes, "one\n\ntwo")
        XCTAssertEqual(first.otpauth, "otpauth://totp/u?secret=JBSWY3DPEHPK3PXP")
        XCTAssertEqual([extra.username, extra.password, extra.notes], ["", "", ""])
        XCTAssertEqual(extra.otpauth, "otpauth://totp/account?secret=GEZDGNBVGY3TQOJQ")
        XCTAssertEqual(r.candidates[1].urls, ["https://m.test", "https://n.test"])
    }

    func testNoteBesideAPasskeyIsKept() throws {
        let key = PasskeyKey.generate().pkcs8B64URL
        let r = try parse([["id": "a", "title": "Site", "credentials": [
            ["type": "passkey", "credentialId": "AQID", "rpId": "PK.Example.Test", "username": "u", "key": key],
            ["type": "note", "content": "recovery codes"]]]])
        XCTAssertEqual(r.unsupported, 0)
        XCTAssertEqual(r.candidates.count, 2)
        XCTAssertEqual(r.candidates[0].kind, .note(NoteFields(notes: "recovery codes")))
        guard case .passkey(let p) = r.candidates[1].kind else { return XCTFail("not a passkey") }
        XCTAssertEqual(p.rpID, "pk.example.test", "the relying party is casefolded, as on Windows and Android")
        XCTAssertEqual(r.candidates[1].urls, ["https://pk.example.test"])
    }

    func testUnknownTypesCountedAndNonObjectItemsIgnored() throws {
        let r = try parse([["id": "a", "title": "X", "credentials": [
            ["type": "ssh-key", "privateKey": "x"], ["type": "wifi"], ["type": "ssh-key"], ["notype": 1]]], 7, "x"])
        XCTAssertEqual(r.candidates.count, 0)
        XCTAssertEqual(r.unsupported, 4)
    }

    func testMalformedCountedNotCrash() throws {
        XCTAssertThrowsError(try CXFImport.candidates(fromAccountJSON: Data("nope".utf8)))
        let r = try CXFImport.candidates(fromAccountJSON: Data(#"{"items":[{"title":"A","credentials":[{"type":"passkey","key":5},{"type":"future"}]},7]}"#.utf8))
        XCTAssertEqual(r.candidates.count, 0)
        XCTAssertGreaterThanOrEqual(r.unsupported, 1)
    }
}

private extension Curve25519.Signing.PrivateKey {
    /// PKCS#8 wrapper for an Ed25519 seed (RFC 8410).
    var pkcs8DER: Data {
        Data([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]) + rawRepresentation
    }
}

extension CXFImportTests {
    static func fixtureKey() throws -> String {
        let o = try Vectors.json("../cxf/apple-passwords-sample.json")
        let items = try XCTUnwrap(o["items"] as? [[String: Any]])
        let creds = try XCTUnwrap(items[1]["credentials"] as? [[String: Any]])
        return try XCTUnwrap(creds.last?["key"] as? String)
    }

    /// docs/PENDING.md: a lone high surrogate escape (`\ud800`) in a CXF file imports with U+FFFD, not a refused file.
    func testLoneHighSurrogateEscapeImportsWithReplacementCharacter() throws {
        let json = #"{"items":[{"id":"a","title":"Memo \ud800 x","credentials":[{"type":"note","content":{"value":"a\ud800b \\ud800 \ud83d\ude00 \udc00"}}]}]}"#
        let r = try CXFImporter.candidates(from: Data(json.utf8), options: ImportOptions())
        XCTAssertEqual(r.candidates.map(\.title), ["Memo \u{FFFD} x"])
        XCTAssertEqual(r.candidates.map(\.kind), [.note(NoteFields(notes: "a\u{FFFD}b \\ud800 \u{1F600} \u{FFFD}"))])
    }
}
