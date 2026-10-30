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
        XCTAssertEqual(f.otpauth, "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&algorithm=SHA1")
    }

    func testPasskeyFields() throws {
        let r = try fixture()
        guard case .passkey(let p) = r.candidates[2].kind else { return XCTFail("not a passkey") }
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
        guard case .login(let f) = r.candidates[1].kind else { return XCTFail("not a login") }
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

    func testInvalidTotpSecretDroppedButLoginKept() throws {
        let r = try login(totp: ["secret": "!!!notbase32"])
        XCTAssertEqual(r.candidates.count, 1); XCTAssertNil(otp(r)); XCTAssertEqual(r.unsupported, 1)
    }

    func testTotpDigitsOutOfRangeDropped() throws {
        let r = try login(totp: ["secret": "JBSWY3DPEHPK3PXP", "digits": 12])
        XCTAssertEqual(r.candidates.count, 1); XCTAssertNil(otp(r)); XCTAssertEqual(r.unsupported, 1)
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
}
