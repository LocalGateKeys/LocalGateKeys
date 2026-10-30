import XCTest
@testable import LGKCore

/// Google Authenticator "Transfer accounts" exports (`totp.py` `parse_migration_uri`) and the issuer/account of
/// an `otpauth://` link, for the 2FA QR scan.
final class OTPMigrationTests: XCTestCase {
    private let alpha = Array("0123456789".utf8)           // 10 bytes: GAYTEMZUGU3DOOBZ
    private let beta = Array("abcdefghijklmnopqrst".utf8)  // 20 bytes

    private func entry(_ secret: [UInt8], name: String, issuer: String, algorithm: Int = 1, digits: Int = 1,
                       type: Int = 2) -> OTPMigration.Entry {
        OTPMigration.Entry(secret: secret, name: name, issuer: issuer, algorithm: algorithm, digits: digits, type: type)
    }

    func testDecodesAccountsWithLabelsAndSettings() throws {
        let uri = OTPMigration.encode([entry(alpha, name: "Alpha:ann@alpha.test", issuer: "Alpha"),
                                       entry(beta, name: "bob", issuer: "", algorithm: 2, digits: 2)])
        let batch = try OTPMigration.parse(uri)
        XCTAssertEqual(batch.batchIndex, 0)
        XCTAssertEqual(batch.batchSize, 1)
        XCTAssertEqual(batch.skipped, [])
        XCTAssertEqual(batch.accounts.count, 2)
        XCTAssertEqual(batch.accounts[0].issuer, "Alpha")
        XCTAssertEqual(batch.accounts[0].account, "ann@alpha.test")   // "Issuer:" prefix dropped
        XCTAssertEqual(batch.accounts[0].config, TOTPConfig(secret: "GAYTEMZUGU3DOOBZ"))
        XCTAssertEqual(batch.accounts[1].config.algorithm, "SHA256")
        XCTAssertEqual(batch.accounts[1].config.digits, 8)
        XCTAssertEqual(batch.accounts[1].account, "bob")
    }

    func testAccountURIRoundTripsThroughTheOtpauthParser() throws {
        let batch = try OTPMigration.parse(OTPMigration.encode([entry(alpha, name: "ann & co:x", issuer: "A/B Corp")]))
        let account = batch.accounts[0]
        XCTAssertEqual(try TOTP.parseOtpauthURI(account.uri), account.config)
        let back = try OTPAccount(otpauth: account.uri)
        XCTAssertEqual(back.issuer, "A/B Corp")
        XCTAssertEqual(back.account, "ann & co:x")
    }

    func testBatchIndexAndSizeAreRead() throws {
        let batch = try OTPMigration.parse(OTPMigration.encode([entry(alpha, name: "a", issuer: "A")], batchIndex: 1, batchSize: 3))
        XCTAssertEqual(batch.batchIndex, 1)
        XCTAssertEqual(batch.batchSize, 3)
    }

    func testHOTPAndBadSettingsAreSkippedWithAReason() throws {
        let batch = try OTPMigration.parse(OTPMigration.encode([
            entry(alpha, name: "h", issuer: "H", type: 1),
            entry(alpha, name: "x", issuer: "X", algorithm: 4),
            entry(Array("short".utf8), name: "s", issuer: "S"),
            entry(alpha, name: "ok", issuer: "OK"),
        ]))
        XCTAssertEqual(batch.accounts.map(\.issuer), ["OK"])
        XCTAssertEqual(batch.skipped.map(\.issuer), ["H", "X", "S"])
        XCTAssertEqual(batch.skipped[0].reason, "Counter-based (HOTP) codes are not supported")
        XCTAssertEqual(batch.skipped[1].reason, "Unsupported algorithm or digit count")
    }

    func testMalformedLinksAreRefused() {
        XCTAssertThrowsError(try OTPMigration.parse("otpauth://totp/x?secret=GAYTEMZUGU3DOOBZ"))
        XCTAssertThrowsError(try OTPMigration.parse("otpauth-migration://offline"))
        XCTAssertThrowsError(try OTPMigration.parse("otpauth-migration://offline?data=%%%"))
        XCTAssertThrowsError(try OTPMigration.parse("otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8"))
        XCTAssertThrowsError(try OTPMigration.parse("otpauth-migration://offline?data=" + String(repeating: "A", count: 70_000)))
        // A batch index outside the batch size.
        XCTAssertThrowsError(try OTPMigration.parse(OTPMigration.encode([entry(alpha, name: "a", issuer: "A")], batchIndex: 2, batchSize: 2)))
    }

    func testURLSafeAndSpacedBase64IsAccepted() throws {
        let uri = OTPMigration.encode([entry(beta, name: "~~~?>>>", issuer: "Q")])
        let data = String(uri.split(separator: "=", maxSplits: 1)[1])
        let decoded = TOTP.pyUnquote(data)
        let urlSafe = decoded.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        XCTAssertEqual(try OTPMigration.parse("otpauth-migration://offline?data=" + urlSafe).accounts.count, 1)
    }

    func testTooManyAccountsIsRefused() {
        let many = (0..<257).map { entry(alpha, name: "n\($0)", issuer: "I") }
        XCTAssertThrowsError(try OTPMigration.parse(OTPMigration.encode(many)))
    }

    func testOtpauthIssuerAndAccount() throws {
        let a = try OTPAccount(otpauth: "otpauth://totp/GitHub:octo%40example.com?secret=GAYTEMZUGU3DOOBZ&issuer=GitHub")
        XCTAssertEqual(a.issuer, "GitHub")
        XCTAssertEqual(a.account, "octo@example.com")
        let b = try OTPAccount(otpauth: "otpauth://totp/Example%20Co%3A%20ann?secret=GAYTEMZUGU3DOOBZ")
        XCTAssertEqual(b.issuer, "Example Co")
        XCTAssertEqual(b.account, "ann")
        let c = try OTPAccount(otpauth: "otpauth://totp/ann?secret=GAYTEMZUGU3DOOBZ&issuer=Site")
        XCTAssertEqual(c.issuer, "Site")
        XCTAssertEqual(c.account, "ann")
        XCTAssertThrowsError(try OTPAccount(otpauth: "otpauth://hotp/x?secret=GAYTEMZUGU3DOOBZ"))
    }

    func testErrorTextNeverHoldsTheSecret() {
        do { _ = try OTPMigration.parse("otpauth-migration://offline?data=GAYTEMZUGU3DOOBZ") } catch let e as OTPMigrationError {
            XCTAssertFalse(e.message.contains("GAYTEMZUGU3DOOBZ"))
        } catch { XCTFail("unexpected \(error)") }
    }
}
