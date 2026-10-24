import XCTest
@testable import LGKCore

final class TOTPTests: XCTestCase {
    // RFC 6238 Appendix B; 8 digits, period 30.
    private let seeds: [String: String] = [
        "SHA1": "12345678901234567890",
        "SHA256": "12345678901234567890123456789012",
        "SHA512": "1234567890123456789012345678901234567890123456789012345678901234",
    ]
    private let table: [(Int64, String, String)] = [
        (59, "SHA1", "94287082"), (59, "SHA256", "46119246"), (59, "SHA512", "90693936"),
        (1111111109, "SHA1", "07081804"), (1111111109, "SHA256", "68084774"), (1111111109, "SHA512", "25091201"),
        (1111111111, "SHA1", "14050471"), (1111111111, "SHA256", "67062674"), (1111111111, "SHA512", "99943326"),
        (1234567890, "SHA1", "89005924"), (1234567890, "SHA256", "91819424"), (1234567890, "SHA512", "93441116"),
        (2000000000, "SHA1", "69279037"), (2000000000, "SHA256", "90698825"), (2000000000, "SHA512", "38618901"),
        (20000000000, "SHA1", "65353130"), (20000000000, "SHA256", "77737706"), (20000000000, "SHA512", "47863826"),
    ]

    private func b32(_ s: String) -> String {
        let alpha = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var out = "", acc = 0, bits = 0
        for b in s.utf8 {
            acc = (acc << 8) | Int(b); bits += 8
            while bits >= 5 { bits -= 5; out.append(alpha[(acc >> bits) & 31]) }
            acc &= (1 << bits) - 1
        }
        if bits > 0 { out.append(alpha[(acc << (5 - bits)) & 31]) }
        return out
    }

    func testRFC6238Vectors() throws {
        for (t, alg, expected) in table {
            let code = try TOTP.code(secret: b32(seeds[alg]!), algorithm: alg, digits: 8, period: 30, at: t)
            XCTAssertEqual(code, expected, "\(alg) at \(t)")
        }
    }

    func testSixDigitTruncation() throws {
        XCTAssertEqual(try TOTP.code(secret: b32(seeds["SHA1"]!), algorithm: "SHA1", digits: 6, period: 30, at: 59), "287082")
    }

    func testOddSecretsMatchDesktop() throws {
        func c(_ s: String) throws -> String { try TOTP.code(secret: s, algorithm: "SHA1", digits: 6, period: 30, at: 59) }
        // Desktop (python): all three give 996554.
        XCTAssertEqual(try c("JBSWY3DPEHPK3PXP"), "996554")
        XCTAssertEqual(try c("jbswy3dpehpk3pxp"), "996554")
        XCTAssertEqual(try c("  JBSW Y3DP-EHPK\t3PXP\n"), "996554")
        XCTAssertEqual(try TOTP.code(secret: "JBSWY3DPEHPK3PXP", algorithm: "sha1", digits: 6, period: 30, at: 59), "996554")
        // Desktop raises TotpError for each of these.
        for bad in ["", "   ", "!!!!", "JBSW Y3DP EHPK 3PXP====", "JBSWY3DPEHPK3PXP=", "JBSWY3DPEHPK3PXP======",
                    "JBSWY3DPEHPK3PX=", "GEZDGNA=", "GEZDGNBVGY3TQOJ", "1111111111111111", String(repeating: "A", count: 4097)] {
            XCTAssertThrowsError(try c(bad), bad) { XCTAssertTrue($0 is TOTPError) }
        }
        // Parameter validation.
        XCTAssertThrowsError(try TOTP.code(secret: "JBSWY3DPEHPK3PXP", algorithm: "MD5", digits: 6, period: 30, at: 0))
        XCTAssertThrowsError(try TOTP.code(secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA1", digits: 5, period: 30, at: 0))
        XCTAssertThrowsError(try TOTP.code(secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA1", digits: 9, period: 30, at: 0))
        XCTAssertThrowsError(try TOTP.code(secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA1", digits: 6, period: 14, at: 0))
        XCTAssertThrowsError(try TOTP.code(secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA1", digits: 6, period: 121, at: 0))
        XCTAssertThrowsError(try TOTP.code(secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA1", digits: 6, period: 30, at: -1))
        XCTAssertNoThrow(try TOTP.code(secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA256", digits: 7, period: 15, at: 0))
        XCTAssertNoThrow(try TOTP.code(secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA512", digits: 8, period: 120, at: 0))
    }

    // MARK: editor field parsing (totp.normalize_secret / parse_otpauth_uri)

    func testNormalizeSecretMatchesDesktop() throws {
        XCTAssertEqual(try TOTP.normalizeSecret(" jbsw-y3dp ehpk3pxp "), "JBSWY3DPEHPK3PXP")
        XCTAssertThrowsError(try TOTP.normalizeSecret("JBSW")) { XCTAssertEqual($0 as? TOTPError, .secretTooShort) }
        XCTAssertThrowsError(try TOTP.normalizeSecret("not base32!")) { XCTAssertEqual($0 as? TOTPError, .invalidBase32) }
        XCTAssertThrowsError(try TOTP.normalizeSecret("  ")) { XCTAssertEqual($0 as? TOTPError, .emptySecret) }
    }

    func testParseOtpauthURI() throws {
        let c = try TOTP.parseOtpauthURI("otpauth://totp/Example:ada?secret=jbswy3dpehpk3pxp&issuer=Example&algorithm=sha256&digits=8&period=60")
        XCTAssertEqual(c, TOTPConfig(secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA256", digits: 8, period: 60))
        XCTAssertEqual(try TOTP.parseOtpauthURI("OTPAUTH://TOTP/x?secret=JBSWY3DPEHPK3PXP"), TOTPConfig(secret: "JBSWY3DPEHPK3PXP"))
        XCTAssertThrowsError(try TOTP.parseOtpauthURI("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP")) { XCTAssertEqual($0 as? TOTPError, .notOtpauthURI) }
        XCTAssertThrowsError(try TOTP.parseOtpauthURI("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXP")) {
            XCTAssertEqual($0 as? TOTPError, .duplicateParameter)
        }
        XCTAssertThrowsError(try TOTP.parseOtpauthURI("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=9")) { XCTAssertEqual($0 as? TOTPError, .unsupportedDigits) }
        XCTAssertThrowsError(try TOTP.parseOtpauthURI("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=-1")) { XCTAssertEqual($0 as? TOTPError, .invalidParameter) }
        XCTAssertThrowsError(try TOTP.parseOtpauthURI("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")) { XCTAssertEqual($0 as? TOTPError, .unsupportedAlgorithm) }
    }

    func testParseFieldKeepsDefaultsForBareSecret() throws {
        XCTAssertNil(try TOTP.parseField("   "))
        let d = TOTPConfig(secret: "", algorithm: "SHA512", digits: 7, period: 45)
        XCTAssertEqual(try TOTP.parseField("jbswy3dpehpk3pxp", defaults: d), TOTPConfig(secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA512", digits: 7, period: 45))
    }

    // Expected values checked with python3.12 against src/localvault/totp.py parse_otpauth_uri.
    func testOtpauthMatchesPythonQueryParsing() throws {
        let base = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"
        XCTAssertThrowsError(try TOTP.parseOtpauthURI(base + "&digits")) { XCTAssertEqual($0 as? TOTPError, .invalidParameter) }
        XCTAssertThrowsError(try TOTP.parseOtpauthURI(base + "&secret")) { XCTAssertEqual($0 as? TOTPError, .duplicateParameter) }
        XCTAssertEqual(try TOTP.parseOtpauthURI("otpauth://totp/x?secret=JBSW%59%33DPEHPK3PXP&issuer=%ZZ%41&digits=%38"),
                       TOTPConfig(secret: "JBSWY3DPEHPK3PXP", digits: 8))
        XCTAssertEqual(try TOTP.parseOtpauthURI(base + "#&digits=9"), TOTPConfig(secret: "JBSWY3DPEHPK3PXP"))
        XCTAssertEqual(try TOTP.parseOtpauthURI("otpauth://to\ttp/x?secret=JBSWY3D\nPEHPK3PXP&digits=8"),
                       TOTPConfig(secret: "JBSWY3DPEHPK3PXP", digits: 8))
        XCTAssertEqual(TOTP.pyUnquote("%ZZ%41"), "%ZZA")
        XCTAssertEqual(TOTP.pyUnquote("%C3%A9%FF%4"), "\u{E9}\u{FFFD}%4")
    }
}
