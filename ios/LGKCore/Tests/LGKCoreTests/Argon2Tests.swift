import XCTest
@testable import LGKCore

final class Argon2Tests: XCTestCase {
    private func derive(_ pw: [UInt8], _ salt: [UInt8]) throws -> String {
        Vectors.hexString(try Argon2id.derive(password: pw, salt: salt, memoryKiB: 131072,
                                              iterations: 4, parallelism: 4, length: 32))
    }

    func test_argon2_matches_desktop_outputs() throws {
        let exp = try Vectors.json("expected.json")
        let epochs = exp["epochs"] as! [String: Any]
        let existing = (exp["existing_group"] as! [String: Any])["epochs"] as! [String: Any]
        // (keyring file, password, expected key) per fixture
        var cases: [(String, String, String)] = [
            ("keyring_epoch1.json", exp["password_epoch1"] as! String, (epochs["1"] as! [String: Any])["password_wrap_key_hex"] as! String),
            ("keyring_epoch2.json", exp["password_epoch2"] as! String, (epochs["2"] as! [String: Any])["password_wrap_key_hex"] as! String),
        ]
        for (file, ep) in [("keyring_existing_epoch1.json", "1"), ("keyring_existing_epoch3.json", "3")] {
            let e = existing[ep] as! [String: Any]
            cases.append((file, e["password"] as! String, e["password_wrap_key_hex"] as! String))
        }
        for (file, password, want) in cases {
            let kdf = try Vectors.json(file)["kdf"] as! [String: Any]
            XCTAssertEqual(kdf["memory_kib"] as? Int, 131072)
            let salt = [UInt8](Data(base64Encoded: kdf["salt"] as! String)!)
            XCTAssertEqual(try derive(Array(password.utf8), salt), want, file)
        }
    }

    func test_nfc_and_nfd_passwords_differ() throws {
        let u = try Vectors.json("expected.json")["unicode_password"] as! [String: Any]
        let salt = Vectors.hex(u["salt_hex"] as! String)
        let nfc = Vectors.hex(u["password_nfc_utf8_hex"] as! String)
        let nfd = Vectors.hex(u["password_nfd_utf8_hex"] as! String)
        XCTAssertNotEqual(nfc, nfd)
        XCTAssertEqual(Array((u["password_nfc"] as! String).utf8), nfc)
        XCTAssertEqual(Array((u["password_nfd"] as! String).utf8), nfd)
        let a = try derive(nfc, salt), b = try derive(nfd, salt)
        XCTAssertNotEqual(a, b)
        XCTAssertEqual(a, u["argon2id_nfc_hex"] as? String)
        XCTAssertEqual(b, u["argon2id_nfd_hex"] as? String)
    }
}
