import XCTest
@testable import LGKCore

/// `tests/vectors/ssh/bcrypt_pbkdf.json` (Python `bcrypt.kdf`, `scripts/make_ssh_vectors.py`): OpenSSH's key
/// derivation for encrypted private keys gives exactly the vector's bytes.
final class BcryptPBKDFTests: XCTestCase {
    struct Case: Decodable {
        let name: String
        let password: String
        let salt_hex: String
        let rounds: Int
        let length: Int
        let key_hex: String
    }

    struct File: Decodable { let cases: [Case] }

    func testBcryptPBKDFVectors() throws {
        let file = try JSONDecoder().decode(File.self, from: Data(contentsOf: Vectors.shared("ssh/bcrypt_pbkdf.json")))
        XCTAssertGreaterThanOrEqual(file.cases.count, 5)
        XCTAssertTrue(file.cases.contains { $0.rounds == 16 && $0.length == 48 }, "OpenSSH's default is covered")
        for c in file.cases {
            let key = try BcryptPBKDF.derive(password: Array(c.password.utf8), salt: Vectors.hex(c.salt_hex),
                                             rounds: c.rounds, length: c.length)
            XCTAssertEqual(Vectors.hexString(key), c.key_hex, "vector \(c.name)")
        }
    }

    func testOpenBSDLimitsAreRefused() {
        let cases: [([UInt8], [UInt8], Int, Int)] = [([], [1], 1, 16), ([1], [], 1, 16), ([1], [1], 0, 16),
                                                     ([1], [1], 1, 0), ([1], [1], 1, 1025)]
        for (password, salt, rounds, length) in cases {
            XCTAssertThrowsError(try BcryptPBKDF.derive(password: password, salt: salt, rounds: rounds, length: length))
        }
    }
}
