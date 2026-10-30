import Foundation
import XCTest
@testable import LGKCore

let GOLDEN = #"{"kdf":{"memory_kib":65536,"parallelism":4,"time_cost":3},"nonce":"CQkJCQkJCQkJCQkJ","salt":"CQkJCQkJCQkJCQkJCQkJCQ==","sealed_key":"2NzRfiY68kD1KRaEwJk8vrgyP4nIkVXR/HasdJ5/AIZ6N5xB9BbojF0Ag/amfKMu","version":1}"#

final class MasterKeyFileTests: XCTestCase {
    struct Fixed: RandomSource {
        func bytes(count: Int) -> [UInt8] { [UInt8](repeating: 9, count: count) }
    }
    let key = [UInt8](0..<32)

    func testSealOpenRoundTrip() throws {
        let f = try MasterKeyFile.seal(localKey: key, password: "correct horse battery", random: Fixed())
        XCTAssertEqual(f.version, 1)
        XCTAssertEqual(f.kdf, MasterKeyFile.KDFParams.default)
        XCTAssertEqual(f.kdf.memoryKiB, 65536)
        XCTAssertEqual(try Base64.decodeStrict(f.salt).count, 16)
        XCTAssertEqual(try Base64.decodeStrict(f.nonce).count, 12)
        XCTAssertEqual(try f.open(password: "correct horse battery"), key)
    }

    func testWrongPasswordThrows() throws {
        let f = try MasterKeyFile.seal(localKey: key, password: "right password", random: Fixed())
        XCTAssertThrowsError(try f.open(password: "wrong password")) {
            XCTAssertEqual($0 as? MasterKeyError, .wrongPassword)
        }
    }

    func testUnicodePasswordNotNormalised() throws {
        let nfc = "\u{00E9}", nfd = "e\u{0301}"
        XCTAssertEqual(nfc, nfd) // Swift treats them as equal; the bytes must not be.
        let f = try MasterKeyFile.seal(localKey: key, password: nfc, random: Fixed())
        XCTAssertEqual(try f.open(password: nfc), key)
        XCTAssertThrowsError(try f.open(password: nfd)) {
            XCTAssertEqual($0 as? MasterKeyError, .wrongPassword)
        }
    }

    func testRejectsOutOfBoundsParams() throws {
        let f = try MasterKeyFile.seal(localKey: key, password: "pw", random: Fixed())
        for (t, m, p) in [(3, 4096, 4), (3, 600 * 1024, 4), (0, 65536, 4), (11, 65536, 4), (3, 65536, 0), (3, 65536, 17)] as [(UInt32, UInt32, UInt32)] {
            var bad = f
            bad.kdf = .init(timeCost: t, memoryKiB: m, parallelism: p)
            XCTAssertThrowsError(try bad.open(password: "pw")) {
                XCTAssertEqual($0 as? MasterKeyError, .badParams)
            }
        }
        var v2 = f; v2.version = 2
        XCTAssertThrowsError(try v2.open(password: "pw")) { XCTAssertEqual($0 as? MasterKeyError, .corrupt) }
        var b = f; b.nonce = "!!"
        XCTAssertThrowsError(try b.open(password: "pw")) { XCTAssertEqual($0 as? MasterKeyError, .corrupt) }
    }

    func testTooLongPasswordThrows() throws {
        let long = String(repeating: "a", count: 4097)
        XCTAssertThrowsError(try MasterKeyFile.seal(localKey: key, password: long, random: Fixed())) {
            XCTAssertEqual($0 as? MasterKeyError, .tooLong)
        }
        let f = try MasterKeyFile.seal(localKey: key, password: String(repeating: "a", count: 4096), random: Fixed())
        XCTAssertThrowsError(try f.open(password: long)) { XCTAssertEqual($0 as? MasterKeyError, .tooLong) }
    }

    func testTwoByteCharsAt4096Succeed() throws {
        let pw = String(repeating: "\u{00E9}", count: 4096)
        let f = try MasterKeyFile.seal(localKey: key, password: pw, random: Fixed())
        XCTAssertEqual(try f.open(password: pw), key)
    }

    func testTamperedSaltAndParamsFail() throws {
        let f = try MasterKeyFile.seal(localKey: key, password: "pw", random: Fixed())
        var s = f; s.salt = Base64.encode([UInt8](repeating: 8, count: 16))
        XCTAssertThrowsError(try s.open(password: "pw")) { XCTAssertEqual($0 as? MasterKeyError, .wrongPassword) }
        var p = f; p.kdf.timeCost = 4
        XCTAssertThrowsError(try p.open(password: "pw")) { XCTAssertEqual($0 as? MasterKeyError, .wrongPassword) }
    }

    func testMemoryBoundsInclusive() throws {
        XCTAssertNoThrow(try MasterKeyFile.validate(.init(timeCost: 3, memoryKiB: 8192, parallelism: 4)))
        XCTAssertNoThrow(try MasterKeyFile.validate(.init(timeCost: 3, memoryKiB: 524288, parallelism: 4)))
        XCTAssertThrowsError(try MasterKeyFile.validate(.init(timeCost: 3, memoryKiB: 8191, parallelism: 4)))
        XCTAssertThrowsError(try MasterKeyFile.validate(.init(timeCost: 3, memoryKiB: 524289, parallelism: 4)))
    }

    func testGoldenJSON() throws {
        let f = try MasterKeyFile.seal(localKey: key, password: "golden", random: Fixed())
        let enc = JSONEncoder(); enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let text = String(decoding: try enc.encode(f), as: UTF8.self)
        XCTAssertEqual(text, GOLDEN)
        let back = try JSONDecoder().decode(MasterKeyFile.self, from: Data(GOLDEN.utf8))
        XCTAssertEqual(try back.open(password: "golden"), key)
    }
}
