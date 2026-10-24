import XCTest
import Foundation
@testable import LGKCore

final class PrimitivesTests: XCTestCase {
    func test_base64_canonical_and_noncanonical() throws {
        XCTAssertEqual(Base64.encode([]), "")
        XCTAssertEqual(Base64.encode(Array("foobar".utf8)), "Zm9vYmFy")
        for (s, b) in [("", ""), ("Zg==", "f"), ("Zm8=", "fo"), ("Zm9v", "foo")] {
            XCTAssertEqual(try Base64.decodeStrict(s), Array(b.utf8))
        }
        for bad in ["Zh==", "Zm9=", "Zg=", "Zg", "Zm9v\n", " Zm9v", "Zg==Zg==", "Z===", "Zm9v====", "Zm-v", "Zm_v", "Zm9", "=Zg=", "Zg=A"] {
            XCTAssertThrowsError(try Base64.decodeStrict(bad), bad)
        }
        XCTAssertEqual(try Base64.decodeStrict("+/+/"), [0xFB, 0xFF, 0xBF])
    }

    func test_base64url_nopad() throws {
        XCTAssertEqual(Base64URL.encodeNoPad([0xFB, 0xFF, 0xBF, 0x01]), "-_-_AQ")
        XCTAssertEqual(try Base64URL.decodeNoPadStrict("-_-_AQ"), [0xFB, 0xFF, 0xBF, 0x01])
        XCTAssertEqual(try Base64URL.decodeNoPadStrict(""), [])
        for bad in ["-_-_AR", "-_-_AQ==", "+/+/", "A", "AAAAA", "Zm 9v", "Zh"] {
            XCTAssertThrowsError(try Base64URL.decodeNoPadStrict(bad), bad)
        }
    }

    func test_identifier_table() {
        let valid = ["a", "A.b_c:d-e", "11111111-aaaa-4000-8000-000000000001", String(repeating: "a", count: 128)]
        for v in valid { XCTAssertTrue(Identifier.isValid(v), v) }
        let invalid = ["", String(repeating: "a", count: 129), "a b", "é", "a/b", "a\n", "a\u{FF21}"]
        for v in invalid { XCTAssertFalse(Identifier.isValid(v), v) }
        for v in ["dev1", "my.device", "COMX", "CON1", "a-b_c"] { XCTAssertTrue(Identifier.isSafeDeviceFile(v), v) }
        for v in ["a:b", ".hidden", "trail.", "con", "Nul", "COM0", "lpt0", "LPT9.txt", "com1.x.y", "aux", "bad id", ""] {
            XCTAssertFalse(Identifier.isSafeDeviceFile(v), v)
        }
    }

    func test_uuid5_known_and_conflict_copies() throws {
        XCTAssertEqual(UUID5.string(UUID5.make(namespace: UUID5.namespaceURL, name: "python.org")),
                       "7af94e2b-4dd9-50f0-9c9a-8a48519bdef0")
        let merge = try Vectors.json("expected_merge.json")
        let copies = merge["conflict_copies"] as! [[String: Any]]
        XCTAssertFalse(copies.isEmpty)
        for c in copies {
            XCTAssertEqual(UUID5.conflictCopyID(itemID: c["original_id"] as! String, contentDigest: c["content_digest"] as! String),
                           c["copy_id"] as! String)
        }
        // Non-UUID id uses the URL-namespace branch.
        let ns = UUID5.make(namespace: UUID5.namespaceURL, name: "lgk-item:note-1")
        XCTAssertEqual(UUID5.conflictCopyID(itemID: "note-1", contentDigest: "ab"),
                       UUID5.string(UUID5.make(namespace: ns, name: "lgk-copy:ab")))
    }

    func test_hkdf_and_gcm() throws {
        // RFC 5869 test case 1
        let okm = CryptoBox.hkdf(ikm: [UInt8](repeating: 0x0b, count: 22), salt: Vectors.hex("000102030405060708090a0b0c"),
                                 info: Vectors.hex("f0f1f2f3f4f5f6f7f8f9"), length: 42)
        XCTAssertEqual(Vectors.hexString(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        let key = [UInt8](repeating: 7, count: 32), nonce = [UInt8](repeating: 9, count: 12)
        let ct = try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: Array("hello".utf8), aad: [1, 2])
        XCTAssertEqual(ct.count, 5 + 16)
        XCTAssertEqual(try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: ct, aad: [1, 2]), Array("hello".utf8))
        XCTAssertThrowsError(try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: ct, aad: [1, 3]))
        var t = ct; t[0] ^= 1
        XCTAssertThrowsError(try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: t, aad: [1, 2]))
        XCTAssertThrowsError(try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: [1, 2], aad: []))
        XCTAssertThrowsError(try CryptoBox.sealGCM(key: [1], nonce: nonce, plaintext: [], aad: []))
    }
}
