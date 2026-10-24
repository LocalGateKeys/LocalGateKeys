import XCTest
import Foundation
import Crypto
@testable import LGKCore

final class PasskeyBytesTests: XCTestCase {

    private func list(_ name: String) throws -> [[String: Any]] {
        guard let a = try JSONSerialization.jsonObject(with: Vectors.data("passkeys/\(name)")) as? [[String: Any]],
              !a.isEmpty else { throw CocoaError(.fileReadCorruptFile) }
        return a
    }

    private func key(_ v: [String: Any]) throws -> PasskeyKey {
        try XCTUnwrap(PasskeyKey(pkcs8B64URL: v["private_key_b64u"] as! String))
    }

    func test_aaguid_constant() {
        XCTAssertEqual(Vectors.hexString(Passkey.aaguid), "b7d2a6f01c4e4a5b9e3d5a1f7c2e8d41")
        XCTAssertEqual(Passkey.credentialIDLength, 16)
    }

    func test_authenticator_data_matches_vectors() throws {
        for v in try list("assertion.json") {
            let ad = authenticatorData(rpID: v["rp_id"] as! String, userVerified: v["user_verified"] as! Bool, attested: nil)
            XCTAssertEqual(Vectors.hexString(ad), v["authenticator_data_hex"] as! String)
        }
        for v in try list("registration.json") {
            let k = try key(v)
            let ad = authenticatorData(rpID: v["rp_id"] as! String, userVerified: true,
                                       attested: (Vectors.hex(v["credential_id_hex"] as! String), coseES256Key(k.publicKey)))
            XCTAssertEqual(Vectors.hexString(ad), v["authenticator_data_hex"] as! String)
        }
    }

    func test_cose_key_matches_vectors() throws {
        for v in try list("registration.json") {
            XCTAssertEqual(Vectors.hexString(coseES256Key(try key(v).publicKey)), v["cose_key_hex"] as! String)
        }
    }

    func test_attestation_object_matches_vectors() throws {
        for v in try list("registration.json") {
            let att = noneAttestationObject(authData: Vectors.hex(v["authenticator_data_hex"] as! String))
            XCTAssertEqual(Vectors.hexString(att), v["attestation_object_hex"] as! String)
        }
    }

    func test_signature_verifies_with_vector_public_key() throws {
        for v in try list("assertion.json") {
            let k = try key(v)
            let x = Vectors.hex(v["public_key_x_hex"] as! String), y = Vectors.hex(v["public_key_y_hex"] as! String)
            let pub = try P256.Signing.PublicKey(rawRepresentation: x + y)
            XCTAssertEqual(k.publicKey.rawRepresentation, pub.rawRepresentation)
            let ad = Vectors.hex(v["authenticator_data_hex"] as! String)
            let cdh = Vectors.hex(v["client_data_hash_hex"] as! String)
            let der = try k.sign(authData: ad, clientDataHash: cdh)
            let sig = try P256.Signing.ECDSASignature(derRepresentation: der)
            XCTAssertTrue(pub.isValidSignature(sig, for: ad + cdh))
            XCTAssertFalse(pub.isValidSignature(sig, for: ad + cdh + [0]))
        }
    }

    func test_pkcs8_roundtrip_matches_desktop_encoding() throws {
        for v in try list("assertion.json") + list("registration.json") {
            XCTAssertEqual(try key(v).pkcs8B64URL, v["private_key_b64u"] as! String)
        }
        let g = PasskeyKey.generate()
        let back = try XCTUnwrap(PasskeyKey(pkcs8B64URL: g.pkcs8B64URL))
        XCTAssertEqual(back.publicKey.rawRepresentation, g.publicKey.rawRepresentation)
        XCTAssertTrue(g.pkcs8B64URL.hasPrefix("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg"))
    }

    func test_rejects_non_p256_key() throws {
        let records = try list("records.json")
        var checked = 0
        for r in records where ["rs256-import", "garbage-key"].contains(r["name"] as? String) {
            XCTAssertEqual(r["usable"] as? Bool, false)
            let pk = (r["input"] as! [String: Any])["private_key"] as! String
            XCTAssertNil(PasskeyKey(pkcs8B64URL: pk), r["name"] as! String); checked += 1
        }
        XCTAssertEqual(checked, 2)
        XCTAssertNil(PasskeyKey(pkcs8B64URL: ""))
        XCTAssertNil(PasskeyKey(pkcs8B64URL: "MIGH+AgEA"))
    }

    func test_rejects_ed25519_pkcs8() {
        // PKCS#8 wrapper for an Ed25519 key (OID 1.3.101.112) around a swift-crypto Curve25519 seed.
        let seed = Array(Curve25519.Signing.PrivateKey().rawRepresentation)
        let der: [UInt8] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                            0x04, 0x22, 0x04, 0x20] + seed
        XCTAssertNil(PasskeyKey(pkcs8B64URL: base64URLNoPad(der)))
    }

    func test_base64url_helpers() {
        XCTAssertEqual(base64URLNoPad([0xfb, 0xff]), "-_8")
        XCTAssertEqual(decodeBase64URL("-_8", maxBytes: 2), [0xfb, 0xff])
        XCTAssertNil(decodeBase64URL("-_8", maxBytes: 1))
        XCTAssertNil(decodeBase64URL("-_8=", maxBytes: 4))
        XCTAssertNil(decodeBase64URL("abcde", maxBytes: 8))
        XCTAssertEqual(decodeBase64URL("", maxBytes: 4), [])
    }

    func test_sign_rejects_client_data_hash_not_32_bytes() throws {
        let k = PasskeyKey.generate()
        for n in [0, 31, 33, 64] {
            XCTAssertThrowsError(try k.sign(authData: [1, 2, 3], clientDataHash: [UInt8](repeating: 7, count: n))) {
                XCTAssertEqual($0 as? PasskeyKeyError, .badClientDataHash, "\(n)")
            }
        }
        XCTAssertNoThrow(try k.sign(authData: [1, 2, 3], clientDataHash: [UInt8](repeating: 7, count: 32)))
    }

    func test_authenticator_data_accepts_max_u16_credential_id() {
        let id = [UInt8](repeating: 1, count: 0xFFFF)
        let ad = authenticatorData(rpID: "example.com", userVerified: true, attested: (id, [0xA0]))
        XCTAssertEqual(Array(ad[53..<55]), [0xFF, 0xFF])
    }
}
