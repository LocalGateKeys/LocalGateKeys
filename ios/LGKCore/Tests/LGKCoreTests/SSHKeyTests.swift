import XCTest
@testable import LGKCore

/// `tests/vectors/ssh` (test-only, published keys from `scripts/make_ssh_vectors.py`): the Mac reads the same keys
/// as the Windows `ssh_keys.py` and gets the same public blobs, fingerprints and signature formats.
final class SSHKeyTests: XCTestCase {
    struct Entry: Decodable {
        let key_type: String
        let public_line: String
        let fingerprint: String
        let signature_blob_b64: String?
    }

    struct Expected: Decodable {
        let passphrase: String
        let sign_data_b64: String
        let keys: [String: Entry]
    }

    private func expected() throws -> Expected {
        try JSONDecoder().decode(Expected.self, from: Data(contentsOf: Vectors.shared("ssh/expected.json")))
    }

    private func text(_ file: String) throws -> String {
        try String(contentsOf: Vectors.shared("ssh/\(file)"), encoding: .utf8)
    }

    private func signData() throws -> [UInt8] { Array(Data(base64Encoded: try expected().sign_data_b64)!) }

    private func blob(ofLine line: String) -> [UInt8] {
        Array(Data(base64Encoded: String(line.split(separator: " ")[1]))!)
    }

    func testLoadEachVectorKey() throws {
        let e = try expected()
        XCTAssertEqual(Set(e.keys.keys), ["ed25519", "ecdsa256", "ecdsa384", "rsa3072"])
        for (name, entry) in e.keys {
            for encrypted in [false, true] {
                let key = try SSHKey.load(try text("\(name)\(encrypted ? "_enc" : "").key"),
                                          passphrase: encrypted ? e.passphrase : nil)
                XCTAssertEqual(key.keyType, entry.key_type, name)
                XCTAssertEqual(key.publicBlob, blob(ofLine: entry.public_line), "\(name) encrypted=\(encrypted)")
                XCTAssertEqual(key.publicLine(comment: "test-only \(name)"), entry.public_line, name)
            }
        }
    }

    func testFingerprints() throws {
        for (name, entry) in try expected().keys {
            XCTAssertEqual(try SSHKey.load(try text("\(name).key"), passphrase: nil).fingerprint, entry.fingerprint, name)
            XCTAssertEqual(SSHKey.fingerprint(of: blob(ofLine: entry.public_line)), entry.fingerprint, name)
            XCTAssertEqual(SSHKey.publicLineBlob(entry.public_line)?.blob, blob(ofLine: entry.public_line), name)
            XCTAssertEqual(SSHKey.publicLineBlob(entry.public_line)?.comment, "test-only \(name)", name)
        }
    }

    /// RFC 8032 Ed25519 signatures are deterministic, but CryptoKit on Apple platforms may randomise them, so the
    /// vector's signature must verify under the loaded key, and ours must verify and have the same layout.
    func testEd25519SignatureMatchesVector() throws {
        let e = try expected(), data = try signData()
        let entry = try XCTUnwrap(e.keys["ed25519"])
        let vector = Array(Data(base64Encoded: try XCTUnwrap(entry.signature_blob_b64))!)
        let key = try SSHKey.load(try text("ed25519.key"), passphrase: nil)
        XCTAssertTrue(SSHSignature.verify(publicBlob: key.publicBlob, signature: vector, data: data))
        let ours = try key.sign(data)
        XCTAssertEqual(ours.count, vector.count)
        XCTAssertEqual(Array(ours.prefix(19)), Array(vector.prefix(19)))   // string("ssh-ed25519"), then the length 64
        XCTAssertTrue(SSHSignature.verify(publicBlob: key.publicBlob, signature: ours, data: data))
        XCTAssertFalse(SSHSignature.verify(publicBlob: key.publicBlob, signature: ours, data: data + [0]))
    }

    func testECDSAAndRSASignaturesVerify() throws {
        let e = try expected(), data = try signData()
        let cases: [(String, UInt32, String)] = [
            ("ecdsa256", 0, "ecdsa-sha2-nistp256"), ("ecdsa384", 0, "ecdsa-sha2-nistp384"),
            ("rsa3072", SSHKey.rsaSHA256, "rsa-sha2-256"), ("rsa3072", SSHKey.rsaSHA512, "rsa-sha2-512"),
            ("rsa3072", SSHKey.rsaSHA256 | SSHKey.rsaSHA512, "rsa-sha2-512"),
        ]
        for (name, flags, algorithm) in cases {
            let key = try SSHKey.load(try text("\(name)_enc.key"), passphrase: e.passphrase)
            let signature = try key.sign(data, flags: flags)
            XCTAssertEqual(SSHWire.strings(signature, count: 1)?.first, Array(algorithm.utf8), name)
            let publicBlob = blob(ofLine: try XCTUnwrap(e.keys[name]).public_line)
            XCTAssertTrue(SSHSignature.verify(publicBlob: publicBlob, signature: signature, data: data), "\(name) \(algorithm)")
            XCTAssertFalse(SSHSignature.verify(publicBlob: publicBlob, signature: signature, data: data + [1]), name)
        }
    }

    func testRSAFlagZeroRefused() throws {
        let key = try SSHKey.load(try text("rsa3072.key"), passphrase: nil)
        let data = try signData()
        XCTAssertThrowsError(try key.sign(data, flags: 0)) { XCTAssertEqual($0 as? SSHKeyError, .sha1Refused) }
        XCTAssertThrowsError(try key.sign(data, flags: 1)) { XCTAssertEqual($0 as? SSHKeyError, .sha1Refused) }
    }

    func testPassphraseRules() throws {
        let e = try expected()
        // An encrypted key without a passphrase (or with an empty one) asks for it; a wrong one is refused.
        let missing: [String?] = [nil, ""]
        for passphrase in missing {
            XCTAssertThrowsError(try SSHKey.load(try text("ed25519_enc.key"), passphrase: passphrase)) {
                XCTAssertEqual($0 as? SSHKeyError, .needsPassphrase)
            }
        }
        XCTAssertThrowsError(try SSHKey.load(try text("ecdsa256_enc.key"), passphrase: "wrong")) {
            XCTAssertEqual($0 as? SSHKeyError, .badPassphrase)
        }
        // A passphrase stored with an unencrypted key is ignored.
        XCTAssertEqual(try SSHKey.load(try text("ed25519.key"), passphrase: e.passphrase).fingerprint,
                       e.keys["ed25519"]?.fingerprint)
    }

    func testUnsupportedKeys() throws {
        for file in ["sk_ed25519.key", "putty.ppk"] {
            XCTAssertThrowsError(try SSHKey.load(try text(file), passphrase: nil)) {
                XCTAssertEqual($0 as? SSHKeyError, .unsupportedFormat, file)
            }
        }
        XCTAssertThrowsError(try SSHKey.load("not a key", passphrase: nil)) { XCTAssertEqual($0 as? SSHKeyError, .unsupportedFormat) }
        XCTAssertThrowsError(try SSHKey.load("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----",
                                             passphrase: nil)) { XCTAssertEqual($0 as? SSHKeyError, .needsPassphrase) }
        XCTAssertTrue(SSHKey.isEncryptedPEM("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"))
        XCTAssertTrue(SSHKey.isEncryptedPEM("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----"))
        XCTAssertFalse(SSHKey.isEncryptedPEM(try text("ed25519_enc.key")), "OpenSSH containers are not PEM")
        XCTAssertNil(SSHKey.publicLineBlob("ssh-dss AAAAB3NzaC1kc3M= x"))
        XCTAssertNil(SSHKey.publicLineBlob("ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQAB"), "the type must match the blob")
    }

    func testCRTExponents() {
        // 1000 mod 7 = 6; 2^64 mod (2^61 - 1) = 8; a zero modulus has no result.
        XCTAssertEqual(BigBytes.mod([0x03, 0xE8], [7]), [6])
        XCTAssertEqual(BigBytes.mod([1, 0, 0, 0, 0, 0, 0, 0, 0], [0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), [8])
        XCTAssertNil(BigBytes.mod([1], [0]))
        XCTAssertEqual(BigBytes.minusOne([1, 0, 0]), [0xFF, 0xFF])
        XCTAssertEqual(BigBytes.minusOne([0, 5]), [4])
    }
}
