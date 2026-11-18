import Crypto
import Foundation
import XCTest
@testable import LGKCore

/// The shared composite-key vectors (`tests/vectors/composite_key`, written by `scripts/make_composite_vectors.py`;
/// Windows `tests/test_composite_key.py` and Android `CompositeKeyTest` read the same files): key files, factor
/// checks, the wrapping key, `MasterKeyFile` v2 and the Windows v4 `vault.json` a Mac restores from a `.lgkfull`
/// (docs/formats/COMPOSITE_KEY_V1.md §1-§6).
final class CompositeKeyTests: XCTestCase {
    private static let dir = Vectors.shared("composite_key")
    private static func file(_ name: String) throws -> Data { try Data(contentsOf: dir.appendingPathComponent(name)) }

    private struct WrongChallenge: Error {}

    /// A fake YubiKey: checks it gets the full 64-byte padded challenge (never the bare 32 bytes) and answers with the
    /// vector's HMAC-SHA1 response; counts how often it was asked. `expected` nil replays the response to any challenge.
    private final class FakeYubiKey: @unchecked Sendable {
        private let lock = NSLock()
        private var asked = 0
        let expected: Data?, response: Data
        init(expected: [UInt8]?, response: [UInt8]) { self.expected = expected.map { Data($0) }; self.response = Data(response) }
        var calls: Int { lock.withLock { asked } }
        var responder: @Sendable (Data) async throws -> Data {
            { [self] challenge in
                lock.withLock { asked += 1 }
                guard expected == nil || challenge == expected else { throw WrongChallenge() }
                return response
            }
        }
    }

    private var root: [String: JSONValue] = [:]

    override func setUpWithError() throws {
        root = obj(try CanonicalJSON.parse(Array(Self.file("cases.json"))))
    }

    // MARK: JSON helpers

    private func obj(_ v: JSONValue?) -> [String: JSONValue] {
        guard case .object(let o)? = v else { XCTFail("not an object"); return [:] }
        return o
    }
    private func arr(_ v: JSONValue?) -> [JSONValue] {
        guard case .array(let a)? = v else { XCTFail("not an array"); return [] }
        return a
    }
    private func str(_ v: JSONValue?) -> String {
        guard case .string(let s)? = v else { XCTFail("not a string"); return "" }
        return s
    }
    private func hex(_ v: JSONValue?) -> [UInt8] { Vectors.hex(str(v)) }
    private func specs(_ v: JSONValue?) throws -> [FactorSpec] { try arr(v).map { try FactorSpec(json: $0) } }
    private func caseNamed(_ name: String) -> [String: JSONValue] {
        arr(root["cases"]).map { obj($0) }.first { str($0["name"]) == name } ?? [:]
    }
    private func keyFileVector(_ name: String) -> [String: JSONValue] {
        arr(root["keyfiles"]).map { obj($0) }.first { str($0["name"]) == name } ?? [:]
    }
    private var yubikey: [String: JSONValue] { obj(root["yubikey"]) }

    private func assertOpenFails(key: [UInt8], nonce: [UInt8], sealed: [UInt8], aad: [UInt8], _ name: String,
                                 file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: sealed, aad: aad),
                             "tampered row \(name) opened the wrapper", file: file, line: line)
    }

    // MARK: - Tests

    func testCompositeVectors() throws {
        let argon = obj(root["argon"])
        let argonOut = hex(argon["output_hex"])
        XCTAssertEqual(try Argon2id.derive(password: Array(str(argon["password"]).utf8), salt: hex(argon["salt_hex"]),
                                           memoryKiB: 8192, iterations: 1, parallelism: 1, length: 32), argonOut)
        XCTAssertEqual(str(root["composite_salt"]), String(decoding: CompositeKey.salt, as: UTF8.self))
        XCTAssertEqual(str(root["check_info"]), String(decoding: CompositeKey.checkInfo, as: UTF8.self))
        let dataKey = hex(root["data_key_hex"])
        let generic = ["no_factors", "keyfile_xml_v2", "keyfile_xml_v1", "keyfile_raw32", "keyfile_hex64", "keyfile_arbitrary",
                       "yubikey_only", "keyfile_and_yubikey"]
        for name in generic {
            let c = caseNamed(name)
            let list = try specs(c["factors"])
            let secrets = arr(c["secrets_hex"]).map { Vectors.hex(str($0)) }
            if list.isEmpty {
                XCTAssertEqual(c["info"], .null)
                XCTAssertEqual(try CompositeKey.combine(argonOut: argonOut, specs: list, secrets: secrets), argonOut, "no factors: Argon2id output")
            } else {
                XCTAssertEqual(String(decoding: try CompositeKey.info(list), as: UTF8.self), str(c["info"]), "info \(name)")
                XCTAssertNoThrow(try CompositeKey.verify(list, secrets: secrets), name)
                for (spec, secret) in zip(list, secrets) { XCTAssertEqual(CompositeKey.check(secret), spec.check, "check \(name)") }
            }
            let key = try CompositeKey.combine(argonOut: argonOut, specs: list, secrets: secrets)
            XCTAssertEqual(Vectors.hexString(key), str(c["combine_hex"]), "combine \(name)")
            let w = obj(c["wrap"])
            XCTAssertEqual(try CryptoBox.openGCM(key: key, nonce: hex(w["nonce_hex"]), ciphertext: hex(w["ciphertext_hex"]),
                                                 aad: hex(w["aad_hex"])), dataKey, "wrap \(name)")
        }
        XCTAssertEqual(Vectors.hexString(try CompositeKey.yubiKeySecret(hex(yubikey["response_hex"]))), str(yubikey["secret_hex"]))
        XCTAssertEqual(CompositeKey.check(hex(yubikey["secret_hex"])), str(yubikey["check"]))
        XCTAssertEqual(Vectors.hexString(try CompositeKey.padChallenge(hex(yubikey["challenge_hex"]))), str(yubikey["padded_challenge_hex"]))
        for p in arr(root["pad_challenge"]).map({ obj($0) }) {
            XCTAssertEqual(Vectors.hexString(try CompositeKey.padChallenge(hex(p["challenge_hex"]))), str(p["padded_hex"]))
        }
        XCTAssertThrowsError(try CompositeKey.yubiKeySecret([UInt8](repeating: 0, count: 19)))
        XCTAssertThrowsError(try CompositeKey.padChallenge([UInt8](repeating: 1, count: 31)))

        // The stored list is strict (§2): one or two valid objects, at most one of each kind, keyfile first.
        let good = caseNamed("keyfile_and_yubikey")["factors"]
        XCTAssertEqual(try CompositeKey.parseList(good), try specs(good))
        let a64 = String(repeating: "a", count: 64)
        let bad = [
            "[]",
            #"[{"check":"10ed9c05250cf31b","kind":"keyfile","slot":2}]"#,
            #"[{"check":"10ED9C05250CF31B","kind":"keyfile"}]"#,
            #"[{"check":"10ed9c05250cf31b","kind":"other"}]"#,
            #"[{"challenge":"\#(a64)","check":"d4cceb1d258554e0","kind":"yubikey-hmac","slot":3}]"#,
            #"[{"challenge":"\#(a64)","check":"d4cceb1d258554e0","kind":"yubikey-hmac","slot":true}]"#,
            #"[{"challenge":"\#(a64)","check":"d4cceb1d258554e0","kind":"yubikey-hmac","slot":2.0}]"#,
            #"[{"challenge":"\#(a64.uppercased())","check":"d4cceb1d258554e0","kind":"yubikey-hmac","slot":2}]"#,
            #"[{"check":"d4cceb1d258554e0","kind":"yubikey-hmac","slot":2}]"#,
            #"[{"challenge":"\#(a64)","check":"d4cceb1d258554e0","kind":"yubikey-hmac","slot":2},{"check":"10ed9c05250cf31b","kind":"keyfile"}]"#,
            #"[{"check":"10ed9c05250cf31b","kind":"keyfile"},{"check":"10ed9c05250cf31b","kind":"keyfile"}]"#,
        ]
        for b in bad { XCTAssertThrowsError(try CompositeKey.parseList(try CanonicalJSON.parse(Array(b.utf8))), b) }

        // A new challenge never ends in 0x00 or 0x20 (a variable-mode slot would drop them): those are drawn again.
        final class Queue: RandomSource, @unchecked Sendable {
            var items: [[UInt8]]
            init(_ items: [[UInt8]]) { self.items = items }
            func bytes(count: Int) -> [UInt8] { items.removeFirst() }
        }
        var end00 = [UInt8](repeating: 1, count: 32); end00[31] = 0
        var end20 = [UInt8](repeating: 1, count: 32); end20[31] = 0x20
        let ok = [UInt8](repeating: 1, count: 32)
        XCTAssertEqual(CompositeKey.newChallenge(random: Queue([end00, end20, ok])), ok)
    }

    func testKeyFileVectors() throws {
        for v in arr(root["keyfiles"]).map({ obj($0) }) {
            let key = try KeyFile.key(from: Self.file(str(v["file"])))
            XCTAssertEqual(Vectors.hexString(key), str(v["key_hex"]), "key file \(str(v["name"]))")
            XCTAssertEqual(CompositeKey.check(key), str(v["check"]), "key file check \(str(v["name"]))")
        }
        for r in arr(root["keyfile_rejects"]).map({ obj($0) }) {
            XCTAssertThrowsError(try KeyFile.key(from: Self.file(str(r["file"]))), str(r["name"])) {
                XCTAssertTrue($0 is KeyFileError, str(r["name"]))
            }
        }
        XCTAssertThrowsError(try KeyFile.key(from: Self.file("keyfiles/reject_xml_doctype.key"))) {
            XCTAssertEqual($0 as? KeyFileError, KeyFileError("Key file contains a DOCTYPE and was rejected"))
        }

        // "Create key file" writes exactly the layout of the vector (the spec's example key).
        let v2 = keyFileVector("keyfile_xml_v2")
        XCTAssertEqual(try KeyFile.keepassXMLv2(key: hex(v2["key_hex"])), try Self.file(str(v2["file"])))
        XCTAssertEqual(try KeyFile.key(from: try KeyFile.newKeepassXMLv2(random: SystemRandomSource())).count, 32)

        // Only ASCII space, tab, CR and LF are whitespace: an NBSP inside the data is refused.
        let key = [UInt8](0..<32)
        let b64 = Base64.encode(key)
        func v1(_ data: String) -> Data { Data("<KeyFile><Meta><Version>1.0</Version></Meta><Key><Data>\(data)</Data></Key></KeyFile>".utf8) }
        let head = String(b64.prefix(10)), tail = String(b64.dropFirst(10))
        XCTAssertEqual(try KeyFile.key(from: v1(" \t\r\n" + head + "\n " + tail + " ")), key)
        XCTAssertThrowsError(try KeyFile.key(from: v1(head + "\u{00A0}" + tail)), "NBSP")
        XCTAssertThrowsError(try KeyFile.key(from: v1(String(b64.dropLast()))), "padding missing")
        XCTAssertThrowsError(try KeyFile.key(from: Data("<KeyFile><Key><Data>".utf8)), "malformed XML") {
            XCTAssertEqual($0 as? KeyFileError, KeyFileError("Key file XML is malformed"))
        }
        // The version is trimmed of ASCII whitespace only; "2" then means hex.
        let hexKey = Vectors.hexString(key).uppercased()
        XCTAssertEqual(try KeyFile.key(from: Data("<KeyFile><Meta><Version> 2.0\n</Version></Meta><Key><Data>\(hexKey)</Data></Key></KeyFile>".utf8)), key)
        // A declared encoding other than UTF-8 / ASCII is refused; UTF-8 in either quote style and case is read.
        let body = "<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data>\(hexKey)</Data></Key></KeyFile>"
        for ok in [#"<?xml version="1.0" encoding="utf-8"?>"#, "<?xml version='1.0' encoding = 'UTF-8'?>", #"<?xml version="1.0"?>"#] {
            XCTAssertEqual(try KeyFile.key(from: Data((ok + body).utf8)), key, ok)
        }
        for bad in [#"<?xml version="1.0" encoding="ISO-8859-1"?>"#, #"<?xml version="1.0" encoding="UTF-16"?>"#] {
            XCTAssertThrowsError(try KeyFile.key(from: Data((bad + body).utf8)), bad) {
                XCTAssertEqual($0 as? KeyFileError, KeyFileError("Key file XML is malformed"))
            }
        }
        // A UTF-8 BOM misses the XML rule: the file is hashed (rule 4), as in the importer.
        let bom = Data([0xEF, 0xBB, 0xBF]) + v1(b64)
        XCTAssertEqual(try KeyFile.key(from: bom), Array(SHA256.hash(data: bom)))
        // A namespaced document has no plain Key/Data.
        XCTAssertThrowsError(try KeyFile.key(from: Data("<KeyFile xmlns=\"urn:x\"><Key><Data>\(b64)</Data></Key></KeyFile>".utf8)))
        // An external entity is never fetched: any DOCTYPE is refused.
        for doc in [
            #"<?xml version="1.0"?><!DOCTYPE KeyFile SYSTEM "http://127.0.0.1:1/x.dtd"><KeyFile/>"#,
            #"<?xml version="1.0"?><!DOCTYPE KeyFile [<!ENTITY x SYSTEM "file:///etc/passwd">]><KeyFile><Key><Data>&x;</Data></Key></KeyFile>"#,
        ] {
            XCTAssertThrowsError(try KeyFile.key(from: Data(doc.utf8)), doc) {
                XCTAssertEqual($0 as? KeyFileError, KeyFileError("Key file contains a DOCTYPE and was rejected"))
            }
        }
        // Without the XML prefix the file is not parsed at all: it is hashed, so nothing is resolved.
        let bare = Data(#"<!DOCTYPE KeyFile [<!ENTITY x SYSTEM "file:///etc/passwd">]><KeyFile/>"#.utf8)
        XCTAssertEqual(try KeyFile.key(from: bare), Array(SHA256.hash(data: bare)))
    }

    func testMasterKeyFileV1Unchanged() async throws {
        struct Fixed: RandomSource { func bytes(count: Int) -> [UInt8] { [UInt8](repeating: 9, count: count) } }
        let enc = JSONEncoder(); enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let localKey = [UInt8](0..<32)
        // No factors: version 1, byte for byte the golden file of `MasterKeyFileTests`.
        for f in [try MasterKeyFile.seal(localKey: localKey, password: "golden", random: Fixed()),
                  try MasterKeyFile.seal(localKey: localKey, password: "golden", random: Fixed(), factors: [], secrets: [])] {
            XCTAssertEqual(f.version, 1)
            XCTAssertNil(f.factors)
            XCTAssertEqual(String(decoding: try enc.encode(f), as: UTF8.self), GOLDEN)
        }
        let back = try JSONDecoder().decode(MasterKeyFile.self, from: Data(GOLDEN.utf8))
        XCTAssertNil(back.factors)
        XCTAssertEqual(back.factorKinds, [])
        XCTAssertEqual(String(decoding: try enc.encode(back), as: UTF8.self), GOLDEN)
        XCTAssertEqual(try back.open(password: "golden"), localKey)
        let opened = try await back.open(password: "golden", factors: FactorSecrets())
        XCTAssertEqual(opened, localKey)
        // A version-1 file with a factor list, or a version-2 file without one, is refused.
        var v1WithFactors = back
        v1WithFactors.factors = [try FactorSpec.keyFile(check: "10ed9c05250cf31b")]
        XCTAssertThrowsError(try v1WithFactors.open(password: "golden")) { XCTAssertEqual($0 as? MasterKeyError, .corrupt) }
        XCTAssertFalse(v1WithFactors.samePasswordWrapper(as: back))
        var v2WithoutFactors = back
        v2WithoutFactors.version = 2
        XCTAssertThrowsError(try v2WithoutFactors.open(password: "golden")) { XCTAssertEqual($0 as? MasterKeyError, .corrupt) }
        do { _ = try await v2WithoutFactors.open(password: "golden", factors: FactorSecrets()); XCTFail("opened") }
        catch { XCTAssertEqual(error as? MasterKeyError, .corrupt) }
        v2WithoutFactors.factors = []
        XCTAssertThrowsError(try v2WithoutFactors.open(password: "golden")) { XCTAssertEqual($0 as? MasterKeyError, .corrupt) }
        // A malformed file is refused before any factor is asked for.
        var badNonce = v1WithFactors
        badNonce.version = 2; badNonce.nonce = "!!"
        XCTAssertThrowsError(try badNonce.factorsForUnlock(password: "golden")) { XCTAssertEqual($0 as? MasterKeyError, .corrupt) }
        XCTAssertThrowsError(try back.factorsForUnlock(password: "")) { XCTAssertEqual($0 as? MasterKeyError, .empty) }
    }

    func testMasterKeyFileV2Vector() async throws {
        let c = caseNamed("apple_masterkeyfile_v2")
        let bytes = try Self.file(str(c["file"]))
        let file = try JSONDecoder().decode(MasterKeyFile.self, from: bytes)
        let list = try specs(c["factors"])
        XCTAssertEqual(file.version, 2)
        XCTAssertEqual(file.factors, list)
        XCTAssertEqual(file.factorKinds, [.yubiKeyHMAC])
        XCTAssertEqual(file.kdf, MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8192, parallelism: 1))
        let enc = JSONEncoder(); enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        XCTAssertEqual(try enc.encode(file), bytes, "decode then encode is byte-identical")

        let y = obj(c["yubikey"])
        XCTAssertEqual(Vectors.hexString(list[0].paddedChallenge), str(y["padded_challenge_hex"]))
        let secret = try CompositeKey.yubiKeySecret(hex(y["response_hex"]))
        XCTAssertEqual(Vectors.hexString(secret), str(y["secret_hex"]))
        let salt = try Base64.decodeStrict(file.salt)
        let argonOut = try MasterKeyFile.derive(str(c["password"]), salt: salt, params: file.kdf)
        XCTAssertEqual(Vectors.hexString(argonOut), str(c["argon_out_hex"]))
        XCTAssertEqual(Vectors.hexString(try CompositeKey.combine(argonOut: argonOut, specs: list, secrets: [secret])), str(c["key_hex"]))
        XCTAssertEqual(Vectors.hexString(try MasterKeyFile.aad(file.kdf, salt: file.salt, factors: list)), str(c["aad_hex"]))

        let localKey = hex(c["local_key_hex"])
        XCTAssertEqual(try file.open(password: str(c["password"]), secrets: [secret]), localKey)
        let yk = FakeYubiKey(expected: hex(y["padded_challenge_hex"]), response: hex(y["response_hex"]))
        let opened = try await file.open(password: str(c["password"]), factors: FactorSecrets(yubiKey: yk.responder))
        XCTAssertEqual(opened, localKey)
        XCTAssertEqual(yk.calls, 1)

        // Every tampered row's key and AAD fail to open `sealed_key`.
        let nonce = try Base64.decodeStrict(file.nonce), sealed = try Base64.decodeStrict(file.sealedKey)
        for t in arr(c["tampered"]).map({ obj($0) }) {
            XCTAssertEqual(str(t["expect"]), "unwrap-fails")
            assertOpenFails(key: hex(t["key_hex"]), nonce: nonce, sealed: sealed, aad: hex(t["aad_hex"]), str(t["name"]))
        }
        // The same edits made to the file: the right secret no longer opens it.
        var slotEdited = file
        slotEdited.factors = [try FactorSpec(kind: .yubiKeyHMAC, check: list[0].check, slot: 2, challenge: list[0].challenge)]
        XCTAssertThrowsError(try slotEdited.open(password: str(c["password"]), secrets: [secret])) {
            XCTAssertEqual($0 as? MasterKeyError, .wrongPassword)
        }
        var removed = file
        removed.version = 1; removed.factors = nil
        XCTAssertThrowsError(try removed.open(password: str(c["password"]))) { XCTAssertEqual($0 as? MasterKeyError, .wrongPassword) }

        // Without the factor: "factor required", never "wrong password"; another YubiKey: a mismatch.
        XCTAssertThrowsError(try file.open(password: str(c["password"]))) { XCTAssertEqual($0 as? FactorError, .required([.yubiKeyHMAC])) }
        do { _ = try await file.open(password: str(c["password"]), factors: FactorSecrets()); XCTFail("opened without the YubiKey") }
        catch { XCTAssertEqual(error as? FactorError, .required([.yubiKeyHMAC])) }
        let other = FakeYubiKey(expected: hex(y["padded_challenge_hex"]), response: hex(yubikey["response_hex"]))
        do { _ = try await file.open(password: str(c["password"]), factors: FactorSecrets(yubiKey: other.responder)); XCTFail("opened with another YubiKey") }
        catch { XCTAssertEqual(error as? FactorError, .mismatch(.yubiKeyHMAC)) }
        // The right factor with a wrong password: a wrong password.
        XCTAssertThrowsError(try file.open(password: "not the password", secrets: [secret])) {
            XCTAssertEqual($0 as? MasterKeyError, .wrongPassword)
        }

        // Sealing with factors writes version 2; it opens again, and a password change renews the challenge.
        let keyFileBytes = try Self.file(str(keyFileVector("keyfile_xml_v2")["file"]))
        let kf = try CompositeKey.enrolKeyFile(keyFileBytes)
        let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8192, parallelism: 1)
        let sealedV2 = try MasterKeyFile.seal(localKey: localKey, password: "river otter lantern 42", params: cheap,
                                              random: SystemRandomSource(), factors: [kf.spec, list[0]], secrets: [kf.secret, secret])
        XCTAssertEqual(sealedV2.version, 2)
        XCTAssertEqual(sealedV2.factorKinds, [.keyFile, .yubiKeyHMAC])
        let round = try JSONDecoder().decode(MasterKeyFile.self, from: try enc.encode(sealedV2))
        XCTAssertEqual(round, sealedV2)
        XCTAssertEqual(try round.open(password: "river otter lantern 42", secrets: [kf.secret, secret]), localKey)
        XCTAssertThrowsError(try MasterKeyFile.seal(localKey: localKey, password: "pw", params: cheap, random: SystemRandomSource(),
                                                    factors: [list[0], kf.spec], secrets: [secret, kf.secret]), "yubikey before keyfile")

        // A factor entry with an unknown field is refused when the file is read.
        let extra = String(decoding: bytes, as: UTF8.self).replacingOccurrences(of: #""slot":1"#, with: #""slot":1,"x":1"#)
        XCTAssertThrowsError(try JSONDecoder().decode(MasterKeyFile.self, from: Data(extra.utf8)))
    }

    func testDesktopVaultV4Vector() async throws {
        let c = caseNamed("windows_v4_header")
        let data = try Self.file(str(c["file"]))
        let password = str(c["password"])
        let list = try specs(c["factors"])
        XCTAssertEqual(try DesktopVaultFile.factors(in: data), list)
        let keyFileBytes = try Self.file(str(keyFileVector("keyfile_xml_v2")["file"]))
        let yk = FakeYubiKey(expected: hex(yubikey["padded_challenge_hex"]), response: hex(yubikey["response_hex"]))
        let factors = FactorSecrets(keyFile: keyFileBytes, yubiKey: yk.responder)

        // The vault opens with the password and both factors, and its catalog is the generator's.
        let (payload, recovery) = try await DesktopVaultFile.openPayload(data, password: password, factors: factors)
        XCTAssertEqual(JSONValue.object(payload), c["payload"])
        XCTAssertTrue(recovery)
        XCTAssertEqual(yk.calls, 1)
        // The recovery phrase opens it without the factors (every AAD uses the v3 identity).
        let entropy = try BIP39.entropy(from: str(c["recovery_phrase"]))
        XCTAssertEqual(Vectors.hexString([UInt8](entropy)), str(c["recovery_entropy_hex"]))
        XCTAssertNoThrow(try DesktopVaultFile.open(data, recoveryEntropy: entropy))

        // The AADs and keys are the generator's.
        guard case .object(let header) = try CanonicalJSON.parse(Array(data)), case .object(let kdf)? = header["kdf"] else {
            return XCTFail("header")
        }
        let wrapperAAD = try DesktopVaultFile.wrapperAADFor(header, kdf: .object(kdf), factors: list)
        XCTAssertEqual(wrapperAAD, try Base64.decodeStrict(str(c["wrapper_aad_b64"])))
        XCTAssertEqual(try DesktopVaultFile.catalogAADFor(header), try Base64.decodeStrict(str(c["catalog_aad_b64"])))
        let recoveryMeta: JSONValue = .object(["kind": .string("bip39-english-24"), "salt": obj(obj(header["wrappers"])["recovery"])["salt"]!])
        XCTAssertEqual(try DesktopVaultFile.wrapperAADFor(header, name: "recovery", metadata: recoveryMeta),
                       try Base64.decodeStrict(str(c["recovery_aad_b64"])))
        let (params, salt) = try DesktopVaultFile.kdfParameters(kdf)
        let argonOut = try DesktopVaultFile.derive(password, kdf: params, salt: salt)
        XCTAssertEqual(Vectors.hexString(argonOut), str(c["argon_out_hex"]))
        let secrets = [try KeyFile.key(from: keyFileBytes), try CompositeKey.yubiKeySecret(hex(yubikey["response_hex"]))]
        let kek = try CompositeKey.combine(argonOut: argonOut, specs: list, secrets: secrets)
        XCTAssertEqual(Vectors.hexString(kek), str(c["kek_hex"]))
        let pw = obj(obj(header["wrappers"])["password"])
        let nonce = try Base64.decodeStrict(str(pw["nonce"])), sealed = try Base64.decodeStrict(str(pw["ciphertext"]))
        XCTAssertEqual(try CryptoBox.openGCM(key: kek, nonce: nonce, ciphertext: sealed, aad: wrapperAAD), hex(c["data_key_hex"]))

        // Every tampered row's key and AAD fail to open the stored password wrapper.
        for t in arr(c["tampered"]).map({ obj($0) }) {
            XCTAssertEqual(str(t["expect"]), "unwrap-fails")
            assertOpenFails(key: hex(t["key_hex"]), nonce: nonce, sealed: sealed, aad: hex(t["aad_hex"]), str(t["name"]))
        }
        // The factor list removed (written as v3): a wrong password, never opened.
        let stripped = try Self.file("windows_v4_tampered_no_factors.json")
        XCTAssertEqual(try DesktopVaultFile.factors(in: stripped), [])
        XCTAssertThrowsError(try DesktopVaultFile.openPayload(stripped, password: password)) {
            XCTAssertEqual($0 as? DesktopVaultError, .wrongPassword)
        }
        // The slot or the challenge edited in the file: the right factors (the YubiKey's answer replayed) no longer open it.
        let replay = FactorSecrets(keyFile: keyFileBytes, yubiKey: FakeYubiKey(expected: nil, response: hex(yubikey["response_hex"])).responder)
        let text = String(decoding: data, as: UTF8.self)
        let challenge = list[1].challenge ?? ""
        let edits = [text.replacingOccurrences(of: #""slot":2"#, with: #""slot":1"#),
                     text.replacingOccurrences(of: challenge, with: String(challenge.reversed()))]
        for edited in edits {
            XCTAssertNotEqual(edited, text)
            do { _ = try await DesktopVaultFile.openPayload(Data(edited.utf8), password: password, factors: replay); XCTFail("edited vault opened") }
            catch { XCTAssertEqual(error as? DesktopVaultError, .wrongPassword) }
        }

        // Without the factors: "factor required" (offer them or the phrase), never "wrong password".
        XCTAssertThrowsError(try DesktopVaultFile.openPayload(data, password: password)) {
            XCTAssertEqual($0 as? FactorError, .required([.keyFile, .yubiKeyHMAC]))
        }
        do { _ = try await DesktopVaultFile.openPayload(data, password: password, factors: FactorSecrets(keyFile: keyFileBytes)); XCTFail("opened") }
        catch { XCTAssertEqual(error as? FactorError, .required([.yubiKeyHMAC])) }
        // Another key file: a mismatch, and the YubiKey is not asked.
        let wrongFile = try Self.file(str(keyFileVector("keyfile_xml_v1")["file"]))
        let unasked = FakeYubiKey(expected: hex(yubikey["padded_challenge_hex"]), response: hex(yubikey["response_hex"]))
        do {
            _ = try await DesktopVaultFile.openPayload(data, password: password, factors: FactorSecrets(keyFile: wrongFile, yubiKey: unasked.responder))
            XCTFail("opened with another key file")
        } catch { XCTAssertEqual(error as? FactorError, .mismatch(.keyFile)) }
        XCTAssertEqual(unasked.calls, 0)
        // The right factors and a wrong password: a wrong password.
        do { _ = try await DesktopVaultFile.openPayload(data, password: "not the master password", factors: factors); XCTFail("opened") }
        catch { XCTAssertEqual(error as? DesktopVaultError, .wrongPassword) }

        // Header checks (`_validate_v4_header`): no factors, a v4 identifier on v3, an extra wrapper field, a newer version.
        func refused(_ edited: String, _ message: String, file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertThrowsError(try DesktopVaultFile.openPayload(Data(edited.utf8), password: password), file: file, line: line) {
                XCTAssertEqual(($0 as? DesktopVaultError)?.message, message, file: file, line: line)
            }
        }
        let factorsJSON = String(text[text.range(of: #","factors":["#)!.lowerBound..<text.range(of: #"}],"nonce""#)!.upperBound])
        refused(text.replacingOccurrences(of: factorsJSON, with: #","nonce""#), "Vault key wrapper is malformed")
        refused(text.replacingOccurrences(of: "localgatekeys-vault-v4", with: "localgatekeys-vault-v3"), "Unsupported vault format identifier")
        refused(text.replacingOccurrences(of: #""version":4"#, with: #""version":3"#), "Unsupported vault format identifier")
        refused(text.replacingOccurrences(of: #""nonce":"8lwySBYeNxCoZsET""#, with: #""nonce":"8lwySBYeNxCoZsET","x":1"#),
                "Vault key wrapper is malformed")
        refused(text.replacingOccurrences(of: #""version":4"#, with: #""version":5"#), "This vault needs a newer LocalGateKeys")
        refused(text.replacingOccurrences(of: #""slot":2"#, with: #""slot":3"#), "Vault key factors are malformed")
    }

    func testMismatchBeforeKDF() async throws {
        let c = caseNamed("apple_masterkeyfile_v2")
        let file = try JSONDecoder().decode(MasterKeyFile.self, from: try Self.file(str(c["file"])))
        let password = str(c["password"])
        var runs = 0
        let counting: (String, [UInt8], MasterKeyFile.KDFParams) throws -> [UInt8] = { pw, salt, params in
            runs += 1
            return try MasterKeyFile.derive(pw, salt: salt, params: params)
        }
        let otherSecret = try CompositeKey.yubiKeySecret(hex(yubikey["response_hex"]))
        XCTAssertThrowsError(try file.open(password: password, secrets: [otherSecret], derive: counting)) {
            XCTAssertEqual($0 as? FactorError, .mismatch(.yubiKeyHMAC))
        }
        XCTAssertThrowsError(try file.open(password: password, secrets: [], derive: counting)) {
            XCTAssertEqual($0 as? FactorError, .required([.yubiKeyHMAC]))
        }
        XCTAssertThrowsError(try file.open(password: password, secrets: [[UInt8](repeating: 0, count: 31)], derive: counting)) {
            XCTAssertEqual($0 as? FactorError, .mismatch(.yubiKeyHMAC))
        }
        XCTAssertEqual(runs, 0, "no Argon2id run for a missing or wrong factor")
        let secret = try CompositeKey.yubiKeySecret(hex(obj(c["yubikey"])["response_hex"]))
        XCTAssertEqual(try file.open(password: password, secrets: [secret], derive: counting), hex(c["local_key_hex"]))
        XCTAssertEqual(runs, 1)

        // A file that is not a usable key file is a mismatch (not a wrong password); the YubiKey is never asked first.
        let v4 = try Self.file(str(caseNamed("windows_v4_header")["file"]))
        let yk = FakeYubiKey(expected: hex(yubikey["padded_challenge_hex"]), response: hex(yubikey["response_hex"]))
        let reject = try Self.file("keyfiles/reject_xml_v2_bad_hash.keyx")
        do {
            _ = try await DesktopVaultFile.openPayload(v4, password: password, factors: FactorSecrets(keyFile: reject, yubiKey: yk.responder))
            XCTFail("opened with a broken key file")
        } catch { XCTAssertEqual(error as? FactorError, .mismatch(.keyFile)) }
        XCTAssertEqual(yk.calls, 0)
    }
}
