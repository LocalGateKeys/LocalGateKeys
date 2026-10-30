import Foundation
import XCTest
@testable import LGKCore

/// The recovery phrase (Windows `vault.py` `phrase_from_entropy` / `entropy_from_phrase` and the `bip39-english-24`
/// wrapper), pinned to `tests/vectors/recovery` (written by `scripts/gen_mac_backup_vectors.py recovery`).
/// `from_mac_vault.json` is written here and opened with the phrase by `tests/test_mac_backup_vectors.py`.
final class BIP39Tests: XCTestCase {
    private static let dir = Vectors.root.deletingLastPathComponent().appendingPathComponent("recovery", isDirectory: true)
    private static let cheap = FullBackupV2.KDF(timeCost: 1, memoryKiB: 8192, parallelism: 1)

    private static func doc(_ name: String) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Data(contentsOf: dir.appendingPathComponent(name))) as! [String: Any]
    }

    private static func typed() throws -> [String: [String: String]] {
        try doc("phrases.json")["typed"] as! [String: [String: String]]
    }

    private func message(_ body: () throws -> Any) -> String? {
        do { _ = try body(); return nil } catch let e as RecoveryPhraseError { return e.message } catch { return "\(error)" }
    }

    func testPhrasesMatchPython() throws {
        let phrases = try Self.doc("phrases.json")["phrases"] as! [[String: String]]
        XCTAssertEqual(phrases.count, 12)
        for p in phrases {
            let entropy = Vectors.hex(p["entropy"]!)
            XCTAssertEqual(try BIP39.phrase(entropy: Data(entropy)), p["phrase"])
            XCTAssertEqual(Array(try BIP39.entropy(from: p["phrase"]!)), entropy)
        }
        XCTAssertThrowsError(try BIP39.phrase(entropy: Data(count: 16)))
    }

    func testNormalisesSpacingAndCase() throws {
        var checked = 0
        for (name, c) in try Self.typed() {
            guard let hex = c["entropy"] else { continue }
            XCTAssertEqual(Vectors.hexString(Array(try BIP39.entropy(from: c["input"]!))), hex, name)
            checked += 1
        }
        XCTAssertEqual(checked, 5)   // extra spaces, tabs and newlines, capitals, fullwidth, non-breaking spaces
    }

    func testBadChecksumMessage() throws {
        let cases = try Self.typed()
        XCTAssertEqual(message { try BIP39.entropy(from: cases["bad checksum"]!["input"]!) },
                       "The recovery phrase checksum does not match; check the word order")
        for (name, c) in cases {
            guard let error = c["error"] else { continue }
            XCTAssertEqual(message { try BIP39.entropy(from: c["input"]!) }, error, name)
        }
    }

    func testTwentyThreeWordsRefused() throws {
        let c = try Self.typed()["23 words"]!
        XCTAssertEqual(message { try BIP39.entropy(from: c["input"]!) }, "A recovery phrase has exactly 24 words")
    }

    func testWordListDigestChecked() throws {
        XCTAssertEqual(try BIP39.words().count, 2048)
        XCTAssertEqual(BIP39.wordListSHA256, try Self.doc("phrases.json")["word_list_sha256"] as? String)
        let damaged = BIP39.englishText.replacingOccurrences(of: "zoo", with: "zoa")
        XCTAssertThrowsError(try BIP39.load(damaged)) {
            XCTAssertEqual(($0 as? RecoveryPhraseError)?.message, "The recovery word list is damaged; recovery phrases are unavailable")
        }
        XCTAssertThrowsError(try BIP39.load("abandon ability"))
        XCTAssertEqual(try BIP39.load(BIP39.englishText).count, 2048)
    }

    func testRecoveryWrapperRoundTripAndWrongPhrase() throws {
        let key = Array(repeating: UInt8(7), count: 32)
        let entropy = Array(repeating: UInt8(1), count: 32)
        let wrapper = try RecoveryWrapper.seal(localKey: key, entropy: Data(entropy), random: SystemRandomSource())
        XCTAssertEqual(wrapper.kind, "bip39-english-24")
        XCTAssertEqual(try RecoveryWrapper.open(wrapper, entropy: Data(entropy)), key)
        XCTAssertThrowsError(try RecoveryWrapper.open(wrapper, entropy: Data(Array(repeating: UInt8(2), count: 32)))) {
            XCTAssertEqual(($0 as? RecoveryPhraseError)?.message,
                           "This recovery phrase does not belong to this vault, or it was regenerated")
        }
        var tampered = wrapper
        tampered.salt = Base64.encode(Array(repeating: UInt8(9), count: 16))
        XCTAssertThrowsError(try RecoveryWrapper.open(tampered, entropy: Data(entropy)))
        // The vault key derived for vault.json is the Windows HKDF over the same salt.
        let vaultKey = try RecoveryWrapper.vaultKey(for: wrapper, entropy: Data(entropy))
        XCTAssertEqual(vaultKey.key, CryptoBox.hkdf(ikm: entropy, salt: try Base64.decodeStrict(wrapper.salt),
                                                    info: Array("localgatekeys|recovery-key|v1".utf8), length: 32))
    }

    /// A Windows vault with a recovery phrase opens on the Mac with that phrase (and refuses another).
    func testWindowsWrapperOpensWithPhrase() throws {
        let doc = try Self.doc("wrapper.json")
        let vault = Data((doc["vault"] as! String).utf8)
        let entropy = try BIP39.entropy(from: doc["phrase"] as! String)
        let opened = try DesktopVaultFile.open(vault, recoveryEntropy: entropy)
        let ids = opened.items.compactMap { item -> String? in
            if case .object(let o) = item, case .string(let id)? = o["id"] { return id }; return nil
        }
        XCTAssertEqual(ids, (doc["records"] as! [[String: Any]]).map { $0["id"] as! String })
        XCTAssertTrue(opened.recoveryEnrolled)
        let other = try BIP39.entropy(from: (try Self.doc("phrases.json")["phrases"] as! [[String: String]])[0]["phrase"]!)
        XCTAssertThrowsError(try DesktopVaultFile.open(vault, recoveryEntropy: other)) {
            XCTAssertEqual(($0 as? RecoveryPhraseError)?.message,
                           "This recovery phrase does not belong to this vault, or it was regenerated")
        }
        XCTAssertTrue(try DesktopVaultFile.open(vault, password: doc["master_password"] as! String).recoveryEnrolled)
    }

    /// Writes `from_mac_vault.json`: a Mac-sealed vault carrying the recovery wrapper of the Mac store's phrase.
    func testMacSealedVaultOpensWithPhrase() throws {
        let random = FullBackupV2Tests.Replay(Array("from-mac-recovery".utf8))
        let phrase = (try Self.doc("phrases.json")["phrases"] as! [[String: String]])[5]["phrase"]!
        let entropy = try BIP39.entropy(from: phrase)
        let wrapper = try RecoveryWrapper.seal(localKey: Array(repeating: 3, count: 32), entropy: entropy, random: random)
        let vaultKey = try RecoveryWrapper.vaultKey(for: wrapper, entropy: entropy)
        let master = "fixture master password 2026"
        // A real Windows login (from wrapper.json), so Windows validates it when it opens the vault.
        let windows = (try Self.doc("wrapper.json")["records"] as! [[String: Any]])[0]
        let records = [try CanonicalJSON.parse(Array(JSONSerialization.data(withJSONObject: windows)))]
        let recordID = windows["id"] as! String
        let vault = try DesktopVaultFile.seal(items: records, settings: .object([:]), password: master, random: random,
                                              now: 1_793_000_300, kdf: Self.cheap, recovery: vaultKey)
        XCTAssertEqual(try DesktopVaultFile.open(vault, recoveryEntropy: entropy).items, records)
        XCTAssertTrue(try DesktopVaultFile.open(vault, password: master).recoveryEnrolled)
        let out: [String: Any] = ["phrase": phrase, "master_password": master, "vault": String(decoding: vault, as: UTF8.self),
                                  "record_ids": [recordID],
                                  "note": "TEST ONLY: written by the Swift BIP39Tests; the phrase and password are published."]
        let data = try JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted, .sortedKeys]) + Data("\n".utf8)
        let url = Self.dir.appendingPathComponent("from_mac_vault.json")
        if (try? Data(contentsOf: url)) != data { try data.write(to: url) }
    }
}
