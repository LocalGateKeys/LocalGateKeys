import Foundation
import XCTest
@testable import LGKCore

/// The scheduled-backup key (design `docs/design/backup-public-key-2026-10-31.md` 3.2, 3.3, 3.4 wrap, 3.6), pinned to
/// `tests/vectors/backup/v3` (`key.json`, `wrap.json`, `record.json`, `authority.json`, written by
/// `scripts/gen_mac_backup_vectors.py backup_v3` with Windows `backup_key.py`).
final class BackupKeyTests: XCTestCase {
    static let dir = Vectors.root.deletingLastPathComponent().appendingPathComponent("backup/v3", isDirectory: true)

    /// Parsed with the strict canonical parser, so passwords keep their exact scalars (composed and decomposed é).
    static func load(_ name: String) throws -> [String: JSONValue] {
        try obj(CanonicalJSON.parse(Array(Data(contentsOf: dir.appendingPathComponent(name)))))
    }

    static func obj(_ v: JSONValue?) throws -> [String: JSONValue] {
        guard case .object(let o)? = v else { throw XCTSkip("not an object") }
        return o
    }
    static func arr(_ v: JSONValue?) throws -> [JSONValue] {
        guard case .array(let a)? = v else { throw XCTSkip("not an array") }
        return a
    }
    static func str(_ v: JSONValue?) throws -> String {
        guard case .string(let s)? = v else { throw XCTSkip("not a string") }
        return s
    }
    static func int(_ v: JSONValue?) throws -> Int64 {
        guard case .int(let n)? = v else { throw XCTSkip("not an int") }
        return n
    }
    static func hex(_ v: JSONValue?) throws -> [UInt8] { Vectors.hex(try str(v)) }
    static func b64(_ v: JSONValue?) throws -> [UInt8] { try Base64.decodeStrict(try str(v)) }

    /// The message of any error these APIs throw.
    static func message(_ error: Error) -> String? {
        switch error {
        case let e as FullBackupError: return e.message
        case let e as BackupKeyError: return e.message
        case let e as RecoveryPhraseError: return e.message
        default: return nil
        }
    }

    static func record(_ v: JSONValue?) throws -> BackupKeyRecord { try BackupKeyRecord(validating: XCTUnwrap(v)) }

    // MARK: key.json (3.2)

    func testKeyCases() throws {
        let k = try Self.load("key.json")
        XCTAssertEqual(try Self.str(k["info"]), String(decoding: BackupKey.keyInfo, as: UTF8.self))
        XCTAssertEqual(try Self.str(k["key_id_prefix"]), String(decoding: BackupKey.keyIDPrefix, as: UTF8.self))
        let cases = try Self.arr(k["cases"])
        XCTAssertEqual(cases.count, 4)
        var keyIDs = Set<String>()
        for c in cases {
            let o = try Self.obj(c)
            let name = try Self.str(o["name"])
            let password = try Self.str(o["password"])
            // No normalisation: the exact UTF-8 bytes and the Python `len` (scalars).
            XCTAssertEqual(Array(password.utf8), try Self.hex(o["password_utf8_hex"]), name)
            XCTAssertEqual(Int64(password.unicodeScalars.count), try Self.int(o["password_characters"]), name)
            let kdf = try BackupKeyKDF.parse(o["kdf"])
            XCTAssertEqual(kdf.json, o["kdf"], name)
            if name == "ascii" { XCTAssertEqual(kdf.parameters, BackupKeyKDF.defaultParameters) }
            let parts = try BackupKey.deriveParts(password: password, kdf: kdf)
            XCTAssertEqual(parts.seed, try Self.hex(o["seed"]), name)
            XCTAssertEqual(parts.skRaw, try Self.hex(o["sk_raw"]), name)
            XCTAssertEqual(parts.sk, try Self.hex(o["sk"]), name)
            XCTAssertEqual(try BackupKey.clamp(parts.skRaw), parts.sk, name)
            let key = try BackupKey.derive(password: password, kdf: kdf)
            XCTAssertEqual(key.privateKey, try Self.hex(o["sk"]), name)
            XCTAssertEqual(key.publicKey, try Self.hex(o["pk"]), name)
            XCTAssertEqual(Base64.encode(key.publicKey), try Self.str(o["pk_b64"]), name)
            XCTAssertEqual(key.keyID, try Self.str(o["key_id"]), name)
            XCTAssertEqual(try BackupKey.keyID(key.publicKey), key.keyID, name)
            keyIDs.insert(key.keyID)
        }
        XCTAssertEqual(keyIDs.count, 4)   // composed and decomposed é give different keys
    }

    func testRejectedPasswordsAndKDFs() throws {
        let k = try Self.load("key.json")
        for c in try Self.arr(k["rejected_passwords"]) {
            let o = try Self.obj(c)
            let kdf = try BackupKeyKDF.parse(o["kdf"])
            let name = try Self.str(o["name"]), password = try Self.str(o["password"])
            XCTAssertThrowsError(try BackupKey.derive(password: password, kdf: kdf), name) {
                XCTAssertEqual(Self.message($0), try? Self.str(o["error"]))
            }
        }
        let rejected = try Self.arr(k["rejected_kdf"])
        XCTAssertGreaterThanOrEqual(rejected.count, 13)
        for c in rejected {
            let o = try Self.obj(c)
            let name = try Self.str(o["name"])
            XCTAssertThrowsError(try BackupKeyKDF.parse(o["kdf"]), name) {
                XCTAssertEqual(Self.message($0), try? Self.str(o["error"]))
            }
        }
    }

    // MARK: wrap.json (3.4)

    func testWrap() throws {
        let w = try Self.load("wrap.json")
        XCTAssertEqual(try Self.str(w["info"]), String(decoding: BackupKey.wrapInfo, as: UTF8.self))
        XCTAssertEqual(try Self.str(w["aad_prefix"]), String(decoding: BackupKey.wrapAADPrefix, as: UTF8.self))
        XCTAssertEqual(try Self.hex(w["nonce"]), BackupKey.wrapNonce)
        let sk = try Self.hex(w["sk"]), pk = try Self.hex(w["pk"]), dk = try Self.hex(w["dk"])
        XCTAssertEqual(try BackupKey.publicKey(of: sk), pk)
        let eph = try BackupKey.ephemeral(raw: Self.hex(w["esk_random"]))
        XCTAssertEqual(eph.secret, try Self.hex(w["esk"]))
        XCTAssertEqual(eph.publicKey, try Self.hex(w["epk"]))
        let ss = try XCTUnwrap(BackupKey.sharedSecret(eph.secret, pk))
        XCTAssertEqual(ss, try Self.hex(w["ss"]))
        XCTAssertEqual(BackupKey.sharedSecret(sk, eph.publicKey), ss)
        XCTAssertEqual(eph.publicKey + pk, try Self.hex(w["kek_salt"]))
        XCTAssertEqual(BackupKey.kek(shared: ss, ephemeralPublic: eph.publicKey, publicKey: pk), try Self.hex(w["kek"]))
        let core = try Self.obj(w["core"]), body = try Self.obj(w["recipient_body"])
        let aad = try BackupKey.wrapAAD(core: core, recipientBody: body)
        XCTAssertEqual(aad, try Self.hex(w["wrap_aad"]))
        let wrapped = try BackupKey.wrap(dataKey: dk, publicKey: pk, ephemeral: eph, aad: aad)
        XCTAssertEqual(wrapped, try Self.hex(w["wrapped"]))
        XCTAssertEqual(Base64.encode(wrapped), try Self.str(w["wrapped_b64"]))
        XCTAssertEqual(try BackupKey.unwrap(privateKey: sk, ephemeralPublic: eph.publicKey, wrapped: wrapped, aad: aad), dk)

        // The reader's path from the password, with the recipient's kdf and key id.
        let password = try Self.str(w["password"])
        let kdf = try BackupKeyKDF.parse(body["kdf"])
        let keyID = try Self.str(body["key_id"])
        XCTAssertEqual(try BackupKey.unwrap(password: password, kdf: kdf, expectedKeyID: keyID, ephemeralPublic: eph.publicKey,
                                            wrapped: wrapped, aad: aad), dk)

        for c in try Self.arr(w["wrap_to_low_order_pk"]) {
            let o = try Self.obj(c)
            XCTAssertThrowsError(try BackupKey.wrap(dataKey: dk, publicKey: Self.hex(o["pk"]), ephemeral: eph, aad: aad)) {
                XCTAssertEqual(Self.message($0), try? Self.str(o["error"]))
            }
        }

        // `unwrap_rejected`: built here from each case's name; every one has the same message.
        let lowOrder = try Self.arr(w["wrap_to_low_order_pk"]).map { try Self.hex(Self.obj($0)["pk"]) }
        var tampered = wrapped; tampered[5] ^= 1
        func aadWith(_ edit: (inout [String: JSONValue], inout [String: JSONValue]) -> Void) throws -> [UInt8] {
            var c = core, b = body
            edit(&c, &b)
            return try BackupKey.wrapAAD(core: c, recipientBody: b)
        }
        let otherKey = try BackupKey.derive(password: "an entirely other password", kdf: kdf)
        let cases: [String: () throws -> [UInt8]] = [
            "epk all zero (low order)": { try BackupKey.unwrap(privateKey: sk, ephemeralPublic: [UInt8](repeating: 0, count: 32), wrapped: wrapped, aad: aad) },
            "epk low order (order 8)": { try BackupKey.unwrap(privateKey: sk, ephemeralPublic: lowOrder[2], wrapped: wrapped, aad: aad) },
            "wrapped tampered": { try BackupKey.unwrap(privateKey: sk, ephemeralPublic: eph.publicKey, wrapped: tampered, aad: aad) },
            "wrapped 47 bytes": { try BackupKey.unwrap(privateKey: sk, ephemeralPublic: eph.publicKey, wrapped: Array(wrapped.dropLast()), aad: aad) },
            "aad tampered (key_set_at + 1)": {
                let a = try aadWith { _, b in if case .int(let n)? = b["key_set_at"] { b["key_set_at"] = .int(n + 1) } }
                return try BackupKey.unwrap(privateKey: sk, ephemeralPublic: eph.publicKey, wrapped: wrapped, aad: a)
            },
            "aad tampered (entry_count + 1)": {
                let a = try aadWith { c, _ in if case .int(let n)? = c["entry_count"] { c["entry_count"] = .int(n + 1) } }
                return try BackupKey.unwrap(privateKey: sk, ephemeralPublic: eph.publicKey, wrapped: wrapped, aad: a)
            },
            "other private key": { try BackupKey.unwrap(privateKey: otherKey.privateKey, ephemeralPublic: eph.publicKey, wrapped: wrapped, aad: aad) },
            "wrong password (key id check, no GCM attempt)": {
                try BackupKey.unwrap(password: "an entirely other password", kdf: kdf, expectedKeyID: keyID,
                                     ephemeralPublic: eph.publicKey, wrapped: wrapped, aad: aad)
            },
            "right password, other key id": {
                try BackupKey.unwrap(password: password, kdf: kdf, expectedKeyID: otherKey.keyID,
                                     ephemeralPublic: eph.publicKey, wrapped: wrapped, aad: aad)
            },
        ]
        let rejected = try Self.arr(w["unwrap_rejected"])
        XCTAssertEqual(rejected.count, cases.count)
        for c in rejected {
            let o = try Self.obj(c)
            let name = try Self.str(o["name"])
            let run = try XCTUnwrap(cases[name], "no Swift case for \(name)")
            XCTAssertThrowsError(try run(), name) { XCTAssertEqual(Self.message($0), try? Self.str(o["error"]), name) }
        }
    }

    // MARK: record.json (3.3)

    func testRecordsRebuildByteForByte() throws {
        let r = try Self.load("record.json")
        let a = try Self.load("authority.json")
        let records = try Self.obj(r["records"])
        let mac = try Self.obj(a["mac"])
        func built(_ name: String, previous: BackupKeyRecord?) throws -> BackupKeyRecord {
            let entry = try Self.obj(records[name])
            let inputs = try Self.obj(entry["inputs"])
            let key = try BackupKey.derive(password: Self.str(inputs["password"]), kdf: BackupKeyKDF.parse(inputs["kdf"]))
            let source = inputs["reset_authority"]
            var authority: JSONValue?
            if case .string(let s)? = source {
                if s.hasPrefix("authority.json windows.old_snapshot") {
                    authority = try Self.obj(a["windows"])["old_snapshot"]
                } else {
                    authority = try ResetAuthority.captureMac(salt: Self.hex(mac["salt"]), recoveryKey: Self.hex(mac["phrase_key"]),
                                                              keyID: key.keyID)
                }
            }
            let rec = try BackupKeyRecord.build(key: key, now: Self.int(inputs["now"]), setBy: Self.str(Self.obj(entry["record"])["set_by"]),
                                                resetAuthority: authority, previous: previous)
            XCTAssertEqual(rec.json, entry["record"], name)
            XCTAssertEqual(String(decoding: try rec.encoded(), as: UTF8.self), try Self.str(entry["canonical"]), name)
            return rec
        }
        let set = try built("set", previous: nil)
        let changed = try built("changed", previous: set)
        XCTAssertEqual(changed.history.first?.keyID, set.keyID)
        let reset = try built("reset", previous: changed)
        XCTAssertEqual(reset.resetAt, reset.setAt)
        _ = try built("migrated", previous: nil)
        // A full history (16) stays at 16: the oldest entry is dropped.
        guard case .object(var withFull) = changed.json else { return XCTFail() }
        withFull["history"] = r["previous_history"]
        let full = try BackupKeyRecord(validating: .object(withFull))
        XCTAssertEqual(full.history.count, 16)
        let rebuilt = try built("changed_history_full", previous: full)
        XCTAssertEqual(rebuilt.history.count, 16)

        // Building refuses an operation without its previous record, and a first set with one.
        let key = try BackupKey.derive(password: "fixture backup password 2026", kdf: set.kdf)
        XCTAssertThrowsError(try BackupKeyRecord.build(key: key, now: 1, setBy: "changed", resetAuthority: nil, previous: nil))
        XCTAssertThrowsError(try BackupKeyRecord.build(key: key, now: 1, setBy: "set", resetAuthority: nil, previous: set))
        XCTAssertThrowsError(try BackupKeyRecord.build(key: key, now: -1, setBy: "set", resetAuthority: nil, previous: nil))
        XCTAssertThrowsError(try BackupKeyRecord.build(key: key, now: 1, setBy: "made up", resetAuthority: nil, previous: nil))
    }

    func testPasswordProofsAndRejectedRecords() throws {
        let r = try Self.load("record.json")
        let records = try Self.obj(r["records"])
        for p in try Self.arr(r["password_proofs"]) {
            let o = try Self.obj(p)
            let name = try Self.str(o["record"]), password = try Self.str(o["password"])
            let rec = try Self.record(Self.obj(records[name])["record"])
            XCTAssertEqual(rec.passwordMatches(password), o["matches"] == .bool(true), name)
        }
        let rejected = try Self.arr(r["rejected"])
        XCTAssertGreaterThanOrEqual(rejected.count, 28)
        for c in rejected {
            let o = try Self.obj(c)
            let name = try Self.str(o["name"])
            XCTAssertThrowsError(try BackupKeyRecord(validating: XCTUnwrap(o["record"])), name) {
                XCTAssertEqual(Self.message($0), try? Self.str(o["error"]), name)
            }
        }
        // Stored bytes round-trip; unparseable bytes are damaged too.
        let set = try Self.record(Self.obj(records["set"])["record"])
        XCTAssertEqual(try BackupKeyRecord(encoded: set.encoded()), set)
        XCTAssertThrowsError(try BackupKeyRecord(encoded: Array("{".utf8)))
    }

    // MARK: authority.json (3.6, Q2)

    func testAuthorityKinds() throws {
        let a = try Self.load("authority.json")
        XCTAssertEqual(try Self.str(a["mac_prefix"]), String(decoding: ResetAuthority.macPrefix, as: UTF8.self))
        XCTAssertEqual(try Self.str(a["phrase_key_info"]), String(decoding: RecoveryWrapper.info, as: UTF8.self))
        let keyID = try Self.str(a["record_key_id"])

        let win = try Self.obj(a["windows"])
        let entropies = ["old_phrase": try Self.hex(win["old_entropy"]), "new_phrase": try Self.hex(win["new_entropy"])]
        for (phrase, entropy) in entropies {
            XCTAssertEqual([UInt8](try BIP39.entropy(from: Self.str(win[phrase]))), entropy, phrase)
        }
        for c in try Self.arr(win["checks"]) {
            let o = try Self.obj(c)
            let snapshot = try XCTUnwrap(win[Self.str(o["snapshot"])])
            let entropy = try XCTUnwrap(entropies[Self.str(o["phrase"])])
            XCTAssertEqual(try ResetAuthority.verify(snapshot, entropy: entropy, keyID: keyID), o["accepted"] == .bool(true))
        }

        let mac = try Self.obj(a["mac"])
        let entropy = try Self.hex(mac["entropy"]), other = try Self.hex(mac["other_entropy"])
        XCTAssertEqual(try BIP39.phrase(entropy: Data(entropy)), try Self.str(mac["phrase"]))
        XCTAssertEqual([UInt8](try BIP39.entropy(from: Self.str(mac["other_phrase"]))), other)
        let salt = try Self.hex(mac["salt"])
        XCTAssertEqual(try ResetAuthority.phraseKey(entropy: entropy, salt: salt), try Self.hex(mac["phrase_key"]))
        // The Mac's own phrase key (RecoveryWrapper) is the same K(salt).
        XCTAssertEqual(try RecoveryWrapper.derive(Data(entropy), salt: salt), try Self.hex(mac["phrase_key"]))
        let authority = try ResetAuthority.captureMac(salt: salt, recoveryKey: Self.hex(mac["phrase_key"]), keyID: keyID)
        XCTAssertEqual(authority, mac["authority"])
        for c in try Self.arr(mac["checks"]) {
            let o = try Self.obj(c)
            let e = try Self.str(o["phrase"]) == "phrase" ? entropy : other
            XCTAssertEqual(try ResetAuthority.verify(authority, entropy: e, keyID: Self.str(o["key_id"])), o["accepted"] == .bool(true))
        }

        for c in try Self.arr(a["rejected"]) {
            let o = try Self.obj(c)
            let name = try Self.str(o["name"])
            XCTAssertThrowsError(try ResetAuthority.validate(o["authority"]), name) {
                XCTAssertEqual(Self.message($0), try? Self.str(o["error"]))
            }
        }
    }

    func testStrictResetAndRebind() throws {
        let a = try Self.load("authority.json")
        let strict = try Self.obj(a["strict_reset"])
        let records = try Self.obj(strict["records"])
        let currents = try Self.obj(strict["currents"])
        let entropies = try Self.obj(strict["entropies"])
        let cases = try Self.arr(strict["cases"])
        XCTAssertEqual(cases.count, 13)
        for c in cases {
            let o = try Self.obj(c)
            let name = try Self.str(o["name"])
            let rec = try Self.record(records[Self.str(o["record"])])
            let current = currents[try Self.str(o["current"])]
            let entropy = try Self.hex(entropies[Self.str(o["entropy"])])
            XCTAssertEqual(try ResetAuthority.verifyReset(record: rec, entropy: entropy, current: current == .null ? nil : current),
                           o["accepted"] == .bool(true), name)
        }

        // The Mac's current authority after the phrase was replaced, from the new VaultKey.
        let replaced = try Self.obj(strict["mac_replaced"])
        let reset = try Self.record(records["reset"])
        let after = try ResetAuthority.captureMac(RecoveryWrapper.VaultKey(salt: Self.hex(replaced["salt"]), key: Self.hex(replaced["phrase_key"])),
                                                  keyID: reset.keyID)
        XCTAssertEqual(after, currents["mac_after"])
        XCTAssertFalse(reset.isBound(to: after))
        XCTAssertTrue(reset.isBound(to: currents["mac_before"]))

        // Re-bind: proof with the current backup password, only the authority changes.
        let r = try Self.load("record.json")
        let inputs = try Self.obj(r["records"]).mapValues { try Self.obj(Self.obj($0)["inputs"]) }
        let canonical = try Self.obj(strict["rebound_canonical"])
        let set = try Self.record(records["set"])
        let setRebound = try set.rebound(password: Self.str(inputs["set"]?["password"]), resetAuthority: currents["windows.new_snapshot"])
        XCTAssertEqual(String(decoding: try setRebound.encoded(), as: UTF8.self), try Self.str(canonical["set_rebound"]))
        XCTAssertEqual(setRebound, try Self.record(records["set_rebound"]))
        XCTAssertEqual(setRebound.setAt, set.setAt)
        XCTAssertEqual(setRebound.history, set.history)
        let resetRebound = try reset.rebound(password: Self.str(inputs["reset"]?["password"]), resetAuthority: after)
        XCTAssertEqual(String(decoding: try resetRebound.encoded(), as: UTF8.self), try Self.str(canonical["reset_rebound"]))
        XCTAssertTrue(resetRebound.isBound(to: after))

        let wrong = try Self.obj(strict["rebind_with_wrong_password"])
        XCTAssertThrowsError(try Self.record(records[Self.str(wrong["record"])]).rebound(password: Self.str(wrong["password"]),
                                                                                    resetAuthority: nil)) {
            XCTAssertEqual(Self.message($0), try? Self.str(wrong["error"]))
        }
        XCTAssertEqual(BackupKeyError.notCurrentPassword.message, try Self.str(wrong["error"]))
    }

    func testPasswordKeyMatchesOnlyItsPassword() throws {
        let kdf = FullBackupV2.KDF(timeCost: 1, memoryKiB: 8192, parallelism: 1)
        let key = try DesktopVaultFile.derivePasswordKey(password: "fixture master password 2026", kdf: kdf, random: SystemRandomSource())
        XCTAssertTrue(key.matches("fixture master password 2026"))
        XCTAssertFalse(key.matches("fixture master password 2027"))
        XCTAssertFalse(key.matches("short"))
    }
}
