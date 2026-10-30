import Foundation
import XCTest
@testable import LGKCore

/// Encrypted and archive importers (password-protected Bitwarden, 1PUX, KDBX 3.1/4, Dashlane and Proton Pass zips) and
/// the bounded `ZipReader`. Expected values are written by `scripts/gen_mac_backup_vectors.py` from the Windows importers.
final class ArchiveImporterTests: XCTestCase {
    private static let repo: URL = Vectors.root.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    private static let vectors = repo.appendingPathComponent("tests/vectors/import", isDirectory: true)

    private func vector(_ relative: String) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Data(contentsOf: Self.vectors.appendingPathComponent(relative))) as! [String: Any]
    }

    private func input(_ v: [String: Any]) throws -> Data {
        try Data(contentsOf: Self.repo.appendingPathComponent(v["input"] as! String))
    }

    private func run(_ v: [String: Any], password: String? = nil) throws -> ImportResult {
        let format = ImportFormat(rawValue: v["format"] as! String)!
        return try ImportSource.candidates(from: input(v), format: format,
                                           options: ImportOptions(password: password ?? v["password"] as? String))
    }

    private func normalised(_ c: ImportCandidate) -> [String: Any] {
        var kind = "", username = "", password = "", identity: [String: String] = [:], card: [String: String] = [:]
        switch c.kind {
        case .login(let f): kind = "login"; username = f.username; password = f.password
        case .note: kind = "note"
        case .card(let f): kind = "card"; card = f.values
        case .identity(let f): kind = "identity"; identity = f.values
        case .passkey: kind = "passkey"
        }
        let none = NSNull()
        return [
            "kind": kind, "title": c.title, "username": username, "password": password, "urls": c.urls, "notes": c.notes,
            "totp_uri": c.totp ?? "", "folder": c.folder, "favorite": c.favourite,
            "custom_fields": c.customFields.map { ["name": $0.name, "value": $0.value, "hidden": $0.hidden] as [String: Any] },
            "created": c.created.map { NSNumber(value: $0) } ?? none, "modified": c.modified.map { NSNumber(value: $0) } ?? none,
            "tags": c.tags, "identity": identity, "card": card,
            "source_row": c.sourceRow.map { NSNumber(value: $0) } ?? none,
        ]
    }

    /// Runs one vector and checks every record field (or the error) against Python.
    @discardableResult
    private func assertMatchesPython(_ relative: String, file: StaticString = #filePath, line: UInt = #line) throws -> ImportResult? {
        let v = try vector(relative)
        if let error = v["error"] as? [String: String] {
            XCTAssertThrowsError(try run(v), relative, file: file, line: line) { e in
                guard let e = e as? ImportError else { return XCTFail("\(relative): \(e)", file: file, line: line) }
                switch error["type"] {
                case "password_required": XCTAssertEqual(e, .needsPassword, relative, file: file, line: line)
                case "wrong_password":
                    XCTAssertTrue(e.isWrongPassword, relative, file: file, line: line)
                    XCTAssertTrue(e.message.hasPrefix(error["message"]!), "\(relative): \(e.message)", file: file, line: line)
                default: XCTAssertEqual(e.message, error["message"], relative, file: file, line: line)
                }
            }
            return nil
        }
        let result = try run(v)
        let expected = v["result"] as! [String: Any]
        XCTAssertEqual(result.skipped.map(\.message), expected["diagnostics"] as! [String], relative, file: file, line: line)
        let records = expected["records"] as! [[String: Any]]
        XCTAssertEqual(result.candidates.count, records.count, relative, file: file, line: line)
        for (i, (c, want)) in zip(result.candidates, records).enumerated() {
            let got = normalised(c)
            for key in want.keys.sorted() {
                let a = got[key] as AnyObject, b = want[key] as AnyObject
                XCTAssertTrue(a.isEqual(b), "\(relative) record \(i) \(key): \(a) != \(b)", file: file, line: line)
            }
        }
        return result
    }

    private func files(in dir: String) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: Self.vectors.appendingPathComponent(dir).path)
            .filter { $0.hasSuffix(".expected.json") }.sorted().map { "\(dir)/\($0)" }
    }

    // MARK: - Bitwarden password-protected JSON

    func testBitwardenEncryptedPBKDF2AndArgon2() throws {
        for name in try files(in: "bitwardenEncrypted") { try assertMatchesPython(name) }
        // Both KDFs open the same document as the plain export of it.
        let plain = try run(vector("bitwarden/bitwarden_types.json.expected.json"))
        let pbkdf2 = try XCTUnwrap(assertMatchesPython("bitwardenEncrypted/bitwarden_pbkdf2.json.expected.json"))
        let argon = try XCTUnwrap(assertMatchesPython("bitwardenEncrypted/bitwarden_argon2.json.expected.json"))
        XCTAssertEqual(pbkdf2, plain)
        XCTAssertEqual(argon, plain)
        // The plain Bitwarden format opens a protected export too (Windows `load_bitwarden_json`).
        let v = try vector("bitwardenEncrypted/bitwarden_argon2.json.expected.json")
        XCTAssertEqual(try ImportSource.candidates(from: input(v), format: .bitwarden,
                                                   options: ImportOptions(password: "argon fixture password")), argon)
        XCTAssertThrowsError(try ImportSource.candidates(from: input(v), format: .bitwardenEncrypted,
                                                         options: ImportOptions(password: ""))) {
            XCTAssertEqual($0 as? ImportError, .needsPassword)
        }
    }

    func testBitwardenWrongPasswordSaysSo() throws {
        let v = try vector("bitwardenEncrypted/bitwarden_protected.json.wrong.expected.json")
        XCTAssertThrowsError(try run(v)) {
            XCTAssertEqual($0 as? ImportError, .wrongPassword)
            XCTAssertEqual(($0 as? ImportError)?.message, "Wrong password or corrupted export (MAC mismatch)")
        }
        XCTAssertThrowsError(try run(v, password: "")) { XCTAssertEqual($0 as? ImportError, .needsPassword) }
        // A tampered MAC reads as a wrong password, never as garbage items.
        try assertMatchesPython("bitwardenEncrypted/bitwarden_tampered.json.expected.json")
        // Out-of-range KDF parameters are refused before any key stretching.
        try assertMatchesPython("bitwardenEncrypted/bitwarden_bad_iterations.json.expected.json")
        try assertMatchesPython("bitwardenEncrypted/bitwarden_bad_argon.json.expected.json")
    }

    // MARK: - 1Password 1PUX

    func test1PUXMatchesPython() throws {
        for name in try files(in: "onePassword1PUX") { try assertMatchesPython(name) }
        // Two-factor keys on items that are not logins are kept, as on Windows.
        let types = try XCTUnwrap(assertMatchesPython("onePassword1PUX/onepassword_types.1pux.expected.json"))
        let note = try XCTUnwrap(types.candidates.first { $0.title == "Note with code" })
        guard case .note = note.kind else { return XCTFail("not a note") }
        XCTAssertEqual(note.totp, "otpauth://totp/Note%20with%20code?secret=JBSWY3DPEHPK3PXP")
        let card = try XCTUnwrap(types.candidates.first { $0.title == "Card" })
        XCTAssertEqual(card.totp, "otpauth://totp/Card?secret=JBSWY3DPEHPK3PXP")
    }

    func testDashlaneAndProtonZipsMatchPython() throws {
        for name in try files(in: "dashlane") where name.contains(".zip.") { try assertMatchesPython(name) }
        for name in try files(in: "protonPass") where name.contains(".zip.") { try assertMatchesPython(name) }
    }

    // MARK: - KeePass KDBX

    func testKDBX4AESAndChaCha() throws {
        for name in try files(in: "keePassKDBX") where name.contains("kdbx4") { try assertMatchesPython(name) }
        // The KDBX 4 databases hold the same entries as the XML exports they were written from.
        let xml = try run(vector("keePassXML/keepass.xml.expected.json"))
        let aes = try XCTUnwrap(assertMatchesPython("keePassKDBX/kdbx4_aes_argon2d.kdbx.expected.json"))
        XCTAssertEqual(aes.candidates.map(\.title), xml.candidates.map(\.title))
        let chacha = try XCTUnwrap(assertMatchesPython("keePassKDBX/kdbx4_chacha_argon2id.kdbx.expected.json"))
        XCTAssertEqual(chacha, try assertMatchesPython("keePassKDBX/kdbx4_aeskdf_plain.kdbx.expected.json"))
        // KDF ceilings are Windows' (`_check_kdf_limits`).
        for name in ["argon_iterations", "argon_memory", "argon_work", "aeskdf_rounds"] {
            try assertMatchesPython("keePassKDBX/kdbx4_\(name).kdbx.expected.json")
        }
        let v = try vector("keePassKDBX/kdbx4_aes_argon2d.kdbx.expected.json")
        XCTAssertThrowsError(try run(v, password: "")) { XCTAssertEqual($0 as? ImportError, .needsPassword) }
    }

    func testKDBX3Salsa20ProtectedValues() throws {
        for name in try files(in: "keePassKDBX") where name.contains("kdbx3") { try assertMatchesPython(name) }
        let salsa = try XCTUnwrap(assertMatchesPython("keePassKDBX/kdbx3_salsa20.kdbx.expected.json"))
        let entry = try XCTUnwrap(salsa.candidates.first { $0.title == "Key query" })
        let field = try XCTUnwrap(entry.customFields.first { $0.name == "Protected" })
        XCTAssertTrue(field.hidden)
        XCTAssertEqual(field.value, "c2VjcmV0IHZhbHVl")
        XCTAssertEqual(salsa, try assertMatchesPython("keePassKDBX/kdbx4_chacha_argon2id.kdbx.expected.json"))
    }

    func testKDBXKeyFileRefusedWithMessage() throws {
        let v = try vector("keePassKDBX/kdbx4_keyfile.kdbx.expected.json")
        XCTAssertThrowsError(try run(v)) { e in
            guard let e = e as? ImportError else { return XCTFail("\(e)") }
            XCTAssertTrue(e.isWrongPassword)
            XCTAssertTrue(e.message.hasPrefix("Wrong password or key file (header HMAC mismatch)"))
            XCTAssertTrue(e.message.contains("key files"), e.message)
        }
        try assertMatchesPython("keePassKDBX/kdbx4_twofish.kdbx.expected.json")
        let twofish = try vector("keePassKDBX/kdbx4_twofish.kdbx.expected.json")
        XCTAssertThrowsError(try run(twofish)) {
            XCTAssertTrue(($0 as? ImportError)?.message.contains("Twofish") ?? false)
        }
    }

    // MARK: - ZipReader

    func testZipTraversalRefused() throws {
        for name in ["../export.data", "a/../../export.data", "/export.data", "\\export.data", "C:export.data",
                     "a\\..\\export.data", "a/./../b"] {
            let zip = TestZip.make([(name, Data("{}".utf8))])
            XCTAssertThrowsError(try ZipReader(data: zip, maxBytes: 1 << 20, maxEntries: 10), name) {
                XCTAssertEqual($0 as? ZipReader.Failure, .unsafeName, name)
            }
            XCTAssertThrowsError(try ImportSource.candidates(from: zip, format: .onePassword1PUX), name) {
                XCTAssertEqual(($0 as? ImportError)?.message, ZipReader.Failure.unsafeName.message, name)
            }
        }
        let dup = TestZip.make([("export.data", Data("{}".utf8)), ("export.data", Data("[]".utf8))])
        XCTAssertThrowsError(try ZipReader(data: dup, maxBytes: 1 << 20, maxEntries: 10)) {
            XCTAssertEqual($0 as? ZipReader.Failure, .duplicateName)
        }
        // Ordinary nested names are fine and read back exactly.
        let ok = TestZip.make([("Proton Pass/data.json", Data("{\"a\": 1}".utf8)), ("dir/", Data())])
        let reader = try ZipReader(data: ok, maxBytes: 1 << 20, maxEntries: 10)
        XCTAssertEqual(reader.entries().map(\.name), ["Proton Pass/data.json", "dir/"])
        XCTAssertEqual(try reader.read(reader.entries()[0], limit: 100), Data("{\"a\": 1}".utf8))
        // Encrypted members cannot be read; zip64 archives are refused outright.
        let encrypted = TestZip.make([("export.data", Data("{}".utf8))], flags: 0x1)
        let r = try ZipReader(data: encrypted, maxBytes: 1 << 20, maxEntries: 10)
        XCTAssertTrue(r.entries()[0].isEncrypted)
        XCTAssertThrowsError(try r.read(r.entries()[0], limit: 100)) { XCTAssertEqual($0 as? ZipReader.Failure, .encrypted) }
        XCTAssertThrowsError(try ZipReader(data: TestZip.make([("a", Data("x".utf8))], zip64: true), maxBytes: 1 << 20, maxEntries: 10)) {
            XCTAssertEqual($0 as? ZipReader.Failure, .zip64)
        }
        XCTAssertThrowsError(try ZipReader(data: Data("PK not a zip".utf8), maxBytes: 1 << 20, maxEntries: 10)) {
            XCTAssertEqual($0 as? ZipReader.Failure, .corrupt)
        }
        // A tampered stored member fails its CRC.
        var bad = TestZip.make([("export.data", Data("{\"accounts\": []}".utf8))])
        bad[30 + 11 + 2] ^= 0x20
        let br = try ZipReader(data: bad, maxBytes: 1 << 20, maxEntries: 10)
        XCTAssertThrowsError(try br.read(br.entries()[0], limit: 100)) { XCTAssertEqual($0 as? ZipReader.Failure, .corrupt) }
    }

    func testZipBombLimit() throws {
        // 64 MiB of zeros deflates to about 64 KiB: refused by the size limit and by the ratio bound.
        let zeros = Data(count: 64 * 1024 * 1024)
        let bomb = TestZip.make([("export.data", zeros)], deflate: true)
        XCTAssertLessThan(bomb.count, 1024 * 1024)
        let reader = try ZipReader(data: bomb, maxBytes: ImportSource.maxArchiveBytes, maxEntries: 10)
        XCTAssertThrowsError(try reader.read(reader.entries()[0], limit: 16 * 1024 * 1024)) {
            XCTAssertEqual($0 as? ZipReader.Failure, .tooLarge)
        }
        XCTAssertThrowsError(try reader.read(reader.entries()[0], limit: 128 * 1024 * 1024)) {
            XCTAssertEqual($0 as? ZipReader.Failure, .ratio)
        }
        // A member that lies about its size is stopped while inflating, not trusted.
        let liar = TestZip.make([("export.data", Data(count: 4 * 1024 * 1024))], deflate: true, declaredSize: 100)
        let lr = try ZipReader(data: liar, maxBytes: ImportSource.maxArchiveBytes, maxEntries: 10)
        XCTAssertThrowsError(try lr.read(lr.entries()[0], limit: 1024)) {
            XCTAssertEqual($0 as? ZipReader.Failure, .tooLarge)
        }
        XCTAssertThrowsError(try ImportSource.candidates(from: bomb, format: .onePassword1PUX)) {
            XCTAssertEqual(($0 as? ImportError)?.message, "export.data is too large")
        }
        // Entry count and archive size are bounded before anything is read.
        let many = TestZip.make((0..<11).map { ("f\($0)", Data()) })
        XCTAssertThrowsError(try ZipReader(data: many, maxBytes: 1 << 20, maxEntries: 10)) {
            XCTAssertEqual($0 as? ZipReader.Failure, .tooManyEntries)
        }
        XCTAssertThrowsError(try ZipReader(data: many, maxBytes: 100, maxEntries: 100)) {
            XCTAssertEqual($0 as? ZipReader.Failure, .tooLarge)
        }
        // A moderate, well-compressed member inside the limits reads back.
        let text = Data(String(repeating: "{\"title\": \"x\"}, ", count: 10_000).utf8)
        let fine = TestZip.make([("export.data", text)], deflate: true)
        let fr = try ZipReader(data: fine, maxBytes: 1 << 20, maxEntries: 10)
        XCTAssertEqual(try fr.read(fr.entries()[0], limit: 1 << 20), text)
    }

    /// Parameters inside Windows' bounds that Argon2 itself rejects (8 KiB with 64 lanes) read as a format error.
    func testKDBXArgon2RejectedParametersAreAFormatError() throws {
        let kdf: [String: KDBX.KDFValue] = ["$UUID": .bytes(KDBX.kdfArgon2id), "M": .int(8 * 1024, signed: false),
                                            "I": .int(1, signed: false), "P": .int(64, signed: false),
                                            "S": .bytes([UInt8](repeating: 1, count: 32))]
        XCTAssertNoThrow(try KDBX.checkKDF(kdf))
        XCTAssertThrowsError(try KDBX.transform([UInt8](repeating: 0, count: 32), kdf)) {
            XCTAssertEqual($0 as? ImportError, .malformed("Argon2 parameters are invalid"))
        }
    }

    /// A zip64 locator (and record) with valid classic fields, as some writers add, is read as a classic archive.
    func testZip64LocatorWithClassicFieldsAccepted() throws {
        let plain = TestZip.make([("export.data", Data("{\"accounts\": []}".utf8))])
        let eocd = plain.count - 22
        let cdSize = Int(plain[eocd + 12]) | Int(plain[eocd + 13]) << 8
        let cdOffset = Int(plain[eocd + 16]) | Int(plain[eocd + 17]) << 8
        func le(_ v: UInt64, _ n: Int) -> [UInt8] { (0..<n).map { UInt8((v >> (8 * UInt64($0))) & 0xFF) } }
        var record: [UInt8] = [0x50, 0x4B, 0x06, 0x06] + le(44, 8) + le(45, 2) + le(45, 2) + le(0, 4) + le(0, 4)
        record += le(1, 8) + le(1, 8) + le(UInt64(cdSize), 8) + le(UInt64(cdOffset), 8)
        let locator: [UInt8] = [0x50, 0x4B, 0x06, 0x07] + le(0, 4) + le(UInt64(eocd), 8) + le(1, 4)
        var zip = Data(plain.prefix(eocd)); zip.append(contentsOf: record + locator); zip.append(plain.suffix(22))
        let reader = try ZipReader(data: zip, maxBytes: 1 << 20, maxEntries: 10)
        XCTAssertEqual(reader.entries().map(\.name), ["export.data"])
        XCTAssertEqual(try reader.read(reader.entries()[0], limit: 100), Data("{\"accounts\": []}".utf8))
        XCTAssertEqual(try ImportSource.candidates(from: zip, format: .onePassword1PUX).candidates.count, 0)
    }

    // MARK: - Crypto known answers

    func testStreamCiphersKnownAnswers() throws {
        // RFC 8439 2.4.2.
        let key = (0..<32).map { UInt8($0) }
        let nonce: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0x4A, 0, 0, 0, 0]
        var text = Array("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8)
        var c = ChaCha20(key: key, nonce: nonce, counter: 1)
        c.process(&text)
        XCTAssertEqual(Vectors.hexString(Array(text.prefix(16))), "6e2e359a2568f98041ba0728dd0d6981")
        XCTAssertEqual(Vectors.hexString(Array(text.suffix(4))), "5e42874d")
        // Salsa20/20, 256-bit key, ECRYPT set 1 vector 0: key 0x80 00..., IV zero.
        var zeros = [UInt8](repeating: 0, count: 64)
        var s = Salsa20(key: [0x80] + [UInt8](repeating: 0, count: 31), nonce: [UInt8](repeating: 0, count: 8))
        s.process(&zeros)
        XCTAssertEqual(Vectors.hexString(Array(zeros.prefix(16))), "e3be8fdd8beca2e3ea8ef9475b29a6e7")
        // PBKDF2-HMAC-SHA256 (RFC 7914 section 11).
        XCTAssertEqual(Vectors.hexString(try PBKDF2.sha256(password: Array("passwd".utf8), salt: Array("salt".utf8),
                                                           iterations: 1, length: 16)), "55ac046e56e3089fec1691c22544b605")
    }
}

/// Writes small zip archives for the reader tests (stored or raw-deflated members).
enum TestZip {
    static func make(_ members: [(String, Data)], deflate: Bool = false, flags: UInt16 = 0, zip64: Bool = false,
                     declaredSize: UInt32? = nil) -> Data {
        var out = Data(), central = Data()
        func u16(_ v: UInt16, _ d: inout Data) { d.append(contentsOf: [UInt8(v & 0xFF), UInt8(v >> 8)]) }
        func u32(_ v: UInt32, _ d: inout Data) { u16(UInt16(v & 0xFFFF), &d); u16(UInt16(v >> 16), &d) }
        for (name, body) in members {
            let stored = deflate ? ((try? (body as NSData).compressed(using: .zlib)) as Data? ?? body) : body
            let crc = ZipReader.crc32(body)
            let name8 = Data(name.utf8)
            let offset = UInt32(out.count)
            let size = zip64 ? UInt32.max : (declaredSize ?? UInt32(body.count))
            u32(0x0403_4B50, &out); u16(20, &out); u16(flags | 0x800, &out); u16(deflate ? 8 : 0, &out)
            u16(0, &out); u16(0x21, &out); u32(crc, &out); u32(UInt32(stored.count), &out); u32(size, &out)
            u16(UInt16(name8.count), &out); u16(0, &out); out.append(name8); out.append(stored)
            u32(0x0201_4B50, &central); u16(20, &central); u16(20, &central); u16(flags | 0x800, &central)
            u16(deflate ? 8 : 0, &central); u16(0, &central); u16(0x21, &central); u32(crc, &central)
            u32(UInt32(stored.count), &central); u32(size, &central); u16(UInt16(name8.count), &central)
            u16(0, &central); u16(0, &central); u16(0, &central); u16(0, &central); u32(0, &central); u32(offset, &central)
            central.append(name8)
        }
        let cdOffset = UInt32(out.count)
        out.append(central)
        u32(0x0605_4B50, &out); u16(0, &out); u16(0, &out); u16(UInt16(members.count), &out); u16(UInt16(members.count), &out)
        u32(UInt32(central.count), &out); u32(cdOffset, &out); u16(0, &out)
        return out
    }
}
