import Crypto
import Foundation

/// KeePass 2 databases, KDBX 3.1 and 4.x (Windows `kdbx.read_kdbx` + `records_from_database`): AES-256 or ChaCha20,
/// AES-KDF or Argon2d/id with Windows' bounds, password only. Twofish and key files are refused with a clear message.
public enum KDBX: Importer {
    static let maxBytes = 64 * 1024 * 1024
    static let maxXMLBytes = 128 * 1024 * 1024
    static let maxSlowStreamTotalBytes = 4 * 1024 * 1024
    static let maxArgon2Memory: UInt64 = 1024 * 1024 * 1024
    static let maxArgon2Iterations: UInt64 = 1_000
    static let maxArgon2Work: UInt64 = 32 * 1024 * 1024 * 1024
    static let maxArgon2Parallelism: UInt64 = 64
    static let maxAESKDFRounds: UInt64 = 50_000_000

    static let cipherAES: [UInt8] = KDBXHex.hex("31c1f2e6bf714350be5805216afc5aff")
    static let cipherChaCha20: [UInt8] = KDBXHex.hex("d6038a2b8b6f4cb5a524339a31dbb59a")
    static let cipherTwofish: [UInt8] = KDBXHex.hex("ad68f29f576f4bb9a36ad47af965346c")
    static let kdfAES: [UInt8] = KDBXHex.hex("c9d9f39a628a4460bf740d08c18a4fea")
    static let kdfArgon2d: [UInt8] = KDBXHex.hex("ef636ddf8c29444b91f7a9a403e30a0c")
    static let kdfArgon2id: [UInt8] = KDBXHex.hex("9e298b1956db4773b23dfc3ec6f0a1e6")
    static let salsaNonce: [UInt8] = KDBXHex.hex("e830094b97205d2a")

    static let twofishMessage = "Twofish-encrypted databases are not supported; change the cipher to AES or ChaCha20 in KeePass"

    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        // Windows `load_records` asks for the password before reading a password format.
        guard let password = options.password, !password.isEmpty else { throw ImportError.needsPassword }
        let root = try read(ImportText.bounded(data, limit: maxBytes), password: password)
        return try KeePassTree.records(root)
    }

    private static func fail(_ m: String) -> ImportError { .malformed(m) }

    // MARK: Header

    enum KDFValue: Equatable { case int(UInt64, signed: Bool), bool(Bool), string(String), bytes([UInt8]) }

    struct Header {
        var major = 0
        var raw: [UInt8] = []
        var end = 0
        var cipher: [UInt8] = []
        var compress = false
        var masterSeed: [UInt8] = []
        var iv: [UInt8] = []
        var kdf: [String: KDFValue] = [:]
        var streamID: UInt32 = 0
        var streamKey: [UInt8] = []
        var streamStart: [UInt8] = []
    }

    static func u16(_ b: [UInt8], _ i: Int) -> Int { Int(b[i]) | Int(b[i + 1]) << 8 }
    static func u32(_ b: [UInt8], _ i: Int) -> UInt32 { UInt32(u16(b, i)) | UInt32(u16(b, i + 2)) << 16 }
    static func i32(_ b: [UInt8], _ i: Int) -> Int { Int(Int32(bitPattern: u32(b, i))) }
    static func u64(_ b: [UInt8], _ i: Int) -> UInt64 { UInt64(u32(b, i)) | UInt64(u32(b, i + 4)) << 32 }
    static func le64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8((v >> (8 * UInt64($0))) & 0xFF) } }

    static func parseHeader(_ data: [UInt8]) throws -> Header {
        guard data.count >= 12 else { throw fail("File is too short to be a KDBX database") }
        let sig1 = u32(data, 0), sig2 = u32(data, 4), major = u16(data, 10), minor = u16(data, 8)
        guard sig1 == 0x9AA2_D903, [0xB54B_FB67, 0xB54B_FB65, 0xB54B_FB66].contains(sig2) else {
            throw fail("Not a KeePass KDBX database")
        }
        if sig2 == 0xB54B_FB65 { throw fail("KeePass 1.x (.kdb) databases are not supported; export from KeePass 2 as .kdbx") }
        guard major == 3 || major == 4 else { throw fail("Unsupported KDBX version \(major).\(minor)") }
        var fields: [UInt8: [UInt8]] = [:]
        var pos = 12
        let sizeLen = major == 4 ? 4 : 2
        while true {
            guard pos + 1 + sizeLen <= data.count else { throw fail("KDBX header is truncated") }
            let id = data[pos]
            let size = major == 4 ? Int(u32(data, pos + 1)) : u16(data, pos + 1)
            pos += 1 + sizeLen
            guard size <= data.count - pos else { throw fail("KDBX header is truncated") }
            let value = Array(data[pos..<(pos + size)])
            pos += size
            if id == 0 { break }
            fields[id] = value
        }
        var h = Header(major: major, raw: Array(data[0..<pos]), end: pos)
        h.cipher = fields[2] ?? []
        guard [cipherAES, cipherChaCha20, cipherTwofish].contains(h.cipher) else { throw fail("Unsupported outer cipher") }
        if h.cipher == cipherTwofish { throw fail(twofishMessage) }
        guard let compression = fields[3], compression.count == 4 else { throw fail("KDBX header is missing the compression flag") }
        let flag = u32(compression, 0)
        guard flag <= 1 else { throw fail("Unsupported compression algorithm") }
        h.compress = flag == 1
        h.masterSeed = fields[4] ?? []
        guard h.masterSeed.count == 32 else { throw fail("KDBX master seed must be 32 bytes") }
        h.iv = fields[7] ?? []
        guard h.iv.count == (h.cipher == cipherAES ? 16 : 12) else { throw fail("KDBX encryption IV has an unexpected length") }
        if major == 4 {
            guard let dict = fields[11] else { throw fail("KDBX 4 header is missing KDF parameters") }
            h.kdf = try variantDictionary(dict)
            try checkKDF(h.kdf)
        } else {
            guard h.cipher == cipherAES else { throw fail("KDBX 3 databases must use AES-256") }
            guard let rounds = fields[6], rounds.count == 8 else { throw fail("KDBX 3 header is missing the transform rounds") }
            h.kdf = ["$UUID": .bytes(kdfAES), "S": .bytes(fields[5] ?? []), "R": .int(u64(rounds, 0), signed: false)]
            try checkKDF(h.kdf)
            h.streamKey = fields[8] ?? []
            h.streamStart = fields[9] ?? []
            guard h.streamStart.count == 32 else { throw fail("KDBX 3 header is missing the stream start bytes") }
            guard let stream = fields[10], stream.count == 4 else { throw fail("KDBX 3 header is missing the inner stream id") }
            h.streamID = u32(stream, 0)
        }
        return h
    }

    /// Windows `_parse_variant_dict`.
    static func variantDictionary(_ d: [UInt8]) throws -> [String: KDFValue] {
        guard d.count >= 3 else { throw fail("KDF parameters are truncated") }
        guard u16(d, 0) & 0xFF00 == 0x0100 else { throw fail("Unsupported KDF parameter dictionary version") }
        var out: [String: KDFValue] = [:]
        var pos = 2
        while true {
            guard pos < d.count else { throw fail("KDF parameters are truncated") }
            let kind = d[pos]
            pos += 1
            if kind == 0 { break }
            guard pos + 4 <= d.count else { throw fail("KDF parameters are truncated") }
            let nameLen = i32(d, pos)
            pos += 4
            guard nameLen >= 0, nameLen <= d.count - pos else { throw fail("KDF parameters are truncated") }
            let name = String(decoding: d[pos..<(pos + nameLen)], as: UTF8.self)
            pos += nameLen
            guard pos + 4 <= d.count else { throw fail("KDF parameters are truncated") }
            let valueLen = i32(d, pos)
            pos += 4
            guard valueLen >= 0, valueLen <= d.count - pos else { throw fail("KDF parameters are truncated") }
            let raw = Array(d[pos..<(pos + valueLen)])
            pos += valueLen
            let malformed = fail("KDF parameters are malformed")
            switch kind {
            case 0x04: guard raw.count == 4 else { throw malformed }; out[name] = .int(UInt64(u32(raw, 0)), signed: false)
            case 0x05: guard raw.count == 8 else { throw malformed }; out[name] = .int(u64(raw, 0), signed: false)
            case 0x08: out[name] = .bool(raw != [0])
            case 0x0C: guard raw.count == 4 else { throw malformed }; out[name] = .int(UInt64(bitPattern: Int64(i32(raw, 0))), signed: true)
            case 0x0D: guard raw.count == 8 else { throw malformed }; out[name] = .int(u64(raw, 0), signed: true)
            case 0x18: guard let s = String(bytes: raw, encoding: .utf8) else { throw malformed }; out[name] = .string(s)
            case 0x42: out[name] = .bytes(raw)
            default: throw fail("Unsupported KDF parameter type \(String(format: "%#x", kind))")
            }
        }
        return out
    }

    /// Python's view of a KDF integer: nil when not an int (bools count as 0/1, as `isinstance(True, int)`).
    static func int(_ v: KDFValue?) -> Int64? {
        switch v {
        case .int(let u, let signed)?:
            if signed { return Int64(bitPattern: u) }
            return u > UInt64(Int64.max) ? Int64.max : Int64(u)
        case .bool(let b)?: return b ? 1 : 0
        default: return nil
        }
    }

    static func bytes(_ v: KDFValue?) -> [UInt8]? { if case .bytes(let b)? = v { return b }; return nil }

    /// Windows `_check_kdf_limits`.
    static func checkKDF(_ kdf: [String: KDFValue]) throws {
        let id = bytes(kdf["$UUID"])
        if id == kdfAES {
            guard let rounds = int(kdf["R"]), rounds >= 1, UInt64(rounds) <= maxAESKDFRounds else {
                throw fail("AES-KDF round count is outside the supported range")
            }
            guard bytes(kdf["S"])?.count == 32 else { throw fail("AES-KDF seed must be 32 bytes") }
        } else if id == kdfArgon2d || id == kdfArgon2id {
            guard let m = int(kdf["M"]), m >= 8 * 1024, UInt64(m) <= maxArgon2Memory else {
                throw fail("Argon2 memory parameter is outside the supported range")
            }
            guard let i = int(kdf["I"]), i >= 1, UInt64(i) <= maxArgon2Iterations else {
                throw fail("Argon2 iteration count is outside the supported range")
            }
            guard let p = int(kdf["P"]), p >= 1, UInt64(p) <= maxArgon2Parallelism else {
                throw fail("Argon2 parallelism is outside the supported range")
            }
            if UInt64(m) * UInt64(i) > maxArgon2Work { throw fail("Argon2 memory x iterations exceeds the supported import budget") }
            guard let salt = bytes(kdf["S"]), (8...64).contains(salt.count) else { throw fail("Argon2 salt length is unsupported") }
            let version: Int64? = kdf["V"] == nil ? 0x13 : int(kdf["V"])
            guard version == 0x10 || version == 0x13 else { throw fail("Unsupported Argon2 version") }
            for key in ["K", "A"] where truthy(kdf[key]) { throw fail("Argon2 secret key / associated data are unsupported") }
        } else {
            throw fail("Unsupported key derivation function")
        }
    }

    private static func truthy(_ v: KDFValue?) -> Bool {
        switch v {
        case nil: return false
        case .int(let u, _)?: return u != 0
        case .bool(let b)?: return b
        case .string(let s)?: return !s.isEmpty
        case .bytes(let b)?: return !b.isEmpty
        }
    }

    // MARK: Keys

    static func transform(_ composite: [UInt8], _ kdf: [String: KDFValue]) throws -> [UInt8] {
        let id = bytes(kdf["$UUID"])
        if id == kdfAES {
            let key = try AESCBC.transform(composite, seed: bytes(kdf["S"])!, rounds: UInt64(int(kdf["R"])!))
            return Array(SHA256.hash(data: key))
        }
        let memory = UInt64(int(kdf["M"])!) / 1024
        do {
            return try Argon2.derive(id == kdfArgon2d ? .d : .id, version: UInt32(kdf["V"].flatMap { int($0) } ?? 0x13),
                                     password: composite, salt: bytes(kdf["S"])!, memoryKiB: UInt32(memory),
                                     iterations: UInt32(int(kdf["I"])!), parallelism: UInt32(int(kdf["P"])!), length: 32)
        } catch {
            // e.g. too little memory for the lane count: within Windows' bounds but refused by Argon2 itself
            throw fail("Argon2 parameters are invalid")
        }
    }

    static func blockKey(_ base: [UInt8], _ index: UInt64) -> [UInt8] { Array(SHA512.hash(data: le64(index) + base)) }

    static func blockHMAC(_ base: [UInt8], _ index: UInt64, _ data: ArraySlice<UInt8>) -> [UInt8] {
        var mac = HMAC<SHA256>(key: SymmetricKey(data: blockKey(base, index)))
        mac.update(data: le64(index))
        let n = UInt32(truncatingIfNeeded: data.count)
        mac.update(data: [UInt8(n & 0xFF), UInt8((n >> 8) & 0xFF), UInt8((n >> 16) & 0xFF), UInt8(n >> 24)])
        mac.update(data: data)
        return Array(mac.finalize())
    }

    private static func equal(_ a: some Collection<UInt8>, _ b: some Collection<UInt8>) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) { diff |= x ^ y }
        return diff == 0
    }

    // MARK: Reading

    /// Windows `read_kdbx` up to the parsed, unprotected XML tree.
    static func read(_ data: Data, password: String) throws -> XMLNode {
        let b = [UInt8](data)
        let h = try parseHeader(b)
        var composite = Array(SHA256.hash(data: Array(SHA256.hash(data: Array(password.utf8)))))
        defer { wipe(&composite) }
        var transformed = try transform(composite, h.kdf)
        var master = Array(SHA256.hash(data: h.masterSeed + transformed))
        var hmacBase = Array(SHA512.hash(data: h.masterSeed + transformed + [1]))
        wipe(&transformed)
        // Best effort: the derived keys are overwritten once the payload is decrypted (or on any failure).
        defer { wipe(&master); wipe(&hmacBase) }
        let xml: [UInt8]
        var streamID = h.streamID, streamKey = h.streamKey
        if h.major == 4 {
            let pos = h.end
            guard pos + 64 <= b.count else { throw fail("KDBX 4 header hash is truncated") }
            guard equal(Array(SHA256.hash(data: h.raw)), b[pos..<(pos + 32)]) else {
                throw fail("KDBX header hash mismatch: the file is corrupted")
            }
            let headerMAC = HMAC<SHA256>.authenticationCode(for: h.raw, using: SymmetricKey(data: blockKey(hmacBase, .max)))
            guard equal(Array(headerMAC), b[(pos + 32)..<(pos + 64)]) else {
                throw ImportError.wrongPasswordOrKeyFile("Wrong password or key file (header HMAC mismatch)")
            }
            let ciphertext = try hmacBlocks(b, pos + 64, hmacBase)
            var plain = try decrypt(h, master, ciphertext)
            if h.compress { plain = try gunzip(plain) }
            let inner = try innerHeader(plain)
            streamID = inner.id; streamKey = inner.key
            xml = Array(plain[inner.end...])
        } else {
            let plain = try decrypt(h, master, Array(b[h.end...]))
            guard plain.count >= 32, equal(plain[0..<32], h.streamStart) else {
                throw ImportError.wrongPasswordOrKeyFile("Wrong password or key file (stream start mismatch)")
            }
            var body = try hashedBlocks(Array(plain[32...]))
            if h.compress { body = try gunzip(body) }
            xml = body
        }
        guard xml.count <= maxXMLBytes else { throw fail("Database XML is too large") }
        let root = try KeePassTree.parse(Data(xml))
        if h.major == 3, let expected = root.find("Meta")?.findText("HeaderHash"), !expected.isEmpty {
            guard Data(SHA256.hash(data: h.raw)).base64EncodedString() == Py.strip(expected) else {
                throw fail("KDBX header hash mismatch: the file is corrupted")
            }
        }
        var stream = try streamID == 0 ? nil : InnerStream(id: streamID, key: streamKey)
        try KeePassTree.unprotect(root, stream: &stream)
        return root
    }

    /// Overwrites key material in place (best effort: copies made by the crypto libraries are out of reach).
    static func wipe(_ key: inout [UInt8]) {
        for i in key.indices { key[i] = 0 }
    }

    static func decrypt(_ h: Header, _ key: [UInt8], _ data: [UInt8]) throws -> [UInt8] {
        if h.cipher == cipherAES {
            guard !data.isEmpty, data.count % 16 == 0 else { throw fail("Encrypted payload is truncated") }
            do { return try AESCBC.decrypt(key: key, iv: h.iv, data: data) } catch {
                throw ImportError.wrongPasswordOrKeyFile("Wrong password or corrupted database")
            }
        }
        var out = data
        var c = ChaCha20(key: key, nonce: h.iv)
        c.process(&out)
        return out
    }

    static func hmacBlocks(_ d: [UInt8], _ start: Int, _ base: [UInt8]) throws -> [UInt8] {
        var out: [UInt8] = [], pos = start, index: UInt64 = 0
        while true {
            guard pos + 36 <= d.count else { throw fail("HMAC block stream is truncated") }
            let expected = d[pos..<(pos + 32)]
            let size = i32(d, pos + 32)
            pos += 36
            guard size >= 0, size <= d.count - pos else { throw fail("HMAC block stream is truncated") }
            let block = d[pos..<(pos + size)]
            pos += size
            guard equal(blockHMAC(base, index, block), expected) else {
                throw fail("HMAC verification failed: wrong password or corrupted data")
            }
            if size == 0 { break }
            out += block
            if out.count > maxBytes { throw fail("Database payload is too large") }
            index += 1
        }
        return out
    }

    static func hashedBlocks(_ d: [UInt8]) throws -> [UInt8] {
        var out: [UInt8] = [], pos = 0, expectedIndex: UInt32 = 0
        while true {
            guard pos + 40 <= d.count else { throw fail("Hashed block stream is truncated") }
            let index = u32(d, pos), digest = d[(pos + 4)..<(pos + 36)], size = Int(u32(d, pos + 36))
            pos += 40
            guard index == expectedIndex else { throw fail("Hashed block stream index mismatch") }
            if size == 0 {
                guard digest.allSatisfy({ $0 == 0 }) else { throw fail("Hashed block stream terminator is corrupted") }
                break
            }
            guard size <= maxBytes, size <= d.count - pos else { throw fail("Hashed block stream is truncated") }
            let block = d[pos..<(pos + size)]
            pos += size
            guard equal(Array(SHA256.hash(data: block)), digest) else {
                throw fail("Hashed block verification failed: corrupted data")
            }
            out += block
            expectedIndex &+= 1
        }
        return out
    }

    static func gunzip(_ data: [UInt8]) throws -> [UInt8] {
        do { return [UInt8](try Inflate.gunzip(Data(data), limit: maxXMLBytes)) }
        catch ZipReader.Failure.tooLarge { throw fail("Decompressed database is too large") }
        catch { throw fail("Compressed payload is corrupted") }
    }

    static func innerHeader(_ d: [UInt8]) throws -> (id: UInt32, key: [UInt8], end: Int) {
        var pos = 0, id: UInt32 = 0, key: [UInt8] = []
        while true {
            guard pos + 5 <= d.count else { throw fail("Inner header is truncated") }
            let field = d[pos], size = i32(d, pos + 1)
            pos += 5
            guard size >= 0, size <= d.count - pos else { throw fail("Inner header is truncated") }
            let value = Array(d[pos..<(pos + size)])
            pos += size
            switch field {
            case 0: return (id, key, pos)
            case 1:
                guard value.count == 4 else { throw fail("Inner header stream id is malformed") }
                id = u32(value, 0)
            case 2: key = value
            case 3: guard !value.isEmpty else { throw fail("Inner header binary is malformed") }
            default: throw fail("Unsupported inner header field \(field)")
            }
        }
    }
}

/// The KDBX protected-value keystream (Windows `_KeyStream`): ARC4 (legacy), Salsa20 (KDBX 3) or ChaCha20 (KDBX 4).
struct InnerStream {
    enum Cipher { case arc4(ARC4), salsa(Salsa20), chacha(ChaCha20) }
    var cipher: Cipher

    /// Salsa20 and ARC4 are held to the smaller budget, as on Windows (where they are pure Python).
    var isSlow: Bool { if case .chacha = cipher { return false }; return true }

    init(id: UInt32, key: [UInt8]) throws {
        switch id {
        case 1:
            guard !key.isEmpty else { throw ImportError.malformed("Empty ARC4 inner stream key") }
            cipher = .arc4(ARC4(key: key))
        case 2: cipher = .salsa(Salsa20(key: Array(SHA256.hash(data: key)), nonce: KDBX.salsaNonce))
        case 3:
            let digest = Array(SHA512.hash(data: key))
            cipher = .chacha(ChaCha20(key: Array(digest[0..<32]), nonce: Array(digest[32..<44])))
        default: throw ImportError.malformed("Unsupported inner random stream \(id)")
        }
    }

    mutating func process(_ data: inout [UInt8]) {
        switch cipher {
        case .arc4(var c): c.process(&data); cipher = .arc4(c)
        case .salsa(var c): c.process(&data); cipher = .salsa(c)
        case .chacha(var c): c.process(&data); cipher = .chacha(c)
        }
    }
}

struct ARC4 {
    private var s = [UInt8](0...255)
    private var i: UInt8 = 0, j: UInt8 = 0

    init(key: [UInt8]) {
        var j: UInt8 = 0
        for i in 0..<256 {
            j = j &+ s[i] &+ key[i % key.count]
            s.swapAt(i, Int(j))
        }
        var discard = [UInt8](repeating: 0, count: 512)  // KeePass drops the first 512 keystream bytes
        process(&discard)
    }

    mutating func process(_ data: inout [UInt8]) {
        for k in data.indices {
            i = i &+ 1
            j = j &+ s[Int(i)]
            s.swapAt(Int(i), Int(j))
            data[k] ^= s[Int(s[Int(i)] &+ s[Int(j)])]
        }
    }
}

enum KDBXHex {
    static func hex(_ s: String) -> [UInt8] {
        var out: [UInt8] = [], i = s.startIndex
        while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
        return out
    }
}
