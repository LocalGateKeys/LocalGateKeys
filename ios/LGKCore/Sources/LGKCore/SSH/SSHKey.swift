import Foundation
import Crypto
#if canImport(Security)
import Security
#endif

// Port of the Windows `ssh_keys.py` (and the key half of `ssh_agent/service.py`): reads the private keys the SSH
// agent serves (ed25519, ECDSA nistp256/nistp384, RSA) from OpenSSH containers (plain or encrypted with
// bcrypt_pbkdf + aes256-ctr) and unencrypted PEM, and builds SSH wire values: public blobs, fingerprints and
// signature blobs. Nothing here touches the disk or logs key material.
//
// Wire formats (RFC 4251): `string` is a uint32 length plus bytes, `mpint` a big-endian two's-complement integer
// without redundant leading bytes. A signature blob is `string(algorithm) || string(signature)`; the inner ECDSA
// signature is `mpint r || mpint s`.

/// Why a key cannot be used: the Windows `SshKeyError` codes.
public enum SSHKeyError: Error, Equatable, Sendable {
    case unsupportedFormat, needsPassphrase, badPassphrase, sha1Refused

    public var code: String {
        switch self {
        case .unsupportedFormat: "unsupported_format"
        case .needsPassphrase: "needs_passphrase"
        case .badPassphrase: "bad_passphrase"
        case .sha1Refused: "sha1_refused"
        }
    }
}

/// SSH wire format helpers (RFC 4251).
public enum SSHWire {
    struct Truncated: Error {}

    public static func u32(_ value: UInt32) -> [UInt8] {
        [UInt8(value >> 24), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
    }

    public static func string(_ data: [UInt8]) -> [UInt8] { u32(UInt32(data.count)) + data }

    public static func string(_ text: String) -> [UInt8] { string(Array(text.utf8)) }

    /// The `mpint` of a non-negative big-endian magnitude (Windows `ssh_mpint`).
    public static func mpint(_ magnitude: [UInt8]) -> [UInt8] {
        var m = Array(magnitude.drop(while: { $0 == 0 }))
        if let first = m.first, first & 0x80 != 0 { m.insert(0, at: 0) }
        return string(m)
    }

    /// Reads SSH values in order; every read past the end throws.
    public struct Reader {
        let bytes: [UInt8]
        var position = 0

        public init(_ bytes: [UInt8]) { self.bytes = bytes }

        public var isAtEnd: Bool { position >= bytes.count }

        public mutating func take(_ count: Int) throws -> [UInt8] {
            guard count >= 0, count <= bytes.count - position else { throw Truncated() }
            defer { position += count }
            return Array(bytes[position..<position + count])
        }

        public mutating func u32() throws -> UInt32 {
            let b = try take(4)
            return UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
        }

        public mutating func string() throws -> [UInt8] {
            let length = try u32()
            guard length <= UInt32(Int32.max) else { throw Truncated() }
            return try take(Int(length))
        }

        public mutating func boolean() throws -> Bool { try take(1)[0] != 0 }

        public mutating func rest() -> [UInt8] {
            defer { position = bytes.count }
            return Array(bytes[min(position, bytes.count)...])
        }
    }

    /// The first `count` SSH strings of `blob`, or nil when it is shorter (Windows `service._strings`).
    public static func strings(_ blob: [UInt8], count: Int) -> [[UInt8]]? {
        var reader = Reader(blob)
        var out: [[UInt8]] = []
        for _ in 0..<count {
            guard let s = try? reader.string() else { return nil }
            out.append(s)
        }
        return out
    }

    /// The key type a public blob starts with, or "" (Windows `service._blob_type`).
    public static func blobType(_ blob: [UInt8]) -> String {
        guard let parts = strings(blob, count: 1) else { return "" }
        return String(decoding: parts[0], as: UTF8.self)
    }
}

/// A usable private key with its SSH public blob (Windows `AgentKey`).
public struct SSHKey: Sendable {
    /// `SSH_AGENT_RSA_SHA2_256` / `SSH_AGENT_RSA_SHA2_512` sign request flags.
    public static let rsaSHA256: UInt32 = 2
    public static let rsaSHA512: UInt32 = 4
    /// What the agent serves (Windows `SUPPORTED_KEY_TYPES`); ssh-rsa signs with SHA-2 only.
    public static let supportedTypes: Set<String> = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ssh-rsa"]

    enum Curve: Sendable {
        case p256, p384
        var size: Int { self == .p256 ? 32 : 48 }
        var name: String { self == .p256 ? "nistp256" : "nistp384" }
    }

    enum Secret: Sendable {
        case ed25519(seed: [UInt8])
        case ecdsa(Curve, scalar: [UInt8])
        case rsa(pkcs1: [UInt8])
    }

    public let keyType: String
    public let publicBlob: [UInt8]
    let secret: Secret

    /// `type base64 [comment]`.
    public func publicLine(comment: String = "") -> String {
        let line = "\(keyType) \(Data(publicBlob).base64EncodedString())"
        return comment.isEmpty ? line : "\(line) \(comment)"
    }

    public var fingerprint: String { Self.fingerprint(of: publicBlob) }

    /// `SHA256:<base64 of the blob's SHA-256, unpadded>`, as `ssh-keygen -l` prints it.
    public static func fingerprint(of blob: [UInt8]) -> String {
        var digest = Data(SHA256.hash(data: blob)).base64EncodedString()
        while digest.hasSuffix("=") { digest.removeLast() }
        return "SHA256:" + digest
    }

    /// The signature blob over `data`. RSA needs the SHA-2 flags: a plain (SHA-1) ssh-rsa request is refused.
    public func sign(_ data: [UInt8], flags: UInt32 = 0) throws -> [UInt8] {
        switch secret {
        case .ed25519(let seed):
            let signature = try Curve25519.Signing.PrivateKey(rawRepresentation: seed).signature(for: data)
            return SSHWire.string("ssh-ed25519") + SSHWire.string(Array(signature))
        case .ecdsa(let curve, let scalar):
            let raw: [UInt8]
            switch curve {
            case .p256: raw = try Array(P256.Signing.PrivateKey(rawRepresentation: scalar).signature(for: data).rawRepresentation)
            case .p384: raw = try Array(P384.Signing.PrivateKey(rawRepresentation: scalar).signature(for: data).rawRepresentation)
            }
            let half = raw.count / 2
            return SSHWire.string(keyType) + SSHWire.string(SSHWire.mpint(Array(raw[..<half])) + SSHWire.mpint(Array(raw[half...])))
        case .rsa(let der):
            let sha512: Bool
            if flags & Self.rsaSHA512 != 0 { sha512 = true } else if flags & Self.rsaSHA256 != 0 { sha512 = false } else {
                throw SSHKeyError.sha1Refused
            }
            let signature = try RSAKeys.sign(pkcs1: der, data: data, sha512: sha512)
            return SSHWire.string(sha512 ? "rsa-sha2-512" : "rsa-sha2-256") + SSHWire.string(signature)
        }
    }

    // MARK: - Loading

    static let opensshHeader = "-----BEGIN OPENSSH PRIVATE KEY-----"
    static let opensshFooter = "-----END OPENSSH PRIVATE KEY-----"
    static let opensshMagic = Array("openssh-key-v1".utf8) + [0]
    static let pemHeaders = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    ]

    /// Windows `load_private_key`. A passphrase is used only for an encrypted key (one stored with an unencrypted
    /// key is ignored); an empty passphrase counts as none. Encrypted PEM keys need the Windows app.
    public static func load(_ text: String, passphrase: String?) throws -> SSHKey {
        let stripped = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let password: [UInt8]? = passphrase.flatMap { $0.isEmpty ? nil : Array($0.utf8) }
        if stripped.hasPrefix(opensshHeader) { return try OpenSSHContainer.load(stripped, password: password) }
        guard pemHeaders.contains(where: { stripped.hasPrefix($0) }) else { throw SSHKeyError.unsupportedFormat }
        if isEncryptedPEM(stripped) {
            // Windows decrypts these (PKCS#8 PBES2, legacy OpenSSL); the Mac does not, yet.
            throw password == nil ? SSHKeyError.needsPassphrase : SSHKeyError.unsupportedFormat
        }
        do { return try PEMKeys.load(stripped) } catch { throw SSHKeyError.unsupportedFormat }
    }

    /// An encrypted PEM key (PKCS#8 `ENCRYPTED PRIVATE KEY` or legacy `Proc-Type: 4,ENCRYPTED`): the Mac can't use it.
    public static func isEncryptedPEM(_ text: String) -> Bool {
        let stripped = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard pemHeaders.contains(where: { stripped.hasPrefix($0) }) else { return false }
        let head = String(String.UnicodeScalarView(stripped.unicodeScalars.prefix(512)))
        return stripped.hasPrefix("-----BEGIN ENCRYPTED PRIVATE KEY-----") || head.contains("Proc-Type: 4,ENCRYPTED")
    }

    /// (blob, comment) from an OpenSSH public key line whose type is served and matches its blob
    /// (Windows `service._public_line_blob`).
    public static func publicLineBlob(_ line: String) -> (blob: [UInt8], comment: String)? {
        let fields = line.trimmingCharacters(in: .whitespacesAndNewlines)
            .split(maxSplits: 2, omittingEmptySubsequences: true, whereSeparator: { $0.isWhitespace })
        guard fields.count >= 2, supportedTypes.contains(String(fields[0])),
              let blob = strictBase64(String(fields[1])), SSHWire.blobType(blob) == String(fields[0]) else { return nil }
        let comment = fields.count > 2 ? String(fields[2]).trimmingCharacters(in: .whitespacesAndNewlines) : ""
        return (blob, comment)
    }

    /// Python `b64decode(validate=True)`: the standard alphabet, then at most two `=` at the very end.
    static func strictBase64(_ text: String) -> [UInt8]? {
        let scalars = text.unicodeScalars
        let body = scalars.prefix { ("A"..."Z").contains($0) || ("a"..."z").contains($0) || ("0"..."9").contains($0)
            || $0 == "+" || $0 == "/" }
        let pad = scalars.dropFirst(body.count)
        guard pad.count <= 2, pad.allSatisfy({ $0 == "=" }), let data = Data(base64Encoded: text) else { return nil }
        return Array(data)
    }
}

// MARK: - OpenSSH containers

/// `openssh-key-v1`: `"openssh-key-v1\0" string(cipher) string(kdf) string(kdf options) uint32(1) string(public key)
/// string(private section)`. The private section (decrypted when needed) is `uint32 check, uint32 check, key,
/// string(comment), padding 1 2 3 …`.
enum OpenSSHContainer {
    /// aes256-ctr is what `ssh-keygen` (and Python `cryptography`) writes for every encrypted key.
    static let cipherKeyLength = ["aes256-ctr": 32]

    static func load(_ stripped: String, password: [UInt8]?) throws -> SSHKey {
        var body = String(stripped.dropFirst(SSHKey.opensshHeader.count))
        if body.hasSuffix(SSHKey.opensshFooter) { body = String(body.dropLast(SSHKey.opensshFooter.count)) }
        body.removeAll(where: { $0.isWhitespace })
        guard let raw = SSHKey.strictBase64(body), raw.starts(with: SSHKey.opensshMagic) else { throw SSHKeyError.unsupportedFormat }
        var reader = SSHWire.Reader(raw)
        let cipher: String, kdf: String, options: [UInt8], publicBlob: [UInt8], privateSection: [UInt8]
        do {
            _ = try reader.take(SSHKey.opensshMagic.count)
            cipher = String(decoding: try reader.string(), as: UTF8.self)
            kdf = String(decoding: try reader.string(), as: UTF8.self)
            options = try reader.string()
            let keyCount = try reader.u32()
            guard keyCount == 1 else { throw SSHKeyError.unsupportedFormat }
            publicBlob = try reader.string()
            privateSection = try reader.string()
        } catch {
            throw SSHKeyError.unsupportedFormat
        }
        let keyType = SSHWire.blobType(publicBlob)
        guard SSHKey.supportedTypes.contains(keyType) else { throw SSHKeyError.unsupportedFormat }   // sk-*, DSA, certificates
        let encrypted = cipher != "none"
        var section = privateSection
        if encrypted {
            guard let password else { throw SSHKeyError.needsPassphrase }
            guard let keyLength = cipherKeyLength[cipher], kdf == "bcrypt" else { throw SSHKeyError.unsupportedFormat }
            do {
                var opts = SSHWire.Reader(options)
                let salt = try opts.string()
                let rounds = try opts.u32()
                guard rounds >= 1, rounds <= 1 << 16, section.count % 16 == 0 else { throw SSHKeyError.badPassphrase }
                let derived = try BcryptPBKDF.derive(password: password, salt: salt, rounds: Int(rounds), length: keyLength + 16)
                section = try aesCTR(key: Array(derived[..<keyLength]), iv: Array(derived[keyLength...]), data: section)
            } catch {
                throw SSHKeyError.badPassphrase
            }
        } else if cipher == "none" && kdf != "none" {
            throw SSHKeyError.unsupportedFormat
        }
        do {
            return try privateKey(section, keyType: keyType, publicBlob: publicBlob, blockSize: encrypted ? 16 : 8)
        } catch {
            // Windows: any failure with a passphrase is a wrong passphrase, without one an unreadable key.
            throw encrypted ? SSHKeyError.badPassphrase : SSHKeyError.unsupportedFormat
        }
    }

    static func privateKey(_ section: [UInt8], keyType: String, publicBlob: [UInt8], blockSize: Int) throws -> SSHKey {
        guard section.count % blockSize == 0 else { throw SSHKeyError.unsupportedFormat }
        var r = SSHWire.Reader(section)
        let check1 = try r.u32()
        let check2 = try r.u32()
        guard check1 == check2 else { throw SSHKeyError.unsupportedFormat }   // a wrong passphrase, as a rule
        let innerType = try r.string()
        guard String(decoding: innerType, as: UTF8.self) == keyType else { throw SSHKeyError.unsupportedFormat }
        let key: SSHKey
        switch keyType {
        case "ssh-ed25519":
            let pub = try r.string(), pair = try r.string()
            guard pub.count == 32, pair.count == 64, Array(pair[32...]) == pub else { throw SSHKeyError.unsupportedFormat }
            key = try ed25519(seed: Array(pair[..<32]))
        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384":
            let curve: SSHKey.Curve = keyType.hasSuffix("nistp256") ? .p256 : .p384
            let curveName = try r.string()
            guard String(decoding: curveName, as: UTF8.self) == curve.name else { throw SSHKeyError.unsupportedFormat }
            let point = try r.string()
            key = try ecdsa(curve, scalar: try r.string())
            guard Array(key.publicBlob) == SSHWire.string(keyType) + SSHWire.string(curve.name) + SSHWire.string(point) else {
                throw SSHKeyError.unsupportedFormat
            }
        default:   // ssh-rsa: n, e, d, iqmp, p, q
            let n = try r.string(), e = try r.string(), d = try r.string(), iqmp = try r.string(), p = try r.string(), q = try r.string()
            key = try RSAKeys.key(n: n, e: e, d: d, p: p, q: q, iqmp: iqmp)
        }
        _ = try r.string()   // comment
        let padding = r.rest()
        // Up to 16 bytes, as the Windows reader (`cryptography`) accepts: some writers pad a full extra block.
        guard padding.count <= 16, padding.enumerated().allSatisfy({ Int($0.element) == $0.offset + 1 }) else {
            throw SSHKeyError.unsupportedFormat
        }
        guard key.publicBlob == publicBlob else { throw SSHKeyError.unsupportedFormat }
        return key
    }

    static func ed25519(seed: [UInt8]) throws -> SSHKey {
        let pub = try Array(Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey.rawRepresentation)
        return SSHKey(keyType: "ssh-ed25519", publicBlob: SSHWire.string("ssh-ed25519") + SSHWire.string(pub),
                      secret: .ed25519(seed: seed))
    }

    /// An ECDSA key from its private scalar (an mpint or DER integer: leading zeros dropped, then padded).
    static func ecdsa(_ curve: SSHKey.Curve, scalar: [UInt8]) throws -> SSHKey {
        let magnitude = Array(scalar.drop(while: { $0 == 0 }))
        guard !magnitude.isEmpty, magnitude.count <= curve.size else { throw SSHKeyError.unsupportedFormat }
        let d = [UInt8](repeating: 0, count: curve.size - magnitude.count) + magnitude
        let point: [UInt8]
        switch curve {
        case .p256: point = try Array(P256.Signing.PrivateKey(rawRepresentation: d).publicKey.x963Representation)
        case .p384: point = try Array(P384.Signing.PrivateKey(rawRepresentation: d).publicKey.x963Representation)
        }
        let keyType = "ecdsa-sha2-" + curve.name
        return SSHKey(keyType: keyType, publicBlob: SSHWire.string(keyType) + SSHWire.string(curve.name) + SSHWire.string(point),
                      secret: .ecdsa(curve, scalar: d))
    }

    /// AES-CTR with OpenSSH's big-endian 128-bit counter: the counter blocks are enciphered (AES-ECB) and XORed in.
    static func aesCTR(key: [UInt8], iv: [UInt8], data: [UInt8]) throws -> [UInt8] {
        guard key.count == 32, iv.count == 16, data.count % 16 == 0 else { throw SSHKeyError.unsupportedFormat }
        if data.isEmpty { return [] }
        var counter = iv
        var blocks = [UInt8]()
        blocks.reserveCapacity(data.count)
        for _ in 0..<(data.count / 16) {
            blocks += counter
            var i = 15
            while i >= 0 {
                counter[i] &+= 1
                if counter[i] != 0 { break }
                i -= 1
            }
        }
        let stream = try AESCBC.transform(blocks, seed: key, rounds: 1)
        return zip(data, stream).map { $0 ^ $1 }
    }
}

// MARK: - PEM (unencrypted)

/// `RSA PRIVATE KEY` (PKCS#1), `EC PRIVATE KEY` (SEC1) and `PRIVATE KEY` (PKCS#8: RSA, EC P-256/384, Ed25519).
enum PEMKeys {
    static let rsaEncryption: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    static let ecPublicKey: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
    static let ed25519: [UInt8] = [0x2B, 0x65, 0x70]
    static let p256: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
    static let p384: [UInt8] = [0x2B, 0x81, 0x04, 0x00, 0x22]

    static func load(_ stripped: String) throws -> SSHKey {
        let lines = stripped.split(whereSeparator: { $0 == "\n" || $0 == "\r" }).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let first = lines.first, let end = lines.firstIndex(where: { $0.hasPrefix("-----END ") }), end > 0 else {
            throw SSHKeyError.unsupportedFormat
        }
        guard let der = SSHKey.strictBase64(lines[1..<end].joined()) else { throw SSHKeyError.unsupportedFormat }
        switch first {
        case "-----BEGIN RSA PRIVATE KEY-----": return try RSAKeys.key(pkcs1: der)
        case "-----BEGIN EC PRIVATE KEY-----": return try sec1(der, curveOID: nil)
        default: return try pkcs8(der)
        }
    }

    static func curve(_ oid: [UInt8]) throws -> SSHKey.Curve {
        if oid == p256 { return .p256 }
        if oid == p384 { return .p384 }
        throw SSHKeyError.unsupportedFormat
    }

    /// SEC1 `ECPrivateKey`: `SEQUENCE { INTEGER 1, OCTET STRING d, [0] OID curve OPTIONAL, [1] BIT STRING OPTIONAL }`.
    static func sec1(_ der: [UInt8], curveOID: [UInt8]?) throws -> SSHKey {
        var outer = DER.Reader(der)
        var seq = DER.Reader(try outer.expect(0x30))
        let version = try seq.expect(0x02)
        guard version == [1] else { throw SSHKeyError.unsupportedFormat }
        let d = try seq.expect(0x04)
        var oid = curveOID
        while !seq.isAtEnd {
            let (tag, value) = try seq.next()
            if tag == 0xA0 { var inner = DER.Reader(value); oid = try inner.expect(0x06) }
        }
        guard let oid else { throw SSHKeyError.unsupportedFormat }
        return try OpenSSHContainer.ecdsa(try curve(oid), scalar: d)
    }

    /// PKCS#8 `PrivateKeyInfo`: `SEQUENCE { INTEGER 0, SEQUENCE { OID, params }, OCTET STRING key, … }`.
    static func pkcs8(_ der: [UInt8]) throws -> SSHKey {
        var outer = DER.Reader(der)
        var seq = DER.Reader(try outer.expect(0x30))
        _ = try seq.expect(0x02)
        var algorithm = DER.Reader(try seq.expect(0x30))
        let oid = try algorithm.expect(0x06)
        let key = try seq.expect(0x04)
        if oid == rsaEncryption { return try RSAKeys.key(pkcs1: key) }
        if oid == ecPublicKey { return try sec1(key, curveOID: try algorithm.expect(0x06)) }
        if oid == ed25519 {
            var inner = DER.Reader(key)
            let seed = try inner.expect(0x04)
            guard seed.count == 32 else { throw SSHKeyError.unsupportedFormat }
            return try OpenSSHContainer.ed25519(seed: seed)
        }
        throw SSHKeyError.unsupportedFormat
    }
}

/// A minimal DER reader and the encoders the RSA key needs.
enum DER {
    struct Reader {
        let bytes: [UInt8]
        var position = 0

        init(_ bytes: [UInt8]) { self.bytes = bytes }

        var isAtEnd: Bool { position >= bytes.count }

        mutating func next() throws -> (tag: UInt8, value: [UInt8]) {
            guard bytes.count - position >= 2 else { throw SSHKeyError.unsupportedFormat }
            let tag = bytes[position]
            var length = Int(bytes[position + 1])
            position += 2
            if length & 0x80 != 0 {
                let count = length & 0x7F
                guard (1...4).contains(count), bytes.count - position >= count else { throw SSHKeyError.unsupportedFormat }
                length = 0
                for _ in 0..<count {
                    length = (length << 8) | Int(bytes[position])
                    position += 1
                }
            }
            guard length <= bytes.count - position else { throw SSHKeyError.unsupportedFormat }
            defer { position += length }
            return (tag, Array(bytes[position..<position + length]))
        }

        mutating func expect(_ tag: UInt8) throws -> [UInt8] {
            let (found, value) = try next()
            guard found == tag else { throw SSHKeyError.unsupportedFormat }
            return value
        }
    }

    static func length(_ count: Int) -> [UInt8] {
        if count < 0x80 { return [UInt8(count)] }
        var bytes: [UInt8] = []
        var value = count
        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    /// A non-negative INTEGER from a big-endian magnitude.
    static func integer(_ magnitude: [UInt8]) -> [UInt8] {
        var m = Array(magnitude.drop(while: { $0 == 0 }))
        if m.isEmpty { m = [0] } else if m[0] & 0x80 != 0 { m.insert(0, at: 0) }
        return [0x02] + length(m.count) + m
    }

    static func sequence(_ parts: [[UInt8]]) -> [UInt8] {
        let body = parts.flatMap { $0 }
        return [0x30] + length(body.count) + body
    }
}

// MARK: - RSA

/// RSA keys sign through the Security framework (`SecKeyCreateSignature`, PKCS#1 v1.5 with SHA-256 or SHA-512),
/// which takes a PKCS#1 `RSAPrivateKey`. OpenSSH stores n, e, d, iqmp, p and q; the CRT exponents d mod (p-1) and
/// d mod (q-1) are computed here.
enum RSAKeys {
    static func key(n: [UInt8], e: [UInt8], d: [UInt8], p: [UInt8], q: [UInt8], iqmp: [UInt8]) throws -> SSHKey {
        guard let p1 = BigBytes.minusOne(p), let q1 = BigBytes.minusOne(q),
              let dp = BigBytes.mod(d, p1), let dq = BigBytes.mod(d, q1) else { throw SSHKeyError.unsupportedFormat }
        let der = DER.sequence([DER.integer([]), DER.integer(n), DER.integer(e), DER.integer(d), DER.integer(p),
                                DER.integer(q), DER.integer(dp), DER.integer(dq), DER.integer(iqmp)])
        return try make(der: der, n: n, e: e)
    }

    /// A PKCS#1 `RSAPrivateKey`: `SEQUENCE { INTEGER 0, n, e, d, p, q, dp, dq, qinv }`.
    static func key(pkcs1 der: [UInt8]) throws -> SSHKey {
        var outer = DER.Reader(der)
        var seq = DER.Reader(try outer.expect(0x30))
        let version = try seq.expect(0x02)
        guard version == [0] else { throw SSHKeyError.unsupportedFormat }
        let n = try seq.expect(0x02), e = try seq.expect(0x02)
        return try make(der: der, n: n, e: e)
    }

    static func make(der: [UInt8], n: [UInt8], e: [UInt8]) throws -> SSHKey {
        guard n.first.map({ $0 & 0x80 == 0 }) ?? false, e.first.map({ $0 & 0x80 == 0 }) ?? false else {
            throw SSHKeyError.unsupportedFormat   // negative or empty
        }
        _ = try privateKey(der)   // the Security framework accepts it
        return SSHKey(keyType: "ssh-rsa", publicBlob: SSHWire.string("ssh-rsa") + SSHWire.mpint(e) + SSHWire.mpint(n),
                      secret: .rsa(pkcs1: der))
    }

    #if canImport(Security)
    static func privateKey(_ der: [UInt8]) throws -> SecKey {
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                         kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(Data(der) as CFData, attributes as CFDictionary, &error) else {
            throw SSHKeyError.unsupportedFormat
        }
        return key
    }

    static func sign(pkcs1 der: [UInt8], data: [UInt8], sha512: Bool) throws -> [UInt8] {
        let key = try privateKey(der)
        let algorithm: SecKeyAlgorithm = sha512 ? .rsaSignatureMessagePKCS1v15SHA512 : .rsaSignatureMessagePKCS1v15SHA256
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, algorithm, Data(data) as CFData, &error) as Data? else {
            throw SSHKeyError.unsupportedFormat
        }
        return Array(signature)
    }

    /// PKCS#1 v1.5 verification with a public key given as n and e (big-endian magnitudes).
    static func verify(n: [UInt8], e: [UInt8], signature: [UInt8], data: [UInt8], sha512: Bool) -> Bool {
        let der = DER.sequence([DER.integer(n), DER.integer(e)])
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                         kSecAttrKeyClass as String: kSecAttrKeyClassPublic]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(Data(der) as CFData, attributes as CFDictionary, &error) else { return false }
        let algorithm: SecKeyAlgorithm = sha512 ? .rsaSignatureMessagePKCS1v15SHA512 : .rsaSignatureMessagePKCS1v15SHA256
        return SecKeyVerifySignature(key, algorithm, Data(data) as CFData, Data(signature) as CFData, &error)
    }
    #else
    static func privateKey(_ der: [UInt8]) throws -> Never { throw SSHKeyError.unsupportedFormat }
    static func sign(pkcs1 der: [UInt8], data: [UInt8], sha512: Bool) throws -> [UInt8] { throw SSHKeyError.unsupportedFormat }
    static func verify(n: [UInt8], e: [UInt8], signature: [UInt8], data: [UInt8], sha512: Bool) -> Bool { false }
    #endif
}

/// Arithmetic on big-endian magnitudes, just enough for the RSA CRT exponents.
enum BigBytes {
    static func magnitude(_ bytes: [UInt8]) -> [UInt8] { Array(bytes.drop(while: { $0 == 0 })) }

    /// `value - 1`, or nil for zero.
    static func minusOne(_ value: [UInt8]) -> [UInt8]? {
        var r = magnitude(value)
        guard !r.isEmpty else { return nil }
        var i = r.count - 1
        while r[i] == 0 {
            r[i] = 0xFF
            i -= 1
        }
        r[i] -= 1
        return magnitude(r)
    }

    /// `a mod m` by shift and subtract, one bit of `a` at a time; nil for a zero modulus.
    static func mod(_ a: [UInt8], _ modulus: [UInt8]) -> [UInt8]? {
        let m = magnitude(modulus)
        guard !m.isEmpty else { return nil }
        let n = m.count + 1
        let mm: [UInt8] = [0] + m
        var r = [UInt8](repeating: 0, count: n)   // always < m before a shift, so 2m fits in n bytes
        for byte in a {
            for bit in stride(from: 7, through: 0, by: -1) {
                var carry = (byte >> UInt8(bit)) & 1
                for i in stride(from: n - 1, through: 0, by: -1) {
                    let v = r[i]
                    r[i] = (v << 1) | carry
                    carry = v >> 7
                }
                if !r.lexicographicallyPrecedes(mm) {
                    var borrow = 0
                    for i in stride(from: n - 1, through: 0, by: -1) {
                        var digit = Int(r[i]) - Int(mm[i]) - borrow
                        if digit < 0 { digit += 256; borrow = 1 } else { borrow = 0 }
                        r[i] = UInt8(digit)
                    }
                }
            }
        }
        return magnitude(r)
    }
}

// MARK: - Verifying (session-bind host signatures, tests)

/// Windows `verify_ssh_signature`: an SSH signature blob over `data` (ed25519, ECDSA P-256/384/521, RSA SHA-2;
/// never SHA-1).
public enum SSHSignature {
    public static func verify(publicBlob: [UInt8], signature: [UInt8], data: [UInt8]) -> Bool {
        let keyType = SSHWire.blobType(publicBlob)
        guard let sig = SSHWire.strings(signature, count: 2) else { return false }
        let algorithm = String(decoding: sig[0], as: UTF8.self), raw = sig[1]
        if keyType == "ssh-ed25519" && algorithm == "ssh-ed25519" {
            guard let parts = SSHWire.strings(publicBlob, count: 2),
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: parts[1]) else { return false }
            return key.isValidSignature(raw, for: data)
        }
        if keyType.hasPrefix("ecdsa-sha2-") && algorithm == keyType {
            guard let parts = SSHWire.strings(publicBlob, count: 3), let numbers = SSHWire.strings(raw, count: 2) else { return false }
            let curve = String(decoding: parts[1], as: UTF8.self)
            guard keyType == "ecdsa-sha2-" + curve else { return false }
            let size = ["nistp256": 32, "nistp384": 48, "nistp521": 66][curve] ?? 0
            guard size > 0, let r = fixed(numbers[0], size), let s = fixed(numbers[1], size) else { return false }
            switch curve {
            case "nistp256":
                guard let key = try? P256.Signing.PublicKey(x963Representation: parts[2]),
                      let signature = try? P256.Signing.ECDSASignature(rawRepresentation: r + s) else { return false }
                return key.isValidSignature(signature, for: data)
            case "nistp384":
                guard let key = try? P384.Signing.PublicKey(x963Representation: parts[2]),
                      let signature = try? P384.Signing.ECDSASignature(rawRepresentation: r + s) else { return false }
                return key.isValidSignature(signature, for: data)
            default:
                guard let key = try? P521.Signing.PublicKey(x963Representation: parts[2]),
                      let signature = try? P521.Signing.ECDSASignature(rawRepresentation: r + s) else { return false }
                return key.isValidSignature(signature, for: data)
            }
        }
        if keyType == "ssh-rsa" && (algorithm == "rsa-sha2-256" || algorithm == "rsa-sha2-512") {
            guard let parts = SSHWire.strings(publicBlob, count: 3),
                  parts[1].first.map({ $0 & 0x80 == 0 }) ?? false, parts[2].first.map({ $0 & 0x80 == 0 }) ?? false else { return false }
            return RSAKeys.verify(n: parts[2], e: parts[1], signature: raw, data: data, sha512: algorithm == "rsa-sha2-512")
        }
        return false
    }

    /// A non-negative mpint as exactly `size` big-endian bytes, or nil when negative or too long.
    static func fixed(_ mpint: [UInt8], _ size: Int) -> [UInt8]? {
        if let first = mpint.first, first & 0x80 != 0 { return nil }
        let magnitude = BigBytes.magnitude(mpint)
        guard magnitude.count <= size else { return nil }
        return [UInt8](repeating: 0, count: size - magnitude.count) + magnitude
    }
}
