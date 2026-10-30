import Crypto
import Foundation

/// Bitwarden's password-protected JSON export (Windows `decrypt_bitwarden_export`): `2.` EncStrings, AES-256-CBC with
/// HMAC-SHA256, keys stretched with PBKDF2-SHA256 or Argon2id and expanded with HKDF (`enc`/`mac`).
public enum BitwardenEncrypted: Importer {
    // Bitwarden's own ceilings (PBKDF2 up to 2,000,000; Argon2id up to 10 iterations, 1024 MiB, 16 lanes).
    static let maxPBKDF2Iterations = 2_000_000
    static let maxArgon2MemoryMiB = 1024
    static let maxArgon2Iterations = 10
    static let maxArgon2Parallelism = 16

    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        // Windows `load_records` asks for the password before reading a password format.
        guard let password = options.password, !password.isEmpty else { throw ImportError.needsPassword }
        return try BitwardenJSON.json(ImportText.text(data), password: password)
    }

    /// The decrypted inner export document.
    static func decrypt(_ doc: PyJSON, password: String) throws -> PyJSON {
        guard doc["passwordProtected"]?.truthy ?? false else { throw ImportError.malformed(BitwardenJSON.accountRestrictedMessage) }
        var (encKey, macKey) = try keys(password: password, doc)
        defer { KDBX.wipe(&encKey); KDBX.wipe(&macKey) }
        if let check = doc["encKeyValidation_DO_NOT_EDIT"] { _ = try open(check, encKey, macKey) }
        let raw = try open(doc["data"] ?? .null, encKey, macKey)
        guard let text = String(bytes: raw, encoding: .utf8), let inner = try? PyJSON.parse(text) else {
            throw ImportError.malformed("Decrypted export is not valid JSON")
        }
        guard inner.isObject else { throw ImportError.malformed("Decrypted export is not a Bitwarden document") }
        return inner
    }

    /// Python `int(value or default)` for the KDF numbers.
    private static func number(_ v: PyJSON?, _ fallback: Int) throws -> Int {
        guard let v, v.truthy else { return fallback }
        switch v {
        case .int(let i): return Int(clamping: i)
        case .bool(let b): return b ? 1 : 0
        case .float(let f) where f.isFinite && abs(f) < 1e18: return Int(f)
        case .string(let s): if let i = Py.int(s) { return i }
        default: break
        }
        throw ImportError.malformed("Encrypted export KDF parameters are malformed")
    }

    /// Windows `derive_export_keys`: (encryption key, MAC key).
    static func keys(password: String, _ doc: PyJSON) throws -> ([UInt8], [UInt8]) {
        guard case .string(let salt)? = doc["salt"], !salt.isEmpty else {
            throw ImportError.malformed("Encrypted export is missing its salt")
        }
        let kdfType = doc["kdfType"] ?? .int(0)
        let iterations = try number(doc["kdfIterations"], 0)
        let secret = Array(password.utf8)
        var master: [UInt8]
        if kdfType.equals(0) {
            guard (1...maxPBKDF2Iterations).contains(iterations) else {
                throw ImportError.malformed("Encrypted export iteration count is outside the supported range")
            }
            master = try PBKDF2.sha256(password: secret, salt: Array(salt.utf8), iterations: iterations, length: 32)
        } else if kdfType.equals(1) {
            let memory = try number(doc["kdfMemory"], 64), parallelism = try number(doc["kdfParallelism"], 4)
            guard (1...maxArgon2Iterations).contains(iterations), (8...maxArgon2MemoryMiB).contains(memory),
                  (1...maxArgon2Parallelism).contains(parallelism) else {
                throw ImportError.malformed("Encrypted export Argon2 parameters are outside the supported range")
            }
            master = try Argon2id.derive(password: secret, salt: Array(SHA256.hash(data: Array(salt.utf8))),
                                         memoryKiB: UInt32(memory * 1024), iterations: UInt32(iterations),
                                         parallelism: UInt32(parallelism), length: 32)
        } else {
            throw ImportError.malformed("Unsupported Bitwarden KDF type")
        }
        let key = SymmetricKey(data: master)
        KDBX.wipe(&master)  // best effort; the caller drops the expanded keys after decrypting
        func expand(_ info: String) -> [UInt8] {
            Array(HMAC<SHA256>.authenticationCode(for: Array(info.utf8) + [1], using: key))
        }
        return (expand("enc"), expand("mac"))
    }

    /// Windows `decrypt_enc_string`.
    static func open(_ value: PyJSON, _ encKey: [UInt8], _ macKey: [UInt8]) throws -> [UInt8] {
        guard case .string(let s) = value, s.hasPrefix("2.") else {
            throw ImportError.malformed("Unsupported Bitwarden encryption string type")
        }
        let parts = s.dropFirst(2).split(separator: "|", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw ImportError.malformed("Bitwarden encryption string is malformed") }
        var decoded: [[UInt8]] = []
        for part in parts {
            guard let d = Data(base64Encoded: String(part)) else {
                throw ImportError.malformed("Bitwarden encryption string is not valid Base64")
            }
            decoded.append([UInt8](d))
        }
        let (iv, ciphertext, mac) = (decoded[0], decoded[1], decoded[2])
        guard iv.count == 16, mac.count == 32, !ciphertext.isEmpty, ciphertext.count % 16 == 0 else {
            throw ImportError.malformed("Bitwarden encryption string has unexpected lengths")
        }
        guard HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: iv + ciphertext, using: SymmetricKey(data: macKey)) else {
            throw ImportError.wrongPassword
        }
        do { return try AESCBC.decrypt(key: encKey, iv: iv, data: ciphertext) } catch {
            throw ImportError.malformed("Encrypted export padding is invalid")
        }
    }
}
