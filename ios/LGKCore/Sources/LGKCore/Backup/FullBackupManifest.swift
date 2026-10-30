import Foundation

/// A refused or failed full backup, with the message Windows (`backup.py`) gives for the same case. Messages never
/// carry passwords, keys, names or contents.
public enum FullBackupError: Error, Equatable, Sendable {
    case tooLarge, unreadable, truncated, unsafeMember, tooManyMembers, compressedOrEncrypted, memberTooLarge
    case unsupportedFormat, unsupportedEncryption, passwordLength, wrongPasswordOrModified, membersMismatch
    case memberAuthentication, cancelled
    /// Any other fixed Windows message (manifest, sidecar and settings checks).
    case invalid(String)

    public var message: String {
        switch self {
        case .tooLarge: return String(localized: "Full backup is too large", bundle: .module)
        case .unreadable: return String(localized: "Could not read full backup", bundle: .module)
        case .truncated: return String(localized: "Full backup is truncated or unreadable", bundle: .module)
        case .unsafeMember: return String(localized: "Full backup contains an unsafe archive member", bundle: .module)
        case .tooManyMembers: return String(localized: "Full backup has too many archive members", bundle: .module)
        case .compressedOrEncrypted: return String(localized: "Full backup compression or ZIP encryption is unsupported", bundle: .module)
        case .memberTooLarge: return String(localized: "Full backup member is too large", bundle: .module)
        case .unsupportedFormat: return String(localized: "Unsupported full backup format", bundle: .module)
        case .unsupportedEncryption: return String(localized: "Unsupported backup encryption parameters", bundle: .module)
        case .passwordLength: return String(localized: "Backup password must contain at least 12 characters", bundle: .module)
        case .wrongPasswordOrModified: return String(localized: "Wrong backup password or modified full backup", bundle: .module)
        case .membersMismatch: return String(localized: "Full backup members do not match its manifest", bundle: .module)
        case .memberAuthentication: return String(localized: "Full backup member authentication failed", bundle: .module)
        case .cancelled: return String(localized: "Backup operation was cancelled", bundle: .module)
        case .invalid(let m): return m
        }
    }
}

/// One manifest row (`backup._full_manifest_entries`), already validated.
public struct FullBackupEntry: Equatable, Sendable {
    public enum Kind: String, Sendable { case vault, settings, generation, attachment }
    public let kind: Kind
    public let target: String
    public let member: String
    public let size: Int
    /// Lowercase hex.
    public let sha256: String
    /// Canonical lowercase UUID, attachments only.
    public let attachmentID: String?
    public let sidecarSize: Int?
}

enum FullBackupManifest {
    static let attachmentMagic: [UInt8] = Array("LGKATT1".utf8) + [0]
    static let maxAttachmentSize = 25 * 1024 * 1024
    static let allowedFields: Set<String> = ["kind", "target", "size", "sha256", "member", "attachment_id", "sidecar_size"]

    static func member(_ index: Int) -> String {
        let digits = String(index)
        return "data/" + String(repeating: "0", count: max(0, 8 - digits.count)) + digits + ".bin"
    }

    /// Python `str(uuid.UUID(text))`: `urn:`/`uuid:` prefixes, braces and hyphens dropped, 32 hex digits, lowercase.
    static func canonicalUUID(_ text: String) -> String? {
        var hex = text.replacingOccurrences(of: "urn:", with: "").replacingOccurrences(of: "uuid:", with: "")
        while hex.hasPrefix("{") { hex.removeFirst() }
        while hex.hasSuffix("}") { hex.removeLast() }
        hex = hex.replacingOccurrences(of: "-", with: "").lowercased()
        let digits = Array(hex.unicodeScalars)
        guard digits.count == 32, digits.allSatisfy({ ("0"..."9").contains($0) || ("a"..."f").contains($0) }) else { return nil }
        let s = String(hex)
        func part(_ a: Int, _ b: Int) -> Substring { s[s.index(s.startIndex, offsetBy: a)..<s.index(s.startIndex, offsetBy: b)] }
        return "\(part(0, 8))-\(part(8, 12))-\(part(12, 16))-\(part(16, 20))-\(part(20, 32))"
    }

    static func isHexDigest(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        return u.count == 64 && u.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) || ("A"..."F").contains($0) }
    }

    static func object(_ data: [UInt8], label: String) throws -> [String: JSONValue] {
        let value: JSONValue
        do { value = try CanonicalJSON.parse(data) } catch { throw FullBackupError.invalid("\(label) is not valid JSON") }
        guard case .object(let o) = value else { throw FullBackupError.invalid("\(label) must be a JSON object") }
        return o
    }

    static func int(_ v: JSONValue?) -> Int64? { if case .int(let n)? = v { return n }; return nil }
    static func string(_ v: JSONValue?) -> String? { if case .string(let s)? = v { return s }; return nil }

    /// Python `str(value)` for the attachment id field (a non-string can never parse as a UUID).
    static func uuidField(_ v: JSONValue?) -> String? { string(v).flatMap(canonicalUUID) }

    static func validProfileName(_ name: String) -> Bool {
        (1...256).contains(name.unicodeScalars.count) && !name.unicodeScalars.contains("\u{0}")
    }

    /// `_full_manifest_entries`: the decrypted manifest's rows, in member order.
    static func entries(_ manifest: [String: JSONValue], entryCount: Int64) throws -> [FullBackupEntry] {
        func bad(_ m: String) -> FullBackupError { .invalid(m) }
        guard int(manifest["version"]) == FullBackupV2.version, case .array(let rows)? = manifest["entries"] else {
            throw bad("Full backup manifest is malformed")
        }
        guard Int64(rows.count) == entryCount, (2...FullBackupV2.maxEntries).contains(rows.count) else {
            throw bad("Full backup entry count is invalid")
        }
        guard let name = string(manifest["profile_name"]), validProfileName(name) else {
            throw bad("Full backup profile name is malformed")
        }
        var result: [FullBackupEntry] = []
        var targets = Set<String>()
        for (index, row) in rows.enumerated() {
            guard case .object(let raw) = row else { throw bad("Full backup manifest entry is malformed") }
            guard Set(raw.keys).isSubset(of: allowedFields) else { throw bad("Full backup manifest contains unsupported fields") }
            guard let kindText = string(raw["kind"]), let kind = FullBackupEntry.Kind(rawValue: kindText),
                  let target = string(raw["target"]) else { throw bad("Full backup manifest entry type is invalid") }
            let member = member(index)
            guard string(raw["member"]) == member else { throw bad("Full backup data member name is invalid") }
            var attachmentID: String?
            switch kind {
            case .vault: guard target == "vault.json" else { throw bad("Full backup vault target is invalid") }
            case .settings: guard target == "settings.json" else { throw bad("Full backup settings target is invalid") }
            case .generation: guard target == "generation.json" else { throw bad("Full backup generation target is invalid") }
            case .attachment:
                guard let id = uuidField(raw["attachment_id"]) else { throw bad("Full backup attachment ID is invalid") }
                guard target == "\(id).blob", let s = raw["sidecar_size"], s != .null else {
                    throw bad("Full backup attachment target is invalid")
                }
                attachmentID = id
            }
            guard !targets.contains(target) else { throw bad("Full backup contains duplicate targets") }
            guard let size = int(raw["size"]), (0...Int64(FullBackupV2.maxMemberBytes)).contains(size) else {
                throw bad("Full backup member size is invalid")
            }
            guard let digest = string(raw["sha256"]), isHexDigest(digest) else { throw bad("Full backup member digest is invalid") }
            var sidecarSize: Int?
            if kind == .attachment {
                guard let s = int(raw["sidecar_size"]), s >= 0, s <= Int64(Int.max) else {
                    throw bad("Full backup sidecar size is invalid")
                }
                sidecarSize = Int(s)
            }
            targets.insert(target)
            result.append(FullBackupEntry(kind: kind, target: target, member: member, size: Int(size),
                                          sha256: digest.lowercased(), attachmentID: attachmentID, sidecarSize: sidecarSize))
        }
        let count = { (k: FullBackupEntry.Kind) in result.filter { $0.kind == k }.count }
        guard count(.vault) > 0, count(.settings) > 0 else { throw bad("Full backup is missing vault or settings") }
        guard count(.vault) == 1, count(.settings) == 1 else { throw bad("Full backup contains duplicate vault or settings entries") }
        guard count(.generation) <= 1 else { throw bad("Full backup contains duplicate generation metadata") }
        return result
    }

    /// `_full_validate_sidecar_header`: the unauthenticated sidecar framing; returns the plaintext size it declares.
    static func sidecarSize(_ sidecar: Data, expectedID: String) throws -> Int {
        let data = ByteView(sidecar)
        func bad(_ m: String) -> FullBackupError { .invalid(m) }
        guard data.count <= maxAttachmentSize + 64 * 1024 else { throw bad("Attachment sidecar is too large") }
        let m = attachmentMagic.count
        guard data.count >= m + 4, data[0..<m] == attachmentMagic else {
            throw bad("Attachment sidecar has an invalid header")
        }
        let headerLength = Int(data[m]) << 24 | Int(data[m + 1]) << 16 | Int(data[m + 2]) << 8 | Int(data[m + 3])
        guard (1...8 * 1024).contains(headerLength) else { throw bad("Attachment sidecar header is malformed") }
        let start = m + 4, end = start + headerLength
        guard end + 12 <= data.count else { throw bad("Attachment sidecar is truncated") }
        let header = try object(data[start..<end], label: "Attachment sidecar header")
        let version = int(header["version"])
        guard string(header["format"]) == "localgatekeys-attachment", version == 1 || version == 2 else {
            throw bad("Unsupported attachment sidecar format")
        }
        guard let id = uuidField(header["id"]) else { throw bad("Attachment sidecar ID is malformed") }
        guard id == expectedID else { throw bad("Attachment sidecar ID does not match its manifest") }
        let ciphertextLength = data.count - (end + 12)
        guard ciphertextLength >= 16, ciphertextLength - 16 <= maxAttachmentSize else {
            throw bad("Attachment sidecar length is out of bounds")
        }
        if version == 1 {
            guard let size = int(header["size"]), (0...Int64(maxAttachmentSize)).contains(size) else {
                throw bad("Attachment sidecar size is malformed")
            }
            guard let digest = string(header["sha256"]), isHexDigest(digest) else { throw bad("Attachment sidecar digest is malformed") }
            guard ciphertextLength == Int(size) + 16 else { throw bad("Attachment sidecar length does not match its header") }
            return Int(size)
        }
        guard Set(header.keys) == ["format", "version", "id", "store_id"] else { throw bad("Attachment sidecar header is malformed") }
        return ciphertextLength - 16
    }

    /// `_full_validate_generation`.
    static func validateGeneration(_ data: [UInt8]) throws {
        let o = try object(data, label: "Vault generation metadata")
        guard int(o["version"]) == 1, let g = int(o["generation"]), g >= 0 else {
            throw FullBackupError.invalid("Vault generation metadata is malformed")
        }
    }
}
