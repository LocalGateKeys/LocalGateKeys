import Foundation

/// A package cannot be made or opened; `reason` is one of the spec's codes (`bad-code`, `malformed`,
/// `unsupported`, `already-opened`, `wrong-code`, `expired`, `not-shareable`, `too-large`).
public struct ShareError: Error, Equatable, Sendable {
    public let reason: String
    public let message: String
    public init(_ reason: String, _ message: String) { self.reason = reason; self.message = message }

    static var damaged: ShareError { ShareError("malformed", String(localized: "The shared item is damaged.", bundle: .module)) }
    static var notAShare: ShareError { ShareError("malformed", String(localized: "This is not a shared LocalGateKeys item.", bundle: .module)) }
}

/// Secure local sharing, `.lgkshare` v1 (`docs/formats/LGKSHARE_V1.md`, desktop `share.py`): one item sealed
/// under a 6-word one-time code. Pinned byte for byte by `tests/vectors/share/v1.json`.
public enum Share {
    public static let format = "localgatekeys-share"
    public static let version: Int64 = 1
    public static let codeWords = 6
    public static let lifetime: Int64 = 24 * 3600
    public static let clockSkew: Int64 = 300
    public static let maxPackage = 256 * 1024
    public static let qrLimit = 2048
    public static let senderLimit = 64
    public static let fileExtension = "lgkshare"
    public static let codeQRPrefix = "lgkshare-code:"
    static let timeCost: Int64 = 2, memoryKiB: Int64 = 19456, parallelism: Int64 = 1
    static let forbidden = ["attachments", "attachment_ids", "passkeys", "passkey"]
    static let localOnly: Set<String> = ["policy", "password_history", "collection_ids", "favorite", "usage", "last_used_at"]
    static let headerKeys: Set<String> = ["format", "version", "id", "sender", "kdf", "nonce", "ciphertext"]

    /// What `open` returns.
    public struct Opened: Equatable, Sendable {
        public let id: String
        public let sender: String
        public let createdAt: Int64
        public let expiresAt: Int64
        public let item: [String: JSONValue]
    }

    /// The clear part, for the pop-up before the code is typed.
    public struct Header: Equatable, Sendable {
        public let id: String
        public let sender: String
        let envelope: [String: JSONValue]
    }

    // MARK: code

    static func words() throws -> [String] {
        do { return try BIP39.words() } catch { throw ShareError("bad-code", String(localized: "The word list is damaged.", bundle: .module)) }
    }

    /// Six words from the BIP39 English list (66 bits), shown on the sender's screen only.
    public static func generateCode(random: any RandomSource = SystemRandomSource()) throws -> String {
        let list = try words()
        guard list.count == 2048 else { throw ShareError("bad-code", String(localized: "The word list is damaged.", bundle: .module)) }
        let bytes = random.bytes(count: codeWords * 2)
        return (0..<codeWords).map { i in
            list[(Int(bytes[2 * i]) << 8 | Int(bytes[2 * i + 1])) & 0x7FF]
        }.joined(separator: " ")
    }

    static func isSeparator(_ c: Character) -> Bool { c.isWhitespace || c == "·" || c == "." || c == "," || c == "-" }

    /// Lower case, split on spaces, `·`, `.`, `,` or `-`; exactly six list words joined with one space.
    public static func normalizeCode(_ text: String) throws -> String {
        let tokens = text.lowercased().split(whereSeparator: isSeparator).map(String.init)
        let allowed = Set(try words())
        guard tokens.count == codeWords, tokens.allSatisfy({ allowed.contains($0) }) else {
            throw ShareError("bad-code", String(localized: "Enter the six words of the code.", bundle: .module))
        }
        return tokens.joined(separator: " ")
    }

    /// The second QR (the key), when the code is not read out.
    public static func codeQRText(_ code: String) throws -> String {
        codeQRPrefix + (try normalizeCode(code)).replacingOccurrences(of: " ", with: "-")
    }

    public static func code(fromQRText text: String) throws -> String {
        guard text.hasPrefix(codeQRPrefix) else {
            throw ShareError("bad-code", String(localized: "This QR code is not a LocalGateKeys share code.", bundle: .module))
        }
        return try normalizeCode(String(text.dropFirst(codeQRPrefix.count)))
    }

    /// Small packages may travel as a QR code; larger ones go as a file.
    public static func fitsQR(_ data: [UInt8]) -> Bool { data.count <= qrLimit }

    // MARK: seal

    static func key(_ code: String, salt: [UInt8]) throws -> [UInt8] {
        let normal = try normalizeCode(code)
        return try Argon2id.derive(password: Array(normal.utf8), salt: salt, memoryKiB: UInt32(memoryKiB),
                                   iterations: UInt32(timeCost), parallelism: UInt32(parallelism), length: 32)
    }

    static func truthy(_ v: JSONValue?) -> Bool {
        guard let v else { return false }
        switch v {
        case .null: return false
        case .bool(let b): return b
        case .int(let i): return i != 0
        case .float(let f): return f != 0
        case .string(let s): return !s.isEmpty
        case .array(let a): return !a.isEmpty
        case .object(let o): return !o.isEmpty
        }
    }

    static func cleanItem(_ item: [String: JSONValue]) throws -> [String: JSONValue] {
        guard case .string(let kind)? = item["kind"], !kind.isEmpty else {
            throw ShareError("malformed", String(localized: "Only a saved item can be shared.", bundle: .module))
        }
        if kind == "passkey" || forbidden.contains(where: { truthy(item[$0]) }) {
            throw ShareError("not-shareable", String(localized: "Passkeys and attachments cannot be shared.", bundle: .module))
        }
        return item.filter { !localOnly.contains($0.key) && !forbidden.contains($0.key) }
    }

    /// Whether `item` may be shared at all (the Share button is hidden otherwise).
    public static func canShare(_ item: [String: JSONValue]) -> Bool { (try? cleanItem(item)) != nil }

    static func kdfObject(salt: [UInt8]) -> JSONValue {
        .object(["name": .string("argon2id"), "time_cost": .int(timeCost), "memory_cost_kib": .int(memoryKiB),
                 "parallelism": .int(parallelism), "salt": .string(Base64.encode(salt))])
    }

    static func aad(_ header: [String: JSONValue]) throws -> [UInt8] {
        try CanonicalJSON.encode(.object(header.filter { $0.key != "ciphertext" }), dialect: .utf8)
    }

    static func randomUUID(_ random: any RandomSource) -> String {
        var b = random.bytes(count: 16)
        b[6] = (b[6] & 0x0F) | 0x40
        b[8] = (b[8] & 0x3F) | 0x80
        let c = Array(b.map { String(format: "%02x", $0) }.joined())
        return String(c[0..<8]) + "-" + String(c[8..<12]) + "-" + String(c[12..<16]) + "-"
            + String(c[16..<20]) + "-" + String(c[20..<32])
    }

    /// The `.lgkshare` bytes for one item. `packageID`, `salt` and `nonce` are for vectors only.
    public static func seal(item: [String: JSONValue], code: String, sender: String, now: Int64,
                            random: any RandomSource = SystemRandomSource(),
                            packageID: String? = nil, salt: [UInt8]? = nil, nonce: [UInt8]? = nil) throws -> [UInt8] {
        let trimmedScalars = sender.trimmingCharacters(in: .whitespacesAndNewlines).unicodeScalars.prefix(senderLimit)
        var trimmed = ""
        trimmed.unicodeScalars.append(contentsOf: trimmedScalars)
        let name = trimmed.isEmpty ? "A LocalGateKeys device" : trimmed
        let salt = salt ?? random.bytes(count: 16)
        let nonce = nonce ?? random.bytes(count: 12)
        var header: [String: JSONValue] = [
            "format": .string(format), "version": .int(version), "id": .string(packageID ?? randomUUID(random)),
            "sender": .string(name), "kdf": kdfObject(salt: salt), "nonce": .string(Base64.encode(nonce)),
        ]
        let payload: JSONValue = .object(["version": .int(version), "created_at": .int(now),
                                          "expires_at": .int(now + lifetime), "item": .object(try cleanItem(item))])
        var key = try key(code, salt: salt)
        defer { for i in key.indices { key[i] = 0 } }
        let ciphertext = try CryptoBox.sealGCM(key: key, nonce: nonce,
                                               plaintext: try CanonicalJSON.encode(payload, dialect: .utf8),
                                               aad: try aad(header))
        header["ciphertext"] = .string(Base64.encode(ciphertext))
        let data = try CanonicalJSON.encode(.object(header), dialect: .utf8)
        guard data.count <= maxPackage else { throw ShareError("too-large", String(localized: "This item is too large to share.", bundle: .module)) }
        return data
    }

    // MARK: open

    static func b64(_ v: JSONValue?, size: Int? = nil) throws -> [UInt8] {
        guard case .string(let s)? = v, let out = try? Base64.decodeStrict(s) else { throw ShareError.damaged }
        if let size, out.count != size { throw ShareError.damaged }
        return out
    }

    /// The clear part: `id` and `sender`, checked as in the spec's step 1.
    public static func readHeader(_ data: [UInt8]) throws -> Header {
        guard data.count <= maxPackage, let value = try? CanonicalJSON.parse(data),
              case .object(let envelope) = value, envelope["format"] == .string(format) else {
            throw ShareError.notAShare
        }
        guard envelope["version"] == .int(version) else {
            throw ShareError("unsupported", String(localized: "This item was shared by a newer LocalGateKeys. Update the app.", bundle: .module))
        }
        guard Set(envelope.keys) == headerKeys, case .object(let kdf)? = envelope["kdf"],
              Set(kdf.keys) == ["name", "time_cost", "memory_cost_kib", "parallelism", "salt"],
              kdf["name"] == .string("argon2id"), kdf["time_cost"] == .int(timeCost),
              kdf["memory_cost_kib"] == .int(memoryKiB), kdf["parallelism"] == .int(parallelism) else {
            throw ShareError.damaged
        }
        guard case .string(let id)? = envelope["id"], UUID(uuidString: id)?.uuidString.lowercased() == id,
              case .string(let sender)? = envelope["sender"], sender.unicodeScalars.count <= senderLimit else {
            throw ShareError.damaged
        }
        _ = try b64(kdf["salt"], size: 16)
        _ = try b64(envelope["nonce"], size: 12)
        return Header(id: id, sender: sender, envelope: envelope)
    }

    /// Decrypts and checks one package. `opened` holds the package ids this device already opened.
    public static func open(_ data: [UInt8], code: String, now: Int64, opened: Set<String> = []) throws -> Opened {
        let header = try readHeader(data)
        let envelope = header.envelope
        if opened.contains(header.id) {
            throw ShareError("already-opened", String(localized: "This shared item was already opened on this device.", bundle: .module))
        }
        guard case .object(let kdf)? = envelope["kdf"] else { throw ShareError.damaged }
        var key = try key(code, salt: try b64(kdf["salt"], size: 16))
        defer { for i in key.indices { key[i] = 0 } }
        let nonce = try b64(envelope["nonce"], size: 12)
        let sealed = try b64(envelope["ciphertext"])
        let plain: [UInt8]
        do {
            plain = try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: sealed, aad: try aad(envelope))
        } catch {
            throw ShareError("wrong-code", String(localized: "That code does not open this item. Check the six words.", bundle: .module))
        }
        guard let value = try? CanonicalJSON.parse(plain), case .object(let payload) = value,
              payload["version"] == .int(version), Set(payload.keys) == ["version", "created_at", "expires_at", "item"],
              case .int(let created)? = payload["created_at"], case .int(let expires)? = payload["expires_at"],
              expires == created + lifetime else {
            throw ShareError.damaged
        }
        if created > now + clockSkew {
            throw ShareError("malformed", String(localized: "The shared item has a date in the future. Check this device's clock.", bundle: .module))
        }
        if now >= expires { throw ShareError("expired", String(localized: "This shared item expired. Ask for it to be shared again.", bundle: .module)) }
        guard case .object(let item)? = payload["item"], let clean = try? cleanItem(item), clean == item else {
            throw ShareError("not-shareable", String(localized: "This shared item holds content that cannot be shared.", bundle: .module))
        }
        return Opened(id: header.id, sender: header.sender, createdAt: created, expiresAt: expires, item: item)
    }
}
