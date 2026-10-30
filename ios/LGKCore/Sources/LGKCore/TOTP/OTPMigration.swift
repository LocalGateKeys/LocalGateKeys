import Foundation

/// One authenticator account from a 2FA QR code: the issuer and account name it was shown with, and its key.
/// `uri` is an `otpauth://totp` link that `TOTP.parseOtpauthURI` reads back to `config`.
public struct OTPAccount: Sendable, Equatable {
    public var issuer: String
    public var account: String
    public var config: TOTPConfig

    public init(issuer: String, account: String, config: TOTPConfig) {
        self.issuer = issuer; self.account = account; self.config = config
    }

    /// The issuer and account of an `otpauth://totp` link: the `issuer` parameter wins over a label's
    /// "Issuer:" prefix (Key Uri Format). Throws `TOTPError` like `TOTP.parseOtpauthURI`.
    public init(otpauth uri: String) throws {
        config = try TOTP.parseOtpauthURI(uri)
        let trimmed = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        let noFragment = trimmed.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
        let afterScheme = noFragment.range(of: "://").map { String(noFragment[$0.upperBound...]) } ?? ""
        let parts = afterScheme.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        let pathPart = parts.first.map(String.init) ?? ""
        let rawLabel = pathPart.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false).dropFirst().first.map(String.init) ?? ""
        let label = TOTP.pyUnquote(rawLabel)
        var issuerParam = ""
        if parts.count == 2 {
            for pair in parts[1].split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                if kv.count == 2, TOTP.pyUnquote(String(kv[0])) == "issuer" {
                    issuerParam = TOTP.pyUnquote(kv[1].replacingOccurrences(of: "+", with: " "))
                }
            }
        }
        var prefix = "", name = label
        if let colon = label.firstIndex(of: ":") {
            prefix = String(label[..<colon]).trimmingCharacters(in: .whitespaces)
            name = String(label[label.index(after: colon)...])
        }
        issuer = issuerParam.isEmpty ? prefix : issuerParam
        account = name.trimmingCharacters(in: .whitespaces)
    }

    /// `otpauth://totp/<issuer>:<account>?secret=…&issuer=…&algorithm=…&digits=…&period=…`.
    public var uri: String {
        let label = issuer.isEmpty ? account : issuer + ":" + account
        var s = "otpauth://totp/" + Self.escape(label) + "?secret=" + config.secret
        if !issuer.isEmpty { s += "&issuer=" + Self.escape(issuer) }
        s += "&algorithm=\(config.algorithm)&digits=\(config.digits)&period=\(config.period)"
        return s
    }

    static func escape(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics.intersection(CharacterSet(charactersIn: Unicode.Scalar(0)...Unicode.Scalar(127)))
        allowed.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
    }
}

/// An export account that could not be used, and why (never its key).
public struct OTPSkippedAccount: Sendable, Equatable {
    public var issuer: String
    public var account: String
    public var reason: String
}

/// One QR code of a Google Authenticator export. A large export is split over `batchSize` codes.
public struct OTPMigrationBatch: Sendable, Equatable {
    public var accounts: [OTPAccount]
    public var skipped: [OTPSkippedAccount]
    public var batchIndex: Int
    public var batchSize: Int
}

/// Fixed wording that never quotes the link or its data.
public enum OTPMigrationError: Error, Equatable, Sendable {
    case tooLong, notMigrationLink, noData, invalidBase64, malformed, tooManyAccounts, noAccounts

    public var message: String {
        switch self {
        case .tooLong: String(localized: "Migration link is too long", bundle: .module)
        case .notMigrationLink: String(localized: "Expected an otpauth-migration://offline link", bundle: .module)
        case .noData: String(localized: "Migration link has no data", bundle: .module)
        case .invalidBase64: String(localized: "Migration data is not valid Base64", bundle: .module)
        case .malformed: String(localized: "Malformed migration data", bundle: .module)
        case .tooManyAccounts: String(localized: "Migration link contains too many accounts", bundle: .module)
        case .noAccounts: String(localized: "Migration link contains no accounts", bundle: .module)
        }
    }
}

/// Google Authenticator "Transfer accounts" export, `otpauth-migration://offline?data=<base64 MigrationPayload>`,
/// decoded by hand like `totp.py` `parse_migration_uri` (no protobuf dependency).
public enum OTPMigration {
    public static let maxBatches = 256
    public static let maxAccounts = 256
    static let maxLength = 64 * 1024
    static let algorithms = [0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512"]
    static let digitCounts = [0: 6, 1: 6, 2: 8]

    enum Value { case int(UInt64), bytes([UInt8]), other }

    static func varint(_ d: [UInt8], _ pos: inout Int) throws -> UInt64 {
        var result: UInt64 = 0, shift: UInt64 = 0
        while true {
            guard pos < d.count, shift <= 63 else { throw OTPMigrationError.malformed }
            let b = d[pos]; pos += 1
            result |= UInt64(b & 0x7F) << shift
            if b & 0x80 == 0 { return result }
            shift += 7
        }
    }

    static func fields(_ d: [UInt8]) throws -> [(Int, Value)] {
        var out: [(Int, Value)] = []
        var pos = 0
        while pos < d.count {
            let key = try varint(d, &pos)
            let number = Int(truncatingIfNeeded: key >> 3)
            switch key & 7 {
            case 0: out.append((number, .int(try varint(d, &pos))))
            case 2:
                let n = try varint(d, &pos)
                guard n <= UInt64(d.count - pos) else { throw OTPMigrationError.malformed }
                out.append((number, .bytes(Array(d[pos..<pos + Int(n)])))); pos += Int(n)
            case 1: pos += 8; out.append((number, .other))
            case 5: pos += 4; out.append((number, .other))
            default: throw OTPMigrationError.malformed
            }
            guard pos <= d.count else { throw OTPMigrationError.malformed }
        }
        return out
    }

    static func base32(_ bytes: [UInt8]) -> String {
        let alpha = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var out = "", acc = 0, bits = 0
        for b in bytes {
            acc = (acc << 8) | Int(b); bits += 8
            while bits >= 5 { bits -= 5; out.append(alpha[(acc >> bits) & 31]) }
            acc &= (1 << bits) - 1
        }
        if bits > 0 { out.append(alpha[(acc << (5 - bits)) & 31]) }
        return out
    }

    public static func parse(_ uri: String) throws -> OTPMigrationBatch {
        guard uri.unicodeScalars.count <= maxLength else { throw OTPMigrationError.tooLong }
        let text = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let sep = text.range(of: "://"), text[..<sep.lowerBound] == "otpauth-migration" else {
            throw OTPMigrationError.notMigrationLink
        }
        let rest = text[sep.upperBound...]
        let hostEnd = rest.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) ?? rest.endIndex
        guard rest[..<hostEnd].lowercased() == "offline" else { throw OTPMigrationError.notMigrationLink }
        var query = ""
        if let q = rest.firstIndex(of: "?") {
            query = String(rest[rest.index(after: q)...])
            if let h = query.firstIndex(of: "#") { query = String(query[..<h]) }
        }
        var data = ""
        for (i, pair) in query.split(separator: "&").enumerated() {
            guard i < 64 else { throw OTPMigrationError.notMigrationLink }
            let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            if kv.count == 2, TOTP.pyUnquote(String(kv[0])) == "data", data.isEmpty {
                data = TOTP.pyUnquote(kv[1].replacingOccurrences(of: "+", with: " "))
            }
        }
        guard !data.isEmpty else { throw OTPMigrationError.noData }
        // parse_qs turns an unescaped "+" into a space; QR readers vary.
        data = data.replacingOccurrences(of: " ", with: "+").filter { !$0.isWhitespace }
        data = data.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        data += String(repeating: "=", count: (4 - data.count % 4) % 4)
        guard let raw = Data(base64Encoded: data) else { throw OTPMigrationError.invalidBase64 }

        var accounts: [OTPAccount] = []
        var skipped: [OTPSkippedAccount] = []
        var batchIndex: UInt64 = 0, batchSize: UInt64 = 1
        for (number, value) in try fields(Array(raw)) {
            switch (number, value) {
            case (2, .int(let n)): batchSize = n
            case (3, .int(let n)): batchIndex = n
            case (1, .bytes(let entry)):
                var secret: [UInt8] = [], name = "", issuer = ""
                var algorithm: UInt64 = 0, digits: UInt64 = 0, type: UInt64 = 0
                var wellFormed = true
                for (sub, v) in try fields(entry) {
                    switch (sub, v) {
                    case (1, .bytes(let b)): secret = b
                    case (2, .bytes(let b)): name = String(decoding: b, as: UTF8.self)
                    case (3, .bytes(let b)): issuer = String(decoding: b, as: UTF8.self)
                    case (4, .int(let n)): algorithm = n
                    case (5, .int(let n)): digits = n
                    case (6, .int(let n)): type = n
                    case (4, _), (5, _), (6, _): wellFormed = false
                    default: break
                    }
                }
                if !issuer.isEmpty, name.hasPrefix(issuer + ":") { name = String(name.dropFirst(issuer.count + 1)) }
                guard accounts.count + skipped.count < maxAccounts else { throw OTPMigrationError.tooManyAccounts }
                func skip(_ reason: String) { skipped.append(OTPSkippedAccount(issuer: issuer, account: name, reason: reason)) }
                guard wellFormed else { skip("Malformed account entry"); continue }
                guard type == 0 || type == 2 else { skip("Counter-based (HOTP) codes are not supported"); continue }
                guard let alg = algorithms[Int(truncatingIfNeeded: algorithm)], algorithm <= 3,
                      let dig = digitCounts[Int(truncatingIfNeeded: digits)], digits <= 2 else {
                    skip("Unsupported algorithm or digit count"); continue
                }
                guard secret.count <= TOTP.maxSecretBytes else { skip("TOTP secret is too long"); continue }
                let normal: String
                do { normal = try TOTP.normalizeSecret(base32(secret)) } catch let e as TOTPError {
                    skip(TOTP.message(for: e)); continue
                }
                accounts.append(OTPAccount(issuer: issuer, account: name,
                                           config: TOTPConfig(secret: normal, algorithm: alg, digits: dig, period: 30)))
            default: continue
            }
        }
        if accounts.isEmpty && skipped.isEmpty { throw OTPMigrationError.noAccounts }
        guard (1...UInt64(maxBatches)).contains(batchSize), batchIndex < batchSize else { throw OTPMigrationError.malformed }
        return OTPMigrationBatch(accounts: accounts, skipped: skipped, batchIndex: Int(batchIndex), batchSize: Int(batchSize))
    }

    #if DEBUG
    /// Test seam: an export entry as Google Authenticator writes it.
    public struct Entry: Sendable {
        public var secret: [UInt8], name: String, issuer: String, algorithm: Int, digits: Int, type: Int
        public init(secret: [UInt8], name: String, issuer: String, algorithm: Int = 1, digits: Int = 1, type: Int = 2) {
            self.secret = secret; self.name = name; self.issuer = issuer
            self.algorithm = algorithm; self.digits = digits; self.type = type
        }
    }

    /// Test seam: builds an export link (`MigrationPayload` with version 1).
    public static func encode(_ entries: [Entry], batchIndex: Int = 0, batchSize: Int = 1) -> String {
        func varint(_ n: Int) -> [UInt8] {
            var v = UInt64(n), out: [UInt8] = []
            repeat { var b = UInt8(v & 0x7F); v >>= 7; if v != 0 { b |= 0x80 }; out.append(b) } while v != 0
            return out
        }
        func bytes(_ field: Int, _ b: [UInt8]) -> [UInt8] { varint(field << 3 | 2) + varint(b.count) + b }
        func int(_ field: Int, _ n: Int) -> [UInt8] { varint(field << 3) + varint(n) }
        var payload: [UInt8] = []
        for e in entries {
            let body = bytes(1, e.secret) + bytes(2, Array(e.name.utf8)) + bytes(3, Array(e.issuer.utf8))
                + int(4, e.algorithm) + int(5, e.digits) + int(6, e.type)
            payload += bytes(1, body)
        }
        payload += int(2, batchSize) + int(3, batchIndex) + int(4, 1) + int(5, 7)
        let b64 = Data(payload).base64EncodedString()
        return "otpauth-migration://offline?data=" + (b64.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "")
    }
    #endif
}
