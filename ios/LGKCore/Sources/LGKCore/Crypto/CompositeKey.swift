import Crypto
import Foundation

/// The two factor kinds, in the only order a factor list may hold them (docs/formats/COMPOSITE_KEY_V1.md §2).
public enum FactorKind: String, CaseIterable, Codable, Sendable {
    case keyFile = "keyfile"
    case yubiKeyHMAC = "yubikey-hmac"
}

/// A key-file / YubiKey factor problem, raised before any Argon2id run and never counted by an unlock throttle.
public enum FactorError: Error, Equatable, Sendable {
    /// The supplied key file or YubiKey is not the one these factors were set up with ("This isn't the key file used
    /// for this vault"). A file that is not a usable key file counts as a mismatch too (Windows `_factor_secret`).
    case mismatch(FactorKind)
    /// The factors are set but these were not supplied (in list order): ask for them, or offer the recovery phrase.
    case required([FactorKind])
}

/// The public description of one factor, stored next to the password wrapper (never a secret). A key file has only
/// `check`; a YubiKey also its `slot` (1 or 2) and its 32-byte `challenge` as 64 lower-case hex digits.
public struct FactorSpec: Equatable, Sendable, Codable {
    public let kind: FactorKind
    public let check: String
    public let slot: Int?
    public let challenge: String?

    public init(kind: FactorKind, check: String, slot: Int? = nil, challenge: String? = nil) throws {
        guard Self.isLowerHex(check, count: 16) else { throw CompositeKeyError("Factor check must be 16 lower-case hex digits") }
        switch kind {
        case .keyFile:
            guard slot == nil, challenge == nil else { throw CompositeKeyError("A key-file factor has no slot or challenge") }
        case .yubiKeyHMAC:
            guard slot == 1 || slot == 2 else { throw CompositeKeyError("YubiKey slot must be 1 or 2") }
            guard let challenge, Self.isLowerHex(challenge, count: 64) else {
                throw CompositeKeyError("YubiKey challenge must be 64 lower-case hex digits")
            }
        }
        self.kind = kind; self.check = check; self.slot = slot; self.challenge = challenge
    }

    public static func keyFile(check: String) throws -> FactorSpec { try FactorSpec(kind: .keyFile, check: check) }

    public static func yubiKey(check: String, slot: Int, challenge: [UInt8]) throws -> FactorSpec {
        guard challenge.count == CompositeKey.challengeSize else { throw CompositeKeyError("YubiKey challenge must be 32 bytes") }
        return try FactorSpec(kind: .yubiKeyHMAC, check: check, slot: slot, challenge: lowerHex(challenge))
    }

    /// The 64 bytes sent to the YubiKey (`yubiKeyHMAC` only; empty for a key file).
    public var paddedChallenge: [UInt8] {
        guard let challenge, let padded = try? CompositeKey.padChallenge(Self.hexBytes(challenge)) else { return [] }
        return padded
    }

    /// Canonical JSON (§2): keys in byte order, no whitespace; every value is ASCII letters, digits or `-`.
    var canonical: String {
        switch kind {
        case .keyFile: return "{\"check\":\"\(check)\",\"kind\":\"\(kind.rawValue)\"}"
        case .yubiKeyHMAC:
            return "{\"challenge\":\"\(challenge ?? "")\",\"check\":\"\(check)\",\"kind\":\"\(kind.rawValue)\",\"slot\":\(slot ?? 0)}"
        }
    }

    /// The stored JSON object (Windows `FactorSpec.to_json`): only the fields this kind has.
    var json: JSONValue {
        var o: [String: JSONValue] = ["kind": .string(kind.rawValue), "check": .string(check)]
        if let slot { o["slot"] = .int(Int64(slot)) }
        if let challenge { o["challenge"] = .string(challenge) }
        return .object(o)
    }

    /// Strict parse of a stored factor object (Windows `FactorSpec.from_json`): any unknown, missing or mistyped field
    /// is refused; `slot` must be an integer (not a boolean or a float).
    init(json value: JSONValue) throws {
        guard case .object(let f) = value else { throw CompositeKeyError("Factor must be an object") }
        guard case .string(let kindText)? = f["kind"], let kind = FactorKind(rawValue: kindText) else {
            throw CompositeKeyError("Unknown factor kind")
        }
        let allowed: Set<String> = kind == .keyFile ? ["kind", "check"] : ["kind", "check", "slot", "challenge"]
        guard Set(f.keys) == allowed else { throw CompositeKeyError("Factor fields are malformed") }
        guard case .string(let check)? = f["check"] else { throw CompositeKeyError("Factor check must be a string") }
        if kind == .keyFile { try self.init(kind: .keyFile, check: check); return }
        guard case .int(let slot)? = f["slot"], slot == 1 || slot == 2 else { throw CompositeKeyError("YubiKey slot must be 1 or 2") }
        guard case .string(let challenge)? = f["challenge"] else { throw CompositeKeyError("YubiKey challenge must be a string") }
        try self.init(kind: kind, check: check, slot: Int(slot), challenge: challenge)
    }

    private enum CodingKeys: String, CodingKey { case kind, check, slot, challenge }

    /// Any key name, so `init(from:)` can see fields that are not ours and refuse them.
    private struct AnyKey: CodingKey {
        let stringValue: String
        init?(stringValue: String) { self.stringValue = stringValue }
        var intValue: Int? { nil }
        init?(intValue: Int) { return nil }
    }

    /// `MasterKeyFile` v2's `factors` entries: the same strict rules as `init(json:)`.
    public init(from decoder: any Decoder) throws {
        let names = Set(try decoder.container(keyedBy: AnyKey.self).allKeys.map(\.stringValue))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(FactorKind.self, forKey: .kind)
        let allowed: Set<String> = kind == .keyFile ? ["kind", "check"] : ["kind", "check", "slot", "challenge"]
        let malformed = DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Factor fields are malformed"))
        guard names == allowed else { throw malformed }
        let check = try c.decode(String.self, forKey: .check)
        let slot = try c.decodeIfPresent(Int.self, forKey: .slot)
        let challenge = try c.decodeIfPresent(String.self, forKey: .challenge)
        guard let spec = try? FactorSpec(kind: kind, check: check, slot: slot, challenge: challenge) else { throw malformed }
        self = spec
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(kind, forKey: .kind)
        try c.encode(check, forKey: .check)
        try c.encodeIfPresent(slot, forKey: .slot)
        try c.encodeIfPresent(challenge, forKey: .challenge)
    }

    static func isLowerHex(_ s: String, count: Int) -> Bool {
        s.utf8.count == count && s.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    /// Hex digits (already checked: lower case, even count) to bytes.
    static func hexBytes(_ s: String) -> [UInt8] {
        let d = Array(s.utf8).map { $0 <= 0x39 ? $0 - 0x30 : $0 - 0x61 + 10 }
        return stride(from: 0, to: d.count - 1, by: 2).map { d[$0] << 4 | d[$0 + 1] }
    }
}

/// A malformed factor list or composite-key input (a programming or file error, not a wrong factor).
public struct CompositeKeyError: Error, Equatable, Sendable {
    public let message: String
    init(_ message: String) { self.message = message }
}

/// What the person supplies for the factors at unlock. `keyFile` is the key file's bytes (`KeyFile.key(from:)` turns
/// them into the secret); `yubiKey` receives the full 64-byte padded challenge (`FactorSpec.paddedChallenge`, never
/// the bare 32 bytes: no YubiKey library may pad) and returns the YubiKey's 20-byte HMAC-SHA1 response. The YubiKey
/// is asked only after every factor is known to be supplied and the key file has passed its check.
public struct FactorSecrets: Sendable {
    public var keyFile: Data?
    public var yubiKey: (@Sendable (Data) async throws -> Data)?

    public init(keyFile: Data? = nil, yubiKey: (@Sendable (Data) async throws -> Data)? = nil) {
        self.keyFile = keyFile; self.yubiKey = yubiKey
    }
}

/// Composite key v1 (docs/formats/COMPOSITE_KEY_V1.md, vectors tests/vectors/composite_key, Windows
/// `src/localvault/composite_key.py`, Android `CompositeKey.kt`): key-file and YubiKey secrets mixed into the
/// Argon2id output,
///
///     HKDF-SHA256(ikm = argon_out || secret_1 [|| secret_2], salt = "localgatekeys|composite|v1",
///                 info = canonical JSON of the factor list, L = 32)
///
/// and the Argon2id output itself when there are no factors, so formats without factors are unchanged.
public enum CompositeKey {
    public static let secretSize = 32
    public static let challengeSize = 32
    public static let paddedChallengeSize = 64
    public static let yubiKeyResponseSize = 20
    static let salt = Array("localgatekeys|composite|v1".utf8)
    static let checkInfo = Array("localgatekeys|factor-check|v1".utf8)

    /// At most one key file, then at most one YubiKey.
    public static func validate(_ specs: [FactorSpec]) throws {
        let kinds = specs.map(\.kind)
        guard kinds == FactorKind.allCases.filter({ kinds.contains($0) }) else {
            throw CompositeKeyError("Factor list must hold at most one key file then at most one YubiKey")
        }
    }

    /// Canonical JSON of the factor list (§2), ASCII; built from the validated fields, not by a JSON encoder.
    public static func info(_ specs: [FactorSpec]) throws -> [UInt8] {
        try validate(specs)
        return Array(("[" + specs.map(\.canonical).joined(separator: ",") + "]").utf8)
    }

    /// A stored factor list (a JSON array value): 1-2 valid objects in §2 order.
    static func parseList(_ value: JSONValue?) throws -> [FactorSpec] {
        guard case .array(let items)? = value, (1...2).contains(items.count) else {
            throw CompositeKeyError("Factor list must hold one or two factors")
        }
        let specs = try items.map { try FactorSpec(json: $0) }
        try validate(specs)
        return specs
    }

    /// Hex of the first 8 bytes of HMAC-SHA256(secret, "localgatekeys|factor-check|v1"). Secrets are 32 bytes
    /// (`verify` and `combine` refuse others).
    public static func check(_ secret: [UInt8]) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: checkInfo, using: SymmetricKey(data: secret))
        return lowerHex(Array(mac).prefix(8))
    }

    /// The factor secret of a YubiKey: SHA-256 of its 20-byte HMAC-SHA1 response.
    public static func yubiKeySecret(_ response: [UInt8]) throws -> [UInt8] {
        guard response.count == yubiKeyResponseSize else { throw CompositeKeyError("YubiKey response must be 20 bytes") }
        return Array(SHA256.hash(data: response))
    }

    /// The 32-byte challenge padded to 64 bytes as KeePassXC pads it (32 bytes of 0x20). These 64 bytes go to the
    /// YubiKey exactly: never hand a YubiKey library the bare 32 bytes and let it pad.
    public static func padChallenge(_ challenge: [UInt8]) throws -> [UInt8] {
        guard challenge.count == challengeSize else { throw CompositeKeyError("YubiKey challenge must be 32 bytes") }
        let pad = paddedChallengeSize - challengeSize
        return challenge + [UInt8](repeating: UInt8(pad), count: pad)
    }

    /// 32 random bytes for a YubiKey factor, never ending in 0x00 or 0x20 (a variable-mode slot would drop them).
    public static func newChallenge(random: any RandomSource) -> [UInt8] {
        while true {
            let c = random.bytes(count: challengeSize)
            if let last = c.last, last != 0x00, last != 0x20 { return c }
        }
    }

    /// `FactorError.mismatch` for the first secret whose check differs (constant-time compare); runs no KDF.
    public static func verify(_ specs: [FactorSpec], secrets: [[UInt8]]) throws {
        try validate(specs)
        guard specs.count == secrets.count else { throw FactorError.required(specs.map(\.kind)) }
        for (spec, secret) in zip(specs, secrets) {
            guard secret.count == secretSize,
                  BackupKey.constantTimeEqual(Array(check(secret).utf8), Array(spec.check.utf8)) else {
                throw FactorError.mismatch(spec.kind)
            }
        }
    }

    /// The wrapping key: `argonOut` itself when there are no factors, otherwise HKDF over `argonOut || secrets`
    /// (a new array the caller wipes; the caller still owns `argonOut`).
    public static func combine(argonOut: [UInt8], specs: [FactorSpec], secrets: [[UInt8]]) throws -> [UInt8] {
        try validate(specs)
        guard specs.count == secrets.count else { throw CompositeKeyError("One secret per factor is required") }
        if specs.isEmpty { return argonOut }
        guard argonOut.count == secretSize, secrets.allSatisfy({ $0.count == secretSize }) else {
            throw CompositeKeyError("Composite key inputs must be 32 bytes each")
        }
        var ikm = argonOut
        defer { wipe(&ikm) }
        for s in secrets { ikm += s }
        return CryptoBox.hkdf(ikm: ikm, salt: salt, info: try info(specs), length: 32)
    }

    /// One 32-byte secret per spec, in list order (the caller wipes them); no KDF runs.
    ///
    /// Every factor must be supplied, else `FactorError.required` names the missing ones before anything is asked of
    /// a YubiKey. Each secret is checked as soon as it is known (`FactorError.mismatch`), so a wrong key file is
    /// reported before the YubiKey is used. A file that is not a usable key file, or a YubiKey answer that is not 20
    /// bytes, is a mismatch (Windows `_factor_secret`). An error the YubiKey responder throws (removed, cancelled,
    /// timed out) reaches the caller unchanged, so the app can say "Touch your YubiKey again".
    public static func secrets(for specs: [FactorSpec], from factors: FactorSecrets) async throws -> [[UInt8]] {
        try validate(specs)
        let missing = specs.map(\.kind).filter { kind in
            kind == .keyFile ? factors.keyFile == nil : factors.yubiKey == nil
        }
        guard missing.isEmpty else { throw FactorError.required(missing) }
        var out: [[UInt8]] = []
        do {
            for spec in specs {
                var secret: [UInt8]
                switch spec.kind {
                case .keyFile:
                    do { secret = try KeyFile.key(from: factors.keyFile ?? Data()) } catch is KeyFileError { throw FactorError.mismatch(.keyFile) }
                case .yubiKeyHMAC:
                    guard let respond = factors.yubiKey else { throw FactorError.required([.yubiKeyHMAC]) }
                    var response = [UInt8](try await respond(Data(spec.paddedChallenge)))
                    defer { wipe(&response) }
                    do { secret = try yubiKeySecret(response) } catch { throw FactorError.mismatch(.yubiKeyHMAC) }
                }
                out.append(secret)
                wipe(&secret)
                try verify([spec], secrets: [out[out.count - 1]])
            }
        } catch {
            for i in out.indices { wipe(&out[i]) }
            throw error
        }
        return out
    }

    // MARK: - Enrolment

    /// A key-file factor for `data` (the bytes of the chosen file) and its secret (the caller wipes it).
    /// Throws `KeyFileError` when the file is not a usable key file.
    public static func enrolKeyFile(_ data: Data) throws -> (spec: FactorSpec, secret: [UInt8]) {
        let secret = try KeyFile.key(from: data)
        return (try FactorSpec.keyFile(check: check(secret)), secret)
    }

    /// A YubiKey factor with a new challenge, answered by `respond` (given the 64-byte padded challenge) now; the
    /// spec and its secret (the caller wipes it). An answer that is not 20 bytes (a slot not set up for
    /// challenge-response) throws `CompositeKeyError`.
    public static func enrolYubiKey(slot: Int, random: any RandomSource,
                                    respond: @Sendable (Data) async throws -> Data) async throws -> (spec: FactorSpec, secret: [UInt8]) {
        guard slot == 1 || slot == 2 else { throw CompositeKeyError("YubiKey slot must be 1 or 2") }
        let challenge = newChallenge(random: random)
        var response = [UInt8](try await respond(Data(try padChallenge(challenge))))
        defer { wipe(&response) }
        let secret = try yubiKeySecret(response)
        return (try FactorSpec.yubiKey(check: check(secret), slot: slot, challenge: challenge), secret)
    }

    /// The factors for a rewritten password wrapper (a password change): the same key file, checked, and for a
    /// YubiKey first its answer to the old challenge (so it is the same key), then a new challenge (§1.2: renewed
    /// whenever the password wrapper is rewritten). Specs and secrets in list order; the caller wipes the secrets.
    public static func renewed(_ specs: [FactorSpec], with factors: FactorSecrets,
                               random: any RandomSource) async throws -> (specs: [FactorSpec], secrets: [[UInt8]]) {
        var old = try await secrets(for: specs, from: factors)
        defer { for i in old.indices { wipe(&old[i]) } }
        var outSpecs: [FactorSpec] = [], outSecrets: [[UInt8]] = []
        do {
            for (spec, secret) in zip(specs, old) {
                if spec.kind == .yubiKeyHMAC, let respond = factors.yubiKey, let slot = spec.slot {
                    let fresh = try await enrolYubiKey(slot: slot, random: random, respond: respond)
                    outSpecs.append(fresh.spec); outSecrets.append(fresh.secret)
                } else {
                    outSpecs.append(spec); outSecrets.append(secret)
                }
            }
        } catch {
            for i in outSecrets.indices { wipe(&outSecrets[i]) }
            throw error
        }
        return (outSpecs, outSecrets)
    }
}
