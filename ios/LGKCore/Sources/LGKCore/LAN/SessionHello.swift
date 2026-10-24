import Crypto
import Foundation

/// A refused LAN transport step (desktop `transport.FrameError` / `AuthenticationError` / `ReplayError`).
public enum LanTransportError: Error, Equatable, Sendable {
    case malformed(String)
    case tooLarge(String)
    case authentication(String)
    case replay(String)
}

/// A paired LAN device as this device pins it (desktop `PairedDevice` + stored endpoint).
public struct PinnedPeer: Equatable, Sendable {
    public let deviceID: String
    public let groupID: String
    public let signingPublic: [UInt8]
    public let exchangePublic: [UInt8]
    public let endpoint: LanEndpoint?

    public init(deviceID: String, groupID: String, signingPublic: [UInt8], exchangePublic: [UInt8], endpoint: LanEndpoint?) {
        self.deviceID = deviceID; self.groupID = groupID
        self.signingPublic = signingPublic; self.exchangePublic = exchangePublic; self.endpoint = endpoint
    }

    /// Lowercase hex SHA-256 of the signing key.
    public var fingerprint: String { lowerHex(Array(SHA256.hash(data: signingPublic))) }
}

/// Transport constants (desktop `sync.transport`).
public enum LanTransport {
    /// Version 2 added the per-session ephemeral key (forward secrecy); there is no fallback to version 1.
    public static let version: Int64 = 2
    public static let maxFramePayload = 1024 * 1024
    public static let maxMessageBytes = maxFramePayload - 256
    public static let sessionIDBytes = 16

    /// 4-byte big-endian length prefix + payload (1 ... 1 MiB).
    public static func encodeFrame(_ payload: [UInt8]) throws -> [UInt8] {
        guard (1...maxFramePayload).contains(payload.count) else { throw LanTransportError.tooLarge("Frame payload is empty or exceeds the bound") }
        let n = UInt32(payload.count)
        return [UInt8(n >> 24), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)] + payload
    }

    /// Strips and checks the length prefix of exactly one frame.
    public static func decodeFrame(_ frame: [UInt8]) throws -> [UInt8] {
        guard frame.count >= 4 else { throw LanTransportError.malformed("Frame is truncated") }
        let n = Int(frame[0]) << 24 | Int(frame[1]) << 16 | Int(frame[2]) << 8 | Int(frame[3])
        guard (1...maxFramePayload).contains(n) else { throw LanTransportError.tooLarge("Frame length is outside the bound") }
        guard frame.count == 4 + n else { throw LanTransportError.malformed("Frame contains trailing or missing bytes") }
        return Array(frame[4...])
    }

    static func canonical(_ v: JSONValue) throws -> [UInt8] {
        guard let data = try? CanonicalJSON.encode(v, dialect: .ascii) else { throw LanTransportError.malformed("Transport message is not serializable") }
        guard data.count <= maxFramePayload else { throw LanTransportError.tooLarge("Transport message exceeds the frame bound") }
        return data
    }

    /// Strict canonical base64 with an optional exact length.
    static func b64(_ v: JSONValue?, length: Int?, _ field: String) throws -> [UInt8] {
        guard case .string(let s)? = v, let raw = try? Base64.decodeStrict(s) else { throw LanTransportError.malformed("\(field) is malformed") }
        if let length, raw.count != length { throw LanTransportError.malformed("\(field) has an invalid length") }
        return raw
    }

    /// The plain frame payload a responder sends for a hello of another version (`version_refusal`):
    /// canonical `{"refused":"version","version":2}`.
    public static func versionRefusal() throws -> [UInt8] {
        try canonical(.object(["refused": .string("version"), "version": .int(version)]))
    }

    /// The version a peer announced in a version refusal, or nil when `payload` is not exactly one
    /// (`parse_version_refusal`): the fields `refused` ("version") and `version` (an integer 1 ... 2^31-1
    /// other than this version), at most 256 bytes.
    public static func parseVersionRefusal(_ payload: [UInt8]) -> Int64? {
        guard payload.count <= 256, case .object(let o)? = try? CanonicalJSON.parse(payload),
              Set(o.keys) == ["refused", "version"], o["refused"] == .string("version"),
              case .int(let v)? = o["version"], v >= 1, v <= Int64(Int32.max), v != version else { return nil }
        return v
    }
}

/// The X25519 ephemeral private key of one session hello this device made (desktop `EphemeralSecret`):
/// `take` hands it out for exactly one derivation and forgets it; `wipe` forgets it unused (a failed
/// handshake). CryptoKit keeps the key bytes inside `PrivateKey`; once this optional is nil and the
/// derivation has returned, no reference to them is left.
public final class EphemeralSecret: @unchecked Sendable, CustomStringConvertible {
    private let lock = NSLock()
    private var key: Curve25519.KeyAgreement.PrivateKey?

    init(_ key: Curve25519.KeyAgreement.PrivateKey) { self.key = key }

    /// The key, once; a second call throws.
    func take() throws -> Curve25519.KeyAgreement.PrivateKey {
        lock.lock(); defer { lock.unlock() }
        guard let k = key else { throw LanTransportError.authentication("Session ephemeral key was already used or wiped") }
        key = nil
        return k
    }

    public func wipe() {
        lock.lock(); defer { lock.unlock() }
        key = nil
    }

    public var used: Bool {
        lock.lock(); defer { lock.unlock() }
        return key == nil
    }

    public var description: String { "EphemeralSecret(<redacted>)" }
}

/// The signed hello each side sends first on a LAN connection (desktop `transport.SessionHello`, version 2).
public struct SessionHello: Equatable, Sendable {
    static let fields: Set<String> = ["counter", "device_id", "ephemeral_public", "exchange_public", "group_id", "nonce",
                                      "session_id", "signature", "signing_public", "version"]
    static let label = Array("localgatekeys|sync|session-hello|v2|".utf8)

    public let sessionID: [UInt8]
    public let groupID: String
    public let deviceID: String
    public let signingPublic: [UInt8]
    public let exchangePublic: [UInt8]
    /// A fresh X25519 public key for this connection only.
    public let ephemeralPublic: [UInt8]
    public let nonce: [UInt8]
    public let counter: Int64
    public let signature: [UInt8]
    /// Set only on a hello this device made (never parsed or serialised); good for one derivation.
    public let ephemeralSecret: EphemeralSecret?

    init(sessionID: [UInt8], groupID: String, deviceID: String, signingPublic: [UInt8], exchangePublic: [UInt8],
         ephemeralPublic: [UInt8], nonce: [UInt8], counter: Int64, signature: [UInt8], ephemeralSecret: EphemeralSecret? = nil) {
        self.sessionID = sessionID; self.groupID = groupID; self.deviceID = deviceID
        self.signingPublic = signingPublic; self.exchangePublic = exchangePublic; self.ephemeralPublic = ephemeralPublic
        self.nonce = nonce; self.counter = counter; self.signature = signature; self.ephemeralSecret = ephemeralSecret
    }

    /// Every wire field; the ephemeral secret is not compared.
    public static func == (a: SessionHello, b: SessionHello) -> Bool {
        a.sessionID == b.sessionID && a.groupID == b.groupID && a.deviceID == b.deviceID
            && a.signingPublic == b.signingPublic && a.exchangePublic == b.exchangePublic
            && a.ephemeralPublic == b.ephemeralPublic && a.nonce == b.nonce && a.counter == b.counter
            && a.signature == b.signature
    }

    var unsignedJSON: [String: JSONValue] {
        ["version": .int(LanTransport.version), "session_id": .string(Base64.encode(sessionID)),
         "group_id": .string(groupID), "device_id": .string(deviceID),
         "signing_public": .string(Base64.encode(signingPublic)), "exchange_public": .string(Base64.encode(exchangePublic)),
         "ephemeral_public": .string(Base64.encode(ephemeralPublic)),
         "nonce": .string(Base64.encode(nonce)), "counter": .int(counter)]
    }

    /// The signed text: label + canonical JSON of the hello without `signature`.
    public func signingBytes() throws -> [UInt8] { Self.label + (try LanTransport.canonical(.object(unsignedJSON))) }

    /// Canonical JSON of the whole hello (the transcript uses this form).
    public func toBytes() throws -> [UInt8] {
        var o = unsignedJSON
        o["signature"] = .string(Base64.encode(signature))
        return try LanTransport.canonical(.object(o))
    }

    /// A signed hello of `identity` with a fresh ephemeral key (`ephemeralSecret`, good for one derivation).
    /// Draws the 32-byte hello nonce, then the 32-byte X25519 ephemeral private key, from `random`
    /// (`SystemRandomSource` in the app; tests inject the vectors' values).
    public static func make(identity: DeviceIdentity, groupID: String, sessionID: [UInt8], counter: Int64,
                            random: some RandomSource) throws -> SessionHello {
        guard !groupID.isEmpty, sessionID.count == LanTransport.sessionIDBytes, counter >= 0 else {
            throw LanTransportError.authentication("Session hello input is malformed")
        }
        let nonce = random.bytes(count: 32)
        guard nonce.count == 32 else { throw LanTransportError.malformed("session nonce is malformed") }
        let ephRaw = random.bytes(count: 32)
        guard ephRaw.count == 32, let eph = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ephRaw) else {
            throw LanTransportError.authentication("Session ephemeral key is malformed")
        }
        let ephPublic = Array(eph.publicKey.rawRepresentation)
        let unsigned = SessionHello(sessionID: sessionID, groupID: groupID, deviceID: identity.deviceID,
                                    signingPublic: identity.signingPublicKey, exchangePublic: identity.exchangePublicKey,
                                    ephemeralPublic: ephPublic, nonce: nonce, counter: counter, signature: [])
        return SessionHello(sessionID: sessionID, groupID: groupID, deviceID: identity.deviceID,
                            signingPublic: identity.signingPublicKey, exchangePublic: identity.exchangePublicKey,
                            ephemeralPublic: ephPublic, nonce: nonce, counter: counter,
                            signature: try identity.sign(try unsigned.signingBytes()), ephemeralSecret: EphemeralSecret(eph))
    }

    /// This hello with `privateKey` attached as its ephemeral secret; it must be the key of `ephemeralPublic`
    /// (tests: a recorded hello and its published ephemeral private key).
    func withEphemeral(privateKey: [UInt8]) throws -> SessionHello {
        guard privateKey.count == 32, let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey),
              Array(k.publicKey.rawRepresentation) == ephemeralPublic else {
            throw LanTransportError.authentication("Session ephemeral key is malformed")
        }
        return SessionHello(sessionID: sessionID, groupID: groupID, deviceID: deviceID, signingPublic: signingPublic,
                            exchangePublic: exchangePublic, ephemeralPublic: ephemeralPublic, nonce: nonce, counter: counter,
                            signature: signature, ephemeralSecret: EphemeralSecret(k))
    }

    /// The version of a first frame that is a signed hello (an object with `signature`) of another integer
    /// version, or nil. Such a hello is never used for a key; the initiator reports "update needed".
    public static func otherVersion(_ bytes: [UInt8]) -> Int64? {
        guard bytes.count <= LanTransport.maxMessageBytes, case .object(let o)? = try? CanonicalJSON.parse(bytes),
              o["signature"] != nil, case .int(let v)? = o["version"], v != LanTransport.version else { return nil }
        return v
    }

    /// Strict parse (`SessionHello.from_bytes`): exact field set, duplicate keys refused, `version`
    /// the JSON integer 2, canonical base64 with exact lengths, `counter` an integer 0 ... 2^63-1.
    /// A signed hello of another version is refused too (`otherVersion`).
    public static func parse(_ bytes: [UInt8]) throws -> SessionHello {
        guard bytes.count <= LanTransport.maxMessageBytes else { throw LanTransportError.tooLarge("Session hello exceeds the bound") }
        if let v = otherVersion(bytes) { throw LanTransportError.malformed("Session hello version \(v) is not supported") }
        guard case .object(let o)? = try? CanonicalJSON.parse(bytes), Set(o.keys) == fields else {
            throw LanTransportError.malformed("Session hello is malformed")
        }
        guard o["version"] == .int(LanTransport.version) else { throw LanTransportError.malformed("Unsupported session hello") }
        guard case .int(let counter)? = o["counter"], counter >= 0 else { throw LanTransportError.malformed("Session hello counter is malformed") }
        guard case .string(let group)? = o["group_id"], case .string(let device)? = o["device_id"] else {
            throw LanTransportError.malformed("Session hello is malformed")
        }
        return SessionHello(sessionID: try LanTransport.b64(o["session_id"], length: LanTransport.sessionIDBytes, "session id"),
                            groupID: group, deviceID: device,
                            signingPublic: try LanTransport.b64(o["signing_public"], length: 32, "signing public key"),
                            exchangePublic: try LanTransport.b64(o["exchange_public"], length: 32, "exchange public key"),
                            ephemeralPublic: try LanTransport.b64(o["ephemeral_public"], length: 32, "ephemeral public key"),
                            nonce: try LanTransport.b64(o["nonce"], length: 32, "session nonce"), counter: counter,
                            signature: try LanTransport.b64(o["signature"], length: 64, "session signature"))
    }

    /// `verify_session_hello`: group, device id, signing key, fingerprint and exchange key must be
    /// exactly the pinned ones, the ephemeral key neither all zero nor the hello's exchange key, then
    /// the Ed25519 signature.
    public static func verify(_ hello: SessionHello, pinned: PinnedPeer, groupID: String) throws {
        guard hello.groupID == groupID, hello.groupID == pinned.groupID else { throw LanTransportError.authentication("Session group mismatch") }
        guard hello.deviceID == pinned.deviceID, hello.signingPublic == pinned.signingPublic else {
            throw LanTransportError.authentication("Session device key is not pinned")
        }
        guard lowerHex(Array(SHA256.hash(data: hello.signingPublic))) == pinned.fingerprint else {
            throw LanTransportError.authentication("Session device fingerprint is not pinned")
        }
        guard hello.exchangePublic == pinned.exchangePublic else { throw LanTransportError.authentication("Session exchange key is not pinned") }
        guard hello.ephemeralPublic != hello.exchangePublic, hello.ephemeralPublic.contains(where: { $0 != 0 }) else {
            throw LanTransportError.authentication("Session ephemeral key is malformed")
        }
        guard DeviceIdentity.verify(signature: hello.signature, message: try hello.signingBytes(), publicKey: hello.signingPublic) else {
            throw LanTransportError.authentication("Session hello signature is invalid")
        }
    }
}
