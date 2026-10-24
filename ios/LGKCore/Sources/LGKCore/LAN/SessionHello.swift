import Crypto

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
    public static let version: Int64 = 1
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
}

/// The signed hello each side sends first on a LAN connection (desktop `transport.SessionHello`).
public struct SessionHello: Equatable, Sendable {
    static let fields: Set<String> = ["counter", "device_id", "exchange_public", "group_id", "nonce", "session_id",
                                      "signature", "signing_public", "version"]
    static let label = Array("localgatekeys|sync|session-hello|v1|".utf8)

    public let sessionID: [UInt8]
    public let groupID: String
    public let deviceID: String
    public let signingPublic: [UInt8]
    public let exchangePublic: [UInt8]
    public let nonce: [UInt8]
    public let counter: Int64
    public let signature: [UInt8]

    var unsignedJSON: [String: JSONValue] {
        ["version": .int(LanTransport.version), "session_id": .string(Base64.encode(sessionID)),
         "group_id": .string(groupID), "device_id": .string(deviceID),
         "signing_public": .string(Base64.encode(signingPublic)), "exchange_public": .string(Base64.encode(exchangePublic)),
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

    /// A signed hello of `identity`; draws the 32-byte hello nonce from `random`.
    public static func make(identity: DeviceIdentity, groupID: String, sessionID: [UInt8], counter: Int64,
                            random: some RandomSource) throws -> SessionHello {
        guard !groupID.isEmpty, sessionID.count == LanTransport.sessionIDBytes, counter >= 0 else {
            throw LanTransportError.authentication("Session hello input is malformed")
        }
        let nonce = random.bytes(count: 32)
        guard nonce.count == 32 else { throw LanTransportError.malformed("session nonce is malformed") }
        let unsigned = SessionHello(sessionID: sessionID, groupID: groupID, deviceID: identity.deviceID,
                                    signingPublic: identity.signingPublicKey, exchangePublic: identity.exchangePublicKey,
                                    nonce: nonce, counter: counter, signature: [])
        return SessionHello(sessionID: sessionID, groupID: groupID, deviceID: identity.deviceID,
                            signingPublic: identity.signingPublicKey, exchangePublic: identity.exchangePublicKey,
                            nonce: nonce, counter: counter, signature: try identity.sign(try unsigned.signingBytes()))
    }

    /// Strict parse (`SessionHello.from_bytes`): exact field set, duplicate keys refused, `version`
    /// the JSON integer 1, canonical base64 with exact lengths, `counter` an integer 0 ... 2^63-1.
    public static func parse(_ bytes: [UInt8]) throws -> SessionHello {
        guard bytes.count <= LanTransport.maxMessageBytes else { throw LanTransportError.tooLarge("Session hello exceeds the bound") }
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
                            nonce: try LanTransport.b64(o["nonce"], length: 32, "session nonce"), counter: counter,
                            signature: try LanTransport.b64(o["signature"], length: 64, "session signature"))
    }

    /// `verify_session_hello`: group, device id, signing key, fingerprint and exchange key must be
    /// exactly the pinned ones, then the Ed25519 signature.
    public static func verify(_ hello: SessionHello, pinned: PinnedPeer, groupID: String) throws {
        guard hello.groupID == groupID, hello.groupID == pinned.groupID else { throw LanTransportError.authentication("Session group mismatch") }
        guard hello.deviceID == pinned.deviceID, hello.signingPublic == pinned.signingPublic else {
            throw LanTransportError.authentication("Session device key is not pinned")
        }
        guard lowerHex(Array(SHA256.hash(data: hello.signingPublic))) == pinned.fingerprint else {
            throw LanTransportError.authentication("Session device fingerprint is not pinned")
        }
        guard hello.exchangePublic == pinned.exchangePublic else { throw LanTransportError.authentication("Session exchange key is not pinned") }
        guard DeviceIdentity.verify(signature: hello.signature, message: try hello.signingBytes(), publicKey: hello.signingPublic) else {
            throw LanTransportError.authentication("Session hello signature is invalid")
        }
    }
}
