import Crypto

/// The AES-GCM channel of one LAN connection (desktop `transport.SecureChannel`).
///
/// Key = HKDF-SHA256(X25519 shared, salt = SHA-256(`session-salt|` + sorted hellos),
/// info = `session-key|` + session id). Nonce = 4-byte direction prefix + 8-byte big-endian
/// counter; each direction starts at counter 1 and a receiver refuses a counter that does not
/// increase. The desktop sends one request and one response per connection.
public struct SecureChannel: Sendable {
    public enum Role: String, Sendable { case initiator, responder }

    static let frameFields: Set<String> = ["ciphertext", "counter", "nonce", "session_id", "version"]

    public let key: [UInt8]
    public let sessionID: [UInt8]
    public let role: Role
    public let sendPrefix: [UInt8]
    public let receivePrefix: [UInt8]
    private var sendCounter: Int64 = 0
    private var lastReceived: Int64 = 0

    public init(key: [UInt8], sessionID: [UInt8], role: Role) throws {
        guard key.count == 32 else { throw LanTransportError.authentication("Session key must be 32 bytes") }
        guard sessionID.count == LanTransport.sessionIDBytes else { throw LanTransportError.authentication("Session ID is malformed") }
        self.key = key; self.sessionID = sessionID; self.role = role
        sendPrefix = Self.prefix(key: key, role: role)
        receivePrefix = Self.prefix(key: key, role: role == .initiator ? .responder : .initiator)
    }

    /// `SecureChannel.from_paired_identities`: verifies the remote hello against `remote`, both
    /// session-id bindings and the local hello's signature, then derives the key.
    public init(local: DeviceIdentity, remote: PinnedPeer, groupID: String, sessionID: [UInt8], role: Role,
                localHello: SessionHello, remoteHello: SessionHello) throws {
        try SessionHello.verify(remoteHello, pinned: remote, groupID: groupID)
        guard localHello.groupID == groupID, localHello.deviceID == local.deviceID,
              localHello.sessionID == sessionID, remoteHello.sessionID == sessionID else {
            throw LanTransportError.authentication("Session hello binding is invalid")
        }
        guard DeviceIdentity.verify(signature: localHello.signature, message: try localHello.signingBytes(),
                                    publicKey: local.signingPublicKey) else {
            throw LanTransportError.authentication("Local session hello signature is invalid")
        }
        let transcript = try Self.transcript(localHello.toBytes(), remoteHello.toBytes())
        let shared: [UInt8]
        do { shared = try local.exchange(with: remote.exchangePublic) }
        catch { throw LanTransportError.authentication("Peer exchange key is malformed") }
        try self.init(key: Self.deriveKey(shared: shared, sessionID: sessionID, transcript: transcript), sessionID: sessionID, role: role)
    }

    /// Both hello texts sorted bytewise and concatenated (never by role or counter).
    public static func transcript(_ a: [UInt8], _ b: [UInt8]) throws -> [UInt8] {
        let t = a.lexicographicallyPrecedes(b) ? a + b : b + a
        guard t.count <= LanTransport.maxMessageBytes else { throw LanTransportError.authentication("Session transcript is malformed") }
        return t
    }

    public static func salt(transcript: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: Array("localgatekeys|sync|session-salt|".utf8) + transcript))
    }

    public static func info(sessionID: [UInt8]) -> [UInt8] { Array("localgatekeys|sync|session-key|".utf8) + sessionID }

    public static func deriveKey(shared: [UInt8], sessionID: [UInt8], transcript: [UInt8]) throws -> [UInt8] {
        guard sessionID.count == LanTransport.sessionIDBytes else { throw LanTransportError.authentication("Session transcript is malformed") }
        return CryptoBox.hkdf(ikm: shared, salt: salt(transcript: transcript), info: info(sessionID: sessionID), length: 32)
    }

    /// First 4 bytes of SHA-256(key + `send|` + sender role).
    public static func prefix(key: [UInt8], role: Role) -> [UInt8] {
        Array(Array(SHA256.hash(data: key + Array("send|".utf8) + Array(role.rawValue.utf8))).prefix(4))
    }

    private func metadata(counter: Int64, nonce: [UInt8]) -> [String: JSONValue] {
        ["version": .int(LanTransport.version), "session_id": .string(Base64.encode(sessionID)),
         "counter": .int(counter), "nonce": .string(Base64.encode(nonce))]
    }

    private static func nonce(prefix: [UInt8], counter: Int64) -> [UInt8] {
        prefix + (0..<8).map { UInt8((UInt64(counter) >> (56 - 8 * UInt64($0))) & 0xFF) }
    }

    /// Seals one message; returns the frame WITH its 4-byte length prefix.
    public mutating func seal(_ payload: [UInt8]) throws -> [UInt8] {
        guard (1...LanTransport.maxMessageBytes).contains(payload.count) else { throw LanTransportError.tooLarge("Encrypted message exceeds the bound") }
        guard sendCounter < Int64.max else { throw LanTransportError.replay("Session counter exhausted") }
        sendCounter += 1
        let nonce = Self.nonce(prefix: sendPrefix, counter: sendCounter)
        var meta = metadata(counter: sendCounter, nonce: nonce)
        let ct = try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: payload, aad: try LanTransport.canonical(.object(meta)))
        meta["ciphertext"] = .string(Base64.encode(ct))
        return try LanTransport.encodeFrame(try LanTransport.canonical(.object(meta)))
    }

    /// Opens one frame (with its length prefix). Strict: exact field set, `version` the JSON
    /// integer 1, this session, an increasing counter bound to the peer's direction prefix.
    public mutating func open(_ frame: [UInt8]) throws -> [UInt8] {
        let payload = try LanTransport.decodeFrame(frame)
        guard payload.count <= LanTransport.maxMessageBytes + 4096 else { throw LanTransportError.tooLarge("Encrypted frame exceeds the bound") }
        let raw = try Self.parseFrame(payload)
        guard raw["session_id"] == .string(Base64.encode(sessionID)) else {
            throw LanTransportError.authentication("Encrypted frame belongs to another session")
        }
        guard case .int(let counter)? = raw["counter"], counter >= 1 else { throw LanTransportError.malformed("Encrypted frame counter is malformed") }
        guard counter > lastReceived else { throw LanTransportError.replay("Duplicate or out-of-order encrypted frame") }
        let nonce = try LanTransport.b64(raw["nonce"], length: 12, "encrypted nonce")
        guard nonce == Self.nonce(prefix: receivePrefix, counter: counter) else {
            throw LanTransportError.authentication("Encrypted nonce is not bound to the session direction")
        }
        let ct = try LanTransport.b64(raw["ciphertext"], length: nil, "encrypted payload")
        guard ct.count <= LanTransport.maxMessageBytes + 16 else { throw LanTransportError.tooLarge("encrypted payload exceeds the size bound") }
        let plain: [UInt8]
        do {
            plain = try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: ct,
                                          aad: try LanTransport.canonical(.object(metadata(counter: counter, nonce: nonce))))
        } catch { throw LanTransportError.authentication("Encrypted frame authentication failed") }
        guard plain.count <= LanTransport.maxMessageBytes else { throw LanTransportError.tooLarge("Decrypted message exceeds the bound") }
        lastReceived = counter
        return plain
    }

    /// Strict frame payload shape check (without the length prefix).
    public static func parseFrame(_ payload: [UInt8]) throws -> [String: JSONValue] {
        guard case .object(let o)? = try? CanonicalJSON.parse(payload), Set(o.keys) == frameFields else {
            throw LanTransportError.malformed("Encrypted frame is malformed")
        }
        guard o["version"] == .int(LanTransport.version) else { throw LanTransportError.malformed("Unsupported encrypted frame") }
        return o
    }
}
