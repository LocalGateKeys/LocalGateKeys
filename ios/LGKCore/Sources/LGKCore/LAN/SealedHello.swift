import Crypto
import Foundation

/// The sealing secret of one sealed-hello exchange (desktop `transport.SealContext`): `es = X25519(x_i, S_R)`,
/// the initiator's one-connection public key `X_i` and the responder's static exchange key `S_R`. Kept only for
/// the length of one handshake; `wipe` drops the secret.
public final class SealContext: @unchecked Sendable, CustomStringConvertible {
    private let lock = NSLock()
    private var shared: [UInt8]?
    public let initiatorEphemeral: [UInt8]
    public let responderStatic: [UInt8]

    init(shared: [UInt8], initiatorEphemeral: [UInt8], responderStatic: [UInt8]) {
        self.shared = shared; self.initiatorEphemeral = initiatorEphemeral; self.responderStatic = responderStatic
    }

    /// HKDF-SHA256(ikm = es, salt = X_i || S_R, info = `sealed-hello|v3|` + role, 32 bytes).
    func key(_ role: SecureChannel.Role) throws -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        guard let shared else { throw LanTransportError.authentication("Sealed hello secret was already wiped") }
        return CryptoBox.hkdf(ikm: shared, salt: initiatorEphemeral + responderStatic,
                              info: SealedHello.label + Array(role.rawValue.utf8), length: 32)
    }

    /// `sealed-hello|v3|` + X_i.
    var aad: [UInt8] { SealedHello.label + initiatorEphemeral }

    public func wipe() {
        lock.lock(); defer { lock.unlock() }
        shared = nil
    }

    public var description: String { "SealContext(<redacted>)" }
}

/// The sealed hello of LAN protocol version 3 (desktop `transport.seal_initiator_hello` and friends,
/// docs/formats/LAN_SYNC_V3.md section 2.2): the version-3 hello, padded to 1024 bytes, encrypted with
/// AES-256-GCM (12 zero nonce bytes; each key encrypts one message) to the responder's pinned exchange key.
/// An outsider sees fixed-size random bytes.
public enum SealedHello {
    static let label = Array("localgatekeys|sync|sealed-hello|v3|".utf8)
    static let nonce = [UInt8](repeating: 0, count: 12)
    static let initiatorFields: Set<String> = ["box", "eph", "signature", "version"]
    static let responderFields: Set<String> = ["box", "version"]
    /// The padded plaintext: 2-byte big-endian length, the inner hello, zero bytes (desktop `SEALED_HELLO_PLAINTEXT_BYTES`).
    public static let plaintextBytes = 1024
    /// The box: the padded plaintext and the 16-byte tag.
    public static let boxBytes = plaintextBytes + 16

    static func pad(_ hello: SessionHello) throws -> [UInt8] {
        let inner = try hello.toBytes()
        let room = plaintextBytes - 2
        guard inner.count <= room else { throw LanTransportError.tooLarge("Session hello does not fit a sealed hello") }
        return [UInt8(inner.count >> 8), UInt8(inner.count & 0xFF)] + inner + [UInt8](repeating: 0, count: room - inner.count)
    }

    /// The length must be 1 ... 1022 and every padding byte zero; the inner hello parses strictly as version 3.
    static func unpad(_ plain: [UInt8]) throws -> SessionHello {
        guard plain.count == plaintextBytes else { throw LanTransportError.malformed("Sealed hello is malformed") }
        let length = Int(plain[0]) << 8 | Int(plain[1])
        guard (1...(plaintextBytes - 2)).contains(length), plain[(2 + length)...].allSatisfy({ $0 == 0 }) else {
            throw LanTransportError.malformed("Sealed hello padding is malformed")
        }
        return try SessionHello.parse(Array(plain[2..<(2 + length)]), version: LanTransport.version)
    }

    /// The initiator's first frame payload, canonical `{"box","eph","signature":"","version":3}`, and its
    /// context. Draws the 32-byte one-connection X25519 private key `x_i` from `random` (`SystemRandomSource`
    /// in the app; tests inject the vectors' value). An all-zero `es` is refused.
    public static func sealInitiator(_ hello: SessionHello, responderExchangePublic: [UInt8],
                                     random: some RandomSource) throws -> (payload: [UInt8], context: SealContext) {
        guard hello.version == LanTransport.version else { throw LanTransportError.authentication("A version-3 session hello is required") }
        guard responderExchangePublic.count == 32 else { throw LanTransportError.authentication("Peer exchange key is malformed") }
        let ephemeral = random.bytes(count: 32)
        guard ephemeral.count == 32 else { throw LanTransportError.authentication("Sealed hello ephemeral key is malformed") }
        let exchanged: (shared: [UInt8], ownPublic: [UInt8])
        do { exchanged = try DeviceIdentity.x25519(privateKey: ephemeral, peerPublic: responderExchangePublic) }
        catch { throw LanTransportError.authentication("Peer exchange key is malformed") }
        let ephPublic = exchanged.ownPublic
        let context = SealContext(shared: exchanged.shared, initiatorEphemeral: ephPublic, responderStatic: responderExchangePublic)
        let box: [UInt8]
        do { box = try CryptoBox.sealGCM(key: try context.key(.initiator), nonce: nonce, plaintext: try pad(hello), aad: context.aad) }
        catch { context.wipe(); throw error }
        let payload = try LanTransport.canonical(.object(["box": .string(Base64.encode(box)), "eph": .string(Base64.encode(ephPublic)),
                                                          "signature": .string(""), "version": .int(LanTransport.version)]))
        return (payload, context)
    }

    /// Responder side: the version-3 hello inside a first frame payload sealed to `identity`, and the context
    /// for the answer. Throws for anything else (exact keys, `signature` "", `version` 3, `eph` 32 bytes, `box`
    /// 1040 bytes, a box that opens, the padding, a strict version-3 hello); the caller then closes the
    /// connection without an answer. The hello is not verified here.
    public static func openInitiator(_ payload: [UInt8], identity: DeviceIdentity) throws -> (hello: SessionHello, context: SealContext) {
        guard payload.count <= LanTransport.maxMessageBytes, case .object(let o)? = try? CanonicalJSON.parse(payload),
              Set(o.keys) == initiatorFields, o["version"] == .int(LanTransport.version), o["signature"] == .string("") else {
            throw LanTransportError.malformed("Sealed hello is malformed")
        }
        let ephPublic = try LanTransport.b64(o["eph"], length: 32, "sealed hello key")
        let box = try LanTransport.b64(o["box"], length: boxBytes, "sealed hello")
        let shared: [UInt8]
        do { shared = try identity.exchange(with: ephPublic) } catch { throw LanTransportError.authentication("Sealed hello key is malformed") }
        let context = SealContext(shared: shared, initiatorEphemeral: ephPublic, responderStatic: identity.exchangePublicKey)
        let plain: [UInt8]
        do { plain = try CryptoBox.openGCM(key: try context.key(.initiator), nonce: nonce, ciphertext: box, aad: context.aad) }
        catch { context.wipe(); throw LanTransportError.authentication("Sealed hello is not for this device") }
        do { return (try unpad(plain), context) } catch { context.wipe(); throw error }
    }

    /// The responder's answer payload, canonical `{"box","version":3}`: its padded version-3 hello sealed under `context`.
    public static func sealResponder(_ hello: SessionHello, context: SealContext) throws -> [UInt8] {
        guard hello.version == LanTransport.version else { throw LanTransportError.authentication("A version-3 session hello is required") }
        let box = try CryptoBox.sealGCM(key: try context.key(.responder), nonce: nonce, plaintext: try pad(hello), aad: context.aad)
        return try LanTransport.canonical(.object(["box": .string(Base64.encode(box)), "version": .int(LanTransport.version)]))
    }

    /// Initiator side: the responder's version-3 hello from its sealed answer (exact keys, a 1040-byte box that
    /// opens with `k_responder`). The hello is not verified here.
    public static func openResponder(_ payload: [UInt8], context: SealContext) throws -> SessionHello {
        guard payload.count <= LanTransport.maxMessageBytes else { throw LanTransportError.tooLarge("Sealed hello exceeds the bound") }
        guard case .object(let o)? = try? CanonicalJSON.parse(payload), Set(o.keys) == responderFields,
              o["version"] == .int(LanTransport.version) else {
            throw LanTransportError.malformed("Sealed hello is malformed")
        }
        let box = try LanTransport.b64(o["box"], length: boxBytes, "sealed hello")
        let plain: [UInt8]
        do { plain = try CryptoBox.openGCM(key: try context.key(.responder), nonce: nonce, ciphertext: box, aad: context.aad) }
        catch { throw LanTransportError.authentication("Sealed hello answer is not from the expected peer") }
        return try unpad(plain)
    }
}
