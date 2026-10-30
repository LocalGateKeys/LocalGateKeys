import Crypto

/// Host side of the offer (desktop `pairing.create_pairing_offer` and `offer_qr_payload`).
extension PairingOffer {
    /// Offer lifetime (`PAIRING_TTL_SECONDS`).
    public static let ttlSeconds: Int64 = 120
    public static let secretBytes = 32
    public static let codeDigits = 8
    /// Largest multiple of 10^8 below 2^32: a 4-byte read at or above it is drawn again.
    static let codeLimit: UInt32 = UInt32((UInt64(1) << 32) / 100_000_000 * 100_000_000)

    /// The secret part of a new offer the host keeps (the same values are inside the QR bundle).
    public struct SecretState: Equatable, Sendable {
        public let offerID: String
        public let pairingSecret: [UInt8]
        public let code: String
    }

    /// A new offer for `group` from `identity`, reachable at `endpoint`, expiring `ttlSeconds` after `now`.
    /// Randomness, in order: 16 bytes (uuid4 offer id), 32 (transcript nonce), 32 (pairing secret), then
    /// 4 bytes per draw for the code (big-endian, drawn again while >= `codeLimit`, then modulo 10^8).
    public static func create(group: String, identity: DeviceIdentity, endpoint: LanEndpoint,
                              now: some UnixClock, random: some RandomSource) throws -> (offer: PairingOffer, secretState: SecretState) {
        guard Identifier.isValid(group) else { throw PairingError.malformed("group id is malformed") }
        guard Identifier.isValid(identity.deviceID) else { throw PairingError.malformed("device id is malformed") }
        let ep = try LanEndpoint(validating: endpoint.host, port: endpoint.port)
        let created = now.now
        guard created >= 0, created <= Pairing.maxInt53 - ttlSeconds else { throw PairingError.malformed("Pairing clock value is malformed") }
        var u = random.bytes(count: 16)
        guard u.count == 16 else { throw PairingError.malformed("Pairing randomness is malformed") }
        u[6] = (u[6] & 0x0F) | 0x40; u[8] = (u[8] & 0x3F) | 0x80
        let h = Array(lowerHex(u))
        let offerID = String(h[0..<8]) + "-" + String(h[8..<12]) + "-" + String(h[12..<16]) + "-" + String(h[16..<20]) + "-" + String(h[20..<32])
        let nonce = random.bytes(count: 32)
        let secret = random.bytes(count: secretBytes)
        guard nonce.count == 32, secret.count == secretBytes else { throw PairingError.malformed("Pairing randomness is malformed") }
        var value: UInt32 = 0
        var draws = 0
        repeat {
            let b = random.bytes(count: 4)
            guard b.count == 4, draws < 64 else { throw PairingError.malformed("Pairing randomness is malformed") }
            value = UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
            draws += 1
        } while value >= codeLimit
        let digits = String(value % 100_000_000)
        let code = String(repeating: "0", count: codeDigits - digits.count) + digits
        let offer = PairingOffer(version: 1, offerID: offerID, groupID: group, endpoint: ep,
                                 inviterDeviceID: identity.deviceID, inviterSigningPublic: identity.signingPublicKey,
                                 inviterExchangePublic: identity.exchangePublicKey, certificateFingerprint: identity.fingerprint,
                                 expiresAt: created + ttlSeconds, transcriptNonce: nonce, pairingSecret: secret, code: code)
        return (offer, SecretState(offerID: offerID, pairingSecret: secret, code: code))
    }

    /// `offer_qr_payload`: `lgk-pair:` + unpadded base64url of the ASCII canonical bundle JSON (<= 1200 characters).
    public func qrPayload() throws -> String {
        let text = Self.qrPrefix + Base64URL.encodeNoPad(try Pairing.canonical(bundleJSON))
        guard text.utf8.count <= Self.maxQRPayload else { throw PairingError.malformed("Pairing QR payload is too large") }
        return text
    }
}
