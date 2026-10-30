import Crypto

/// One-use network enrollment, new-device side (desktop `pairing.build_enrollment_request` /
/// `open_enrollment_reply`), plus the inviter-side request opener used to check the format.
///
/// Version 2 (Accept step): the request names the new device (`name`, also `invitee_name` in the
/// transcript); both screens show the 6-digit `verificationCode` of the transcript, and the inviting
/// device answers only after its user chose Accept (within `acceptTimeoutSeconds`), so the new device
/// waits up to `replySeconds` for the reply.
public enum Enrollment {
    public static let requestMagic = Array("LGKENROLL1\n".utf8)
    public static let replyMagic = Array("LGKENROLLOK1\n".utf8)
    public static let refusedMagic = Array("LGKENROLLNO1\n".utf8)
    public static let maxBytes = 16 * 1024
    /// Version of the request body and transcript (`ENROLL_VERSION`; 2 added the name and the Accept step).
    public static let version: Int64 = 2
    /// Generic, offer used up or expired, peer list full, declined on the inviting device (or no answer
    /// within `acceptTimeoutSeconds`), and a request of an older version (this device needs an update).
    public static let refusalReasons: Set<String> = ["refused", "used-or-expired", "full", "declined", "update-needed"]
    /// How long the inviting device waits for its user's Accept (desktop `lan_sync.ACCEPT_TIMEOUT_SECONDS`).
    public static let acceptTimeoutSeconds = 60
    /// How long the new device waits for the reply after sending its request (`ENROLL_REPLY_SECONDS`).
    public static let replySeconds = acceptTimeoutSeconds + 15
    /// Longest device name in a request, in UTF-8 bytes (the keyring's member name rule).
    public static let maxNameBytes = 64
    /// The name the phone gives itself when no other is passed (generic, like the keyring's member name).
    public static let defaultName = "iPhone"

    static let requestInfo = Array("localgatekeys|sync|enroll-request|v1|".utf8)
    static let replyInfo = Array("localgatekeys|sync|enroll-reply|v1|".utf8)
    static let macLabel = Array("localgatekeys|sync|enroll-mac|v1|".utf8)
    static let sigLabel = Array("localgatekeys|sync|enroll-sig|v1|".utf8)
    static let replySigLabel = Array("localgatekeys|sync|enroll-reply-sig|v1|".utf8)
    static let verifyLabel = Array("localgatekeys|sync|enroll-verify|v2|".utf8)
    static let requestFields: Set<String> = ["version", "offer_id", "device_id", "signing_public", "exchange_public",
                                             "endpoint", "name", "signature", "mac"]
    static let replyFields: Set<String> = ["group_id", "epoch", "key", "device_id", "signing_public"]

    /// The verified content of an enrollment request (inviter side).
    public struct Request: Equatable, Sendable {
        public let deviceID: String
        public let signingPublic: [UInt8]
        public let exchangePublic: [UInt8]
        public let endpoint: LanEndpoint?
        public let transcript: [UInt8]
        /// The decrypted body as received.
        public let body: [UInt8]
        /// The new device's name for the Accept prompt.
        public let name: String

        /// The verification code both screens show (`verificationCode`).
        public var code: String { Enrollment.verificationCode(transcript: transcript) }
    }

    /// `check_device_name`: 1 ... 64 UTF-8 bytes, no character below U+0020 and no U+007F.
    public static func checkName(_ name: String) throws -> String {
        guard !name.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) else {
            throw PairingError.malformed("Device name is malformed")
        }
        guard (1...maxNameBytes).contains(name.utf8.count) else { throw PairingError.malformed("Device name must be 1..64 UTF-8 bytes") }
        return name
    }

    /// `verification_code`: the first 4 bytes of SHA-256(`enroll-verify|v2|` + transcript) as a big-endian
    /// unsigned integer, modulo 10^6, as 6 ASCII digits (zero-padded).
    public static func verificationCode(transcript: [UInt8]) -> String {
        let d = Array(SHA256.hash(data: verifyLabel + transcript))
        let n = (UInt32(d[0]) << 24 | UInt32(d[1]) << 16 | UInt32(d[2]) << 8 | UInt32(d[3])) % 1_000_000
        let digits = String(n)
        return String(repeating: "0", count: 6 - digits.count) + digits
    }

    /// `enrollment_transcript` (version 2: with `invitee_name`; ASCII canonical JSON escapes a
    /// non-ASCII name as `\uXXXX`).
    public static func transcript(offer: PairingOffer, deviceID: String, signingPublic: [UInt8],
                                  exchangePublic: [UInt8], endpoint: LanEndpoint?, name: String) throws -> [UInt8] {
        guard Identifier.isValid(deviceID) else { throw PairingError.malformed("invitee device id is malformed") }
        return try Pairing.canonical(.object([
            "protocol": .string("localgatekeys-sync-enrollment"), "version": .int(version),
            "offer": offer.publicJSON, "code": .string(offer.code),
            "invitee_device_id": .string(deviceID),
            "invitee_signing_public": .string(Base64.encode(signingPublic)),
            "invitee_exchange_public": .string(Base64.encode(exchangePublic)),
            "invitee_endpoint": endpoint?.json ?? .null,
            "invitee_name": .string(try checkName(name)),
        ]))
    }

    /// The code this device shows while it waits for the reply to its request for `offer` (the same
    /// transcript as `buildRequest` with the same `endpoint` and `name`).
    public static func verificationCode(offer: PairingOffer, identity: DeviceIdentity, endpoint: LanEndpoint? = nil,
                                        name: String = defaultName) throws -> String {
        let ep = try endpoint.map { try LanEndpoint(validating: $0.host, port: $0.port) }
        return verificationCode(transcript: try transcript(offer: offer, deviceID: identity.deviceID,
                                                           signingPublic: identity.signingPublicKey,
                                                           exchangePublic: identity.exchangePublicKey, endpoint: ep, name: name))
    }

    static func mac(_ offer: PairingOffer, _ transcript: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: macLabel + transcript, using: SymmetricKey(data: offer.pairingSecret)))
    }

    /// The new device's one request for a scanned offer: `LGKENROLL1\n` + canonical JSON. `name` is
    /// shown on the inviting device's Accept prompt (and must be passed again to `openReply`).
    /// Randomness: the 32-byte ephemeral X25519 private key, then the 12-byte nonce.
    public static func buildRequest(offer: PairingOffer, identity: DeviceIdentity, endpoint: LanEndpoint? = nil,
                                    name: String = defaultName, random: some RandomSource, now: some UnixClock) throws -> [UInt8] {
        try offer.check(now: now.now)
        guard identity.deviceID != offer.inviterDeviceID else {
            throw PairingError.authentication("A distinct invitee device identity is required")
        }
        let ep = try endpoint.map { try LanEndpoint(validating: $0.host, port: $0.port) }
        let transcript = try transcript(offer: offer, deviceID: identity.deviceID, signingPublic: identity.signingPublicKey,
                                        exchangePublic: identity.exchangePublicKey, endpoint: ep, name: name)
        let body = try Pairing.canonical(.object([
            "version": .int(version), "offer_id": .string(offer.offerID), "device_id": .string(identity.deviceID),
            "signing_public": .string(Base64.encode(identity.signingPublicKey)),
            "exchange_public": .string(Base64.encode(identity.exchangePublicKey)),
            "endpoint": ep?.json ?? .null, "name": .string(name),
            "signature": .string(Base64.encode(try identity.sign(sigLabel + transcript))),
            "mac": .string(Base64.encode(mac(offer, transcript))),
        ]))
        let ephPrivate = random.bytes(count: 32)
        let nonce = random.bytes(count: 12)
        guard nonce.count == 12 else { throw PairingError.malformed("Enrollment nonce is malformed") }
        let (shared, ephPublic): ([UInt8], [UInt8])
        do { (shared, ephPublic) = try DeviceIdentity.x25519(privateKey: ephPrivate, peerPublic: offer.inviterExchangePublic) }
        catch { throw PairingError.authentication("Inviter exchange key is unusable") }
        let key = CryptoBox.hkdf(ikm: shared, salt: offer.transcriptNonce, info: requestInfo + Array(offer.offerID.utf8), length: 32)
        let header: [String: JSONValue] = ["offer_id": .string(offer.offerID), "eph": .string(Base64.encode(ephPublic))]
        let ct = try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: body, aad: try Pairing.canonical(.object(header)))
        var outer = header
        outer["nonce"] = .string(Base64.encode(nonce))
        outer["ct"] = .string(Base64.encode(ct))
        let raw = requestMagic + (try Pairing.canonical(.object(outer)))
        guard raw.count <= maxBytes else { throw PairingError.malformed("Enrollment request is too large") }
        return raw
    }

    /// Inviter side (`_decrypt_enrollment_request` + `_verify_enrollment_body`): decrypt with the
    /// inviter's exchange key, then check the body, MAC and signature.
    public static func openRequest(offer: PairingOffer, inviter: DeviceIdentity, raw: [UInt8]) throws -> Request {
        try verifyRequestBody(offer: offer, plain: try decryptRequest(offer: offer, inviter: inviter, raw: raw))
    }

    /// `_decrypt_enrollment_request`: size, magic, JSON shape, offer id and AES-GCM (never an attempt).
    static func decryptRequest(offer: PairingOffer, inviter: DeviceIdentity, raw: [UInt8]) throws -> [UInt8] {
        guard raw.count <= maxBytes, raw.starts(with: requestMagic) else { throw PairingError.malformed("Enrollment request is malformed") }
        guard case .object(let outer) = try Pairing.strictJSON(Array(raw[requestMagic.count...])),
              Set(outer.keys) == ["offer_id", "eph", "nonce", "ct"] else { throw PairingError.malformed("Enrollment request is malformed") }
        guard outer["offer_id"] == .string(offer.offerID) else { throw PairingError.authentication("Enrollment request is for another offer") }
        let eph = try Pairing.b64(outer["eph"], length: 32, "enrollment key")
        let nonce = try Pairing.b64(outer["nonce"], length: 12, "enrollment nonce")
        guard case .string(let ctText)? = outer["ct"], let ct = try? Base64.decodeStrict(ctText),
              let shared = try? inviter.exchange(with: eph) else {
            throw PairingError.authentication("Enrollment request cannot be opened")
        }
        let key = CryptoBox.hkdf(ikm: shared, salt: offer.transcriptNonce, info: requestInfo + Array(offer.offerID.utf8), length: 32)
        let aad = try Pairing.canonical(.object(["offer_id": outer["offer_id"]!, "eph": outer["eph"]!]))
        guard let plain = try? CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: ct, aad: aad) else {
            throw PairingError.authentication("Enrollment request authentication failed")
        }
        return plain
    }

    /// `_verify_enrollment_body`: the checks after a successful decrypt (they count as attempts).
    static func verifyRequestBody(offer: PairingOffer, plain: [UInt8]) throws -> Request {
        guard case .object(let body) = try Pairing.strictJSON(plain) else { throw PairingError.malformed("Enrollment request is malformed") }
        if case .int(let v)? = body["version"], v < version, body["offer_id"] == .string(offer.offerID) {
            // Desktop `EnrollmentOutdated`: the inviter answers `update-needed`.
            throw PairingError.refused("update-needed")
        }
        guard Set(body.keys) == requestFields, body["version"] == .int(version), body["offer_id"] == .string(offer.offerID) else {
            throw PairingError.malformed("Enrollment request is malformed")
        }
        let deviceID = try Pairing.ident(body["device_id"], "invitee device id")
        guard deviceID != offer.inviterDeviceID else { throw PairingError.authentication("This device id is already in use in the group") }
        let signing = try Pairing.b64(body["signing_public"], length: 32, "invitee signing key")
        let exchange = try Pairing.b64(body["exchange_public"], length: 32, "invitee exchange key")
        let endpoint: LanEndpoint?
        switch body["endpoint"] {
        case .null?: endpoint = nil
        case .object(let e)? where Set(e.keys) == ["host", "port"]: endpoint = try Pairing.endpoint(host: e["host"], port: e["port"])
        default: throw PairingError.malformed("Enrollment endpoint is malformed")
        }
        guard case .string(let rawName)? = body["name"] else { throw PairingError.malformed("Device name is malformed") }
        let name = try checkName(rawName)
        let transcript = try transcript(offer: offer, deviceID: deviceID, signingPublic: signing, exchangePublic: exchange,
                                        endpoint: endpoint, name: name)
        let mac = try Pairing.b64(body["mac"], length: 32, "enrollment mac")
        guard Keyring.constantTimeEqual(mac, self.mac(offer, transcript)) else { throw PairingError.authentication("Enrollment does not prove the pairing secret") }
        let sig = try Pairing.b64(body["signature"], length: 64, "enrollment signature")
        guard DeviceIdentity.verify(signature: sig, message: sigLabel + transcript, publicKey: signing) else {
            throw PairingError.authentication("Enrollment signature is invalid")
        }
        return Request(deviceID: deviceID, signingPublic: signing, exchangePublic: exchange, endpoint: endpoint,
                       transcript: transcript, body: plain, name: name)
    }

    /// The refusal frame the inviter sends for `reason` (`LGKENROLLNO1\n` + canonical `{"reason"}`).
    public static func refusal(_ reason: String) throws -> [UInt8] {
        guard refusalReasons.contains(reason) else { throw PairingError.malformed("Unknown refusal reason") }
        return refusedMagic + (try Pairing.canonical(.object(["reason": .string(reason)])))
    }

    /// New-device side: verify the inviter's reply against the QR-pinned key and return the group key.
    /// `endpoint` and `name` are the ones this device announced in its request. A refusal throws
    /// `PairingError.refused` with one of `refusalReasons` (an unknown reason reads as `refused`).
    public static func openReply(offer: PairingOffer, identity: DeviceIdentity, raw: [UInt8],
                                 endpoint: LanEndpoint? = nil, name: String = defaultName) throws -> GroupKey {
        if raw.starts(with: refusedMagic) {
            var reason = "refused"
            if case .object(let o)? = try? CanonicalJSON.parse(Array(raw[refusedMagic.count...])),
               case .string(let r)? = o["reason"], refusalReasons.contains(r) { reason = r }
            throw PairingError.refused(reason)
        }
        guard raw.count <= maxBytes, raw.starts(with: replyMagic) else { throw PairingError.malformed("Enrollment reply is malformed") }
        guard case .object(let outer) = try Pairing.strictJSON(Array(raw[replyMagic.count...])),
              Set(outer.keys) == ["eph", "nonce", "ct", "sig"] else { throw PairingError.malformed("Enrollment reply is malformed") }
        let ep = try endpoint.map { try LanEndpoint(validating: $0.host, port: $0.port) }
        let transcript = try transcript(offer: offer, deviceID: identity.deviceID, signingPublic: identity.signingPublicKey,
                                        exchangePublic: identity.exchangePublicKey, endpoint: ep, name: name)
        let bound = Array(SHA256.hash(data: transcript))
        let header = try Pairing.canonical(.object(["eph": outer["eph"]!, "nonce": outer["nonce"]!]))
        let eph = try Pairing.b64(outer["eph"], length: 32, "reply key")
        let nonce = try Pairing.b64(outer["nonce"], length: 12, "reply nonce")
        guard case .string(let ctText)? = outer["ct"], let ct = try? Base64.decodeStrict(ctText) else {
            throw PairingError.malformed("Enrollment reply is malformed")
        }
        let sig = try Pairing.b64(outer["sig"], length: 64, "reply signature")
        guard DeviceIdentity.verify(signature: sig, message: replySigLabel + bound + header + ct, publicKey: offer.inviterSigningPublic),
              let shared = try? identity.exchange(with: eph),
              let plain = try? CryptoBox.openGCM(key: CryptoBox.hkdf(ikm: shared, salt: bound, info: replyInfo + Array(offer.offerID.utf8), length: 32),
                                                 nonce: nonce, ciphertext: ct, aad: header + bound) else {
            throw PairingError.authentication("Enrollment reply is not from the pinned inviter")
        }
        guard case .object(let body) = try Pairing.strictJSON(plain), Set(body.keys) == replyFields else {
            throw PairingError.malformed("Enrollment reply is malformed")
        }
        guard body["device_id"] == .string(identity.deviceID),
              body["signing_public"] == .string(Base64.encode(identity.signingPublicKey)) else {
            throw PairingError.authentication("Inviter pinned another device identity")
        }
        guard body["group_id"] == .string(offer.groupID), case .int(let epoch)? = body["epoch"], epoch >= 1 else {
            throw PairingError.malformed("Enrollment reply group is malformed")
        }
        let key = try Pairing.b64(body["key"], length: 32, "group key")
        do { return try GroupKey(groupID: offer.groupID, epoch: epoch, key: key) }
        catch { throw PairingError.malformed("Enrollment reply group is malformed") }
    }
}
