import Crypto

/// One-use network enrollment, new-device side (desktop `pairing.build_enrollment_request` /
/// `open_enrollment_reply`), plus the inviter-side request opener used to check the format.
///
/// Version 2 (Accept step): the request names the new device (`name`, also `invitee_name` in the
/// transcript); both screens show the 6-digit `verificationCode` of the transcript, and the inviting
/// device answers only after its user chose Accept (within `acceptTimeoutSeconds`), so the new device
/// waits up to `replySeconds` for the reply.
///
/// Version 3 (commit-then-reveal, docs/formats/LAN_SYNC_V3.md section 3), for a version-2 offer: the QR
/// carries a commitment to a 32-byte reveal; the inviter sends the reveal (`revealMagic` frame) only after a
/// request decrypted and verified, before its reply; the code covers the reveal (`verificationCode(transcript:
/// reveal:)`), and the new device shows it only after the reveal matched the commitment.
public enum Enrollment {
    public static let requestMagic = Array("LGKENROLL1\n".utf8)
    public static let replyMagic = Array("LGKENROLLOK1\n".utf8)
    public static let refusedMagic = Array("LGKENROLLNO1\n".utf8)
    /// The inviter's interim frame for a version-2 offer (desktop `ENROLL_REVEAL_MAGIC`).
    public static let revealMagic = Array("LGKENROLLRV1\n".utf8)
    /// Longest reveal frame the new device reads.
    public static let maxRevealBytes = 256
    public static let maxBytes = 16 * 1024
    /// Version of the request body and transcript for a version-2 offer (`ENROLL_VERSION`; 2 added the name and
    /// the Accept step, 3 the commit-then-reveal code).
    public static let version: Int64 = 3
    /// The version for a version-1 offer (`LEGACY_ENROLL_VERSION`).
    public static let legacyVersion: Int64 = 2
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
    static let verifyLabelV3 = Array("localgatekeys|sync|enroll-verify|v3|".utf8)
    static let commitLabel = Array("localgatekeys|sync|enroll-commit|v3|".utf8)
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
        /// The inviter's reveal (a version-2 offer), which the code covers; nil for a version-1 offer.
        let reveal: [UInt8]?

        init(deviceID: String, signingPublic: [UInt8], exchangePublic: [UInt8], endpoint: LanEndpoint?,
             transcript: [UInt8], body: [UInt8], name: String, reveal: [UInt8]? = nil) {
            self.deviceID = deviceID; self.signingPublic = signingPublic; self.exchangePublic = exchangePublic
            self.endpoint = endpoint; self.transcript = transcript; self.body = body; self.name = name; self.reveal = reveal
        }

        /// The verification code both screens show (`verificationCode`).
        public var code: String { Enrollment.verificationCode(transcript: transcript, reveal: reveal) }
    }

    /// `enroll_version`: 3 for a version-2 offer (it has a commitment), 2 for a version-1 offer.
    public static func enrollVersion(for offer: PairingOffer) -> Int64 { offer.commit != nil ? version : legacyVersion }

    /// `enrollment_commit`: SHA-256(`enroll-commit|v3|` + reveal), the commitment of a version-2 offer.
    public static func commitment(_ reveal: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: commitLabel + reveal)) }

    /// `enrollment_reveal`: the interim frame payload for a verified request of a version-2 offer
    /// (`LGKENROLLRV1\n` + canonical `{"reveal"}`); nil for a version-1 offer. The offer must be the inviter's own.
    public static func revealFrame(offer: PairingOffer) throws -> [UInt8]? {
        guard offer.commit != nil else { return nil }
        guard let reveal = offer.reveal else { throw PairingError.malformed("This pairing offer was not created on this device") }
        return revealMagic + (try Pairing.canonical(.object(["reveal": .string(Base64.encode(reveal))])))
    }

    /// `open_enrollment_reveal`, new-device side: the reveal of the interim frame `raw`, checked against the
    /// QR's commitment (at most `maxRevealBytes`, exact field set, 32 bytes, a matching commitment).
    public static func openReveal(offer: PairingOffer, raw: [UInt8]) throws -> [UInt8] {
        guard let commit = offer.commit else { throw PairingError.malformed("This offer has no commitment") }
        guard raw.count <= maxRevealBytes, raw.starts(with: revealMagic) else { throw PairingError.malformed("Enrollment reveal is malformed") }
        guard case .object(let o) = try Pairing.strictJSON(Array(raw[revealMagic.count...])), Set(o.keys) == ["reveal"] else {
            throw PairingError.malformed("Enrollment reveal is malformed")
        }
        let reveal = try Pairing.b64(o["reveal"], length: 32, "pairing reveal")
        guard Keyring.constantTimeEqual(commitment(reveal), commit) else {
            throw PairingError.authentication("Enrollment reveal does not match the QR code")
        }
        return reveal
    }

    /// The verification code of a version-2 offer: the first 4 bytes of SHA-256(`enroll-verify|v3|` + transcript
    /// + reveal), big-endian, modulo 10^6, 6 digits. Without `reveal`: the version-2 code (`verificationCode(transcript:)`).
    public static func verificationCode(transcript: [UInt8], reveal: [UInt8]?) -> String {
        guard let reveal else { return verificationCode(transcript: transcript) }
        return sixDigits(Array(SHA256.hash(data: verifyLabelV3 + transcript + reveal)))
    }

    static func sixDigits(_ d: [UInt8]) -> String {
        let n = (UInt32(d[0]) << 24 | UInt32(d[1]) << 16 | UInt32(d[2]) << 8 | UInt32(d[3])) % 1_000_000
        let digits = String(n)
        return String(repeating: "0", count: 6 - digits.count) + digits
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
        sixDigits(Array(SHA256.hash(data: verifyLabel + transcript)))
    }

    /// `enrollment_transcript` (version 2: with `invitee_name`; ASCII canonical JSON escapes a
    /// non-ASCII name as `\uXXXX`; version 3 for a version-2 offer, `enrollVersion(for:)`).
    public static func transcript(offer: PairingOffer, deviceID: String, signingPublic: [UInt8],
                                  exchangePublic: [UInt8], endpoint: LanEndpoint?, name: String) throws -> [UInt8] {
        guard Identifier.isValid(deviceID) else { throw PairingError.malformed("invitee device id is malformed") }
        return try Pairing.canonical(.object([
            "protocol": .string("localgatekeys-sync-enrollment"), "version": .int(enrollVersion(for: offer)),
            "offer": offer.publicJSON, "code": .string(offer.code),
            "invitee_device_id": .string(deviceID),
            "invitee_signing_public": .string(Base64.encode(signingPublic)),
            "invitee_exchange_public": .string(Base64.encode(exchangePublic)),
            "invitee_endpoint": endpoint?.json ?? .null,
            "invitee_name": .string(try checkName(name)),
        ]))
    }

    /// The code this device shows while it waits for the reply to its request for `offer` (the same
    /// transcript as `buildRequest` with the same `endpoint` and `name`). For a version-2 offer `reveal` is the
    /// one `openReveal` returned: the code is shown only once it has arrived and matched.
    public static func verificationCode(offer: PairingOffer, identity: DeviceIdentity, endpoint: LanEndpoint? = nil,
                                        name: String = defaultName, reveal: [UInt8]? = nil) throws -> String {
        guard (offer.commit == nil) == (reveal == nil) else { throw PairingError.malformed("Pairing reveal is malformed") }
        let ep = try endpoint.map { try LanEndpoint(validating: $0.host, port: $0.port) }
        return verificationCode(transcript: try transcript(offer: offer, deviceID: identity.deviceID,
                                                           signingPublic: identity.signingPublicKey,
                                                           exchangePublic: identity.exchangePublicKey, endpoint: ep, name: name),
                                reveal: reveal)
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
            "version": .int(enrollVersion(for: offer)), "offer_id": .string(offer.offerID), "device_id": .string(identity.deviceID),
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
        let expected = enrollVersion(for: offer)
        if case .int(let v)? = body["version"], v < expected, body["offer_id"] == .string(offer.offerID) {
            // Desktop `EnrollmentOutdated`: the inviter answers `update-needed` (also a version-2 body for a
            // version-2 offer: without the reveal its code could be ground).
            throw PairingError.refused("update-needed")
        }
        guard Set(body.keys) == requestFields, body["version"] == .int(expected), body["offer_id"] == .string(offer.offerID) else {
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
                       transcript: transcript, body: plain, name: name, reveal: offer.reveal)
    }

    /// The refusal frame the inviter sends for `reason` (`LGKENROLLNO1\n` + canonical `{"reason"}`).
    public static func refusal(_ reason: String) throws -> [UInt8] {
        guard refusalReasons.contains(reason) else { throw PairingError.malformed("Unknown refusal reason") }
        return refusedMagic + (try Pairing.canonical(.object(["reason": .string(reason)])))
    }

    /// New-device side: verify the inviter's reply against the QR-pinned key and return the group key.
    /// `endpoint` and `name` are the ones this device announced in its request. A refusal throws
    /// `PairingError.refused` with one of `refusalReasons` (an unknown reason reads as `refused`).
    /// For a version-2 offer `reveal` must be the one `openReveal` returned (the one the shown code covered):
    /// a key reply without it is refused.
    public static func openReply(offer: PairingOffer, identity: DeviceIdentity, raw: [UInt8],
                                 endpoint: LanEndpoint? = nil, name: String = defaultName,
                                 reveal: [UInt8]? = nil) throws -> GroupKey {
        if raw.starts(with: refusedMagic) {
            var reason = "refused"
            if case .object(let o)? = try? CanonicalJSON.parse(Array(raw[refusedMagic.count...])),
               case .string(let r)? = o["reason"], refusalReasons.contains(r) { reason = r }
            throw PairingError.refused(reason)
        }
        guard raw.count <= maxBytes, raw.starts(with: replyMagic) else { throw PairingError.malformed("Enrollment reply is malformed") }
        if let commit = offer.commit {
            guard let reveal, reveal.count == 32, Keyring.constantTimeEqual(commitment(reveal), commit) else {
                throw PairingError.authentication("The inviting device sent no valid reveal before its reply")
            }
        }
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
