import Crypto

/// Host side of the enrollment reply (desktop `pairing.seal_enrollment_reply`).
extension Enrollment {
    /// The group key for an accepted `request`, sealed to the new device: `LGKENROLLOK1\n` + canonical
    /// `{"ct","eph","nonce","sig"}`. Randomness: the 32-byte ephemeral X25519 private key, then the 12-byte nonce.
    public static func sealReply(inviter: DeviceIdentity, offer: PairingOffer, request: Request,
                                 groupKey: GroupKey, random: some RandomSource) throws -> [UInt8] {
        try sealReply(inviter: inviter, offer: offer, request: request, groupKey: groupKey, random: random,
                      sign: { try inviter.sign($0) })
    }

    /// `sign` is the inviter's Ed25519 signer; tests pass the desktop's deterministic signature to pin the bytes.
    static func sealReply(inviter: DeviceIdentity, offer: PairingOffer, request: Request, groupKey: GroupKey,
                          random: some RandomSource, sign: ([UInt8]) throws -> [UInt8]) throws -> [UInt8] {
        guard groupKey.epoch >= 1, groupKey.key.count == 32 else { throw PairingError.malformed("Group key is malformed") }
        guard Identifier.isValid(groupKey.groupID) else { throw PairingError.malformed("group id is malformed") }
        let bound = Array(SHA256.hash(data: request.transcript))
        let ephPrivate = random.bytes(count: 32)
        let nonce = random.bytes(count: 12)
        guard nonce.count == 12 else { throw PairingError.malformed("Enrollment nonce is malformed") }
        let (shared, ephPublic): ([UInt8], [UInt8])
        do { (shared, ephPublic) = try DeviceIdentity.x25519(privateKey: ephPrivate, peerPublic: request.exchangePublic) }
        catch { throw PairingError.authentication("Invitee exchange key is unusable") }
        let secret = CryptoBox.hkdf(ikm: shared, salt: bound, info: replyInfo + Array(offer.offerID.utf8), length: 32)
        let header: [String: JSONValue] = ["eph": .string(Base64.encode(ephPublic)), "nonce": .string(Base64.encode(nonce))]
        let headerBytes = try Pairing.canonical(.object(header))
        let body = try Pairing.canonical(.object([
            "group_id": .string(groupKey.groupID), "epoch": .int(groupKey.epoch), "key": .string(Base64.encode(groupKey.key)),
            "device_id": .string(request.deviceID), "signing_public": .string(Base64.encode(request.signingPublic)),
        ]))
        let ct = try CryptoBox.sealGCM(key: secret, nonce: nonce, plaintext: body, aad: headerBytes + bound)
        let sig: [UInt8]
        do { sig = try sign(replySigLabel + bound + headerBytes + ct) }
        catch { throw PairingError.malformed("Signed transcript is malformed") }
        var outer = header
        outer["ct"] = .string(Base64.encode(ct))
        outer["sig"] = .string(Base64.encode(sig))
        return replyMagic + (try Pairing.canonical(.object(outer)))
    }
}
