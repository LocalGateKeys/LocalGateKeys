extension Keyring {
    /// `ring` (authenticated under `gk`) plus `identity` and its wrap; `prev_mac` carried over. Written as
    /// format 2: the new entry lists this device's signing key and proof, and a format-1 member gets
    /// `signing_public` and `signing_proof` null. Draws the device wrap (eph 32, nonce 12), then the name
    /// nonce (12); the Ed25519 proof draws nothing from `random`.
    static func withMember(_ ring: JSONValue, gk: GroupKey, identity: DeviceIdentity, name: String,
                           random: RandomSource, now: UnixClock) throws -> JSONValue {
        let addedAt = now.now
        guard addedAt >= 0, addedAt <= maxInt else { throw KeyringError("bad-fields", "added_at") }
        var body = obj(ring)
        let wrap = try wrapDevice(gk, deviceID: identity.deviceID, exchangePublic: identity.exchangePublicKey, random: random)
        let exchange = Base64.encode(identity.exchangePublicKey), signing = Base64.encode(identity.signingPublicKey)
        let nameCT = try sealName(gk, deviceID: identity.deviceID, name: name, random: random)
        let proof: [UInt8]
        do {
            proof = try identity.sign(proofMessage(groupID: gk.groupID, deviceID: identity.deviceID,
                                                   exchangePublic: exchange, signingPublic: signing))
        } catch { throw KeyringError("bad-member-key", "signing key unusable") }
        let entry: JSONValue = .object([
            "device_id": .string(identity.deviceID),
            "name_ct": .string(nameCT),
            "exchange_public": .string(exchange),
            "signing_public": .string(signing),
            "signing_proof": .string(Base64.encode(proof)),
            "added_at": .int(addedAt),
        ])
        body["format"] = .int(format)   // a format-1 keyring is written back as format 2
        body["members"] = .array(arr(body["members"]).map(asFormat2) + [entry])
        var wraps = obj(body["device_wraps"]); wraps[identity.deviceID] = wrap
        body["device_wraps"] = .object(wraps)
        return try finish(body, key: gk)
    }

    /// `_as_format2`: a member entry in format 2 (a format-1 entry gets null `signing_public` and `signing_proof`).
    static func asFormat2(_ member: JSONValue) -> JSONValue {
        var o = obj(member)
        if o["signing_public"] == nil { o["signing_public"] = .null }
        if o["signing_proof"] == nil { o["signing_proof"] = .null }
        return .object(o)
    }

    static func checkIdentity(_ identity: DeviceIdentity) throws {
        guard Identifier.isValid(identity.deviceID) else {
            throw KeyringError("bad-device-id", "device id must be ASCII [A-Za-z0-9._:-], 1..128 chars")
        }
    }

    /// Join by sync password: open G, require the MAC, add this device, recompute the MAC.
    public static func join(_ ring: JSONValue, password: String, identity: DeviceIdentity, name: String,
                            random: RandomSource, now: UnixClock) throws -> (JSONValue, GroupKey) {
        try join(ring, identity: identity, name: name, random: random, now: now) { try passwordKey(ring, password: password) }
    }

    /// `join` with the Argon2id step injectable (tests pass a known key); the key is derived only after the cheap checks.
    static func join(_ ring: JSONValue, identity: DeviceIdentity, name: String, random: RandomSource, now: UnixClock,
                     passwordKey: () throws -> [UInt8]) throws -> (JSONValue, GroupKey) {
        try verifyStructure(ring)
        try checkIdentity(identity)
        _ = try checkName(name)
        let members = arr(obj(ring)["members"])
        if members.contains(where: { str(obj($0)["device_id"]) == identity.deviceID }) {
            throw KeyringError("already-member", "device is already a member")
        }
        guard members.count < maxMembers else { throw KeyringError("too-many-members", "the group already has 16 devices") }
        let gk = try unwrap(ring, passwordKey: try passwordKey())
        guard macOK(ring, key: gk) else { throw KeyringError("tampered", "keyring MAC does not verify under the group key") }
        return (try withMember(ring, gk: gk, identity: identity, name: name, random: random, now: now), gk)
    }

    /// Add a device that already holds `stored` (e.g. from Wi-Fi enrollment) to `ring`.
    /// Idempotent: returns `ring` unchanged when this identity is already listed with its own key and wrap.
    public static func attach(_ ring: JSONValue, password: String, identity: DeviceIdentity, name: String,
                              stored: GroupKey, random: RandomSource, now: UnixClock) throws -> JSONValue {
        try attach(ring, identity: identity, name: name, stored: stored, random: random, now: now) {
            try passwordKey(ring, password: password)
        }
    }

    static func attach(_ ring: JSONValue, passwordKey key: [UInt8], identity: DeviceIdentity, name: String,
                       stored: GroupKey, random: RandomSource, now: UnixClock) throws -> JSONValue {
        try attach(ring, identity: identity, name: name, stored: stored, random: random, now: now) { key }
    }

    static func attach(_ ring: JSONValue, identity: DeviceIdentity, name: String, stored: GroupKey,
                       random: RandomSource, now: UnixClock, passwordKey: () throws -> [UInt8]) throws -> JSONValue {
        try verifyStructure(ring)
        try checkIdentity(identity)
        _ = try checkName(name)
        let o = obj(ring)
        guard str(o["group_id"]) == stored.groupID else { throw KeyringError("different-group-key", "the folder holds another sync group") }
        guard int(o["epoch"]) == stored.epoch else { throw KeyringError("epoch-mismatch", "the folder's group key is from another epoch") }
        let members = arr(o["members"]).map { obj($0) }
        let listed = members.contains { str($0["device_id"]) == identity.deviceID }
        let ownKey = Base64.encode(identity.exchangePublicKey)
        if listed && !members.contains(where: { str($0["device_id"]) == identity.deviceID && str($0["exchange_public"]) == ownKey }) {
            throw KeyringError("already-member", "another device is listed under this device id")
        }
        if !listed && members.count >= maxMembers { throw KeyringError("too-many-members", "the group already has 16 devices") }
        let gk = try unwrap(ring, passwordKey: try passwordKey())
        guard constantTimeEqual(gk.key, stored.key) else {
            throw KeyringError("different-group-key", "the password opens a different group key")
        }
        guard macOK(ring, key: gk) else { throw KeyringError("tampered", "keyring MAC does not verify under the group key") }
        if listed {
            guard let own = try? unwrapDevice(ring, identity: identity), constantTimeEqual(own.key, stored.key) else {
                throw KeyringError("already-member", "device is already a member")
            }
            return ring
        }
        return try withMember(ring, gk: gk, identity: identity, name: name, random: random, now: now)
    }
}
