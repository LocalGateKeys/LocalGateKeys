/// Keyring writers (desktop `keyring.create_group`, `create_for_existing_group` and `rotate`); joining and
/// attaching (a device adding itself as a member) are in `KeyringJoin.swift`.
///
/// Random draw order matches the desktop, so a fixed stream gives the desktop's bytes (up to the Ed25519
/// proof of a member this device signs, which CryptoKit hedges): `create` draws G (32), the KDF salt (16),
/// the password-wrap nonce (12), then the member's device wrap (eph 32, nonce 12) and name nonce (12);
/// `createForExistingGroup` the same without G; `rotate` like `create` with a wrap and name nonce per
/// remaining member in member order. The public `create` first draws the uuid4 group id (16).
extension Keyring {
    public static let minPasswordLength = 12
    public static let minPasswordScore = 3
    /// Re-encrypted in place of a member name that cannot be read when rotating (desktop `UNNAMED_DEVICE`).
    public static let unnamedDevice = "Unnamed device"

    /// Argon2id of `password` with `salt` at the format parameters; tests inject a known table instead.
    typealias KeyDerivation = @Sendable (_ password: String, _ salt: [UInt8]) throws -> [UInt8]

    static let productionKDF: KeyDerivation = { password, salt in
        do {
            return try Argon2id.derive(password: Array(password.utf8), salt: salt, memoryKiB: UInt32(kdfMemoryKiB),
                                       iterations: UInt32(kdfIterations), parallelism: UInt32(kdfParallelism),
                                       length: keyLen)
        } catch { throw KeyringError("bad-kdf", "argon2id failed") }
    }

    /// Desktop `_check_password`: at least 12 characters and a strength score of 3 (`weak-password`).
    public static func checkPassword(_ password: String) throws {
        guard password.unicodeScalars.count >= minPasswordLength,
              PasswordStrength.estimate(password).score >= minPasswordScore else {
            throw KeyringError("weak-password", "sync password is too short or too easy to guess")
        }
    }

    /// A member to write: its id, plaintext name, base64 exchange key, `added_at`, and either the identity
    /// that signs a new proof or the carried `signing_public` / `signing_proof` (null for a format-1 member).
    struct NewMember {
        enum Signing { case identity(DeviceIdentity), carried(JSONValue, JSONValue) }
        var deviceID: String
        var name: String
        var exchangePublic: String
        var signing: Signing
        var addedAt: Int64
    }

    static func newMember(_ identity: DeviceIdentity, name: String, now: UnixClock) throws -> NewMember {
        let addedAt = now.now
        guard addedAt >= 0, addedAt <= maxInt else { throw KeyringError("bad-fields", "added_at") }
        return NewMember(deviceID: identity.deviceID, name: name, exchangePublic: Base64.encode(identity.exchangePublicKey),
                         signing: .identity(identity), addedAt: addedAt)
    }

    /// (entry, wrap) of `member` (desktop `_member_entry`): draws the wrap, then the name nonce.
    static func memberEntry(_ gk: GroupKey, _ member: NewMember, random: RandomSource) throws -> (JSONValue, JSONValue) {
        let wrap = try wrapDevice(gk, deviceID: member.deviceID,
                                  exchangePublic: try b64(.string(member.exchangePublic), 32, "exchange_public"), random: random)
        let signingPublic: JSONValue, proof: JSONValue
        switch member.signing {
        case .identity(let identity):
            let key = Base64.encode(identity.signingPublicKey)
            do {
                let sig = try identity.sign(proofMessage(groupID: gk.groupID, deviceID: member.deviceID,
                                                         exchangePublic: member.exchangePublic, signingPublic: key))
                signingPublic = .string(key); proof = .string(Base64.encode(sig))
            } catch { throw KeyringError("bad-member-key", "signing key unusable") }
        case .carried(let key, let carriedProof):
            signingPublic = key; proof = carriedProof
        }
        let entry: JSONValue = .object([
            "device_id": .string(member.deviceID),
            "name_ct": .string(try sealName(gk, deviceID: member.deviceID, name: member.name, random: random)),
            "exchange_public": .string(member.exchangePublic),
            "signing_public": signingPublic,
            "signing_proof": proof,
            "added_at": .int(member.addedAt),
        ])
        return (entry, wrap)
    }

    /// A new epoch's body (desktop `_fresh_body`): salt, password wrap, then each member.
    static func freshBody(_ gk: GroupKey, password: String, members: [NewMember], random: RandomSource,
                          derive: KeyDerivation) throws -> [String: JSONValue] {
        let salt = try draw(random, kdfSaltLen)
        let nonce = try draw(random, nonceLen)
        let ct: [UInt8]
        do {
            ct = try CryptoBox.sealGCM(key: try derive(password, salt), nonce: nonce, plaintext: gk.key,
                                       aad: passwordAAD(gk.groupID, gk.epoch))
        } catch let e as KeyringError { throw e } catch { throw KeyringError("bad-kdf", "\(error)") }
        var entries: [JSONValue] = []
        var wraps: [String: JSONValue] = [:]
        for member in members {
            let (entry, wrap) = try memberEntry(gk, member, random: random)
            entries.append(entry); wraps[member.deviceID] = wrap
        }
        return [
            "format": .int(format),
            "group_id": .string(gk.groupID),
            "epoch": .int(gk.epoch),
            "kdf": .object(["name": .string(kdfName), "salt": .string(Base64.encode(salt)),
                            "memory_kib": .int(kdfMemoryKiB), "iterations": .int(kdfIterations),
                            "parallelism": .int(kdfParallelism)]),
            "password_wrap": .object(["nonce": .string(Base64.encode(nonce)), "ct": .string(Base64.encode(ct))]),
            "device_wraps": .object(wraps),
            "members": .array(entries),
        ]
    }

    /// `body` with `prev_mac` (the chain from `prev`, or null) and `mac` set.
    static func finish(_ body: [String: JSONValue], key gk: GroupKey, prev: GroupKey?) throws -> JSONValue {
        var out = body
        out["prev_mac"] = prev.map { .string(Base64.encode(chainMac(old: $0, new: gk))) } ?? .null
        return try finish(out, key: gk)
    }

    // MARK: create

    /// Create a new group (epoch 1, uuid4 group id) with `identity` as its only member (desktop `create_group`).
    public static func create(password: String, identity: DeviceIdentity, name: String, random: RandomSource,
                              now: UnixClock) throws -> (JSONValue, GroupKey) {
        try create(password: password, identity: identity, name: name, groupID: nil, random: random, now: now,
                   derive: productionKDF)
    }

    /// `share`: a share group owned by `identity` (`bad-metadata` first when the description is malformed); the
    /// collection name is sealed under G (one more nonce) and the owner signs the roster. `shareFormat` 3 (the
    /// default, share v2) then draws the content key C (32) and the owner's content wrap (eph 32, nonce 12); 2 writes
    /// a share v1 keyring (only the legacy vectors and the migration tests); anything else is `bad-format`.
    static func create(password: String, identity: DeviceIdentity, name: String, groupID: String?, random: RandomSource,
                       now: UnixClock, derive: KeyDerivation, share: ShareKeyring.Spec? = nil,
                       shareFormat: Int64 = Keyring.shareFormat) throws -> (JSONValue, GroupKey) {
        guard shareFormat == format || shareFormat == Keyring.shareFormat else {
            throw KeyringError("bad-format", "unsupported share format")
        }
        try share?.check()
        try checkPassword(password)
        try checkIdentity(identity)
        _ = try checkName(name)
        let gid = try groupID ?? SyncGroup.uuid4(random: random)
        let gk = try groupKey(gid, 1, try draw(random, keyLen))
        var body = try freshBody(gk, password: password, members: [try newMember(identity, name: name, now: now)],
                                 random: random, derive: derive)
        if let share {
            body["metadata"] = .object([
                "kind": .string(ShareKeyring.kind),
                "collection_id": .string(share.collectionID),
                "name_ct": .string(try ShareKeyring.sealName(gk, collectionID: share.collectionID, name: share.name,
                                                             random: random)),
                "shared_mode": .string(share.sharedMode),
                "owner": .string(identity.deviceID),
                "owner_key": .string(Base64.encode(identity.signingPublicKey)),
            ])
            var content: GroupKey? = nil
            if shareFormat == Keyring.shareFormat {
                body["format"] = .int(Keyring.shareFormat)
                body["prev_mac"] = .null  // signed by the owner (share v2)
                content = try groupKey(gk.groupID, gk.epoch, try draw(random, keyLen))
            }
            body = try ShareKeyring.signOwner(body, identity: identity, approve: nil, content: content, random: random)
        }
        return (try finish(body, key: gk, prev: nil), gk)
    }

    /// The first keyring of an existing group (`gk` from Wi-Fi enrollment), `identity` its only member;
    /// `prev_mac` null at any epoch (desktop `create_for_existing_group`).
    public static func createForExistingGroup(_ gk: GroupKey, password: String, identity: DeviceIdentity, name: String,
                                              random: RandomSource, now: UnixClock) throws -> JSONValue {
        try createForExistingGroup(gk, password: password, identity: identity, name: name, random: random, now: now,
                                   derive: productionKDF)
    }

    static func createForExistingGroup(_ gk: GroupKey, password: String, identity: DeviceIdentity, name: String,
                                       random: RandomSource, now: UnixClock, derive: KeyDerivation) throws -> JSONValue {
        try checkPassword(password)
        try checkIdentity(identity)
        _ = try checkName(name)
        let body = try freshBody(gk, password: password, members: [try newMember(identity, name: name, now: now)],
                                 random: random, derive: derive)
        return try finish(body, key: gk, prev: nil)
    }

    // MARK: rotate

    /// New G, epoch + 1, new salt and a NEW sync password; drops the `remove` devices (desktop `rotate`).
    /// Reasons: `weak-password`, the `accept` reasons, `stale-trust`, `cannot-remove-self`, `not-member`,
    /// `password-reused`. Every remaining member keeps its keys, proof and `added_at`; names are re-encrypted
    /// under the new epoch (`Unnamed device` for one that cannot be read).
    public static func rotate(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity, newPassword: String,
                              remove: [String] = [], random: RandomSource) throws -> (JSONValue, GroupKey) {
        try rotate(ring, trusted: trusted, identity: identity, newPassword: newPassword, remove: remove, random: random,
                   derive: productionKDF)
    }

    /// Change the sync password (a rotation that keeps every member).
    public static func changePassword(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity, newPassword: String,
                                      random: RandomSource) throws -> (JSONValue, GroupKey) {
        try rotate(ring, trusted: trusted, identity: identity, newPassword: newPassword, remove: [], random: random)
    }

    /// `share`: `ring` may be a share keyring; then only its owner rotates (`not-owner`, raised after the draws) and the
    /// collection name is re-sealed for the new epoch (one more nonce). A share v1 rotation approves every remaining
    /// member. A share v2 keyring (format 3), or a share v1 one with `upgrade` (`not-share` for a personal keyring),
    /// is written as share v2: after the name nonce it draws the new content key C (32), then one content wrap per
    /// approved member in id order; the approved members are the previous ones minus `remove` (the owner always).
    /// `allowSamePassword` (the upgrade only) skips `password-reused`.
    static func rotate(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity, newPassword: String,
                       remove: [String], random: RandomSource, derive: KeyDerivation,
                       share: Bool = false, upgrade: Bool = false,
                       allowSamePassword: Bool = false) throws -> (JSONValue, GroupKey) {
        try checkPassword(newPassword)
        let gk = try accept(ring, trusted: trusted, identity: identity, share: share)
        guard gk.epoch == trusted.epoch else { throw KeyringError("stale-trust", "adopt the current keyring before rotating") }
        if upgrade && obj(ring)["metadata"] == nil {
            throw KeyringError("not-share", "a personal keyring has no share version")
        }
        _ = try member(ring, identity)
        let members = arr(obj(ring)["members"]).map { obj($0) }
        let drop = Set(remove)
        let have = Set(members.compactMap { str($0["device_id"]) })
        if drop.contains(identity.deviceID) { throw KeyringError("cannot-remove-self", "a device cannot remove itself") }
        guard drop.isSubset(of: have) else { throw KeyringError("not-member", "device to remove is not a member") }
        let salt = try b64(obj(obj(ring)["kdf"])["salt"], kdfSaltLen, "kdf salt")
        if !allowSamePassword, (try? unwrap(ring, passwordKey: try derive(newPassword, salt))) != nil {
            throw KeyringError("password-reused", "choose a sync password different from the current one")
        }
        let newKey = try groupKey(gk.groupID, gk.epoch + 1, try draw(random, keyLen))
        let names = memberNames(ring, key: gk)
        let remaining: [NewMember] = members.compactMap { m in
            guard let id = str(m["device_id"]), !drop.contains(id) else { return nil }
            return NewMember(deviceID: id, name: (names[id] ?? nil) ?? unnamedDevice,
                             exchangePublic: str(m["exchange_public"]) ?? "",
                             signing: .carried(m["signing_public"] ?? .null, m["signing_proof"] ?? .null),
                             addedAt: int(m["added_at"]) ?? 0)
        }
        var body = try freshBody(newKey, password: newPassword, members: remaining, random: random, derive: derive)
        if case .object(let old)? = obj(ring)["metadata"] {
            guard let cid = str(old["collection_id"]) else { throw KeyringError("bad-metadata", "collection_id") }
            var meta = old
            meta["name_ct"] = .string(try ShareKeyring.sealName(newKey, collectionID: cid,
                                                                name: try ShareKeyring.shareName(ring, key: gk), random: random))
            body["metadata"] = .object(meta)
            if upgrade || int(obj(ring)["format"]) == Keyring.shareFormat {
                body["format"] = .int(Keyring.shareFormat)
                // Signed by the owner (share v2); `finish` writes the same chain MAC.
                body["prev_mac"] = .string(Base64.encode(chainMac(old: gk, new: newKey)))
                let content = try groupKey(newKey.groupID, newKey.epoch, try draw(random, keyLen))
                let dropBytes = Set(drop.map { Array($0.utf8) })
                let keep = (ShareKeyring.approvedMembers(ring) ?? []).filter { !dropBytes.contains(Array($0.utf8)) }
                body = try ShareKeyring.signOwner(body, identity: identity, approve: keep, content: content, random: random)
            } else {
                body = try ShareKeyring.signOwner(body, identity: identity, approve: nil)
            }
        }
        return (try finish(body, key: newKey, prev: gk), newKey)
    }
}
