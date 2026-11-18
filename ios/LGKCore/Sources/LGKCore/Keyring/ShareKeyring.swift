import Crypto

/// Shared-collection keyrings (sub-plan 07; desktop `keyring.py` share fields and `share_group.py`; Kotlin
/// `ShareKeyring`). Byte for byte with `tests/vectors/share/collections/keyring.json`, up to the Ed25519 signatures
/// this device makes (CryptoKit hedges them; the desktop's deterministic ones verify here and ours there).
///
/// A share keyring is a format-2 keyring with two more top-level fields:
///
/// - `metadata`: `{"kind":"share","collection_id","name_ct","shared_mode","owner","owner_key"}`. The collection name is
///   sealed under the group key (`name_ct`, HKDF info `localgatekeys|sync|share-name|v1|<epoch>`, salt the group id,
///   AAD `lgk-keyring-share-name-v1|<group>|<epoch>|<collection>`); `owner` and `owner_key` are the owner device id and
///   its raw Ed25519 view-signing key, listed as that member's `signing_public`.
/// - `owner_sig`: `{"members":[approved ids, sorted],"sig"}`, the owner's Ed25519 signature over
///   `localgatekeys|sync|share-owner|v1|` + canonical JSON of `{group_id, epoch, metadata, members:[{device_id,
///   exchange_public, signing_public}] of the approved ids}`.
///
/// Every member holds G and can re-MAC a keyring, so the owner's signature is what gives the owner authority: only the
/// owner approves members, rotates and removes. Within one epoch a share keyring may only grow (`checkSameEpochGrowth`);
/// the owner id and key, collection id and mode are pinned at join (`Pin`) and never change.
///
/// Share v2 (keyring format 3; spec `docs/superpowers/specs/2026-11-12-collections-crypto-gating.md`, vectors
/// `gating.json`): one more top-level field `content` = `{"commit", "wraps": {device_id: {"eph","nonce","ct"}}}`. The
/// share's item views are sealed with a content key C (`openContentKey`) that the owner wraps only to the members it
/// approved, so the share password (which opens G) opens no item. `commit` = SHA-256(`localgatekeys|sync|share-content|v1|`
/// + group id + `|` + epoch + `|` + C); a content wrap is a device wrap of C with its own HKDF info
/// (`localgatekeys|sync|content-wrap|v1|` + device id) and AAD label (`lgk-keyring-content-wrap-v1|`). The wraps' keys
/// are exactly `owner_sig.members` (`bad-content`), and the owner signs v2 (`localgatekeys|sync|share-owner|v2|`, the
/// v1 body plus `content`), so only the owner adds, drops or swaps a wrap. Share v1 (format 2) keyrings are still read
/// and synced with G until the owner upgrades them (`upgrade`, or any removal).
public enum ShareKeyring {
    public static let kind = "share"
    public static let sharedModes: Set<String> = ["read", "edit"]
    public static let maxNameLen = 100
    static let nameCTMin = 12 + 1 + 16
    static let nameCTMax = 12 + 4 * maxNameLen + 16

    static let nameAAD = Array("lgk-keyring-share-name-v1|".utf8)
    static let nameInfo = Array("localgatekeys|sync|share-name|v1|".utf8)
    static let ownerSigLabel = Array("localgatekeys|sync|share-owner|v1|".utf8)
    static let ownerSigLabelV2 = Array("localgatekeys|sync|share-owner|v2|".utf8)
    static let contentAAD = Array("lgk-keyring-content-wrap-v1|".utf8)
    static let contentInfo = Array("localgatekeys|sync|content-wrap|v1|".utf8)
    static let contentCommitLabel = Array("localgatekeys|sync|share-content|v1|".utf8)
    static let contentFields: Set<String> = ["commit", "wraps"]
    static let metadataFields: Set<String> = ["kind", "collection_id", "name_ct", "shared_mode", "owner", "owner_key"]
    static let ownerSigFields: Set<String> = ["members", "sig"]
    static let sameEpochFixed = ["format", "group_id", "epoch", "kdf", "password_wrap", "metadata", "prev_mac"]

    // MARK: helpers

    static func obj(_ v: JSONValue?) -> [String: JSONValue] { Keyring.obj(v) }
    static func arr(_ v: JSONValue?) -> [JSONValue] { Keyring.arr(v) }
    static func str(_ v: JSONValue?) -> String? { Keyring.str(v) }

    /// Exact text equality by UTF-8 bytes (Swift `==` on `String` is canonical equivalence, Python's is not).
    static func same(_ a: String?, _ b: String?) -> Bool {
        guard let a, let b else { return a == nil && b == nil }
        return Array(a.utf8) == Array(b.utf8)
    }

    /// Exact JSON equality: both absent, or the same canonical bytes (never canonical string equivalence).
    static func sameJSON(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case (let x?, let y?):
            guard let ex = try? CanonicalJSON.encode(x, dialect: .utf8),
                  let ey = try? CanonicalJSON.encode(y, dialect: .utf8) else { return false }
            return ex == ey
        default: return false
        }
    }

    /// Sorted (code point order), unique.
    static func sortedIDs<S: Sequence>(_ ids: S) -> [String] where S.Element == String {
        var seen = Set<[UInt8]>()
        var out: [String] = []
        for id in ids where seen.insert(Array(id.utf8)).inserted { out.append(id) }
        return out.sorted(by: scalarOrder)
    }

    /// Canonical lowercase 8-4-4-4-12 (Python `str(uuid.UUID(v)) == v`).
    public static func isCanonicalUUID(_ v: String?) -> Bool {
        guard let v else { return false }
        let u = Array(v.utf8)
        guard u.count == 36 else { return false }
        for (i, c) in u.enumerated() {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                guard c == 0x2D else { return false }
            } else {
                guard (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66) else { return false }
            }
        }
        return true
    }

    /// The plaintext share description given at creation (desktop `check_share_spec`).
    public struct Spec: Sendable, CustomStringConvertible {
        public let collectionID: String
        public let name: String
        public let sharedMode: String

        public init(collectionID: String, name: String, sharedMode: String) {
            self.collectionID = collectionID; self.name = name; self.sharedMode = sharedMode
        }

        /// `bad-metadata` unless well formed.
        public func check() throws {
            guard ShareKeyring.isCanonicalUUID(collectionID) else {
                throw KeyringError("bad-metadata", "collection_id must be a canonical UUID")
            }
            _ = try ShareKeyring.checkShareName(name)
            guard ShareKeyring.sharedModes.contains(sharedMode) else {
                throw KeyringError("bad-metadata", "shared_mode must be read or edit")
            }
        }

        /// No collection name (it is private to the group).
        public var description: String { "ShareKeyring.Spec(collection=\(collectionID), mode=\(sharedMode))" }
    }

    /// What a device pins when it creates or joins a share (desktop `_PINNED`): no later keyring may change it.
    /// `ownerKey` is base64 text as stored in the metadata.
    public struct Pin: Equatable, Sendable {
        public let collectionID: String
        public let owner: String
        public let ownerKey: String
        public let sharedMode: String

        public init(collectionID: String, owner: String, ownerKey: String, sharedMode: String) {
            self.collectionID = collectionID; self.owner = owner; self.ownerKey = ownerKey; self.sharedMode = sharedMode
        }

        /// From a structurally verified share keyring; `not-share` for a personal one.
        public static func of(_ ring: JSONValue) throws -> Pin {
            guard let m = try ShareKeyring.metadata(ring) else {
                throw KeyringError("not-share", "a personal keyring has no owner")
            }
            return Pin(collectionID: ShareKeyring.str(m["collection_id"]) ?? "", owner: ShareKeyring.str(m["owner"]) ?? "",
                       ownerKey: ShareKeyring.str(m["owner_key"]) ?? "", sharedMode: ShareKeyring.str(m["shared_mode"]) ?? "")
        }

        /// Byte-exact comparison (the metadata texts are ASCII once checked, but never rely on `String ==`).
        func matches(_ other: Pin) -> Bool {
            ShareKeyring.same(collectionID, other.collectionID) && ShareKeyring.same(owner, other.owner)
                && ShareKeyring.same(ownerKey, other.ownerKey) && ShareKeyring.same(sharedMode, other.sharedMode)
        }
    }

    /// 1..100 code points, equal to its Python `strip()` (`bad-metadata`). Swift strings are always encodable.
    static func checkShareName(_ name: String) throws -> String {
        let n = name.unicodeScalars.count
        guard (1...maxNameLen).contains(n), same(Normalise.pyStrip(name), name) else {
            throw KeyringError("bad-metadata", "name must be 1..100 characters without outer spaces")
        }
        return name
    }

    // MARK: structure

    /// Desktop `check_metadata`: the stored metadata block's exact shape (no authentication).
    static func checkMetadata(_ v: JSONValue?) throws -> [String: JSONValue] {
        guard case .object(let m)? = v, Set(m.keys) == metadataFields else { throw KeyringError("bad-fields", "metadata fields") }
        guard same(str(m["kind"]), kind) else { throw KeyringError("bad-metadata", "unsupported metadata kind") }
        guard isCanonicalUUID(str(m["collection_id"])) else {
            throw KeyringError("bad-metadata", "collection_id must be a canonical UUID")
        }
        guard (nameCTMin...nameCTMax).contains(try Keyring.b64any(m["name_ct"], "metadata name_ct").count) else {
            throw KeyringError("bad-metadata", "name_ct must be 29..428 bytes")
        }
        guard let mode = str(m["shared_mode"]), sharedModes.contains(where: { same($0, mode) }) else {
            throw KeyringError("bad-metadata", "shared_mode must be read or edit")
        }
        guard let owner = str(m["owner"]), Identifier.isValid(owner) else { throw KeyringError("bad-metadata", "owner") }
        _ = try Keyring.b64(m["owner_key"], 32, "metadata owner_key")
        return m
    }

    /// The share metadata of a structurally verified keyring, or nil for a personal (device sync) keyring.
    public static func metadata(_ ring: JSONValue) throws -> [String: JSONValue]? {
        guard let m = obj(ring)["metadata"] else { return nil }
        return try checkMetadata(m)
    }

    /// `owner_sig` of a structurally valid share keyring: the approved member ids (desktop `_check_owner_sig`).
    @discardableResult
    static func checkOwnerSig(_ ring: JSONValue) throws -> Set<String> {
        let o = obj(ring)
        let meta = obj(o["metadata"])
        guard case .object(let sig)? = o["owner_sig"], Set(sig.keys) == ownerSigFields else {
            throw KeyringError("bad-fields", "owner_sig fields")
        }
        guard case .array(let listed)? = sig["members"] else {
            throw KeyringError("bad-owner", "owner_sig members must be sorted, unique ids")
        }
        var ids: [String] = []
        for v in listed {
            guard let s = str(v) else { throw KeyringError("bad-owner", "owner_sig members must be sorted, unique ids") }
            ids.append(s)
        }
        // Strictly increasing in code point order: sorted and unique.
        for (a, b) in zip(ids, ids.dropFirst()) where !scalarOrder(a, b) {
            throw KeyringError("bad-owner", "owner_sig members must be sorted, unique ids")
        }
        var byID: [[UInt8]: [String: JSONValue]] = [:]
        for m in arr(o["members"]) {
            let mo = obj(m)
            if let id = str(mo["device_id"]) { byID[Array(id.utf8)] = mo }
        }
        let ownerID = str(meta["owner"]) ?? ""
        guard let owner = byID[Array(ownerID.utf8)], sameJSON(owner["signing_public"], meta["owner_key"]) else {
            throw KeyringError("bad-owner", "the owner is not listed with its key")
        }
        guard ids.contains(where: { same($0, ownerID) }),
              ids.allSatisfy({ d in
                  guard let m = byID[Array(d.utf8)], let key = m["signing_public"], key != .null else { return false }
                  return true
              }) else {
            throw KeyringError("bad-owner", "owner_sig lists a member that is not in the keyring")
        }
        if Keyring.int(o["format"]) == Keyring.shareFormat {
            // Share v2: a content wrap for exactly the approved members (the content shape was checked before).
            let wrapIDs = Set(obj(obj(o["content"])["wraps"]).keys.map { Array($0.utf8) })
            guard wrapIDs == Set(ids.map { Array($0.utf8) }) else {
                throw KeyringError("bad-content", "content wraps must match the approved members exactly")
            }
        }
        let rawSig = try Keyring.b64(sig["sig"], Keyring.proofLen, "owner_sig sig")
        let key = try Keyring.b64(meta["owner_key"], 32, "owner_key")
        guard DeviceIdentity.verify(signature: rawSig, message: try ownerMessage(o, approved: ids), publicKey: key) else {
            throw KeyringError("bad-owner-sig", "the owner's signature does not verify")
        }
        return Set(ids)
    }

    /// Member ids the owner approved; nil for a personal keyring. Call only on a verified keyring.
    public static func approvedMembers(_ ring: JSONValue) -> Set<String>? {
        guard let sig = obj(ring)["owner_sig"] else { return nil }
        return Set(arr(obj(sig)["members"]).compactMap { str($0) })
    }

    /// What the owner signs (desktop `_owner_message`).
    static func ownerMessage(_ ring: [String: JSONValue], approved: [String]) throws -> [UInt8] {
        var byID: [[UInt8]: [String: JSONValue]] = [:]
        for m in arr(ring["members"]) {
            let mo = obj(m)
            if let id = str(mo["device_id"]) { byID[Array(id.utf8)] = mo }
        }
        let roster: [JSONValue] = approved.sorted(by: scalarOrder).map { d in
            let m = byID[Array(d.utf8)] ?? [:]
            return .object(["device_id": .string(d), "exchange_public": m["exchange_public"] ?? .null,
                            "signing_public": m["signing_public"] ?? .null])
        }
        var body: [String: JSONValue] = [
            "group_id": ring["group_id"] ?? .null,
            "epoch": ring["epoch"] ?? .null,
            "metadata": ring["metadata"] ?? .null,
            "members": .array(roster),
        ]
        if Keyring.int(ring["format"]) == Keyring.shareFormat {
            // Share v2: the owner also signs the content block (commitment and wraps) and binds G (audit 2026-11-12
            // F-01): the KDF, password wrap, approved members' device wraps and the chain MAC (null or base64).
            body["content"] = ring["content"] ?? .null
            body["kdf"] = ring["kdf"] ?? .null
            body["password_wrap"] = ring["password_wrap"] ?? .null
            let deviceWraps = obj(ring["device_wraps"])
            var signedWraps: [String: JSONValue] = [:]
            for d in approved { signedWraps[d] = deviceWraps[d] ?? .null }
            body["device_wraps"] = .object(signedWraps)
            body["prev_mac"] = ring["prev_mac"] ?? .null
            return ownerSigLabelV2 + (try CanonicalJSON.encode(.object(body), dialect: .utf8))
        }
        return ownerSigLabel + (try CanonicalJSON.encode(.object(body), dialect: .utf8))
    }

    /// `body` without `mac`, with `owner_sig` by `identity` (the owner) approving `approve` (nil: every listed member)
    /// plus the owner itself. `not-owner` unless `identity` is the metadata's owner; `not-member` for an id not listed.
    /// A format-3 `body` also gets its `content` block for the content key `content` (C; `content-key` when nil): the
    /// wraps it already holds for that C are kept, then `reuse` (the owner's own earlier wraps of this epoch), and every
    /// other approved member gets a new wrap from `random` (eph 32, nonce 12), in member id order.
    static func signOwner(_ body: [String: JSONValue], identity: DeviceIdentity, approve: Set<String>?,
                          content: GroupKey? = nil, random: RandomSource = SystemRandomSource(),
                          reuse: [String: JSONValue]? = nil) throws -> [String: JSONValue] {
        let meta = obj(body["metadata"])
        guard same(str(meta["owner"]), identity.deviceID),
              same(str(meta["owner_key"]), Base64.encode(identity.signingPublicKey)) else {
            throw KeyringError("not-owner", "only the owner changes a share group")
        }
        var out = body
        out["mac"] = nil
        out["owner_sig"] = nil
        let listed = arr(out["members"]).compactMap { str(obj($0)["device_id"]) }
        let chosen: [String] = approve.map { Array($0) + [identity.deviceID] } ?? listed
        let listedBytes = Set(listed.map { Array($0.utf8) })
        guard chosen.allSatisfy({ listedBytes.contains(Array($0.utf8)) }) else {
            throw KeyringError("not-member", "an approved device is not a member")
        }
        let approved = sortedIDs(chosen)
        if Keyring.int(out["format"]) == Keyring.shareFormat {
            guard out["prev_mac"] != nil else {
                throw KeyringError("bad-fields", "set prev_mac before the owner signs a share v2 keyring")
            }
            guard let content else { throw KeyringError("content-key", "a share v2 keyring needs its content key") }
            let commit = Base64.encode(contentCommit(content))
            let old = obj(out["content"])
            let have: [String: JSONValue] = same(str(old["commit"]), commit) ? obj(old["wraps"]) : [:]
            var exchangeKeys: [String: String] = [:]
            for m in arr(out["members"]) {
                let mo = obj(m)
                if let id = str(mo["device_id"]) { exchangeKeys[id] = str(mo["exchange_public"]) ?? "" }
            }
            var wraps: [String: JSONValue] = [:]
            for d in approved {
                if let w = have[d] {
                    wraps[d] = w
                } else if let w = reuse?[d] {
                    wraps[d] = w
                } else {
                    wraps[d] = try wrapContent(content, deviceID: d, exchangePublic: exchangeKeys[d] ?? "", random: random)
                }
            }
            out["content"] = .object(["commit": .string(commit), "wraps": .object(wraps)])
        }
        let sig: [UInt8]
        do { sig = try identity.sign(try ownerMessage(out, approved: approved)) } catch {
            throw KeyringError("bad-member-key", "signing key unusable")
        }
        out["owner_sig"] = .object(["members": .array(approved.map { .string($0) }), "sig": .string(Base64.encode(sig))])
        return out
    }

    // MARK: the content key (share v2)

    /// `content.commit` of C (`ck`): SHA-256 over the label, group id, epoch and C.
    static func contentCommit(_ ck: GroupKey) -> [UInt8] {
        let message = contentCommitLabel + Array(ck.groupID.utf8) + Keyring.bar + Keyring.epochBytes(ck.epoch)
            + Keyring.bar + ck.key
        return Array(SHA256.hash(data: message))
    }

    static func contentAAD(_ groupID: String, _ epoch: Int64, _ deviceID: String) -> [UInt8] {
        contentAAD + Array(groupID.utf8) + Keyring.bar + Keyring.epochBytes(epoch) + Keyring.bar + Array(deviceID.utf8)
    }

    /// The content wrap of C (`ck`) for `deviceID` (base64 X25519 `exchangePublic`): draws eph (32) then nonce (12).
    static func wrapContent(_ ck: GroupKey, deviceID: String, exchangePublic: String, random: RandomSource) throws -> JSONValue {
        try Keyring.wrapDevice(ck, deviceID: deviceID, exchangePublic: try Keyring.b64(.string(exchangePublic), 32, "exchange_public"),
                               random: random, info: contentInfo, aadLabel: contentAAD)
    }

    /// Desktop `_check_content_shape`: exactly `commit` (32 bytes) and `wraps`, an object of valid device ids to wraps
    /// with the device-wrap fields and lengths (`bad-fields`, `bad-content`, `bad-base64`, `bad-length`).
    static func checkContentShape(_ v: JSONValue?) throws {
        let c = try Keyring.fields(v, contentFields, "content fields")
        _ = try Keyring.b64(c["commit"], 32, "content commit")
        guard case .object(let wraps)? = c["wraps"] else {
            throw KeyringError("bad-content", "content wraps must be an object")
        }
        for (id, wrap) in wraps.sorted(by: { $0.key < $1.key }) {
            guard Identifier.isValid(id) else { throw KeyringError("bad-content", "content wrap device id") }
            let w = try Keyring.fields(wrap, Keyring.devWrapFields, "content wrap fields")
            _ = try Keyring.b64(w["eph"], 32, "content wrap eph")
            _ = try Keyring.b64(w["nonce"], Keyring.nonceLen, "content wrap nonce")
            _ = try Keyring.b64(w["ct"], Keyring.wrapCTLen, "content wrap ct")
        }
    }

    /// 1 for a share v1 keyring (items sealed with G), 2 for share v2 (format 3), nil for a personal one (desktop
    /// `share_version`). Call it only on a keyring that passed the structure check.
    public static func shareVersion(_ ring: JSONValue) -> Int? {
        let o = obj(ring)
        guard o["metadata"] != nil else { return nil }
        return Keyring.int(o["format"]) == Keyring.shareFormat ? 2 : 1
    }

    /// `GroupKey(group_id, epoch, C)` of share v2 `ring` from this device's content wrap (desktop `open_content_key`);
    /// nil when the owner has not wrapped C for this device (not approved yet). Reasons: `not-share-v2` for any other
    /// keyring, `not-member` / `key-mismatch`, `content-key` when the wrap does not open or opens a key other than the
    /// committed one. Call it only on an accepted keyring.
    public static func openContentKey(_ ring: JSONValue, identity: DeviceIdentity) throws -> GroupKey? {
        let o = obj(ring)
        guard Keyring.int(o["format"]) == Keyring.shareFormat, case .object(let content)? = o["content"] else {
            throw KeyringError("not-share-v2", "this keyring has no content key")
        }
        _ = try Keyring.member(ring, identity)
        guard let wrapValue = obj(content["wraps"])[identity.deviceID] else { return nil }
        let wrap = obj(wrapValue)
        guard let gid = str(o["group_id"]), let epoch = Keyring.int(o["epoch"]) else {
            throw KeyringError("bad-fields", "keyring")
        }
        let ck: GroupKey
        do {
            let shared = try identity.exchange(with: try Keyring.b64(wrap["eph"], 32, "eph"))
            let key = CryptoBox.hkdf(ikm: shared, salt: Array(gid.utf8), info: contentInfo + Array(identity.deviceID.utf8),
                                     length: Keyring.keyLen)
            let plain = try CryptoBox.openGCM(key: key, nonce: try Keyring.b64(wrap["nonce"], Keyring.nonceLen, "nonce"),
                                              ciphertext: try Keyring.b64(wrap["ct"], Keyring.wrapCTLen, "ct"),
                                              aad: contentAAD(gid, epoch, identity.deviceID))
            ck = try GroupKey(groupID: gid, epoch: epoch, key: plain)
        } catch {
            throw KeyringError("content-key", "the content wrap cannot be opened")
        }
        let committed: [UInt8]
        do { committed = try Keyring.b64(content["commit"], 32, "content commit") } catch {
            throw KeyringError("content-key", "the content commitment cannot be read")
        }
        guard Keyring.constantTimeEqual(contentCommit(ck), committed) else {
            throw KeyringError("content-key", "the content key differs from the committed one")
        }
        return ck
    }

    // MARK: the collection name

    static func nameKey(_ gk: GroupKey) -> [UInt8] {
        CryptoBox.hkdf(ikm: gk.key, salt: Array(gk.groupID.utf8), info: nameInfo + Keyring.epochBytes(gk.epoch),
                       length: Keyring.keyLen)
    }

    static func nameAAD(_ gk: GroupKey, _ collectionID: String) -> [UInt8] {
        nameAAD + Array(gk.groupID.utf8) + Keyring.bar + Keyring.epochBytes(gk.epoch) + Keyring.bar + Array(collectionID.utf8)
    }

    /// `name_ct` of `name` for `collectionID` under `gk`. Draws the 12-byte nonce.
    static func sealName(_ gk: GroupKey, collectionID: String, name: String, random: RandomSource) throws -> String {
        let plain = Array(try checkShareName(name).utf8)
        let nonce = try Keyring.draw(random, Keyring.nonceLen)
        let ct = try CryptoBox.sealGCM(key: nameKey(gk), nonce: nonce, plaintext: plain, aad: nameAAD(gk, collectionID))
        return Base64.encode(nonce + ct)
    }

    /// The collection name of an accepted share keyring at `gk`'s epoch; `bad-metadata` when it cannot be read.
    public static func shareName(_ ring: JSONValue, key gk: GroupKey) throws -> String {
        let meta = try checkMetadata(obj(ring)["metadata"])
        let raw = try Keyring.b64any(meta["name_ct"], "metadata name_ct")
        guard raw.count > Keyring.nonceLen,
              let plain = try? CryptoBox.openGCM(key: nameKey(gk), nonce: Array(raw[0..<Keyring.nonceLen]),
                                                 ciphertext: Array(raw[Keyring.nonceLen...]),
                                                 aad: nameAAD(gk, str(meta["collection_id"]) ?? "")),
              let name = Keyring.strictUTF8(plain) else {
            throw KeyringError("bad-metadata", "the collection name cannot be read")
        }
        guard (1...maxNameLen).contains(name.unicodeScalars.count), same(Normalise.pyStrip(name), name) else {
            throw KeyringError("bad-metadata", "the collection name is malformed")
        }
        return name
    }

    // MARK: reading

    /// Parse a keyring a share flow reads (strict, structure and owner signature verified). A personal keyring
    /// parses too: `requireShare` refuses it.
    public static func parse(_ data: [UInt8]) throws -> JSONValue { try Keyring.parse(data, share: true) }

    /// `not-share` for a device-sync keyring (desktop `join_share_group`).
    @discardableResult
    public static func requireShare(_ ring: JSONValue) throws -> [String: JSONValue] {
        guard let m = try metadata(ring) else {
            throw KeyringError("not-share", "that keyring is device sync, not a shared collection")
        }
        return m
    }

    /// Sorted member ids.
    public static func memberIDs(_ ring: JSONValue) -> [String] {
        arr(obj(ring)["members"]).compactMap { str(obj($0)["device_id"]) }.sorted(by: scalarOrder)
    }

    /// Members the owner has not approved, never `own` (desktop `_pending`).
    public static func pending(_ ring: JSONValue, own: String) -> [String] {
        let approved = Set((approvedMembers(ring) ?? []).map { Array($0.utf8) })
        return memberIDs(ring).filter { !approved.contains(Array($0.utf8)) && !same($0, own) }
    }

    // MARK: writers

    /// A new share group (epoch 1) owned by `identity` (desktop `create_group(metadata=)`), share v2. Draw order as
    /// `Keyring.create`, then the name nonce (12), C (32) and the owner's content wrap (eph 32, nonce 12). Reasons:
    /// `bad-metadata`, `weak-password`, `bad-device-id`, `bad-name`, `bad-fields`.
    public static func create(password: String, identity: DeviceIdentity, name: String, spec: Spec, random: RandomSource,
                              now: UnixClock) throws -> (JSONValue, GroupKey) {
        try create(password: password, identity: identity, name: name, spec: spec, random: random, now: now,
                   derive: Keyring.productionKDF)
    }

    /// `shareFormat` 2 writes a share v1 keyring (only the legacy vectors and the migration tests).
    static func create(password: String, identity: DeviceIdentity, name: String, spec: Spec, random: RandomSource,
                       now: UnixClock, derive: Keyring.KeyDerivation,
                       shareFormat: Int64 = Keyring.shareFormat) throws -> (JSONValue, GroupKey) {
        try Keyring.create(password: password, identity: identity, name: name, groupID: nil, random: random, now: now,
                           derive: derive, share: spec, shareFormat: shareFormat)
    }

    /// Join a share by its password: `not-share` for a device-sync keyring, then the `Keyring.join` reasons. The new
    /// member is pending until the owner approves it. Pin the result with `Pin.of`.
    public static func join(_ ring: JSONValue, password: String, identity: DeviceIdentity, name: String,
                            random: RandomSource, now: UnixClock) throws -> (JSONValue, GroupKey) {
        try Keyring.verifyStructure(ring, share: true)
        try requireShare(ring)
        return try Keyring.join(ring, identity: identity, name: name, random: random, now: now, share: true) {
            try Keyring.passwordKey(ring, password: password)
        }
    }

    static func join(_ ring: JSONValue, passwordKey key: [UInt8], identity: DeviceIdentity, name: String,
                     random: RandomSource, now: UnixClock) throws -> (JSONValue, GroupKey) {
        try Keyring.verifyStructure(ring, share: true)
        try requireShare(ring)
        return try Keyring.join(ring, identity: identity, name: name, random: random, now: now, share: true) { key }
    }

    /// Authenticate a share keyring against the trusted key (structure, owner signature, MAC, chain).
    public static func accept(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity) throws -> GroupKey {
        try Keyring.accept(ring, trusted: trusted, identity: identity, share: true)
    }

    /// The owner approves `approve` (nil: every member) at the trusted epoch (desktop `owner_approve_members`). Same
    /// epoch, key, metadata and wraps; only `owner_sig` and `mac` change. Reasons: the `accept` ones, `stale-trust`,
    /// `not-share`, `not-member` / `key-mismatch` (this device), `not-owner`, `not-member` (an approved id).
    public static func approve(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity,
                               approve: Set<String>?) throws -> JSONValue {
        try ShareKeyring.approve(ring, trusted: trusted, identity: identity, approve: approve, reuseWraps: nil,
                                 random: SystemRandomSource())
    }

    /// Share v2: the owner opens C from its own content wrap (`content-key` without one) and wraps it to each newly
    /// approved member in id order (eph 32, nonce 12 each, from `random`); `reuseWraps` (the `content` block of the
    /// owner's own stored keyring of this epoch) gives the wraps it already made when its commitment matches, so a merge
    /// grows from that keyring. Reasons in order: the `accept` ones, `stale-trust`, `not-share`, `not-member` /
    /// `key-mismatch`, `not-owner`, `content-key`, `not-member` (an approved id).
    static func approve(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity, approve: Set<String>?,
                        reuseWraps: JSONValue?, random: RandomSource) throws -> JSONValue {
        let gk = try accept(ring, trusted: trusted, identity: identity)
        guard gk.epoch == trusted.epoch else { throw KeyringError("stale-trust", "adopt the current keyring first") }
        try requireShare(ring)
        _ = try Keyring.member(ring, identity)
        let o = obj(ring)
        let meta = obj(o["metadata"])
        guard same(str(meta["owner"]), identity.deviceID),
              same(str(meta["owner_key"]), Base64.encode(identity.signingPublicKey)) else {
            throw KeyringError("not-owner", "only the owner changes a share group")
        }
        let chosen = approve.map { (approvedMembers(ring) ?? []).union($0) }
        var content: GroupKey? = nil
        var reuse: [String: JSONValue]? = nil
        if Keyring.int(o["format"]) == Keyring.shareFormat {
            guard let ck = try openContentKey(ring, identity: identity) else {
                throw KeyringError("content-key", "the owner has no content wrap")
            }
            content = ck
            if case .object(let r)? = reuseWraps, sameJSON(r["commit"], obj(o["content"])["commit"]),
               case .object(let w)? = r["wraps"] {
                reuse = w
            }
        }
        let signed = try signOwner(o, identity: identity, approve: chosen, content: content, random: random, reuse: reuse)
        return try Keyring.finish(signed, key: gk)
    }

    /// The owner approves pending members it showed by name (desktop `approve_members`): `not-pending` for an empty
    /// choice or an id that is not pending in `ring`, else `approve`.
    public static func approvePending(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity,
                                      deviceIDs: [String]) throws -> JSONValue {
        try approvePending(ring, trusted: trusted, identity: identity, deviceIDs: deviceIDs, random: SystemRandomSource())
    }

    static func approvePending(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity, deviceIDs: [String],
                               random: RandomSource) throws -> JSONValue {
        let waiting = Set(pending(ring, own: identity.deviceID).map { Array($0.utf8) })
        guard !deviceIDs.isEmpty, deviceIDs.allSatisfy({ waiting.contains(Array($0.utf8)) }) else {
            throw KeyringError("not-pending", "approve only members that are waiting")
        }
        return try ShareKeyring.approve(ring, trusted: trusted, identity: identity, approve: Set(deviceIDs), reuseWraps: nil,
                                        random: random)
    }

    /// The owner rotates (new key, epoch + 1, a NEW share password), dropping `remove` (desktop `rotate` +
    /// `remove_member`: pass the removed member and every unapproved one). The name is re-sealed. Share v1: every
    /// remaining member approved. Share v2 (or `upgrade`): a new content key C wrapped to the previously approved members
    /// minus `remove`. Reasons: as `Keyring.rotate`, then `not-owner`.
    public static func rotate(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity, newPassword: String,
                              remove: [String], random: RandomSource) throws -> (JSONValue, GroupKey) {
        try rotate(ring, trusted: trusted, identity: identity, newPassword: newPassword, remove: remove, random: random,
                   derive: Keyring.productionKDF)
    }

    static func rotate(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity, newPassword: String,
                       remove: [String], random: RandomSource, derive: Keyring.KeyDerivation,
                       upgrade: Bool = false) throws -> (JSONValue, GroupKey) {
        try Keyring.rotate(ring, trusted: trusted, identity: identity, newPassword: newPassword, remove: remove,
                           random: random, derive: derive, share: true, upgrade: upgrade)
    }

    /// The owner upgrades share v1 `ring` to share v2 (desktop `upgrade_share_keyring`): a rotation to epoch + 1 that
    /// removes nobody. New G and a content key C wrapped to the members already approved (pending ones stay pending).
    /// `password` is the share password for the new epoch: it must pass the share password rules and may be the current
    /// one (it no longer opens any item). Draw order as a share v2 rotation. Reasons: `not-share`, `already-v2`,
    /// `not-owner` and what `rotate` refuses.
    public static func upgrade(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity, password: String,
                               random: RandomSource) throws -> (JSONValue, GroupKey) {
        try upgrade(ring, trusted: trusted, identity: identity, password: password, random: random,
                    derive: Keyring.productionKDF)
    }

    static func upgrade(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity, password: String,
                        random: RandomSource, derive: Keyring.KeyDerivation) throws -> (JSONValue, GroupKey) {
        let o = obj(ring)
        guard o["metadata"] != nil else { throw KeyringError("not-share", "a personal keyring has no share version") }
        if Keyring.int(o["format"]) == Keyring.shareFormat {
            throw KeyringError("already-v2", "this share is already share v2")
        }
        return try Keyring.rotate(ring, trusted: trusted, identity: identity, newPassword: password, remove: [],
                                  random: random, derive: derive, share: true, upgrade: true, allowSamePassword: true)
    }

    /// What `removeMember` returns: the rotated keyring and key, and the owner's signed notice to write to `removed/`.
    public struct Removed: Sendable, CustomStringConvertible {
        public let keyring: JSONValue
        public let key: GroupKey
        public let notice: [UInt8]
        public let dropped: [String]
        /// No key material.
        public var description: String { "ShareKeyring.Removed(epoch=\(key.epoch), dropped=\(dropped.count))" }
    }

    /// The owner removes `deviceID` (desktop `share_group.remove_member`; works without Pro): a rotation with a NEW
    /// share password (the removed person knows the old one) that also drops every member the owner never approved
    /// (they get no notice), and the owner-signed notice naming this share group only. A share v1 keyring is upgraded to
    /// share v2 in the same rotation. `not-owner` on any other
    /// device, `not-member` for a bad id, then the `rotate` reasons.
    public static func removeMember(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity, deviceID: String,
                                    newPassword: String, random: RandomSource, issuedAt: Int64) throws -> Removed {
        try removeMember(ring, trusted: trusted, identity: identity, deviceID: deviceID, newPassword: newPassword,
                         random: random, issuedAt: issuedAt, derive: Keyring.productionKDF)
    }

    static func removeMember(_ ring: JSONValue, trusted: GroupKey, identity: DeviceIdentity, deviceID: String,
                             newPassword: String, random: RandomSource, issuedAt: Int64,
                             derive: Keyring.KeyDerivation) throws -> Removed {
        let pin = try Pin.of(ring)
        guard same(pin.owner, identity.deviceID) else {
            throw KeyringError("not-owner", "only the person who shared the collection does this")
        }
        guard Identifier.isValid(deviceID) else { throw KeyringError("not-member", "invalid device id") }
        let drop = [deviceID] + pending(ring, own: identity.deviceID).filter { !same($0, deviceID) }
        // A share v1 group is upgraded to share v2 in the same rotation (a new content key for the others).
        let (rotated, key) = try rotate(ring, trusted: trusted, identity: identity, newPassword: newPassword, remove: drop,
                                        random: random, derive: derive, upgrade: true)
        let notice = try RemovalNotice.make(identity: identity, groupID: trusted.groupID, deviceID: deviceID,
                                            epoch: key.epoch, issuedAt: issuedAt)
        return Removed(keyring: rotated, key: key, notice: notice, dropped: drop)
    }

    // MARK: adopting

    /// At one epoch a share keyring may only grow (desktop `_check_same_epoch_growth`): `tampered` for anything else.
    /// Fixed: format, group, epoch, kdf, password wrap, metadata, prev_mac; the old members an unchanged prefix; every
    /// old device wrap unchanged; the approved roster a superset.
    public static func checkSameEpochGrowth(old: JSONValue, new: JSONValue) throws {
        let o = obj(old), n = obj(new)
        if sameEpochFixed.contains(where: { !sameJSON(o[$0], n[$0]) }) {
            throw KeyringError("tampered", "a share keyring changed within its epoch")
        }
        let om = arr(o["members"]), nm = arr(n["members"])
        guard nm.count >= om.count, zip(om, nm).allSatisfy({ sameJSON($0, $1) }) else {
            throw KeyringError("tampered", "a share keyring dropped or changed a member within its epoch")
        }
        let nw = obj(n["device_wraps"])
        if obj(o["device_wraps"]).contains(where: { d, w in !sameJSON(nw[d], w) }) {
            throw KeyringError("tampered", "a share keyring changed a device wrap within its epoch")
        }
        let newApproved = Set((approvedMembers(new) ?? []).map { Array($0.utf8) })
        guard (approvedMembers(old) ?? []).allSatisfy({ newApproved.contains(Array($0.utf8)) }) else {
            throw KeyringError("tampered", "a share keyring un-approved a member within its epoch")
        }
        // Share v2: the content commitment is fixed and no content wrap changes or disappears.
        let oc = o["content"], nc = n["content"]
        if (oc == nil) != (nc == nil) {
            throw KeyringError("tampered", "a share keyring changed its version within its epoch")
        }
        if let oc, let nc {
            let ocO = obj(oc), ncO = obj(nc)
            let nw = obj(ncO["wraps"])
            if !sameJSON(ocO["commit"], ncO["commit"]) || obj(ocO["wraps"]).contains(where: { d, w in !sameJSON(nw[d], w) }) {
                throw KeyringError("tampered", "a share keyring changed its content key or a content wrap within its epoch")
            }
        }
    }

    /// Whether `new` is a later state of `old` (a later epoch, or growth within one); desktop `grows_from`.
    public static func growsFrom(old: JSONValue, new: JSONValue) -> Bool {
        let o = obj(old), n = obj(new)
        guard o["group_id"] != nil, sameJSON(o["group_id"], n["group_id"]) else { return false }
        if let oe = Keyring.int(o["epoch"]), let ne = Keyring.int(n["epoch"]), oe < ne { return true }
        if !sameJSON(o["epoch"], n["epoch"]) || sameJSON(old, new) { return false }
        return (try? checkSameEpochGrowth(old: old, new: new)) != nil
    }

    static func checkPinned(_ ring: JSONValue, pin: Pin) throws {
        // `Pin.of` refuses a personal keyring and checks the metadata's shape.
        guard let got = try? Pin.of(ring), got.matches(pin) else {
            throw KeyringError("tampered", "the keyring changes the share's owner, collection or mode")
        }
    }

    /// Accept a newer keyring of a share this device is in (desktop `adopt_keyring`): `stored` is the last accepted
    /// keyring at `trusted`'s epoch, `pin` what this device pinned. Returns the key to keep (same or next epoch).
    /// Reasons in order: the `accept` ones, `tampered` (pinned facts), `tampered` (same-epoch growth), `removed`.
    public static func adopt(stored: JSONValue, candidate: JSONValue, trusted: GroupKey, identity: DeviceIdentity,
                             pin: Pin) throws -> GroupKey {
        let gk = try accept(candidate, trusted: trusted, identity: identity)
        try checkPinned(candidate, pin: pin)
        if gk.epoch == trusted.epoch { try checkSameEpochGrowth(old: stored, new: candidate) }
        guard memberIDs(candidate).contains(where: { same($0, identity.deviceID) }) else {
            throw KeyringError("removed", "this device is no longer in the share group")
        }
        return gk
    }

    /// Owner only (desktop `reconcile_owner_keyring`): the owner's stored approvals re-signed onto a same-epoch folder
    /// keyring that someone else grew meanwhile, when the result grows from `stored`; nil for anything else.
    public static func reconcileOwner(stored: JSONValue, folder: JSONValue, trusted: GroupKey, identity: DeviceIdentity,
                                      pin: Pin) -> JSONValue? {
        guard same(pin.owner, identity.deviceID) else { return nil }
        let f = obj(folder)
        guard sameJSON(f["group_id"], .string(trusted.groupID)), f["epoch"] == .int(trusted.epoch) else { return nil }
        do {
            // Share v2: the owner's stored content wraps are reused, so the result still grows from `stored`.
            let ring = try ShareKeyring.approve(folder, trusted: trusted, identity: identity,
                                                approve: approvedMembers(stored) ?? [], reuseWraps: obj(stored)["content"],
                                                random: SystemRandomSource())
            try checkPinned(ring, pin: pin)
            try checkSameEpochGrowth(old: stored, new: ring)
            return ring
        } catch {
            return nil
        }
    }

    /// A member's join lost to someone else's join at the same moment (desktop `superseded_join`): the folder keyring
    /// authenticates at the stored epoch, no longer lists this device, and grows from `stored` minus this device's own
    /// last entry and wrap. The user joins again; anything else stays `tampered`.
    public static func supersededJoin(stored: JSONValue, folder: JSONValue, trusted: GroupKey, identity: DeviceIdentity,
                                      pin: Pin) -> Bool {
        guard !same(pin.owner, identity.deviceID) else { return false }
        let f = obj(folder)
        guard sameJSON(f["group_id"], .string(trusted.groupID)), f["epoch"] == .int(trusted.epoch) else { return false }
        do {
            _ = try accept(folder, trusted: trusted, identity: identity)
            let own = identity.deviceID
            if memberIDs(folder).contains(where: { same($0, own) }) { return false }
            let s = obj(stored)
            let members = arr(s["members"])
            guard let last = members.last, same(str(obj(last)["device_id"]), own) else { return false }
            var base = s
            base["members"] = .array(Array(members.dropLast()))
            base["device_wraps"] = .object(obj(s["device_wraps"]).filter { !same($0.key, own) })
            try checkSameEpochGrowth(old: .object(base), new: folder)
            return true
        } catch {
            return false
        }
    }

    /// Whether `folder` is a later epoch of this share signed by the pinned owner key (desktop `_owner_signed_ahead`).
    /// Only the owner's own device can make one, so an owner's device that trusts an older epoch (its vault went back)
    /// never writes that older keyring over it.
    public static func ownerSignedAhead(folder: JSONValue, trusted: GroupKey, pin: Pin) -> Bool {
        let f = obj(folder)
        guard sameJSON(f["group_id"], .string(trusted.groupID)), let epoch = Keyring.int(f["epoch"]),
              epoch > trusted.epoch else { return false }
        do {
            try Keyring.verifyStructure(folder, share: true) // the owner signature included
            guard try metadata(folder) != nil else { return false }
            return try Pin.of(folder).matches(pin)
        } catch {
            return false
        }
    }

    /// Whether `folder` (at the trusted epoch) has a valid MAC under the trusted key and the pinned owner's signature
    /// (desktop `_authenticates_at_epoch`).
    public static func authenticatesAtEpoch(folder: JSONValue, trusted: GroupKey, identity: DeviceIdentity,
                                            pin: Pin) -> Bool {
        do {
            _ = try accept(folder, trusted: trusted, identity: identity)
            guard let m = try metadata(folder) else { return false }
            return same(str(m["owner"]), pin.owner) && same(str(m["owner_key"]), pin.ownerKey)
        } catch {
            return false
        }
    }
}
