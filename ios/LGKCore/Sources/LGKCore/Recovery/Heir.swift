import Crypto
import Foundation

/// `reason`: `invalid`, `malformed`, `conflict` (a synced plan that re-keys the stored one), `unsupported`,
/// `bad-signature`, `need-more` (`missing` shards short), `duplicate`, `mixed-plans` or `check-failed`
/// (desktop `heir.HeirError`).
public struct HeirError: Error, Equatable, Sendable {
    public let reason: String
    public let message: String
    public let missing: Int
    public init(_ reason: String, _ message: String? = nil, missing: Int = 0) {
        self.reason = reason; self.message = message ?? reason; self.missing = missing
    }
}

/// One verified `.lgkheir` package: the shard (`share` = `[index, 32 bytes]`) and the plan facts it carries.
public struct Shard: Sendable, CustomStringConvertible {
    public let packageID: String
    public let planID: String
    public let index: Int
    public let holder: String
    public let k: Int
    public let n: Int
    public let waitDays: Int
    public let created: Int64
    public let owner: String
    public let signer: [UInt8]
    public let share: [UInt8]
    public let checkSalt: [UInt8]
    public let check: [UInt8]

    func samePlan(_ other: Shard) -> Bool {
        planID == other.planID && signer == other.signer && k == other.k && n == other.n && waitDays == other.waitDays
            && created == other.created && owner == other.owner && checkSalt == other.checkSalt && check == other.check
    }

    public var description: String { "Shard(plan=\(planID), index=\(index))" }   // never the share
}

/// The owner's plan as one of the owner's phones or Macs holds it: the synced record (desktop `heir.synced_record`),
/// received from the owner's computer. It carries the plan's Ed25519 signing key, so this device can sign deny and
/// grant files.
public struct HeirPlan: Sendable, CustomStringConvertible {
    public let planID: String
    public let k: Int
    public let n: Int
    public let holders: [String]
    public let waitDays: Int
    public let created: Int64
    public let owner: String
    public let signer: [UInt8]
    let seed: [UInt8]
    public let checkSalt: [UInt8]
    public let check: [UInt8]
    public let backupPublic: [UInt8]
    let holderKeys: [[UInt8]]
    public let stale: Bool
    public let denied: [String]

    /// A copy of the plan's Ed25519 seed.
    func signingSeed() -> [UInt8] { seed }

    /// Holder `index`'s proof key (1-based).
    func holderKey(_ index: Int) -> [UInt8] { holderKeys[index - 1] }

    public var description: String { "HeirPlan(plan=\(planID), k=\(k), n=\(n))" }   // never key material
}

/// Emergency access shards and the owner's plan record: port of `src/localvault/heir.py` and Android `Heir.kt`
/// (byte rules in `docs/formats/LGKHEIR_V1.md`, vectors in `tests/vectors/heir`). iPhones and Macs read and combine
/// shards, check the entropy, hold the plan by sync and merge it like the desktop; they never make a plan.
public enum Heir {
    public static let format = "localgatekeys-heir"
    public static let version: Int64 = 1
    public static let kind = "heir-shard"
    public static let maxPackage = 4096
    public static let qrPrefix = "lgkheir:"
    public static let qrLimit = 2048
    public static let nicknameLimit = 32
    public static let ownerLimit = Envelope.senderLimit
    public static let minWaitDays = 1
    public static let maxWaitDays = 30
    public static let deniedLimit = 64
    /// Sync namespace and the one state id of the owner's plan (desktop `vault_bridge.HEIR_NS` / `HEIR_STATE_ID`).
    public static let ns = "heir"
    public static let stateID = "heir:plan"
    public static let fileExtension = "lgkheir"
    static let checkInfo: [UInt8] = Array("LocalGateKeys heir check v1\n".utf8)
    static let holderInfo: [UInt8] = Array("LocalGateKeys heir holder v1\n".utf8)
    static let backupKeyInfo: [UInt8] = Array("LocalGateKeys heir backup key v1\n".utf8)

    static let payloadKeys: Set<String> = ["kind", "plan_id", "index", "holder", "k", "n", "wait_days", "created", "share",
                                           "check_salt", "check"]
    static let recordKeys: Set<String> = ["version", "plan_id", "k", "n", "holders", "wait_days", "folder", "created",
                                          "owner", "signer", "signing_key", "check_salt", "check", "backup_public",
                                          "holder_keys"]
    /// Never synced: the shared folder's path on that device, and whether it made the plan.
    static let localOnlyKeys: Set<String> = ["folder", "home"]
    /// Exactly the keys of a synced record (desktop `_SYNCED_KEYS`).
    public static let syncedKeys: Set<String> = recordKeys.subtracting(["folder"]).union(["stale", "denied"])
    static let mutableKeys: Set<String> = ["stale", "denied"]

    // MARK: validation

    static func bad() -> HeirError { HeirError("malformed") }

    /// Desktop `_printable`: NFC, Python-stripped, 1...`limit` code points with no control, format, surrogate or
    /// private-use ones (see `isOther`).
    public static func printable(_ raw: String, limit: Int, allowEmpty: Bool = false) throws -> String {
        let name = Normalise.pyStrip(raw.precomposedStringWithCanonicalMapping)
        let count = Envelope.length(name)
        if (count == 0 && !allowEmpty) || count > limit || name.unicodeScalars.contains(where: isOther) {
            throw HeirError("invalid", "A name must be 1 to \(limit) printable characters")
        }
        return name
    }

    /// Unicode general categories Cc, Cf, Cs and Co. Unassigned (Cn) is accepted on purpose: these names come from
    /// signed packages the desktop already checked against its own (often newer) Unicode tables, and an older
    /// device's tables report later emoji as unassigned, which would refuse a valid shard as `malformed`.
    static func isOther(_ s: Unicode.Scalar) -> Bool {
        switch s.properties.generalCategory {
        case .control, .format, .surrogate, .privateUse: return true
        default: return false
        }
    }

    static func int(_ v: JSONValue?) throws -> Int64 {
        guard case .int(let i)? = v else { throw HeirError("invalid") }
        return i
    }

    static func str(_ v: JSONValue?) -> String? {
        if case .string(let s)? = v { return s }
        return nil
    }

    static func checkCounts(_ k: JSONValue?, _ n: JSONValue?, _ waitDays: JSONValue?) throws {
        let kk = try int(k), nn = try int(n)
        guard Int64(SSS.minK) <= kk, kk <= nn, nn <= Int64(SSS.maxN) else { throw HeirError("invalid") }
        let w = try int(waitDays)
        guard w >= Int64(minWaitDays), w <= Int64(maxWaitDays) else { throw HeirError("invalid") }
    }

    static func holders(_ value: JSONValue?, _ n: Int64) throws -> [String] {
        guard case .array(let list)? = value else { throw HeirError("invalid") }
        let names = try list.map { v -> String in
            guard case .string(let s) = v else { throw HeirError("invalid") }
            return try printable(s, limit: nicknameLimit)
        }
        guard Int64(names.count) == n, Set(names.map { Casefold.fold($0) }).count == names.count else { throw HeirError("invalid") }
        return names
    }

    // MARK: derived keys

    static func info(_ prefix: [UInt8], _ planID: String) -> [UInt8] { prefix + Array(planID.utf8) }

    /// `HKDF-SHA256(ikm=entropy, salt, info=checkInfo || plan_id)`, 32 bytes.
    public static func entropyCheck(_ entropy: [UInt8], planID: String, salt: [UInt8]) throws -> [UInt8] {
        guard entropy.count == SSS.secretLength, salt.count == 16 else { throw HeirError("invalid") }
        return CryptoBox.hkdf(ikm: entropy, salt: salt, info: info(checkInfo, planID), length: 32)
    }

    /// A holder's proof key: `HKDF-SHA256(ikm=share (33 bytes), salt, info=holderInfo || plan_id)`.
    public static func holderKey(_ share: [UInt8], planID: String, salt: [UInt8]) throws -> [UInt8] {
        guard share.count == SSS.shareLength, salt.count == 16 else { throw HeirError("invalid") }
        return CryptoBox.hkdf(ikm: share, salt: salt, info: info(holderInfo, planID), length: 32)
    }

    /// The clamped X25519 key the heir folder's backups are locked to.
    public static func backupPrivateKey(_ entropy: [UInt8], planID: String, salt: [UInt8]) throws -> [UInt8] {
        guard entropy.count == SSS.secretLength, salt.count == 16 else { throw HeirError("invalid") }
        var key = CryptoBox.hkdf(ikm: entropy, salt: salt, info: info(backupKeyInfo, planID), length: 32)
        key[0] &= 0xF8
        key[31] = (key[31] & 0x7F) | 0x40
        return key
    }

    public static func backupPublicKey(_ entropy: [UInt8], planID: String, salt: [UInt8]) throws -> [UInt8] {
        var priv = try backupPrivateKey(entropy, planID: planID, salt: salt)
        defer { for i in priv.indices { priv[i] = 0 } }
        guard let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: priv) else { throw HeirError("invalid") }
        return Array(key.publicKey.rawRepresentation)
    }

    /// Whether `entropy` is the one the plan was made from (constant-time compare of the HKDF check).
    public static func verifyEntropy(planID: String, salt: [UInt8], check: [UInt8], entropy: [UInt8]) -> Bool {
        guard entropy.count == SSS.secretLength, var mine = try? entropyCheck(entropy, planID: planID, salt: salt) else {
            return false
        }
        defer { for i in mine.indices { mine[i] = 0 } }
        return Envelope.same(mine, check)
    }

    public static func verifyEntropy(_ shard: Shard, _ entropy: [UInt8]) -> Bool {
        verifyEntropy(planID: shard.planID, salt: shard.checkSalt, check: shard.check, entropy: entropy)
    }

    public static func verifyEntropy(_ plan: HeirPlan, _ entropy: [UInt8]) -> Bool {
        verifyEntropy(planID: plan.planID, salt: plan.checkSalt, check: plan.check, entropy: entropy)
    }

    // MARK: packages

    /// The signed package of one shard, as the desktop's `create_plan` writes it (`sign` pins a vector's signature).
    public static func sealPackage(planID: String, share: [UInt8], holder: String, k: Int, n: Int, waitDays: Int,
                                   created: Int64, checkSalt: [UInt8], check: [UInt8], owner: String, packageID: String,
                                   signingSeed: [UInt8], sign: Envelope.Signer? = nil) throws -> [UInt8] {
        let payload: [String: JSONValue] = [
            "kind": .string(kind), "plan_id": .string(planID), "index": .int(Int64(share[0])), "holder": .string(holder),
            "k": .int(Int64(k)), "n": .int(Int64(n)), "wait_days": .int(Int64(waitDays)), "created": .int(created),
            "share": .string(Envelope.b64e(share)), "check_salt": .string(Envelope.b64e(checkSalt)),
            "check": .string(Envelope.b64e(check)),
        ]
        return try Envelope.seal(format: format, version: version, packageID: packageID, sender: owner, payload: payload,
                                 seed: signingSeed, sign: sign)
    }

    /// Parses and verifies one `.lgkheir` package (signature first, then every payload rule).
    public static func readPackage(_ data: [UInt8]) throws -> Shard {
        let opened: SignedEnvelope
        do {
            opened = try Envelope.open(data, format: format, version: version, limit: maxPackage)
        } catch let e as EnvelopeError {
            throw HeirError(e.reason, "This is not a valid emergency access shard")
        }
        let p = opened.payload
        do {
            guard Set(p.keys) == payloadKeys, p["kind"] == .string(kind) else { throw bad() }
            try checkCounts(p["k"], p["n"], p["wait_days"])
            let index = try int(p["index"]), n = try int(p["n"]), created = try int(p["created"])
            guard let holder = str(p["holder"]) else { throw bad() }
            guard index >= 1, index <= n, created >= 0, try printable(holder, limit: nicknameLimit) == holder,
                  try printable(opened.sender, limit: ownerLimit, allowEmpty: true) == opened.sender else { throw bad() }
            let share = try Envelope.b64d(p["share"], size: SSS.shareLength)
            guard Int64(share[0]) == index else { throw bad() }
            return Shard(packageID: opened.id, planID: try Envelope.checkedID(p["plan_id"]), index: Int(index),
                         holder: holder, k: Int(try int(p["k"])), n: Int(n), waitDays: Int(try int(p["wait_days"])),
                         created: created, owner: opened.sender, signer: opened.signer, share: share,
                         checkSalt: try Envelope.b64d(p["check_salt"], size: 16), check: try Envelope.b64d(p["check"], size: 32))
        } catch {
            throw HeirError("malformed", "This emergency access shard is damaged")
        }
    }

    /// Packages that must belong to one plan, each shard once (at least one).
    public static func checkShards(_ packages: [[UInt8]]) throws -> [Shard] {
        let shards = try packages.map(readPackage)
        guard let first = shards.first else {
            throw HeirError("need-more", "Add the shards you were given", missing: SSS.minK)
        }
        if shards.contains(where: { !$0.samePlan(first) }) { throw HeirError("mixed-plans", "These shards come from different plans") }
        if Set(shards.map(\.index)).count != shards.count { throw HeirError("duplicate", "The same shard was added twice") }
        return shards
    }

    /// The recovery entropy from at least `k` packages of one plan, confirmed against the plan's check.
    public static func combinePackages(_ packages: [[UInt8]]) throws -> [UInt8] {
        let shards = try checkShards(packages)
        let k = shards[0].k
        if shards.count < k {
            throw HeirError("need-more", "\(k - shards.count) more shard(s) needed", missing: k - shards.count)
        }
        // Review 5b M1: the shares are copied into one local buffer that is zeroed after the combine (Kotlin
        // `parts.forEach { it.fill(0) }`; value semantics make this best effort).
        var parts = shards.map(\.share)
        defer { for i in parts.indices { for j in parts[i].indices { parts[i][j] = 0 } } }
        var entropy: [UInt8]
        do { entropy = try SSS.combine(parts) } catch { throw HeirError("malformed") }
        if !verifyEntropy(shards[0], entropy) {
            for i in entropy.indices { entropy[i] = 0 }
            throw HeirError("check-failed", "These shards do not recover the owner's recovery phrase")
        }
        return entropy
    }

    /// `lgkheir:` + unpadded base64url of the package bytes; the package is verified first.
    public static func shardQRText(_ package: [UInt8]) throws -> String {
        _ = try readPackage(package)
        let text = qrPrefix + Base64URL.encodeNoPad(package)
        if text.count > qrLimit { throw HeirError("invalid", "This shard is too large for one QR code") }
        return text
    }

    /// The package bytes of a scanned `lgkheir:` text (verified).
    public static func package(fromQRText text: String) throws -> [UInt8] {
        let no = HeirError("malformed", "This QR code is not an emergency access shard")
        guard text.hasPrefix(qrPrefix), text.utf8.count <= qrLimit else { throw no }
        let body = String(text.dropFirst(qrPrefix.count))
        let allowed = body.utf8.allSatisfy { c in
            (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) || c == 0x2D || c == 0x5F
        }
        guard !body.isEmpty, allowed, body.utf8.count % 4 != 1, let data = decodeBase64URL(body, maxBytes: qrLimit) else {
            throw no
        }
        _ = try readPackage(data)
        return data
    }

    // MARK: the plan record

    /// Parses a plan record: the desktop's stored form (with `folder`, optional `home`) or the synced form a phone
    /// keeps. Throws `malformed` for anything the desktop's `_parse` refuses.
    public static func parsePlan(_ record: JSONValue?) throws -> HeirPlan {
        do {
            guard case .object(let r)? = record else { throw bad() }
            let optional: Set<String> = ["stale", "denied", "home", "folder"]
            guard Set(r.keys).subtracting(optional) == recordKeys.subtracting(["folder"]), r["version"] == .int(version) else {
                throw bad()
            }
            let stale = r["stale"] ?? .bool(false), home = r["home"] ?? .bool(true)
            guard case .bool(let isStale) = stale, case .bool = home else { throw bad() }
            if let folder = r["folder"] {
                switch folder {
                case .null, .string: break
                default: throw bad()
                }
            }
            try checkCounts(r["k"], r["n"], r["wait_days"])
            let n = try int(r["n"])
            let names = try holders(r["holders"], n)
            let seed = try Envelope.b64d(r["signing_key"], size: 32)
            let signer = try Envelope.b64d(r["signer"], size: 32)
            guard try Envelope.publicKey(seed: seed) == signer, case .int(let created)? = r["created"] else { throw bad() }
            guard let owner = str(r["owner"]), try printable(owner, limit: ownerLimit, allowEmpty: true) == owner else { throw bad() }
            guard case .array(let keys)? = r["holder_keys"], Int64(keys.count) == n else { throw bad() }
            let holderKeys = try keys.map { try Envelope.b64d($0, size: 32) }
            var denied: [JSONValue] = []
            if let d = r["denied"] {
                guard case .array(let a) = d else { throw bad() }
                denied = a
            }
            guard denied.count <= deniedLimit else { throw bad() }
            return HeirPlan(planID: try Envelope.checkedID(r["plan_id"]), k: Int(try int(r["k"])), n: Int(n), holders: names,
                            waitDays: Int(try int(r["wait_days"])), created: created, owner: owner, signer: signer, seed: seed,
                            checkSalt: try Envelope.b64d(r["check_salt"], size: 16),
                            check: try Envelope.b64d(r["check"], size: 32),
                            backupPublic: try Envelope.b64d(r["backup_public"], size: 32), holderKeys: holderKeys,
                            stale: isStale, denied: try denied.map { try Envelope.checkedID($0) })
        } catch {
            throw HeirError("malformed", "The stored emergency access plan is damaged")
        }
    }

    /// The synced form of a record: no local-only keys, `stale` and `denied` always present (desktop `synced_record`).
    public static func syncedRecord(_ record: JSONValue?) throws -> JSONValue {
        _ = try parsePlan(record)
        guard case .object(let r)? = record else { throw bad() }
        var out = r.filter { !localOnlyKeys.contains($0.key) }
        if out["stale"] == nil { out["stale"] = .bool(false) }
        if out["denied"] == nil { out["denied"] = .array([]) }
        return .object(out)
    }

    /// The synced record to keep when `remote` arrives (desktop `merge_synced`, keeping only the synced form). The
    /// same plan: `stale` is either side's and `denied` the union (the newest `deniedLimit`; the remote's order when
    /// nothing is new); every other field is pinned (`conflict` when it differs). Another plan replaces `local`.
    public static func mergeSynced(local: JSONValue?, remote: JSONValue?) throws -> JSONValue {
        guard case .object(let r)? = remote, Set(r.keys) == syncedKeys else {
            throw HeirError("malformed", "The synced emergency access plan is damaged")
        }
        guard case .object(let theirs) = try syncedRecord(remote) else { throw bad() }
        guard case .object(let l)? = local, l["plan_id"] == theirs["plan_id"] else {
            _ = try parsePlan(.object(theirs))
            return .object(theirs)
        }
        guard case .object(let mine) = try syncedRecord(local) else { throw bad() }
        if syncedKeys.subtracting(mutableKeys).contains(where: { mine[$0] != theirs[$0] }) {
            throw HeirError("conflict", "The synced emergency access plan differs from this one")
        }
        guard case .array(let localDenied)? = mine["denied"], case .array(let remoteDenied)? = theirs["denied"],
              case .bool(let ls)? = mine["stale"], case .bool(let rs)? = theirs["stale"] else { throw bad() }
        var denied = localDenied + remoteDenied.filter { !localDenied.contains($0) }
        if Set(denied.compactMap(str)) == Set(remoteDenied.compactMap(str)) { denied = remoteDenied }
        var stored = theirs
        stored["stale"] = .bool(ls || rs)
        stored["denied"] = .array(Array(denied.suffix(deniedLimit)))
        _ = try parsePlan(.object(stored))
        return .object(stored)
    }

    /// `states` to publish; without `heir` the plan's state is left out (desktop `publishable(heir=...)`): it goes
    /// only to peers that advertise the `heir` feature, so older apps never see a namespace they would refuse.
    public static func publishable(_ states: [ItemState], heir: Bool) -> [ItemState] {
        heir ? states : states.filter { $0.itemID != stateID }
    }

    /// `record` with `requestID` remembered as refused (the newest `deniedLimit` kept; desktop `add_denied`).
    public static func withDenied(_ record: JSONValue, requestID: String) throws -> JSONValue {
        guard Envelope.isID(requestID) else { throw bad() }
        _ = try parsePlan(record)
        guard case .object(var r) = record else { throw bad() }
        var before: [JSONValue] = []
        if case .array(let a)? = r["denied"] { before = a }
        let denied = before.filter { $0 != .string(requestID) } + [.string(requestID)]
        r["denied"] = .array(Array(denied.suffix(deniedLimit)))
        return .object(r)
    }

    /// Records `peer` as a Wi-Fi peer that reads the plan (desktop `set_heir_peer`): one commit, only when the list
    /// changes. Returns whether it changed.
    @discardableResult
    public static func setPeer(_ peer: String, store: any ItemStore) -> Bool {
        guard let snap = try? store.load(), var state = snap.sync, !state.heirPeers.contains(peer),
              state.heirPeers.count < 64, Identifier.isValid(peer) else { return false }
        state.heirPeers = (state.heirPeers + [peer]).sorted()
        return (try? store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta,
                                              sync: state))) != nil
    }
}
