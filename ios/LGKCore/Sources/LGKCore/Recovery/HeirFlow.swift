import Crypto
import Foundation

/// `reason`: `no-folder`, `no-plan`, `no-request`, `denied`, `waiting` (`daysLeft`), `need-more` (`missing`),
/// `no-backup`, `check-failed`, `stale-plan`, `malformed`, `mixed-plans`, `duplicate` or `wrong-phrase`
/// (desktop `heir_flow.HeirFlowError`).
public struct HeirFlowError: Error, Equatable, Sendable {
    public let reason: String
    public let missing: Int
    public let daysLeft: Int
    public init(_ reason: String, missing: Int = 0, daysLeft: Int = 0) {
        self.reason = reason; self.missing = missing; self.daysLeft = daysLeft
    }
}

/// A requester's keys, kept in the requester's own encrypted vault: Ed25519 signs requests, X25519 receives a grant.
public struct RequesterIdentity: Sendable, CustomStringConvertible {
    let seed: [UInt8]
    let box: [UInt8]

    public init(signingSeed: [UInt8], boxKey: [UInt8]) throws {
        guard signingSeed.count == 32, boxKey.count == 32,
              (try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: boxKey)) != nil else { throw HeirFlowError("malformed") }
        seed = signingSeed; box = boxKey
    }

    public var signer: [UInt8] { (try? Envelope.publicKey(seed: seed)) ?? [] }
    public var boxPublic: [UInt8] {
        (try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: box)).map { Array($0.publicKey.rawRepresentation) } ?? []
    }

    /// `{"version": 1, "signing_key", "box_key"}` (desktop `RequesterIdentity.to_record`).
    public func toRecord() -> JSONValue {
        .object(["version": .int(1), "signing_key": .string(Envelope.b64e(seed)), "box_key": .string(Envelope.b64e(box))])
    }

    public static func generate(random: any RandomSource) throws -> RequesterIdentity {
        try RequesterIdentity(signingSeed: random.bytes(count: 32), boxKey: random.bytes(count: 32))
    }

    public static func fromRecord(_ record: JSONValue?) throws -> RequesterIdentity {
        guard case .object(let r)? = record, Set(r.keys) == ["version", "signing_key", "box_key"], r["version"] == .int(1),
              let s = try? Envelope.b64d(r["signing_key"], size: 32), let b = try? Envelope.b64d(r["box_key"], size: 32) else {
            throw HeirFlowError("malformed")
        }
        return try RequesterIdentity(signingSeed: s, boxKey: b)
    }

    public var description: String { "RequesterIdentity" }
}

/// One verified access request in the folder; `holder`, `daysLeft` and `granted` are filled for the owner's list.
public struct HeirRequest: Sendable, Identifiable, CustomStringConvertible {
    public let requestID: String
    public let planID: String
    public let holderIndex: Int
    public let requester: String
    public let signer: [UInt8]
    public let boxPublic: [UInt8]
    public let created: Int64
    let proof: [UInt8]
    public var holder: String = ""
    public var daysLeft: Int = 0
    public var granted: Bool = false

    public var id: String { requestID }
    public var description: String { "HeirRequest(\(requestID))" }
}

/// The owner's open requests (newest first), plus `flooded`: too many request files to read them all.
public struct HeirPending: Sendable {
    public let requests: [HeirRequest]
    public let flooded: Bool
}

/// What the requester's screen says: `none` (ask first), `denied`, `need-more` (`missing`), `waiting` (`daysLeft`),
/// `no-backup` or `ready` (desktop `heir_flow.Status`).
public struct HeirStatus: Equatable, Sendable {
    public var state: String
    public var planID = ""
    public var owner = ""
    public var k = 0
    public var have = 0
    public var requestID = ""
    public var daysLeft = 0
    public var missing = 0
    public var granted = false
}

/// The heir folder, a folder the owner shares with the holders. `rootName` is the picked folder's own name: picking
/// `LocalGateKeys Emergency` itself also works, as on the desktop (`plan_dir`).
public struct HeirFolder: Sendable {
    public let access: any FolderAccess
    public let rootName: String?
    public init(access: any FolderAccess, rootName: String? = nil) { self.access = access; self.rootName = rootName }
}

/// Emergency access flows with no server: port of `src/localvault/heir_flow.py` and Android `HeirFlow.kt` (byte rules
/// in `docs/formats/LGKHEIR_V1.md` "Folder flow"). Every file in `<folder>/LocalGateKeys Emergency/<plan id>/` is a
/// signed envelope with its own `kind` and exact payload keys; nothing in the folder is trusted.
///
/// An iPhone or Mac takes part as one of the owner's devices (the plan arrives by sync: list requests, deny, grant now
/// with the typed phrase) and as a holder (ask for access, follow the status, then recover and check the owner's
/// recovery phrase). The owner's backups in the folder are written and restored by the computer; this device only
/// reads their signed descriptors. Times are integer Unix seconds from the caller.
public enum HeirFlow {
    public static let folderName = "LocalGateKeys Emergency"
    public static let day: Int64 = 86_400
    public static let requestSuffix = ".lgkheirreq"
    public static let denySuffix = ".lgkheirdeny"
    public static let grantSuffix = ".lgkheirgrant"
    public static let descriptorSuffix = ".lgkheirbackup"
    public static let backupSuffix = ".lgk"
    static let heirSuffixes = [".lgkheir", requestSuffix, denySuffix, grantSuffix, descriptorSuffix]
    public static let requestKind = "heir-request"
    public static let denyKind = "heir-deny"
    public static let grantKind = "heir-grant"
    public static let backupKind = "heir-backup"
    public static let maxFile = 8192
    public static let maxScan = 512
    public static let maxRequestScan = 4096
    static let proofContext: [UInt8] = Array("LocalGateKeys heir request v1\n".utf8)
    static let grantInfo: [UInt8] = Array("LocalGateKeys heir grant v1\n".utf8)
    static let requestFields: Set<String> = ["kind", "plan_id", "holder_index", "box_public", "created", "proof"]
    static let denyFields: Set<String> = ["kind", "plan_id", "request_id", "created"]
    static let grantFields: Set<String> = ["kind", "plan_id", "request_id", "box_public", "ephemeral", "wrapped", "created"]
    static let backupFields: Set<String> = ["kind", "plan_id", "file", "size", "sha256", "written_at", "backup_public"]
    static let maxTime: Int64 = (1 << 53) - 1

    // MARK: file names (the Kotlin regexes, spelled out)

    static func isDigits(_ s: Substring, _ n: Int) -> Bool { s.utf8.count == n && s.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }
    static func isLowerHex(_ s: Substring, _ n: Int) -> Bool {
        s.utf8.count == n && s.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }

    /// `backup-\d{8}-\d{6}-[0-9a-f]{8}`.
    static func isBackupStem(_ s: String) -> Bool {
        let parts = s.split(separator: "-", omittingEmptySubsequences: false)
        return parts.count == 4 && parts[0] == "backup" && isDigits(parts[1], 8) && isDigits(parts[2], 6) && isLowerHex(parts[3], 8)
    }

    static func stem(_ name: String, prefix: String, suffix: String) -> String? {
        guard name.hasPrefix(prefix), name.hasSuffix(suffix), name.count >= prefix.count + suffix.count else { return nil }
        return String(name.dropFirst(prefix.count).dropLast(suffix.count))
    }

    /// `request-<uuid>.lgkheirreq`.
    static func isRequestName(_ name: String) -> Bool {
        stem(name, prefix: "request-", suffix: requestSuffix).map(Envelope.isID) ?? false
    }

    /// `deny-<uuid>[ ()A-Za-z0-9_-]{0,40}.lgkheirdeny` (and the same for grants): a copy a cloud drive renamed.
    static func isTaggedName(_ name: String, prefix: String, suffix: String) -> Bool {
        guard let body = stem(name, prefix: prefix, suffix: suffix), body.utf8.count >= 36 else { return false }
        let id = String(body.prefix(36)), rest = body.dropFirst(36)
        guard Envelope.isID(id), rest.utf8.count <= 40 else { return false }
        return rest.utf8.allSatisfy { c in
            c == 0x20 || c == 0x28 || c == 0x29 || c == 0x2D || c == 0x5F || (c >= 0x30 && c <= 0x39)
                || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)
        }
    }

    static func isDenyName(_ name: String) -> Bool { isTaggedName(name, prefix: "deny-", suffix: denySuffix) }
    static func isGrantName(_ name: String) -> Bool { isTaggedName(name, prefix: "grant-", suffix: grantSuffix) }
    static func isDescriptorName(_ name: String) -> Bool {
        name.hasSuffix(descriptorSuffix) && isBackupStem(String(name.dropLast(descriptorSuffix.count)))
    }

    // MARK: the folder

    /// `LocalGateKeys Emergency/<plan id>` inside `folder` (`<plan id>` when the picked folder is the emergency folder).
    public static func planDir(_ folder: HeirFolder, planID: String) throws -> String {
        guard Envelope.isID(planID) else { throw HeirFlowError("malformed") }
        return folder.rootName == folderName ? planID : "\(folderName)/\(planID)"
    }

    static func join(_ dir: String, _ name: String) -> String { dir.isEmpty ? name : "\(dir)/\(name)" }

    /// Whether a folder entry belongs to emergency access (the folder sync ignores these).
    public static func isHeirFile(_ name: String) -> Bool {
        if name == folderName || heirSuffixes.contains(where: { name.hasSuffix($0) }) { return true }
        return name.hasSuffix(backupSuffix) && isBackupStem(String(name.dropLast(backupSuffix.count)))
    }

    static func write(_ folder: HeirFolder, _ path: String, _ data: [UInt8]) throws {
        do { try folder.access.writeAtomic(path, data) } catch { throw HeirFlowError("no-folder") }
    }

    static func readSmall(_ folder: HeirFolder, _ path: String, limit: Int = maxFile) -> [UInt8]? {
        guard let data = try? folder.access.read(path, limit: limit + 1), data.count <= limit else { return nil }
        return data
    }

    static func entries(_ folder: HeirFolder, _ dir: String, _ match: (String) -> Bool, cap: Int = maxScan) -> [String] {
        guard let names = try? folder.access.list(dir) else { return [] }
        return names.filter(match).sorted().prefix(cap).map { join(dir, $0) }
    }

    static func flooded(_ folder: HeirFolder, _ dir: String) -> Bool {
        guard let names = try? folder.access.list(dir) else { return false }
        return names.filter(isRequestName).count > maxRequestScan
    }

    /// A signed heir file of `kind` with exactly `fields`, or nil (never throws).
    static func open(_ data: [UInt8]?, kind: String, fields: Set<String>) -> SignedEnvelope? {
        guard let data, let opened = try? Envelope.open(data, format: Heir.format, version: Heir.version, limit: maxFile),
              Set(opened.payload.keys) == fields, opened.payload["kind"] == .string(kind) else { return nil }
        return opened
    }

    static func signed(_ payload: [String: JSONValue], seed: [UInt8], packageID: String, sender: String = "",
                       sign: Envelope.Signer? = nil) throws -> [UInt8] {
        try Envelope.seal(format: Heir.format, version: Heir.version, packageID: packageID, sender: sender, payload: payload,
                          seed: seed, sign: sign)
    }

    static func isTime(_ v: JSONValue?) -> Bool {
        if case .int(let t)? = v { return t >= 0 && t <= maxTime }
        return false
    }

    static func daysLeft(_ deadline: Int64, _ now: Int64) -> Int {
        deadline <= now ? 0 : Int((deadline - now + day - 1) / day)
    }

    static func uuid4(_ random: any RandomSource) throws -> String {
        do { return try SyncGroup.uuid4(random: random) } catch { throw HeirFlowError("malformed") }
    }

    // MARK: requests

    static func proofMessage(planID: String, requestID: String, holderIndex: Int, signer: [UInt8], boxPublic: [UInt8],
                             created: Int64) throws -> [UInt8] {
        proofContext + (try Envelope.canonical(.object([
            "plan_id": .string(planID), "request_id": .string(requestID), "holder_index": .int(Int64(holderIndex)),
            "signer": .string(Envelope.b64e(signer)), "box_public": .string(Envelope.b64e(boxPublic)), "created": .int(created),
        ])))
    }

    static func proof(key: [UInt8], planID: String, requestID: String, holderIndex: Int, signer: [UInt8],
                      boxPublic: [UInt8], created: Int64) throws -> [UInt8] {
        let msg = try proofMessage(planID: planID, requestID: requestID, holderIndex: holderIndex, signer: signer,
                                   boxPublic: boxPublic, created: created)
        return Array(HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: key)))
    }

    static func readRequest(_ folder: HeirFolder, _ path: String, planID: String) -> HeirRequest? {
        guard let opened = open(readSmall(folder, path), kind: requestKind, fields: requestFields) else { return nil }
        let p = opened.payload
        guard case .int(let index)? = p["holder_index"], p["plan_id"] == .string(planID), (1...5).contains(index),
              isTime(p["created"]), case .int(let created)? = p["created"],
              let box = try? Envelope.b64d(p["box_public"], size: 32), let mac = try? Envelope.b64d(p["proof"], size: 32) else {
            return nil
        }
        return HeirRequest(requestID: opened.id, planID: planID, holderIndex: Int(index), requester: opened.sender,
                           signer: opened.signer, boxPublic: box, created: created, proof: mac)
    }

    static func requests(_ folder: HeirFolder, _ dir: String, planID: String) -> [HeirRequest] {
        entries(folder, dir, isRequestName, cap: maxRequestScan).compactMap { readRequest(folder, $0, planID: planID) }
            .sorted { $0.created != $1.created ? $0.created > $1.created : $0.requestID > $1.requestID }
    }

    static func readShard(_ data: [UInt8]) throws -> Shard {
        do { return try Heir.readPackage(data) } catch let e as HeirError { throw fromHeir(e) }
    }

    static func fromHeir(_ e: HeirError) -> HeirFlowError {
        switch e.reason {
        case "need-more": return HeirFlowError("need-more", missing: e.missing)
        case "check-failed", "mixed-plans", "duplicate": return HeirFlowError(e.reason)
        default: return HeirFlowError("malformed")
        }
    }

    /// The request file a holder writes for the plan of `shard` (their package); `requestID` is its envelope id.
    public static func requestBytes(shard: [UInt8], identity: RequesterIdentity, requestID: String, created: Int64,
                                    sign: Envelope.Signer? = nil) throws -> [UInt8] {
        let holderShard = try readShard(shard)
        guard Envelope.isID(requestID), created >= 0, created <= maxTime else { throw HeirFlowError("malformed") }
        let box = identity.boxPublic
        var key = try Heir.holderKey(holderShard.share, planID: holderShard.planID, salt: holderShard.checkSalt)
        defer { for i in key.indices { key[i] = 0 } }
        let mac = try proof(key: key, planID: holderShard.planID, requestID: requestID, holderIndex: holderShard.index,
                            signer: identity.signer, boxPublic: box, created: created)
        let payload: [String: JSONValue] = [
            "kind": .string(requestKind), "plan_id": .string(holderShard.planID),
            "holder_index": .int(Int64(holderShard.index)), "box_public": .string(Envelope.b64e(box)),
            "created": .int(created), "proof": .string(Envelope.b64e(mac)),
        ]
        return try signed(payload, seed: identity.seed, packageID: requestID, sender: holderShard.holder, sign: sign)
    }

    /// Writes a signed access request for the plan of `shard` into the folder; returns its path.
    @discardableResult
    public static func requestAccess(_ folder: HeirFolder, shard: [UInt8], identity: RequesterIdentity, now: Int64,
                                     random: any RandomSource) throws -> String {
        let planID = try readShard(shard).planID
        let requestID = try uuid4(random)
        let path = join(try planDir(folder, planID: planID), "request-\(requestID)\(requestSuffix)")
        try write(folder, path, try requestBytes(shard: shard, identity: identity, requestID: requestID, created: now))
        return path
    }

    // MARK: deny and grant files

    static func validDeny(_ folder: HeirFolder, _ path: String, signer: [UInt8], planID: String) -> String? {
        guard let opened = open(readSmall(folder, path), kind: denyKind, fields: denyFields),
              Envelope.same(opened.signer, signer), opened.payload["plan_id"] == .string(planID),
              case .string(let rid)? = opened.payload["request_id"] else { return nil }
        return rid
    }

    static func denials(_ folder: HeirFolder, _ dir: String, signer: [UInt8], planID: String) -> Set<String> {
        Set(entries(folder, dir, isDenyName).compactMap { validDeny(folder, $0, signer: signer, planID: planID) })
    }

    /// Any valid deny for this request by the plan key, whatever its time (the veto); its own name is read first.
    static func denyPresent(_ folder: HeirFolder, _ dir: String, signer: [UInt8], planID: String, requestID: String) -> Bool {
        if validDeny(folder, join(dir, "deny-\(requestID)\(denySuffix)"), signer: signer, planID: planID) == requestID { return true }
        return denials(folder, dir, signer: signer, planID: planID).contains(requestID)
    }

    struct GrantKey: Hashable { let requestID: String; let box: String }

    static func grantIndex(_ folder: HeirFolder, _ dir: String, signer: [UInt8], planID: String) -> [GrantKey: [SignedEnvelope]] {
        var out: [GrantKey: [SignedEnvelope]] = [:]
        for path in entries(folder, dir, isGrantName) {
            guard let opened = open(readSmall(folder, path), kind: grantKind, fields: grantFields),
                  Envelope.same(opened.signer, signer), opened.payload["plan_id"] == .string(planID),
                  case .string(let rid)? = opened.payload["request_id"], case .string(let box)? = opened.payload["box_public"] else {
                continue
            }
            out[GrantKey(requestID: rid, box: box), default: []].append(opened)
        }
        return out
    }

    static func grantAAD(planID: String, requestID: String, boxPublic: [UInt8]) throws -> [UInt8] {
        grantInfo + (try Envelope.canonical(.object([
            "plan_id": .string(planID), "request_id": .string(requestID), "box_public": .string(Envelope.b64e(boxPublic)),
        ])))
    }

    static func grantKEK(shared: [UInt8], ephemeral: [UInt8], boxPublic: [UInt8], planID: String, requestID: String) -> [UInt8] {
        let info = grantInfo + Array(planID.utf8) + Array("\n".utf8) + Array(requestID.utf8)
        return CryptoBox.hkdf(ikm: shared, salt: ephemeral + boxPublic, info: info, length: 32)
    }

    static func agree(_ privateKey: [UInt8], _ publicKey: [UInt8]) throws -> [UInt8] {
        guard let priv = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey),
              let pub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey),
              let secret = try? priv.sharedSecretFromKeyAgreement(with: pub) else { throw HeirFlowError("malformed") }
        return secret.withUnsafeBytes { Array($0) }
    }

    static func x25519Public(_ privateKey: [UInt8]) throws -> [UInt8] {
        guard let priv = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey) else { throw HeirFlowError("malformed") }
        return Array(priv.publicKey.rawRepresentation)
    }

    /// The grant file: `entropy` wrapped to the request's X25519 key with the ephemeral key `ephemeralKey`, signed by
    /// the plan key.
    public static func grantBytes(plan: HeirPlan, request: HeirRequest, entropy: [UInt8], now: Int64,
                                  ephemeralKey: [UInt8], packageID: String, sign: Envelope.Signer? = nil) throws -> [UInt8] {
        let epk = try x25519Public(ephemeralKey)
        let box = request.boxPublic
        var shared = try agree(ephemeralKey, box)
        var kek = grantKEK(shared: shared, ephemeral: epk, boxPublic: box, planID: plan.planID, requestID: request.requestID)
        for i in shared.indices { shared[i] = 0 }
        defer { for i in kek.indices { kek[i] = 0 } }
        let wrapped = try CryptoBox.sealGCM(key: kek, nonce: [UInt8](repeating: 0, count: 12), plaintext: entropy,
                                            aad: try grantAAD(planID: plan.planID, requestID: request.requestID, boxPublic: box))
        let payload: [String: JSONValue] = [
            "kind": .string(grantKind), "plan_id": .string(plan.planID), "request_id": .string(request.requestID),
            "box_public": .string(Envelope.b64e(box)), "ephemeral": .string(Envelope.b64e(epk)),
            "wrapped": .string(Envelope.b64e(wrapped)), "created": .int(now),
        ]
        return try signed(payload, seed: plan.signingSeed(), packageID: packageID, sign: sign)
    }

    /// The entropy of a grant made out to `identity`, or nil.
    public static func openGrant(_ grant: SignedEnvelope, identity: RequesterIdentity) -> [UInt8]? {
        let p = grant.payload
        guard case .string(let planID)? = p["plan_id"], case .string(let requestID)? = p["request_id"],
              let epk = try? Envelope.b64d(p["ephemeral"], size: 32), let wrapped = try? Envelope.b64d(p["wrapped"], size: 48),
              var shared = try? agree(identity.box, epk) else { return nil }
        var kek = grantKEK(shared: shared, ephemeral: epk, boxPublic: identity.boxPublic, planID: planID, requestID: requestID)
        for i in shared.indices { shared[i] = 0 }
        defer { for i in kek.indices { kek[i] = 0 } }
        guard let aad = try? grantAAD(planID: planID, requestID: requestID, boxPublic: identity.boxPublic) else { return nil }
        return try? CryptoBox.openGCM(key: kek, nonce: [UInt8](repeating: 0, count: 12), ciphertext: wrapped, aad: aad)
    }

    /// Opens a grant file's bytes (signature and fields checked) for tests and the requester's flow.
    public static func readGrant(_ data: [UInt8]) -> SignedEnvelope? { open(data, kind: grantKind, fields: grantFields) }

    /// The deny file for `requestID`, signed by the plan key.
    public static func denyBytes(plan: HeirPlan, requestID: String, now: Int64, packageID: String,
                                 sign: Envelope.Signer? = nil) throws -> [UInt8] {
        let payload: [String: JSONValue] = [
            "kind": .string(denyKind), "plan_id": .string(plan.planID), "request_id": .string(requestID), "created": .int(now),
        ]
        return try signed(payload, seed: plan.signingSeed(), packageID: packageID, sign: sign)
    }

    // MARK: the owner's side

    static func verified(_ request: HeirRequest, _ plan: HeirPlan) -> Bool {
        guard request.planID == plan.planID, (1...plan.n).contains(request.holderIndex),
              let expect = try? proof(key: plan.holderKey(request.holderIndex), planID: request.planID,
                                      requestID: request.requestID, holderIndex: request.holderIndex, signer: request.signer,
                                      boxPublic: request.boxPublic, created: request.created) else { return false }
        return Envelope.same(expect, request.proof)
    }

    @discardableResult
    static func writeDeny(_ folder: HeirFolder, _ dir: String, plan: HeirPlan, requestID: String, now: Int64,
                          random: any RandomSource) throws -> String {
        let path = join(dir, "deny-\(requestID)\(denySuffix)")
        try write(folder, path, try denyBytes(plan: plan, requestID: requestID, now: now, packageID: try uuid4(random)))
        return path
    }

    /// The owner's open requests: only those that prove a shard of this plan and are not denied. A request the owner
    /// refused (`HeirPlan.denied`) whose deny file is missing gets it written again (best effort).
    public static func pending(plan: HeirPlan, folder: HeirFolder, now: Int64, random: any RandomSource) throws -> HeirPending {
        let dir = try planDir(folder, planID: plan.planID)
        if plan.stale { purgeBackups(folder, dir) } // the replaced phrase's backups: old shards must find nothing to open
        let denied = denials(folder, dir, signer: plan.signer, planID: plan.planID)
        let grants = grantIndex(folder, dir, signer: plan.signer, planID: plan.planID)
        var out: [HeirRequest] = []
        for request in requests(folder, dir, planID: plan.planID) {
            guard verified(request, plan), !denied.contains(request.requestID) else { continue }
            if plan.denied.contains(request.requestID) {
                _ = try? writeDeny(folder, dir, plan: plan, requestID: request.requestID, now: now, random: random)
                continue
            }
            var listed = request
            listed.holder = plan.holders[request.holderIndex - 1]
            listed.daysLeft = daysLeft(request.created + Int64(plan.waitDays) * day, now)
            listed.granted = grants[GrantKey(requestID: request.requestID, box: Envelope.b64e(request.boxPublic))] != nil
            out.append(listed)
        }
        return HeirPending(requests: out, flooded: flooded(folder, dir))
    }

    /// Deletes every backup file and descriptor in a plan's folder (best effort; the number deleted). Run on each look
    /// at a stale plan: those backups are locked to the replaced phrase (`LGKHEIR_V1.md` "Stale plans").
    @discardableResult
    public static func purgeBackups(_ folder: HeirFolder, _ dir: String) -> Int {
        guard let names = try? folder.access.list(dir) else { return 0 }
        var removed = 0
        for name in names where isHeirBackupOrDescriptor(name) {
            if (try? folder.access.remove(join(dir, name))) != nil { removed += 1 } // a failure: the next look tries again
        }
        return removed
    }

    static func isHeirBackupOrDescriptor(_ name: String) -> Bool {
        if isDescriptorName(name) { return true }
        return name.hasSuffix(backupSuffix) && isBackupStem(String(name.dropLast(backupSuffix.count)))
    }

    /// The request as it is in the folder now, re-verified (never the caller's copy).
    static func findRequest(plan: HeirPlan, folder: HeirFolder, requestID: String) throws -> (String, HeirRequest) {
        guard Envelope.isID(requestID) else { throw HeirFlowError("malformed") }
        let dir = try planDir(folder, planID: plan.planID)
        guard let found = requests(folder, dir, planID: plan.planID).first(where: { $0.requestID == requestID && verified($0, plan) }) else {
            throw HeirFlowError("no-request")
        }
        return (dir, found)
    }

    /// Refuses a request: writes a deny file signed by the plan key. The caller keeps `Heir.withDenied` of the plan
    /// record first (so it is written again if it goes missing, and the refusal syncs to the owner's other devices).
    @discardableResult
    public static func deny(plan: HeirPlan, folder: HeirFolder, requestID: String, now: Int64,
                            random: any RandomSource) throws -> String {
        guard Envelope.isID(requestID) else { throw HeirFlowError("malformed") }
        return try writeDeny(folder, try planDir(folder, planID: plan.planID), plan: plan, requestID: requestID, now: now,
                             random: random)
    }

    /// "Grant now" (the plan arrived by sync, so the plan's check decides the typed phrase). The caller
    /// re-authenticates the owner first. Order: the request (still in the folder, proving a shard), not denied, plan
    /// current, then the phrase against the plan's HKDF check (`wrong-phrase`).
    @discardableResult
    public static func grantNow(plan: HeirPlan, folder: HeirFolder, requestID: String, phrase: String, now: Int64,
                                random: any RandomSource) throws -> String {
        let (dir, found) = try findRequest(plan: plan, folder: folder, requestID: requestID)
        if plan.denied.contains(found.requestID)
            || denyPresent(folder, dir, signer: plan.signer, planID: plan.planID, requestID: found.requestID) {
            throw HeirFlowError("denied")
        }
        if plan.stale { throw HeirFlowError("stale-plan") }
        guard var data = try? BIP39.entropy(from: phrase) else { throw HeirFlowError("wrong-phrase") }
        var entropy = [UInt8](data)
        data.resetBytes(in: data.startIndex..<data.endIndex)   // review 5b M2: the source buffer too
        var ephemeral = random.bytes(count: 32)
        defer {
            for i in entropy.indices { entropy[i] = 0 }
            for i in ephemeral.indices { ephemeral[i] = 0 }
        }
        guard Heir.verifyEntropy(plan, entropy) else { throw HeirFlowError("wrong-phrase") }
        let bytes = try grantBytes(plan: plan, request: found, entropy: entropy, now: now, ephemeralKey: ephemeral,
                                   packageID: try uuid4(random))
        let path = join(dir, "grant-\(found.requestID)\(grantSuffix)")
        try write(folder, path, bytes)
        return path
    }

    // MARK: the owner's backups (read only here)

    /// One valid backup descriptor by the plan key.
    public struct BackupInfo: Sendable {
        public let file: String
        public let size: Int64
        public let sha256: String
        public let writtenAt: Int64
        public let backupPublic: [UInt8]
    }

    /// Valid descriptors by the plan key, newest first.
    public static func backups(_ folder: HeirFolder, _ dir: String, signer: [UInt8], planID: String) -> [BackupInfo] {
        var out: [BackupInfo] = []
        for path in entries(folder, dir, isDescriptorName) {
            guard let opened = open(readSmall(folder, path), kind: backupKind, fields: backupFields),
                  Envelope.same(opened.signer, signer) else { continue }
            let p = opened.payload
            guard case .string(let name)? = p["file"], case .int(let size)? = p["size"], case .string(let sha)? = p["sha256"],
                  p["plan_id"] == .string(planID), name.hasSuffix(backupSuffix),
                  isBackupStem(String(name.dropLast(backupSuffix.count))), isTime(p["written_at"]),
                  case .int(let writtenAt)? = p["written_at"], size > 0, isLowerHex(Substring(sha), 64),
                  let pub = try? Envelope.b64d(p["backup_public"], size: 32) else { continue }
            out.append(BackupInfo(file: name, size: size, sha256: sha, writtenAt: writtenAt, backupPublic: pub))
        }
        return out.sorted { $0.writtenAt != $1.writtenAt ? $0.writtenAt > $1.writtenAt : $0.file > $1.file }
    }

    // MARK: the requester's side

    struct Evaluation {
        let status: HeirStatus
        let shards: [Shard]
        let dir: String
        let request: HeirRequest?
        let grant: SignedEnvelope?
    }

    static func evaluate(_ folder: HeirFolder, packages: [[UInt8]], identity: RequesterIdentity, now: Int64) throws -> Evaluation {
        let shards: [Shard]
        do { shards = try Heir.checkShards(packages) } catch let e as HeirError { throw fromHeir(e) }
        let base = shards[0]
        let dir = try planDir(folder, planID: base.planID)
        let signer = identity.signer, box = identity.boxPublic
        func status(_ state: String, _ requestID: String = "", daysLeft: Int = 0, missing: Int = 0, granted: Bool = false) -> HeirStatus {
            HeirStatus(state: state, planID: base.planID, owner: base.owner, k: base.k, have: shards.count,
                       requestID: requestID, daysLeft: daysLeft, missing: missing, granted: granted)
        }
        let mine = requests(folder, dir, planID: base.planID).filter {
            Envelope.same($0.signer, signer) && Envelope.same($0.boxPublic, box)
        }
        guard let request = mine.first else { return Evaluation(status: status("none"), shards: shards, dir: dir, request: nil, grant: nil) }
        let rid = request.requestID
        if denyPresent(folder, dir, signer: base.signer, planID: base.planID, requestID: rid) {
            return Evaluation(status: status("denied", rid), shards: shards, dir: dir, request: request, grant: nil)
        }
        let grant = grantIndex(folder, dir, signer: base.signer, planID: base.planID)[GrantKey(requestID: rid, box: Envelope.b64e(box))]?.first
        if grant == nil {
            if shards.count < base.k {
                return Evaluation(status: status("need-more", rid, missing: base.k - shards.count), shards: shards, dir: dir,
                                  request: request, grant: nil)
            }
            let left = daysLeft(request.created + Int64(base.waitDays) * day, now)
            if left > 0 {
                return Evaluation(status: status("waiting", rid, daysLeft: left), shards: shards, dir: dir, request: request, grant: nil)
            }
        }
        let backup = backups(folder, dir, signer: base.signer, planID: base.planID).contains { $0.writtenAt >= base.created }
        return Evaluation(status: status(backup ? "ready" : "no-backup", rid, granted: grant != nil), shards: shards, dir: dir,
                          request: request, grant: grant)
    }

    /// Where the requester stands (reads the folder; recovers nothing).
    public static func requestStatus(_ folder: HeirFolder, packages: [[UInt8]], identity: RequesterIdentity,
                                     now: Int64) throws -> HeirStatus {
        try evaluate(folder, packages: packages, identity: identity, now: now).status
    }

    /// The owner's recovery entropy for a requester whose access is open (a grant, or `k` shards once the waiting
    /// period is over), checked against the plan's HKDF check before it is returned and with the veto read again
    /// last. The caller shows the phrase (`BIP39.phrase`) and zeroes the bytes. Refused: `no-request`, `denied`,
    /// `need-more`, `waiting`, `malformed` (a grant that does not open), `check-failed`, `no-backup` (no descriptor
    /// newer than the plan locked to this entropy's backup key, as the desktop's restore requires).
    public static func recoverEntropy(_ folder: HeirFolder, packages: [[UInt8]], identity: RequesterIdentity,
                                      now: Int64) throws -> [UInt8] {
        let e = try evaluate(folder, packages: packages, identity: identity, now: now)
        switch e.status.state {
        case "none": throw HeirFlowError("no-request")
        case "denied": throw HeirFlowError("denied")
        case "need-more": throw HeirFlowError("need-more", missing: e.status.missing)
        case "waiting": throw HeirFlowError("waiting", daysLeft: e.status.daysLeft)
        // The desktop restores only a backup newer than the plan; nothing is revealed without one (Ruling T2-M1:
        // after the owner replaces the phrase, old shards must not open anything).
        case "no-backup": throw HeirFlowError("no-backup")
        default: break
        }
        let base = e.shards[0]
        guard let request = e.request else { throw HeirFlowError("no-request") }
        var entropy: [UInt8]
        if let grant = e.grant {
            guard let opened = openGrant(grant, identity: identity) else { throw HeirFlowError("malformed") }
            entropy = opened
        } else {
            do { entropy = try Heir.combinePackages(packages) } catch let x as HeirError { throw fromHeir(x) }
        }
        func refuse(_ reason: String) -> HeirFlowError {
            for i in entropy.indices { entropy[i] = 0 }
            return HeirFlowError(reason)
        }
        // The recovered secret is checked against the plan's HKDF check before anything uses it.
        guard Heir.verifyEntropy(base, entropy) else { throw refuse("check-failed") }
        // As the desktop's `_open_backup`: a descriptor newer than the plan whose backup is locked to this entropy's
        // backup key. A replaced phrase (a new plan or new backups under another key) leaves old shards with nothing.
        guard let expected = try? Heir.backupPublicKey(entropy, planID: base.planID, salt: base.checkSalt),
              backups(folder, e.dir, signer: base.signer, planID: base.planID)
                .contains(where: { $0.writtenAt >= base.created && Envelope.same($0.backupPublic, expected) }) else {
            throw refuse("no-backup")
        }
        if denyPresent(folder, e.dir, signer: base.signer, planID: base.planID, requestID: request.requestID) {
            throw refuse("denied")
        }
        return entropy
    }
}
