import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// One state in a phone backup: the stored form of an item (desktop `ItemState`).
public struct BackupState: Equatable, Sendable {
    public var id: String
    public var deleted: Bool
    /// Unix seconds, 0...2^53-1, or nil.
    public var deletedAt: Int64?
    /// An object exactly when the state is live; nil for a tombstone.
    public var item: JSONValue?
    /// Version vector; zero counters are dropped on write.
    public var vv: [String: Int64]

    public init(id: String, deleted: Bool, deletedAt: Int64?, item: JSONValue?, vv: [String: Int64]) {
        self.id = id; self.deleted = deleted; self.deletedAt = deletedAt; self.item = item; self.vv = vv
    }
}

/// The opened contents of a backup.
public struct BackupPayload: Equatable, Sendable {
    public var createdAt: Int64
    public var platform: String
    public var appVersion: String
    public var deviceID: String
    public var proHint: Bool
    public var states: [BackupState]
    /// Format 2: blob id -> sealed sync blob (`LGKABLB1`) of the live documents' files; empty in format 1.
    /// Checked for shape and naming only; a file is opened against its reference when it is restored.
    public var files: [String: [UInt8]]

    public init(createdAt: Int64, platform: String, appVersion: String, deviceID: String, proHint: Bool,
                states: [BackupState], files: [String: [UInt8]] = [:]) {
        self.createdAt = createdAt; self.platform = platform; self.appVersion = appVersion
        self.deviceID = deviceID; self.proHint = proHint; self.states = states; self.files = files
    }
}

/// The `LGKMBAK1` encrypted phone backup (desktop `localvault/phone_backup.py`). Version 1 is frozen; version 2
/// (2026-10-29) adds the payload key `files`, the sealed blobs of the live documents' files.
public enum PhoneBackup {
    public enum Error: Swift.Error, Equatable, Sendable {
        case tooLarge, notABackup, unsupportedVersion, badKDF, wrongPassword, badPayload
    }

    public static let format = "LGKMBAK1"
    public static let version: Int64 = 1
    /// The format that carries document files (written only when at least one file is included).
    public static let filesVersion: Int64 = 2
    public static let platform = "ios"
    public static let maxFileBytes = 256 * 1024 * 1024
    /// Writers include document files until their sealed blobs add up to this; the rest are left out.
    public static let maxBackupFilesBytes = 160 * 1024 * 1024
    public static let maxFiles = 500
    public static let maxStates = 20000
    static let timeCost: Int64 = 4, memoryKiB: Int64 = 131072, parallelism: Int64 = 4
    static let maxInt: Int64 = (1 << 53) - 1

    // MARK: write

    /// Version 2 when `files` (blob id -> sealed sync blob, see `selectFiles`) is non-empty, else version 1.
    public static func seal(states: [BackupState], password: String, appVersion: String, deviceID: String,
                            proHint: Bool, now: Date, random: RandomSource, files: [String: [UInt8]] = [:]) throws -> Data {
        try seal(states: states, password: password, appVersion: appVersion, deviceID: deviceID, proHint: proHint,
                 now: now, random: random, files: files, writerPlatform: platform)
    }

    /// `seal` under another header platform (tests rewrite the desktop's `android` vectors byte for byte).
    static func seal(states: [BackupState], password: String, appVersion: String, deviceID: String, proHint: Bool,
                     now: Date, random: RandomSource, files: [String: [UInt8]], writerPlatform: String) throws -> Data {
        let createdAt = Int64(now.timeIntervalSince1970.rounded(.down))
        let ordered = states.sorted { Array($0.id.utf8).lexicographicallyPrecedes(Array($1.id.utf8)) }
        guard validAppVersion(appVersion), Identifier.isValid(deviceID), ordered.count <= maxStates,
              (0...maxInt).contains(createdAt) else { throw Error.badPayload }
        var stateValues: [JSONValue] = []
        var itemStates: [ItemState] = []
        var previous: String?
        for s in ordered {
            if let p = previous, p == s.id { throw Error.badPayload }
            previous = s.id
            let vv = s.vv.filter { $0.value != 0 }
            do {
                itemStates.append(try ItemState(itemID: s.id, vv: vv, deleted: s.deleted, deletedAt: s.deletedAt, item: s.item))
            } catch { throw Error.badPayload }
            stateValues.append(.object([
                "deleted": .bool(s.deleted),
                "deleted_at": s.deletedAt.map { .int($0) } ?? .null,
                "id": .string(s.id),
                "item": s.item ?? .null,
                "vv": .object(vv.mapValues { .int($0) }),
            ]))
        }
        let v = files.isEmpty ? version : filesVersion
        if !files.isEmpty { try checkFiles(files, states: itemStates) }
        let salt = random.bytes(count: 16), nonce = random.bytes(count: 12)
        let header: JSONValue = .object([
            "created_at": .int(createdAt),
            "format": .string(format),
            "kdf": .object(["name": .string("argon2id"), "time_cost": .int(timeCost),
                            "memory_cost_kib": .int(memoryKiB), "parallelism": .int(parallelism)]),
            "nonce": .string(Base64.encode(nonce)),
            "platform": .string(writerPlatform),
            "salt": .string(Base64.encode(salt)),
            "version": .int(v),
        ])
        var payloadFields: [String: JSONValue] = [
            "app_version": .string(appVersion),
            "device_id": .string(deviceID),
            "pro_hint": .bool(proHint),
            "states": .array(stateValues),
            "version": .int(v),
        ]
        if !files.isEmpty {
            payloadFields["files"] = .array(files.keys.sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }.map { blob in
                JSONValue.object(["blob": .string(blob), "data": .string(Base64.encode(files[blob] ?? []))])
            })
        }
        let payload: JSONValue = .object(payloadFields)
        var key = try derive(password, salt: salt, t: timeCost, m: memoryKiB, p: parallelism)
        defer { wipe(&key) }
        let ct = try CryptoBox.sealGCM(key: key, nonce: nonce,
                                       plaintext: CanonicalJSON.encode(payload, dialect: .utf8),
                                       aad: CanonicalJSON.encode(header, dialect: .utf8))
        let file: JSONValue = .object(["ciphertext": .string(Base64.encode(ct)), "header": header])
        return Data(try CanonicalJSON.encode(file, dialect: .utf8))
    }

    // MARK: read

    public static func open(_ file: Data, password: String) throws -> BackupPayload {
        guard file.count <= maxFileBytes else { throw Error.tooLarge }
        let bytes = [UInt8](file)
        guard String(bytes: bytes, encoding: .utf8) != nil,
              case .object(let env)? = try? CanonicalJSON.parse(bytes),
              Set(env.keys) == ["ciphertext", "header"],
              case .object(let header)? = env["header"],
              Set(header.keys) == ["created_at", "format", "kdf", "nonce", "platform", "salt", "version"],
              header["format"] == .string(format) else { throw Error.notABackup }
        let salt = try b64(header["salt"], length: 16)
        let nonce = try b64(header["nonce"], length: 12)
        let ct = try b64(env["ciphertext"], length: nil)
        guard case .string(let plat)? = header["platform"], plat == "android" || plat == "ios",
              case .int(let createdAt)? = header["created_at"], (0...maxInt).contains(createdAt) else {
            throw Error.notABackup
        }
        guard case .int(let v)? = header["version"] else { throw Error.notABackup }
        if v > filesVersion { throw Error.unsupportedVersion }
        if v != version && v != filesVersion { throw Error.notABackup }
        guard case .object(let kdf)? = header["kdf"], Set(kdf.keys) == ["name", "time_cost", "memory_cost_kib", "parallelism"],
              kdf["name"] == .string("argon2id"),
              case .int(let t)? = kdf["time_cost"], (1...10).contains(t),
              case .int(let m)? = kdf["memory_cost_kib"], (8192...524288).contains(m),
              case .int(let p)? = kdf["parallelism"], (1...16).contains(p) else { throw Error.badKDF }
        var key = try derive(password, salt: salt, t: t, m: m, p: p)
        defer { wipe(&key) }
        let plain: [UInt8]
        do {
            plain = try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: ct,
                                          aad: CanonicalJSON.encode(.object(header), dialect: .utf8))
        } catch { throw Error.wrongPassword }
        return try parsePayload(plain, version: v, createdAt: createdAt, platform: plat)
    }

    private static let payloadKeys: Set<String> = ["app_version", "device_id", "pro_hint", "states", "version"]

    private static func parsePayload(_ plain: [UInt8], version v: Int64, createdAt: Int64, platform: String) throws -> BackupPayload {
        guard String(bytes: plain, encoding: .utf8) != nil,
              case .object(let o)? = try? CanonicalJSON.parse(plain),
              Set(o.keys) == (v == filesVersion ? payloadKeys.union(["files"]) : payloadKeys),
              o["version"] == .int(v),
              case .string(let appVersion)? = o["app_version"], validAppVersion(appVersion),
              case .string(let deviceID)? = o["device_id"], Identifier.isValid(deviceID),
              case .bool(let proHint)? = o["pro_hint"],
              case .array(let raw)? = o["states"], raw.count <= maxStates else { throw Error.badPayload }
        var states: [BackupState] = []
        var itemStates: [ItemState] = []
        var previous: [UInt8]?
        for r in raw {
            guard case .object(let s) = r, Set(s.keys) == ["deleted", "deleted_at", "id", "item", "vv"],
                  case .string(let id)? = s["id"], case .bool(let deleted)? = s["deleted"],
                  case .object(let vvRaw)? = s["vv"] else { throw Error.badPayload }
            var vv: [String: Int64] = [:]
            for (dev, n) in vvRaw {
                guard case .int(let c) = n, (1...maxInt).contains(c) else { throw Error.badPayload }
                vv[dev] = c
            }
            let deletedAt: Int64?
            switch s["deleted_at"] {
            case .null?: deletedAt = nil
            case .int(let n)?: deletedAt = n  // ItemState below enforces 0...2^53-1
            default: throw Error.badPayload
            }
            let item: JSONValue? = s["item"] == .null ? nil : s["item"]
            do { itemStates.append(try ItemState(itemID: id, vv: vv, deleted: deleted, deletedAt: deletedAt, item: item)) }
            catch { throw Error.badPayload }
            let idBytes = Array(id.utf8)
            if let p = previous, !p.lexicographicallyPrecedes(idBytes) { throw Error.badPayload }
            previous = idBytes
            states.append(BackupState(id: id, deleted: deleted, deletedAt: deletedAt, item: item, vv: vv))
        }
        var files: [String: [UInt8]] = [:]
        if v == filesVersion {
            files = try parseFiles(o["files"])
            try checkFiles(files, states: itemStates)
        }
        return BackupPayload(createdAt: createdAt, platform: platform, appVersion: appVersion,
                             deviceID: deviceID, proHint: proHint, states: states, files: files)
    }

    /// `[{"blob", "data"}]` strictly ascending by blob id, each `data` canonical base64; else `bad-payload`.
    private static func parseFiles(_ raw: JSONValue?) throws -> [String: [UInt8]] {
        guard case .array(let entries)? = raw, entries.count <= maxFiles else { throw Error.badPayload }
        var out: [String: [UInt8]] = [:]
        var previous: [UInt8]?
        for entry in entries {
            guard case .object(let e) = entry, Set(e.keys) == ["blob", "data"], case .string(let blob)? = e["blob"],
                  case .string(let text)? = e["data"], let data = try? Base64.decodeStrict(text) else { throw Error.badPayload }
            let blobBytes = Array(blob.utf8)
            if let p = previous, !p.lexicographicallyPrecedes(blobBytes) { throw Error.badPayload }  // unsorted or duplicate
            previous = blobBytes
            out[blob] = data
        }
        return out
    }

    /// The format-2 rules (desktop `check_files`): 1...500 files, each a well-shaped sync blob whose SHA-256 is its
    /// id, named with the same `blob_size` by the reference of a live document in `states`; else `bad-payload`.
    static func checkFiles(_ files: [String: [UInt8]], states: [ItemState]) throws {
        guard !files.isEmpty, files.count <= maxFiles else { throw Error.badPayload }
        var sizes: [String: Int] = [:]
        for ref in AttachmentDocuments.refs(states) { sizes[ref.blob] = ref.blobSize }
        for (blob, data) in files {
            do { try AttachmentSync.checkBlobShape(data, expectedID: blob) } catch { throw Error.badPayload }
            guard sizes[blob] == data.count else { throw Error.badPayload }  // not named by a live document, or another size
        }
    }

    /// The files a writer includes, and the attachment ids it leaves out (desktop `select_files`). Live documents
    /// are taken in state id order; each blob (`fetch`) is included while the total stays within `budget` and
    /// `maxFiles`. A missing blob, or one that does not fit, is left out: its document stays without its file.
    public static func selectFiles(_ states: [BackupState], budget: Int = maxBackupFilesBytes,
                                   fetch: (AttachmentRef) -> [UInt8]?) -> (files: [String: [UInt8]], leftOut: [String]) {
        let ordered = states.sorted { Array($0.id.utf8).lexicographicallyPrecedes(Array($1.id.utf8)) }
        var files: [String: [UInt8]] = [:]
        var leftOut: [String] = []
        var total = 0
        for s in ordered where !s.deleted {
            guard let ref = AttachmentDocuments.ref(of: s.item) else { continue }
            if files[ref.blob] != nil { continue }
            guard let blob = fetch(ref), blob.count == ref.blobSize, files.count < maxFiles,
                  total + blob.count <= budget else {
                leftOut.append(ref.attachmentID)
                continue
            }
            files[ref.blob] = blob
            total += blob.count
        }
        return (files, leftOut)
    }

    // MARK: helpers

    private static func validAppVersion(_ s: String) -> Bool {
        let u = Array(s.utf8)
        return (1...32).contains(u.count) && u.allSatisfy { (0x20...0x7E).contains($0) }
    }

    private static func b64(_ v: JSONValue?, length: Int?) throws -> [UInt8] {
        guard case .string(let s)? = v, let raw = try? Base64.decodeStrict(s),
              length == nil || raw.count == length else { throw Error.notABackup }
        return raw
    }

    private static func derive(_ password: String, salt: [UInt8], t: Int64, m: Int64, p: Int64) throws -> [UInt8] {
        // The Swift String `password` itself cannot be wiped; only this UTF-8 copy is.
        var pw = Array(password.utf8)
        defer { wipe(&pw) }
        return try Argon2id.derive(password: pw, salt: salt, memoryKiB: UInt32(m),
                                   iterations: UInt32(t), parallelism: UInt32(p), length: 32)
    }
}

/// Zeroes secret bytes in place in a way the optimiser cannot drop.
func wipe(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { buf in
        guard let base = buf.baseAddress, buf.count > 0 else { return }
        #if canImport(Darwin)
        _ = memset_s(base, buf.count, 0, buf.count)
        #else
        let p = base.assumingMemoryBound(to: UInt8.self)
        for i in 0..<buf.count { withUnsafeMutablePointer(to: &p[i]) { $0.pointee = 0 } }
        #endif
    }
}

// MARK: - restore

/// The blobs a restore plan may count on, without storing anything: this device's own store plus the backup's
/// files (read only; the backup's files are stored by `PhoneBackup.storeFiles` after verification).
struct BackupBlobs: AttachmentBlobStore {
    let local: (any AttachmentBlobStore)?
    let files: [String: [UInt8]]

    func has(_ blobID: String) -> Bool { files[blobID] != nil || local?.has(blobID) == true }
    func read(_ blobID: String) -> [UInt8]? { files[blobID] ?? local?.read(blobID) }
    func write(_ blob: [UInt8]) throws -> String { throw AttachmentSyncError("write-failed", "read only") }
    func ids() -> Set<String> { Set(files.keys).union(local?.ids() ?? []) }
}

/// What restoring a phone backup does (desktop `sync/phone_restore.py` `RestorePlan`): the counts the review
/// shows and the store content to commit. The backup merged as one peer view, so version vectors and
/// tombstones are kept and nothing the store holds at a newer or equal version is overwritten.
public struct PhoneRestorePlan: Equatable, Sendable {
    public var new: Int
    public var updated: Int
    public var unchanged: Int
    /// Items the phone deleted that this store still holds live.
    public var deleted: Int
    /// States this version cannot read (malformed, newer, implausible version vector) or that the merge quarantined.
    public var skipped: Int
    /// New items left out on the free plan.
    public var heldBack: Int
    /// Two-factor keys kept as hidden fields on the free plan.
    public var totpAsField: Int
    /// The store content after the restore (every existing record kept).
    public var records: [String: JSONValue]
    public var meta: [String: SyncMeta]
    /// Licence bundles received that verified.
    public var licenses: [JSONValue]
    /// Whether committing changes the store at all.
    public var changes: Bool
    /// Format 2: blob id -> sealed blob, the backup files the restored documents need (not yet on this device).
    /// `storeFiles` verifies and stores them before the commit.
    public var files: [String: [UInt8]] = [:]
    /// The reference each of `files` is opened with.
    public var fileRefs: [String: AttachmentRef] = [:]
    /// Live documents left out because their file is neither in the backup nor on this device.
    public var filesMissing: Int = 0
}

extension PhoneBackup {
    public enum RestoreError: Swift.Error, Equatable, Sendable {
        /// The backup was written under this device's id.
        case sameDevice
        /// The store could not be read or merged (the sync issue kind).
        case failed(String)
    }

    /// Run issue kinds that skip one record while the rest is applied (desktop `QUARANTINE_KINDS`).
    static let quarantineKinds: Set<String> = ["bad-peer-record", "update-needed", "implausible-vv"]
    static let totpFieldName = "Two-factor key (needs Pro)"

    /// Merges the backup's states into `snapshot` as one peer view from the backup's device (desktop
    /// `plan_restore` and `restore`). On the free plan (`freeSlots` not nil) new items beyond the slots are held
    /// back (newest `updated_at` first, ties by id); conflict copies count as new items after plain ones. When
    /// `totpAllowed` is false a login's new two-factor key moves into a hidden custom field before the merge,
    /// so restoring the same backup again changes nothing. Pure: the caller commits `records` and `meta`.
    ///
    /// Documents (format 2, desktop `_document_files`): a live document is restored only with its file, from the
    /// backup's `files` or already in `blobs` (this device's attachment store); otherwise it is left out and
    /// counted in `filesMissing`. Nothing is stored here: the caller runs `storeFiles` and plans again on commit.
    public static func restoreStates(_ backup: BackupPayload, into snapshot: StoreSnapshot, device: String, now: Int64,
                                     freeSlots: Int? = nil, totpAllowed: Bool = true,
                                     licenseKeys: [String: [UInt8]] = [:],
                                     blobs: (any AttachmentBlobStore)? = nil) throws -> PhoneRestorePlan {
        let overlay = BackupBlobs(local: blobs, files: backup.files)
        guard backup.deviceID != device else { throw RestoreError.sameDevice }
        let local: [String: ItemState]
        do {
            local = try SyncMeta.localView(records: snapshot.records, meta: snapshot.meta, device: device, now: now).states
        } catch { throw RestoreError.failed("local-data") }
        var byID: [String: ItemState] = [:]
        var order: [String] = []
        var rewritten = Set<String>()
        var unreadable = 0
        var noFile = 0
        let known = Set([device, backup.deviceID]).union(snapshot.sync?.members ?? [])
        for s in backup.states {
            guard var state = try? ItemState(itemID: s.id, vv: s.vv, deleted: s.deleted, deletedAt: s.deletedAt, item: s.item)
            else { unreadable += 1; continue }
            // Unreadable first (Windows and Android order): a document that is both is skipped, not "file missing".
            let problem = SyncRunner.check(state, licenseKeys: licenseKeys, blobs: overlay)
            if (problem != nil && problem != "attachment-missing")
                || Plausibility.implausibleVV(state.vv, local: local[s.id]?.vv, known: known) != nil {
                unreadable += 1
                continue
            }
            if !state.deleted, let ref = AttachmentDocuments.ref(of: state.item), !overlay.has(ref.blob) {
                noFile += 1
                continue
            }
            if !totpAllowed, let moved = keepTOTPAsField(state, local: local[s.id]) {
                state = moved
                rewritten.insert(s.id)
            }
            byID[s.id] = state
            order.append(s.id)
        }
        func ranked(_ ids: some Sequence<String>) -> [String] {
            ids.sorted { a, b in
                let (ua, ub) = (updatedAt(byID[a]), updatedAt(byID[b]))
                return ua != ub ? ua > ub : a < b
            }
        }
        var held = Set<String>()
        if let slots = freeSlots {
            let t = try tally(local, order.compactMap { byID[$0] })
            let newIDs = ranked(t.new)
            held.formUnion(newIDs.dropFirst(max(0, slots)))
            var remaining = max(0, slots - newIDs.count)
            for id in ranked(t.copies.keys) {
                let n = t.copies[id] ?? 0
                if n <= remaining { remaining -= n } else { held.insert(id) }
            }
        }
        let final = order.filter { !held.contains($0) }.compactMap { byID[$0] }
        let t = try tally(local, final)
        let touched = t.new.union(t.updated).union(t.copies.keys)
        let report = SyncRunner.run(store: snapshot, views: [PeerView(deviceID: backup.deviceID, states: final)],
                                    device: device, now: now, licenseKeys: licenseKeys, known: known, blobs: overlay)
        if let fatal = report.issues.first(where: { !quarantineKinds.contains($0.kind) && $0.kind != "attachment-missing" }) {
            throw RestoreError.failed(fatal.kind)
        }
        guard let records = report.records, let meta = report.meta else { throw RestoreError.failed("local-data") }
        var files: [String: [UInt8]] = [:]
        var fileRefs: [String: AttachmentRef] = [:]
        for ref in AttachmentDocuments.refs(final) where blobs?.has(ref.blob) != true && fileRefs[ref.blob] == nil {
            guard let blob = backup.files[ref.blob] else { continue }
            files[ref.blob] = blob
            fileRefs[ref.blob] = ref
        }
        return PhoneRestorePlan(
            new: t.new.count + t.copies.values.reduce(0, +),
            updated: t.updated.count,
            unchanged: final.filter(isContent).count - touched.count,
            deleted: t.deleted.count,
            skipped: unreadable + report.issues.filter { quarantineKinds.contains($0.kind) }.count,
            heldBack: held.count,
            totpAsField: touched.intersection(rewritten).count,
            records: records, meta: meta, licenses: report.licenses,
            changes: records != snapshot.records || meta != snapshot.meta,
            files: files, fileRefs: fileRefs,
            filesMissing: noFile + report.issues.filter { $0.kind == "attachment-missing" }.count)
    }

    /// Verifies each backup file the plan needs against its reference (hash, AES-GCM, frame, digest, nonce) and
    /// stores it in `blobs` (desktop `import_missing`). Returns how many were stored and the blob ids refused; a
    /// refused file stores nothing, so planning again without the backup's files leaves its document out.
    public static func storeFiles(_ plan: PhoneRestorePlan, into blobs: any AttachmentBlobStore) -> (stored: Int, refused: Set<String>) {
        var stored = 0
        var refused = Set<String>()
        for blob in plan.files.keys.sorted() {
            guard let data = plan.files[blob], let ref = plan.fileRefs[blob] else { continue }
            do {
                _ = try AttachmentSync.openBlob(data, ref: ref)
                try blobs.write(data)
                stored += 1
            } catch {
                refused.insert(blob)
            }
        }
        return (stored, refused)
    }

    private static func ns(_ s: ItemState?) -> String? {
        guard case .object(let o)? = s?.item, case .string(let n)? = o["ns"] else { return nil }
        return n
    }

    private static func isContent(_ s: ItemState) -> Bool { !s.deleted && (ns(s) == "entry" || ns(s) == "item") }

    private static func updatedAt(_ s: ItemState?) -> Int64 {
        guard case .object(let o)? = s?.item, case .int(let n)? = o["updated_at"] else { return 0 }
        return n
    }

    /// (new ids, updated ids, conflict copies per backup id, deleted ids) of merging `states` into `local`.
    private static func tally(_ local: [String: ItemState], _ states: [ItemState]) throws
        -> (new: Set<String>, updated: Set<String>, copies: [String: Int], deleted: Set<String>) {
        let out: MergeOutcome
        do { out = try Engine.merge(local: local, remote: states) } catch { throw RestoreError.failed("bad-peer-data") }
        let upserts = Set(out.upserts.filter(isContent).map(\.itemID))
        let new = upserts.filter { local[$0] == nil || local[$0]!.deleted }
        let deleted = Set(out.deletes.map(\.itemID).filter { local[$0].map(isContent) ?? false })
        var cause: [String: String] = [:]
        for (loc, remote) in out.conflicts {
            for side in [loc, remote] {
                if let item = side.item, let digest = try? ConflictCopy.contentDigest(item),
                   let cid = try? ConflictCopy.id(itemID: remote.itemID, contentDigest: digest) { cause[cid] = remote.itemID }
            }
        }
        var copies: [String: Int] = [:]
        for c in out.copies where isContent(c) {
            if let id = cause[c.itemID] { copies[id, default: 0] += 1 }
        }
        return (new, upserts.subtracting(new), copies, deleted)
    }

    /// Desktop `transfer._keep_totp_as_field`: a login's new two-factor key becomes a hidden custom field; an
    /// unchanged key stays. Nil when nothing changes.
    static func keepTOTPAsField(_ state: ItemState, local: ItemState?) -> ItemState? {
        guard !state.deleted, ns(state) == "entry", case .object(var wrapper)? = state.item,
              case .object(var record)? = wrapper["record"], case .object(let totp)? = record["totp"] else { return nil }
        var original: [String: JSONValue]?
        if let local, !local.deleted, case .object(let lw)? = local.item, case .object(let lr)? = lw["record"] { original = lr }
        if let original, original["totp"] == record["totp"] { return nil }
        func int(_ k: String, _ d: Int) -> Int { if case .int(let n)? = totp[k] { return Int(n) }; return d }
        func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }
        let uri = ImportRules.totpURI(str(totp["secret"]), label: str(record["username"]), digits: int("digits", 6),
                                      period: int("period", 30), algorithm: str(totp["algorithm"]).isEmpty ? "SHA1" : str(totp["algorithm"]))
        record["totp"] = original?["totp"]
        var fields: [JSONValue] = []
        if case .array(let f)? = record["custom_fields"] { fields = f }
        if !uri.isEmpty, fields.count < 50 {
            fields.append(.object(["name": .string(totpFieldName), "value": .string(uri), "hidden": .bool(true)]))
        }
        record["custom_fields"] = .array(fields)
        wrapper["record"] = .object(record)
        return try? ItemState(itemID: state.itemID, vv: state.vv, deleted: false, deletedAt: nil, item: .object(wrapper))
    }
}
