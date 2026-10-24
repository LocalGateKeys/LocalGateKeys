import Foundation
@_exported import LGKCore

public enum LocalStoreError: Error, Equatable {
    case noContainer
    /// No local key in the Keychain: the app has not been set up on this device.
    case noLocalKey
    case badLocalKey
    /// Store files are on this device but the local key is not (a restored backup: the key is device-only).
    /// Nothing can read them; the app offers Start fresh instead of making a new key over them.
    case vaultWithoutKey
    /// `commit` was based on an older revision.
    case stale(expected: Int64, actual: Int64)
    case corrupt(String)
    case io(String)
}

/// The encrypted item store in the app-group container (`ItemStore`).
///
/// Layout of `directory`:
/// - `CURRENT` — the committed revision as ASCII decimal. It is the only commit point.
/// - `g<rev>/state.blob` — sealed state: revision, item index (id -> file), sync meta, sync group state.
/// - `g<rev>/i<n>.blob` — one sealed blob per record (its synced wrapper).
/// - `.lock` — `flock` target serializing writers across the app and the extension.
///
/// Every blob is `nonce(12) || AES-256-GCM(ciphertext || tag)` under the 256-bit local key from the
/// Keychain. AAD binds each blob to its revision (and item id), so blobs cannot be swapped between
/// generations or items.
///
/// Commit: write a full new generation into `tmp-<uuid>/` (each file fsynced), rename it to `g<rev+1>`,
/// then write `CURRENT` via temp file + fsync + rename. Readers resolve `CURRENT` first and read only
/// that generation, so they see the old generation or the new one, never a mix. A crash before the
/// final rename leaves the old revision current; stray `tmp-*`/newer `g*` dirs are removed on the next
/// commit. The previous generation is kept one commit longer so a reader racing a commit still finds
/// its files; a reader that loses that race (CURRENT moved and its generation was pruned) retries from
/// `CURRENT`, up to three reads in all (see `load`).
///
/// No password KDF exists on any path here: both the app and the AutoFill extension open the store
/// with the local key read from the Keychain.
public final class LocalStore: ItemStore, @unchecked Sendable {
    public let directory: URL
    private let key: [UInt8]
    private let random: any RandomSource
    private let lock = NSLock()
    /// Where each commit publishes `AppSettings.planFullRevision` (nil: not published).
    public var limitHints: AppSettings?
    /// Where each commit publishes the Safari fingerprint index (nil: not published). Best effort.
    public var safariIndex: (any SafariIndexPublishing)?

    static let stateAAD = "localgatekeys|local-state|v1|"
    static let itemAAD = "localgatekeys|local-item|v1|"

    /// Opens the store with the local key already in the Keychain (app after unlock, AutoFill extension).
    public static func open(directory: URL, vault: any KeychainVault,
                            random: any RandomSource = SystemRandomSource(),
                            limitHints: AppSettings? = .shared) throws -> LocalStore {
        guard let key = try vault.read(.localKey) else { throw LocalStoreError.noLocalKey }
        let store = try LocalStore(directory: directory, key: key, random: random)
        store.limitHints = limitHints
        return store
    }

    /// The committed revision from the plain `CURRENT` file, readable without the key (the AutoFill extension
    /// checks it against `AppSettings.planFullRevision` before Face ID). nil when absent or unreadable.
    public static func committedRevision(directory: URL) -> Int64? {
        guard let data = FileManager.default.contents(atPath: directory.appendingPathComponent("CURRENT").path),
              let text = String(data: data, encoding: .ascii) else { return nil }
        return Int64(text.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Main app first run: creates a random 256-bit local key in the Keychain when none exists, then opens.
    /// Store files without a key in the Keychain throw `vaultWithoutKey` (no key is written).
    public static func bootstrap(directory: URL, vault: any KeychainVault,
                                 random: any RandomSource = SystemRandomSource()) throws -> LocalStore {
        excludeFromBackup(directory)   // every bootstrap: directories made by older builds lack the flag
        removeSetAside(nextTo: directory)   // copies a forced Start fresh could not delete
        if try vault.read(.localKey) == nil {
            if hasStoreFiles(directory) { throw LocalStoreError.vaultWithoutKey }
            try vault.write(.localKey, random.bytes(count: 32))
        }
        return try open(directory: directory, vault: vault, random: random)
    }

    static let setAsidePrefix = "-unreadable-"

    /// Renames `directory` to `<name>-unreadable-<timestamp>` next to it (Start fresh, when it cannot be
    /// deleted). Nothing reads it again; `removeSetAside` deletes it later.
    public static func setAside(_ directory: URL, now: Int64) throws {
        let parent = directory.deletingLastPathComponent()
        var target = parent.appendingPathComponent(directory.lastPathComponent + setAsidePrefix + "\(now)", isDirectory: true)
        var n = 1
        while FileManager.default.fileExists(atPath: target.path) {
            target = parent.appendingPathComponent(directory.lastPathComponent + setAsidePrefix + "\(now)-\(n)", isDirectory: true)
            n += 1
        }
        try FileManager.default.moveItem(at: directory, to: target)
    }

    /// Best effort: deletes the set-aside copies of `directory` (`<name>-unreadable-*`). Errors are ignored.
    public static func removeSetAside(nextTo directory: URL) {
        let parent = directory.deletingLastPathComponent()
        let prefix = directory.lastPathComponent + setAsidePrefix
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: parent.path) else { return }
        for name in names where name.hasPrefix(prefix) {
            try? FileManager.default.removeItem(at: parent.appendingPathComponent(name, isDirectory: true))
        }
    }

    /// True when `directory` holds a committed store: `CURRENT` or a `g<rev>` generation.
    static func hasStoreFiles(_ directory: URL) -> Bool {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else { return false }
        return names.contains { (name: String) -> Bool in
            name == "CURRENT" || (name.hasPrefix("g") && name.count > 1 && name.utf8.dropFirst().allSatisfy { $0 >= 0x30 && $0 <= 0x39 })
        }
    }

    /// The vault never goes into iCloud or computer backups: its key is device-only, so a restored copy of
    /// the files could never be opened. Best effort; a missing directory is skipped.
    static func excludeFromBackup(_ directory: URL) {
        guard FileManager.default.fileExists(atPath: directory.path) else { return }
        var url = directory
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }

    init(directory: URL, key: [UInt8], random: any RandomSource) throws {
        guard key.count == 32 else { throw LocalStoreError.badLocalKey }
        self.directory = directory; self.key = key; self.random = random
        do { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true) }
        catch { throw LocalStoreError.io("create directory") }
        Self.excludeFromBackup(directory)
    }

    // MARK: ItemStore

    /// Reads the generation CURRENT names. A commit racing this read may move CURRENT and prune the
    /// generation being read (a missing `state.blob`/`iN.blob`, or no generation left). Only in that case,
    /// when CURRENT has moved past the revision being read, the read re-resolves CURRENT and retries (at
    /// most `maxReadAttempts` reads). If CURRENT has not moved, the error is thrown as is: a file missing
    /// from the current generation is damage or tampering, never retried away.
    public func load() throws -> StoreSnapshot {
        var attempt = 1
        while true {
            let current = try currentRevision()
            if current == 0 { return StoreSnapshot() }
            do {
                return try visibleSnapshot(current: current)
            } catch let e as LocalStoreError {
                guard attempt < Self.maxReadAttempts, Self.isMissingFile(e), try currentRevision() != current else { throw e }
                attempt += 1
            }
        }
    }

    static let maxReadAttempts = 3

    private static func isMissingFile(_ e: LocalStoreError) -> Bool {
        switch e {
        case .io(let m): return m.hasPrefix("missing ")
        case .corrupt(let m): return m.hasPrefix("no generation")
        default: return false
        }
    }

    /// Test seam: called after a generation's state blob was read, before its item blobs are.
    var afterStateRead: ((Int64) -> Void)?

    /// The generation CURRENT names. Only when that generation (or its state blob) is absent from disk,
    /// i.e. it never got there before a power loss, does this fall back to the newest older generation.
    /// Any other failure (I/O, authentication, corrupt data) throws: tampering or damage is reported,
    /// never silently rolled back, and `commit` refuses to run on top of it.
    private func visibleSnapshot(current: Int64) throws -> StoreSnapshot {
        if stateExists(current) { return try read(revision: current) }
        for rev in generations().filter({ $0 < current }).sorted(by: >) where stateExists(rev) {
            return try read(revision: rev)
        }
        throw LocalStoreError.corrupt("no generation at or below \(current)")
    }

    private func stateExists(_ rev: Int64) -> Bool {
        let path = generationURL(rev).appendingPathComponent("state.blob").path
        if access(path, F_OK) == 0 { return true }
        return errno != ENOENT   // anything but "absent" counts as present, so read() reports the real error
    }

    /// Commits are short (encrypt + write one generation), and the flock is held only for that. AppShared
    /// is extension-safe and cannot reach `UIApplication.beginBackgroundTask`; the main app runs sync runs
    /// and editor/delete commits inside a background task (`BackgroundTasking`), so it is not suspended
    /// while holding the flock in the app-group container (0xdead10cc).
    public func commit(_ change: StoreChange) throws {
        try lock.withLock {
            try withFileLock {
                let current = try currentRevision()
                // The revision readers actually see (CURRENT, or the fallback generation if it is missing).
                let visible = current == 0 ? 0 : try visibleSnapshot(current: current).revision
                guard change.baseRevision == visible else {
                    throw LocalStoreError.stale(expected: change.baseRevision, actual: visible)
                }
                let rev = current + 1
                let fm = FileManager.default
                let tmp = directory.appendingPathComponent("tmp-\(UUID().uuidString)", isDirectory: true)
                do {
                    try fm.createDirectory(at: tmp, withIntermediateDirectories: false)
                    var index: [JSONValue] = []
                    for (n, id) in change.records.keys.sorted().enumerated() {
                        let file = "i\(n).blob"
                        let plain = try CanonicalJSON.encode(change.records[id]!, dialect: .utf8)
                        try writeFileSynced(try seal(plain, aad: Self.itemAAD + "\(rev)|" + id), to: tmp.appendingPathComponent(file))
                        index.append(.object(["id": .string(id), "file": .string(file)]))
                    }
                    let state = JSONValue.object([
                        "v": .int(1), "revision": .int(rev), "items": .array(index),
                        "meta": .object(change.meta.mapValues(Self.encodeMeta)),
                        "sync": change.sync.map(Self.encodeSync) ?? .null,
                    ])
                    try writeFileSynced(try seal(try CanonicalJSON.encode(state, dialect: .utf8), aad: Self.stateAAD + "\(rev)"),
                                        to: tmp.appendingPathComponent("state.blob"))
                    try syncDirectory(tmp)
                    let gen = generationURL(rev)
                    if fm.fileExists(atPath: gen.path) { try fm.removeItem(at: gen) } // leftover of a crashed commit
                    try fm.moveItem(at: tmp, to: gen)
                    try syncDirectory(directory)
                    try writeDurably(Array("\(rev)\n".utf8), to: directory.appendingPathComponent("CURRENT"))
                } catch let e as LocalStoreError {
                    try? fm.removeItem(at: tmp); throw e
                } catch {
                    try? fm.removeItem(at: tmp); throw LocalStoreError.io("\(error)")
                }
                prune(keepingFrom: rev - 1, current: rev)
                let committed = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: rev)
                publishLimitHint(committed)
                safariIndex?.publish(committed)   // never throws: a failed publish never fails the commit
            }
        }
    }

    private func publishLimitHint(_ snap: StoreSnapshot) {
        guard let limitHints else { return }
        let revision = snap.revision
        let full = !ItemLimit.allows(.create, snapshot: snap, isPro: false)
            && ItemLimit.validLicense(in: snap, keys: LicenseKeys.production) == nil
        limitHints.planFullRevision = full ? revision : nil
    }

    // MARK: files

    private func generationURL(_ rev: Int64) -> URL { directory.appendingPathComponent("g\(rev)", isDirectory: true) }

    private func generations() -> [Int64] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? [])
            .compactMap { $0.hasPrefix("g") ? Int64($0.dropFirst()) : nil }
    }

    /// 0 only when CURRENT does not exist (ENOENT) and no generation exists. Any other read error, or a
    /// missing CURRENT next to existing generations, throws, so a failed read is never taken for an empty
    /// vault (which the next commit would overwrite).
    func currentRevision() throws -> Int64 {
        let path = directory.appendingPathComponent("CURRENT").path
        let fd = Darwin.open(path, O_RDONLY)
        if fd < 0 {
            let err = errno
            guard err == ENOENT else { throw LocalStoreError.io("CURRENT: errno \(err)") }
            if !generations().isEmpty { throw LocalStoreError.corrupt("CURRENT missing but generations exist") }
            return 0
        }
        defer { close(fd) }
        var buf = [UInt8](repeating: 0, count: 32)
        let n = Darwin.read(fd, &buf, buf.count)
        guard n > 0, let s = String(bytes: buf[0..<n], encoding: .ascii)?.trimmingCharacters(in: .whitespacesAndNewlines),
              let rev = Int64(s), rev > 0 else { throw LocalStoreError.corrupt("CURRENT") }
        return rev
    }

    private func readFile(_ url: URL) throws -> [UInt8] {
        guard let d = FileManager.default.contents(atPath: url.path) else { throw LocalStoreError.io("missing \(url.lastPathComponent)") }
        return Array(d)
    }


    private func read(revision rev: Int64) throws -> StoreSnapshot {
        let gen = generationURL(rev)
        let state = try CanonicalJSON.parse(try open(try readFile(gen.appendingPathComponent("state.blob")), aad: Self.stateAAD + "\(rev)"))
        guard case .object(let o) = state, o["revision"] == .int(rev), case .array(let items)? = o["items"],
              case .object(let meta)? = o["meta"], let sync = o["sync"] else { throw LocalStoreError.corrupt("state") }
        afterStateRead?(rev)
        var records: [String: JSONValue] = [:]
        for entry in items {
            guard case .object(let e) = entry, case .string(let id)? = e["id"], case .string(let file)? = e["file"],
                  !file.contains("/") else { throw LocalStoreError.corrupt("index") }
            let plain = try open(try readFile(gen.appendingPathComponent(file)), aad: Self.itemAAD + "\(rev)|" + id)
            records[id] = try CanonicalJSON.parse(plain)
        }
        return StoreSnapshot(records: records, meta: try meta.mapValues(Self.decodeMeta),
                             sync: sync == .null ? nil : try Self.decodeSync(sync), revision: rev)
    }

    /// Writes a new file and flushes it to stable storage (F_FULLFSYNC).
    private func writeFileSynced(_ bytes: [UInt8], to url: URL) throws {
        let fd = Darwin.open(url.path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
        guard fd >= 0 else { throw LocalStoreError.io("create \(url.lastPathComponent)") }
        defer { close(fd) }
        var off = 0
        while off < bytes.count {
            let w = bytes[off...].withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
            guard w > 0 else { throw LocalStoreError.io("write \(url.lastPathComponent)") }
            off += w
        }
        try fullSync(fd, url.lastPathComponent)
        do {
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                                                  ofItemAtPath: url.path)
        } catch { throw LocalStoreError.io("protect \(url.lastPathComponent)") }
    }

    private func fullSync(_ fd: Int32, _ what: String) throws {
        if fcntl(fd, F_FULLFSYNC) != 0 && fsync(fd) != 0 { throw LocalStoreError.io("sync \(what)") }
    }

    private func syncDirectory(_ url: URL) throws {
        let fd = Darwin.open(url.path, O_RDONLY)
        guard fd >= 0 else { throw LocalStoreError.io("open dir \(url.lastPathComponent)") }
        defer { close(fd) }
        try fullSync(fd, url.lastPathComponent)
    }

    /// Temp file in the same directory, full sync, rename over the target, sync the directory.
    private func writeDurably(_ bytes: [UInt8], to url: URL) throws {
        let dir = url.deletingLastPathComponent()
        let tmp = dir.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        do {
            try writeFileSynced(bytes, to: tmp)
            guard rename(tmp.path, url.path) == 0 else { throw LocalStoreError.io("rename \(url.lastPathComponent)") }
            try syncDirectory(dir)
        } catch { try? FileManager.default.removeItem(at: tmp); throw error }
    }

    private func prune(keepingFrom oldest: Int64, current: Int64) {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: directory.path) else { return }
        for name in names {
            var drop = name.hasPrefix("tmp-")
            if name.hasPrefix("g"), let n = Int64(name.dropFirst()) { drop = n < oldest || n > current }
            if drop { try? fm.removeItem(at: directory.appendingPathComponent(name)) }
        }
    }

    private func withFileLock<T>(_ body: () throws -> T) throws -> T {
        let path = directory.appendingPathComponent(".lock").path
        let fd = Darwin.open(path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { throw LocalStoreError.io("lock") }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw LocalStoreError.io("lock") }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }

    // MARK: crypto

    private func seal(_ plain: [UInt8], aad: String) throws -> [UInt8] {
        try SealedBlob.seal(plain, key: key, aad: aad, random: random)
    }

    private func open(_ blob: [UInt8], aad: String) throws -> [UInt8] {
        guard blob.count >= SealedBlob.minimumLength else { throw LocalStoreError.corrupt("blob") }
        do { return try SealedBlob.open(blob, key: key, aad: aad) }
        catch { throw LocalStoreError.corrupt("authentication") }
    }

    // MARK: state encoding (CanonicalJSON, never Foundation JSON)

    private static func optStr(_ s: String?) -> JSONValue { s.map { .string($0) } ?? .null }
    private static func optInt(_ n: Int64?) -> JSONValue { n.map { .int($0) } ?? .null }
    private static func ints(_ d: [String: Int64]) -> JSONValue { .object(d.mapValues { .int($0) }) }
    private static func b64(_ b: [UInt8]) -> JSONValue { .string(Base64.encode(b)) }

    static func encodeMeta(_ m: SyncMeta) -> JSONValue {
        .object(["digest": optStr(m.digest), "body": optStr(m.body), "updated_at": optInt(m.updatedAt),
                 "vv": ints(m.vv), "deleted": .bool(m.deleted), "deleted_at": optInt(m.deletedAt)])
    }

    static func encodeSync(_ s: SyncGroupState) -> JSONValue {
        .object(["group_id": .string(s.groupID), "epoch": .int(s.epoch), "key": b64(s.key),
                 "device_id": .string(s.identity.deviceID), "signing": b64(s.identity.signingPrivateKey),
                 "exchange": b64(s.identity.exchangePrivateKey), "install_id": .string(s.installID),
                 "has_folder": .bool(s.hasFolder), "last_seen": ints(s.lastSeen),
                 "peer_digests": .object(s.peerDigests.mapValues { .string($0) }),
                 "members_epoch": .int(s.membersEpoch), "members": .array(s.members.map { .string($0) }),
                 "keyring": s.keyring.map(b64) ?? .null, "own_counter": .int(s.ownCounter)])
    }

    private struct Fields {
        let o: [String: JSONValue]
        init(_ v: JSONValue) throws { guard case .object(let o) = v else { throw LocalStoreError.corrupt("state") }; self.o = o }
        func str(_ k: String) throws -> String { guard case .string(let s)? = o[k] else { throw LocalStoreError.corrupt(k) }; return s }
        func optStr(_ k: String) throws -> String? { o[k] == .null ? nil : try str(k) }
        func int(_ k: String) throws -> Int64 { guard case .int(let n)? = o[k] else { throw LocalStoreError.corrupt(k) }; return n }
        func optInt(_ k: String) throws -> Int64? { o[k] == .null ? nil : try int(k) }
        func bool(_ k: String) throws -> Bool { guard case .bool(let b)? = o[k] else { throw LocalStoreError.corrupt(k) }; return b }
        func bytes(_ k: String) throws -> [UInt8] {
            do { return try Base64.decodeStrict(try str(k)) } catch { throw LocalStoreError.corrupt(k) }
        }
        func dict(_ k: String) throws -> [String: JSONValue] { guard case .object(let d)? = o[k] else { throw LocalStoreError.corrupt(k) }; return d }
        func ints(_ k: String) throws -> [String: Int64] {
            try dict(k).mapValues { guard case .int(let n) = $0 else { throw LocalStoreError.corrupt(k) }; return n }
        }
    }

    static func decodeMeta(_ v: JSONValue) throws -> SyncMeta {
        let f = try Fields(v)
        return SyncMeta(digest: try f.optStr("digest"), body: try f.optStr("body"), updatedAt: try f.optInt("updated_at"),
                        vv: try f.ints("vv"), deleted: try f.bool("deleted"), deletedAt: try f.optInt("deleted_at"))
    }

    static func decodeSync(_ v: JSONValue) throws -> SyncGroupState {
        let f = try Fields(v)
        let identity = try DeviceIdentity(deviceID: try f.str("device_id"), signingPrivate: try f.bytes("signing"),
                                          exchangePrivate: try f.bytes("exchange"))
        guard case .array(let members)? = f.o["members"] else { throw LocalStoreError.corrupt("members") }
        return SyncGroupState(
            groupID: try f.str("group_id"), epoch: try f.int("epoch"), key: try f.bytes("key"), identity: identity,
            installID: try f.str("install_id"), hasFolder: try f.bool("has_folder"), lastSeen: try f.ints("last_seen"),
            peerDigests: try f.dict("peer_digests").mapValues { guard case .string(let s) = $0 else { throw LocalStoreError.corrupt("peer_digests") }; return s },
            membersEpoch: try f.int("members_epoch"),
            members: try members.map { guard case .string(let s) = $0 else { throw LocalStoreError.corrupt("members") }; return s },
            keyring: f.o["keyring"] == .null ? nil : try f.bytes("keyring"), ownCounter: try f.int("own_counter"))
    }
}

/// `nonce(12) || AES-256-GCM(ciphertext || tag)` with a string AAD: the blob format of `LocalStore` and
/// `SafariInbox`.
enum SealedBlob {
    /// Nonce plus tag: anything shorter cannot be a sealed blob.
    static let minimumLength = 28

    static func seal(_ plain: [UInt8], key: [UInt8], aad: String, random: any RandomSource) throws -> [UInt8] {
        let nonce = random.bytes(count: 12)
        return nonce + (try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: plain, aad: Array(aad.utf8)))
    }

    /// Throws `CryptoBoxError` when the blob is too short, the key is not 32 bytes, or it does not authenticate.
    static func open(_ blob: [UInt8], key: [UInt8], aad: String) throws -> [UInt8] {
        guard blob.count >= minimumLength else { throw CryptoBoxError.authenticationFailed }
        return try CryptoBox.openGCM(key: key, nonce: Array(blob[0..<12]), ciphertext: Array(blob[12...]), aad: Array(aad.utf8))
    }
}
