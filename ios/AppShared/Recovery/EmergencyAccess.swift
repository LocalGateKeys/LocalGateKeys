import Foundation
import LGKCore

/// This device's own emergency access data, never synced (Android keeps it in the vault's sealed slots): the shard
/// packages given to this person, their requester keys and the heir folder's bookmark. One file, `heir-local.bin`,
/// next to the vault's generations, sealed with AES-GCM under a key derived from the vault's local key, so the duress
/// password's vault (its own folder and key) has its own and never sees the real one's.
public final class HeirLocalState: @unchecked Sendable {
    public static let fileName = "heir-local.bin"
    static let info = Array("localgatekeys|heir-local|v1".utf8)

    public let url: URL
    private let key: [UInt8]
    private let random: any RandomSource
    private let lock = NSLock()

    public init(directory: URL, key: [UInt8], random: any RandomSource = SystemRandomSource()) {
        url = directory.appendingPathComponent(Self.fileName); self.key = key; self.random = random
    }

    /// The state of an unlocked `LocalStore`, also seen through a store that forwards to one (the Mac's
    /// `PublishingItemStore`); nil for any other store.
    public static func open(for store: any ItemStore) -> HeirLocalState? {
        guard let local = LocalStore.underlying(store) else { return nil }
        return HeirLocalState(directory: local.directory, key: local.derivedKey(info: info))
    }

    /// The stored fields (empty when there is no file; an unreadable file reads as empty and is replaced on save).
    func read() -> [String: JSONValue] {
        lock.withLock {
            guard let data = FileManager.default.contents(atPath: url.path), data.count > 12 + 16 else { return [:] }
            let bytes = Array(data)
            guard let plain = try? CryptoBox.openGCM(key: key, nonce: Array(bytes[0..<12]), ciphertext: Array(bytes[12...]),
                                                     aad: Self.info),
                  case .object(let o)? = try? CanonicalJSON.parse(plain) else { return [:] }
            return o
        }
    }

    func update(_ change: (inout [String: JSONValue]) -> Void) throws {
        var o = read()
        change(&o)
        try lock.withLock {
            let nonce = random.bytes(count: 12)
            let sealed = try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: try CanonicalJSON.encode(.object(o), dialect: .utf8),
                                               aad: Self.info)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(nonce + sealed).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        }
    }
}

/// Emergency access on an iPhone or Mac (sub-plan 08, Task 5c; Android `EmergencyAccess`), over one unlocked vault.
/// Blocking: call off the main actor.
///
/// - As one of the owner's devices: the plan arrives by sync (record `heir:plan`). With this device's heir folder
///   chosen, it lists the requests that prove a shard (rewriting a lost deny), denies (the refusal is kept in the plan,
///   which syncs) and grants now with the typed recovery phrase after the owner confirms. Plans are made on the computer.
/// - As a holder: the shards given to this person and their own requester keys stay in this vault's sealed local state.
///   It asks for access, follows the status, and once access is open shows the owner's recovery phrase, checked
///   against the plan's HKDF check first (Ruling T5a).
public final class EmergencyAccess: @unchecked Sendable {
    private let store: any ItemStore
    private let local: HeirLocalState
    /// The heir folder for stored bookmark bytes (nil: not available any more); fresh bytes replace stale ones.
    private let openFolder: @Sendable ([UInt8]) -> (folder: HeirFolder, refreshed: [UInt8]?)?
    private let now: @Sendable () -> Int64
    private let random: any RandomSource
    /// A local edit of the plan (a refusal) for sync to publish.
    private let onLocalEdit: @Sendable () -> Void

    public init(store: any ItemStore, local: HeirLocalState,
                openFolder: @escaping @Sendable ([UInt8]) -> (folder: HeirFolder, refreshed: [UInt8]?)?,
                now: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970) },
                random: any RandomSource = SystemRandomSource(), onLocalEdit: @escaping @Sendable () -> Void = {}) {
        self.store = store; self.local = local; self.openFolder = openFolder; self.now = now; self.random = random
        self.onLocalEdit = onLocalEdit
    }

    // MARK: the folder

    public var hasFolder: Bool { folderBookmark() != nil }

    private func folderBookmark() -> [UInt8]? {
        guard case .string(let b)? = local.read()["folder"] else { return nil }
        return try? Base64.decodeStrict(b)
    }

    public func setFolder(bookmark: [UInt8]) throws {
        try local.update { $0["folder"] = .string(Base64.encode(bookmark)) }
    }

    func folder() throws -> HeirFolder {
        guard let bookmark = folderBookmark(), let opened = openFolder(bookmark) else { throw HeirFlowError("no-folder") }
        if let fresh = opened.refreshed { try? setFolder(bookmark: fresh) }
        return opened.folder
    }

    // MARK: the owner's plan

    /// The synced plan record, or nil (none, removed, or not a plan).
    public func planRecord() throws -> JSONValue? {
        let snap = try store.load()
        if snap.meta[Heir.stateID]?.deleted == true { return nil }
        guard case .object(let w)? = snap.records[Heir.stateID], w["ns"] == .string(Namespace.heir.rawValue) else { return nil }
        return w["record"]
    }

    /// The plan, or nil; a damaged record throws `HeirError` `malformed`.
    public func plan() throws -> HeirPlan? { try planRecord().map { try Heir.parsePlan($0) } }

    private func requirePlan() throws -> HeirPlan {
        guard let plan = try plan() else { throw HeirFlowError("no-plan") }
        return plan
    }

    /// The open requests (a refused one whose deny went missing gets it written again).
    public func pending() throws -> HeirPending {
        try HeirFlow.pending(plan: try requirePlan(), folder: try folder(), now: now(), random: random)
    }

    /// Refuses a request, in the desktop's order (`add_denied` first): the refusal is kept in the plan (it syncs to the
    /// owner's other devices, which write the deny file again if this one is lost), then the deny file is written.
    public func deny(requestID: String) throws {
        let plan = try requirePlan()
        let folder = try folder()
        let snap = try store.load()
        guard let record = try planRecord() else { throw HeirFlowError("no-plan") }
        var records = snap.records
        records[Heir.stateID] = Wrapper.make(ns: .heir, record: try Heir.withDenied(record, requestID: requestID))
        try store.commit(StoreChange(baseRevision: snap.revision, records: records, meta: snap.meta, sync: snap.sync))
        onLocalEdit()
        try HeirFlow.deny(plan: plan, folder: folder, requestID: requestID, now: now(), random: random)
    }

    /// Grant now with the typed `phrase` (the caller has re-authenticated the owner).
    @discardableResult
    public func grant(requestID: String, phrase: String) throws -> String {
        try HeirFlow.grantNow(plan: try requirePlan(), folder: try folder(), requestID: requestID, phrase: phrase, now: now(),
                              random: random)
    }

    // MARK: the holder's side

    /// The shard packages held (in the order added).
    public func packages() -> [[UInt8]] {
        guard case .array(let a)? = local.read()["shards"] else { return [] }
        return a.compactMap { if case .string(let s) = $0 { return try? Base64.decodeStrict(s) } else { return nil } }
    }

    public func shards() -> [Shard] { packages().compactMap { try? Heir.readPackage($0) } }

    /// Adds a shard file's bytes; refused when it is not one, or of another plan than those held, or held already.
    @discardableResult
    public func addPackage(_ data: [UInt8]) throws -> Shard {
        let all = packages() + [data]
        let checked = try Heir.checkShards(all)
        try local.update { $0["shards"] = .array(all.map { .string(Base64.encode($0)) }) }
        return checked[checked.count - 1]
    }

    /// Adds a scanned or pasted `lgkheir:` code.
    @discardableResult
    public func addText(_ text: String) throws -> Shard {
        try addPackage(try Heir.package(fromQRText: text.trimmingCharacters(in: .whitespacesAndNewlines)))
    }

    public func clearShards() throws { try local.update { $0["shards"] = nil } }

    private func identity() throws -> RequesterIdentity {
        if let record = local.read()["identity"], let id = try? RequesterIdentity.fromRecord(record) { return id }
        // None yet, or damaged: a new identity (an earlier request then simply stays unanswered).
        let made = try RequesterIdentity.generate(random: random)
        try local.update { $0["identity"] = made.toRecord() }
        return made
    }

    private func held() throws -> [[UInt8]] {
        let p = packages()
        if p.isEmpty { throw HeirFlowError("need-more", missing: 2) }
        return p
    }

    /// Writes an access request for the plan of the shards held.
    @discardableResult
    public func request() throws -> String {
        try HeirFlow.requestAccess(try folder(), shard: try held()[0], identity: try identity(), now: now(), random: random)
    }

    public func status() throws -> HeirStatus {
        try HeirFlow.requestStatus(try folder(), packages: try held(), identity: try identity(), now: now())
    }

    /// The owner's recovery phrase once access is open, after the plan's check (the caller shows it, keeps nothing).
    public func recoverPhrase() throws -> String {
        var entropy = try HeirFlow.recoverEntropy(try folder(), packages: try held(), identity: try identity(), now: now())
        var data = Data(entropy)
        defer {
            for i in entropy.indices { entropy[i] = 0 }
            data.resetBytes(in: 0..<data.count)
        }
        // The phrase String itself cannot be zeroed; the view shows it once, not selectable, and keeps nothing.
        return try BIP39.phrase(entropy: data)
    }
}

/// The owner's look at the heir folder (desktop `HeirService.timer_check`, Android `HeirNotices`): after unlock and
/// sync runs, the open requests are read (a refused request's lost deny is written again) and each new one is
/// announced once per app run, with a one-time warning when the folder holds too many request files to read them all.
public final class HeirNotices: @unchecked Sendable {
    public static let shared = HeirNotices()
    private var announced = Set<String>()
    private var floodShown = false
    private let lock = NSLock()

    public init() {}

    /// The notices to show now (none without a plan or a folder; a failed look is silent and tried again later).
    public func check(_ access: EmergencyAccess?) -> [String] {
        guard let access, access.hasFolder, (try? access.plan()) != nil, let pending = try? access.pending() else { return [] }
        return lock.withLock {
            var out: [String] = []
            for r in pending.requests where !r.granted && announced.insert(r.requestID).inserted {
                out.append(EmergencyAccessText.requestNotice(holder: r.holder, daysLeft: r.daysLeft))
            }
            if pending.flooded && !floodShown {
                floodShown = true
                out.append(EmergencyAccessText.flooded)
            }
            return out
        }
    }
}
