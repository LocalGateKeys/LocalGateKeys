import XCTest
import AppShared
@testable import LocalGateKeys

// MARK: vectors (the desktop's tests/vectors/sync; tests fail, never skip, when missing)

enum SyncVectors {
    static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../../tests/vectors/sync").standardized

    static func data(_ name: String) throws -> [UInt8] { Array(try Data(contentsOf: root.appendingPathComponent(name))) }
    static func json(_ name: String) throws -> [String: JSONValue] {
        guard case .object(let o) = try CanonicalJSON.parse(try data(name)) else { throw CocoaError(.fileReadCorruptFile) }
        return o
    }
    static func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
    static func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }
    static func hex(_ s: String) -> [UInt8] {
        var out: [UInt8] = []; var i = s.startIndex
        while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
        return out
    }

    static func identity(_ who: String) throws -> DeviceIdentity {
        let p = obj(obj(obj(try json("identities.json")["devices"])[who])["private"])
        return try DeviceIdentity(deviceID: str(p["device_id"]), signingPrivate: try Base64.decodeStrict(str(p["signing_private"])),
                                  exchangePrivate: try Base64.decodeStrict(str(p["exchange_private"])))
    }

    static func qrText() throws -> String { String(decoding: try data("lan/qr_payload.txt"), as: UTF8.self) }
    static func lanNow() throws -> Int64 { if case .int(let n)? = try json("lan/expected_lan.json")["now"] { return n }; return 0 }
    static func lanGroupKey() throws -> GroupKey {
        let lan = try json("lan/expected_lan.json")
        let offer = try PairingOffer.parseQR(try qrText())
        return try GroupKey(groupID: offer.groupID, epoch: 1, key: hex(str(obj(lan["reply_no_endpoint"])["key_hex"])))
    }
    static let password = "correct horse battery staple 42"
}

// MARK: fakes

/// In-memory folder: path -> bytes; directories exist when a file lies under them.
final class MemoryFolder: FolderAccess, @unchecked Sendable {
    private let lock = NSLock()
    private var _files: [String: [UInt8]] = [:]
    var files: [String: [UInt8]] { get { lock.withLock { _files } } set { lock.withLock { _files = newValue } } }

    func list(_ dir: String) throws -> [String] {
        let prefix = dir + "/"
        let names = files.keys.filter { $0.hasPrefix(prefix) }.map { String($0.dropFirst(prefix.count)) }.filter { !$0.contains("/") }
        if names.isEmpty && !exists(dir) { throw FolderAccessError.notFound(dir) }
        return names
    }
    func read(_ path: String, limit: Int) throws -> [UInt8] {
        guard let d = files[path] else { throw FolderAccessError.notFound(path) }
        return Array(d.prefix(limit))
    }
    func writeAtomic(_ path: String, _ data: [UInt8]) throws { lock.withLock { _files[path] = data } }
    func remove(_ path: String) throws {
        guard lock.withLock({ _files.removeValue(forKey: path) }) != nil else { throw FolderAccessError.notFound(path) }
    }
    func exists(_ path: String) -> Bool { files[path] != nil || files.keys.contains { $0.hasPrefix(path + "/") } }
}

final class FakeFolders: FolderOpening, @unchecked Sendable {
    let folder: MemoryFolder
    var refreshed: [UInt8]?
    var opened: [[UInt8]] = []
    init(_ folder: MemoryFolder) { self.folder = folder }
    func bookmark(for url: URL) throws -> [UInt8] { Array(url.path.utf8) }
    func open(bookmark: [UInt8]) throws -> (folder: any FolderAccess, refreshed: [UInt8]?) {
        opened.append(bookmark)
        return (folder, refreshed)
    }
}

/// Fake Wi-Fi transport. `exchange` answers view exchanges; `gate` (when set) holds each exchange until
/// the test opens it, so overlapping runs would be visible in `maxConcurrent`.
final class FakeLan: LanTransporting, @unchecked Sendable {
    private let lock = NSLock()
    var exchange: @Sendable ([ItemState]) throws -> [ItemState] = { _ in [] }
    var enrollReply: @Sendable ([UInt8]) throws -> [UInt8] = { _ in throw LanSocketError("refused") }
    /// Awaited before `enrollReply` (a dial still in flight).
    var enrollHold: (@Sendable () async throws -> Void)?
    /// Reports the dial as connected before `enrollHold` (the reply is awaited after connecting).
    var connectsBeforeHold = false
    private(set) var exchanges = 0, enrolls = 0, active = 0, maxConcurrent = 0
    private(set) var sent: [[ItemState]] = []
    private var waiters: [CheckedContinuation<Void, Never>] = []
    var gated = false

    func exchangeViews(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                       ownCounter: Int64) async throws -> [ItemState] {
        lock.withLock { exchanges += 1; active += 1; maxConcurrent = max(maxConcurrent, active); sent.append(localStates) }
        defer { lock.withLock { active -= 1 } }
        if lock.withLock({ gated }) { await withCheckedContinuation { c in lock.withLock { waiters.append(c) } } }
        return try exchange(localStates)
    }

    func enroll(endpoint: LanEndpoint, request: [UInt8], onConnected: @escaping @Sendable () -> Void) async throws -> [UInt8] {
        lock.withLock { enrolls += 1 }
        if connectsBeforeHold { onConnected() }
        if let enrollHold { try await enrollHold() }
        return try enrollReply(request)
    }

    var waiting: Int { lock.withLock { waiters.count } }
    func release() { let w = lock.withLock { defer { waiters = []; gated = false }; return waiters }; w.forEach { $0.resume() } }
}

final class CountingAutoFill: AutoFillIdentityRefreshing, @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    var calls: Int { lock.withLock { n } }
    func syncDidFinish(store: any ItemStore) async { lock.withLock { n += 1 } }
}

/// Holds the first publish until `release`, and records overlapping publishes.
final class GatedAutoFill: AutoFillIdentityRefreshing, @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0, active = 0, peak = 0, held = true
    private var waiters: [CheckedContinuation<Void, Never>] = []
    var calls: Int { lock.withLock { n } }
    var maxConcurrent: Int { lock.withLock { peak } }
    var waiting: Int { lock.withLock { waiters.count } }
    func syncDidFinish(store: any ItemStore) async {
        let hold = lock.withLock { n += 1; active += 1; peak = max(peak, active); return held }
        if hold { await withCheckedContinuation { c in lock.withLock { waiters.append(c) } } }
        lock.withLock { active -= 1 }
    }
    func release() { let w = lock.withLock { held = false; defer { waiters = [] }; return waiters }; w.forEach { $0.resume() } }
}

/// `MemoryStore` that is safe to touch from the coordinator's background work.
final class LockedStore: ItemStore, @unchecked Sendable {
    private let lock = NSLock()
    private var snap: StoreSnapshot
    private var n = 0, reads = 0
    init(_ s: StoreSnapshot = StoreSnapshot()) { snap = s }
    var snapshot: StoreSnapshot { lock.withLock { snap } }
    var commits: Int { lock.withLock { n } }
    var loads: Int { lock.withLock { reads } }
    func load() throws -> StoreSnapshot { lock.withLock { reads += 1; return snap } }
    func commit(_ change: StoreChange) throws {
        try lock.withLock {
            guard change.baseRevision == snap.revision else { throw LocalStoreError.stale(expected: change.baseRevision, actual: snap.revision) }
            snap = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: snap.revision + 1)
            n += 1
        }
    }
}

final class FixedRandom: RandomSource, @unchecked Sendable {
    func bytes(count: Int) -> [UInt8] { SystemRandomSource().bytes(count: count) }
}

/// Records sleeps; returns at once (no real waiting).
final class NoSleep: @unchecked Sendable {
    private let lock = NSLock()
    private var log: [UInt64] = []
    var slept: [UInt64] { lock.withLock { log } }
    var fn: @Sendable (UInt64) async -> Void { { [self] n in lock.withLock { log.append(n) } } }
}

func noteRecord(_ i: Int, title: String = "Note") -> (String, JSONValue) {
    let id = String(format: "00000000-0000-4000-8000-%012d", i)
    let r = rec(["id": .string(id), "kind": .string("note"), "title": .string("\(title) \(i)"), "created_at": .int(1_700_000_000),
                 "updated_at": .int(1_700_000_000 + Int64(i)), "favorite": .bool(false), "tags": .array([]),
                 "payload": rec(["body": .string("body \(i)"), "fields": .array([]), "template_id": .null])])
    let normal = try! Normalise.normalForm(ns: .item, record: r)
    return (id, Wrapper.make(ns: .item, record: normal))
}

/// The states device `device` would publish for `records`.
func peerStates(_ records: [String: JSONValue], device: String, now: Int64) throws -> [ItemState] {
    try SyncMeta.localView(records: records, meta: [:], device: device, now: now).states.values.sorted { $0.itemID < $1.itemID }
}

// MARK: tests

@MainActor
final class SyncCoordinatorTests: XCTestCase {
    var keychain: InMemoryKeychainVault!, lan: FakeLan!, folder: MemoryFolder!, folders: FakeFolders!
    var autoFill: CountingAutoFill!, clock: TestClock!, sleeper: NoSleep!

    override func setUp() async throws {
        keychain = InMemoryKeychainVault(); lan = FakeLan(); folder = MemoryFolder(); folders = FakeFolders(folder)
        autoFill = CountingAutoFill(); clock = TestClock(try SyncVectors.lanNow()); sleeper = NoSleep()
    }

    func test_quicktype_updates_run_in_order_and_stop_after_shutdown() async {
        let c = SyncCoordinator(store: LockedStore(StoreSnapshot()), deps: deps(), background: FakeBackgroundTasks())
        c.identitySettingsChanged(); c.identitySettingsChanged()
        await c.shutdownAndWait()
        let after = autoFill.calls
        XCTAssertLessThanOrEqual(after, 2)
        c.identitySettingsChanged()
        await c.shutdownAndWait()
        XCTAssertEqual(autoFill.calls, after, "nothing republishes after shutdown")
    }

    // MARK: AutoFill identities without a joined sync

    func test_not_joined_sync_still_publishes_identities() async {
        let (id, wrapper) = noteRecord(1)
        let store = LockedStore(StoreSnapshot(records: [id: wrapper], meta: [:], sync: nil, revision: 1))
        let c = SyncCoordinator(store: store, deps: deps(), background: FakeBackgroundTasks())
        await c.sync(.appOpen)   // unlock
        XCTAssertEqual(autoFill.calls, 1, "unlock publishes the identities even when this phone never joined")
        XCTAssertEqual(lan.exchanges, 0)
    }

    func test_local_commit_publishes_identities_at_once_and_never_after_lock() async {
        var d = deps()
        d.sleep = { _ in try? await Task.sleep(nanoseconds: 3_600_000_000_000) }   // the debounced sync never fires
        let c = SyncCoordinator(store: LockedStore(), deps: d, background: FakeBackgroundTasks())
        c.noteLocalEdit()
        await c.identitiesSettled()
        XCTAssertEqual(autoFill.calls, 1, "an editor save/delete or passkey rename/delete republishes without waiting for sync")
        c.noteLocalEdit()
        await c.identitiesSettled()
        XCTAssertEqual(autoFill.calls, 2)
        XCTAssertEqual(lan.exchanges, 0)
        c.shutdown()
        c.noteLocalEdit()
        await c.identitiesSettled()
        XCTAssertEqual(autoFill.calls, 2, "nothing republishes after lock")
    }

    func test_sync_publishes_after_a_queued_identity_update_never_alongside() async {
        let gated = GatedAutoFill()
        var d = deps(); d.autoFill = gated
        let c = SyncCoordinator(store: LockedStore(), deps: d, background: FakeBackgroundTasks())
        c.refreshIdentities()                       // a Settings change, held mid-publish
        while gated.waiting == 0 { await Task.yield() }
        let run = Task { await c.sync(.appOpen) }   // not joined: the run publishes too
        for _ in 0..<200 { await Task.yield() }
        XCTAssertEqual(gated.calls, 1, "the run's publish waits for the update queued before it")
        gated.release()
        await run.value
        XCTAssertEqual(gated.calls, 2)
        XCTAssertEqual(gated.maxConcurrent, 1)
    }

    func deps(identity: DeviceIdentity? = nil) -> SyncDependencies {
        var d = SyncDependencies(keychain: keychain, folders: folders, lan: lan, autoFill: autoFill, random: FixedRandom(),
                                 clock: clock, licenseKeys: [:])
        if let identity { d.newIdentity = { _ in identity } }
        d.sleep = sleeper.fn
        return d
    }

    /// The desktop's inviter (A) side of the vector enrollment: checks B's request, answers with the recorded reply.
    func inviterAnswers() throws {
        let offer = try PairingOffer.parseQR(try SyncVectors.qrText())
        let a = try SyncVectors.identity("A")
        let reply = try SyncVectors.data("lan/enroll_reply_no_endpoint.bin")
        lan.enrollReply = { request in
            let opened = try Enrollment.openRequest(offer: offer, inviter: a, raw: request)
            XCTAssertNil(opened.endpoint)   // a phone announces no endpoint
            return reply
        }
    }

    /// A phone joined by QR (vector group, identity B, paired with A at the offer endpoint).
    func qrJoined(_ store: LockedStore) async throws -> SyncCoordinator {
        try inviterAnswers()
        let c = SyncCoordinator(store: store, deps: deps(identity: try SyncVectors.identity("B")))
        let ok = await c.joinByQR(try SyncVectors.qrText())
        XCTAssertTrue(ok, c.actionError ?? "")
        return c
    }

    // MARK: joining

    func test_join_by_qr_enrolls_pins_the_inviter_and_runs_the_first_sync() async throws {
        let a = try SyncVectors.identity("A")
        let (id, wrapper) = noteRecord(1, title: "From PC")
        let fromPC = try peerStates([id: wrapper], device: a.deviceID, now: clock.now)
        lan.exchange = { _ in fromPC }
        let store = LockedStore()
        let c = try await qrJoined(store)

        let state = try XCTUnwrap(store.snapshot.sync)
        let gk = try SyncVectors.lanGroupKey()
        XCTAssertEqual(state.groupID, gk.groupID); XCTAssertEqual(state.epoch, 1); XCTAssertEqual(state.key, gk.key)
        XCTAssertEqual(state.deviceID, try SyncVectors.identity("B").deviceID)
        XCTAssertFalse(state.hasFolder)
        XCTAssertEqual(state.installID, try keychain.installID(random: FixedRandom()))
        let peer = try XCTUnwrap(try keychain.pairedPeer())
        XCTAssertEqual(peer, try PairingOffer.parseQR(try SyncVectors.qrText()).inviterPeer)
        XCTAssertTrue(LanAddress.isLAN(try XCTUnwrap(peer.endpoint).host))
        // First sync ran: the PC's item arrived through ItemStore, AutoFill was told.
        XCTAssertEqual(lan.enrolls, 1); XCTAssertEqual(lan.exchanges, 1)
        XCTAssertEqual(store.snapshot.records[id], wrapper)
        XCTAssertEqual(autoFill.calls, 1)
        XCTAssertEqual(c.phase, .idle); XCTAssertTrue(c.membership.joined); XCTAssertEqual(c.membership.peer, peer)
        XCTAssertNotNil(c.lastSyncedAt); XCTAssertEqual(c.issues, [])
    }

    func test_qr_refusals_use_desktop_wording_and_leave_store_untouched() async throws {
        let store = LockedStore()
        let c = SyncCoordinator(store: store, deps: deps(identity: try SyncVectors.identity("B")))
        await c.joinByQR("not a code")
        XCTAssertEqual(c.actionError, "That is not a valid LocalGateKeys pairing code.")
        lan.enrollReply = { _ in throw LanSocketError("connect failed") }
        await c.joinByQR(try SyncVectors.qrText())
        XCTAssertEqual(c.actionError, "Could not connect to 192.168.1.20:48201. Check that the PC is on this Wi-Fi and shows its code.")
        lan.enrollReply = { _ in Enrollment.refusedMagic + Array(#"{"reason":"used-or-expired"}"#.utf8) }
        await c.joinByQR(try SyncVectors.qrText())
        XCTAssertEqual(c.actionError, "This pairing code was used up or expired. Show a new code.")
        lan.enrollReply = { _ in Enrollment.refusedMagic + Array(#"{"reason":"full"}"#.utf8) }
        await c.joinByQR(try SyncVectors.qrText())
        XCTAssertEqual(c.actionError, "The other device already has the most paired devices. Remove one there first.")
        clock.now = 1_790_000_000 + 10_000   // past the offer's expiry: refused before anything is sent
        let before = lan.enrolls
        await c.joinByQR(try SyncVectors.qrText())
        XCTAssertEqual(c.actionError, "This pairing code was used up or expired. Show a new code.")
        XCTAssertEqual(lan.enrolls, before)
        XCTAssertEqual(store.commits, 0); XCTAssertNil(store.snapshot.sync); XCTAssertNil(try keychain.pairedPeer())
    }

    // MARK: pairing failures (Wi-Fi)

    func test_enroll_failures_name_the_address_and_what_to_do() async throws {
        let store = LockedStore()
        let c = SyncCoordinator(store: store, deps: deps(identity: try SyncVectors.identity("B")))
        let cases: [(LanFailure, String)] = [
            (.refused, "Nothing is listening at 192.168.1.20:48201. Open Sync on the PC, choose Show QR code, and scan the new code."),
            (.unreachable, "192.168.1.20:48201 cannot be reached from this iPhone. Check that the PC is on this Wi-Fi and that the code shows the PC's Wi-Fi address."),
            (.timedOut, "192.168.1.20:48201 did not answer. Check that Windows Firewall allows LocalGateKeys on Private networks, and that the PC is on this Wi-Fi."),
            (.localNetworkDenied, "LocalGateKeys is not allowed to use the local network, so it could not reach 192.168.1.20:48201. Allow Local Network for LocalGateKeys in Settings › Privacy & Security › Local Network, then scan the code again."),
            (.closedByPeer, "The PC at 192.168.1.20:48201 closed the connection: the code has probably expired or is no longer waiting. Show a new code on the PC and scan it again."),
        ]
        for (kind, text) in cases {
            lan.enrollReply = { _ in throw LanSocketError("x", kind: kind) }
            let joined = await c.joinByQR(try SyncVectors.qrText())
            XCTAssertFalse(joined)
            XCTAssertEqual(c.actionError, text, "\(kind)")
            XCTAssertEqual(c.actionOffersSettings, kind == .localNetworkDenied, "\(kind)")
            XCTAssertEqual(c.phase, .idle); XCTAssertNil(c.connecting)
        }
        XCTAssertEqual(store.commits, 0); XCTAssertNil(try keychain.pairedPeer())
    }

    func test_offer_off_this_subnet_explains_the_address_when_it_fails() async throws {
        var d = deps(identity: try SyncVectors.identity("B"))
        d.localSubnet = { IPv4Subnet(address: "192.168.60.11", netmask: "255.255.255.0") }
        let c = SyncCoordinator(store: LockedStore(), deps: d)
        let offSubnet = "The code points to 192.168.1.20 but this iPhone is on 192.168.60.0/24. On the PC, set the sync address to its Wi-Fi IPv4 address (ipconfig) and show a new code."
        for kind in [LanFailure.refused, .unreachable, .timedOut, .other] {
            lan.enrollReply = { _ in throw LanSocketError("x", kind: kind) }
            await c.joinByQR(try SyncVectors.qrText())
            XCTAssertEqual(c.actionError, offSubnet, "\(kind)")
        }
        // It still dials (the address may be routed), and a denial or a close keeps its own advice.
        XCTAssertEqual(lan.enrolls, 4)
        lan.enrollReply = { _ in throw LanSocketError("x", kind: .localNetworkDenied) }
        await c.joinByQR(try SyncVectors.qrText())
        XCTAssertTrue(c.actionError?.hasPrefix("LocalGateKeys is not allowed to use the local network") ?? false)
        // On the same subnet: the plain message.
        d.localSubnet = { IPv4Subnet(address: "192.168.1.9", netmask: "255.255.255.0") }
        let same = SyncCoordinator(store: LockedStore(), deps: d)
        lan.enrollReply = { _ in throw LanSocketError("x", kind: .refused) }
        await same.joinByQR(try SyncVectors.qrText())
        XCTAssertEqual(same.actionError, "Nothing is listening at 192.168.1.20:48201. Open Sync on the PC, choose Show QR code, and scan the new code.")
    }

    func test_connecting_shows_the_address_and_cancel_stops_the_join() async throws {
        let store = LockedStore()
        let c = SyncCoordinator(store: store, deps: deps(identity: try SyncVectors.identity("B")))
        lan.enrollHold = { try await Task.sleep(nanoseconds: 60_000_000_000) }
        let qr = try SyncVectors.qrText()
        let join = Task { await c.joinByQR(qr) }
        while lan.enrolls == 0 { await Task.yield() }
        XCTAssertEqual(c.phase, .joining)
        XCTAssertEqual(c.connecting, try LanEndpoint(validating: "192.168.1.20", port: 48201))
        let started = Date()
        c.cancelJoin()
        let joined = await join.value
        XCTAssertFalse(joined)
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
        XCTAssertEqual(c.phase, .idle); XCTAssertNil(c.connecting)
        XCTAssertNil(c.actionError); XCTAssertEqual(c.actionInfo, "Pairing was cancelled.")
        XCTAssertEqual(store.commits, 0); XCTAssertNil(try keychain.pairedPeer())
    }

    func test_connecting_clears_once_connected_and_cancel_is_then_ignored() async throws {
        try inviterAnswers()
        let c = SyncCoordinator(store: LockedStore(), deps: deps(identity: try SyncVectors.identity("B")))
        let gate = AsyncGate()
        lan.connectsBeforeHold = true
        lan.enrollHold = { await gate.wait() }
        let qr = try SyncVectors.qrText()
        let join = Task { await c.joinByQR(qr) }
        while gate.waiting == 0 { await Task.yield() }
        while c.connecting != nil { await Task.yield() }   // the hop to the main actor
        XCTAssertEqual(c.phase, .joining)
        c.cancelJoin()   // no Cancel once connected: the reply is being processed
        gate.open()
        let joined = await join.value
        XCTAssertTrue(joined)
    }

    func test_open_settings_offer_resets_on_the_next_action() async throws {
        let c = SyncCoordinator(store: LockedStore(), deps: deps(identity: try SyncVectors.identity("B")))
        lan.enrollReply = { _ in throw LanSocketError("x", kind: .localNetworkDenied) }
        await c.joinByQR(try SyncVectors.qrText())
        XCTAssertTrue(c.actionOffersSettings)
        await c.reset()
        XCTAssertFalse(c.actionOffersSettings)
        lan.enrollReply = { _ in throw LanSocketError("x", kind: .localNetworkDenied) }
        await c.joinByQR(try SyncVectors.qrText())
        XCTAssertTrue(c.actionOffersSettings)
        await c.joinByQR("not a code")
        XCTAssertFalse(c.actionOffersSettings)
    }

    func test_shutdown_and_wait_waits_for_a_join_in_flight() async throws {
        let c = SyncCoordinator(store: LockedStore(), deps: deps(identity: try SyncVectors.identity("B")))
        let gate = AsyncGate()
        lan.enrollHold = { await gate.wait() }
        let qr = try SyncVectors.qrText()
        let join = Task { await c.joinByQR(qr) }
        while gate.waiting == 0 { await Task.yield() }
        let done = Flag()
        let shut = Task { await c.shutdownAndWait(); done.set() }
        for _ in 0..<200 { await Task.yield() }
        XCTAssertFalse(done.isSet, "shutdownAndWait returned while the join was still in flight")
        gate.open()
        await shut.value
        _ = await join.value
        XCTAssertTrue(done.isSet)
    }

    func test_join_by_folder_with_password() async throws {
        folder.files["LocalGateKeys Sync/keyring.lgkkeys"] = try SyncVectors.data("keyring_epoch1.json")
        for (who, name) in [("A", "A"), ("B", "B"), ("C", "C")] {
            let id = try SyncVectors.identity(who).deviceID
            folder.files["LocalGateKeys Sync/devices/\(id).lgksync"] = try SyncVectors.data("devices/\(name).lgksync")
        }
        clock.now = 1_790_000_000 + 1000
        let store = LockedStore()
        let c = SyncCoordinator(store: store, deps: deps())

        // A wrong password is refused with the desktop wording and changes nothing.
        let wrong = await c.joinFolder(bookmark: Array("bm".utf8), password: "wrong password here")
        XCTAssertFalse(wrong)
        XCTAssertEqual(c.actionError, "That sync password is not right for this folder.")
        XCTAssertEqual(store.commits, 0); XCTAssertNil(try keychain.read(.folderBookmark))

        folders.refreshed = Array("fresh".utf8)
        let ok = await c.joinFolder(bookmark: Array("bm".utf8), password: SyncVectors.password)
        XCTAssertTrue(ok, c.actionError ?? "")
        let state = try XCTUnwrap(store.snapshot.sync)
        XCTAssertTrue(state.hasFolder)
        XCTAssertFalse(store.snapshot.records.isEmpty)   // A, B and C's items merged in the first run
        XCTAssertNotNil(folder.files["LocalGateKeys Sync/devices/\(state.deviceID).lgksync"])
        // The (refreshed) bookmark is kept in the Keychain; the folder is used on the next sync.
        XCTAssertEqual(try keychain.read(.folderBookmark), Array("fresh".utf8))
        XCTAssertTrue(c.membership.hasFolder); XCTAssertTrue(c.membership.hasBookmark)
        XCTAssertEqual(autoFill.calls, 1)
        await c.sync(.appOpen)
        XCTAssertEqual(folders.opened.last, Array("fresh".utf8))
        XCTAssertEqual(autoFill.calls, 2)
    }

    func test_wrong_password_backs_off_after_five_attempts() async throws {
        folder.files["LocalGateKeys Sync/keyring.lgkkeys"] = try SyncVectors.data("keyring_epoch1.json")
        let c = SyncCoordinator(store: LockedStore(), deps: deps())
        // Argon2id runs only until the back-off: attempt 6 is refused without reading the folder.
        for _ in 0..<5 { await c.joinFolder(bookmark: [1], password: "nope nope nope") }
        let opens = folders.opened.count
        await c.joinFolder(bookmark: [1], password: SyncVectors.password)
        XCTAssertEqual(c.actionError, SyncWording.passwordBackoffText)
        XCTAssertEqual(folders.opened.count, opens)
        clock.now += 30
        await c.joinFolder(bookmark: [1], password: SyncVectors.password)
        XCTAssertNil(c.actionError)
    }

    func test_attach_after_qr_keeps_the_pairing() async throws {
        // QR-joined to the existing-group vector group (A created it; the phone holds the epoch-1 key).
        let x = try SyncVectors.json("expected.json")
        let existing = SyncVectors.obj(x["existing_group"])
        let gid = SyncVectors.str(existing["group_id"])
        let key = SyncVectors.hex(SyncVectors.str(SyncVectors.obj(SyncVectors.obj(existing["epochs"])["1"])["group_key_hex"]))
        let me = try DeviceIdentity.generate(random: FixedRandom())
        let install = try keychain.installID(random: FixedRandom())
        let store = LockedStore(StoreSnapshot(sync: SyncGroupState(groupID: gid, epoch: 1, key: key, identity: me,
                                                                    installID: install, hasFolder: false)))
        let a = try SyncVectors.identity("A")
        let peer = PinnedPeer(deviceID: a.deviceID, groupID: gid, signingPublic: a.signingPublicKey,
                              exchangePublic: a.exchangePublicKey, endpoint: try LanEndpoint(validating: "192.168.1.20", port: 47821))
        try keychain.setPairedPeer(peer)
        folder.files["LocalGateKeys Sync/keyring.lgkkeys"] = try SyncVectors.data("keyring_existing_epoch1.json")
        clock.now = 1_790_000_000 + 1000

        let c = SyncCoordinator(store: store, deps: deps())
        XCTAssertTrue(c.membership.joined); XCTAssertFalse(c.membership.hasFolder)
        let ok = await c.joinFolder(bookmark: [7], password: SyncVectors.str(SyncVectors.obj(existing["attach"])["password"]))
        XCTAssertTrue(ok, c.actionError ?? "")
        let state = try XCTUnwrap(store.snapshot.sync)
        XCTAssertTrue(state.hasFolder)
        XCTAssertEqual(state.identity, me)            // attach: no new identity, no re-merge
        XCTAssertEqual(state.groupID, gid)
        XCTAssertTrue(state.members.contains(me.deviceID))
        XCTAssertEqual(try keychain.pairedPeer(), peer)   // Wi-Fi pairing kept
        XCTAssertEqual(lan.exchanges, 1)                   // and still synced after the attach
        // Its own file is in the folder now.
        XCTAssertNotNil(folder.files["LocalGateKeys Sync/devices/\(me.deviceID).lgksync"])
    }

    // MARK: running

    func test_issues_map_to_the_desktop_wording() async throws {
        let store = LockedStore()
        let c = try await qrJoined(store)
        lan.exchange = { _ in throw LanSocketError("connect failed: refused") }
        await c.sync(.manual)
        XCTAssertEqual(c.issues.map(\.kind), ["unreachable"])
        XCTAssertEqual(c.issues.first?.text, "A device could not be reached on this network. Check that it is on the same Wi-Fi and that LocalGateKeys is unlocked there.")
        XCTAssertEqual(c.issues.first?.severity, .notice)
        lan.exchange = { _ in throw LanSyncError("epoch-behind", "a1111111-0000-4000-8000-00000000000a") }
        await c.sync(.manual)
        XCTAssertEqual(c.issues.first?.text, "This iPhone has an older sync key than Device a1111111. Leave sync on this iPhone, then pair it again.")
        lan.exchange = { _ in throw LanSyncError("bad-message") }
        await c.sync(.manual)
        XCTAssertEqual(c.issues.map(\.kind), ["bad-reply"])

        // Table checks: verbatim desktop copy, shown with "iPhone" for "PC".
        XCTAssertEqual(SyncWording.desktopText(SyncIssue("keyring-missing")),
                       "The key file in the sync folder is missing. Check the folder, or reset sync on this PC.")
        XCTAssertEqual(SyncWording.text(SyncIssue("keyring-missing")),
                       "The key file in the sync folder is missing. Check the folder, or reset sync on this iPhone.")
        XCTAssertEqual(SyncWording.text(SyncIssue("unreadable", "x.lgksync: io")), "The file x.lgksync could not be read and was skipped.")
        XCTAssertEqual(SyncWording.text(SyncIssue("rollback", "keyring.lgkkeys: x")),
                       "The key file in the sync folder was replaced by an older copy and could not be put back. Sync stopped. Check the folder, or reset sync on this iPhone and join again.")
        XCTAssertEqual(SyncWording.text(SyncIssue("rejoin-required", "install-mismatch")),
                       "This vault was set up for sync on another device. Join the folder again on this iPhone, or reset sync.")
        XCTAssertEqual(SyncWording.errorText(reason: "rejoin-required"),
                       "This vault was set up for sync on another device. Join the folder again on this iPhone.")
        XCTAssertEqual(SyncWording.text(SyncIssue("ignored-file", "2 files: a (1).lgksync, b")),
                       "Unknown files in the sync folder were ignored (2 files: a (1).lgksync, b). Cloud apps sometimes make copies like these; you can delete them.")
        XCTAssertEqual(SyncWording.text(SyncIssue("something-new")), "Sync reported a problem. Details are in the error log.")
        let views = SyncWording.views([SyncIssue("busy"), SyncIssue("tampered"), SyncIssue("tampered"), SyncIssue("corrupt", "f.lgksync: x")])
        XCTAssertEqual(views.map(\.kind), ["tampered", "corrupt", "busy"])
        XCTAssertEqual(views.map(\.resetOffered), [true, false, false])
    }

    func test_no_concurrent_syncs() async throws {
        let store = LockedStore()
        let c = try await qrJoined(store)
        let base = lan.exchanges
        lan.gated = true
        let first = Task { await c.sync(.appOpen) }
        while lan.waiting == 0 { await Task.yield() }
        XCTAssertEqual(c.phase, .syncing)
        // Pull-to-refresh and an edit while the run is in flight: folded into ONE more run after it.
        let second = Task { await c.sync(.pullToRefresh) }
        let third = Task { await c.sync(.localEdit) }
        for _ in 0..<50 { await Task.yield() }
        XCTAssertEqual(lan.exchanges, base + 1)
        let joinWhileBusy = await c.joinByQR(try SyncVectors.qrText())
        XCTAssertFalse(joinWhileBusy)
        lan.release()
        await first.value; await second.value; await third.value
        XCTAssertEqual(lan.exchanges, base + 2)
        XCTAssertEqual(lan.maxConcurrent, 1)
        XCTAssertEqual(c.phase, .idle)
    }

    func test_edits_trigger_one_debounced_sync() async throws {
        let store = LockedStore()
        let c = try await qrJoined(store)
        let base = lan.exchanges
        c.noteLocalEdit(); c.noteLocalEdit(); c.noteLocalEdit()
        for _ in 0..<200 where lan.exchanges == base { await Task.yield() }
        for _ in 0..<50 { await Task.yield() }
        XCTAssertEqual(lan.exchanges, base + 1)
        XCTAssertTrue(sleeper.slept.allSatisfy { $0 == 2_000_000_000 })
        // The edited item is what the next run publishes.
        XCTAssertEqual(lan.sent.count, base + 1)
    }

    func test_failed_sync_leaves_store_untouched() async throws {
        let store = LockedStore()
        let (id, wrapper) = noteRecord(3)
        let c = try await qrJoined(store)
        var snap = store.snapshot
        snap.records[id] = wrapper
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        let before = store.snapshot, commits = store.commits
        for failure: Error in [LanSyncError("bad-chunk"), LanSyncError("device-mismatch", "x"), LanSocketError("read timed out"),
                               LanTransportError.authentication("bad hello")] {
            lan.exchange = { _ in throw failure }
            await c.sync(.manual)
            XCTAssertEqual(store.snapshot, before)
            XCTAssertEqual(store.commits, commits)
            XCTAssertFalse(c.issues.isEmpty)
        }
        // A folder group whose bookmark is gone: reported, store untouched.
        var s = store.snapshot
        s.sync?.hasFolder = true
        try store.commit(StoreChange(baseRevision: s.revision, records: s.records, meta: s.meta, sync: s.sync))
        let folderBefore = store.snapshot
        await c.sync(.manual)
        XCTAssertTrue(c.issues.contains { $0.kind == "folder-missing" })
        XCTAssertEqual(store.snapshot, folderBefore)
    }

    func test_lan_refuses_a_non_lan_peer_address() async throws {
        let store = LockedStore()
        let c = try await qrJoined(store)
        let p = try XCTUnwrap(try keychain.pairedPeer())
        // A stored peer can only hold a validated LAN endpoint; a forged one is refused before any connect.
        try keychain.write(.pairedPeer, Array(#"{"device_id":"\#(p.deviceID)","endpoint":{"host":"8.8.8.8","port":443},"exchange_public":"\#(Base64.encode(p.exchangePublic))","group_id":"\#(p.groupID)","signing_public":"\#(Base64.encode(p.signingPublic))"}"#.utf8))
        let base = lan.exchanges
        await c.sync(.manual)
        XCTAssertEqual(lan.exchanges, base)
        XCTAssertFalse(c.issues.isEmpty)
    }

    func seedEpoch1Folder() throws {
        folder.files["LocalGateKeys Sync/keyring.lgkkeys"] = try SyncVectors.data("keyring_epoch1.json")
        for who in ["A", "B", "C"] {
            let id = try SyncVectors.identity(who).deviceID
            folder.files["LocalGateKeys Sync/devices/\(id).lgksync"] = try SyncVectors.data("devices/\(who).lgksync")
        }
        clock.now = 1_790_000_000 + 1000
    }

    func test_choose_the_folder_again_stores_the_bookmark_without_joining() async throws {
        try seedEpoch1Folder()
        let store = LockedStore()
        let c = SyncCoordinator(store: store, deps: deps())
        let joined = await c.joinFolder(bookmark: [1], password: SyncVectors.password)
        XCTAssertTrue(joined)
        let member = try XCTUnwrap(store.snapshot.sync)
        try keychain.delete(.folderBookmark)   // e.g. the Keychain write after the join failed
        c.refreshMembership(); XCTAssertFalse(c.membership.hasBookmark)

        // A folder holding another group is refused and the bookmark is not stored.
        let other = MemoryFolder()
        other.files["LocalGateKeys Sync/keyring.lgkkeys"] = try SyncVectors.data("keyring_existing_epoch1.json")
        let otherFolders = FakeFolders(other)
        var d = deps(); d.folders = otherFolders
        let c2 = SyncCoordinator(store: store, deps: d)
        do { let r = await c2.joinFolder(bookmark: [9], password: ""); XCTAssertFalse(r) }
        XCTAssertEqual(c2.actionError, "That folder holds a different sync group. Choose another folder, or the folder your other device added to this group.")
        XCTAssertNil(try keychain.read(.folderBookmark))

        let ok = await c.joinFolder(bookmark: [2], password: "")
        XCTAssertTrue(ok, c.actionError ?? "")
        XCTAssertEqual(try keychain.read(.folderBookmark), [2])
        XCTAssertEqual(store.snapshot.sync?.identity, member.identity)   // no new join
        XCTAssertTrue(c.membership.hasBookmark)
    }

    func test_choosing_the_folder_again_is_not_subject_to_the_password_backoff() async throws {
        try seedEpoch1Folder()
        let store = LockedStore()
        let c = SyncCoordinator(store: store, deps: deps())
        for _ in 0..<5 { await c.joinFolder(bookmark: [1], password: "nope nope nope") }
        // The vault joins the group (another coordinator over the same store), then the bookmark is lost.
        let joined = await SyncCoordinator(store: store, deps: deps()).joinFolder(bookmark: [1], password: SyncVectors.password)
        XCTAssertTrue(joined)
        try keychain.delete(.folderBookmark)
        // Re-picking checks no password, so the 30 s back-off does not apply.
        let ok = await c.joinFolder(bookmark: [3], password: "")
        XCTAssertTrue(ok, c.actionError ?? "")
        XCTAssertEqual(try keychain.read(.folderBookmark), [3])
    }

    func test_failed_folder_reads_never_commit() async throws {
        try seedEpoch1Folder()
        let store = LockedStore()
        let c = SyncCoordinator(store: store, deps: deps())
        // A bad password key: refused, nothing committed.
        do { let r = await c.joinFolder(bookmark: [1], password: "not the sync password"); XCTAssertFalse(r) }
        XCTAssertEqual(store.commits, 0)
        do { let r = await c.joinFolder(bookmark: [1], password: SyncVectors.password); XCTAssertTrue(r) }
        await c.sync(.manual); await c.sync(.manual)   // settle
        let a = try SyncVectors.identity("A").deviceID

        // A corrupt device file: reported, skipped, no commit.
        var commits = store.commits
        let goodA = folder.files["LocalGateKeys Sync/devices/\(a).lgksync"]!
        folder.files["LocalGateKeys Sync/devices/\(a).lgksync"] = Array(goodA.prefix(40)) + [UInt8](repeating: 0x41, count: 64)
        await c.sync(.manual)
        XCTAssertTrue(c.issues.contains { $0.kind == "corrupt" })
        XCTAssertEqual(store.commits, commits)
        folder.files["LocalGateKeys Sync/devices/\(a).lgksync"] = goodA

        // A tampered key file: sync stops, no commit.
        commits = store.commits
        var ring = folder.files["LocalGateKeys Sync/keyring.lgkkeys"]!
        let snapshot = store.snapshot
        if let i = ring.firstIndex(of: UInt8(ascii: "\"")) { ring[ring.index(i, offsetBy: 30)] ^= 0x01 }
        folder.files["LocalGateKeys Sync/keyring.lgkkeys"] = ring
        await c.sync(.manual)
        // Tampered or damaged: either sync stops, or the trusted copy is put back; the store is untouched.
        XCTAssertTrue(c.issues.contains { ["tampered", "keyring-corrupt", "keyring-restored"].contains($0.kind) }, "\(c.issues.map(\.kind))")
        XCTAssertEqual(store.commits, commits)
        XCTAssertEqual(store.snapshot, snapshot)
    }

    func test_edit_during_a_failed_join_syncs_afterwards() async throws {
        let store = LockedStore()
        let c = try await qrJoined(store)
        let base = lan.exchanges
        lan.enrollReply = { _ in throw LanSocketError("x") }
        // Hold the join (already joined, so it fails at once) while an edit sync asks to run.
        let join = Task { await c.joinByQR("lgk-pair:x") }
        await c.sync(.localEdit)   // may run before or during the join; either way it must not be lost
        await join.value
        for _ in 0..<100 where lan.exchanges == base { await Task.yield() }
        XCTAssertGreaterThanOrEqual(lan.exchanges, base + 1)
    }

    func test_nothing_commits_after_lock() async throws {
        let store = LockedStore()
        let (id, wrapper) = noteRecord(9)
        let c = try await qrJoined(store)
        lan.exchange = { [a = try SyncVectors.identity("A")] _ in try peerStates([id: wrapper], device: a.deviceID, now: 1_790_000_030) }
        lan.gated = true
        let run = Task { await c.sync(.manual) }
        while lan.waiting == 0 { await Task.yield() }
        let commits = store.commits
        c.shutdown()   // the vault locks mid-run
        c.noteLocalEdit()
        lan.release()
        await run.value
        XCTAssertEqual(store.commits, commits)
        XCTAssertNil(store.snapshot.records[id])
        await c.sync(.manual)
        XCTAssertEqual(store.commits, commits)
    }

    func test_lock_mid_run_stops_reads_identity_refresh_and_commits() async throws {
        let store = LockedStore()
        let (id, wrapper) = noteRecord(9)
        let c = try await qrJoined(store)
        lan.exchange = { [a = try SyncVectors.identity("A")] _ in try peerStates([id: wrapper], device: a.deviceID, now: 1_790_000_030) }
        lan.gated = true
        let run = Task { await c.sync(.manual) }
        while lan.waiting == 0 { await Task.yield() }
        let loads = store.loads, commits = store.commits, refreshes = autoFill.calls
        c.shutdown()   // the vault locks while the exchange is in flight
        lan.release()
        await run.value
        XCTAssertEqual(store.loads, loads, "no store read after lock")
        XCTAssertEqual(autoFill.calls, refreshes, "no AutoFill identity refresh after lock")
        XCTAssertEqual(store.commits, commits, "no commit after lock")
        XCTAssertThrowsError(try c.store.load())
        // The production hook refuses too: the gated store is never read after lock.
        await IdentityStoreSync().syncDidFinish(store: c.store)
        XCTAssertEqual(store.loads, loads)
    }

    func test_sync_runs_inside_a_paired_background_task() async throws {
        let store = LockedStore()
        let bg = FakeBackgroundTasks()
        try inviterAnswers()
        let c = SyncCoordinator(store: store, deps: deps(identity: try SyncVectors.identity("B")), background: bg)
        let joined = await c.joinByQR(try SyncVectors.qrText())
        XCTAssertTrue(joined)
        await c.sync(.manual)
        XCTAssertGreaterThanOrEqual(bg.begun.count, 2)
        XCTAssertEqual(bg.ended.count, bg.begun.count)
        XCTAssertTrue(bg.open.isEmpty)

        // Expiry mid-run cancels the run and ends the task exactly once.
        lan.gated = true
        let run = Task { await c.sync(.manual) }
        while lan.waiting == 0 { await Task.yield() }
        XCTAssertEqual(bg.open.count, 1)
        bg.expireAll()
        XCTAssertTrue(bg.open.isEmpty)
        lan.release()
        await run.value
        XCTAssertEqual(bg.ended.count, bg.begun.count)
        XCTAssertEqual(Set(bg.ended).count, bg.ended.count, "each task ended once")
    }

    func test_leave_and_reset() async throws {
        let store = LockedStore()
        let (id, wrapper) = noteRecord(4)
        lan.exchange = { _ in [] }
        let c = try await qrJoined(store)
        var snap = store.snapshot
        snap.records[id] = wrapper
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        await c.sync(.manual)   // gives the item sync meta
        XCTAssertFalse(store.snapshot.meta.isEmpty)
        try keychain.write(.folderBookmark, [1])

        await c.leave()
        XCTAssertNil(store.snapshot.sync); XCTAssertEqual(store.snapshot.records[id], wrapper)
        XCTAssertFalse(store.snapshot.meta.isEmpty)   // leave keeps the sync history
        XCTAssertNil(try keychain.pairedPeer()); XCTAssertNil(try keychain.read(.folderBookmark))
        XCTAssertEqual(c.actionInfo, "This iPhone left sync. Remove it on one of your other devices.")
        XCTAssertFalse(c.membership.joined)

        await c.reset()
        XCTAssertTrue(store.snapshot.meta.isEmpty); XCTAssertEqual(store.snapshot.records[id], wrapper)
        XCTAssertEqual(c.actionInfo, "Sync was reset on this iPhone.")
        await c.reset()
        XCTAssertEqual(c.actionInfo, "There was nothing to reset.")
        XCTAssertEqual(SyncWording.onPhone(SyncWording.resetText2), "Are you sure? This cannot be undone. Reset sync on this iPhone now?")
    }
}

// MARK: retry-once connector

/// A gate a fake awaits until the test opens it (non-throwing: cancellation does not open it).
final class AsyncGate: @unchecked Sendable {
    private let lock = NSLock()
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var isOpen = false
    var waiting: Int { lock.withLock { waiters.count } }
    func wait() async {
        await withCheckedContinuation { c in
            let resumeNow = lock.withLock { () -> Bool in if isOpen { return true }; waiters.append(c); return false }
            if resumeNow { c.resume() }
        }
    }
    func open() { let w = lock.withLock { isOpen = true; defer { waiters = [] }; return waiters }; w.forEach { $0.resume() } }
}

final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    func set() { lock.withLock { value = true } }
    var isSet: Bool { lock.withLock { value } }
}

/// Low-level socket fake: each dial pops the next scripted outcome.
final class ScriptedDialer: LanDialer, @unchecked Sendable {
    enum Step { case refuse, dropBeforeReply, answer }
    private let lock = NSLock()
    private var script: [Step]
    private(set) var dials: [LanEndpoint] = []
    private(set) var sentFrames: [[UInt8]] = []
    init(_ script: [Step]) { self.script = script }

    final class Socket: LanSocket, @unchecked Sendable {
        let step: Step; let owner: ScriptedDialer
        init(_ step: Step, _ owner: ScriptedDialer) { self.step = step; self.owner = owner }
        func send(_ bytes: [UInt8]) async throws { owner.lock.withLock { owner.sentFrames.append(bytes) } }
        func receiveFrame() async throws -> [UInt8] {
            if step == .dropBeforeReply { throw LanSocketError("peer closed the connection") }
            return try LanTransport.encodeFrame(Array("reply".utf8))
        }
        func close() {}
    }

    private(set) var waited: [Bool] = []
    func dial(_ endpoint: LanEndpoint, waitForNetwork: Bool) async throws -> any LanSocket {
        let step: Step = lock.withLock { dials.append(endpoint); waited.append(waitForNetwork); return script.isEmpty ? .answer : script.removeFirst() }
        if step == .refuse { throw LanSocketError("connect failed: refused") }
        return Socket(step, self)
    }
}

final class PairedConnectorTests: XCTestCase {
    let endpoint = try! LanEndpoint(validating: "192.168.1.20", port: 47821)
    var peer: PinnedPeer { PinnedPeer(deviceID: "a1111111-0000-4000-8000-00000000000a", groupID: "g", signingPublic: [UInt8](repeating: 1, count: 32),
                                      exchangePublic: [UInt8](repeating: 2, count: 32), endpoint: endpoint) }

    func hello() throws -> [UInt8] { try LanTransport.encodeFrame(Array("hello".utf8)) }

    /// Refused and unanswered hellos are `LanPeerNotAnswering` (LanClient retries those with a new hello;
    /// see LGKCore `test_unanswered_request_is_retried_once_with_a_new_hello`).
    func test_refused_or_unanswered_hello_is_peer_not_answering() async throws {
        for failure in [ScriptedDialer.Step.refuse, .dropBeforeReply] {
            let dialer = ScriptedDialer([failure])
            let conn = try await PairedLanConnector(paired: peer, dialer: dialer).connect(to: peer)
            do { _ = try await conn.exchange(try hello()); XCTFail("expected a failure") } catch is LanPeerNotAnswering {}
            XCTAssertEqual(dialer.dials, [endpoint])
        }
    }

    func test_the_sealed_request_is_not_peer_not_answering() async throws {
        let dialer = ScriptedDialer([.answer])
        let conn = try await PairedLanConnector(paired: peer, dialer: dialer).connect(to: peer)
        let reply = try await conn.exchange(try hello())
        XCTAssertEqual(try LanTransport.decodeFrame(reply), Array("reply".utf8))
        _ = try await conn.exchange(Array("sealed".utf8))
        do { _ = try await conn.exchange(Array("again".utf8)); XCTFail("closed") } catch is LanSocketError {}
        XCTAssertEqual(dialer.dials.count, 1)
    }

    func test_only_the_paired_peer_at_a_lan_address() async throws {
        let dialer = ScriptedDialer([])
        let other = PinnedPeer(deviceID: "other", groupID: "g", signingPublic: peer.signingPublic, exchangePublic: peer.exchangePublic, endpoint: endpoint)
        do { _ = try await PairedLanConnector(paired: peer, dialer: dialer).connect(to: other); XCTFail() } catch is LanSocketError {}
        let noAddress = PinnedPeer(deviceID: peer.deviceID, groupID: "g", signingPublic: peer.signingPublic, exchangePublic: peer.exchangePublic, endpoint: nil)
        do { _ = try await PairedLanConnector(paired: noAddress, dialer: dialer).connect(to: noAddress); XCTFail() } catch is LanSocketError {}
        XCTAssertEqual(dialer.dials.count, 0)
    }

    func test_enroller_waits_for_network_and_sends_one_frame() async throws {
        let dialer = ScriptedDialer([.answer])
        let connected = Flag()
        let reply = try await SocketEnroller(dialer: dialer).enroll(endpoint: endpoint, request: Enrollment.requestMagic + [1, 2],
                                                                    onConnected: { connected.set() })
        XCTAssertTrue(connected.isSet)
        XCTAssertEqual(reply, Array("reply".utf8))
        XCTAssertEqual(dialer.sentFrames, [try LanTransport.encodeFrame(Enrollment.requestMagic + [1, 2])])
        XCTAssertEqual(dialer.waited, [true])
    }
}
