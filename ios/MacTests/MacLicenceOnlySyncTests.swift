import XCTest
import AppKit
import LGKCore
@testable import AppSharedMac

// Plan 2026-10-29-appstore-licence Task 8: a free Mac host runs licence-only sync (desktop rule of Task 6), and the
// Mac takes no licence key or link. Uses the TEST-ONLY licence vector (never valid with production keys).
// When a free Mac listens at all (pairing, 120 s after it or after Sync now) is the scheduler's rule:
// `MacSyncSchedulerTests.testFreeMacListensOnlyInTheListenWindow`. Here the host is started directly.

private let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

private enum OnlyVector {
    static func load() throws -> (keys: [String: [UInt8]], id: String, wrapper: JSONValue) {
        let url = repo.appendingPathComponent("tests/vectors/sync/license_state.json")
        guard case .object(let o) = try CanonicalJSON.parse(Array(try Data(contentsOf: url))),
              case .string(let keyID)? = o["key_id"], case .string(let pub)? = o["public_key_b64"],
              case .string(let stateID)? = o["state_id"], let wrapper = o["wrapper"] else {
            throw XCTSkip("licence vector shape")
        }
        return ([keyID: try Base64.decodeStrict(pub)], stateID, wrapper)
    }
}

private final class OnlyStore: ItemStore, @unchecked Sendable {
    private let lock = NSLock()
    private var snap: StoreSnapshot
    init(_ s: StoreSnapshot) { snap = s }
    var snapshot: StoreSnapshot { lock.withLock { snap } }
    func load() throws -> StoreSnapshot { lock.withLock { snap } }
    func commit(_ change: StoreChange) throws {
        try lock.withLock {
            guard change.baseRevision == snap.revision else { throw LocalStoreError.stale(expected: change.baseRevision, actual: snap.revision) }
            snap = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: snap.revision + 1)
        }
    }
}

private func noteRecord(_ i: Int, title: String) -> (String, JSONValue) {
    let id = String(format: "00000000-0000-4000-8000-%012d", i)
    let r: JSONValue = .object(["id": .string(id), "kind": .string("note"), "title": .string("\(title) \(i)"), "created_at": .int(1_700_000_000),
                                "updated_at": .int(1_700_000_000 + Int64(i)), "favorite": .bool(false), "tags": .array([]),
                                "payload": .object(["body": .string("body \(i)"), "fields": .array([]), "template_id": .null])])
    let normal = try! Normalise.normalForm(ns: .item, record: r)
    return (id, Wrapper.make(ns: .item, record: normal))
}

@MainActor
private func waitUntil(_ timeout: TimeInterval = 20, _ condition: () -> Bool) async throws {
    let end = Date().addingTimeInterval(timeout)
    while !condition() {
        guard Date() < end else { throw LanListenError.cannotListen("condition not met in time") }
        try await Task.sleep(nanoseconds: 10_000_000)
    }
}

@MainActor
final class MacLicenceOnlySyncTests: XCTestCase {
    private struct Pair {
        let host: LanHost
        let macStore: OnlyStore
        let phone: SyncCoordinator
        let phoneStore: OnlyStore
        let macNote: String
        let phoneNote: String
    }

    private func liveDeps(_ keys: [String: [UInt8]]) -> (SyncDependencies, HelloCounterSource) {
        let keychain = InMemoryKeychainVault()
        var deps = SyncDependencies.live(keychain: keychain)
        let counters = HelloCounterSource(store: VaultCounterStore(vault: keychain), clock: SystemClock())
        deps.lan = LiveLanTransport(dialer: NWLanDialer(browseForPrompt: false), counters: counters,
                                    random: SystemRandomSource(), clock: SystemClock())
        deps.autoFill = NoAutoFillRefresh()
        deps.localSubnet = { nil }
        deps.licenseKeys = keys
        return (deps, counters)
    }

    /// A free Mac (licence-only host) pairs with a phone that holds a licence state and one item; the join runs
    /// the first sync over loopback.
    private func pairFreeMacWithProPhone(_ v: (keys: [String: [UInt8]], id: String, wrapper: JSONValue)) async throws -> Pair {
        let (macID, macNote) = noteRecord(1, title: "From Mac")
        let (phoneID, phoneNote) = noteRecord(2, title: "From iPhone")
        let macStore = OnlyStore(StoreSnapshot(records: [macID: macNote], meta: [:], sync: nil, revision: 1))
        let (macDeps, macCounters) = liveDeps(v.keys)
        let host = LanHost(store: macStore, deps: macDeps, counters: macCounters)
        host.licenceOnly = true
        host.allowsLoopbackForTests = true
        let started = await host.start(host: "127.0.0.1", port: 0)
        XCTAssertTrue(started, host.listenError ?? "")
        XCTAssertEqual(host.showQR(), .shown, "a free Mac shows a pairing code")
        let qr = try XCTUnwrap(host.pairing.qrText)

        let phoneStore = OnlyStore(StoreSnapshot(records: [phoneID: phoneNote, v.id: v.wrapper], meta: [:], sync: nil, revision: 1))
        let (phoneDeps, _) = liveDeps(v.keys)
        let phone = SyncCoordinator(store: phoneStore, deps: phoneDeps)
        let join = Task { await phone.joinByQR(qr) }
        try await waitUntil { host.pairing.stage == .confirm && phone.verificationCode != nil }
        let request = try XCTUnwrap(host.pairing.request)
        XCTAssertTrue(host.pairing.decide(true, deviceID: request.deviceID))
        let joined = await join.value
        XCTAssertTrue(joined, phone.actionError ?? "")
        return Pair(host: host, macStore: macStore, phone: phone, phoneStore: phoneStore, macNote: macID, phoneNote: phoneID)
    }

    func test_free_mac_host_adopts_licence() async throws {
        let v = try OnlyVector.load()
        let p = try await pairFreeMacWithProPhone(v)
        defer { p.host.shutdown() }
        XCTAssertEqual(p.macStore.snapshot.records[v.id], v.wrapper, "the licence state was taken in")
        XCTAssertNil(p.macStore.snapshot.records[p.phoneNote], "items are dropped while free, never stored")
        let pro = ProModel(purchases: NoPurchases(), licenseKeys: v.keys)
        XCTAssertFalse(pro.isPro)
        pro.update(from: p.macStore.snapshot)
        XCTAssertTrue(pro.isPro, "the window's update after the merge makes this Mac Pro")
        XCTAssertNotNil(pro.licenceKey)
        XCTAssertTrue(LicencePage.status(purchased: false, license: pro.license).hasPrefix("Pro from your synced devices"))
        XCTAssertEqual(ItemLimit.liveCount(p.macStore.snapshot), 1, "only this Mac's own item")
    }

    func test_free_mac_host_publishes_nothing() async throws {
        let v = try OnlyVector.load()
        let p = try await pairFreeMacWithProPhone(v)
        defer { p.host.shutdown() }
        XCTAssertNil(p.phoneStore.snapshot.records[p.macNote], "the free Mac answered with no states")
        await p.phone.sync(.manual)
        XCTAssertNil(p.phoneStore.snapshot.records[p.macNote])
        XCTAssertNil(p.macStore.snapshot.records[p.phoneNote])

        // Pro now (the licence it took in): the next round is a full one, both ways.
        p.host.licenceOnly = false
        await p.phone.sync(.manual)
        XCTAssertNotNil(p.phoneStore.snapshot.records[p.macNote])
        XCTAssertNotNil(p.macStore.snapshot.records[p.phoneNote])
    }

    func test_licence_page_has_no_key_field() throws {
        let pro = ProModel(purchases: NoPurchases(), licenseKeys: [:])
        let page = LicencePage(pro: pro, clipboard: MacClipboard(pasteboard: NSPasteboard(name: .init("lgk-licence-\(UUID().uuidString)")),
                                                                 clock: SystemClock(), clearAfter: 60))
        let fields = Mirror(reflecting: page).children.compactMap(\.label)
        XCTAssertFalse(fields.contains { $0.lowercased().contains("key") }, "\(fields)")
        XCTAssertFalse(LicencePage.intro.contains("licence key"))
        XCTAssertFalse(LicencePage.intro.contains(LicenceText.pastePrefix))
        XCTAssertEqual(LicencePage.status(purchased: false, license: nil), "Free plan: up to 4 items. Upgrade to Pro to add more.")
        XCTAssertEqual(LicencePage.status(purchased: true, license: nil), "Pro, bought on the App Store. Everything is unlocked on this Mac.")
        XCTAssertEqual(LicencePage.syncedText, "Pro from your synced devices")
        XCTAssertEqual(LicencePage.alsoUnlocksWindows, "Also unlocks Windows: pair your PC")
        XCTAssertEqual(LicencePage.copyKeyLabel, "Copy key")
        // No `localgatekeys://install-licence/` link: the URL scheme is gone from the Mac app.
        let project = try String(contentsOf: repo.appendingPathComponent("ios/project.yml"), encoding: .utf8)
        XCTAssertFalse(project.contains("CFBundleURLSchemes: [localgatekeys]"))
        let plist = try String(contentsOf: repo.appendingPathComponent("ios/Mac/Info.plist"), encoding: .utf8)
        XCTAssertFalse(plist.contains("CFBundleURLSchemes"))
    }
}
