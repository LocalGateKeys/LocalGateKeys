import XCTest
import AppShared
@testable import LocalGateKeys

@MainActor
final class FakeWatchLink: WatchSending {
    var isAvailable = true
    var sent: [WatchMessage] = []
    func send(_ message: WatchMessage) { sent.append(message) }
}

/// An in-memory Keychain for the pinned-code store (tests never touch the real Keychain or app group).
final class MemoryPinKeychain: KeychainAccess, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]
    func store(_ data: Data, key: String) throws { lock.withLock { items[key] = data } }
    func load(key: String) -> Data? { lock.withLock { items[key] } }
    func delete(key: String) { lock.withLock { _ = items.removeValue(forKey: key) } }
    var isEmpty: Bool { lock.withLock { items.isEmpty } }
}

/// UX workstream 12: pins, Pro, unpin and forget on the iPhone side.
@MainActor
final class WatchCodesModelTests: XCTestCase {
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    func snapshot() -> StoreSnapshot {
        func login(_ id: String) -> JSONValue {
            Wrapper.make(ns: .entry, record: .object(["id": .string(id), "kind": .string("web"), "title": .string(id),
                                                      "totp": .object(["secret": .string(secret)])]))
        }
        return StoreSnapshot(records: ["a": login("a"), "b": login("b")], meta: [:], revision: 1)
    }

    let other = "JBSWY3DPEHPK3PXP"
    var suites: [String] = []
    /// Widget timeline reloads asked for by the model under test.
    var reloads = 0

    override func tearDown() async throws {
        for name in suites { UserDefaults().removePersistentDomain(forName: name) }
        suites = []
    }

    func suite(_ prefix: String) -> UserDefaults {
        let name = "\(prefix)-\(UUID().uuidString)"
        suites.append(name)
        return UserDefaults(suiteName: name)!
    }

    /// Logins by id: a TOTP secret, or nil for an item without 2FA.
    func vault(_ secrets: [String: String?], revision: Int64 = 1) -> StoreSnapshot {
        var records: [String: JSONValue] = [:]
        for (id, value) in secrets {
            var r: [String: JSONValue] = ["id": .string(id), "kind": .string("web"), "title": .string(id)]
            if let value { r["totp"] = .object(["secret": .string(value)]) }
            records[id] = Wrapper.make(ns: .entry, record: .object(r))
        }
        return StoreSnapshot(records: records, meta: [:], revision: revision)
    }

    func make(legacyPins: [String]? = nil, pinStore: PinnedCodeStore? = nil, keychain: MemoryPinKeychain? = nil,
              forgetOnLock: Bool = false) -> (WatchCodesModel, FakeWatchLink, PinnedCodeStore, MemoryPinKeychain) {
        let d = suite("watch")
        if let legacyPins { d.set(legacyPins, forKey: PinnedCodeStore.legacyPinsKey) }
        if forgetOnLock { d.set(true, forKey: WatchCodesModel.forgetOnLockKey) }
        let kc = keychain ?? MemoryPinKeychain()
        let store = pinStore ?? PinnedCodeStore(defaults: suite("pins"), keychain: kc)
        let link = FakeWatchLink()
        let model = WatchCodesModel(link: link, defaults: d, pinStore: store, reloadWidgets: { [weak self] in
            if let self { self.reloads += 1 }
        })
        return (model, link, store, kc)
    }

    let t59 = Date(timeIntervalSince1970: 59)

    func test_pin_sends_codes_and_unpin_removes_the_secret() {
        let (m, link, store, keychain) = make()
        XCTAssertEqual(m.toggle("a", snapshot: snapshot(), isPro: true), .pinned)
        XCTAssertEqual(m.toggle("b", snapshot: snapshot(), isPro: true), .pinned)
        guard case .replace(let two)? = link.sent.last else { return XCTFail() }
        XCTAssertEqual(two.map(\.id), ["a", "b"])
        XCTAssertEqual(m.toggle("a", snapshot: snapshot(), isPro: true), .unpinned)
        guard case .replace(let one)? = link.sent.last else { return XCTFail() }
        XCTAssertEqual(one.map(\.id), ["b"])
        XCTAssertEqual(store.codes(at: t59).map { $0.0.id }, ["b"], "the widgets lose the unpinned code too")
        XCTAssertEqual(m.toggle("b", snapshot: snapshot(), isPro: true), .unpinned)
        XCTAssertEqual(link.sent.last, .forget, "the last unpin leaves nothing on the watch")
        XCTAssertEqual(store.pinnedIDs, [])
        XCTAssertTrue(keychain.isEmpty, "no secret left for the widgets")
    }

    func test_free_plan_cannot_pin() {
        let (m, link, store, _) = make()
        XCTAssertEqual(m.toggle("a", snapshot: snapshot(), isPro: false), .needsPro)
        XCTAssertTrue(link.sent.isEmpty)
        XCTAssertTrue(m.pins.isEmpty)
        XCTAssertTrue(store.pinnedIDs.isEmpty)
    }

    func test_forget_on_lock_and_erase() {
        let (m, link, store, keychain) = make()
        m.toggle("a", snapshot: snapshot(), isPro: true)
        m.vaultLocked()
        XCTAssertEqual(link.sent.count, 1, "Forget on watch is off by default")
        XCTAssertEqual(store.codes(at: t59).count, 1, "the widgets keep the code with the setting off")
        m.forgetOnLock = true
        m.vaultLocked()
        XCTAssertEqual(link.sent.last, .forget)
        XCTAssertTrue(store.codes(at: t59).isEmpty, "Forget on lock empties the widgets' store")
        XCTAssertTrue(keychain.isEmpty)
        XCTAssertEqual(store.pinnedIDs, ["a"], "the pin stays for the next unlock")
        m.vaultErased()
        XCTAssertTrue(m.pins.isEmpty)
        XCTAssertTrue(store.pinnedIDs.isEmpty)
        XCTAssertEqual(link.sent.last, .forget)
    }

    func test_unlock_writes_the_secrets_again_without_touching_the_watch() {
        let (m, link, store, _) = make()
        m.toggle("a", snapshot: snapshot(), isPro: true)
        m.forgetOnLock = true
        m.vaultLocked()
        let sent = link.sent.count
        let vault = MemoryItemStore(snapshot())
        m.vaultUnlocked(store: vault)
        XCTAssertEqual(store.codes(at: t59).map { $0.code }, ["287082"])
        XCTAssertEqual(link.sent.count, sent)
    }

    func test_launch_in_the_locked_state_forgets_with_the_setting_on() {
        let keychain = MemoryPinKeychain()
        let store = PinnedCodeStore(defaults: suite("pins"), keychain: keychain)
        store.pinnedIDs = ["a"]
        store.replace([WatchCode(id: "a", title: "a", secret: secret)])
        // The app was killed before it processed the lock; this launch starts locked (onChange initial: true).
        let (m, _, _, _) = make(pinStore: store, keychain: keychain, forgetOnLock: true)
        m.vaultLocked()
        XCTAssertTrue(store.codes(at: t59).isEmpty)
        XCTAssertTrue(keychain.isEmpty)
    }

    func test_background_expiry_hides_codes_when_the_vault_would_lock() {
        let (m, _, store, _) = make()
        m.vaultUnlocked(store: MemoryItemStore(snapshot()))
        m.toggle("a", snapshot: snapshot(), isPro: true)
        m.didEnterBackground(lockDeadline: 100)
        XCTAssertNil(store.expiresAt, "no expiry with Forget on lock off")
        m.forgetOnLock = true
        m.didEnterBackground(lockDeadline: 100)
        XCTAssertEqual(store.codes(at: t59).count, 1)
        XCTAssertTrue(store.codes(at: Date(timeIntervalSince1970: 100)).isEmpty, "suspended or killed: still hidden")
        m.foregroundedUnlocked()
        XCTAssertNil(store.expiresAt)
        m.didEnterBackground(lockDeadline: nil)
        XCTAssertTrue(store.codes(at: t59).isEmpty, "locked already")
        m.forgetOnLock = false
        XCTAssertNil(store.expiresAt)
    }

    func test_refresh_drops_deleted_and_removed_codes_and_rewrites_changed_ones() {
        let (m, _, store, keychain) = make()
        m.vaultUnlocked(store: MemoryItemStore(snapshot()))
        m.toggle("a", snapshot: snapshot(), isPro: true)
        m.toggle("b", snapshot: snapshot(), isPro: true)
        m.refresh(snapshot: vault(["b": other], revision: 2))   // a deleted, b's secret changed
        XCTAssertEqual(m.pins, ["b"])
        XCTAssertEqual(store.pinnedIDs, ["b"])
        XCTAssertEqual(store.codes(at: t59).map { $0.0.secret }, [other])
        m.refresh(snapshot: vault(["b": nil], revision: 3))     // b's 2FA removed
        XCTAssertTrue(m.pins.isEmpty)
        XCTAssertTrue(store.codes(at: t59).isEmpty)
        XCTAssertTrue(keychain.isEmpty)
    }

    func test_refresh_ignores_older_snapshots_and_commits_after_the_lock() {
        let (m, _, store, _) = make()
        m.vaultUnlocked(store: MemoryItemStore(vault(["a": secret], revision: 5)))
        m.toggle("a", snapshot: snapshot(), isPro: true)
        m.refresh(snapshot: vault([:], revision: 4))
        XCTAssertEqual(m.pins, ["a"], "an older snapshot arriving late is ignored")
        m.vaultLocked()
        m.refresh(snapshot: vault([:], revision: 6))
        XCTAssertEqual(m.pins, ["a"], "a commit finishing after the lock changes nothing")
        XCTAssertEqual(store.codes(at: t59).count, 1)
    }

    func test_unreadable_vault_at_unlock_leaves_no_secret() {
        let (m, _, store, keychain) = make()
        m.vaultUnlocked(store: MemoryItemStore(snapshot()))
        m.toggle("a", snapshot: snapshot(), isPro: true)
        m.vaultUnlocked(store: FailingItemStore())
        XCTAssertTrue(keychain.isEmpty)
        XCTAssertEqual(store.pinnedIDs, ["a"])
    }

    func test_only_real_keychain_groups_are_used() {
        XCTAssertNil(AppGroup.usableGroup(nil))
        XCTAssertNil(AppGroup.usableGroup(""))
        XCTAssertNil(AppGroup.usableGroup(".app.localgatekeys.app.codes"), "unsigned: no team prefix")
        XCTAssertNil(AppGroup.usableGroup("$(AppIdentifierPrefix)app.localgatekeys.app.codes"))
        XCTAssertEqual(AppGroup.usableGroup("ABCDE12345.app.localgatekeys.app.codes"), "ABCDE12345.app.localgatekeys.app.codes")
    }

    func test_old_pin_list_moves_once() {
        let (m, _, store, _) = make(legacyPins: ["a", "b"])
        XCTAssertEqual(m.pins, ["a", "b"])
        XCTAssertEqual(store.pinnedIDs, ["a", "b"])
    }

    func test_every_change_to_the_widgets_store_reloads_the_widgets() {
        let (m, _, _, _) = make(forgetOnLock: true)
        XCTAssertEqual(reloads, 0)
        m.vaultUnlocked(store: MemoryItemStore(snapshot()))
        XCTAssertEqual(reloads, 1, "unlock")
        m.toggle("a", snapshot: snapshot(), isPro: true)
        XCTAssertEqual(reloads, 2, "pin")
        m.toggle("a", snapshot: snapshot(), isPro: true)
        XCTAssertEqual(reloads, 3, "unpin: the widget shows the empty state")
        m.refresh(snapshot: vault(["a": secret], revision: 2))
        XCTAssertEqual(reloads, 4, "commit or sync")
        m.didEnterBackground(lockDeadline: 100)
        XCTAssertEqual(reloads, 5, "auto-lock deadline")
        m.foregroundedUnlocked()
        XCTAssertEqual(reloads, 6)
        m.vaultLocked()
        XCTAssertEqual(reloads, 7, "forget on lock")
        m.vaultErased()
        XCTAssertEqual(reloads, 8, "erase")
        m.forgetOnLock = false
        XCTAssertEqual(reloads, 9, "the expiry is cleared")
        m.vaultUnlocked(store: FailingItemStore())
        XCTAssertEqual(reloads, 10, "unreadable vault: the secrets are gone")
    }

    /// Scan 2026-11-12 APL-I1: a duress unlock empties the watch even with "Forget on watch" off; the next real
    /// unlock sends the real pins again, and no flag about the duress unlock is stored.
    func test_duress_unlock_empties_the_watch_and_the_real_unlock_restores_it() {
        let (m, link, store, _) = make()
        m.vaultUnlocked(store: MemoryItemStore(snapshot()), isPro: true)
        m.toggle("a", snapshot: snapshot(), isPro: true)
        m.vaultLocked()
        let before = link.sent.count
        m.freezeForSecondVault()
        XCTAssertEqual(link.sent.count, before + 1)
        XCTAssertEqual(link.sent.last, .forget, "the watch shows the second vault's pins: none")
        XCTAssertEqual(store.pinnedIDs, ["a"], "the real pins are kept")
        m.frozen = false   // DuressEffects.realVaultOpened
        m.vaultUnlocked(store: MemoryItemStore(snapshot()), isPro: true)
        guard case .replace(let codes)? = link.sent.last else { return XCTFail() }
        XCTAssertEqual(codes.map(\.id), ["a"])
    }

    func test_pinned_codes_stay_visible_without_pro() {
        let (m, link, store, _) = make()
        m.toggle("a", snapshot: snapshot(), isPro: true)
        m.send(snapshot: snapshot(), isPro: false)
        XCTAssertEqual(link.sent.last, .forget, "the watch gets no secret without Pro (unchanged)")
        XCTAssertEqual(store.codes(at: t59).count, 1, "showing an already pinned code is not re-gated")
    }
}

/// A vault that only returns one snapshot.
final class MemoryItemStore: ItemStore, @unchecked Sendable {
    let snapshot: StoreSnapshot
    init(_ snapshot: StoreSnapshot) { self.snapshot = snapshot }
    func load() throws -> StoreSnapshot { snapshot }
    func commit(_ change: StoreChange) throws {}
}

/// A vault whose read fails.
final class FailingItemStore: ItemStore, @unchecked Sendable {
    struct Unreadable: Error {}
    func load() throws -> StoreSnapshot { throw Unreadable() }
    func commit(_ change: StoreChange) throws {}
}
