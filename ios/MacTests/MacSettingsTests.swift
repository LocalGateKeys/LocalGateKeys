import XCTest
import AppKit
import StoreKitTest
import LGKCore
@testable import AppSharedMac

/// Settings › Unlocking test double: records calls, accepts only `right`.
@MainActor
private final class FakePasswords: MasterPasswordService {
    var right = "correct horse"
    var hasVault = true
    var isUnlocked = true
    var touchIDAvailable = true
    var error: Error?
    private(set) var changedTo: String?
    private(set) var touchID: Bool?

    func verifyPassword(_ password: String) async throws {
        if let error { throw error }
        guard password == right else { throw MacVaultError.wrongPassword(retryAfter: nil) }
    }

    func changePassword(old: String, new: String) async throws {
        if let error { throw error }
        guard old == right else { throw MacVaultError.wrongPassword(retryAfter: nil) }
        guard new.count >= MacVault.minPasswordLength else { throw MacVaultError.passwordTooShort }
        right = new; changedTo = new
    }

    func setTouchID(_ on: Bool, password: String) async throws {
        guard password == right else { throw MacVaultError.wrongPassword(retryAfter: nil) }
        touchID = on
    }
}

private final class FixedClock: UnixClock, @unchecked Sendable { var now: Int64 = 2_000 }

@MainActor
final class MacSettingsTests: XCTestCase {
    private var suite: String!
    private var settings: AppSettings!
    private var now = Date(timeIntervalSince1970: 1_800_000_000)

    override func setUp() async throws {
        suite = "lgk-settings-tests-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
    }

    override func tearDown() async throws { UserDefaults().removePersistentDomain(forName: suite) }

    private func model(_ passwords: (any MasterPasswordService)? = FakePasswords(), pro: ProModel? = nil) -> MacSettingsModel {
        MacSettingsModel(settings: settings, pro: pro ?? ProModel(purchases: StoreKitPurchases(), licenseKeys: [:]),
                         passwords: passwords, clock: { [unowned self] in self.now })
    }

    func testAutoLockSettingAppliesToLockModel() async throws {
        let m = model()
        m.autoLock = .oneMinute
        m.lockOnSleep = false
        m.maxSession = 3600
        XCTAssertEqual(settings.idleLock, .oneMinute)
        XCTAssertEqual(settings.maxSessionSeconds, 3600)

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-settings-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(),
                             clock: { [unowned self] in self.now },
                             kdfParams: .init(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1))
        let events = FakeSystemEvents()
        let lock = MacLockModel(vault: vault, settings: settings, events: events, clock: { [unowned self] in self.now },
                                startTimer: false)
        await lock.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertEqual(lock.state, .unlocked)
        XCTAssertEqual(lock.autoLockRemaining ?? 0, 60, accuracy: 0.5)

        // Sleep no longer locks.
        events.fireSleep()
        try await Task.sleep(for: .milliseconds(50))
        XCTAssertEqual(lock.state, .unlocked)

        now += 61
        lock.tick()
        XCTAssertEqual(lock.state, .locked)
    }

    func testClipboardSettingApplies() {
        let m = model()
        XCTAssertEqual(m.clipboardExpiry, .sixtySeconds, "default shared with the iPhone")
        XCTAssertEqual(ClipboardExpiry.allCases.map(\.rawValue), [30, 60, 120, 300], "the iPhone's choices")
        m.clipboardExpiry = .thirtySeconds
        let pasteboard = NSPasteboard(name: NSPasteboard.Name("app.localgatekeys.tests.\(UUID().uuidString)"))
        defer { pasteboard.releaseGlobally() }
        let clock = FixedClock()
        let clip = MacClipboard(pasteboard: pasteboard, clock: clock, clearAfter: 60, settings: settings)
        clip.copy("hunter2-secret", concealed: true)
        XCTAssertEqual(clip.clearAfter, 30)
        XCTAssertEqual(clip.expiresAt, clock.now + 30)

        m.clipboardExpiry = .fiveMinutes
        clip.copy("again", concealed: true)
        XCTAssertEqual(clip.clearAfter, 300)
    }

    func testAppearanceOverride() {
        let m = model()
        XCTAssertEqual(m.appearance, .system)
        XCTAssertNil(Appearance.system.colorScheme)
        m.appearance = .dark
        XCTAssertEqual(settings.appearance, .dark)
        XCTAssertEqual(settings.appearance.colorScheme, .dark)
        m.appearance = .light
        XCTAssertEqual(settings.appearance.colorScheme, .light)
    }

    func testChangePasswordFromSettings() async {
        let fake = FakePasswords()
        let m = model(fake)

        var ok = await m.changePassword(current: "correct horse", new: "new password 1", confirm: "new password 2")
        XCTAssertFalse(ok)
        XCTAssertEqual(m.passwordMessage, "The new passwords don't match.")

        ok = await m.changePassword(current: "wrong", new: "new password 1", confirm: "new password 1")
        XCTAssertFalse(ok)
        XCTAssertEqual(m.passwordMessage, "That password isn't right.")

        fake.error = MacVaultError.throttled(until: now.addingTimeInterval(4))
        ok = await m.changePassword(current: "correct horse", new: "new password 1", confirm: "new password 1")
        XCTAssertFalse(ok)
        XCTAssertEqual(m.passwordMessage, "Too many attempts. Try again in 4 s.")
        fake.error = nil

        ok = await m.changePassword(current: "correct horse", new: "short", confirm: "short")
        XCTAssertFalse(ok)
        XCTAssertEqual(m.passwordMessage, "Use at least \(MacVault.minPasswordLength) characters.")

        ok = await m.changePassword(current: "correct horse", new: "new password 1", confirm: "new password 1")
        XCTAssertTrue(ok)
        XCTAssertNil(m.passwordMessage)
        XCTAssertEqual(fake.changedTo, "new password 1")

        // Touch ID asks for the (new) master password.
        ok = await m.setTouchID(true, password: "correct horse")
        XCTAssertFalse(ok)
        XCTAssertEqual(m.touchIDMessage, "That password isn't right.")
        ok = await m.setTouchID(true, password: "new password 1")
        XCTAssertTrue(ok)
        XCTAssertEqual(fake.touchID, true)

        // Locked out (no vault): nothing to change.
        let none = model(nil)
        XCTAssertFalse(none.canChangeUnlocking)
        let refused = await none.changePassword(current: "a", new: "b", confirm: "b")
        XCTAssertFalse(refused)
    }

    func testLockedSettingsRefuseLockingAndUnlocking() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-settings-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(),
                             clock: { [unowned self] in self.now },
                             kdfParams: .init(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1))
        let lock = MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), clock: { [unowned self] in self.now },
                                startTimer: false)
        await lock.create(password: "correct horse", confirm: "correct horse", touchID: false)
        let m = model(lock)
        XCTAssertTrue(m.canChangeLocking)
        XCTAssertTrue(m.canChangeUnlocking)
        lock.lock()
        XCTAssertFalse(m.isUnlocked)
        XCTAssertFalse(m.canChangeLocking)
        XCTAssertFalse(m.canChangeUnlocking)
        XCTAssertEqual(MacSettingsModel.lockedMessage, "Unlock LocalGateKeys to change settings.")
        let changed = await m.changePassword(current: "correct horse", new: "battery staple", confirm: "battery staple")
        XCTAssertFalse(changed)
        let touch = await m.setTouchID(true, password: "correct horse")
        XCTAssertFalse(touch)
        await lock.unlock(password: "correct horse")
        XCTAssertEqual(lock.state, .unlocked, "the password is unchanged")
    }

    func testAppearanceChangeIsObserved() {
        let m = model()
        final class Flag: @unchecked Sendable { var fired = false }
        let flag = Flag()
        withObservationTracking { _ = settings.appearance } onChange: { flag.fired = true }
        m.appearance = .dark
        XCTAssertTrue(flag.fired, "views reading AppSettings.appearance re-render on change")
    }

    func testMenuCopyOnlyFromFocusedList() {
        XCTAssertTrue(MainWindow.menuCopyAllowed(listShown: true, listFocused: true))
        XCTAssertFalse(MainWindow.menuCopyAllowed(listShown: true, listFocused: false))
        XCTAssertFalse(MainWindow.menuCopyAllowed(listShown: false, listFocused: true))
    }

    func testChangePasswordWithRealVaultAndTouchIDSetting() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-settings-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(),
                             clock: { [unowned self] in self.now },
                             kdfParams: .init(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1))
        let lock = MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), clock: { [unowned self] in self.now },
                                startTimer: false)
        await lock.create(password: "correct horse", confirm: "correct horse", touchID: false)
        let m = model(lock)
        let changed = await m.changePassword(current: "correct horse", new: "battery staple", confirm: "battery staple")
        XCTAssertTrue(changed)
        let on = await m.setTouchID(true, password: "battery staple")
        XCTAssertTrue(on)
        XCTAssertTrue(settings.touchIDUnlock)
        lock.lock()
        await lock.unlock(password: "battery staple")
        XCTAssertEqual(lock.state, .unlocked)
    }

    /// The purchase-to-limit chain, with StoreKit behind `ProPurchasing` (the unhosted Mac test bundle has no app
    /// bundle ID, so StoreKit returns no products there; `testStoreKitSessionPurchase` covers StoreKit itself).
    func testProPurchaseUnlocksLimit() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-pro-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        store.limitHints = nil
        try DemoData.seed(into: store, now: 1_800_000_000)
        XCTAssertGreaterThanOrEqual(try store.load().records.count, ItemLimit.freeItems)

        let purchases = SessionPurchases()
        let pro = ProModel(purchases: purchases, licenseKeys: [:])
        let m = model(pro: pro)
        var reasons: [ProReason] = []
        let editor = MacEditorSession(store: store, pro: pro, onNeedsPro: { reasons.append($0) })
        XCTAssertFalse(editor.allowsNew())
        XCTAssertEqual(reasons, [.itemLimit])
        XCTAssertEqual(MacUpgradeSheet.subtitle(.itemLimit), UpgradePrompt.itemLimitMessage)
        XCTAssertEqual(MacUpgradeSheet.subtitle(.twoFactor), UpgradePrompt.twoFactorMessage)

        await pro.loadPrice()
        XCTAssertEqual(pro.price, "€9.99")
        await m.pro.buy()
        XCTAssertTrue(pro.isPro, pro.message ?? "")
        XCTAssertTrue(editor.allowsNew())
        XCTAssertEqual(reasons, [.itemLimit])

        // Restore on another Mac with the same Apple Account.
        let other = ProModel(purchases: purchases, licenseKeys: [:])
        await other.restore()
        XCTAssertTrue(other.isPro)
    }

    /// Real StoreKit with the iPhone's configuration file. Skipped where StoreKit cannot load products (the
    /// unhosted bundle under `xcodebuild test`); runs when the tests are hosted.
    func testStoreKitSessionPurchase() async throws {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "LocalGateKeys", withExtension: "storekit"))
        let session = try SKTestSession(contentsOf: url)
        session.resetToDefaultState()
        session.disableDialogs = true
        session.clearTransactions()
        defer { session.clearTransactions() }
        let kit = StoreKitPurchases()
        guard case .available = await kit.offer() else {
            throw XCTSkip("StoreKit returns no products in an unhosted test bundle")
        }
        let pro = ProModel(purchases: kit, licenseKeys: [:])
        await pro.buy()
        XCTAssertTrue(pro.isPro, pro.message ?? "")
    }
}

/// A StoreKit test session in memory: one account's `pro_unlimited` transactions.
@MainActor
private final class SessionPurchases: ProPurchasing {
    private var owned = false
    func isEntitled() async -> Bool { owned }
    func offer() async -> ProOffer { .available(price: "€9.99") }
    func purchase() async throws -> PurchaseOutcome { owned = true; return .purchased }
    func restore() async throws -> Bool { owned }
    func entitlementChanges() -> AsyncStream<Void> { AsyncStream { $0.finish() } }
}
