import XCTest
@testable import AppShared

final class AppSettingsTests: XCTestCase {
    func fresh() -> UserDefaults { UserDefaults(suiteName: "settings-\(UUID().uuidString)")! }

    func test_defaults() {
        let s = AppSettings(defaults: fresh())
        XCTAssertEqual(s.autoLockDelay, .immediately)
        XCTAssertEqual(s.idleLock, .fiveMinutes)
        XCTAssertEqual(s.idleLock.seconds, 300)
        XCTAssertEqual(s.clipboardExpiry, .sixtySeconds)
        XCTAssertEqual(s.clipboardExpiry.rawValue, 60)
        XCTAssertTrue(s.concealSecretsInDetail)
        XCTAssertTrue(s.showCodesRow)
        XCTAssertTrue(s.copyCodeOnFill)
        XCTAssertTrue(s.showInQuickType)
        XCTAssertEqual(s.appearance, .system)
        XCTAssertNil(s.generatorOptionsData)
        XCTAssertFalse(s.erasePending)
    }

    func test_offer_passkeys_default_true() {
        let s = AppSettings(defaults: UserDefaults(suiteName: "pk-\(UUID().uuidString)")!)
        XCTAssertTrue(s.offerPasskeys)
        s.offerPasskeys = false
        XCTAssertFalse(AppSettings(defaults: s.defaults).offerPasskeys)
        XCTAssertTrue(AppSettings.Key.all.contains("settings.offerPasskeys"))
    }

    /// Audit 2026-10-24 M-5: opt-in. A user who never touched the switch has no stored value and gets the default.
    func test_quicktype_exact_sites_default_false_and_persisted() {
        let s = AppSettings(defaults: fresh())
        XCTAssertFalse(s.quickTypeExactSites)
        XCTAssertNil(s.defaults.object(forKey: AppSettings.Key.quickTypeExactSites), "reading never stores the default")
        s.quickTypeExactSites = true
        XCTAssertTrue(AppSettings(defaults: s.defaults).quickTypeExactSites)
        s.quickTypeExactSites = false
        XCTAssertFalse(AppSettings(defaults: s.defaults).quickTypeExactSites)
        s.quickTypeExactSites = true
        XCTAssertTrue(AppSettings(defaults: s.defaults).quickTypeExactSites)
        XCTAssertTrue(AppSettings.Key.all.contains("settings.quickTypeExactSites"))
    }

    func test_choices() {
        XCTAssertEqual(AutoLockDelay.allCases.map(\.rawValue), [0, 60, 300, 900, 3600])
        XCTAssertEqual(IdleLock.allCases.map(\.seconds), [60, 300, 900, 1800, nil])
        XCTAssertEqual(ClipboardExpiry.allCases.map(\.rawValue), [30, 60, 120, 300])
    }

    func test_round_trip_through_defaults() {
        let d = fresh()
        let s = AppSettings(defaults: d)
        s.autoLockDelay = .oneHour; s.idleLock = .never; s.clipboardExpiry = .fiveMinutes
        s.concealSecretsInDetail = false; s.showCodesRow = false; s.copyCodeOnFill = false
        s.showInQuickType = false; s.appearance = .dark; s.generatorOptionsData = Data([1, 2])
        let r = AppSettings(defaults: d)
        XCTAssertEqual(r.autoLockDelay, .oneHour); XCTAssertEqual(r.idleLock, .never)
        XCTAssertEqual(r.clipboardExpiry, .fiveMinutes)
        XCTAssertFalse(r.concealSecretsInDetail); XCTAssertFalse(r.showCodesRow)
        XCTAssertFalse(r.copyCodeOnFill); XCTAssertFalse(r.showInQuickType)
        XCTAssertEqual(r.appearance, .dark); XCTAssertEqual(r.generatorOptionsData, Data([1, 2]))
    }

    func test_reads_the_value_another_process_wrote() {
        let d = fresh()
        let s = AppSettings(defaults: d)
        AppSettings(defaults: d).copyCodeOnFill = false   // e.g. the app, read by the extension
        XCTAssertFalse(s.copyCodeOnFill)
    }

    func test_unknown_stored_values_fall_back_to_defaults() {
        let d = fresh()
        d.set(7, forKey: AppSettings.Key.autoLockDelay); d.set(-3, forKey: AppSettings.Key.idleLock)
        d.set(5, forKey: AppSettings.Key.clipboardExpiry); d.set("x", forKey: AppSettings.Key.appearance)
        let s = AppSettings(defaults: d)
        XCTAssertEqual(s.autoLockDelay, .immediately); XCTAssertEqual(s.idleLock, .fiveMinutes)
        XCTAssertEqual(s.clipboardExpiry, .sixtySeconds); XCTAssertEqual(s.appearance, .system)
    }

    /// Key names pass the UserDefaults secret scan's word list.
    func test_key_names_hold_no_flagged_words() {
        for k in AppSettings.Key.all {
            for bad in ["localgatekeys", "lgk", "vault", "secret", "password", "localkey", "groupkey", "identity", "keyring", "bookmark", "counter"] {
                XCTAssertFalse(k.lowercased().contains(bad), k)
            }
        }
    }
}
