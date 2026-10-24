import XCTest
import Security
import LGKCore
@testable import AppShared

final class AppKeychainVaultTests: XCTestCase {
    func test_sync_only_slots_go_to_the_app_only_group() throws {
        XCTAssertEqual(VaultSlot.appOnly, [.pairedPeer, .installID, .folderBookmark])
        let shared = InMemoryKeychainVault(), app = InMemoryKeychainVault()
        let v = AppKeychainVault(shared: shared, appOnly: app)
        for slot in VaultSlot.allCases { try v.write(slot, [1, 2]) }
        for slot in VaultSlot.allCases {
            let inApp = try app.read(slot), inShared = try shared.read(slot)
            if VaultSlot.appOnly.contains(slot) {
                XCTAssertEqual(inApp, [1, 2], "\(slot)"); XCTAssertNil(inShared, "\(slot) must not be readable by AutoFill")
            } else {
                XCTAssertEqual(inShared, [1, 2], "\(slot)"); XCTAssertNil(inApp, "\(slot)")
            }
            XCTAssertEqual(try v.read(slot), [1, 2])
        }
        try v.delete(.pairedPeer)
        XCTAssertNil(try v.read(.pairedPeer))
    }

    func test_existing_shared_items_migrate_once() throws {
        let shared = InMemoryKeychainVault(), app = InMemoryKeychainVault()
        try shared.write(.installID, Array("abc".utf8)); try shared.write(.folderBookmark, [9])
        try shared.write(.pairedPeer, [7]); try shared.write(.localKey, [5])
        let v = AppKeychainVault(shared: shared, appOnly: app)
        try v.migrate()
        XCTAssertEqual(try app.read(.installID), Array("abc".utf8))
        XCTAssertEqual(try app.read(.folderBookmark), [9]); XCTAssertEqual(try app.read(.pairedPeer), [7])
        for slot in VaultSlot.appOnly { XCTAssertNil(try shared.read(slot)) }
        XCTAssertEqual(try shared.read(.localKey), [5], "the local key stays shared for AutoFill")
        XCTAssertNil(try app.read(.localKey))
        XCTAssertEqual(try v.installID(random: SystemRandomSource()), "abc", "the install id survives the move")
        // A leftover shared copy (move interrupted after the copy) is removed and the app-only copy wins.
        try shared.write(.pairedPeer, [8])
        XCTAssertEqual(try v.read(.pairedPeer), [7]); XCTAssertNil(try shared.read(.pairedPeer))
    }

    func test_sync_keychain_is_narrow() {
        XCTAssertEqual(Set(SyncSlot.allCases.map(\.vaultSlot)), [.pairedPeer, .installID, .folderBookmark, .peerCounters])
    }

    final class FailingDeleteVault: KeychainVault, @unchecked Sendable {
        let inner = InMemoryKeychainVault()
        func read(_ slot: VaultSlot) throws -> [UInt8]? { try inner.read(slot) }
        func write(_ slot: VaultSlot, _ bytes: [UInt8]) throws { try inner.write(slot, bytes) }
        func delete(_ slot: VaultSlot) throws { throw KeychainVaultError.status(-25300 - 1) }
    }

    func test_failed_shared_cleanup_never_fails_the_app_only_operation() throws {
        let shared = FailingDeleteVault(), app = InMemoryKeychainVault()
        try shared.write(.pairedPeer, [7])
        let v = AppKeychainVault(shared: shared, appOnly: app)
        XCTAssertEqual(try v.read(.pairedPeer), [7], "migrating read succeeds")
        XCTAssertEqual(try app.read(.pairedPeer), [7])
        XCTAssertEqual(try v.read(.pairedPeer), [7], "read with a leftover shared copy succeeds")
        XCTAssertNoThrow(try v.write(.installID, [1]))
        XCTAssertNoThrow(try v.delete(.installID))
        XCTAssertNil(try app.read(.installID))
        XCTAssertNoThrow(try v.migrate())
    }

    func test_app_only_group_fallback_decision() {
        let ok: (String) throws -> Void = { _ in }
        XCTAssertNil(AppKeychainVault.appOnlyGroup(configured: nil, probe: ok))
        XCTAssertNil(AppKeychainVault.appOnlyGroup(configured: "", probe: ok))
        XCTAssertNil(AppKeychainVault.appOnlyGroup(configured: ".com.localgatekeys.app", probe: ok), "no team prefix")
        XCTAssertNil(AppKeychainVault.appOnlyGroup(configured: "$(AppIdentifierPrefix)com.localgatekeys.app", probe: ok))
        XCTAssertNil(AppKeychainVault.appOnlyGroup(configured: "ABCDE12345.com.localgatekeys.app") { _ in
            throw KeychainVaultError.status(errSecMissingEntitlement) })
        XCTAssertEqual(AppKeychainVault.appOnlyGroup(configured: "ABCDE12345.com.localgatekeys.app", probe: ok),
                       "ABCDE12345.com.localgatekeys.app")
        XCTAssertEqual(AppKeychainVault.appOnlyGroup(configured: "ABCDE12345.com.localgatekeys.app") { _ in
            throw KeychainVaultError.status(errSecInteractionNotAllowed) }, "ABCDE12345.com.localgatekeys.app",
                       "only a missing entitlement falls back")
    }

    // MARK: Safari group (audit 2026-10-24 L-8)

    func test_safari_keys_go_to_the_safari_group_and_nothing_else_does() throws {
        let base = InMemoryKeychainVault(), safari = InMemoryKeychainVault(), legacy = InMemoryKeychainVault()
        let v = SafariKeychainVault(base: base, safari: safari, legacy: legacy)
        for slot in VaultSlot.allCases { try v.write(slot, [3]) }
        for slot in VaultSlot.allCases {
            if VaultSlot.deviceUnlocked.contains(slot) {
                XCTAssertEqual(try safari.read(slot), [3], "\(slot)"); XCTAssertNil(try base.read(slot), "\(slot)")
            } else {
                XCTAssertEqual(try base.read(slot), [3], "\(slot)")
                XCTAssertNil(try safari.read(slot), "\(slot) must not be readable by the Safari extension")
            }
            XCTAssertEqual(try v.read(slot), [3])
        }
        try v.delete(.safariInboxKey)
        XCTAssertNil(try v.read(.safariInboxKey))
        XCTAssertNil(try safari.read(.safariInboxKey))
    }

    /// Keys an earlier build stored in the shared group move byte for byte (the inbox sealed under them still
    /// opens), once; a leftover shared copy is removed and the Safari-group copy wins.
    func test_existing_shared_safari_keys_migrate_once() throws {
        let base = InMemoryKeychainVault(), safari = InMemoryKeychainVault(), legacy = InMemoryKeychainVault()
        try legacy.write(.safariIndexKey, Array(repeating: 7, count: 32))
        try legacy.write(.safariInboxKey, Array(repeating: 8, count: 32))
        try legacy.write(.localKey, [5])
        let v = SafariKeychainVault(base: base, safari: safari, legacy: legacy)
        try v.migrate()
        XCTAssertEqual(try safari.read(.safariIndexKey), Array(repeating: 7, count: 32))
        XCTAssertEqual(try safari.read(.safariInboxKey), Array(repeating: 8, count: 32))
        for slot in VaultSlot.deviceUnlocked { XCTAssertNil(try legacy.read(slot)) }
        XCTAssertEqual(try legacy.read(.localKey), [5], "only the Safari keys move")
        try v.migrate()   // again: nothing to move, nothing lost
        XCTAssertEqual(try v.read(.safariInboxKey), Array(repeating: 8, count: 32))
        try legacy.write(.safariIndexKey, [1])
        XCTAssertEqual(try v.read(.safariIndexKey), Array(repeating: 7, count: 32))
        XCTAssertNil(try legacy.read(.safariIndexKey))
        // SafariKeys.ensure through the routing vault keeps the moved keys.
        try SafariKeys.ensure(keychain: v)
        XCTAssertEqual(try safari.read(.safariInboxKey), Array(repeating: 8, count: 32))
    }

    func test_failed_legacy_cleanup_never_fails_a_safari_key_operation() throws {
        let legacy = FailingDeleteVault(), safari = InMemoryKeychainVault()
        try legacy.write(.safariInboxKey, [4])
        let v = SafariKeychainVault(base: InMemoryKeychainVault(), safari: safari, legacy: legacy)
        XCTAssertEqual(try v.read(.safariInboxKey), [4])
        XCTAssertEqual(try safari.read(.safariInboxKey), [4])
        XCTAssertNoThrow(try v.write(.safariIndexKey, [1]))
        XCTAssertNoThrow(try v.delete(.safariIndexKey))
        XCTAssertNoThrow(try v.migrate())
    }

    func test_safari_group_unusable_keeps_the_base_vault() {
        let base = InMemoryKeychainVault()
        XCTAssertTrue(SafariKeys.appVault(base: base, group: nil) as AnyObject === base)
        XCTAssertNil(SafariKeys.group(configured: "$(AppIdentifierPrefix)app.localgatekeys.safari") { _ in })
        XCTAssertEqual(SafariKeys.group(configured: "ABCDE12345.app.localgatekeys.safari") { _ in },
                       "ABCDE12345.app.localgatekeys.safari")
    }
}
