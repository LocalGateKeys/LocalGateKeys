import XCTest
import AuthenticationServices
import AppShared
@testable import LocalGateKeys

final class RecordingIdentityStore: CredentialIdentityStoring, @unchecked Sendable {
    private(set) var removedAll = 0
    var fail = false
    var enabled = true
    /// Thrown by `removeAll` instead of `Failed` when set.
    var error: (any Error)?
    struct Failed: Error {}
    func isEnabled() async -> Bool { enabled }
    func replace(_ identities: [IdentityEntry]) async throws {}
    func removeAll() async throws {
        removedAll += 1
        if let error { throw error }
        if fail { throw Failed() }
    }
}

/// Counts how often the eraser asked for a later AutoFill identity removal.
final class RetryCounter: @unchecked Sendable {
    private(set) var count = 0
    func bump() { count += 1 }
}

/// Deletes fail for the slots in `failing` until it is cleared.
final class FlakyKeychain: KeychainVault, @unchecked Sendable {
    let inner = InMemoryKeychainVault()
    var failing: Set<VaultSlot> = []
    /// When set, failing deletes throw this Keychain status instead of `Failed`.
    var failStatus: OSStatus?
    /// What the follow-up existence check reports for a slot whose delete failed.
    var presence: [VaultSlot: KeychainItemPresence] = [:]
    struct Failed: Error {}
    func read(_ slot: VaultSlot) throws -> [UInt8]? { try inner.read(slot) }
    func write(_ slot: VaultSlot, _ bytes: [UInt8]) throws { try inner.write(slot, bytes) }
    func delete(_ slot: VaultSlot) throws {
        if failing.contains(slot) { if let failStatus { throw KeychainVaultError.status(failStatus) }; throw Failed() }
        try inner.delete(slot)
    }
}

extension FlakyKeychain: KeychainPresenceChecking {
    func presence(_ slot: VaultSlot) -> KeychainItemPresence { presence[slot] ?? .unknown }
}

@MainActor
final class VaultEraserTests: XCTestCase {
    func test_erase_removes_store_keychain_slots_and_identities() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("erase-\(UUID().uuidString)/Vault")
        let vault = InMemoryKeychainVault()
        let store = try LocalStore.bootstrap(directory: dir, vault: vault)
        try store.commit(StoreChange(baseRevision: try store.load().revision, records: [:], meta: [:], sync: nil))
        for slot in VaultSlot.allCases where slot != .localKey { try vault.write(slot, [1, 2, 3]) }
        XCTAssertNotNil(try vault.read(.localKey))
        let ids = RecordingIdentityStore()

        try await VaultEraser(directory: { dir }, keychains: [vault], identities: ids).erase()

        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path))
        for slot in VaultSlot.allCases { XCTAssertNil(try vault.read(slot), "\(slot)") }
        XCTAssertEqual(ids.removedAll, 1)
        // First run again: a new store bootstraps with a new local key.
        let again = try LocalStore.bootstrap(directory: dir, vault: vault)
        XCTAssertTrue(try again.load().records.isEmpty)
    }

    func test_erase_removes_safari_save_files_and_keys() async throws {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("erase-\(UUID().uuidString)")
        let dir = base.appendingPathComponent("Vault")
        let safari = base.appendingPathComponent("SafariSave")
        let vault = InMemoryKeychainVault()
        _ = try LocalStore.bootstrap(directory: dir, vault: vault)
        try SafariKeys.ensure(keychain: vault)
        try SafariSaveFiles.writeAtomically([1], to: SafariSaveFiles.indexURL(in: safari))
        try SafariSaveFiles.writeAtomically([2], to: safari.appendingPathComponent("inbox/\(UUID().uuidString.lowercased()).blob"))

        try await VaultEraser(directory: { dir }, keychains: [vault], identities: RecordingIdentityStore(),
                              safariDirectory: { safari }).erase()

        XCTAssertFalse(FileManager.default.fileExists(atPath: safari.path))
        XCTAssertNil(try vault.read(.safariIndexKey))
        XCTAssertNil(try vault.read(.safariInboxKey))
        // Never created: erasing again (or with no Safari files at all) is not a failure.
        try await VaultEraser(directory: { dir }, keychains: [vault], identities: RecordingIdentityStore(),
                              safariDirectory: { safari }).erase()
        XCTAssertFalse(FileManager.default.fileExists(atPath: safari.path))
        try? FileManager.default.removeItem(at: base)
    }

    func test_undeletable_vault_directory_is_set_aside_so_the_next_unlock_starts_empty() async throws {
        let parent = FileManager.default.temporaryDirectory.appendingPathComponent("erase-\(UUID().uuidString)")
        let dir = parent.appendingPathComponent("Vault")
        defer { try? FileManager.default.removeItem(at: parent) }
        let vault = InMemoryKeychainVault()
        let store = try LocalStore.bootstrap(directory: dir, vault: vault)
        try store.commit(StoreChange(baseRevision: 0, records: [:], meta: [:], sync: nil))
        var eraser = VaultEraser(directory: { dir }, keychains: [vault], identities: RecordingIdentityStore())
        eraser.removeDirectory = { _ in throw CocoaError(.fileWriteNoPermission) }
        eraser.now = { 1_790_000_000 }

        try await eraser.erase()   // not a failure: the files are out of the way

        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path))
        let aside = parent.appendingPathComponent("Vault-unreadable-1790000000")
        XCTAssertNotNil(LocalStore.committedRevision(directory: aside), "set aside, not lost mid-erase")
        // The next unlock is a first run (no vaultWithoutKey loop), and it clears the set-aside copy.
        let fresh = try LocalStore.bootstrap(directory: dir, vault: vault)
        XCTAssertEqual(try fresh.load().revision, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: aside.path))
    }

    func test_vault_without_key_start_fresh_with_undeletable_files_unlocks_empty() async throws {
        let parent = FileManager.default.temporaryDirectory.appendingPathComponent("fresh-\(UUID().uuidString)")
        let dir = parent.appendingPathComponent("Vault")
        defer { try? FileManager.default.removeItem(at: parent) }
        let old = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        try old.commit(StoreChange(baseRevision: 0, records: [:], meta: [:], sync: nil))
        let restored = InMemoryKeychainVault()   // a restored backup: files, no key
        XCTAssertThrowsError(try LocalStore.bootstrap(directory: dir, vault: restored))
        var eraser = VaultEraser(directory: { dir }, keychains: [restored], identities: RecordingIdentityStore())
        eraser.removeDirectory = { _ in throw CocoaError(.fileWriteNoPermission) }
        try await eraser.erase()
        XCTAssertNoThrow(try LocalStore.bootstrap(directory: dir, vault: restored))
    }

    func test_erase_of_an_empty_install_succeeds() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("erase-\(UUID().uuidString)/Vault")
        try await VaultEraser(directory: { dir }, keychains: [InMemoryKeychainVault()], identities: RecordingIdentityStore()).erase()
    }

    func test_failed_steps_do_not_stop_the_others_and_a_retry_finishes() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("erase-\(UUID().uuidString)/Vault")
        let shared = FlakyKeychain(), appOnly = InMemoryKeychainVault()
        _ = try LocalStore.bootstrap(directory: dir, vault: shared)
        for slot in VaultSlot.allCases { try shared.write(slot, [1]); try appOnly.write(slot, [2]) }
        shared.failing = [.localKey]
        let ids = RecordingIdentityStore(); ids.fail = true
        let eraser = VaultEraser(directory: { dir }, keychains: [shared, appOnly], identities: ids)

        do { try await eraser.erase(); XCTFail("must report the failures") } catch let e as VaultEraseFailure {
            XCTAssertEqual(e.steps, ["local-key"], "AutoFill identities are best-effort")
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path), "later steps still ran")
        XCTAssertNotNil(try shared.read(.localKey))
        XCTAssertEqual(ids.removedAll, 1)
        for slot in VaultSlot.allCases where slot != .localKey { XCTAssertNil(try shared.read(slot)) }
        for slot in VaultSlot.allCases { XCTAssertNil(try appOnly.read(slot), "\(slot) in the app-only group") }
        XCTAssertEqual(ids.removedAll, 1)

        shared.failing = []; ids.fail = false
        try await eraser.erase()   // missing items are not errors
        XCTAssertNil(try shared.read(.localKey))
        XCTAssertEqual(ids.removedAll, 2)
    }

    func test_store_directory_failure_is_reported() async {
        let eraser = VaultEraser(directory: { throw LocalStoreError.noContainer }, keychains: [InMemoryKeychainVault()],
                                 identities: RecordingIdentityStore())
        do { try await eraser.erase(); XCTFail() } catch let e as VaultEraseFailure { XCTAssertEqual(e.steps, ["store files"]) }
        catch { XCTFail("\(error)") }
    }

    func test_wording_matches_the_two_step_style() {
        XCTAssertTrue(VaultEraser.confirmText1.hasPrefix("Erase this iPhone's vault?"))
        XCTAssertTrue(VaultEraser.confirmText2.hasPrefix("Are you sure? This cannot be undone."))
    }

    // MARK: AutoFill identities are best-effort (they hold only usernames and domains)

    func test_store_disabled_identities_do_not_fail_the_erase() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("erase-\(UUID().uuidString)/Vault")
        let ids = RecordingIdentityStore(); ids.error = ASCredentialIdentityStoreError(.storeDisabled)
        let retries = RetryCounter()
        try await VaultEraser(directory: { dir }, keychains: [InMemoryKeychainVault()], identities: ids,
                              scheduleIdentityRetry: { retries.bump() }).erase()
        XCTAssertEqual(retries.count, 0, "nothing to retry: the store is off")
    }

    func test_identities_skipped_when_autofill_is_not_enabled() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("erase-\(UUID().uuidString)/Vault")
        let ids = RecordingIdentityStore(); ids.enabled = false; ids.fail = true
        try await VaultEraser(directory: { dir }, keychains: [InMemoryKeychainVault()], identities: ids).erase()
        XCTAssertEqual(ids.removedAll, 0)
    }

    func test_other_identity_error_schedules_a_retry_and_the_erase_succeeds() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("erase-\(UUID().uuidString)/Vault")
        let ids = RecordingIdentityStore(); ids.fail = true
        let retries = RetryCounter()
        try await VaultEraser(directory: { dir }, keychains: [InMemoryKeychainVault()], identities: ids,
                              scheduleIdentityRetry: { retries.bump() }).erase()
        XCTAssertEqual(retries.count, 1)
    }

    func test_live_retry_sets_the_identity_removal_flag() {
        let settings = AppSettings(defaults: UserDefaults(suiteName: "erase-\(UUID().uuidString)")!)
        VaultEraser.live(settings: settings).scheduleIdentityRetry()
        XCTAssertTrue(settings.identityRemovalPending)
    }

    // MARK: Keychain deletes that cannot run while locked

    func test_interaction_not_allowed_with_item_gone_counts_as_deleted() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("erase-\(UUID().uuidString)/Vault")
        let kc = FlakyKeychain(); kc.failing = [.localKey]; kc.failStatus = errSecInteractionNotAllowed
        kc.presence = [.localKey: .absent]
        try await VaultEraser(directory: { dir }, keychains: [kc], identities: RecordingIdentityStore()).erase()
    }

    func test_auth_failed_with_item_gone_counts_as_deleted() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("erase-\(UUID().uuidString)/Vault")
        let kc = FlakyKeychain(); kc.failing = [.installID]; kc.failStatus = errSecAuthFailed
        kc.presence = [.installID: .absent]
        try await VaultEraser(directory: { dir }, keychains: [kc], identities: RecordingIdentityStore()).erase()
    }

    func test_interaction_not_allowed_with_item_present_or_unknown_is_a_failure() async {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("erase-\(UUID().uuidString)/Vault")
        let kc = FlakyKeychain(); kc.failing = [.localKey, .installID]; kc.failStatus = errSecInteractionNotAllowed
        kc.presence = [.localKey: .present]   // installID: unknown
        do {
            try await VaultEraser(directory: { dir }, keychains: [kc], identities: RecordingIdentityStore()).erase()
            XCTFail("must fail")
        } catch let e as VaultEraseFailure { XCTAssertEqual(e.steps, ["local-key", "install-id"]) }
        catch { XCTFail("\(error)") }
    }

    func test_other_keychain_status_is_a_failure_even_if_absent() async {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("erase-\(UUID().uuidString)/Vault")
        let kc = FlakyKeychain(); kc.failing = [.localKey]; kc.failStatus = errSecIO
        kc.presence = [.localKey: .absent]
        do {
            try await VaultEraser(directory: { dir }, keychains: [kc], identities: RecordingIdentityStore()).erase()
            XCTFail("must fail")
        } catch let e as VaultEraseFailure { XCTAssertEqual(e.steps, ["local-key"]) }
        catch { XCTFail("\(error)") }
    }

    // MARK: users already stuck recover on the next launch

    func test_stuck_flag_with_store_disabled_recovers_on_next_unlock_into_an_empty_vault() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("erase-\(UUID().uuidString)/Vault")
        let vault = InMemoryKeychainVault()
        let old = try LocalStore.bootstrap(directory: dir, vault: vault)
        try old.commit(StoreChange(baseRevision: 0, records: [:], meta: [:], sync: nil))
        XCTAssertEqual(try old.load().revision, 1)
        let oldKey = try vault.read(.localKey)
        let defaults = UserDefaults(suiteName: "stuck-\(UUID().uuidString)")!
        let settings = AppSettings(defaults: defaults)
        settings.erasePending = true   // what the old eraser left behind (storeDisabled)
        let ids = RecordingIdentityStore(); ids.error = ASCredentialIdentityStoreError(.storeDisabled)
        let unlocker = BootstrappingUnlocker(directory: dir, vault: vault)
        let clock = TestClock(1_790_000_000)
        let m = AppLockModel(unlocker: unlocker, clock: clock, scheduler: ManualScheduler(clock: clock), settings: settings,
                             clipboard: nil, eraser: VaultEraser(directory: { dir }, keychains: [vault], identities: ids))

        await m.sceneBecameActive()   // launch

        XCTAssertFalse(settings.erasePending); XCTAssertNil(m.errorMessage)
        XCTAssertEqual(m.state, .unlocked)
        let snap = try XCTUnwrap(m.store).load()
        XCTAssertEqual(snap.revision, 0); XCTAssertTrue(snap.records.isEmpty)
        XCTAssertNotEqual(try vault.read(.localKey), oldKey, "a new local key: a first run")
    }
}

/// Opens the real `LocalStore` like `SystemUnlocker`, without Face ID.
@MainActor
final class BootstrappingUnlocker: Unlocking {
    let directory: URL
    let vault: any KeychainVault
    var keychain: (any KeychainVault)? { vault }
    init(directory: URL, vault: any KeychainVault) { self.directory = directory; self.vault = vault }
    func unlock(reason: String) async throws -> any ItemStore { try LocalStore.bootstrap(directory: directory, vault: vault) }
    func lock() {}
}
