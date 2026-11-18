import XCTest
import LGKCore
@testable import AppSharedMac

/// Mac profiles end to end on real lock models (in-memory Keychains, a recording eraser): switching, removing
/// (the default profile too), and the lock screen's Backup & restore with the published v2 fixture.
@MainActor
final class MacProfileSessionTests: XCTestCase {
    private static let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent()
    private static let fixture = repo.appendingPathComponent("tests/vectors/backup/v2/full.lgkfull")
    private static let backupPassword = "fixture backup password 2026"
    private static let fixtureMaster = "fixture master password 2026"
    private static let password = "correct horse battery"

    private var root: URL!
    private var suite: String!
    private var settings: AppSettings!
    /// One Keychain per profile prefix, as the real accounts are separated by their prefix.
    private var keychains: [String: InMemoryKeychainVault] = [:]
    /// (directory, Keychain prefix) of every erase.
    private final class Erases: @unchecked Sendable {
        private let lock = NSLock()
        private var list: [(URL, String)] = []
        func add(_ e: (URL, String)) { lock.withLock { list.append(e) } }
        var all: [(URL, String)] { lock.withLock { list } }
    }
    private let erases = Erases()
    private var erased: [(URL, String)] { erases.all }

    override func setUp() async throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-session-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        suite = "lgk-session-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: root)
        UserDefaults().removePersistentDomain(forName: suite)
        ProfileScope.select(ProfileScope.defaultID)
    }

    private func session() -> (MacProfileSession, ProfileRegistry) {
        let registry = ProfileRegistry(root: root, defaultName: "Personal")
        let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
        let session = MacProfileSession(registry: registry, makeLock: { [unowned self] in
            let prefix = ProfileScope.keychainPrefix
            let keychain = self.keychains[prefix] ?? InMemoryKeychainVault()
            self.keychains[prefix] = keychain
            let vault = MacVault(directory: registry.vaultDirectory(for: ProfileScope.currentID), keychain: keychain,
                                 biometric: FakeBiometricKeyStore(), kdfParams: cheap)
            return MacLockModel(vault: vault, settings: self.settings, events: FakeSystemEvents(), startTimer: false)
        }, makeEraser: { [unowned self] dir in
            let prefix = ProfileScope.keychainPrefix
            let erases = self.erases
            return MacVaultEraser(directory: dir, keychains: [self.keychains[prefix] ?? InMemoryKeychainVault()],
                                  biometric: { erases.add((dir, prefix)) })
        }, defaults: settings.defaults)
        return (session, registry)
    }

    func testProfilesKeepTheirOwnVaultsAndSettings() async throws {
        let (session, registry) = session()
        XCTAssertEqual(session.active.id, ProfileScope.defaultID)
        await session.lock.create(password: Self.password, confirm: Self.password, touchID: false)
        settings.wifiSyncOn = true
        session.lock.lock()

        XCTAssertTrue(session.create(name: "Work"))
        XCTAssertNotEqual(session.active.id, ProfileScope.defaultID)
        XCTAssertEqual(session.lock.state, .noVault, "a new profile starts on its create screen")
        XCTAssertFalse(settings.wifiSyncOn, "per-vault settings start empty")
        await session.lock.create(password: "work horse battery staple", confirm: "work horse battery staple", touchID: false)
        XCTAssertEqual(session.lock.state, .unlocked)
        XCTAssertTrue(FileManager.default.fileExists(atPath: registry.vaultDirectory(for: session.active.id).path))
        session.lock.lock()

        session.open(ProfileScope.defaultID)
        XCTAssertEqual(ProfileScope.currentID, ProfileScope.defaultID)
        XCTAssertTrue(settings.wifiSyncOn)
        await session.lock.unlock(password: "work horse battery staple")
        XCTAssertEqual(session.lock.state, .locked, "the other profile's password does not open this one")
        await session.lock.unlock(password: Self.password)
        XCTAssertEqual(session.lock.state, .unlocked)
        session.open(session.profiles[1].id)
        XCTAssertEqual(session.active.id, ProfileScope.defaultID, "never switches while a vault is open")
    }

    func testRemovingTheDefaultProfileErasesOnlyItsOwnStorage() async throws {
        let (session, registry) = session()
        XCTAssertTrue(session.create(name: "Work"))
        let work = session.active.id
        session.open(ProfileScope.defaultID)
        settings.wifiSyncOn = true
        let ok = await session.removeActive(password: "")   // no vault: nothing to confirm
        XCTAssertTrue(ok)
        XCTAssertEqual(erased.map(\.0), [registry.vaultDirectory(for: ProfileScope.defaultID)])
        XCTAssertEqual(erased.map(\.1), [""], "the default profile's unprefixed items")
        XCTAssertEqual(registry.profiles().map(\.id), [work])
        XCTAssertEqual(session.active.id, work)
        XCTAssertEqual(ProfileScope.currentID, work)
        XCTAssertNil(settings.defaults.object(forKey: AppSettings.Key.wifiSyncOn), "its settings are gone")
        let last = await session.removeActive(password: "")
        XCTAssertFalse(last)
        XCTAssertEqual(session.message, MacProfileSession.lastProfileError)
    }

    func testRemovingNeedsTheMasterPassword() async throws {
        let (session, registry) = session()
        XCTAssertTrue(session.create(name: "Work"))
        let work = session.active.id
        await session.lock.create(password: Self.password, confirm: Self.password, touchID: false)
        session.lock.lock()
        let wrong = await session.removeActive(password: "not the password")
        XCTAssertFalse(wrong)
        XCTAssertTrue(registry.profiles().contains { $0.id == work })
        XCTAssertTrue(erased.isEmpty)
        let right = await session.removeActive(password: Self.password)
        XCTAssertTrue(right)
        XCTAssertEqual(erased.map(\.1), [ProfileScope.keychainPrefix(for: work)])
        XCTAssertEqual(session.active.id, ProfileScope.defaultID)
    }

    func testRestoreOnTheCreateScreenFillsThisProfile() async throws {
        let (session, registry) = session()
        let backup = LockBackupModel(session: session, attachments: { nil })
        XCTAssertFalse(backup.intoNewProfile)
        backup.file = Self.fixture
        backup.backupPassword = Self.backupPassword
        backup.masterPassword = Self.fixtureMaster
        let ok = await backup.restore()
        XCTAssertTrue(ok, backup.message ?? "")
        XCTAssertEqual(registry.profiles().count, 1, "no new profile")
        XCTAssertEqual(session.lock.state, .unlocked)
        XCTAssertFalse(try XCTUnwrap(session.lock.store).load().records.isEmpty)
    }

    func testRestoreFromTheLockScreenMakesANewProfile() async throws {
        let (session, registry) = session()
        await session.lock.create(password: Self.password, confirm: Self.password, touchID: false)
        session.lock.lock()
        let backup = LockBackupModel(session: session, attachments: { nil })
        XCTAssertTrue(backup.intoNewProfile)
        backup.file = Self.fixture
        backup.backupPassword = Self.backupPassword
        backup.masterPassword = "wrong master password 2026"
        let refused = await backup.restore()
        XCTAssertFalse(refused)
        XCTAssertEqual(registry.profiles().count, 1, "a backup that does not open makes no profile")

        backup.masterPassword = Self.fixtureMaster
        backup.profileName = "Fixture"
        let ok = await backup.restore()
        XCTAssertTrue(ok, backup.message ?? "")
        XCTAssertEqual(registry.profiles().map(\.name), ["Personal", "Fixture"])
        XCTAssertEqual(session.active.name, "Fixture")
        XCTAssertEqual(session.lock.state, .unlocked)
        XCTAssertFalse(try XCTUnwrap(session.lock.store).load().records.isEmpty)
    }

    func testVerifyChangesNothing() async throws {
        let (session, registry) = session()
        let backup = LockBackupModel(session: session, attachments: { nil })
        backup.file = Self.fixture
        backup.backupPassword = Self.backupPassword
        backup.masterPassword = Self.fixtureMaster
        await backup.verify()
        XCTAssertEqual(backup.success, LockBackupModel.verifiedText, backup.message ?? "")
        XCTAssertEqual(session.lock.state, .noVault)
        XCTAssertEqual(registry.profiles().count, 1)
    }
}
