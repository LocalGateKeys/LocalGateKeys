import XCTest
@testable import AppSharedMac

/// Mac profiles (docs/design/mac-profiles-2026-11-03.md): the registry, and the keys and accounts each profile uses.
final class ProfileRegistryTests: XCTestCase {
    private var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-profiles-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: root)
        ProfileScope.select(ProfileScope.defaultID)
    }

    private func registry(now: Int64 = 1_800_000_000) -> ProfileRegistry {
        ProfileRegistry(root: root, defaultName: "Personal", now: { now })
    }

    func testNoFileIsTheDefaultProfileAtTheOldPlace() {
        let r = registry()
        XCTAssertEqual(r.profiles().map(\.id), [ProfileScope.defaultID])
        XCTAssertEqual(r.active().name, "Personal")
        XCTAssertEqual(r.vaultDirectory(for: ProfileScope.defaultID), root.appendingPathComponent("Vault", isDirectory: true))
        XCTAssertFalse(FileManager.default.fileExists(atPath: r.fileURL.path), "nothing is written until a profile is added")
    }

    func testCreateOpenRenameRemove() throws {
        let r = registry()
        let work = try r.create(name: "  Work ")
        XCTAssertEqual(work.name, "Work")
        XCTAssertEqual(UUID(uuidString: work.id)?.uuidString.lowercased(), work.id)
        XCTAssertEqual(r.vaultDirectory(for: work.id).path, root.path + "/Profiles/\(work.id)/Vault")
        XCTAssertEqual(r.active().id, ProfileScope.defaultID, "a new profile is not opened by the registry")
        XCTAssertEqual(r.profiles()[1].color, ProfileRegistry.colors[1])

        try r.setActive(work.id)
        XCTAssertEqual(r.active().id, work.id)
        XCTAssertEqual(r.active().lastUsedAt, 1_800_000_000)
        try r.rename(work.id, to: "Office")
        XCTAssertEqual(registry().active().name, "Office", "read back from the file")

        try r.remove(work.id)
        XCTAssertEqual(r.profiles().map(\.id), [ProfileScope.defaultID])
        XCTAssertEqual(r.active().id, ProfileScope.defaultID, "the active one passes to another profile")
        XCTAssertThrowsError(try r.remove(ProfileScope.defaultID)) { XCTAssertEqual($0 as? ProfileRegistryError, .lastProfile) }
    }

    func testNamesAreChecked() {
        let r = registry()
        for bad in ["", "   ", String(repeating: "x", count: 41), "a\nb"] {
            XCTAssertThrowsError(try r.create(name: bad)) { XCTAssertEqual($0 as? ProfileRegistryError, .invalidName) }
        }
        XCTAssertNoThrow(try r.create(name: String(repeating: "x", count: 40)))
    }

    func testADamagedOrForgedFileFallsBackToTheDefault() throws {
        let r = registry()
        try FileManager.default.createDirectory(at: r.fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        // An id that would leave the Profiles folder is refused as a whole.
        try Data(##"{"version":1,"active":"../x","profiles":[{"id":"../x","name":"x","color":"#fff","created_at":0,"last_used_at":0}]}"##.utf8)
            .write(to: r.fileURL)
        XCTAssertEqual(r.profiles().map(\.id), [ProfileScope.defaultID])
        XCTAssertThrowsError(try r.create(name: "Work"), "a damaged list is not overwritten")
    }

    func testOnlyPerVaultKeysAndAccountsTakeTheProfilePrefix() {
        ProfileScope.select(ProfileScope.defaultID)
        XCTAssertEqual(ProfileScope.key(AppSettings.Key.touchIDUnlock), AppSettings.Key.touchIDUnlock)
        XCTAssertEqual(ProfileScope.keychainPrefix, "")

        ProfileScope.select("0b7e2c1a-0000-4000-8000-000000000001")
        XCTAssertEqual(ProfileScope.key(AppSettings.Key.touchIDUnlock), "profile.0b7e2c1a-0000-4000-8000-000000000001." + AppSettings.Key.touchIDUnlock)
        XCTAssertEqual(ProfileScope.key("recoveryCentre.lastBackupAt"), "profile.0b7e2c1a-0000-4000-8000-000000000001.recoveryCentre.lastBackupAt")
        XCTAssertEqual(ProfileScope.key(AppSettings.Key.appearance), AppSettings.Key.appearance, "app-wide settings are shared")
        XCTAssertEqual(ProfileScope.keychainPrefix, "0b7e2c1a-0000-4000-8000-000000000001/")
    }

    func testSettingsFollowTheOpenProfile() {
        let defaults = UserDefaults(suiteName: "lgk-profiles-\(UUID().uuidString)")!
        let settings = AppSettings(defaults: defaults)
        settings.touchIDUnlock = true
        settings.appearance = .dark
        ProfileScope.select("0b7e2c1a-0000-4000-8000-000000000002")
        XCTAssertFalse(settings.touchIDUnlock, "another profile starts with its own Touch ID setting")
        XCTAssertEqual(settings.appearance, .dark)
        settings.touchIDUnlock = true
        ProfileScope.select(ProfileScope.defaultID)
        settings.touchIDUnlock = false
        ProfileScope.select("0b7e2c1a-0000-4000-8000-000000000002")
        XCTAssertTrue(settings.touchIDUnlock)
    }
}
