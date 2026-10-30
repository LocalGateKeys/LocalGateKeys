import XCTest
import CryptoKit
import LGKCore
@testable import AppSharedMac

/// Answers HIBP range requests from a fixed set of breached passwords; never touches the network.
private final class FakeBreachTransport: BreachTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var _calls = 0
    let breached: [String: Int]
    let delay: Duration
    init(breached: [String: Int] = [:], delay: Duration = .zero) { self.breached = breached; self.delay = delay }
    var calls: Int { lock.withLock { _calls } }

    func get(_ url: URL, headers: [String: String]) async throws -> Data {
        lock.withLock { _calls += 1 }
        if delay > .zero { try await Task.sleep(for: delay) }
        let prefix = url.lastPathComponent
        var lines = ["0000000000000000000000000000000000A:1"]
        for (password, count) in breached {
            let hex = Insecure.SHA1.hash(data: Data(password.utf8)).map { String(format: "%02X", $0) }.joined()
            if hex.hasPrefix(prefix) { lines.append(String(hex.dropFirst(5)) + ":\(count)") }
        }
        return Data(lines.joined(separator: "\r\n").utf8)
    }
}

@MainActor
final class SecurityModelTests: XCTestCase {
    private var suite: String!
    private var settings: AppSettings!
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    override func setUp() async throws {
        suite = "lgk-security-tests-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
    }

    override func tearDown() async throws {
        UserDefaults().removePersistentDomain(forName: suite)
    }

    private func login(_ id: String, _ title: String, _ password: String, totp: Bool = true, age: TimeInterval = 0) -> HealthLogin {
        HealthLogin(id: id, title: title, password: password, hasTOTP: totp, updatedAt: now.addingTimeInterval(-age))
    }

    private func health(_ logins: [HealthLogin], breached: Set<String> = []) -> VaultHealth {
        VaultHealth.compute(logins, breached: breached, now: now, cache: StrengthCache())
    }

    private func model(_ transport: FakeBreachTransport, pause: Duration = .zero) -> SecurityModel {
        SecurityModel(settings: settings, transport: transport, appVersion: "1.0", pause: pause)
    }

    func testDefaults() {
        XCTAssertFalse(settings.breachCheckEnabled)
        XCTAssertTrue(settings.strictOfflineMode)
    }

    func testHeadlineCopy() {
        XCTAssertEqual(SecurityModel.headline(nil, issues: []), "Add logins to see how healthy your passwords are.")
        XCTAssertEqual(SecurityModel.headline(health([]), issues: []), "Add logins to see how healthy your passwords are.")
        let strong = [login("a", "Alpha", "correct horse battery staple")]
        let good = health(strong)
        XCTAssertEqual(SecurityModel.headline(good, issues: SecurityModel.issues(good, titles: ["a": "Alpha"])),
                       "Good overall. Nothing urgent to fix.")
        let weak = health([login("a", "Alpha", "password"), login("b", "Beta", "correct horse battery staple")])
        let issues = SecurityModel.issues(weak, titles: ["a": "Alpha", "b": "Beta"])
        XCTAssertEqual(SecurityModel.headline(weak, issues: issues),
                       "\(weak.label) overall. Fixing the flagged logins below would bring you to 100.")
    }

    func testIssueRowsAndNames() {
        let year: TimeInterval = 400 * 86_400
        let logins = [login("1", "Delta", "password", totp: false), login("2", "alpha", "password", totp: false),
                      login("3", "Charlie", "password"), login("4", "Bravo", "password", age: year),
                      login("5", "Echo", "correct horse battery staple")]
        let titles = Dictionary(uniqueKeysWithValues: logins.map { ($0.id, $0.title) })
        let h = health(logins, breached: ["1", "5"])
        let issues = SecurityModel.issues(h, titles: titles)
        XCTAssertEqual(issues.map(\.key), [.breached, .weak, .reused, .noTwoFactor, .old])
        XCTAssertEqual(issues[0].title, "Found in a data breach")
        XCTAssertEqual(issues[0].description, "Delta, Echo · these passwords appear in known breach lists")
        XCTAssertEqual(issues[0].actionLabel, "Change passwords")
        XCTAssertEqual(issues[1].title, "Weak passwords")
        XCTAssertEqual(issues[1].description, "alpha, Bravo, Charlie and 1 more")
        XCTAssertEqual(issues[1].actionLabel, "Review 4")
        XCTAssertEqual(issues[2].title, "Reused passwords")
        XCTAssertEqual(issues[2].description, "alpha, Bravo, Charlie and 1 more share a password with another login")
        XCTAssertEqual(issues[3].title, "Two-factor not set up")
        XCTAssertEqual(issues[3].description, "Add a one-time code to these logins where the site offers it")
        XCTAssertEqual(issues[3].actionLabel, "Set up 2FA")
        XCTAssertEqual(issues[4].title, "Not changed in over a year")
        XCTAssertEqual(issues[4].description, "Low risk; change when convenient")
        XCTAssertEqual(SecurityFilter.allCases.map(\.label), ["All", "Weak", "Reused", "No 2FA", "Old (>1 year)", "Exposed (HIBP)"])
    }

    func testScanAllText() {
        XCTAssertEqual(SecurityModel.scanAllText(unique: 1, logins: 2),
                       "Checks 1 unique password from 2 logins, one request about every 1.5 seconds (under a minute). Each request sends only a 5-character SHA-1 prefix over HTTPS. The service sees your IP address. No password, full hash, username or website is sent. You can keep using the app while it runs.")
        XCTAssertTrue(SecurityModel.scanAllText(unique: 100, logins: 120).contains("(about 2 minutes)"))
        XCTAssertTrue(SecurityModel.scanAllText(unique: 50, logins: 50).contains("(about 1 minute)"))
    }

    func testScanRefusedWhenStrictOffline() async {
        let transport = FakeBreachTransport()
        let m = model(transport)
        settings.breachCheckEnabled = true
        m.requestCheckAll([login("a", "A", "pw1")])
        XCTAssertEqual(m.refusal?.0, .strictOffline)
        XCTAssertEqual(m.refusal?.0.text, "Strict offline mode is on. Turn it off in Privacy settings to run an explicit external check.")
        XCTAssertNil(m.confirmation)
        m.requestCheckOne(login("a", "A", "pw1"))
        XCTAssertEqual(m.refusal?.0, .strictOffline)
        XCTAssertEqual(transport.calls, 0)
    }

    func testScanRefusedWhenDisabled() async {
        let transport = FakeBreachTransport(breached: ["pw1": 3201])
        let m = model(transport)
        settings.strictOfflineMode = false
        let logins = [login("a", "A", "pw1"), login("b", "B", "pw1"), login("c", "C", "pw2")]
        m.requestCheckAll(logins)
        XCTAssertEqual(m.refusal?.0, .disabled)
        XCTAssertEqual(m.refusal?.0.text, "Breach checks are off. Turning them on lets a check button send a 5-character hash prefix to HIBP. Nothing is checked automatically.")
        XCTAssertEqual(SecurityModel.turnOnAndCheck, "Turn on and check")
        XCTAssertEqual(transport.calls, 0)
        m.turnOnAndCheck()
        XCTAssertTrue(settings.breachCheckEnabled)
        XCTAssertNil(m.refusal)
        XCTAssertEqual(m.confirmation?.title, "Check every password with HIBP?")
        XCTAssertEqual(transport.calls, 0, "nothing is sent before the person confirms")
        m.confirm()
        await m.waitForScan()
        XCTAssertEqual(transport.calls, 2, "identical passwords are requested once")
        XCTAssertEqual(m.breached, ["a", "b"])
        XCTAssertEqual(m.exposure["a"], "Found in 3,201 breaches")
        XCTAssertEqual(m.exposure["c"], "Not found")
        XCTAssertEqual(m.statusText, "Checked 2 unique passwords · 2 logins exposed · 0 errors. Not found does not prove a password is safe.")
    }

    func testCheckOneAddsToBreached() async {
        let transport = FakeBreachTransport(breached: ["pw2": 1])
        let m = model(transport)
        settings.strictOfflineMode = false; settings.breachCheckEnabled = true
        m.requestCheckOne(login("c", "C", "pw2"))
        XCTAssertEqual(m.confirmation?.title, "Check selected password with HIBP?")
        m.confirm()
        await m.waitForScan()
        XCTAssertEqual(m.breached, ["c"])
    }

    private func unlockedLockModel() async -> (MacLockModel, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-sec-\(UUID().uuidString)", isDirectory: true)
        let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(),
                             clock: { [now] in now }, kdfParams: cheap)
        let lock = MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), clock: { [now] in now },
                                startTimer: false)
        await lock.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertEqual(lock.state, .unlocked)
        return (lock, dir)
    }

    func testBreachResultsClearedOnLock() async {
        let transport = FakeBreachTransport(breached: ["pw1": 5])
        let m = model(transport)
        let (lock, dir) = await unlockedLockModel()
        defer { try? FileManager.default.removeItem(at: dir) }
        m.clear(on: lock)
        settings.strictOfflineMode = false; settings.breachCheckEnabled = true
        m.requestCheckAll([login("a", "A", "pw1")])
        m.confirm()
        await m.waitForScan()
        XCTAssertEqual(m.breached, ["a"])
        XCTAssertFalse(m.exposure.isEmpty)
        lock.lock()
        XCTAssertEqual(m.breached, [])
        XCTAssertTrue(m.exposure.isEmpty)
        XCTAssertNil(m.statusText)
    }

    func testCancelScanOnLock() async {
        let transport = FakeBreachTransport(breached: ["pw1": 5, "pw2": 7])
        let m = model(transport, pause: .seconds(30))
        let (lock, dir) = await unlockedLockModel()
        defer { try? FileManager.default.removeItem(at: dir) }
        m.clear(on: lock)
        settings.strictOfflineMode = false; settings.breachCheckEnabled = true
        m.requestCheckAll([login("a", "A", "pw1"), login("b", "B", "pw2"), login("c", "C", "pw3")])
        m.confirm()
        XCTAssertTrue(m.running)
        // Let the first request go out; the scan then waits 30 s before the next one.
        for _ in 0..<200 where transport.calls == 0 { try? await Task.sleep(for: .milliseconds(5)) }
        let started = Date()
        lock.lock()
        XCTAssertFalse(m.running)
        await m.waitForScan()
        try? await Task.sleep(for: .milliseconds(50))
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
        XCTAssertEqual(transport.calls, 1)
        XCTAssertEqual(m.breached, [], "nothing found before the lock is kept")
        XCTAssertNil(m.statusText)
    }

    func testRefusedWhenLocked() async {
        let transport = FakeBreachTransport()
        var unlocked = false
        let m = SecurityModel(settings: settings, transport: transport, appVersion: "1.0", pause: .zero, isUnlocked: { unlocked })
        settings.strictOfflineMode = false; settings.breachCheckEnabled = true
        m.requestCheckAll([login("a", "A", "pw1")])
        XCTAssertNil(m.confirmation)
        m.requestCheckOne(login("a", "A", "pw1"))
        XCTAssertNil(m.confirmation)
        unlocked = true
        m.requestCheckAll([login("a", "A", "pw1")])
        XCTAssertNotNil(m.confirmation)
        unlocked = false
        m.confirm()
        XCTAssertFalse(m.running)
        await m.waitForScan()
        XCTAssertEqual(transport.calls, 0)
    }

    private func cancelsOnSettingChange(_ change: (AppSettings) -> Void) async {
        let transport = FakeBreachTransport(breached: ["pw1": 5])
        let m = model(transport, pause: .seconds(30))
        settings.strictOfflineMode = false; settings.breachCheckEnabled = true
        m.requestCheckAll([login("a", "A", "pw1"), login("b", "B", "pw2")])
        m.confirm()
        for _ in 0..<200 where transport.calls == 0 { try? await Task.sleep(for: .milliseconds(5)) }
        let started = Date()
        change(settings)
        await m.waitForScan()
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
        XCTAssertFalse(m.running)
        XCTAssertEqual(transport.calls, 1)
        XCTAssertEqual(m.breached, [])
        XCTAssertEqual(m.statusText, "Breach check cancelled.")
    }

    func testStrictOfflineOnCancelsScan() async { await cancelsOnSettingChange { $0.strictOfflineMode = true } }
    func testBreachChecksOffCancelsScan() async { await cancelsOnSettingChange { $0.breachCheckEnabled = false } }
}
