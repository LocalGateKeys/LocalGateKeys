import XCTest
import LGKCore
@testable import AppSharedMac

@MainActor
private final class FakeVault: MasterPasswordService {
    var right = "correct horse"
    var throttledUntil: Date?
    private(set) var verifyCalls = 0
    private(set) var touchIDCalls = 0
    var hasVault = true
    var isUnlocked = true
    var touchIDAvailable = true
    func verifyPassword(_ password: String) async throws {
        verifyCalls += 1
        if let throttledUntil { throw MacVaultError.throttled(until: throttledUntil) }
        guard password == right else { throw MacVaultError.wrongPassword(retryAfter: nil) }
    }
    func changePassword(old: String, new: String) async throws {}
    func setTouchID(_ on: Bool, password: String) async throws { touchIDCalls += 1 }
}

@MainActor
final class StrictItemGateTests: XCTestCase {
    private func login(strict: Bool) -> VaultItem {
        var r: [String: JSONValue] = ["kind": .string("web"), "title": .string("Bank"), "username": .string("alex"),
                                      "password": .string("pw"), "notes": .string("pin 1234"),
                                      "totp": .object(["secret": .string("JBSWY3DPEHPK3PXP")])]
        if strict { r["policy"] = .object(["require_master_password": .bool(true)]) }
        return VaultItem(id: "b", record: r)!
    }

    /// Every path that releases a strict login's secrets goes through the gate with one of these actions.
    private let paths = ["Copy one-time code", "Copy password", "Show password", "Copy username", "Edit", "Show notes",
                         "Show one-time code"]

    func testOrdinaryItemsPassStraightThrough() {
        let vault = FakeVault(), gate = StrictItemGate(passwords: vault)
        for path in paths {
            var released = false
            gate.release(login(strict: false), action: path) { released = true }
            XCTAssertTrue(released, path)
            XCTAssertNil(gate.pending)
        }
        XCTAssertEqual(vault.verifyCalls, 0)
    }

    func testEveryPathAsksEveryTime() async {
        let vault = FakeVault(), gate = StrictItemGate(passwords: vault)
        for path in paths {
            for round in 1...2 {
                var released = 0
                gate.release(login(strict: true), action: path) { released += 1 }
                XCTAssertEqual(gate.pending?.action, path)
                XCTAssertEqual(released, 0, "\(path): nothing before the password")
                await gate.submit("correct horse")
                XCTAssertEqual(released, 1, "\(path) round \(round)")
                XCTAssertNil(gate.pending)
            }
        }
        XCTAssertEqual(vault.verifyCalls, paths.count * 2, "no grace period: each release asks")
    }

    func testWrongCancelledOrThrottledReleasesNothing() async {
        let vault = FakeVault(), gate = StrictItemGate(passwords: vault)
        var released = false
        gate.release(login(strict: true), action: "Copy password") { released = true }
        await gate.submit("wrong")
        XCTAssertFalse(released)
        XCTAssertNotNil(gate.pending, "the prompt stays for another try")
        XCTAssertNotNil(gate.message)
        gate.cancel()
        XCTAssertNil(gate.pending)
        await gate.submit("correct horse")
        XCTAssertFalse(released, "cancelled: nothing released")

        vault.throttledUntil = Date().addingTimeInterval(30)
        gate.release(login(strict: true), action: "Copy username") { released = true }
        await gate.submit("correct horse")
        XCTAssertFalse(released, "the throttle applies")
        XCTAssertNotNil(gate.message)
    }

    func testTouchIDNeverOffered() async {
        let vault = FakeVault(), gate = StrictItemGate(passwords: vault)
        XCTAssertFalse(gate.offersTouchID)
        var released = false
        gate.release(login(strict: true), action: "Edit") { released = true }
        await gate.submit("correct horse")
        XCTAssertTrue(released)
        XCTAssertEqual(vault.touchIDCalls, 0)
        XCTAssertTrue(StrictItemGate.isStrict(login(strict: true)))
        XCTAssertFalse(StrictItemGate.isStrict(login(strict: false)))
    }

    func testConfirmMasterPasswordRefusesWhileAnotherPromptIsOpen() async {
        let vault = FakeVault(), gate = StrictItemGate(passwords: vault)
        var first = 0, second = 0
        XCTAssertTrue(gate.confirmMasterPassword(title: "Exporting passwords", action: "Export as CSV") { first += 1 })
        let shown = gate.pending?.id
        XCTAssertFalse(gate.confirmMasterPassword(title: "Exporting passwords", action: "Export encrypted backup") { second += 1 })
        XCTAssertEqual(gate.pending?.id, shown, "the open prompt is kept, not silently replaced")
        await gate.submit("correct horse")
        XCTAssertEqual(first, 1)
        XCTAssertEqual(second, 0)
        XCTAssertTrue(gate.confirmMasterPassword(title: "Exporting passwords", action: "Export encrypted backup") { second += 1 })
    }

    // MARK: emergency access (audit 2026-11-10)

    /// Granting emergency access now and showing a recovered phrase ask for the master password: never Touch ID (the
    /// Mac's Touch ID check releases no vault key) and never the Mac's login password. No gate refuses.
    func testEmergencyOwnerCheckAsksTheMasterPassword() async {
        let refused = await OwnerCheck.confirm("Grant access now", gate: nil)
        XCTAssertFalse(refused, "no gate: refused")

        let vault = FakeVault(), gate = StrictItemGate(passwords: vault)
        let answer = Task { await OwnerCheck.confirm("Grant access now", gate: gate) }
        for _ in 0..<10_000 where gate.pending == nil { await Task.yield() }
        XCTAssertEqual(gate.pending?.level, .strict)
        XCTAssertEqual(gate.pending?.offersTouchID, false)
        XCTAssertEqual(gate.pending?.title, EmergencyAccessText.title)
        await gate.submit("wrong")
        XCTAssertNotNil(gate.pending, "a wrong password keeps the prompt")
        await gate.submit("correct horse")
        XCTAssertNil(gate.pending)
        let confirmed = await answer.value
        XCTAssertTrue(confirmed)

        let cancelled = Task { await OwnerCheck.confirm("Show recovery phrase", gate: gate) }
        for _ in 0..<10_000 where gate.pending == nil { await Task.yield() }
        gate.cancel()
        let afterCancel = await cancelled.value
        XCTAssertFalse(afterCancel)

        let dropped = Task { await OwnerCheck.confirm("Show recovery phrase", gate: gate) }
        for _ in 0..<10_000 where gate.pending == nil { await Task.yield() }
        gate.lockReset()
        let afterLock = await dropped.value
        XCTAssertFalse(afterLock, "a lock drops the prompt")
    }

    // MARK: Wi-Fi QR

    private func wifi(strict: Bool) -> VaultItem {
        var r: [String: JSONValue] = ["kind": .string("wifi"), "title": .string("Home"),
                                      "payload": .object(["ssid": .string("Home"), "password": .string("pw"), "security": .string("wpa2")])]
        if strict { r["policy"] = .object(["require_master_password": .bool(true)]) }
        return VaultItem(id: "w", record: r)!
    }

    private func detail(_ item: VaultItem) -> ItemDetailModel {
        ItemDetailModel(item: item, clipboard: MacClipboard.shared, clock: SystemClock(), concealSecrets: true)
    }

    func testWifiQRWaitsForTheGateOnStrictItems() {
        let gate = StrictItemGate(passwords: FakeVault())
        let item = wifi(strict: true), model = detail(item)
        var result: Bool?
        DetailPanel.requestWifiQR(model: model, item: item, gate: gate) { result = $0 }
        XCTAssertNotNil(gate.pending, "the master password is asked first")
        XCTAssertNil(model.wifiQRText)
        XCTAssertNil(result)
        gate.pending?.perform()
        XCTAssertEqual(result, true)
        XCTAssertNotNil(model.wifiQRText)
    }

    func testWifiQRShowsAtOnceOnOrdinaryItems() {
        let gate = StrictItemGate(passwords: FakeVault())
        let item = wifi(strict: false), model = detail(item)
        var result: Bool?
        DetailPanel.requestWifiQR(model: model, item: item, gate: gate) { result = $0 }
        XCTAssertNil(gate.pending)
        XCTAssertEqual(result, true)
        XCTAssertNotNil(model.wifiQRText)
    }
}

