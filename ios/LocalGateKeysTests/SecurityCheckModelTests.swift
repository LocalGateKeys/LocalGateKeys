import XCTest
import AppShared
@testable import LocalGateKeys

/// Counts requests; never answers with a match.
final class CountingBreachTransport: BreachTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    var requests: Int { lock.withLock { n } }
    func get(_ url: URL, headers: [String: String]) async throws -> Data {
        lock.withLock { n += 1 }
        return Data("0123456789012345678901234567890ABCD:3\n".utf8)
    }
}

/// UX plan workstream 2: the iPhone Security check uses the shared VaultHealth; breach checks off by default.
@MainActor
final class SecurityCheckModelTests: XCTestCase {
    private func login(_ id: String, _ password: String, totp: Bool = false, updated: Int64 = 1_790_000_000) -> JSONValue {
        var o: [String: JSONValue] = ["id": .string(id), "kind": .string("web"), "label": .string("Site \(id)"),
                                      "username": .string("u"), "password": .string(password),
                                      "scope": rec(["origin": .string("https://\(id).example.com")]),
                                      "updated_at": .int(updated)]
        if totp { o["totp"] = rec(["algorithm": .string("SHA1"), "digits": .int(6), "period": .int(30), "secret": .string("JBSWY3DPEHPK3PXP")]) }
        return .object(o)
    }

    private func settings() -> AppSettings { AppSettings(defaults: UserDefaults(suiteName: "security-\(UUID().uuidString)")!) }

    private func model(_ records: [JSONValue], settings: AppSettings) -> SecurityCheckModel {
        let m = SecurityCheckModel(store: MemoryStore(snapshot(records)), settings: settings,
                                   clock: { Date(timeIntervalSince1970: 1_800_000_000) })
        m.refresh()
        return m
    }

    func testCategoriesMatchTheSharedHealth() {
        let m = model([login("a", "password"), login("b", "Tr1cky-Orbit-Maple-7731", totp: true),
                       login("c", "Tr1cky-Orbit-Maple-7731"), login("d", "Unique-Lantern-Quartz-9921", updated: 1_700_000_000)],
                      settings: settings())
        XCTAssertEqual(m.ids(.weak), ["a"])
        XCTAssertEqual(m.ids(.reused), ["b", "c"])
        XCTAssertEqual(m.ids(.old), ["d"])
        XCTAssertEqual(m.ids(.noTwoFactor), ["a", "c", "d"])
        XCTAssertEqual(m.ids(.breached), [])
        // The same score as the Mac (VaultHealth): 4 logins, a, b and c need attention.
        XCTAssertEqual(m.score, 25)
    }

    func testDismissHidesOneItemFromOneRowAndPersists() {
        let s = settings()
        let records = [login("a", "password"), login("b", "Unique-Lantern-Quartz-9921")]
        let m = model(records, settings: s)
        m.dismiss(.noTwoFactor, id: "a")
        XCTAssertEqual(m.ids(.noTwoFactor), ["b"])
        XCTAssertEqual(m.ids(.weak), ["a"])
        XCTAssertEqual(model(records, settings: s).ids(.noTwoFactor), ["b"])
        m.restoreDismissed()
        XCTAssertEqual(m.ids(.noTwoFactor), ["a", "b"])
    }

    func testBreachChecksAreOffOnANewInstallAndSendNothing() async {
        let s = settings()
        XCTAssertFalse(s.breachCheckEnabled)
        XCTAssertTrue(s.strictOfflineMode)
        let transport = CountingBreachTransport()
        let m = model([login("a", "password")], settings: s)
        XCTAssertEqual(m.breachBlockedText, SecurityCheckModel.offlineText)
        m.checkBreaches(transport: transport, pause: .zero)
        await m.settle()
        s.strictOfflineMode = false
        XCTAssertEqual(m.breachBlockedText, SecurityCheckModel.disabledText)
        m.checkBreaches(transport: transport, pause: .zero)
        await m.settle()
        XCTAssertEqual(transport.requests, 0)
    }

    func testBreachCheckRunsOnceAllowed() async {
        let s = settings()
        s.strictOfflineMode = false
        s.breachCheckEnabled = true
        let transport = CountingBreachTransport()
        let m = model([login("a", "password"), login("b", "password")], settings: s)
        m.checkBreaches(transport: transport, pause: .zero)
        await m.settle()
        XCTAssertEqual(transport.requests, 1)   // identical passwords are requested once
        XCTAssertFalse(m.running)
    }
}
