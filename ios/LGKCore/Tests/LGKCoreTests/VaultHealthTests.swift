import XCTest
@testable import LGKCore

final class VaultHealthTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let strong = "correct horse battery staple"

    func login(_ id: String, _ password: String, totp: Bool = true, daysOld: Double = 1) -> HealthLogin {
        HealthLogin(id: id, title: id, password: password, hasTOTP: totp,
                    updatedAt: now.addingTimeInterval(-daysOld * 86_400))
    }

    func testScoreAndLabels() {
        let empty = VaultHealth.compute([], breached: [], now: now)
        XCTAssertNil(empty.score); XCTAssertEqual(empty.label, "No logins yet"); XCTAssertEqual(empty.total, 0)

        let good = VaultHealth.compute([login("a", strong), login("b", "Tr0ub4dor&3")], breached: [], now: now)
        XCTAssertEqual(good.score, 100); XCTAssertEqual(good.label, "Good")

        // a weak, b+c reused, d breached, e,f,g fine → 3/7 = 42.857 → 43 Poor
        let mixed = [login("a", "password"), login("b", strong), login("c", strong),
                     login("d", "Tr0ub4dor&3"), login("e", "Xq7!vR2#mL9pZ"), login("f", "Gh8$kP3@wN6t"),
                     login("g", "Yt5%bJ1^cV4s")]
        let h = VaultHealth.compute(mixed, breached: ["d", "zzz"], now: now)
        XCTAssertEqual(h.weak, ["a"]); XCTAssertEqual(h.reused, ["b", "c"]); XCTAssertEqual(h.breached, ["d"])
        XCTAssertEqual(h.attention, ["a", "b", "c", "d"])
        XCTAssertEqual(h.score, 43); XCTAssertEqual(h.label, "Poor")

        let fair = VaultHealth.compute([login("a", "password"), login("b", strong)], breached: [], now: now)
        XCTAssertEqual(fair.score, 50); XCTAssertEqual(fair.label, "Fair")
    }

    func testReusedBySha256SkipsEmpty() {
        let h = VaultHealth.compute([login("a", ""), login("b", ""), login("c", strong), login("d", strong + " ")],
                                    breached: [], now: now)
        XCTAssertEqual(h.reused, [])
        XCTAssertTrue(h.weak.isSuperset(of: ["a", "b"]))
    }

    func testOldIsNotInScore() {
        let h = VaultHealth.compute([login("a", strong, totp: false, daysOld: 400), login("b", "Tr0ub4dor&3")],
                                    breached: [], now: now)
        XCTAssertEqual(h.old, ["a"]); XCTAssertEqual(h.noTwoFactor, ["a"])
        XCTAssertEqual(h.score, 100)
    }

    func testTagPriority() {
        let h = VaultHealth.compute([login("a", "password"), login("b", "password"), login("c", strong),
                                     login("d", strong)], breached: ["a"], now: now)
        XCTAssertEqual(h.tag(for: "a"), "Breached")
        XCTAssertEqual(h.tag(for: "b"), "Weak")
        XCTAssertEqual(h.tag(for: "c"), "Reused")
        XCTAssertNil(h.tag(for: "x"))
    }

    func testCacheReused() {
        let cache = StrengthCache()
        let logins = (0..<50).map { login("\($0)", strong) }
        _ = VaultHealth.compute(logins, breached: [], now: now, cache: cache)
        let start = Date()
        let h = VaultHealth.compute(logins, breached: [], now: now, cache: cache)
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.5)
        XCTAssertEqual(h.reused.count, 50)
    }
}

final class VaultHealthFixTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let strong = ["Xq7!vR2#mL9pZ", "Gh8$kP3@wN6t", "Yt5%bJ1^cV4s", "Tr0ub4dor&3", "correct horse battery staple",
                  "Pz4&dW8*qE2r", "Lm3#sK9!fA7u", "Vb6@nH1$gT5y"]

    func logins(attention: Int) -> [HealthLogin] {
        strong.enumerated().map { i, p in
            HealthLogin(id: "\(i)", title: "", password: i < attention ? "password" + String(i) : p,
                        hasTOTP: true, updatedAt: now)
        }
    }

    func testScoreRoundsHalfToEven() {
        // 5/8 = 62.5 → 62; 7/8 = 87.5 → 88 (Python round)
        XCTAssertEqual(VaultHealth.compute(logins(attention: 3), breached: [], now: now).score, 62)
        XCTAssertEqual(VaultHealth.compute(logins(attention: 1), breached: [], now: now).score, 88)
    }

    func testNilUpdatedAtIsNotOld() {
        let h = VaultHealth.compute([HealthLogin(id: "a", title: "", password: "x", hasTOTP: true, updatedAt: nil),
                                     HealthLogin(id: "b", title: "", password: "y", hasTOTP: true,
                                                 updatedAt: Date(timeIntervalSince1970: 0))],
                                    breached: [], now: now)
        XCTAssertEqual(h.old, ["b"])
    }
}
