import XCTest
@testable import LGKCore

/// `tests/vectors/health/site_cases.json`: the same cases the Windows and Android tests run (see its README).
final class VaultHealthSiteCasesTests: XCTestCase {
    private struct Case: Decodable {
        struct Login: Decodable {
            let id: String
            let urls: [String]
            let hasTotp: Bool
            enum CodingKeys: String, CodingKey { case id, urls, hasTotp = "has_totp" }
        }
        let name: String
        let logins: [Login]
        let passkeyDomains: [String]
        let sites: [String: [String]]
        let expected: [String: [String]]
        enum CodingKeys: String, CodingKey { case name, logins, sites, expected, passkeyDomains = "passkey_domains" }
    }

    private func cases() throws -> [Case] {
        try JSONDecoder().decode([Case].self, from: Data(contentsOf: Vectors.shared("health/site_cases.json")))
    }

    private func health(_ c: Case, features: Bool = true) -> VaultHealth {
        let logins = c.logins.map {
            HealthLogin(id: $0.id, title: "", password: "Xk9#mQ2$vLp7!zRt", hasTOTP: $0.hasTotp, updatedAt: nil, urls: $0.urls)
        }
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        guard features else { return VaultHealth.compute(logins, breached: [], now: now) }
        let site = SiteFeatures(sites: c.sites.mapValues { Set($0) }, matcher: URLMatcher(rules: URLMatchTests.rules))
        return VaultHealth.compute(logins, breached: [], now: now, features: site, passkeyDomains: Set(c.passkeyDomains))
    }

    func test_every_case_gives_the_expected_ids() throws {
        let all = try cases()
        XCTAssertGreaterThanOrEqual(all.count, 19)
        for c in all {
            let h = health(c)
            XCTAssertEqual(h.insecure, Set(c.expected["http"] ?? []), "\(c.name) http")
            XCTAssertEqual(h.noTwoFactor, Set(c.expected["no_2fa"] ?? []), "\(c.name) no_2fa")
            XCTAssertEqual(h.passkeyAvailable, Set(c.expected["passkey"] ?? []), "\(c.name) passkey")
        }
    }

    func test_without_features_2fa_and_passkey_are_empty_but_http_still_works() throws {
        let c = try XCTUnwrap(cases().first { $0.name == "mixed_logins" })
        let h = health(c, features: false)
        XCTAssertTrue(h.noTwoFactor.isEmpty)
        XCTAssertTrue(h.passkeyAvailable.isEmpty)
        XCTAssertEqual(h.insecure, ["a"])
    }

    func test_site_features_json_loads_and_reduces_subdomains() {
        let json = Data(#"{"format":"localgatekeys-site-features","version":1,"sites":{"github.com":["passkey","totp"]}}"#.utf8)
        let f = SiteFeatures(json: json, matcher: URLMatcher(rules: URLMatchTests.rules))
        XCTAssertTrue(f.supports(host: "login.github.com", feature: "totp"))
        XCTAssertFalse(f.supports(host: "github.com.evil.test", feature: "totp"))
        XCTAssertTrue(SiteFeatures(json: Data("not json".utf8)).isEmpty)
    }
}
