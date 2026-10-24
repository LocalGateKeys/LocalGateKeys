import XCTest
import UIKit
import AppShared
@testable import LocalGateKeys

@MainActor
final class SiteIconTests: XCTestCase {
    var dir: URL!
    var settings: AppSettings!

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("icons-\(UUID().uuidString)")
        let defaults = UserDefaults(suiteName: "icons-\(UUID().uuidString)")!
        settings = AppSettings(defaults: defaults)
    }

    override func tearDown() { try? FileManager.default.removeItem(at: dir) }

    static func png(side: Int) -> Data {
        UIGraphicsImageRenderer(size: CGSize(width: side, height: side), format: {
            let f = UIGraphicsImageRendererFormat(); f.scale = 1; return f
        }()).pngData { ctx in UIColor.systemBlue.setFill(); ctx.fill(CGRect(x: 0, y: 0, width: side, height: side)) }
    }

    func store(fetch: @escaping @Sendable (URL) async throws -> Data) -> SiteIconStore {
        SiteIconStore(directory: dir, settings: settings, fetch: fetch)
    }

    func waitIdle(_ s: SiteIconStore) async {
        for _ in 0..<200 where !s.isIdle { try? await Task.sleep(for: .milliseconds(10)) }
    }

    func test_icons_are_off_by_default() {
        XCTAssertFalse(settings.showWebsiteIcons)
    }

    func test_only_public_dns_names_are_eligible() {
        XCTAssertEqual(SiteIconStore.eligibleHost("GitHub.com."), "github.com")
        XCTAssertEqual(SiteIconStore.eligibleHost("accounts.google.com"), "accounts.google.com")
        for bad in ["localhost", "router.local", "nas.lan", "192.168.1.1", "10.0.0.1", "intranet", "printer.home.arpa",
                    "bank.example", "x.test", "[::1]", "exa mple.com", "-bad.com", "a..b.com", "ex_ample.com", "münchen.de"] {
            XCTAssertNil(SiteIconStore.eligibleHost(bad), bad)
        }
    }

    func test_normalized_reencodes_and_refuses_bad_input() throws {
        let out = try XCTUnwrap(SiteIconStore.normalized(Self.png(side: 180)))
        let image = try XCTUnwrap(UIImage(data: out))
        XCTAssertLessThanOrEqual(max(image.size.width, image.size.height) * image.scale, CGFloat(SiteIconStore.pixelSize))
        XCTAssertNil(SiteIconStore.normalized(Data()))
        XCTAssertNil(SiteIconStore.normalized(Data("<html>not an icon</html>".utf8)))
        XCTAssertNil(SiteIconStore.normalized(Self.png(side: 1)), "a tracking pixel")
        XCTAssertNil(SiteIconStore.normalized(Self.png(side: 2048)), "over the source size limit")
        XCTAssertNil(SiteIconStore.normalized(Data(count: SiteIconStore.maxDownloadBytes + 1)))
    }

    func test_downloads_once_then_serves_from_memory_and_disk() async throws {
        let calls = Counter()
        let png = Self.png(side: 64)
        let s = store { url in await calls.add(url); return png }
        XCTAssertNil(s.image(for: "github.com"), "a lookup never starts a download by itself")
        s.request("github.com")
        await waitIdle(s)
        XCTAssertNotNil(s.image(for: "github.com"))
        let urls = await calls.urls
        XCTAssertEqual(urls.map(\.absoluteString), ["https://github.com/apple-touch-icon.png"])
        s.request("github.com")
        let again = store { _ in XCTFail("served from disk"); return Data() }
        again.request("github.com")
        XCTAssertNotNil(again.image(for: "github.com"))
    }

    func test_falls_back_to_favicon_then_remembers_a_failure() async {
        let calls = Counter()
        let s = store { url in await calls.add(url); throw URLError(.badServerResponse) }
        s.request("nothing.example.org")
        await waitIdle(s)
        XCTAssertNil(s.image(for: "nothing.example.org"))
        s.request("nothing.example.org")
        await waitIdle(s)
        let urls = await calls.urls
        XCTAssertEqual(urls.map(\.path), ["/apple-touch-icon.png", "/favicon.ico"], "no retry within a day")
    }

    func test_nothing_is_fetched_when_switched_off_and_switching_off_clears() async {
        settings.showWebsiteIcons = false
        let s = store { _ in XCTFail("no download while off"); return Data() }
        s.request("github.com")
        await waitIdle(s)
        XCTAssertNil(s.image(for: "github.com"))
        settings.showWebsiteIcons = true
        let png = Self.png(side: 64)
        let on = store { _ in png }
        on.request("github.com"); await waitIdle(on)
        XCTAssertNotNil(on.image(for: "github.com"))
        on.clear()
        XCTAssertNil(on.image(for: "github.com"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path))
    }

    func test_ineligible_hosts_are_never_requested() async {
        let s = store { _ in XCTFail("no download"); return Data() }
        s.request("192.168.0.10"); s.request("router.local")
        await waitIdle(s)
    }

    /// Audit 2026-10-24 L-8: a public name that resolves to the LAN, loopback or link-local is refused.
    func test_only_public_resolved_addresses_are_fetched() {
        for v4: [UInt8] in [[0, 0, 0, 0], [10, 1, 2, 3], [127, 0, 0, 1], [100, 64, 0, 1], [169, 254, 169, 254], [172, 16, 0, 1],
                            [172, 31, 255, 255], [192, 168, 1, 1], [192, 0, 0, 1], [198, 18, 0, 1], [224, 0, 0, 1],
                            [255, 255, 255, 255], [1, 2, 3]] {
            XCTAssertFalse(SiteIconAddress.isPublic(ipv4: v4), "\(v4)")
        }
        for v4: [UInt8] in [[1, 1, 1, 1], [8, 8, 8, 8], [172, 32, 0, 1], [100, 128, 0, 1], [192, 0, 2, 1], [140, 82, 121, 4]] {
            XCTAssertTrue(SiteIconAddress.isPublic(ipv4: v4), "\(v4)")
        }
        func v6(_ prefix: [UInt8], _ tail: [UInt8] = []) -> [UInt8] { prefix + Array(repeating: 0, count: 16 - prefix.count - tail.count) + tail }
        XCTAssertFalse(SiteIconAddress.isPublic(ipv6: v6([])), "::")
        XCTAssertFalse(SiteIconAddress.isPublic(ipv6: v6([], [1])), "::1")
        XCTAssertFalse(SiteIconAddress.isPublic(ipv6: v6([0xfe, 0x80], [1])), "link-local")
        XCTAssertFalse(SiteIconAddress.isPublic(ipv6: v6([0xfd, 0x12], [1])), "unique local")
        XCTAssertFalse(SiteIconAddress.isPublic(ipv6: v6([0xff, 0x02], [1])), "multicast")
        XCTAssertFalse(SiteIconAddress.isPublic(ipv6: v6([], [0xff, 0xff, 192, 168, 1, 1])), "IPv4-mapped private")
        XCTAssertFalse(SiteIconAddress.isPublic(ipv6: v6([0x00, 0x64, 0xff, 0x9b], [10, 0, 0, 1])), "NAT64 private")
        XCTAssertTrue(SiteIconAddress.isPublic(ipv6: v6([], [0xff, 0xff, 8, 8, 8, 8])), "IPv4-mapped public")
        XCTAssertTrue(SiteIconAddress.isPublic(ipv6: v6([0x26, 0x06, 0x47, 0x00], [0x11])))
        XCTAssertFalse(SiteIconAddress.isPublic(ipv6: [1, 2]))
        XCTAssertFalse(SiteIconAddress.resolvesToPublicOnly("localhost"))
    }

    func test_icon_host_is_the_login_site_and_none_for_cards() throws {
        XCTAssertEqual(try XCTUnwrap(VaultItem.items(from: snapshot([webLogin])).first).iconHost, "accounts.example.com")
        XCTAssertNil(try XCTUnwrap(VaultItem.items(from: snapshot([validCard])).first).iconHost)
    }

    func test_password_strength_estimate() {
        XCTAssertEqual(GeneratorStrength.estimate(password: "abc123"), .weak)
        XCTAssertEqual(GeneratorStrength.estimate(password: "aaaaaaaaaaaaaaaaaaaa"), .weak)
        XCTAssertEqual(GeneratorStrength.estimate(password: "password"), .weak)
        XCTAssertEqual(GeneratorStrength.estimate(password: "Tr0ub4dor&3xQ!"), .strong)
        XCTAssertEqual(GeneratorStrength.estimate(password: "k#9Vq!2mZ@x7Lp$4Rt8&wN"), .veryStrong)
    }
}

actor Counter {
    private(set) var urls: [URL] = []
    func add(_ url: URL) { urls.append(url) }
}
