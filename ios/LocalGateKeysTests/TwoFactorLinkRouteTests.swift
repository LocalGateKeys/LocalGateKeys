import XCTest
import LGKCore
@testable import AppShared
@testable import LocalGateKeys

@MainActor
private final class LinkPurchases: ProPurchasing {
    func isEntitled() async -> Bool { false }
    func offer() async -> ProOffer { .unavailable }
    func purchase() async throws -> PurchaseOutcome { .cancelled }
    func restore() async throws -> Bool { false }
    func entitlementChanges() -> AsyncStream<Void> { AsyncStream { $0.finish() } }
}

/// iPhone "Set Up Codes In" task 4: an `otpauth` / `otpauth-migration` link opened from outside goes to the scan flow
/// after the unlock (a matching login, a new login, or an export's checklist); a bad secret gets a clear message.
@MainActor
final class TwoFactorLinkRouteTests: XCTestCase {
    private var dir: URL!
    private var store: LocalStore!
    private let link = "otpauth://totp/GitHub:octo%40example.com?secret=GAYTEMZUGU3DOOBZ&issuer=GitHub"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-link-\(UUID().uuidString)", isDirectory: true)
        store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        store.limitHints = nil
    }

    override func tearDown() async throws { try? FileManager.default.removeItem(at: dir) }

    private func pro(_ on: Bool = true) -> ProModel { ProModel(purchases: LinkPurchases(), purchased: on) }

    func test_only_the_two_2fa_schemes_are_routed() throws {
        XCTAssertTrue(TwoFactorLinkRoute.isTwoFactorLink(try XCTUnwrap(URL(string: link))))
        XCTAssertTrue(TwoFactorLinkRoute.isTwoFactorLink(try XCTUnwrap(URL(string: "OTPAUTH://totp/x?secret=GAYTEMZUGU3DOOBZ"))))
        XCTAssertTrue(TwoFactorLinkRoute.isTwoFactorLink(try XCTUnwrap(URL(string: "otpauth-migration://offline?data=AA"))))
        XCTAssertFalse(TwoFactorLinkRoute.isTwoFactorLink(try XCTUnwrap(URL(string: "https://example.com/otpauth"))))
        XCTAssertFalse(TwoFactorLinkRoute.isTwoFactorLink(URL(fileURLWithPath: "/tmp/a.lgkshare")))
    }

    func test_a_delivered_link_waits_for_release_and_is_taken_once() throws {
        let route = TwoFactorLinkRoute()
        route.deliver(try XCTUnwrap(URL(string: link)))
        XCTAssertNil(route.pending, "held until the vault is unlocked and settled")
        route.vaultLocked()
        route.release()
        XCTAssertEqual(route.take(), link)
        XCTAssertNil(route.take())
        XCTAssertNil(route.pending)
    }

    func test_free_plan_gets_no_flow() {
        XCTAssertNil(TwoFactorLinkRoute.scanFlow(link, store: store, pro: pro(false)))
    }

    func test_no_matching_login_opens_a_new_login_with_the_key() throws {
        let (scan, editor) = try XCTUnwrap(TwoFactorLinkRoute.scanFlow(link, store: store, pro: pro()))
        let e = try XCTUnwrap(editor)
        XCTAssertEqual(e.value("label"), "GitHub")
        XCTAssertEqual(e.value("username"), "octo@example.com")
        XCTAssertEqual(e.value("totp"), link)
        XCTAssertNil(scan.error)
    }

    func test_a_matching_login_is_offered() throws {
        let m = EditorModel(store: store, pro: pro(), editing: nil, kind: .web, clock: SystemClock(),
                            random: SystemRandomSource(), background: NoBackgroundTasks())
        m.set("label", "GitHub"); m.set("origin", "https://github.com"); m.set("username", "octo@example.com"); m.set("password", "pw-1")
        XCTAssertEqual(m.save(), .saved)
        let (scan, editor) = try XCTUnwrap(TwoFactorLinkRoute.scanFlow(link, store: store, pro: pro()))
        XCTAssertNil(editor)
        guard case .chooseLogin(_, let matches) = scan.step else { return XCTFail("\(scan.step)") }
        XCTAssertEqual(matches.map(\.id), [m.savedID])
    }

    func test_a_bad_secret_shows_a_message_and_saves_nothing() throws {
        let (scan, editor) = try XCTUnwrap(TwoFactorLinkRoute.scanFlow("otpauth://totp/x?secret=not-base32!", store: store, pro: pro()))
        XCTAssertNil(editor)
        XCTAssertNotNil(scan.error)
        XCTAssertEqual(scan.step, .scanning)
        XCTAssertTrue(VaultItem.items(from: try store.load()).isEmpty)
    }

    func test_a_migration_link_opens_the_checklist() throws {
        let export = OTPMigration.encode([OTPMigration.Entry(secret: Array("0123456789".utf8), name: "ann", issuer: "Alpha"),
                                          OTPMigration.Entry(secret: Array("abcdefghijklmnopqrst".utf8), name: "bob", issuer: "Beta")])
        let (scan, editor) = try XCTUnwrap(TwoFactorLinkRoute.scanFlow(export, store: store, pro: pro()))
        XCTAssertNil(editor)
        XCTAssertEqual(scan.step, .checklist)
        XCTAssertEqual(scan.accounts.count, 2)
    }
}

extension TwoFactorLinkRouteTests {
    func test_a_released_link_not_taken_is_dropped_at_lock() throws {
        let route = TwoFactorLinkRoute()
        route.deliver(try XCTUnwrap(URL(string: link)))
        route.release()
        route.vaultLocked()
        XCTAssertNil(route.take())
        route.release()
        XCTAssertNil(route.pending, "nothing held any more")
    }
}
