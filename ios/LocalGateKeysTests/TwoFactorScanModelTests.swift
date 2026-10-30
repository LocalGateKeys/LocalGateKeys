import XCTest
import LGKCore
#if os(macOS)
@testable import AppSharedMac
#else
@testable import AppShared
@testable import LocalGateKeys
#endif

@MainActor
private final class ScanPurchases: ProPurchasing {
    func isEntitled() async -> Bool { false }
    func offer() async -> ProOffer { .unavailable }
    func purchase() async throws -> PurchaseOutcome { .cancelled }
    func restore() async throws -> Bool { false }
    func entitlementChanges() -> AsyncStream<Void> { AsyncStream { $0.finish() } }
}

/// The 2FA QR scan shared by the iPhone and the Mac (compiled into both test bundles): one key goes to a
/// matching login or a new one, an authenticator export becomes a checklist imported through ImportReviewModel.
@MainActor
final class TwoFactorScanModelTests: XCTestCase {
    private var dir: URL!
    private var store: LocalStore!
    private let alpha = Array("0123456789".utf8)            // GAYTEMZUGU3DOOBZ
    private let beta = Array("abcdefghijklmnopqrst".utf8)   // MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U
    private let key = "otpauth://totp/GitHub:octo%40example.com?secret=GAYTEMZUGU3DOOBZ&issuer=GitHub"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-scan-\(UUID().uuidString)", isDirectory: true)
        store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        store.limitHints = nil
    }

    override func tearDown() async throws { try? FileManager.default.removeItem(at: dir) }

    private func pro(_ on: Bool = true) -> ProModel { ProModel(purchases: ScanPurchases(), purchased: on) }

    private func model(pro on: Bool = true) -> TwoFactorScanModel {
        TwoFactorScanModel(store: store, pro: pro(on), background: NoBackgroundTasks())
    }

    @discardableResult
    private func addLogin(_ title: String, _ origin: String, _ user: String, password: String = "pw-1", totp: String? = nil) throws -> String {
        let m = EditorModel(store: store, pro: pro(), editing: nil, kind: .web, clock: SystemClock(),
                            random: SystemRandomSource(), background: NoBackgroundTasks())
        m.set("label", title); m.set("origin", origin); m.set("username", user); m.set("password", password)
        if let totp { m.set("totp", totp) }
        XCTAssertEqual(m.save(), .saved)
        return try XCTUnwrap(m.savedID)
    }

    private func items() throws -> [VaultItem] { VaultItem.items(from: try store.load()) }

    private func entry(_ secret: [UInt8], _ name: String, _ issuer: String) -> OTPMigration.Entry {
        OTPMigration.Entry(secret: secret, name: name, issuer: issuer)
    }

    // MARK: one key

    func testSingleKeyWithAMatchingLoginOffersIt() throws {
        let id = try addLogin("GitHub", "github.com", "octo@example.com")
        try addLogin("Bank", "bank.example", "octo@example.com")
        let m = model()
        m.scanned([key])
        guard case .chooseLogin(let account, let matches) = m.step else { return XCTFail("\(m.step)") }
        XCTAssertEqual(account.issuer, "GitHub")
        XCTAssertEqual(matches.map(\.id), [id], "only the login that matches the issuer")
        XCTAssertEqual(m.addKey(to: id), .saved)
        let saved = try XCTUnwrap(items().first { $0.id == id })
        XCTAssertEqual(saved.record["totp"]?.objectValue?["secret"]?.stringValue, "GAYTEMZUGU3DOOBZ")
        XCTAssertEqual(saved.record["password"]?.stringValue, "pw-1")
        guard case .finished = m.step else { return XCTFail("\(m.step)") }
    }

    func testSingleKeyWithoutAMatchOpensANewPrefilledLogin() throws {
        try addLogin("Bank", "bank.example", "sam")
        let m = model()
        m.scanned([key])
        guard case .newLogin = m.step else { return XCTFail("\(m.step)") }
        let editor = try XCTUnwrap(m.newLoginEditor())
        XCTAssertTrue(editor.isNew)
        XCTAssertEqual(editor.value("label"), "GitHub")
        XCTAssertEqual(editor.value("username"), "octo@example.com")
        XCTAssertEqual(editor.value("totp"), key)
    }

    func testAccountOnlyMatchesWhenTheCodeHasNoIssuer() throws {
        let id = try addLogin("Forum", "forum.example", "sam")
        let m = model()
        m.scanned(["otpauth://totp/sam?secret=GAYTEMZUGU3DOOBZ"])
        guard case .chooseLogin(_, let matches) = m.step else { return XCTFail("\(m.step)") }
        XCTAssertEqual(matches.map(\.id), [id])
    }

    func testFreePlanAsksForProAndSavesNothing() throws {
        let id = try addLogin("GitHub", "github.com", "octo@example.com")
        let m = model(pro: false)
        XCTAssertTrue(m.needsPro)
        m.scanned([key])
        XCTAssertEqual(m.addKey(to: id), .needsPro)
        XCTAssertTrue(m.showUpgrade)
        XCTAssertNil(try items().first { $0.id == id }?.record["totp"]?.objectValue)
    }

    func testABadKeyShowsAnErrorWithoutTheSecret() {
        let m = model()
        m.scanned(["otpauth://totp/x?secret=ABC"])
        XCTAssertEqual(m.step, .scanning)
        XCTAssertNotNil(m.error)
        XCTAssertFalse(m.error!.contains("ABC"))
    }

    func testDecoderFailuresAreShown() {
        let m = model()
        m.failed(.noQRCode)
        XCTAssertEqual(m.error, TwoFactorQRDecoder.Failure.noQRCode.message)
    }

    // MARK: exports

    func testExportWithSeveralAccountsShowsAChecklistAllSelected() throws {
        let m = model()
        m.scanned([OTPMigration.encode([entry(alpha, "ann", "Alpha"), entry(beta, "bob", "Beta")])])
        XCTAssertEqual(m.step, .checklist)
        XCTAssertEqual(m.accounts.map(\.issuer), ["Alpha", "Beta"])
        XCTAssertEqual(m.selected, [0, 1])
    }

    func testExportWithOneAccountIsTheSingleFlow() {
        let m = model()
        m.scanned([OTPMigration.encode([entry(alpha, "ann", "Alpha")])])
        guard case .newLogin(let a) = m.step else { return XCTFail("\(m.step)") }
        XCTAssertEqual(a.issuer, "Alpha")
    }

    func testMultiPartExportAsksForTheNextCode() {
        let m = model()
        m.scanned([OTPMigration.encode([entry(alpha, "ann", "Alpha")], batchIndex: 0, batchSize: 2)])
        XCTAssertEqual(m.step, .nextPart(received: 1, total: 2))
        // The same part again changes nothing.
        m.scanned([OTPMigration.encode([entry(alpha, "ann", "Alpha")], batchIndex: 0, batchSize: 2)])
        XCTAssertEqual(m.step, .nextPart(received: 1, total: 2))
        // A plain key is not the next part.
        m.scanned([key])
        XCTAssertEqual(m.step, .nextPart(received: 1, total: 2))
        XCTAssertNotNil(m.error)
        m.scanned([OTPMigration.encode([entry(beta, "bob", "Beta")], batchIndex: 1, batchSize: 2)])
        XCTAssertEqual(m.step, .checklist)
        XCTAssertEqual(m.accounts.map(\.issuer), ["Alpha", "Beta"])
    }

    func testImportAddsKeysToMatchingLoginsAndMakesNewLoginsForTheRest() async throws {
        let gh = try addLogin("GitHub", "github.com", "octo@example.com", password: "keep-me")
        let m = model()
        m.scanned([OTPMigration.encode([entry(alpha, "octo@example.com", "GitHub"), entry(beta, "bob", "Beta"),
                                        entry(beta, "carol", "Gamma")])])
        m.selected = [0, 1]
        XCTAssertEqual(m.rows[0].target, .existing(gh), "one exact issuer+account match is the default")
        XCTAssertEqual(m.rows[1].target, .newLogin)
        XCTAssertFalse(m.canAdd, "a new login needs a website")
        m.rows[1].website = "beta.example"
        XCTAssertTrue(m.canAdd)
        let summary = await m.importSelected()
        XCTAssertNotNil(summary, m.error ?? "")
        let all = try items()
        let login = try XCTUnwrap(all.first { $0.id == gh })
        XCTAssertEqual(login.record["totp"]?.objectValue?["secret"]?.stringValue, "GAYTEMZUGU3DOOBZ")
        XCTAssertEqual(login.record["password"]?.stringValue, "keep-me")
        XCTAssertFalse(login.tags.contains(TwoFactorScanModel.needsPasswordTag))
        XCTAssertFalse(all.contains { $0.kind == "note" }, "export accounts become logins, never notes")
        let beta = try XCTUnwrap(all.first { $0.title == "Beta" })
        XCTAssertEqual(beta.kind, "web")
        XCTAssertEqual(beta.username, "bob")
        XCTAssertEqual(beta.record["scope"]?.objectValue?["origin"]?.stringValue, "https://beta.example")
        XCTAssertEqual(beta.record["totp"]?.objectValue?["secret"]?.stringValue, "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U")
        XCTAssertFalse((beta.record["password"]?.stringValue ?? "").isEmpty, "a generated password")
        XCTAssertEqual(beta.tags, [TwoFactorScanModel.needsPasswordTag])
        XCTAssertEqual(beta.record["notes"]?.stringValue,
                       "Password not set — added from a 2FA QR code. Replace this generated password with your real one.")
        XCTAssertFalse(all.contains { $0.title == "Gamma" }, "unselected accounts are left out")
        guard case .finished = m.step else { return XCTFail("\(m.step)") }
    }

    func testWebsiteIsSuggestedFromADomainIssuerButNeverFilled() {
        let m = model()
        m.scanned([OTPMigration.encode([entry(alpha, "ann", "Example.com"), entry(beta, "bob", "Beta Corp")])])
        XCTAssertEqual(m.rows[0].suggestion, "example.com")
        XCTAssertEqual(m.rows[0].website, "")
        XCTAssertNil(m.rows[1].suggestion)
    }

    func testSubstringMatchesAreOfferedButNotDefault() throws {
        let id = try addLogin("GitHub work", "github.com", "octo@example.com")
        let m = model()
        m.scanned([OTPMigration.encode([entry(alpha, "octo@example.com", "GitHub"), entry(beta, "bob", "Beta")])])
        XCTAssertEqual(m.rows[0].target, .newLogin)
        XCTAssertEqual(m.rows[0].matches.map(\.id), [id])
    }

    func testReplacingAKeyOnAnExportNeedsConfirmation() async throws {
        let gh = try addLogin("GitHub", "github.com", "octo@example.com", totp: "JBSWY3DPEHPK3PXP")
        let m = model()
        m.scanned([OTPMigration.encode([entry(alpha, "octo@example.com", "GitHub"), entry(beta, "bob", "Beta")])])
        m.selected = [0]
        XCTAssertTrue(m.rows[0].replacesKey)
        let first = await m.importSelected()
        XCTAssertNil(first)
        XCTAssertEqual(m.replaceQuestion?.isEmpty, false)
        XCTAssertEqual(try items().first { $0.id == gh }?.record["totp"]?.objectValue?["secret"]?.stringValue, "JBSWY3DPEHPK3PXP")
        m.confirmReplacements()
        let second = await m.importSelected()
        XCTAssertNotNil(second)
        XCTAssertEqual(try items().first { $0.id == gh }?.record["totp"]?.objectValue?["secret"]?.stringValue, "GAYTEMZUGU3DOOBZ")
    }

    func testReplacingAKeyOnASingleCodeNeedsConfirmation() throws {
        let gh = try addLogin("GitHub", "github.com", "octo@example.com", totp: "JBSWY3DPEHPK3PXP")
        let m = model()
        m.scanned([key])
        XCTAssertNotEqual(m.addKey(to: gh), .saved)
        XCTAssertEqual(m.confirmReplaceID, gh)
        XCTAssertEqual(try items().first { $0.id == gh }?.record["totp"]?.objectValue?["secret"]?.stringValue, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(m.addKey(to: gh, confirmed: true), .saved)
        XCTAssertEqual(try items().first { $0.id == gh }?.record["totp"]?.objectValue?["secret"]?.stringValue, "GAYTEMZUGU3DOOBZ")
    }

    func testMultiPartTotalIsCappedAt256() {
        let m = model()
        let first = (0..<200).map { entry(alpha, "a\($0)", "A") }
        let second = (0..<57).map { entry(beta, "b\($0)", "B") }
        m.scanned([OTPMigration.encode(first, batchIndex: 0, batchSize: 2)])
        XCTAssertEqual(m.step, .nextPart(received: 1, total: 2))
        m.scanned([OTPMigration.encode(second, batchIndex: 1, batchSize: 2)])
        XCTAssertEqual(m.step, .nextPart(received: 1, total: 2), "nothing is added")
        XCTAssertNotNil(m.error)
    }

    func testOnlyTheFirstOfSeveralCodesIsReadAndTheUserIsTold() {
        let m = model()
        m.scanned([key, "otpauth://totp/Beta:bob?secret=MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U&issuer=Beta"])
        guard case .newLogin(let a) = m.step else { return XCTFail("\(m.step)") }
        XCTAssertEqual(a.issuer, "GitHub")
        XCTAssertEqual(m.notice, TwoFactorScanModel.moreCodesNotice(1))
    }

    func testADecodeFinishingAfterResetIsIgnored() {
        let m = model()
        let generation = m.generation
        m.reset()
        m.scanned([key], generation: generation)
        XCTAssertEqual(m.step, .scanning)
        XCTAssertTrue(m.accounts.isEmpty)
        m.failed(.noQRCode, generation: generation)
        XCTAssertNil(m.error)
    }

    func testImportingTheSameExportTwiceAddsNothingNew() async throws {
        try addLogin("GitHub", "github.com", "octo@example.com")
        let uri = OTPMigration.encode([entry(alpha, "octo@example.com", "GitHub"), entry(beta, "bob", "Beta")])
        let first = model(); first.scanned([uri]); first.rows[1].website = "beta.example"; _ = await first.importSelected()
        let before = try items().count
        let again = model(); again.scanned([uri]); again.rows[1].website = "beta.example"; _ = await again.importSelected()
        XCTAssertEqual(try items().count, before)
    }

    func testFreePlanImportIsRefused() async throws {
        let m = model(pro: false)
        m.scanned([OTPMigration.encode([entry(alpha, "ann", "Alpha"), entry(beta, "bob", "Beta")])])
        let result = await m.importSelected()
        XCTAssertNil(result)
        XCTAssertTrue(m.showUpgrade)
        XCTAssertTrue(try items().isEmpty)
    }

    func testResetForgetsTheKeys() {
        let m = model()
        m.scanned([OTPMigration.encode([entry(alpha, "ann", "Alpha"), entry(beta, "bob", "Beta")])])
        m.reset()
        XCTAssertEqual(m.step, .scanning)
        XCTAssertTrue(m.accounts.isEmpty)
        XCTAssertNil(m.error)
    }
}

/// Begins and ends nothing (no UIKit background task in tests).
@MainActor
final class NoBackgroundTasks: BackgroundTasking {
    private var next = 0
    func begin(_ name: String, expiration: @escaping @MainActor () -> Void) -> Int { next += 1; return next }
    func end(_ token: Int) {}
}
