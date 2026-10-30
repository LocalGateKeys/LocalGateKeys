import XCTest
import LGKCore
@testable import AppSharedMac

@MainActor
private final class FreePurchases: ProPurchasing {
    func isEntitled() async -> Bool { false }
    func offer() async -> ProOffer { .unavailable }
    func purchase() async throws -> PurchaseOutcome { .cancelled }
    func restore() async throws -> Bool { false }
    func entitlementChanges() -> AsyncStream<Void> { AsyncStream { $0.finish() } }
}

/// The Mac editor: new items, edits that keep fields the form does not show, the free-plan limit, QR images.
@MainActor
final class MacEditorFlowTests: XCTestCase {
    private var dir: URL!
    private var store: LocalStore!
    private var needsPro = 0
    private var reasons: [ProReason] = []

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-mac-editor-\(UUID().uuidString)", isDirectory: true)
        store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        store.limitHints = nil
        needsPro = 0; reasons = []
    }

    override func tearDown() async throws { try? FileManager.default.removeItem(at: dir) }

    private func session() -> MacEditorSession {
        MacEditorSession(store: store, pro: ProModel(purchases: FreePurchases()), onNeedsPro: { [unowned self] in needsPro += 1; reasons.append($0) })
    }

    private func items() -> [VaultItem] {
        let list = VaultListModel(store: store)
        list.reload()
        return list.items
    }

    func testCreateLoginAppearsInList() throws {
        let s = session()
        XCTAssertTrue(s.startNew(.web))
        let m = try XCTUnwrap(s.model)
        m.set("label", "GitHub"); m.set("origin", "github.com"); m.set("username", "alex"); m.set("password", "pa55-word")
        XCTAssertTrue(s.isDirty)
        XCTAssertEqual(s.save(), .saved)
        XCTAssertNil(s.model, "the editor closes after saving")
        let item = try XCTUnwrap(items().first { $0.title == "GitHub" })
        XCTAssertEqual(s.lastSavedID, item.id)
        XCTAssertEqual(item.username, "alex")
        XCTAssertEqual(item.record["password"]?.stringValue, "pa55-word")
        XCTAssertEqual(item.record["scope"]?.objectValue?["origin"]?.stringValue, "https://github.com")
    }

    func testEditKeepsPasswordHistoryFieldUntouched() throws {
        var r = EditorModel.newRecord(kind: .web, now: 1_700_000_000, random: SystemRandomSource())
        let id = try XCTUnwrap(r["id"]?.stringValue)
        r["label"] = .string("Bank"); r["username"] = .string("sam"); r["password"] = .string("old-password")
        r["scope"] = .object(["origin": .string("https://bank.example")])
        // Within the 365 days kept (the session runs on the real clock); older rows are dropped on save.
        let monthAgo = Int64(Date().timeIntervalSince1970) - 30 * 86_400
        let history: JSONValue = .array([.object(["password": .string("older-password"), "changed_at": .int(monthAgo)])])
        let fields: JSONValue = .array([.object(["name": .string("Customer no."), "value": .string("12345"), "hidden": .bool(false)])])
        let codes: JSONValue = .array([.string("AAAA-BBBB"), .string("CCCC-DDDD")])
        r["password_history"] = history; r["custom_fields"] = fields; r["recovery_codes"] = codes
        let record = try Normalise.normalForm(ns: .entry, record: .object(r))
        let before = try XCTUnwrap(record.objectValue)
        try store.commit(StoreChange(baseRevision: 0, records: [id: Wrapper.make(ns: .entry, record: record)], meta: [:], sync: nil))

        let s = session()
        s.startEdit(try XCTUnwrap(items().first { $0.id == id }))
        XCTAssertFalse(s.isDirty)
        s.model?.set("password", "new-password")
        XCTAssertTrue(s.isDirty)
        XCTAssertEqual(s.save(), .saved)

        let after = try XCTUnwrap(items().first { $0.id == id }).record
        XCTAssertEqual(after["password"]?.stringValue, "new-password")
        for key in ["custom_fields", "recovery_codes"] {
            XCTAssertEqual(after[key], before[key], "\(key) round-trips untouched")
        }
        // The replaced password goes first in the history (vault.py); the older row is kept after it.
        let rows = try XCTUnwrap(after["password_history"]?.arrayValue)
        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows.first?.objectValue?["password"]?.stringValue, "old-password")
        XCTAssertEqual(rows.last, before["password_history"]?.arrayValue?.first)
    }

    func testFifthItemOnFreePlanShowsUpgrade() throws {
        let s = session()
        for n in 1...4 {
            XCTAssertTrue(s.startNew(.note))
            s.model?.set("title", "Note \(n)")
            XCTAssertEqual(s.save(), .saved)
        }
        XCTAssertEqual(needsPro, 0)
        XCTAssertFalse(s.startNew(.note), "a fifth item is refused on the free plan")
        XCTAssertNil(s.model)
        XCTAssertEqual(needsPro, 1)
        XCTAssertEqual(reasons, [.itemLimit])
        XCTAssertEqual(items().count, 4)
    }

    func testQRImageDecodesOtpauth() throws {
        let uri = "otpauth://totp/Example:alex@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "totp-qr", withExtension: "png"))
        XCTAssertEqual(QRImageDecoder.otpauth(in: url), uri)

        let s = session()
        XCTAssertTrue(s.startNew(.web))
        s.importQR(from: url)
        XCTAssertNil(s.qrMessage)
        XCTAssertEqual(s.model?.value("totp"), uri)
    }

    func testExportQRWithOneAccountFillsTheFieldAndSeveralPointToTheScan() throws {
        let s = session()
        XCTAssertTrue(s.startNew(.web))
        let m = try XCTUnwrap(s.model)
        let one = OTPMigration.encode([OTPMigration.Entry(secret: Array("0123456789".utf8), name: "ann", issuer: "Alpha")])
        m.scanTOTP(one)
        XCTAssertNil(m.totpError)
        XCTAssertEqual(try TOTP.parseOtpauthURI(m.value("totp")).secret, "GAYTEMZUGU3DOOBZ")
        let two = OTPMigration.encode([OTPMigration.Entry(secret: Array("0123456789".utf8), name: "ann", issuer: "Alpha"),
                                       OTPMigration.Entry(secret: Array("abcdefghijklmnopqrst".utf8), name: "bob", issuer: "Beta")])
        m.set("totp", "")
        m.scanTOTP(two)
        XCTAssertEqual(m.totpError, EditorModel.migrationQRMessage)
        XCTAssertEqual(m.value("totp"), "")
    }

    func testTwoFactorOnFreePlanAsksForPro() throws {
        let s = session()
        XCTAssertTrue(s.startNew(.web))
        let m = try XCTUnwrap(s.model)
        m.set("label", "Example"); m.set("origin", "example.com"); m.set("totp", "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(s.save(), .needsPro)
        XCTAssertEqual(reasons, [.twoFactor])
        XCTAssertNotNil(s.model, "the form stays open")
        XCTAssertTrue(items().isEmpty)
    }

    func testEveryKindSavesAndReopens() throws {
        let pro = ProModel(purchases: FreePurchases(), purchased: true)   // more than 4 items
        let s = MacEditorSession(store: store, pro: pro, onNeedsPro: { [unowned self] in reasons.append($0) })
        for kind in EditorKind.allCases {
            XCTAssertTrue(s.startNew(kind), kind.rawValue)
            let m = try XCTUnwrap(s.model)
            let title = "Item \(kind.rawValue)"
            m.set(m.titleKey, title)
            switch kind {
            case .web: m.set("origin", "example.com"); m.set("username", "alex")
            case .bookmark: m.set("url", "https://example.com")
            case .purchase, .warranty, .subscription: m.set("currency", "EUR"); m.set("amount_minor", "12.99")
            default: break
            }
            XCTAssertEqual(s.save(), .saved, "\(kind.rawValue): \(m.error ?? "")")
            let item = try XCTUnwrap(items().first { $0.id == s.lastSavedID }, kind.rawValue)
            XCTAssertEqual(item.title, title)
            XCTAssertEqual(item.kind, kind.rawValue)
            s.startEdit(item)
            XCTAssertEqual(s.model?.kind, kind)
            XCTAssertEqual(s.model?.value(m.titleKey), title)
            XCTAssertFalse(s.isDirty, kind.rawValue)
            XCTAssertEqual(s.save(), .unchanged, kind.rawValue)
        }
        XCTAssertEqual(items().count, EditorKind.allCases.count)
        XCTAssertTrue(reasons.isEmpty)
    }

    func testDiscardingLeavesTheStoreAlone() throws {
        let s = session()
        XCTAssertTrue(s.startNew(.note))
        s.model?.set("title", "Draft")
        s.cancel()
        XCTAssertNil(s.model)
        XCTAssertTrue(items().isEmpty)
    }
}
