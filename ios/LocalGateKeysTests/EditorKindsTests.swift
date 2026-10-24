import XCTest
import AppShared
@testable import LocalGateKeys

/// The kinds the phone gained alongside the desktop's: create, reopen unchanged, and the non-text controls.
@MainActor
final class EditorKindsTests: XCTestCase {
    let clock = TestClock(1_800_000_000)

    func editor(_ store: MemoryStore, item: VaultItem? = nil, kind: EditorKind) -> EditorModel {
        EditorModel(store: store, pro: ProModel(purchases: FakePurchases(), licenseKeys: [:]), editing: item, kind: kind,
                    clock: clock, random: CountingRandom(), background: FakeBackgroundTasks())
    }

    /// One valid form per new kind.
    static let samples: [EditorKind: [String: String]] = [
        .bankAccount: ["title": "Everyday", "bank": "Bank", "account_holder": "Ann", "account_number": "ch93 0076 2011 6238 5295 7",
                       "routing": "ubswchzh80a", "pin": "1234"],
        .purchase: ["title": "Laptop", "vendor": "Shop", "amount_minor": "1299.99", "currency": "chf", "purchase_date": "2026-01-02"],
        .subscription: ["title": "Music", "amount_minor": "10,99", "currency": "EUR", "renewal_date": "2026-11-01"],
        .warranty: ["title": "Fridge", "expiration_date": "2028-01-01"],
        .wifi: ["title": "Home", "ssid": "DemoNet", "password": "pw", "security": "wpa3", "hidden": "true"],
        .license: ["title": "Editor", "license_value": "AAAA-BBBB", "purchase_date": "2026-01-01", "expiration_date": "2027-01-01"],
        .apiKey: ["title": "Weather", "service": "Weather", "key": "k", "secret": "s", "expires": "2027-12-31"],
        .sshKey: ["title": "Laptop key", "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nAA==\n-----END OPENSSH PRIVATE KEY-----",
                  "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ann@laptop"],
        .bookmark: ["title": "Docs", "url": "https://example.com/docs"],
    ]

    func test_every_phone_item_kind_but_passkey_has_an_editor() {
        for kind in Normalise.phoneItemKinds.subtracting(["passkey"]) { XCTAssertNotNil(EditorKind(kind: kind), kind) }
        XCTAssertNil(EditorKind(kind: "document")); XCTAssertNil(EditorKind(kind: "desktop"))
        XCTAssertEqual(Set(EditorKind.menuSections.joined()), Set(EditorKind.allCases), "every kind is in the menu once")
        XCTAssertEqual(EditorKind.menuSections.joined().count, EditorKind.allCases.count)
    }

    func test_each_new_kind_saves_and_reopens_unchanged() throws {
        for (kind, form) in Self.samples {
            let store = MemoryStore(snapshot([]))
            let e = editor(store, kind: kind)
            for (k, v) in form { e.set(k, v) }
            XCTAssertEqual(e.save(), .saved, "\(kind): \(e.error ?? "")")
            let item = try XCTUnwrap(VaultItem.items(from: store.snapshot).first, "\(kind)")
            XCTAssertEqual(item.kind, kind.rawValue)
            let again = editor(store, item: item, kind: kind)
            XCTAssertEqual(again.save(), .unchanged, "\(kind): opening and saving changes nothing")
            XCTAssertEqual(store.commits, 1, "\(kind)")
        }
    }

    func test_saved_payloads_match_the_desktop_shape() throws {
        func payload(_ kind: EditorKind) throws -> [String: JSONValue] {
            let store = MemoryStore(snapshot([]))
            let e = editor(store, kind: kind)
            for (k, v) in Self.samples[kind]! { e.set(k, v) }
            XCTAssertEqual(e.save(), .saved, e.error ?? "")
            return try XCTUnwrap(VaultItem.items(from: store.snapshot).first?.record["payload"]?.objectValue)
        }
        let bank = try payload(.bankAccount)
        XCTAssertEqual(bank["account_number"], .string("CH9300762011623852957"))
        XCTAssertEqual(bank["number_format"], .string("iban"))
        XCTAssertEqual(bank["routing"], .string("UBSWCHZH80A"))
        let purchase = try payload(.purchase)
        XCTAssertEqual(purchase["amount_minor"], .int(129_999)); XCTAssertEqual(purchase["currency"], .string("CHF"))
        XCTAssertEqual(purchase["active"], .bool(true))
        XCTAssertEqual(try payload(.subscription)["amount_minor"], .int(1099))
        let wifi = try payload(.wifi)
        XCTAssertEqual(wifi["hidden"], .bool(true)); XCTAssertEqual(wifi["security"], .string("wpa3"))
        let ssh = try payload(.sshKey)
        XCTAssertEqual(ssh["key_format"], .string("openssh"))
        XCTAssertEqual(ssh["fingerprint"]?.stringValue?.hasPrefix("SHA256:"), true)
    }

    func test_no_amount_saves_neither_amount_nor_currency() throws {
        let store = MemoryStore(snapshot([]))
        let e = editor(store, kind: .warranty)
        e.set("title", "Fridge"); e.set("currency", "EUR")
        XCTAssertEqual(e.save(), .saved, e.error ?? "")
        let p = try XCTUnwrap(VaultItem.items(from: store.snapshot).first?.record["payload"]?.objectValue)
        XCTAssertEqual(p["amount_minor"], .int(0)); XCTAssertEqual(p["currency"], .string("XXX"), "the desktop's empty amount")
        let reopened = editor(store, item: VaultItem.items(from: store.snapshot)[0], kind: .warranty)
        XCTAssertEqual(reopened.value("amount_minor"), ""); XCTAssertEqual(reopened.value("currency"), "")
    }

    func test_bad_amount_is_an_inline_error() {
        let store = MemoryStore(snapshot([]))
        let e = editor(store, kind: .purchase)
        e.set("title", "x"); e.set("currency", "EUR"); e.set("amount_minor", "1.999")
        XCTAssertEqual(e.save(), .invalid)
        XCTAssertEqual(e.amountError, "Use at most 2 decimals.")
        e.set("amount_minor", "1.99")
        XCTAssertNil(e.amountError)
        XCTAssertEqual(store.commits, 0)
    }

    func test_amount_conversion() throws {
        XCTAssertEqual(try Amount.minorUnits("12.5", currency: "EUR"), 1250)
        XCTAssertEqual(try Amount.minorUnits("-3", currency: "USD"), -300)
        XCTAssertEqual(try Amount.minorUnits(".5", currency: "EUR"), 50)
        XCTAssertEqual(try Amount.minorUnits("1500", currency: "JPY"), 1500)
        XCTAssertThrowsError(try Amount.minorUnits("1.5", currency: "JPY"))
        XCTAssertThrowsError(try Amount.minorUnits("abc", currency: "EUR"))
        XCTAssertThrowsError(try Amount.minorUnits(".", currency: "EUR"))
        XCTAssertThrowsError(try Amount.minorUnits("1.2.3", currency: "EUR"))
        XCTAssertThrowsError(try Amount.minorUnits("99999999999999999", currency: "EUR"))
        XCTAssertEqual(Amount.text(minor: 129_999, currency: "CHF"), "1299.99")
        XCTAssertEqual(Amount.text(minor: 5, currency: "EUR"), "0.05")
        XCTAssertEqual(Amount.text(minor: -1500, currency: "EUR"), "-15.00")
        XCTAssertEqual(Amount.text(minor: 1500, currency: "JPY"), "1500")
    }

    func test_bad_iban_is_refused() {
        let store = MemoryStore(snapshot([]))
        let e = editor(store, kind: .bankAccount)
        e.set("title", "x"); e.set("account_number", "CH9400762011623852957")
        XCTAssertEqual(e.save(), .invalid)
        XCTAssertEqual(e.error, "IBAN failed its checksum")
    }

    func test_detail_shows_amount_dates_and_flags_readably() throws {
        let store = MemoryStore(snapshot([]))
        let e = editor(store, kind: .wifi)
        for (k, v) in Self.samples[.wifi]! { e.set(k, v) }
        XCTAssertEqual(e.save(), .saved)
        let wifi = ItemDetailModel.fields(for: VaultItem.items(from: store.snapshot)[0])
        XCTAssertEqual(wifi.first { $0.id == "security" }?.value, "WPA3")
        XCTAssertEqual(wifi.first { $0.id == "hidden" }?.value, "Yes")
        XCTAssertEqual(wifi.first { $0.id == "password" }?.isSecret, true)
        let s2 = MemoryStore(snapshot([]))
        let p = editor(s2, kind: .subscription)
        for (k, v) in Self.samples[.subscription]! { p.set(k, v) }
        XCTAssertEqual(p.save(), .saved)
        let sub = ItemDetailModel.fields(for: VaultItem.items(from: s2.snapshot)[0])
        XCTAssertEqual(sub.first { $0.id == "active" }?.value, "Yes")
        XCTAssertNotNil(sub.first { $0.id == "amount_minor" }?.value.range(of: "10.99") ?? sub.first { $0.id == "amount_minor" }?.value.range(of: "10,99"))
        XCTAssertFalse(sub.contains { $0.id == "currency" || $0.id == "template_id" || $0.id == "document_ids" })
    }
}
