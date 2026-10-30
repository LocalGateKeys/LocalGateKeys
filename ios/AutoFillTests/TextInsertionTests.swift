import XCTest
import AuthenticationServices
import AppShared

/// UX workstream 11: the card and identity fields offered for text insertion (iOS 18+).
@MainActor
final class TextInsertionTests: XCTestCase {
    static func item(_ id: String, kind: String, title: String, payload: [String: JSONValue]) -> JSONValue {
        Wrapper.make(ns: .item, record: .object(["id": .string(id), "kind": .string(kind), "title": .string(title),
                                                 "payload": .object(payload), "updated_at": .int(1)]))
    }

    static func snapshot() -> StoreSnapshot {
        let deleted = SyncMeta(digest: nil, body: nil, updatedAt: 1, vv: [:], deleted: true, deletedAt: 1)
        return StoreSnapshot(records: [
            "c1": item("c1", kind: "card", title: "Visa", payload: [
                "cardholder": .string("Alice Example"), "number": .string("4111 1111 1111 6411"),
                "expiry": .string("08/27"), "cvv": .string("123"), "pin": .string("9999")]),
            "c2": item("c2", kind: "card", title: "Amex", payload: ["number": .string("3782-822463-10005")]),
            "c3": item("c3", kind: "card", title: "Gone", payload: ["number": .string("5555555555554444")]),
            "i1": item("i1", kind: "identity", title: "Home", payload: [
                "name": .string("Alice Example"), "email": .string("alice@example.com"), "phone": .string("+30 210 000"),
                "address_line1": .string("1 Main St"), "city": .string("Athens"), "postal_code": .string("10431"),
                "country": .string("Greece")]),
            "n1": item("n1", kind: "note", title: "Note", payload: ["body": .string("secret")]),
            "w1": Fixture.snapshot().records["w1"]!,
        ], meta: ["c3": deleted], revision: 1)
    }

    func test_lists_cards_then_identities_without_pins_notes_or_deleted() {
        let f = TextInsertionCatalog.fields(Self.snapshot())
        XCTAssertEqual(Set(f.map(\.recordID)), ["c1", "c2", "i1"])
        // Cards first (by title: Amex, Visa), then identities.
        XCTAssertEqual(f.first?.recordID, "c2")
        XCTAssertEqual(f.last?.recordID, "i1")
        XCTAssertFalse(f.contains { $0.value == "9999" }, "a PIN is never offered")
        XCTAssertFalse(f.contains { $0.value == "secret" })
    }

    func test_card_fields_masked_and_security_code_last_and_not_preselectable() {
        let visa = TextInsertionCatalog.fields(Self.snapshot()).filter { $0.recordID == "c1" }
        XCTAssertEqual(visa.map(\.kind), [.cardNumber, .cardExpiry, .cardholder, .cardSecurityCode])
        XCTAssertEqual(visa[0].value, "4111111111116411")
        XCTAssertEqual(visa[0].display, "•••• 6411")
        XCTAssertEqual(visa[3].display, "•••")
        XCTAssertFalse(visa[3].isPreselectable)
        XCTAssertTrue(visa.dropLast().allSatisfy(\.isPreselectable))
        let amex = TextInsertionCatalog.fields(Self.snapshot()).filter { $0.recordID == "c2" }
        XCTAssertEqual(amex.map(\.value), ["378282246310005"])
    }

    func test_identity_fields_and_joined_address() {
        let home = TextInsertionCatalog.fields(Self.snapshot()).filter { $0.recordID == "i1" }
        XCTAssertEqual(home.map(\.kind), [.name, .email, .phone, .address, .addressLine1, .city, .postalCode, .country])
        XCTAssertEqual(home.first { $0.kind == .address }?.value, "1 Main St\n10431 Athens\nGreece")
    }

    func test_empty_vault_lists_nothing() {
        XCTAssertTrue(TextInsertionCatalog.fields(StoreSnapshot(records: [:], meta: [:], revision: 0)).isEmpty)
    }

    func driver() -> (CredentialRequestDriver, RecordingSink, FakeAuth) {
        let auth = FakeAuth(vault: InMemoryKeychainVault())
        let settings = AppSettings(defaults: UserDefaults(suiteName: "ti-\(UUID().uuidString)")!)
        let flow = CredentialFlow(auth: auth, opener: FakeOpener(RecordingStore(Self.snapshot())),
                                  matcher: .bundled(Bundle(for: TextInsertionTests.self)),
                                  clipboard: FakeClipboard(), clock: FixedClock(59), settings: settings)
        let d = CredentialRequestDriver(flow: flow), sink = RecordingSink()
        d.sink = sink
        return (d, sink, auth)
    }

    func test_unlock_then_pick_inserts_once_and_forgets_the_vault() async {
        let (d, sink, auth) = driver()
        d.beginTextInsertion()
        await d.task?.value
        XCTAssertEqual(auth.calls, 1, "Face ID before the list")
        XCTAssertEqual(auth.reasons, [CredentialRequestDriver.textReason])
        let fields = try! XCTUnwrap(sink.textLists.first)
        let cvv = try! XCTUnwrap(fields.first { $0.kind == .cardSecurityCode })
        d.selectText(cvv)
        XCTAssertEqual(sink.texts, ["123"])
        XCTAssertNil(d.flow.snapshot)
        d.selectText(fields[0])   // a second tap inserts nothing
        XCTAssertEqual(sink.texts, ["123"])
    }

    func test_failed_unlock_cancels_and_lists_nothing() async {
        let (d, sink, auth) = driver()
        auth.fail = LAErrorStub.cancelled
        d.beginTextInsertion()
        await d.task?.value
        XCTAssertTrue(sink.textLists.isEmpty)
        XCTAssertEqual(sink.cancels.count, 1)
        d.selectText(TextInsertionCatalog.fields(Self.snapshot())[0])
        XCTAssertTrue(sink.texts.isEmpty, "nothing inserted without the unlock")
    }
}
