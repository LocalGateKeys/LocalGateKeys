import XCTest
import AppShared

/// Sub-plan 07 Task 5c: collection states (`col:`/`cm:`/`csl:`) live in the item store, and AutoFill never offers or
/// publishes them: the login list, the QuickType identities (passwords, passkeys, codes), passkey sign-in and text
/// insertion. Records planted under reserved ids look like a login, a passkey and a card; only the shared filter
/// (`StoreSnapshot.itemRecords`) keeps them out.
@MainActor
final class CollectionRecordsAutoFillTests: XCTestCase {
    let matcher = AutoFillMatcher.bundled(Bundle(for: CollectionRecordsAutoFillTests.self))
    static let family = "3f2a6c1e-8b4d-4e7a-9c05-d1e2f3a4b5c6"

    static func planted(_ key: PasskeyKey) -> StoreSnapshot {
        var s = Fixture.snapshotWithPasskeys(key)
        s.records["c1"] = TextInsertionTests.item("c1", kind: "card", title: "Visa", payload: ["number": .string("4111111111116411")])
        s.records[CollectionStates.catalogPrefix + family] = CollectionStates.wrapper(CollectionStates.catalog(
            collectionID: family, name: "Family", description: "", createdAt: 1, updatedAt: 1))
        s.records[CollectionStates.linkPrefix + family] = CollectionStates.wrapper(CollectionStates.link(
            collectionID: family, mode: "read", role: "member"))
        s.records["col:w"] = Fixture.web("col:w", user: "eve", password: "pw-eve", origin: "https://example.com",
                                         urls: [("https://shop.example.co.uk/", "base_domain")], totp: Fixture.rfcTOTP)
        s.records["cm:p"] = Fixture.passkey("cm:p", rp: "example.com", user: "eve", credID: [42], handle: [42], key: key.pkcs8B64URL)
        s.records["csl:c"] = TextInsertionTests.item("csl:c", kind: "card", title: "Planted", payload: ["number": .string("5555555555554444")])
        return s
    }

    func test_logins_and_identities_never_include_collection_states() {
        let snap = Self.planted(PasskeyKey.generate())
        XCTAssertFalse(AutoFillMatcher.logins(snap).contains { $0.login.id.hasPrefix("col:") })
        XCTAssertEqual(Set(AutoFillMatcher.logins(snap).map(\.login.id)), ["w1", "w2"])
        let settings = AppSettings(defaults: UserDefaults(suiteName: "af-col-\(UUID().uuidString)")!)
        settings.quickTypeExactSites = false
        let sync = IdentityStoreSync(identityStore: FakeIdentityStore(enabled: true), matcher: matcher.matcher, settings: settings,
                                     oneTimeCodes: true)
        // The planted login has a base_domain row and a code, so without the filter it would publish both kinds.
        XCTAssertFalse("\(sync.identities(snap))".contains("col:w"))
        XCTAssertFalse(sync.identities(snap).isEmpty)
        XCTAssertFalse("\(sync.oneTimeCodeIdentities(snap))".contains("col:w"))
        XCTAssertFalse("\(sync.passkeyIdentities(snap))".contains("cm:p"))
        XCTAssertFalse(sync.passkeyIdentities(snap).isEmpty)
    }

    func test_passkey_sign_in_and_text_insertion_never_offer_collection_states() {
        let snap = Self.planted(PasskeyKey.generate())
        XCTAssertEqual(PasskeyVault.candidates(snap, rpID: "example.com", allowed: []).map(\.itemID), ["p1"])
        XCTAssertNil(PasskeyVault.live(snap, "cm:p"))
        XCTAssertEqual(Set(TextInsertionCatalog.fields(snap).map(\.recordID)), ["c1"])
    }
}
