import XCTest
import StoreKit
import StoreKitTest
import AppShared
@testable import LocalGateKeys

/// Runs the real StoreKit 2 code against ios/App/StoreKit/LocalGateKeys.storekit in a local test session.
@MainActor
final class StoreKitPurchaseTests: XCTestCase {
    var session: SKTestSession!

    override func setUp() async throws {
        session = try SKTestSession(configurationFileNamed: "LocalGateKeys")
        session.resetToDefaultState()
        session.disableDialogs = true
        session.clearTransactions()
    }

    override func tearDown() async throws { session?.clearTransactions() }

    func test_storekit_purchase_and_restore() async throws {
        let store = StoreKitPurchases()
        let entitledAtStart = await store.isEntitled()
        XCTAssertFalse(entitledAtStart)
        let offer = await store.offer()
        guard case .available = offer else { return XCTFail("\(offer)") }
        let outcome = try await store.purchase()
        XCTAssertEqual(outcome, .purchased)
        let entitledAfterBuy = await store.isEntitled()
        XCTAssertTrue(entitledAfterBuy)

        let p = ProModel(purchases: store, licenseKeys: [:])
        await p.restore()
        XCTAssertTrue(p.isPro)

        session.clearTransactions()
        let entitledAfterClear = await store.isEntitled()
        XCTAssertFalse(entitledAfterClear)
    }

    func test_storekit_product_is_a_non_consumable_without_family_sharing() async throws {
        let products = try await Product.products(for: [StoreKitPurchases.productID])
        let product = try XCTUnwrap(products.first)
        XCTAssertEqual(product.type, .nonConsumable)
        XCTAssertFalse(product.isFamilyShareable)
        XCTAssertTrue(product.displayPrice.contains("4.99"), product.displayPrice)
        let posix = Locale(identifier: "en_US_POSIX")
        let expected = try XCTUnwrap(Decimal(string: "4.99", locale: posix))
        // The product's own offer price, as a Decimal, must be exactly 4.99. `Product.price` itself reads 4
        // on hosts whose region uses a decimal comma: the test session's storekitd writes the offer as
        // "4,99" (host region) and `Product` parses it as en_US. The offer string is the product's data.
        let json = try JSONSerialization.jsonObject(with: product.jsonRepresentation) as? [String: Any]
        guard let attributes = json?["attributes"] as? [String: Any],
              let offer = (attributes["offers"] as? [[String: Any]])?.first,
              let priceString = offer["priceString"] as? String else { return XCTFail("no offer price") }
        XCTAssertEqual(Decimal(string: priceString.replacingOccurrences(of: ",", with: "."), locale: posix), expected)
        XCTAssertEqual(offer["currencyCode"] as? String, "USD")
        if priceString.contains(".") { XCTAssertEqual(product.price, expected) }
    }

    /// The item-limit gate end to end through the real StoreKit test session: blocked, buy, allowed;
    /// then a fresh model with no entitlement in memory restores and is allowed again.
    func test_gate_end_to_end_buy_then_restore() async throws {
        let store = MemoryStore(snapshot(numberedNotes(ItemLimit.freeItems)))
        let pro = ProModel(purchases: StoreKitPurchases(), licenseKeys: [:])
        await pro.refresh()
        XCTAssertFalse(pro.isPro)
        func newNote(_ p: ProModel) -> EditorModel {
            let e = EditorModel(store: store, pro: p, editing: nil, kind: .note, clock: TestClock(1_800_000_000),
                                random: SystemRandomSource(), background: FakeBackgroundTasks())
            e.set(e.titleKey, "More"); e.set("body", "x")
            return e
        }
        let blocked = newNote(pro)
        XCTAssertEqual(blocked.save(), .needsPro)
        XCTAssertTrue(blocked.showUpgrade)
        await pro.buy()
        XCTAssertNil(pro.message)
        XCTAssertTrue(pro.isPro)
        XCTAssertEqual(newNote(pro).save(), .saved)

        let fresh = ProModel(purchases: StoreKitPurchases(), licenseKeys: [:])
        XCTAssertFalse(fresh.isPro)
        await fresh.restore()
        XCTAssertTrue(fresh.isPro)
        XCTAssertEqual(newNote(fresh).save(), .saved)
        XCTAssertEqual(store.commits, 2)

        // With the transactions gone, restore must find nothing: the entitlement above came from restore
        // reading the store, not from a model already holding it.
        session.clearTransactions()
        let cleared = ProModel(purchases: StoreKitPurchases(), licenseKeys: [:])
        await cleared.restore()
        XCTAssertFalse(cleared.isPro)
        XCTAssertEqual(newNote(cleared).save(), .needsPro)
    }

    // MARK: no product (not yet in App Store Connect, or not in this storefront)

    func test_missing_product_is_unavailable_and_buy_never_reaches_storekit() async throws {
        let store = StoreKitPurchases(productID: "pro_not_configured")
        let offer = await store.offer()
        XCTAssertEqual(offer, .unavailable)
        do { _ = try await store.purchase(); XCTFail("bought a missing product") } catch {
            XCTAssertEqual(error as? ProPurchaseError, .unavailable)
        }
        let p = ProModel(purchases: store, licenseKeys: [:])
        await p.loadPrice()
        XCTAssertFalse(p.canBuy)
        XCTAssertEqual(p.message, "Pro isn't available yet")
        await p.buy()
        XCTAssertEqual(p.message, "Pro isn't available yet")
        XCTAssertFalse(p.isPro)
    }
}
