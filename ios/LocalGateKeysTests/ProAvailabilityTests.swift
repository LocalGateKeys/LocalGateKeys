import XCTest
import StoreKit
@testable import LocalGateKeys

/// The upgrade sheet when the App Store has no `pro_unlimited` product, and when the user cancels.
@MainActor
final class ProAvailabilityTests: XCTestCase {
    func test_no_product_shows_not_available_and_disables_buy() async {
        let purchases = FakePurchases(); purchases.offerResult = .unavailable
        let p = ProModel(purchases: purchases, licenseKeys: [:])
        XCTAssertTrue(p.canBuy, "until the product is looked up")
        await p.loadPrice()
        XCTAssertFalse(p.canBuy)
        XCTAssertNil(p.price)
        XCTAssertEqual(p.message, ProModel.unavailableMessage)
        XCTAssertEqual(ProModel.unavailableMessage, "Pro isn't available yet")
        await p.buy()
        XCTAssertEqual(purchases.purchaseCalls, 0, "Buy never starts a purchase of a missing product")
        XCTAssertEqual(p.message, "Pro isn't available yet")
    }

    func test_a_later_lookup_that_finds_the_product_clears_the_message() async {
        let purchases = FakePurchases(); purchases.offerResult = .unavailable
        let p = ProModel(purchases: purchases, licenseKeys: [:])
        await p.loadPrice()
        XCTAssertEqual(p.message, ProModel.unavailableMessage)
        purchases.offerResult = .available(price: "$4.99")
        await p.loadPrice()   // the sheet opened again once the product went live
        XCTAssertNil(p.message)
        XCTAssertTrue(p.canBuy)
        XCTAssertEqual(p.price, "$4.99")
    }

    func test_purchase_finding_no_product_says_not_available() async {
        let purchases = FakePurchases(); purchases.purchaseError = ProPurchaseError.unavailable
        let p = ProModel(purchases: purchases, licenseKeys: [:])
        await p.buy()
        XCTAssertEqual(p.message, "Pro isn't available yet")
        XCTAssertFalse(p.canBuy)
    }

    func test_lookup_failure_keeps_buy_enabled() async {
        let purchases = FakePurchases(); purchases.offerResult = .unknown
        let p = ProModel(purchases: purchases, licenseKeys: [:])
        await p.loadPrice()
        XCTAssertTrue(p.canBuy, "offline: the lookup failed, the product may well exist")
        XCTAssertNil(p.message)
    }

    func test_cancelled_restore_or_purchase_is_silent() async {
        for error: any Error in [StoreKitError.userCancelled, ProPurchaseError.cancelled, SKError(.paymentCancelled)] {
            let purchases = FakePurchases(); purchases.restoreError = error; purchases.purchaseError = error
            let p = ProModel(purchases: purchases, licenseKeys: [:])
            await p.restore()
            XCTAssertNil(p.message, "restore: \(error)")
            await p.buy()
            XCTAssertNil(p.message, "buy: \(error)")
            XCTAssertTrue(p.canBuy)
        }
    }

    func test_other_restore_failures_still_explain() async {
        let purchases = FakePurchases(); purchases.restoreError = StoreKitError.networkError(URLError(.notConnectedToInternet))
        let p = ProModel(purchases: purchases, licenseKeys: [:])
        await p.restore()
        XCTAssertEqual(p.message, "Purchases could not be restored. Try again later.")
    }
}
