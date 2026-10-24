import Foundation
import Observation
import StoreKit
import AppShared

/// `unverified`: StoreKit returned a transaction whose JWS failed verification; it is not finished.
enum PurchaseOutcome: Equatable, Sendable { case purchased, pending, cancelled, unverified }

/// What the App Store says about `pro_unlimited`. `unavailable`: the lookup worked and returned no product
/// (not set up in App Store Connect yet, or not sold in this storefront). `unknown`: the lookup failed
/// (offline); the product may exist.
enum ProOffer: Equatable, Sendable { case available(price: String), unavailable, unknown }

enum ProPurchaseError: Error, Equatable {
    /// There is no `pro_unlimited` product to buy.
    case unavailable
    /// The user cancelled (the purchase sheet or the Apple Account sign-in).
    case cancelled

    /// A cancellation by the user, in any of the shapes StoreKit reports it.
    static func isCancellation(_ error: any Error) -> Bool {
        if let e = error as? ProPurchaseError { return e == .cancelled }
        if let e = error as? StoreKitError, case .userCancelled = e { return true }
        if let e = error as? SKError, e.code == .paymentCancelled { return true }
        return false
    }
}

/// StoreKit behind a protocol so view-model tests use a fake.
@MainActor
protocol ProPurchasing: AnyObject {
    /// True while `Transaction.currentEntitlements` holds a verified, unrevoked `pro_unlimited` (works offline).
    func isEntitled() async -> Bool
    func offer() async -> ProOffer
    func purchase() async throws -> PurchaseOutcome
    /// "Restore purchases": `AppStore.sync()`, then the entitlement check.
    func restore() async throws -> Bool
    /// Fires when a transaction arrives outside a purchase call (Ask to Buy, another device, refund).
    func entitlementChanges() -> AsyncStream<Void>
}

@MainActor
final class StoreKitPurchases: ProPurchasing {
    static let productID = "pro_unlimited"
    private let productID: String
    private var product: Product?

    /// `productID` other than `pro_unlimited` only in tests (a product the StoreKit configuration lacks).
    init(productID: String = StoreKitPurchases.productID) { self.productID = productID }

    private func loadProduct() async throws -> Product? {
        if product == nil { product = try await Product.products(for: [productID]).first }
        return product
    }

    func isEntitled() async -> Bool {
        for await result in Transaction.currentEntitlements {
            if case .verified(let t) = result, t.productID == Self.productID, t.revocationDate == nil { return true }
        }
        return false
    }

    func offer() async -> ProOffer {
        do {
            guard let product = try await loadProduct() else { return .unavailable }
            return .available(price: product.displayPrice)
        } catch {
            return .unknown
        }
    }

    func purchase() async throws -> PurchaseOutcome {
        guard let product = try await loadProduct() else { throw ProPurchaseError.unavailable }
        switch try await product.purchase() {
        case .success(let verification):
            guard case .verified(let t) = verification else { return .unverified }
            await t.finish()
            return .purchased
        case .pending: return .pending
        case .userCancelled: return .cancelled
        @unknown default: return .cancelled
        }
    }

    func restore() async throws -> Bool {
        do { try await AppStore.sync() } catch where ProPurchaseError.isCancellation(error) {
            throw ProPurchaseError.cancelled   // the Apple Account sign-in was cancelled
        }
        return await isEntitled()
    }

    func entitlementChanges() -> AsyncStream<Void> {
        AsyncStream { continuation in
            let task = Task {
                for await result in Transaction.updates {
                    if case .verified(let t) = result { await t.finish() }
                    continuation.yield()
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}

/// Pro on this phone: the `pro_unlimited` entitlement or a valid synced desktop licence.
@MainActor
@Observable
final class ProModel {
    private(set) var purchased = false
    private(set) var license: LicenseInfo?
    private(set) var price: String?
    private(set) var busy = false
    private(set) var message: String?
    /// False once the App Store has said there is no `pro_unlimited` product: Buy is disabled.
    private(set) var canBuy = true

    var isPro: Bool { purchased || license != nil }

    static let unavailableMessage = "Pro isn't available yet"

    @ObservationIgnored private let purchases: any ProPurchasing
    @ObservationIgnored private let licenseKeys: [String: [UInt8]]
    @ObservationIgnored private var observer: Task<Void, Never>?

    /// `purchased` starts as the last known entitlement (tests pass `true` for a Pro phone); `refresh()` re-reads it.
    init(purchases: any ProPurchasing, licenseKeys: [String: [UInt8]] = LicenseKeys.production, purchased: Bool = false) {
        self.purchases = purchases; self.licenseKeys = licenseKeys; self.purchased = purchased
    }

    /// The entitlement only (`Transaction.currentEntitlements`, local and offline). Runs at launch, so it must
    /// never load products or call `AppStore.sync()`; either can show an Apple Account sign-in.
    /// A refresh whose task was cancelled meanwhile (its view went away) keeps the last known value: a cut-short
    /// entitlement read could otherwise say "not purchased".
    func refresh() async {
        let entitled = await purchases.isEntitled()
        guard !Task.isCancelled else { return }
        purchased = entitled
    }

    /// The product price, loaded only when the upgrade sheet is shown.
    func loadPrice() async {
        guard price == nil else { return }
        switch await purchases.offer() {
        case .available(let p):
            price = p; canBuy = true
            if message == Self.unavailableMessage { message = nil }   // an earlier lookup found none
        case .unavailable: markUnavailable()
        case .unknown: break
        }
    }

    private func markUnavailable() { canBuy = false; message = Self.unavailableMessage }

    func startObserving() {
        guard observer == nil else { return }
        let changes = purchases.entitlementChanges()
        observer = Task { [weak self] in
            for await _ in changes { await self?.refresh() }
        }
    }

    /// Re-reads the synced licence states.
    func update(from snapshot: StoreSnapshot) {
        license = ItemLimit.validLicense(in: snapshot, keys: licenseKeys)
    }

    func buy() async {
        guard canBuy else { message = Self.unavailableMessage; return }
        busy = true; message = nil
        defer { busy = false }
        do {
            switch try await purchases.purchase() {
            case .purchased: purchased = await purchases.isEntitled()
            case .pending: message = "The purchase is waiting for approval."
            case .cancelled: break
            case .unverified: message = "The App Store could not verify this purchase. Try Restore purchases or try again later."
            }
        } catch ProPurchaseError.unavailable {
            markUnavailable()
        } catch where ProPurchaseError.isCancellation(error) {
            // Cancelled by the user: nothing to say.
        } catch {
            message = "The purchase could not be completed. Try again later."
        }
    }

    func restore() async {
        busy = true; message = nil
        defer { busy = false }
        do {
            purchased = try await purchases.restore()
            if !purchased { message = "No purchase was found for this Apple Account." }
        } catch where ProPurchaseError.isCancellation(error) {
            // The sign-in was cancelled: silent.
            if !canBuy { message = Self.unavailableMessage }
        } catch {
            message = "Purchases could not be restored. Try again later."
        }
    }
}
