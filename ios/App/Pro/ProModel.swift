import Foundation
import Observation
import StoreKit
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

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
    /// The JWS of the current verified, unrevoked `pro_unlimited` transaction (for the licence claim); nil without one.
    func currentTransactionJWS() async -> String?
}

extension ProPurchasing {
    /// Fakes without a transaction: nothing to claim.
    func currentTransactionJWS() async -> String? { nil }
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

    func currentTransactionJWS() async -> String? {
        for await result in Transaction.currentEntitlements {
            if case .verified(let t) = result, t.productID == Self.productID, t.revocationDate == nil {
                return result.jwsRepresentation
            }
        }
        return nil
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
/// After a purchase, a restore or a launch with the entitlement, and while the vault is unlocked and holds no
/// valid licence, the purchase is claimed once (per launch) from the licence Worker (`LicenceClaim.swift`) and
/// stored as a licence state, so pairing carries it to a PC. Pro here never depends on the claim.
@MainActor
@Observable
final class ProModel {
    private(set) var purchased = false
    private(set) var license: LicenseInfo?
    private(set) var price: String?
    private(set) var busy = false
    /// What the Pro screen says (compared by id, shown translated).
    enum Notice: Equatable {
        case unavailable, pending, unverified, purchaseFailed, nothingRestored, restoreFailed
        var text: String {
            switch self {
            case .unavailable: ProModel.unavailableMessage
            case .pending: String(localized: "The purchase is waiting for approval.")
            case .unverified: String(localized: "The App Store could not verify this purchase. Try Restore purchases or try again later.")
            case .purchaseFailed: String(localized: "The purchase could not be completed. Try again later.")
            case .nothingRestored: String(localized: "No purchase was found for this Apple Account.")
            case .restoreFailed: String(localized: "Purchases could not be restored. Try again later.")
            }
        }
    }
    private(set) var notice: Notice?
    var message: String? { notice?.text }
    /// False once the App Store has said there is no `pro_unlimited` product: Buy is disabled.
    private(set) var canBuy = true
    /// The `LGK1-` key of the licence shown (Settings › Pro "Copy key"); nil without a licence.
    private(set) var licenceKey: String?

    var isPro: Bool {
        #if DEBUG
        // Debug builds only: `LGK_DEBUG_PRO=1` acts as Pro (manual checks without a store purchase).
        if Self.debugPro { return true }
        #endif
        return purchased || license != nil
    }

    #if DEBUG
    static let debugPro = ProcessInfo.processInfo.environment["LGK_DEBUG_PRO"] == "1"
    #endif

    nonisolated static var unavailableMessage: String { String(localized: "Pro isn't available yet") }

    @ObservationIgnored private let purchases: any ProPurchasing
    @ObservationIgnored private let licenseKeys: [String: [UInt8]]
    @ObservationIgnored private var observer: Task<Void, Never>?
    /// nil: no claims (tests and previews that do not test them).
    @ObservationIgnored private let claimer: (any LicenceClaiming)?
    @ObservationIgnored private let claimFlags: LicenceClaimFlags
    /// The unlocked vault the claimed licence goes into; nil while locked.
    @ObservationIgnored private var claimStore: (any ItemStore)?
    /// Bumped by every lock: a claim answered after the vault locked writes nothing.
    @ObservationIgnored private var claimGeneration = 0
    /// One claim per launch; an offline or failed one is tried again at the next launch.
    @ObservationIgnored private var claimTried = false

    /// `purchased` starts as the last known entitlement (tests pass `true` for a Pro phone); `refresh()` re-reads it.
    init(purchases: any ProPurchasing, licenseKeys: [String: [UInt8]] = LicenseKeys.production, purchased: Bool = false,
         claimer: (any LicenceClaiming)? = nil, claimFlags: LicenceClaimFlags = LicenceClaimFlags(defaults: nil)) {
        self.purchases = purchases; self.licenseKeys = licenseKeys; self.purchased = purchased
        self.claimer = claimer; self.claimFlags = claimFlags
    }

    /// The entitlement only (`Transaction.currentEntitlements`, local and offline). Runs at launch, so it must
    /// never load products or call `AppStore.sync()`; either can show an Apple Account sign-in.
    /// A refresh whose task was cancelled meanwhile (its view went away) keeps the last known value: a cut-short
    /// entitlement read could otherwise say "not purchased".
    func refresh() async {
        let entitled = await purchases.isEntitled()
        guard !Task.isCancelled else { return }
        purchased = entitled
        claimInBackground()
    }

    /// The product price, loaded only when the upgrade sheet is shown.
    func loadPrice() async {
        guard price == nil else { return }
        switch await purchases.offer() {
        case .available(let p):
            price = p; canBuy = true
            if notice == .unavailable { notice = nil }   // an earlier lookup found none
        case .unavailable: markUnavailable()
        case .unknown: break
        }
    }

    private func markUnavailable() { canBuy = false; notice = .unavailable }

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
        licenceKey = license.flatMap { info in
            guard case .object(let w)? = snapshot.records[License.stateID(licenseID: info.licenseID)],
                  let bundle = w["record"] else { return nil }
            return try? LicenceText.encodePaste(bundle)
        }
    }

    // MARK: licence claim

    /// The vault was unlocked: a pending claim may run now.
    func vaultUnlocked(store: any ItemStore) {
        claimStore = store
        claimInBackground()
    }

    /// The vault locked: nothing is written until the next unlock.
    func vaultLocked() {
        claimStore = nil
        claimGeneration += 1
    }

    private func claimInBackground() {
        guard claimer != nil, purchased, license == nil, !claimTried, let store = claimStore else { return }
        let generation = claimGeneration
        Task { [weak self] in
            guard let self, self.claimGeneration == generation else { return }   // locked before it started
            await self.claimIfNeeded(store: store)
        }
    }

    /// Claims the App Store purchase from the licence Worker when this device has the entitlement, the vault
    /// holds no valid licence and no claim ran this launch (and none was refused). A returned licence is verified
    /// with the production keys before it is stored; any failure is silent.
    func claimIfNeeded(store: any ItemStore) async {
        guard let claimer, purchased, !claimTried, !claimFlags.refused else { return }
        guard let snapshot = try? store.load() else { return }
        update(from: snapshot)
        guard license == nil else { return }
        claimTried = true
        let mine = claimGeneration
        guard let jws = await purchases.currentTransactionJWS() else { claimTried = false; return }
        let result = await claimer.claim(jws: jws)
        guard mine == claimGeneration else { claimTried = false; return }   // locked meanwhile: next unlock
        switch result {
        case .licence(let text): install(text, into: store)
        case .retryLater: break
        case .refused: claimFlags.refused = true
        }
    }

    /// Writes the claimed licence only when it verifies with this build's keys.
    private func install(_ text: String, into store: any ItemStore) {
        guard let bundle = try? LicenceText.parse(text),
              let info = try? License.verify(bundle: bundle, keys: licenseKeys) else { return }
        guard (try? LicenceStateWriter.write(bundle: bundle, licenseID: info.licenseID, to: store)) != nil else { return }
        if let snapshot = try? store.load() { update(from: snapshot) }
    }

    func buy() async {
        guard canBuy else { notice = .unavailable; return }
        busy = true; notice = nil
        defer { busy = false }
        do {
            switch try await purchases.purchase() {
            case .purchased: purchased = await purchases.isEntitled(); claimInBackground()
            case .pending: notice = .pending
            case .cancelled: break
            case .unverified: notice = .unverified
            }
        } catch ProPurchaseError.unavailable {
            markUnavailable()
        } catch where ProPurchaseError.isCancellation(error) {
            // Cancelled by the user: nothing to say.
        } catch {
            notice = .purchaseFailed
        }
    }

    func restore() async {
        busy = true; notice = nil
        defer { busy = false }
        do {
            purchased = try await purchases.restore()
            if !purchased { notice = .nothingRestored }
            claimInBackground()
        } catch where ProPurchaseError.isCancellation(error) {
            // The sign-in was cancelled: silent.
            if !canBuy { notice = .unavailable }
        } catch {
            notice = .restoreFailed
        }
    }
}
