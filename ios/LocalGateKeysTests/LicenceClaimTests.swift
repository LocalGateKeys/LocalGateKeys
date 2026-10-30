import XCTest
import AppShared
@testable import LocalGateKeys

/// The App Store purchase claimed as a desktop licence (plan 2026-10-29-appstore-licence Task 7), on the
/// TEST-ONLY licence vector (`LicenseVector`, never valid with production keys).
@MainActor
final class LicenceClaimTests: XCTestCase {
    private func vector() throws -> (keys: [String: [UInt8]], id: String, wrapper: JSONValue, text: String) {
        let v = try LicenseVector.load()
        guard case .object(let w) = v.wrapper, let bundle = w["record"] else { throw XCTSkip("licence vector shape") }
        return (v.keys, v.id, v.wrapper, try LicenceText.encodePaste(bundle))
    }

    private func model(_ purchases: FakePurchases, _ claim: FakeLicenceClaim, keys: [String: [UInt8]],
                       flags: LicenceClaimFlags = LicenceClaimFlags(defaults: nil)) -> ProModel {
        ProModel(purchases: purchases, licenseKeys: keys, purchased: purchases.entitled, claimer: claim, claimFlags: flags)
    }

    private func entitled() -> FakePurchases { let p = FakePurchases(); p.entitled = true; return p }

    func test_claim_writes_licence_state() async throws {
        let v = try vector()
        let store = MemoryStore()
        let claim = FakeLicenceClaim(.licence(v.text))
        let purchases = entitled()
        let pro = model(purchases, claim, keys: v.keys)
        await pro.claimIfNeeded(store: store)
        XCTAssertEqual(claim.calls, [try XCTUnwrap(purchases.jws)])
        XCTAssertEqual(store.snapshot.records[v.id], v.wrapper, "stored as the synced licence state")
        XCTAssertEqual(store.commits, 1)
        XCTAssertNotNil(pro.license)
        XCTAssertEqual(pro.licenceKey, v.text)
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), 0, "a licence is not an item")
    }

    func test_no_claim_when_licence_exists() async throws {
        let v = try vector()
        let store = MemoryStore(StoreSnapshot(records: [v.id: v.wrapper]))
        let claim = FakeLicenceClaim(.licence(v.text))
        let pro = model(entitled(), claim, keys: v.keys)
        await pro.claimIfNeeded(store: store)
        XCTAssertTrue(claim.calls.isEmpty)
        XCTAssertEqual(store.commits, 0)
        XCTAssertNotNil(pro.license)
    }

    func test_offline_retries_next_launch() async throws {
        let v = try vector()
        let store = MemoryStore()
        let claim = FakeLicenceClaim(.retryLater)
        let suite = "lgk-claim-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        let first = model(entitled(), claim, keys: v.keys, flags: LicenceClaimFlags(defaults: defaults))
        await first.claimIfNeeded(store: store)
        await first.claimIfNeeded(store: store)
        XCTAssertEqual(claim.calls.count, 1, "once per launch")
        XCTAssertNil(first.license)
        XCTAssertEqual(store.commits, 0)
        XCTAssertFalse(defaults.bool(forKey: LicenceClaimFlags.refusedKey))
        XCTAssertNil(first.message, "silent")

        // The next launch (a new model over the same saved flags) claims again and succeeds.
        claim.answer = .licence(v.text)
        let second = model(entitled(), claim, keys: v.keys, flags: LicenceClaimFlags(defaults: defaults))
        await second.claimIfNeeded(store: store)
        XCTAssertEqual(claim.calls.count, 2)
        XCTAssertNotNil(second.license)
    }

    func test_refused_stops_retrying() async throws {
        let v = try vector()
        let store = MemoryStore()
        let claim = FakeLicenceClaim(.refused)
        let suite = "lgk-claim-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        let first = model(entitled(), claim, keys: v.keys, flags: LicenceClaimFlags(defaults: defaults))
        await first.claimIfNeeded(store: store)
        XCTAssertTrue(defaults.bool(forKey: LicenceClaimFlags.refusedKey))
        let second = model(entitled(), claim, keys: v.keys, flags: LicenceClaimFlags(defaults: defaults))
        await second.claimIfNeeded(store: store)
        XCTAssertEqual(claim.calls.count, 1, "403 is never asked again")
        XCTAssertTrue(second.isPro, "Pro here never depends on the claim")
        XCTAssertNil(second.message, "silent")

        // The Worker's answers.
        XCTAssertEqual(WorkerLicenceClaim.result(status: 403, body: Data()), .refused)
        XCTAssertEqual(WorkerLicenceClaim.result(status: 400, body: Data()), .retryLater)
        XCTAssertEqual(WorkerLicenceClaim.result(status: 429, body: Data()), .retryLater)
        XCTAssertEqual(WorkerLicenceClaim.result(status: 503, body: Data()), .retryLater)
        XCTAssertEqual(WorkerLicenceClaim.result(status: 200, body: Data(#"{"licence":"LGK1-abc"}"#.utf8)), .licence("LGK1-abc"))
        XCTAssertEqual(WorkerLicenceClaim.result(status: 200, body: Data(#"{"licence":"nope"}"#.utf8)), .retryLater)
        XCTAssertEqual(WorkerLicenceClaim.url.absoluteString, "https://licenses.localgatekeys.app/appstore/claim")
    }

    func test_bad_licence_not_written() async throws {
        let v = try vector()
        let store = MemoryStore()
        // Signed with the test key, checked against the production keys: never written.
        let claim = FakeLicenceClaim(.licence(v.text))
        let pro = model(entitled(), claim, keys: LicenseKeys.production)
        await pro.claimIfNeeded(store: store)
        XCTAssertEqual(claim.calls.count, 1)
        XCTAssertEqual(store.commits, 0)
        XCTAssertNil(pro.license)

        let garbled = model(entitled(), FakeLicenceClaim(.licence("LGK1-not-a-licence")), keys: v.keys)
        await garbled.claimIfNeeded(store: store)
        XCTAssertEqual(store.commits, 0)
        XCTAssertNil(garbled.license)
    }

    func test_no_claim_without_entitlement() async throws {
        let v = try vector()
        let store = MemoryStore()
        let claim = FakeLicenceClaim(.licence(v.text))
        let pro = model(FakePurchases(), claim, keys: v.keys)
        await pro.claimIfNeeded(store: store)
        XCTAssertTrue(claim.calls.isEmpty)
        XCTAssertEqual(store.commits, 0)

        // Entitled, but StoreKit has no transaction to sign: nothing is sent.
        let noTransaction = entitled(); noTransaction.jws = nil
        let other = model(noTransaction, claim, keys: v.keys)
        await other.claimIfNeeded(store: store)
        XCTAssertTrue(claim.calls.isEmpty)
        XCTAssertEqual(store.commits, 0)
    }

    func test_plan_copy() {
        XCTAssertEqual(SettingsView.alsoUnlocksWindows, "Also unlocks Windows: pair your PC")
        XCTAssertEqual(SettingsView.copyKeyLabel, "Copy key")
    }
}
