import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// What the licence Worker answered to a claim (`POST /appstore/claim`).
/// `licence`: an `LGK1-` key, still to be verified here. `retryLater`: offline, 4xx other than 403, 5xx or 429;
/// tried again at the next launch. `refused`: 403, the purchase was refunded or revoked; never tried again.
enum ClaimResult: Equatable, Sendable { case licence(String), retryLater, refused }

/// The licence Worker behind a protocol so tests use a fake.
protocol LicenceClaiming: Sendable {
    /// `jws`: the current `pro_unlimited` transaction as StoreKit signed it (`VerificationResult.jwsRepresentation`).
    func claim(jws: String) async -> ClaimResult
}

/// The live Worker. The body carries the signed transaction only (no email, no device data); failures are silent.
struct WorkerLicenceClaim: LicenceClaiming {
    static let url = URL(string: "https://licenses.localgatekeys.app/appstore/claim")!
    static let timeout: TimeInterval = 20

    func claim(jws: String) async -> ClaimResult {
        var request = URLRequest(url: Self.url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: Self.timeout)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        guard let body = try? JSONSerialization.data(withJSONObject: ["jws": jws]) else { return .retryLater }
        request.httpBody = body
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse else { return .retryLater }
            return Self.result(status: http.statusCode, body: data)
        } catch {
            return .retryLater
        }
    }

    /// `200 {"licence": "LGK1-…"}`, `403` refused, anything else later.
    static func result(status: Int, body: Data) -> ClaimResult {
        switch status {
        case 200:
            guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
                  let text = object["licence"] as? String, text.hasPrefix(LicenceText.pastePrefix) else { return .retryLater }
            return .licence(text)
        case 403: return .refused
        default: return .retryLater
        }
    }
}

/// The one claim flag kept across launches: the Worker refused this purchase (403), so it is never claimed again.
/// `defaults` nil keeps it in memory (tests, previews).
final class LicenceClaimFlags: @unchecked Sendable {
    static let refusedKey = "lgk.licenceClaim.refused"
    private let defaults: UserDefaults?
    private let lock = NSLock()
    private var memory = false

    init(defaults: UserDefaults?) { self.defaults = defaults }

    var refused: Bool {
        get { lock.withLock { defaults?.bool(forKey: Self.refusedKey) ?? memory } }
        set { lock.withLock { if let defaults { defaults.set(newValue, forKey: Self.refusedKey) } else { memory = newValue } } }
    }
}

/// Stores a verified licence as the synced licence state (namespace `license`, id `lic:` + 32 hex of the
/// licence id's SHA-256), the record a PC's vault bridge publishes, so it syncs, backs up and restores like one.
enum LicenceStateWriter {
    enum Outcome: Equatable { case stored, unchanged, full }

    static func write(bundle: JSONValue, licenseID: String, to store: any ItemStore) throws -> Outcome {
        let id = License.stateID(licenseID: licenseID)
        let wrapper = Wrapper.make(ns: .license, record: bundle)
        var snap = try store.load()
        if snap.records[id] == wrapper { return .unchanged }
        let held = snap.records.keys.filter { $0.hasPrefix(License.idPrefix) }.count
        if snap.records[id] == nil, held >= SyncMeta.maxSyncLicenses { return .full }
        snap.records[id] = wrapper
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        return .stored
    }
}
