import Foundation
import AuthenticationServices
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// Credential Exchange (iOS 26): the Passwords app (or another provider) hands the app a one-time token
/// through a user activity; the data it unlocks is mapped through `CXFImport`.
@available(iOS 26, macOS 26, *)
enum CredentialExchangeImport {
    /// Encodes each account as its CXF JSON and reads it with `CXFImport`.
    static func candidates(from data: ASExportedCredentialData) throws -> (candidates: [ImportCandidate], unsupported: Int) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        var all = [ImportCandidate]()
        var unsupported = 0
        for account in data.accounts {
            let r = try CXFImport.candidates(fromAccountJSON: try encoder.encode(account))
            all += r.candidates
            unsupported += r.unsupported
        }
        return (all, unsupported)
    }

    /// The import token a Credential Exchange activity carries, if any.
    static func token(from activity: NSUserActivity) -> UUID? {
        guard activity.activityType == ASCredentialExchangeActivity else { return nil }
        if let id = activity.userInfo?[ASCredentialImportToken] as? UUID { return id }
        return (activity.userInfo?[ASCredentialImportToken] as? String).flatMap(UUID.init(uuidString:))
    }
}

/// Holds a Credential Exchange token (memory only) until the vault is unlocked, then imports with it.
/// The import runs in a task the model owns, once per token, so view updates never cancel it; the token is
/// dropped only when the import has finished (or definitively failed), so a cancelled run can be retried.
@MainActor @Observable
final class CredentialExchangeModel {
    /// The string value of `ASCredentialExchangeActivity` (iOS 26), usable on iOS 17 for `onContinueUserActivity`.
    nonisolated static let activityType = "ASCredentialExchangeActivity"
    static let exchangeFailedMessage = String(localized: "The export was cancelled or has expired. Export again from the Passwords app.")
    static let unreadableMessage = String(localized: "The exported data couldn't be read.")

    enum FetchError: Error { case exchange, unreadable }
    typealias Fetch = @MainActor (UUID) async throws -> (candidates: [ImportCandidate], unsupported: Int)

    private(set) var pendingToken: UUID?
    private(set) var isRunning = false
    /// The notice (or failure) to show after the import.
    var message: String?
    private let fetch: Fetch

    init(fetch: Fetch? = nil) { self.fetch = fetch ?? Self.liveFetch }

    static func liveFetch(_ token: UUID) async throws -> (candidates: [ImportCandidate], unsupported: Int) {
        guard #available(iOS 26, macOS 26, *) else { throw FetchError.exchange }
        let data: ASExportedCredentialData
        do { data = try await ASCredentialImportManager().importCredentials(token: token) } catch is CancellationError {
            throw CancellationError()
        } catch { throw FetchError.exchange }
        do { return try CredentialExchangeImport.candidates(from: data) } catch { throw FetchError.unreadable }
    }

    func received(_ activity: NSUserActivity) {
        guard #available(iOS 26, macOS 26, *), let token = CredentialExchangeImport.token(from: activity) else { return }
        pendingToken = token
    }

    /// Test seam and activity-free entry point.
    func received(token: UUID) { pendingToken = token }

    /// Starts the pending import unless one is already running. Returns the task (for tests).
    @discardableResult
    func start(importer: VaultImporter) -> Task<Void, Never>? {
        guard !isRunning, let token = pendingToken else { return nil }
        isRunning = true
        return Task { await run(token, importer: importer) }
    }

    private func run(_ token: UUID, importer: VaultImporter) async {
        defer { isRunning = false }
        do {
            let r = try await fetch(token)
            let result = try importer.importCandidates(r.candidates, unsupported: r.unsupported)
            message = result.notice.isEmpty ? String(localized: "Nothing to import.") : result.notice
        } catch is CancellationError {
            return   // keep the token: the next start retries it
        } catch FetchError.unreadable {
            message = Self.unreadableMessage
        } catch FetchError.exchange {
            message = Self.exchangeFailedMessage
        } catch {
            message = String(localized: "The passwords could not be saved.")
        }
        if pendingToken == token { pendingToken = nil }
    }
}
