import Foundation
import Observation
import AppSharedMac

/// Credential Exchange on the Mac (macOS 26): the Passwords app's File › Export Data to Another App opens the
/// app with a one-time token (`ASCredentialExchangeActivity`). The token is kept here, in memory only, until the
/// vault is unlocked; the window then opens Import & export and reads the data into the review
/// (`ImportExportModel.importFromApplePasswords`), so nothing is saved without the review.
@MainActor @Observable
final class MacCredentialExchangeInbox {
    private(set) var pending: UUID?

    /// Keeps the token a Credential Exchange activity carries (the latest wins); other activities are ignored.
    func receive(_ activity: NSUserActivity) {
        guard #available(macOS 26, *), let token = CredentialExchangeImport.token(from: activity) else { return }
        pending = token
    }

    /// Test seam.
    func receive(token: UUID) { pending = token }

    func take() -> UUID? {
        defer { pending = nil }
        return pending
    }
}
