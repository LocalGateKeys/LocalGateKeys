import AppKit
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
    /// Tokens already handed to the window: the same activity can arrive through both the app delegate and the
    /// SwiftUI scene, and a token is good for one import only.
    private var taken: Set<UUID> = []

    /// Keeps the token a Credential Exchange activity carries (the latest wins); other activities are ignored.
    /// Returns true when the activity was a Credential Exchange one.
    @discardableResult func receive(_ activity: NSUserActivity) -> Bool {
        guard #available(macOS 26, *), let token = CredentialExchangeImport.token(from: activity) else { return false }
        receive(token: token)
        return true
    }

    /// Test seam.
    func receive(token: UUID) {
        guard !taken.contains(token) else { return }
        pending = token
    }

    func take() -> UUID? {
        defer { pending = nil }
        if let pending { taken.insert(pending) }
        return pending
    }
}

/// macOS hands the Passwords app's export to the app delegate (`application(_:continue:restorationHandler:)`);
/// SwiftUI's `onContinueUserActivity` alone missed it, so the import never started (Mac 1.1 report).
final class MacAppDelegate: NSObject, NSApplicationDelegate {
    func application(_ application: NSApplication, willContinueUserActivityWithType userActivityType: String) -> Bool {
        userActivityType == CredentialExchangeModel.activityType
    }

    func application(_ application: NSApplication, continue userActivity: NSUserActivity,
                     restorationHandler: @escaping ([any NSUserActivityRestoring]) -> Void) -> Bool {
        MainActor.assumeIsolated {
            guard MacAppEnvironment.credentialExchange.receive(userActivity) else { return false }
            QuickAccessBridge.activate()
            return true
        }
    }
}
