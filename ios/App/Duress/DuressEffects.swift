import Foundation
import UserNotifications
import AppShared

/// What the iPhone does around a duress-password session (sub-plan 08, Task 5c), beside the store itself.
@MainActor
enum DuressEffects {
    /// The second vault opened (the real one is now held): the real vault's widget pins freeze as they are, its
    /// AutoFill suggestions leave the QuickType bar and its pending reminder notifications are withdrawn (nothing
    /// of the real vault shows while it is held; all come back at its next unlock).
    static func secondVaultOpened() {
        WatchCodes.shared.freezeForSecondVault()
        Task { try? await SystemCredentialIdentityStore().removeAll() }
        withdrawReminders()
    }

    /// The real vault opened: its pins work again (its reminders and suggestions are planned again by the unlock).
    static func realVaultOpened() {
        WatchCodes.shared.frozen = false
    }

    /// Removes this app's pending and delivered reminder notifications.
    /// The async API (review M3): no completion closure is formed on the main actor, so nothing traps under Swift 6
    /// when UserNotifications answers on its own queue.
    static func withdrawReminders() {
        let prefix = PhoneReminders.prefix
        Task.detached(priority: .userInitiated) {
            let centre = UNUserNotificationCenter.current()
            let pending = await centre.pendingNotificationRequests().map(\.identifier).filter { $0.hasPrefix(prefix) }
            centre.removePendingNotificationRequests(withIdentifiers: pending)
            let delivered = await centre.deliveredNotifications().map(\.request.identifier).filter { $0.hasPrefix(prefix) }
            centre.removeDeliveredNotifications(withIdentifiers: delivered)
        }
    }
}
