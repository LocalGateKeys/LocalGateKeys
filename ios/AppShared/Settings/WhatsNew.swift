import Foundation

/// "What's new" after an update: one sheet per version, shown once after unlock on a device that already had items.
/// A new vault (no items yet) skips it, since the setup pages introduce the app instead.
public enum WhatsNew {
    public struct Item: Equatable, Sendable {
        public let symbol: String
        public let title: String
        public let detail: String
    }

    /// The version these notes describe. Bump it (and `items`) with each release that has something to show.
    public static let version = "1.1"

    public static let title = String(localized: "What's new in LocalGateKeys \(version)")

    public static let items: [Item] = [
        Item(symbol: "square.grid.2x2", title: String(localized: "A new home"),
             detail: String(localized: "Vault, Sync, Security and Settings tabs. Search from the Vault, sort the list and pin favorites.")),
        Item(symbol: "checkmark.shield", title: String(localized: "Security check"),
             detail: String(localized: "A score with weak, reused and old passwords, and logins that could use two-factor codes.")),
        Item(symbol: "applewatch", title: String(localized: "Codes on your Apple Watch"),
             detail: String(localized: "Show the two-factor codes you choose on your wrist.")),
        Item(symbol: "creditcard", title: String(localized: "AutoFill cards and identities"),
             detail: String(localized: "Fill card numbers, addresses and more in any text field (iOS 18 and later).")),
        Item(symbol: "paperclip", title: String(localized: "Attach files"),
             detail: String(localized: "Keep documents and photos in your vault, encrypted, and sync them with your other devices.")),
        Item(symbol: "square.and.arrow.up", title: String(localized: "Share an item securely"),
             detail: String(localized: "Send one item with a six-word code. It opens once, and only with the code.")),
        Item(symbol: "arrow.down.doc", title: String(localized: "Import from any app"),
             detail: String(localized: "Bring passwords over from many password managers and authenticator apps.")),
        Item(symbol: "trash.slash", title: String(localized: "Recently deleted and Undo"),
             detail: String(localized: "Deleted items wait 30 days, and Undo brings one straight back.")),
        Item(symbol: "clock.arrow.circlepath", title: String(localized: "Password history and reminders"),
             detail: String(localized: "See earlier passwords, and get a reminder before a card or document expires.")),
        Item(symbol: "lock.rectangle", title: String(localized: "Optional app password"),
             detail: String(localized: "Open LocalGateKeys with your own password instead of the iPhone passcode.")),
    ]

    /// Show the sheet now? Not twice for one version, not over the setup pages, not on a vault with no items.
    public static func shouldShow(seen: String, itemCount: Int, setupPagesOpen: Bool) -> Bool {
        seen != version && itemCount > 0 && !setupPagesOpen
    }

    /// A new vault never sees this version's sheet later (it learns the app from the setup pages).
    public static func skipsForever(seen: String, itemCount: Int) -> Bool {
        seen != version && itemCount == 0
    }
}
