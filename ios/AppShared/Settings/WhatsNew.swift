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
    public static let version = "1.2"

    public static let title = String(localized: "What's new in LocalGateKeys \(version)")

    public static let items: [Item] = [
        Item(symbol: "globe", title: String(localized: "whatsNew.1.2.languages.title", defaultValue: "Eleven languages"),
             detail: (DeviceText.isPad ? String(localized: "ipad.whatsNew.1.2.languages.detail", defaultValue: "LocalGateKeys follows your iPad's language: English, French, German, Spanish, Italian, Dutch, Polish, Brazilian Portuguese, Japanese, Korean or Simplified Chinese.") : String(localized: "whatsNew.1.2.languages.detail", defaultValue: "LocalGateKeys follows your iPhone's language: English, French, German, Spanish, Italian, Dutch, Polish, Brazilian Portuguese, Japanese, Korean or Simplified Chinese."))),
        Item(symbol: "key.horizontal", title: String(localized: "whatsNew.1.2.factors.title", defaultValue: "Key file and YubiKey"),
             detail: String(localized: "whatsNew.1.2.factors.detail", defaultValue: "Add a key file or a YubiKey (NFC) to your app password, so the vault needs both to open.")),
        Item(symbol: "arrow.counterclockwise", title: String(localized: "whatsNew.1.2.restore.title", defaultValue: "Restore a backup"),
             detail: String(localized: "whatsNew.1.2.restore.detail", defaultValue: "Bring back a phone backup (.lgkm) from Settings › Import & Export. It is merged in, and nothing is wiped.")),
        Item(symbol: "checkmark.shield", title: String(localized: "whatsNew.1.2.security.title", defaultValue: "A sharper Security check"),
             detail: String(localized: "whatsNew.1.2.security.detail", defaultValue: "Spot logins on sites without HTTPS, and sites that offer two-factor codes or passkeys you don't use yet.")),
        Item(symbol: "text.alignleft", title: String(localized: "whatsNew.1.2.notes.title", defaultValue: "Formatted notes"),
             detail: String(localized: "whatsNew.1.2.notes.detail", defaultValue: "Notes show headings, lists, checklists and code. Turn off Show formatting to see the plain text.")),
        Item(symbol: "wifi", title: String(localized: "whatsNew.1.2.wifi.title", defaultValue: "Wi-Fi QR code"),
             detail: String(localized: "whatsNew.1.2.wifi.detail", defaultValue: "Show a Wi-Fi item as a QR code, and a guest's phone joins by scanning it.")),
        Item(symbol: "questionmark.bubble", title: String(localized: "whatsNew.1.2.answers.title", defaultValue: "Security question answers"),
             detail: String(localized: "whatsNew.1.2.answers.detail", defaultValue: "The generator's Answer mode makes up answers no one can guess from your life.")),
        Item(symbol: "printer", title: String(localized: "whatsNew.1.2.kit.title", defaultValue: "Emergency kit"),
             detail: String(localized: "whatsNew.1.2.kit.detail", defaultValue: "Print your recovery steps and backup details, and keep them somewhere safe.")),
        Item(symbol: "iphone.slash", title: String(localized: "whatsNew.1.2.removal.title", defaultValue: "Remove a lost device"),
             detail: String(localized: "whatsNew.1.2.removal.detail", defaultValue: "Take a device out of sync from the Sync tab. Its copy of the vault is erased the next time it opens.")),
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
