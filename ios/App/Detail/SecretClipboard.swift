import UIKit
import UniformTypeIdentifiers
import AppShared

/// The part of `UIPasteboard` the app writes through, so a test can read back the options.
@MainActor
protocol PasteboardWriting: AnyObject {
    func setItems(_ items: [[String: Any]], options: [UIPasteboard.OptionsKey: Any])
    var changeCount: Int { get }
}

extension UIPasteboard: PasteboardWriting {}

/// Copies secrets local-only (never to Universal Clipboard) with the expiry chosen in Settings (60 seconds by
/// default). The app shares one instance so locking can clear what the detail screen copied.
@MainActor
final class SecretClipboard {
    static let shared = SecretClipboard()
    let pasteboard: any PasteboardWriting
    let clock: any UnixClock
    let settings: AppSettings
    /// The pasteboard's changeCount right after our last copy, or nil when we hold nothing.
    private(set) var ownChangeCount: Int?

    init(pasteboard: any PasteboardWriting = UIPasteboard.general, clock: any UnixClock = SystemClock(),
         settings: AppSettings = .shared) {
        self.pasteboard = pasteboard; self.clock = clock; self.settings = settings
    }

    var expiry: Int64 { settings.clipboardExpiry.rawValue }

    func copy(_ text: String) {
        pasteboard.setItems([[UTType.utf8PlainText.identifier: text]], options: [
            .localOnly: true,
            .expirationDate: Date(timeIntervalSince1970: TimeInterval(clock.now + expiry)),
        ])
        ownChangeCount = pasteboard.changeCount
    }

    /// Clears the pasteboard only if it still holds our copy (the user may have copied something else since).
    func clearIfOwned() {
        defer { ownChangeCount = nil }
        guard let own = ownChangeCount, pasteboard.changeCount == own else { return }
        pasteboard.setItems([], options: [:])
    }
}
