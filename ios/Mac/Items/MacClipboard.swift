import AppKit
import AppSharedMac

/// Copies to the pasteboard and clears it again, the Mac counterpart of the iPhone's `SecretClipboard`:
/// secrets are marked `org.nspasteboard.ConcealedType` (clipboard managers and Universal Clipboard history
/// skip them), and after `clearAfter` seconds (Settings › clipboard expiry, 60 s by default as on the iPhone),
/// or when the vault locks, the pasteboard is cleared only if it still holds what we copied — the
/// `changeCount` is unchanged — so something the person copied since is never touched.
@MainActor
final class MacClipboard: SecretCopying {
    static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")

    /// The app's instance: the general pasteboard, the Settings expiry read at each copy.
    static let shared = MacClipboard(pasteboard: .general, clock: SystemClock(),
                                     clearAfter: TimeInterval(AppSettings.shared.clipboardExpiry.rawValue),
                                     settings: .shared)

    let pasteboard: NSPasteboard
    let clock: any UnixClock
    /// Seconds until a copy is cleared; refreshed from `settings` (when given) at each copy.
    private(set) var clearAfter: TimeInterval
    private let settings: AppSettings?
    /// The pasteboard's changeCount right after our last copy, or nil when we hold nothing.
    private(set) var ownChangeCount: Int?
    /// Unix seconds after which our copy is cleared.
    private(set) var expiresAt: Int64?
    private var timer: Task<Void, Never>?

    init(pasteboard: NSPasteboard, clock: any UnixClock, clearAfter: TimeInterval, settings: AppSettings? = nil) {
        self.pasteboard = pasteboard; self.clock = clock; self.clearAfter = clearAfter; self.settings = settings
    }

    func copy(_ secret: String, concealed: Bool) {
        if let settings { clearAfter = TimeInterval(settings.clipboardExpiry.rawValue) }
        pasteboard.clearContents()
        if concealed {
            pasteboard.declareTypes([.string, Self.concealedType], owner: nil)
            pasteboard.setData(Data(), forType: Self.concealedType)
        }
        pasteboard.setString(secret, forType: .string)
        ownChangeCount = pasteboard.changeCount
        expiresAt = clock.now + Int64(clearAfter.rounded(.up))
        schedule()
    }

    /// `SecretCopying` (the shared detail model): everything it copies is treated as a secret.
    func copy(_ text: String) { copy(text, concealed: true) }

    /// Clears the pasteboard only if it still holds our copy.
    func clearIfOurs() {
        timer?.cancel(); timer = nil
        defer { ownChangeCount = nil; expiresAt = nil }
        guard let own = ownChangeCount, pasteboard.changeCount == own else { return }
        pasteboard.clearContents()
    }

    /// Clears our copy once its time is up; the timer calls this, tests call it after moving the clock.
    func clearIfExpired() {
        guard let expiresAt, clock.now >= expiresAt else { return }
        clearIfOurs()
    }

    private func schedule() {
        timer?.cancel()
        let delay = clearAfter
        timer = Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled else { return }
            self?.clearIfOurs()   // the timer belongs to the latest copy (each copy restarts it)
        }
    }
}
