import AppKit
import AppSharedMac

/// Keeps every LocalGateKeys window (main window, sheets, Settings, the menu bar panel) out of screenshots, screen
/// recordings and screen sharing with `NSWindow.sharingType = .none`, like the Windows app's `hide_from_capture`
/// (`docs/SECURITY_HARDENING_2026-10-30.md` WP-B). On by default; Settings › Privacy turns it off. This only stops
/// other apps from capturing the windows; LocalGateKeys itself never captures the screen.
@MainActor
final class CaptureProtection {
    static let key = "settings.mac.hideFromCapture"
    static let shared = CaptureProtection()

    private var observer: NSObjectProtocol?

    /// The setting; debug builds take `LGK_MAC_ALLOW_CAPTURE=1` so screenshot runs can still capture the window.
    static var isOn: Bool {
        #if DEBUG
        if ProcessInfo.processInfo.environment["LGK_MAC_ALLOW_CAPTURE"] == "1" { return false }
        #endif
        // Release builds ignore a `-settings.mac.hideFromCapture NO` launch argument: only the stored value counts.
        return value(PersistentDefaults.object(.standard, forKey: key, domainName: Bundle.main.bundleIdentifier))
    }

    /// On unless the stored value says off (Bool, or "YES"/"NO" text as `bool(forKey:)` reads it).
    static func value(_ stored: Any?) -> Bool {
        switch stored {
        case nil: return true
        case let b as Bool: return b
        case let s as String: return (s as NSString).boolValue
        case let n as NSNumber: return n.boolValue
        default: return true
        }
    }

    /// Applies the setting to the open windows and, from then on, to every window that opens later.
    func start() {
        apply()
        guard observer == nil else { return }
        // Posted once per pass of the event loop: a new sheet or panel is covered before it is drawn twice.
        observer = NotificationCenter.default.addObserver(forName: NSApplication.didUpdateNotification, object: nil,
                                                          queue: .main) { _ in
            MainActor.assumeIsolated { CaptureProtection.shared.apply() }
        }
    }

    func apply() {
        let sharing: NSWindow.SharingType = Self.isOn ? .none : .readOnly
        for window in NSApplication.shared.windows where window.sharingType != sharing {
            window.sharingType = sharing
        }
    }
}
