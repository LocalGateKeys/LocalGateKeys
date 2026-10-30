import Foundation
import Observation
import AuthenticationServices
import SafariServices
import AppKit
import LGKCore

/// Where the Mac reads its connection state from (faked in tests).
@MainActor
protocol ConnectionStateProviding {
    /// Whether the Safari extension is switched on; nil when Safari cannot say.
    func safariExtensionEnabled() async -> Bool?
    /// Whether LocalGateKeys is switched on in System Settings › AutoFill & Passwords.
    func autoFillEnabled() async -> Bool
    /// False when Safari's settings could not be opened (the provider then opens Safari itself).
    func openSafariSettings() async -> Bool
    func openAutoFillSettings()
}

/// The live providers: Safari's extension manager and the credential identity store.
@MainActor
struct SystemConnectionState: ConnectionStateProviding {
    static let safariExtensionID = "app.localgatekeys.app.safari"
    /// System Settings › Passwords (macOS 15; macOS 14 shows AutoFill & Passwords under General).
    static let autoFillURL = URL(string: "x-apple.systempreferences:com.apple.Passwords-Settings.extension")!

    /// Bridges a callback API to async. The handler is `@Sendable` so it never inherits the main actor
    /// (the system calls these completions on a background queue).
    static func bridge<T: Sendable>(_ start: (@escaping @Sendable (T) -> Void) -> Void) async -> T {
        await withCheckedContinuation { (cont: CheckedContinuation<T, Never>) in
            start { value in cont.resume(returning: value) }
        }
    }

    func safariExtensionEnabled() async -> Bool? {
        await Self.bridge { done in
            SFSafariExtensionManager.getStateOfSafariExtension(withIdentifier: Self.safariExtensionID) { @Sendable state, error in
                done(error == nil ? state?.isEnabled : nil)
            }
        }
    }

    func autoFillEnabled() async -> Bool { await ASCredentialIdentityStore.shared.state().isEnabled }

    func openSafariSettings() async -> Bool {
        let ok: Bool = await Self.bridge { done in
            SFSafariApplication.showPreferencesForExtension(withIdentifier: Self.safariExtensionID) { @Sendable error in
                done(error == nil)
            }
        }
        if !ok, let safari = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Safari") {
            NSWorkspace.shared.open(safari)
        }
        return ok
    }

    func openAutoFillSettings() {
        if !NSWorkspace.shared.open(Self.autoFillURL) {
            NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/System Settings.app"))
        }
    }
}

/// Devices & connections (Windows `ConnectionsService.view`): a status card and one row per connection.
@MainActor @Observable
final class ConnectionsModel {
    nonisolated static let title = String(localized: "Devices & connections")
    nonisolated static let subtitle = String(localized: "See which parts of LocalGateKeys are connected on this Mac.")
    nonisolated static let footer = String(localized: "Nothing leaves this Mac. Safari and AutoFill talk to the app through the encrypted vault on this Mac only.")
    nonisolated static let otherBrowsers = String(localized: "Other browsers aren't supported on the Mac yet. Use Safari, or AutoFill in apps that support it.")
    nonisolated static let wifiOff = String(localized: "Off")
    nonisolated static let openSync = String(localized: "Open Sync")
    /// "On · 192.168.1.20:47821" while listening, "On" while starting, "Off".
    nonisolated static func wifiState(on: Bool, endpoint: LanEndpoint?) -> (text: String, ok: Bool?) {
        guard on else { return (wifiOff, nil) }
        guard let endpoint else { return (String(localized: "On"), nil) }
        return (String(localized: "On · \(SyncWording.hostPort(endpoint))"), true)
    }
    /// The Wi-Fi sync row's live state (the window wires it to the sync schedule).
    @ObservationIgnored var wifiState: @MainActor () -> (text: String, ok: Bool?) = { (wifiOff, nil) }

    enum Tone: Equatable { case success, warning, neutral }

    struct Row: Equatable, Identifiable {
        let id: String
        let title: String
        let state: String
        let ok: Bool?
        let action: String?
    }

    private(set) var safari: Bool?
    private(set) var autoFill = false
    private(set) var loaded = false
    @ObservationIgnored private let provider: any ConnectionStateProviding

    init(provider: any ConnectionStateProviding) { self.provider = provider }

    func refresh() async {
        safari = await provider.safariExtensionEnabled()
        autoFill = await provider.autoFillEnabled()
        loaded = true
    }

    nonisolated static let safariFallback = String(localized: "Open Safari › Settings › Extensions to turn on LocalGateKeys.")
    nonisolated static let checking = String(localized: "Checking…")
    /// A short note under the rows (Safari's settings could not be opened directly).
    private(set) var message: String?

    func openSafariSettings() async {
        message = await provider.openSafariSettings() ? nil : Self.safariFallback
    }
    func openAutoFillSettings() { provider.openAutoFillSettings() }

    var headline: String {
        if !loaded { return Self.checking }
        return switch (safari == true, autoFill) {
        case (true, true): String(localized: "Connected on this Mac")
        case (false, false): String(localized: "Connections need setup")
        default: String(localized: "Connection needs attention")
        }
    }

    var summary: String {
        if !loaded { return String(localized: "Looking at Safari and AutoFill.") }
        if safari == nil { return String(localized: "Safari didn't report the extension's state. Press Refresh.") }
        return switch (safari == true, autoFill) {
        case (true, true): String(localized: "The Safari extension and AutoFill are both switched on.")
        case (false, false): String(localized: "Switch on the Safari extension and AutoFill to fill logins and passkeys.")
        case (true, false): String(localized: "The Safari extension is on. Switch on AutoFill to fill in apps and other places.")
        case (false, true): String(localized: "AutoFill is on. Switch on the Safari extension to fill and save in Safari.")
        }
    }

    var status: String { !loaded ? String(localized: "Checking") : (tone == .success ? String(localized: "Ready") : String(localized: "Action needed")) }
    var tone: Tone { !loaded ? .neutral : (safari == true && autoFill ? .success : .warning) }

    var rows: [Row] {
        [Row(id: "safari", title: String(localized: "Safari extension"),
             state: safari == nil ? String(localized: "Unknown") : (safari == true ? String(localized: "Enabled") : String(localized: "Disabled")), ok: safari,
             action: String(localized: "Open Safari settings")),
         Row(id: "autofill", title: String(localized: "AutoFill"), state: autoFill ? String(localized: "Enabled") : String(localized: "Disabled"), ok: autoFill,
             action: String(localized: "Open AutoFill settings")),
         Row(id: "others", title: String(localized: "Other browsers"), state: Self.otherBrowsers, ok: nil, action: nil),
         Row(id: "wifi", title: String(localized: "Wi-Fi sync"), state: wifiState().text, ok: wifiState().ok, action: Self.openSync)]
    }
}

#if DEBUG
/// `LGK_MAC_SHELL_PREVIEW=1`: Safari on, AutoFill off, so the page shows both colours.
@MainActor
struct PreviewConnectionState: ConnectionStateProviding {
    func safariExtensionEnabled() async -> Bool? { true }
    func autoFillEnabled() async -> Bool { false }
    func openSafariSettings() async -> Bool { true }
    func openAutoFillSettings() {}
}
#endif
