import Foundation
import Observation
import AuthenticationServices

/// Settings › AutoFill: whether LocalGateKeys is the enabled provider, re-checked whenever the app becomes
/// active again (the person usually comes back from the Settings app), and the "Open AutoFill settings"
/// failure shown instead of swallowed.
@MainActor
@Observable
final class AutoFillStatusModel {
    private(set) var enabled: Bool?
    private(set) var openError: String?

    static let openFailedMessage = String(localized: "AutoFill settings could not be opened. Open the Settings app › General › AutoFill & Passwords and turn on LocalGateKeys.")

    @ObservationIgnored private let isEnabled: @MainActor () async -> Bool
    @ObservationIgnored private let open: @MainActor () async throws -> Void

    init(isEnabled: @escaping @MainActor () async -> Bool, openSettings: @escaping @MainActor () async throws -> Void) {
        self.isEnabled = isEnabled; self.open = openSettings
    }

    static func live() -> AutoFillStatusModel {
        AutoFillStatusModel(isEnabled: { await SystemCredentialIdentityStore().isEnabled() },
                            openSettings: { try await ASSettingsHelper.openCredentialProviderAppSettings() })
    }

    func refresh() async {
        enabled = await isEnabled()
        if enabled == true { openError = nil }
    }

    func openSettings() async {
        do { try await open(); openError = nil } catch { openError = Self.openFailedMessage }
    }
}
