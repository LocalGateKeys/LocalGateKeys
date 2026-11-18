import SwiftUI
import AuthenticationServices
import AppSharedMac

/// The Mac's passkey check (feature pack §6.2), read only and best effort: whether LocalGateKeys is turned on as a
/// passkey and password provider (`ASCredentialIdentityStore` state), whether Offer passkeys is on, and how many
/// passkeys are saved. Nothing is sent anywhere.
@MainActor
enum MacPasskeyDoctor {
    /// `unknown` until the system answered (never shown as `off`).
    enum Status: Equatable { case on, off, unknown }

    static func status(enabled: Bool?) -> Status {
        switch enabled {
        case true?: .on
        case false?: .off
        case nil: .unknown
        }
    }

    static func text(_ status: Status) -> String {
        switch status {
        case .on: String(localized: "LocalGateKeys can save and use passkeys on this device.")
        case .off: String(localized: "LocalGateKeys isn't turned on for passkeys yet.")
        case .unknown: String(localized: "This device didn't say whether LocalGateKeys is turned on.")
        }
    }

    static var howTo: String {
        String(localized: "Turn on LocalGateKeys under Passwords or Passkeys in your device settings. Turn off other managers there if passkeys keep going to them.")
    }

    struct Check: Equatable, Identifiable {
        let id: String
        let title: String
        let advice: String
    }

    /// The checks after the provider's: Offer passkeys off, no passkey saved yet (the iPhone's wording).
    static func otherChecks(offerPasskeys: Bool, passkeyCount: Int) -> [Check] {
        var out: [Check] = []
        if !offerPasskeys {
            out.append(Check(id: "offerPasskeys", title: String(localized: "Offer passkeys is off"),
                             advice: String(localized: "Turn on Offer passkeys in Settings › AutoFill.")))
        }
        if passkeyCount == 0 {
            out.append(Check(id: "saved", title: String(localized: "No passkeys saved yet"),
                             advice: String(localized: "On a site that offers passkeys, create one and choose LocalGateKeys to save it.")))
        }
        return out
    }

    /// Live, not deleted `passkey` items.
    static func passkeyCount(_ snapshot: StoreSnapshot) -> Int {
        snapshot.itemRecords.filter { id, wrapper in
            guard snapshot.meta[id]?.deleted != true, case .object(let w) = wrapper, case .object(let r)? = w["record"] else { return false }
            return r["kind"] == .string("passkey")
        }.count
    }

    static func providerEnabled() async -> Bool { await ASCredentialIdentityStore.shared.state().isEnabled }

    /// System Settings › the credential provider list (macOS 14+), else the Passwords pane.
    static func openSettings() async {
        do {
            try await ASSettingsHelper.openCredentialProviderAppSettings()
        } catch {
            SystemConnectionState().openAutoFillSettings()
        }
    }
}

/// Settings › AutoFill › Passkey check.
struct MacPasskeyCheckSection: View {
    let store: (any ItemStore)?
    let offerPasskeys: Bool
    @Environment(\.macTheme) private var theme
    @State private var status = MacPasskeyDoctor.Status.unknown
    @State private var checked = false
    @State private var passkeys = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: status == .on ? "checkmark.circle" : "exclamationmark.triangle")
                    .foregroundStyle(status == .on ? theme.success : theme.warning).accessibilityHidden(true)
                Text(checked ? MacPasskeyDoctor.text(status) : String(localized: "Checking…")).font(.system(size: 13))
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
            if status != .on {
                Text(MacPasskeyDoctor.howTo).font(.system(size: 11)).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if store != nil {
                ForEach(MacPasskeyDoctor.otherChecks(offerPasskeys: offerPasskeys, passkeyCount: passkeys)) { check in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(check.title).font(.system(size: 13))
                        Text(check.advice).font(.system(size: 11)).foregroundStyle(theme.textMuted)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .accessibilityElement(children: .combine)
                }
            }
            HStack {
                Spacer()
                Button(String(localized: "Refresh")) { Task { await refresh() } }.buttonStyle(PillButtonStyle(primary: false))
                Button(String(localized: "Open AutoFill settings")) { Task { await MacPasskeyDoctor.openSettings() } }
                    .buttonStyle(PillButtonStyle(primary: false))
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .task { await refresh() }
    }

    private func refresh() async {
        status = MacPasskeyDoctor.status(enabled: await MacPasskeyDoctor.providerEnabled())
        checked = true
        passkeys = (try? store?.load()).map { MacPasskeyDoctor.passkeyCount($0) } ?? 0
    }
}
