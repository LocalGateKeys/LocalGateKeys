import SwiftUI
import AppSharedMac

/// The sidebar's Licence page: the plan this Mac is on and the App Store Buy / Restore. Store builds take no
/// licence key (App Store guideline 3.1.1): Pro comes from the App Store purchase or from a licence state received
/// by sync, shown as "Pro from your synced devices". A licence already in the vault stays valid; it is read, never
/// entered. When a licence is held, "Copy key" copies it for a PC (pairing carries it there too).
struct LicencePage: View {
    let pro: ProModel
    let clipboard: MacClipboard
    @Environment(\.macTheme) private var theme

    static let title = String(localized: "Licence")
    static let intro = String(localized: "Pro unlocks unlimited items, 2FA codes and Wi-Fi sync hosting. Buy it on the App Store, or pair this Mac with a device that has Pro.")
    static let syncedText = String(localized: "Pro from your synced devices")
    static let alsoUnlocksWindows = String(localized: "Also unlocks Windows: pair your PC")
    static let copyKeyLabel = String(localized: "Copy key")

    /// The status line under the title.
    static func status(purchased: Bool, license: LicenseInfo?) -> String {
        if purchased { return String(localized: "Pro, bought on the App Store. Everything is unlocked on this Mac.") }
        if let license { return String(localized: "\(syncedText). Updates until \(license.updatesUntil).") }
        return String(localized: "Free plan: up to 4 items. Upgrade to Pro to add more.")
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text(Self.title).font(.system(size: 19, weight: .semibold))
                Text(Self.intro).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                card(pro.isPro ? String(localized: "You have Pro") : String(localized: "Free plan")) {
                    Text(Self.status(purchased: pro.purchased, license: pro.license))
                        .font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true)
                    if !pro.purchased {
                        HStack(spacing: 8) {
                            Button(action: { Task { await pro.buy() } }) {
                                Text(pro.price.map { String(localized: "Buy Pro – \($0)") } ?? String(localized: "Buy Pro"))
                            }
                            .buttonStyle(PillButtonStyle(primary: !pro.isPro)).disabled(pro.busy || !pro.canBuy)
                            Button("Restore purchases") { Task { await pro.restore() } }
                                .buttonStyle(PillButtonStyle(primary: false)).disabled(pro.busy)
                            if pro.busy { ProgressView().controlSize(.small) }
                        }
                        if let m = pro.message { note(m, theme.warning) }
                    }
                    if let key = pro.licenceKey {
                        Text(Self.alsoUnlocksWindows).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                            .fixedSize(horizontal: false, vertical: true)
                        HStack {
                            Button(Self.copyKeyLabel) { clipboard.copy(key, concealed: true) }
                                .buttonStyle(PillButtonStyle(primary: false))
                            Spacer()
                        }
                    }
                }
            }
            .foregroundStyle(theme.text)
            .padding(18)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .task { await pro.loadPrice() }
    }

    private func note(_ text: String, _ color: Color) -> some View {
        Text(text).font(.system(size: 12.5)).foregroundStyle(color).fixedSize(horizontal: false, vertical: true)
    }

    private func card<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.system(size: 15, weight: .semibold))
            content()
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading)
        .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
    }
}
