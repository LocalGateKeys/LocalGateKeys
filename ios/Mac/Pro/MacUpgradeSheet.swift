import SwiftUI
import AppSharedMac

/// The Pro upgrade sheet, shown when the free plan says no (the editor's `onNeedsPro`). The reason line is
/// the subtitle; Buy and Restore go through the shared `ProModel` (the same `pro_unlimited` purchase as on
/// the iPhone, universal purchase).
struct MacUpgradeSheet: View {
    static let proStatus = String(localized: "Everything is unlocked on this Mac.")

    let pro: ProModel
    let reason: ProReason
    let onClose: () -> Void
    @Environment(\.macTheme) private var theme

    static func subtitle(_ reason: ProReason) -> String {
        UpgradePrompt.message(reason)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "sparkles").font(.system(size: 24)).foregroundStyle(theme.accent)
                Text(pro.isPro ? String(localized: "You have Pro") : String(localized: "Upgrade to Pro")).font(.title2.weight(.semibold)).foregroundStyle(theme.text)
            }
            Text(pro.isPro ? Self.proStatus : Self.subtitle(reason))
                .font(.callout).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            if !pro.isPro {
                VStack(alignment: .leading, spacing: 8) {
                    feature("infinity", String(localized: "Unlimited items"))
                    feature("number.square", String(localized: "2FA codes for your logins"))
                    feature("arrow.triangle.2.circlepath", String(localized: "Wi-Fi sync hosting and new sync groups"))
                    feature("iphone.and.arrow.forward", String(localized: "One purchase for this Mac and your iPhone"))
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
                MessageLine(text: pro.message)
                Button(action: { Task { await pro.buy() } }) {
                    if pro.busy { ProgressView().controlSize(.small).tint(theme.onAccent) }
                    else { Text(pro.price.map { String(localized: "Buy Pro – \($0)") } ?? String(localized: "Buy Pro")) }
                }
                .buttonStyle(AccentButtonStyle())
                .disabled(pro.busy || !pro.canBuy)
                Button("Restore purchases") { Task { await pro.restore() } }
                    .buttonStyle(GlassButtonStyle())
                    .disabled(pro.busy)
            }
            Button(pro.isPro ? String(localized: "Done") : String(localized: "Not now"), action: onClose)
                .buttonStyle(GlassButtonStyle())
                .keyboardShortcut(.cancelAction)
        }
        .padding(26)
        .frame(width: 400)
        .background(WashBackground())
        .task { await pro.loadPrice() }
    }

    private func feature(_ symbol: String, _ text: String) -> some View {
        Label { Text(text).foregroundStyle(theme.text) } icon: { Image(systemName: symbol).foregroundStyle(theme.accent) }
            .font(.system(size: 13))
    }
}
