import SwiftUI
import AppShared

/// The upgrade sheet: the in-app purchase, "Restore purchases" and the Privacy Policy and Licence Agreement
/// (the only links out of the app here, to the website's legal pages).
/// The free plan's item slots are drawn as a capacity strip (filled for each item saved when `itemsUsed` is
/// known), ending in the unlimited tile Pro opens up; the purchase sits in a bar pinned to the bottom.
struct UpgradeView: View {
    let pro: ProModel
    /// Live items in the vault, for the capacity strip; nil where the caller does not have the count.
    var itemsUsed: Int? = nil
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 22) {
                    header
                    CapacityStrip(used: itemsUsed, isPro: pro.isPro)
                    benefits
                    Text("Sync with your PC needs Pro on the PC as well.")
                        .font(.footnote).foregroundStyle(Palette.secondaryText)
                        .multilineTextAlignment(.center)
                }
                .padding(.horizontal, 24).padding(.top, 8).padding(.bottom, 24)
                .frame(maxWidth: 520)
                .frame(maxWidth: .infinity)
            }
            .safeAreaInset(edge: .bottom) { purchaseBar }
            .lgkAuroraBackground()
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } } }
            .task { await pro.refresh(); await pro.loadPrice() }
        }
    }

    private var header: some View {
        VStack(spacing: 10) {
            Image("BrandMark").resizable().aspectRatio(contentMode: .fit).frame(width: 72, height: 72)
                .shadow(color: Palette.glowBlue.opacity(0.45), radius: 24, y: 8)
                .accessibilityHidden(true)
            Text("LocalGateKeys Pro").font(.largeTitle.bold()).foregroundStyle(Palette.text)
            Text(pro.isPro ? "Everything is unlocked on this iPhone."
                           : "Pay once for unlimited items and two\u{2011}factor codes.")
                .font(.title3).foregroundStyle(Palette.secondaryText).multilineTextAlignment(.center)
        }
    }

    private var benefits: some View {
        VStack(alignment: .leading, spacing: 16) {
            Benefit(symbol: "square.stack.3d.up.fill", title: "Unlimited items",
                    detail: "Logins, cards, notes and everything else, past the free \(ItemLimit.freeItems).")
            Benefit(symbol: "number.square.fill", title: "Two-factor codes",
                    detail: "Add and change 2FA codes. Codes you already saved keep working without Pro.")
            Benefit(symbol: "checkmark.seal.fill", title: "One payment",
                    detail: "No subscription and no account. Restore it on another iPhone with the same Apple Account.")
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.groupSurface, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
    }

    private var purchaseBar: some View {
        VStack(spacing: 10) {
            if pro.isPro {
                Label("Pro is active", systemImage: "checkmark.seal.fill")
                    .font(.headline).foregroundStyle(Palette.success)
                    .frame(maxWidth: .infinity, minHeight: 52)
            } else {
                Button {
                    Task { await pro.buy(); if pro.isPro { dismiss() } }
                } label: {
                    Group {
                        if pro.busy { ProgressView().tint(.white) }
                        else { Text(pro.price.map { "Buy for \($0)" } ?? "Buy Pro") }
                    }
                    .font(.headline).frame(maxWidth: .infinity, minHeight: 52)
                }
                .buttonStyle(.borderedProminent).buttonBorderShape(.capsule).tint(Palette.accent)
                .disabled(pro.busy || !pro.canBuy)
                Text("One-time purchase, no subscription.")
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
                Button("Restore purchases") {
                    Task { await pro.restore(); if pro.isPro { dismiss() } }
                }
                .font(.subheadline).foregroundStyle(Palette.accentText).disabled(pro.busy)
            }
            if let message = pro.message {
                Text(message).font(.footnote).foregroundStyle(Palette.secondaryText).multilineTextAlignment(.center)
            }
            HStack(spacing: 20) {
                Link("Privacy Policy", destination: SettingsView.privacyPolicyURL)
                Link("Licence Agreement", destination: SettingsView.licenceAgreementURL)
            }
            .font(.footnote).foregroundStyle(Palette.secondaryText)
        }
        .padding(.horizontal, 24).padding(.top, 14).padding(.bottom, 8)
        .frame(maxWidth: 520)
        .frame(maxWidth: .infinity)
        .background(.ultraThinMaterial)
    }
}

/// One line of what Pro adds: a symbol in an accent tile, a title and one sentence.
private struct Benefit: View {
    let symbol: String
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: symbol).font(.system(size: 18, weight: .semibold)).foregroundStyle(Palette.accentText)
                .frame(width: 40, height: 40)
                .background(Palette.accent.opacity(0.16), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline).foregroundStyle(Palette.text)
                Text(detail).font(.subheadline).foregroundStyle(Palette.secondaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// The free plan's slots, one tile each, filled for every item saved (all filled once Pro is active), then the
/// wider unlimited tile. With no count, the slots are drawn empty and the caption gives the free limit.
private struct CapacityStrip: View {
    let used: Int?
    let isPro: Bool

    var body: some View {
        VStack(spacing: 10) {
            HStack(spacing: 8) {
                ForEach(0..<ItemLimit.freeItems, id: \.self) { slot in
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(filled(slot) ? Palette.accent.opacity(0.85) : Palette.groupSurface)
                        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .strokeBorder(Palette.accent.opacity(filled(slot) ? 0 : 0.35), lineWidth: 1.5))
                        .frame(width: 46, height: 46)
                }
                Image(systemName: "infinity").font(.system(size: 22, weight: .bold)).foregroundStyle(.white)
                    .frame(maxWidth: .infinity, minHeight: 46)
                    .background(LinearGradient(colors: [Palette.accent, Palette.glowBlue], startPoint: .leading,
                                               endPoint: .trailing),
                                in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
            Text(caption).font(.footnote.weight(.medium)).foregroundStyle(Palette.secondaryText)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(caption)
    }

    private func filled(_ slot: Int) -> Bool { isPro || slot < min(used ?? 0, ItemLimit.freeItems) }

    private var caption: String {
        if isPro { return "No limit on items" }
        guard let used else { return "Free: \(ItemLimit.freeItems) items. Pro: no limit." }
        return "\(min(used, ItemLimit.freeItems)) of \(ItemLimit.freeItems) free items used. Pro: no limit."
    }
}
