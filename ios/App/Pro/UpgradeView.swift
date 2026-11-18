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
                    Text("Also unlocks Windows: pair your PC.")
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
            Text(pro.isPro ? (DeviceText.isPad ? String(localized: "ipad.upgradeView.everythingUnlocked", defaultValue: "Everything is unlocked on this iPad.") : String(localized: "Everything is unlocked on this iPhone."))
                           : String(localized: "Pay once for unlimited items, sync, two\u{2011}factor codes and attachments."))
                .font(.title3).foregroundStyle(Palette.secondaryText).multilineTextAlignment(.center)
        }
    }

    private var benefits: some View {
        VStack(alignment: .leading, spacing: 16) {
            Benefit(symbol: "square.stack.3d.up.fill", title: String(localized: "Unlimited items"),
                    detail: String(localized: "Logins, cards, notes and everything else, past the free \(ItemLimit.freeItems)."))
            Benefit(symbol: "number.square.fill", title: String(localized: "Two-factor codes"),
                    detail: String(localized: "Add and change 2FA codes. Codes you already saved keep working without Pro."))
            Benefit(symbol: "checkmark.seal.fill", title: String(localized: "One payment"),
                    detail: (DeviceText.isPad ? String(localized: "ipad.upgradeView.noSubscriptionAndNo", defaultValue: "No subscription and no account. Restore it on another iPad with the same Apple Account.") : String(localized: "No subscription and no account. Restore it on another iPhone with the same Apple Account.")))
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
                        if pro.busy { ProgressView().tint(Palette.onAccent) }
                        else { Text(pro.price.map { String(localized: "Buy for \($0)") } ?? String(localized: "Buy Pro")) }
                    }
                    .font(.headline).frame(maxWidth: .infinity, minHeight: 52)
                }
                .buttonStyle(.borderedProminent).buttonBorderShape(.capsule).tint(Palette.accent).foregroundStyle(Palette.onAccent)
                .disabled(pro.busy || !pro.canBuy)
                Text("One payment. Every update, forever, free. No subscription.")
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
    /// The tile grows with Dynamic Type (review 2026-11-15, UX 3).
    @ScaledMetric(relativeTo: .headline) var iconSize: CGFloat = 18
    @ScaledMetric(relativeTo: .headline) var tileSize: CGFloat = 40

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: symbol).font(.system(size: iconSize, weight: .semibold)).foregroundStyle(Palette.accentText)
                .frame(width: tileSize, height: tileSize)
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

/// The free plan's slots, one tile each in rows of five so they fit a narrow phone, filled for every item saved (all
/// filled once Pro is active), then a full-width unlimited tile. With no count, the slots are drawn empty and the
/// caption gives the free limit.
private struct CapacityStrip: View {
    let used: Int?
    let isPro: Bool
    @ScaledMetric(relativeTo: .title3) var infinitySize: CGFloat = 20
    @ScaledMetric(relativeTo: .title3) var infinityHeight: CGFloat = 36

    var body: some View {
        VStack(spacing: 8) {
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 6), count: ItemLimit.freeItems), spacing: 6) {
                ForEach(0..<ItemLimit.freeItems, id: \.self) { slot in
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .fill(filled(slot) ? Palette.accent.opacity(0.85) : Palette.groupSurface)
                        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .strokeBorder(Palette.accent.opacity(filled(slot) ? 0 : 0.35), lineWidth: 1.5))
                        .frame(height: 28)
                }
            }
            Image(systemName: "infinity").font(.system(size: infinitySize, weight: .bold)).foregroundStyle(.white)
                .frame(maxWidth: .infinity, minHeight: infinityHeight)
                .background(LinearGradient(colors: [Palette.accent, Palette.glowBlue], startPoint: .leading,
                                           endPoint: .trailing),
                            in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            Text(caption).font(.footnote.weight(.medium)).foregroundStyle(Palette.secondaryText)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(caption)
    }

    private func filled(_ slot: Int) -> Bool { isPro || slot < min(used ?? 0, ItemLimit.freeItems) }

    private var caption: String {
        if isPro { return String(localized: "No limit on items") }
        guard let used else { return String(localized: "Free: \(ItemLimit.freeItems) items. Pro: no limit.") }
        return String(localized: "\(min(used, ItemLimit.freeItems)) of \(ItemLimit.freeItems) free items used. Pro: no limit.")
    }
}
