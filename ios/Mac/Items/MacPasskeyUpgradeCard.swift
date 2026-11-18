import SwiftUI
import AppKit
import AppSharedMac

/// The passkey upgrade prompt on this Mac (feature pack §6.3), apart from SwiftUI: a `web` login whose site lists
/// passkeys while no passkey is saved for that domain, unless it was dismissed on this Mac in the last 90 days
/// (`LocalData.passkeyUpgradeDismissed`, never synced). The password is never touched.
@MainActor
enum MacPasskeyUpgrade {
    /// The relying party ids of the live passkey items.
    static func relyingPartyIDs(in snapshot: StoreSnapshot) -> [String] {
        snapshot.itemRecords.compactMap { id, wrapper in
            guard snapshot.meta[id]?.deleted != true, case .object(let w) = wrapper, case .object(let r)? = w["record"],
                  r["kind"] == .string("passkey"), case .object(let p)? = r["payload"],
                  case .string(let rp)? = p["relying_party_id"] else { return nil }
            return rp
        }
    }

    /// The registrable domain the prompt is about for `record`, or nil.
    nonisolated static func domain(for record: [String: JSONValue], rpIDs: [String], features: SiteFeatures,
                                   dismissed: [String: Int64], now: Int64) -> String? {
        guard record["kind"] == .string("web") else { return nil }
        guard let domain = PasskeyUpgrade.domain(for: record, features: features,
                                                 passkeyDomains: features.passkeyDomains(relyingPartyIDs: rpIDs)) else { return nil }
        return PasskeyUpgrade.isDismissed(domain, in: dismissed, now: now) ? nil : domain
    }

    /// Stores "Not now" for `domain` in this Mac's local data. False when it could not be saved.
    @discardableResult
    static func dismiss(_ domain: String, local: any LocalDataHosting, now: Int64) -> Bool {
        guard var data = local.localData else { return false }
        data.passkeyUpgradeDismissed = PasskeyUpgrade.dismissing(domain, in: data.passkeyUpgradeDismissed, now: now)
        do { try local.commitLocalData(data) } catch { return false }
        return true
    }
}

/// The card in a login's detail pane: the site supports passkeys, Open website, Not now. Never blocks anything.
struct MacPasskeyUpgradeCard: View {
    let item: VaultItem
    let store: any ItemStore
    let local: any LocalDataHosting
    @Environment(\.macTheme) private var theme
    @State private var domain: String?

    var body: some View {
        Group {
            if let domain {
                VStack(alignment: .leading, spacing: 8) {
                    Label(String(localized: "\(domain) supports passkeys"), systemImage: "person.badge.key")
                        .font(.system(size: 13, weight: .semibold))
                    Text("A passkey can't be phished or leaked. Add one in the site's security settings; LocalGateKeys saves it when you choose it as the passkey provider.")
                        .font(.system(size: 12)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 8) {
                        if let url = ItemActions.website(item) {
                            Button(String(localized: "Open website")) { NSWorkspace.shared.open(url) }
                                .buttonStyle(PillButtonStyle(primary: true))
                        }
                        Button(String(localized: "Not now")) {
                            self.domain = nil
                            MacPasskeyUpgrade.dismiss(domain, local: local, now: SystemClock().now)
                        }
                        .buttonStyle(PillButtonStyle(primary: false))
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
                .padding(.top, 12)
                .accessibilityElement(children: .contain)
            }
        }
        .task(id: item.id) { await load() }
    }

    private func load() async {
        guard item.kind == "web", let snap = try? store.load() else { domain = nil; return }
        let record = item.record
        let rpIDs = MacPasskeyUpgrade.relyingPartyIDs(in: snap)
        let dismissed = local.localData?.passkeyUpgradeDismissed ?? [:]
        let now = SystemClock().now
        domain = await Task.detached(priority: .utility) { () -> String? in
            MacPasskeyUpgrade.domain(for: record, rpIDs: rpIDs, features: SiteFeatures.bundled(), dismissed: dismissed, now: now)
        }.value
    }
}
