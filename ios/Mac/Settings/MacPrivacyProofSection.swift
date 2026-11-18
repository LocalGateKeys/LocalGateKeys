import SwiftUI
import AppKit
import UniformTypeIdentifiers
import AppSharedMac

/// The privacy proof file on this Mac (feature pack §5), apart from SwiftUI: the iPhone's `PrivacyProofActions` with
/// platform "mac". Facts read from this Mac, signed with the sync device key when sync is on (`"signature": null`
/// otherwise; no new key is made). Only `PrivacyProof.appleClaims` are claimed (the breach check's 5-character prefix,
/// covered by `BreachCheckTests`); there is no network list until a Mac network guard test exists.
@MainActor
enum MacPrivacyProof {
    static let platform = "mac"

    /// `items` leaves out what travel mode hides, so a proof made while travelling does not tell that more exists
    /// (scan 2026-11-15 W-L7).
    static func facts(_ snapshot: StoreSnapshot, settings: AppSettings = .shared,
                      travel: TravelMode = TravelModeBox.shared.current) -> PrivacyProof.Facts {
        let sync: PrivacyProof.SyncMode
        if let s = snapshot.sync {
            let wifi = !s.lanPeers.isEmpty
            sync = s.hasFolder ? (wifi ? .both : .folder) : .wifi
        } else {
            sync = .off
        }
        let shares: Int64 = switch snapshot.shares {
        case .object(let o)?: Int64(o.count)
        case .array(let a)?: Int64(a.count)
        default: 0
        }
        return PrivacyProof.Facts(sync: sync, devices: Int64(snapshot.sync?.members.count ?? 0), shares: shares,
                                  items: Int64(ItemLimit.liveCount(visible(snapshot, travel: travel))),
                                  breachChecks: settings.breachCheckEnabled, strictOffline: settings.strictOfflineMode,
                                  updateCheck: false)
    }

    /// `snapshot` without the records travel mode hides.
    nonisolated static func visible(_ snapshot: StoreSnapshot, travel: TravelMode) -> StoreSnapshot {
        var out = snapshot
        for id in travel.hiddenIDs(in: snapshot) { out.records[id] = nil }
        return out
    }

    /// This build's version (`CFBundleShortVersionString`).
    static var appVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0" }

    /// The signed (or unsigned) document and the file's bytes.
    static func make(_ snapshot: StoreSnapshot, appVersion: String = MacPrivacyProof.appVersion, settings: AppSettings = .shared,
                     now: Date = Date()) throws -> (document: [String: JSONValue], bytes: [UInt8]) {
        let doc = PrivacyProof.document(platform: platform, appVersion: appVersion, generatedAt: PrivacyProof.timestamp(now),
                                        facts: facts(snapshot, settings: settings))
        let signed = try PrivacyProof.signed(doc, identity: snapshot.sync?.identity)
        return (signed, try PrivacyProof.fileBytes(signed))
    }

    /// The 16-hex fingerprint of this Mac's sync key, nil when sync is off (the file is then unsigned).
    static func fingerprint(_ snapshot: StoreSnapshot) -> String? {
        snapshot.sync.map { PrivacyProof.fingerprint(publicKey: $0.identity.signingPublicKey) }
    }

    static func syncLabel(_ mode: PrivacyProof.SyncMode) -> String {
        switch mode {
        case .off: String(localized: "Off")
        case .folder: String(localized: "Cloud folder")
        case .wifi: String(localized: "Wi-Fi")
        case .both: String(localized: "Cloud folder and Wi-Fi")
        }
    }

    static var intro: String { String(localized: "What this app sent from this device, and what it can show.") }
    static var terms: SettingsRowText { SettingsRowText(title: String(localized: "Privacy proof"), detail: intro) }
}

/// Settings › Security › Privacy proof: this Mac's facts and claims, who signs the file, and Export.
struct MacPrivacyProofSection: View {
    let store: any ItemStore
    @Environment(\.macTheme) private var theme
    @State private var facts: PrivacyProof.Facts?
    @State private var fingerprint: String?
    @State private var message: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(MacPrivacyProof.intro).font(.system(size: 11)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 14).padding(.top, 10).padding(.bottom, 4)
            if let facts {
                fact(String(localized: "Sync"), MacPrivacyProof.syncLabel(facts.sync))
                fact(String(localized: "Devices in the sync group"), "\(facts.devices)")
                fact(String(localized: "Shared collections"), "\(facts.shares)")
                fact(String(localized: "Items"), "\(facts.items)")
                fact(String(localized: "Breach checks"), facts.breachChecks ? String(localized: "Allowed") : String(localized: "Off"))
                fact(String(localized: "Strict offline mode"), facts.strictOffline ? String(localized: "On") : String(localized: "Off"))
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("Claims").font(.system(size: 11, weight: .semibold)).foregroundStyle(theme.textFaint)
                    .accessibilityAddTraits(.isHeader)
                Text("Breach checks send only a 5-character hash prefix, never a password.").font(.system(size: 12.5))
                Text("A list of connections isn't available on this device yet.").font(.system(size: 11))
                    .foregroundStyle(theme.textMuted)
                if let fingerprint {
                    HStack(spacing: 6) {
                        Text("Signed by this device").font(.system(size: 12.5))
                        Text(fingerprint).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                    }
                    .accessibilityElement(children: .combine)
                } else {
                    Text("Sync is off, so the file is not signed.").font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                }
                Text("A signature proves the file was not changed after this device made it: compare the key with this device's key in Settings › Sync on another of your devices. It does not prove the claims.")
                    .font(.system(size: 11)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
                HStack {
                    if let message {
                        Text(message).font(.system(size: 11)).foregroundStyle(theme.danger).fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 8)
                    Button(String(localized: "Export privacy proof"), action: export).buttonStyle(PillButtonStyle(primary: false))
                }
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
        }
        .onAppear(perform: reload)
    }

    private func fact(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).font(.system(size: 13))
            Spacer(minLength: 12)
            Text(value).font(.system(size: 13)).foregroundStyle(theme.textMuted)
        }
        .padding(.horizontal, 14).padding(.vertical, 6)
        .accessibilityElement(children: .combine)
    }

    private func reload() {
        guard let snap = try? store.load() else { return }
        facts = MacPrivacyProof.facts(snap)
        fingerprint = MacPrivacyProof.fingerprint(snap)
    }

    /// Asks where to save, then writes the file (made fresh, so its facts are the current ones).
    private func export() {
        message = nil
        do {
            let snap = try store.load()
            let made = try MacPrivacyProof.make(snap)
            let panel = NSSavePanel()
            panel.nameFieldStringValue = PrivacyProof.fileName(date: RecordDigest.today())
            panel.canCreateDirectories = true
            panel.isExtensionHidden = false
            panel.allowedContentTypes = [.json]
            panel.prompt = String(localized: "Export")
            guard panel.runModal() == .OK, let url = panel.url else { return }
            try Data(made.bytes).write(to: url, options: .atomic)
            reload()
        } catch {
            message = String(localized: "The privacy proof could not be made on this device.")
        }
    }
}
