import SwiftUI
import AppShared

/// The privacy proof file on iPhone (feature pack §5) apart from SwiftUI: this device's facts, signed with the sync
/// device key when sync is on (unsigned otherwise). Only `PrivacyProof.appleClaims` are claimed; no network list.
@MainActor
enum PrivacyProofActions {
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
                                  items: Int64(ItemLimit.liveCount(PrivacyProofActions.visible(snapshot, travel: travel))),
                                  breachChecks: settings.breachCheckEnabled, strictOffline: settings.strictOfflineMode,
                                  updateCheck: false)
    }

    /// `snapshot` without the records travel mode hides.
    nonisolated static func visible(_ snapshot: StoreSnapshot, travel: TravelMode) -> StoreSnapshot {
        var out = snapshot
        for id in travel.hiddenIDs(in: snapshot) { out.records[id] = nil }
        return out
    }

    /// The contract's platform names: iPhone and iPad are both "ios".
    static let platform = "ios"

    /// The signed (or unsigned) document and its file bytes.
    static func make(_ snapshot: StoreSnapshot, appVersion: String, now: Date = Date()) throws -> (document: [String: JSONValue], bytes: [UInt8]) {
        let doc = PrivacyProof.document(platform: platform, appVersion: appVersion, generatedAt: PrivacyProof.timestamp(now),
                                        facts: facts(snapshot))
        let signed = try PrivacyProof.signed(doc, identity: snapshot.sync?.identity)
        return (signed, try PrivacyProof.fileBytes(signed))
    }

    /// A temporary file for the share sheet.
    static func write(_ bytes: [UInt8], now: Date = Date()) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(PrivacyProof.fileName(date: RecordDigest.today(now)))
        try Data(bytes).write(to: url, options: [.atomic, .completeFileProtection])
        return url
    }
}

/// Settings › Privacy proof: what this iPhone can state about itself, as a signed file anyone can check with
/// `lgk proof verify`.
struct PrivacyProofView: View {
    let store: any ItemStore
    let appVersion: String
    @State private var facts: PrivacyProof.Facts?
    @State private var fingerprint: String?
    @State private var file: URL?
    @State private var failed = false

    var body: some View {
        List {
            if let facts {
                Section("This device") {
                    LabeledContent("Sync", value: Self.syncLabel(facts.sync))
                    LabeledContent("Devices in the sync group", value: "\(facts.devices)")
                    LabeledContent("Shared collections", value: "\(facts.shares)")
                    LabeledContent("Items", value: "\(facts.items)")
                    LabeledContent("Breach checks", value: facts.breachChecks ? String(localized: "Allowed") : String(localized: "Off"))
                }
                .listRowBackground(Palette.groupSurface)
            }
            Section {
                Text("Breach checks send only a 5-character hash prefix, never a password.")
            } header: {
                Text("Claims")
            } footer: {
                Text("This iPhone does not list its network connections yet, so the file makes no claim about them. It never holds item content, file paths or site names.")
            }
            .listRowBackground(Palette.groupSurface)
            Section {
                if let fingerprint {
                    LabeledContent("Signed by this device", value: fingerprint).font(.footnote.monospaced())
                } else {
                    Text("Sync is off, so the file is not signed.").foregroundStyle(Palette.secondaryText)
                }
                Text("A signature proves the file was not changed after this device made it: compare the key with this device's key in Settings › Sync on another of your devices. It does not prove the claims.")
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
                if let file {
                    ShareLink(item: file) { Label("Export privacy proof", systemImage: "square.and.arrow.up") }
                }
            }
            .listRowBackground(Palette.groupSurface)
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Privacy proof")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear(perform: build)
        .onDisappear { if let file { try? FileManager.default.removeItem(at: file) } }
        .alert("The privacy proof could not be made on this device.", isPresented: $failed) { Button("OK") {} }
    }

    private func build() {
        do {
            let snap = try store.load()
            let made = try PrivacyProofActions.make(snap, appVersion: appVersion)
            facts = PrivacyProofActions.facts(snap)
            fingerprint = snap.sync.map { PrivacyProof.fingerprint(publicKey: $0.identity.signingPublicKey) }
            file = try PrivacyProofActions.write(made.bytes)
        } catch {
            failed = true
        }
    }

    static func syncLabel(_ mode: PrivacyProof.SyncMode) -> String {
        switch mode {
        case .off: String(localized: "Off")
        case .folder: String(localized: "Cloud folder")
        case .wifi: String(localized: "Wi-Fi")
        case .both: String(localized: "Cloud folder and Wi-Fi")
        }
    }
}
