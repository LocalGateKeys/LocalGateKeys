import SwiftUI
import AppShared

/// The iPhone's passkey doctor (feature pack §6.2): the checks that decide whether passkeys work here, each with
/// what to do. Read only; nothing is sent anywhere.
@MainActor
enum PasskeyDoctor {
    enum Check: String, CaseIterable, Identifiable {
        case provider, offerPasskeys, saved
        var id: String { rawValue }
    }

    /// The failing checks, in order. `providerEnabled` nil: not known yet (not counted as failing).
    static func failing(providerEnabled: Bool?, offerPasskeys: Bool, passkeyCount: Int) -> [Check] {
        var out: [Check] = []
        if providerEnabled == false { out.append(.provider) }
        if !offerPasskeys { out.append(.offerPasskeys) }
        if passkeyCount == 0 { out.append(.saved) }
        return out
    }

    static func title(_ check: Check) -> String {
        switch check {
        case .provider: String(localized: "LocalGateKeys is not turned on for passwords and passkeys")
        case .offerPasskeys: String(localized: "Offer passkeys is off")
        case .saved: String(localized: "No passkeys saved yet")
        }
    }

    static func advice(_ check: Check) -> String {
        switch check {
        case .provider: String(localized: "Open AutoFill settings and turn on LocalGateKeys.")
        case .offerPasskeys: String(localized: "Turn on Offer passkeys in Settings › AutoFill.")
        case .saved: String(localized: "On a site that offers passkeys, create one and choose LocalGateKeys to save it.")
        }
    }
}

struct PasskeyDoctorView: View {
    let store: any ItemStore
    let status: AutoFillStatusModel
    @State private var passkeys = 0

    var body: some View {
        let failing = PasskeyDoctor.failing(providerEnabled: status.enabled, offerPasskeys: AppSettings.shared.offerPasskeys,
                                            passkeyCount: passkeys)
        List {
            Section {
                if failing.isEmpty {
                    Label("Passkeys are ready on this device.", systemImage: "checkmark.circle").foregroundStyle(Palette.text)
                }
                ForEach(failing) { check in
                    VStack(alignment: .leading, spacing: 4) {
                        Label(PasskeyDoctor.title(check), systemImage: "exclamationmark.triangle").foregroundStyle(Palette.text)
                        Text(PasskeyDoctor.advice(check)).font(.footnote).foregroundStyle(Palette.secondaryText)
                    }
                    .accessibilityElement(children: .combine)
                }
            }
            .listRowBackground(Palette.groupSurface)
            Section {
                Button("Open AutoFill settings") { Task { await status.openSettings() } }.foregroundStyle(Palette.accentText)
                if let error = status.openError { Text(error).font(.footnote).foregroundStyle(Palette.secondaryText) }
            }
            .listRowBackground(Palette.groupSurface)
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Passkey check")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            await status.refresh()
            passkeys = (try? store.load()).map { snap in
                snap.itemRecords.filter { id, wrapper in
                    guard snap.meta[id]?.deleted != true, case .object(let w) = wrapper, case .object(let r)? = w["record"] else { return false }
                    return r["kind"] == .string("passkey")
                }.count
            } ?? 0
        }
    }
}
