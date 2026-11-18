import SwiftUI
import AppShared

/// "Remove a device…" and "I lost a device…" on the Sync tab's Cloud folder card (Windows `remove_device`,
/// `lost_device`, `remove_orphans`): choose the devices, enter a NEW sync password twice, then (lost) the checklist.
/// One rotation removes every chosen device; each gets a signed removal notice (`DeviceRemoval`).
struct RemoveDevicesChooser: View {
    struct Candidate: Identifiable, Equatable { let id: String; let name: String; let detail: String }

    let lost: Bool
    let candidates: [Candidate]
    let onContinue: ([String]) -> Void
    let onCancel: () -> Void
    @State private var chosen: [String] = []

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ForEach(candidates) { c in
                        Toggle(isOn: binding(c.id)) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(c.name).foregroundStyle(Palette.text)
                                if !c.detail.isEmpty { Text(c.detail).font(.footnote).foregroundStyle(Palette.secondaryText) }
                            }
                        }
                    }
                } footer: {
                    Text(lost ? DeviceRemoval.lostIntro : DeviceRemoval.chooseText)
                }
            }
            .navigationTitle(lost ? DeviceRemoval.lostTitle : DeviceRemoval.removeTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { onCancel() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Continue") { onContinue(candidates.map(\.id).filter { chosen.contains($0) }) }.disabled(chosen.isEmpty)
                }
            }
        }
    }

    /// A lost device is one device: choosing another replaces it. Remove takes several.
    private func binding(_ id: String) -> Binding<Bool> {
        Binding(get: { chosen.contains(id) }, set: { on in
            if on { chosen = lost ? [id] : chosen + [id] } else { chosen.removeAll { $0 == id } }
        })
    }
}

/// The new sync password, entered twice, for the chosen removal (Windows rotation form).
struct RemoveDevicesPasswordSheet: View {
    let coordinator: SyncCoordinator
    let plan: DeviceRemoval.Plan
    let onDone: (_ removed: Bool) -> Void
    @State private var password = ""
    @State private var again = ""
    @State private var working = false

    var body: some View {
        NavigationStack {
            Form {
                Section { Text(plan.intro).font(.footnote).foregroundStyle(Palette.text).fixedSize(horizontal: false, vertical: true) }
                Section {
                    SecureField("Sync password", text: $password)
                        .textContentType(VaultInputTraits.secretContentType).textInputAutocapitalization(.never).autocorrectionDisabled()
                    SecureField("Enter it again", text: $again)
                        .textContentType(VaultInputTraits.secretContentType).textInputAutocapitalization(.never).autocorrectionDisabled()
                } footer: {
                    Text(String(localized: "At least 12 characters, rated Strong or better.") + " " + DeviceRemoval.passwordAdvice)
                }
                if let e = coordinator.actionError {
                    Section { Text(e).foregroundStyle(Palette.danger).fixedSize(horizontal: false, vertical: true) }
                }
            }
            .navigationTitle(plan.names.count == 1 ? String(localized: "Remove \(plan.names[0])") : DeviceRemoval.removeTitle)
            .navigationBarTitleDisplayMode(.inline)
            .interactiveDismissDisabled(working)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { onDone(false) }.disabled(working) }
                ToolbarItem(placement: .confirmationAction) {
                    Button(working ? String(localized: "Working…") : String(localized: "Continue")) {
                        let pw = password, pw2 = again
                        working = true
                        Task {
                            let ok = await coordinator.removeMembers(plan, password: pw, again: pw2)
                            working = false
                            if ok { password = ""; again = ""; onDone(true) }
                        }
                    }
                    .disabled(working || password.isEmpty || again.isEmpty)
                }
            }
        }
    }
}

/// After "I lost a device" removed it: what to do next (Windows `lost_device_checklist(folder=True)`).
struct LostDeviceChecklist: View {
    let onDone: () -> Void

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(Array(DeviceRemoval.lostChecklist.enumerated()), id: \.offset) { _, line in
                        Label(line, systemImage: "checkmark.circle").foregroundStyle(Palette.text)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .listRowBackground(Palette.groupSurface)
            }
            .scrollContentBackground(.hidden)
            .lgkAuroraBackground()
            .navigationTitle(DeviceRemoval.lostTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { onDone() } } }
        }
    }
}
