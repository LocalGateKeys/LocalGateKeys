import SwiftUI
import AppShared

/// AutoFill setup (iOS review 2026-11-15, UX item 5): the steps, a deep link to the system AutoFill settings
/// (`ASSettingsHelper.openCredentialProviderAppSettings`, through `AutoFillStatusModel`) and a check mark once
/// LocalGateKeys is the AutoFill provider, checked again whenever the app comes back to the front (the person usually
/// returns from the Settings app). Opened from the setup pages, the `>` command and Settings › AutoFill.
struct AutoFillSetupView: View {
    let status: AutoFillStatusModel
    /// Shown as a Done button when the screen is a sheet; nil when it is pushed.
    var onDone: (() -> Void)?
    @Environment(\.scenePhase) private var scenePhase

    static let onText = String(localized: "AutoFill is on")
    static let offText = String(localized: "AutoFill is off")
    static let stepOpen = String(localized: "Tap Open AutoFill settings below.")
    static let stepTurnOn = String(localized: "Turn on LocalGateKeys in the list of apps that fill passwords and passkeys.")
    static let stepReturn = String(localized: "Come back here. A check mark shows once it is on.")
    static let doneText = String(localized: "LocalGateKeys now offers your logins and passkeys when you tap a sign-in field.")

    var body: some View {
        List {
            Section {
                HStack(spacing: 12) {
                    Image(systemName: status.enabled == true ? "checkmark.circle.fill" : "key.horizontal.fill")
                        .font(.title)
                        .foregroundStyle(status.enabled == true ? Palette.success : Palette.accentText)
                        .accessibilityHidden(true)
                    Text(status.enabled == nil ? "…" : (status.enabled == true ? Self.onText : Self.offText))
                        .font(.headline)
                        .foregroundStyle(Palette.text)
                }
                .accessibilityElement(children: .combine)
                .padding(.vertical, 4)
            } footer: {
                if status.enabled == true { Text(Self.doneText) }
            }
            .listRowBackground(Palette.groupSurface)

            if status.enabled != true {
                Section {
                    step(1, Self.stepOpen)
                    step(2, Self.stepTurnOn)
                    step(3, Self.stepReturn)
                }
                .listRowBackground(Palette.groupSurface)
            }

            Section {
                Button("Open AutoFill settings") {
                    Task { await status.openSettings() }
                }
                .foregroundStyle(Palette.accentText)
                if let error = status.openError {
                    Text(error).font(.footnote).foregroundStyle(Palette.danger)
                }
            }
            .listRowBackground(Palette.groupSurface)
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Set up AutoFill")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if let onDone {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { onDone() } }
            }
        }
        .task { await status.refresh() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { Task { await status.refresh() } }
        }
    }

    /// One numbered step; the number follows Dynamic Type with the text.
    private func step(_ n: Int, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(verbatim: "\(n).")
                .font(.body.monospacedDigit().weight(.semibold))
                .foregroundStyle(Palette.accentText)
            Text(text).foregroundStyle(Palette.text)
        }
        .accessibilityElement(children: .combine)
    }
}
