import SwiftUI
import AppShared

struct UnlockView: View {
    let model: AppLockModel
    /// "Start fresh anyway": 0 none, 1 first confirmation, 2 second.
    @State private var freshStep = 0

    var body: some View {
        ZStack {
            AuroraBackground()
            VStack(spacing: 24) {
                Spacer()
                Image("BrandMark")
                    .resizable().interpolation(.high).aspectRatio(contentMode: .fit)
                    .frame(width: 96, height: 96)
                    .shadow(color: .black.opacity(0.25), radius: 16, y: 6)
                    .accessibilityHidden(true)
                Text("LocalGateKeys").font(.title.bold()).foregroundStyle(Palette.text)
                if let message = model.errorMessage {
                    Text(message).font(.callout).foregroundStyle(Palette.secondaryText)
                        .multilineTextAlignment(.center).padding(.horizontal, 32)
                }
                if model.offersStartFresh {
                    Button("Start fresh anyway", role: .destructive) { freshStep = 1 }
                        .disabled(model.state == .unlocking)
                }
                Spacer()
                Button {
                    Task { await model.unlock() }
                } label: {
                    Label("Unlock", systemImage: "faceid").frame(maxWidth: .infinity).padding(.vertical, 6)
                }
                .buttonStyle(.borderedProminent).tint(Palette.accent)
                .disabled(model.state == .unlocking)
                .padding(.horizontal, 32).padding(.bottom, 48)
            }
        }
        .confirmationDialog(AppLockModel.startFreshConfirm1, isPresented: step(1), titleVisibility: .visible) {
            Button("Start fresh", role: .destructive) { freshStep = 2 }
            Button("Cancel", role: .cancel) { freshStep = 0 }
        }
        .confirmationDialog(AppLockModel.startFreshConfirm2, isPresented: step(2), titleVisibility: .visible) {
            Button("Start fresh now", role: .destructive) {
                freshStep = 0
                Task { await model.startFreshAnyway() }
            }
            Button("Cancel", role: .cancel) { freshStep = 0 }
        }
    }

    private func step(_ n: Int) -> Binding<Bool> {
        Binding(get: { freshStep == n }, set: { if !$0, freshStep == n { freshStep = 0 } })
    }
}
