import SwiftUI
import AppShared

/// The confirmation shown for a passkey registration: which site and account, Create or Cancel, on the
/// app's aurora. Nothing is generated or written until Create (and then Face ID) runs.
struct PasskeyCreateSheet: View {
    let rpID: String
    let userName: String
    let create: () -> Void
    let cancel: () -> Void
    /// Create runs once: disabled after the first tap (the driver ignores repeats too).
    @State private var creating = false

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "person.badge.key.fill")
                .font(.system(size: 44))
                .foregroundStyle(Palette.accentText)
            Text("Create a passkey")
                .font(.title2.bold())
                .foregroundStyle(Palette.text)
            VStack(spacing: 6) {
                Text(rpID).font(.headline).foregroundStyle(Palette.text)
                if !userName.isEmpty {
                    Text(userName).font(.subheadline).foregroundStyle(Palette.secondaryText)
                }
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(Palette.groupSurface, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            Text("It is saved in LocalGateKeys on this iPhone and syncs to your PC with your other items.")
                .font(.footnote)
                .multilineTextAlignment(.center)
                .foregroundStyle(Palette.secondaryText)
            Spacer()
            Button {
                guard !creating else { return }
                creating = true
                create()
            } label: {
                Text("Create").font(.headline).frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .buttonStyle(.borderedProminent)
            .disabled(creating)
            .tint(Palette.accent)
            Button("Cancel", role: .cancel, action: cancel)
                .foregroundStyle(Palette.accentText)
        }
        .padding(24)
        .background { AuroraBackground().ignoresSafeArea() }
    }
}
