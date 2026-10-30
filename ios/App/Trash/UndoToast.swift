import SwiftUI
import AppShared

/// "Moved to Recently deleted · Undo" at the bottom of the screen for 5 seconds (UX plan workstream 3).
/// One shared instance, hosted by `RootTabs` over every tab and pushed screen.
@MainActor
@Observable
final class UndoToast {
    static let shared = UndoToast()

    private(set) var message: String?
    @ObservationIgnored private var action: (() -> Void)?
    @ObservationIgnored private var hideTask: Task<Void, Never>?

    func show(_ message: String, seconds: Double = PhoneTrash.undoSeconds, undo: @escaping () -> Void) {
        self.message = message
        action = undo
        AccessibilityNotification.Announcement(String(localized: "\(message). Undo is available.")).post()
        hideTask?.cancel()
        hideTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(seconds))
            guard !Task.isCancelled else { return }
            self?.dismiss()
        }
    }

    func undo() {
        let run = action
        dismiss()
        run?()
    }

    func dismiss() {
        hideTask?.cancel()
        message = nil; action = nil
    }
}

struct UndoToastHost: ViewModifier {
    let toast: UndoToast
    func body(content: Content) -> some View {
        content
            .overlay(alignment: .bottom) {
                if let message = toast.message {
                    HStack(spacing: 12) {
                        Image(systemName: "trash").foregroundStyle(Palette.secondaryText).accessibilityHidden(true)
                        Text(message).foregroundStyle(Palette.text).fixedSize(horizontal: false, vertical: true)
                        Button("Undo") { toast.undo() }
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(Palette.accentText)
                            .accessibilityHint("Restores the deleted item")
                    }
                    .font(.subheadline)
                    .padding(.horizontal, 16).padding(.vertical, 12)
                    .lgkGlass(in: Capsule())
                    .padding(.horizontal, 16)
                    .padding(.bottom, SettingsView.legacyTabBarRoom + 8)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .accessibilityElement(children: .contain)
                }
            }
            .animation(.spring(duration: 0.3), value: toast.message)
    }
}

extension View {
    func undoToastHost(_ toast: UndoToast = .shared) -> some View { modifier(UndoToastHost(toast: toast)) }
}
