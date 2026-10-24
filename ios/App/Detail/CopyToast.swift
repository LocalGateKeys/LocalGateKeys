import SwiftUI
import AppShared

/// A short "Copied" capsule at the top of the screen. One shared instance; `RootTabs` hosts it so it shows
/// over the vault list and pushed detail screens alike. Each new copy restarts the timer.
@MainActor
@Observable
final class CopyToast {
    static let shared = CopyToast()
    static let visibleFor: Duration = .seconds(1.6)

    private(set) var message: String?
    /// Bumped on every show so a repeat copy still triggers the haptic.
    private(set) var count = 0
    @ObservationIgnored private var hideTask: Task<Void, Never>?

    /// `duration`: longer for a message with more to read (the Safari import summary).
    func show(_ message: String, for duration: Duration? = nil) {
        self.message = message
        count += 1
        AccessibilityNotification.Announcement(message).post()
        hideTask?.cancel()
        let duration = duration ?? Self.visibleFor
        hideTask = Task { [weak self] in
            try? await Task.sleep(for: duration)
            guard !Task.isCancelled else { return }
            self?.message = nil
        }
    }
}

struct CopyToastHost: ViewModifier {
    let toast: CopyToast
    func body(content: Content) -> some View {
        content
            .overlay(alignment: .top) {
                if let message = toast.message {
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.circle.fill").foregroundStyle(Palette.success)
                        Text(message).foregroundStyle(Palette.text)
                    }
                        .font(.subheadline.weight(.semibold))
                        .padding(.horizontal, 16).padding(.vertical, 10)
                        .lgkGlass(in: Capsule())
                        .padding(.top, 6)
                        .transition(.move(edge: .top).combined(with: .opacity))
                        .allowsHitTesting(false)
                        .accessibilityHidden(true)   // announced when shown
                }
            }
            .animation(.spring(duration: 0.3), value: toast.message)
            .sensoryFeedback(.success, trigger: toast.count)
    }
}

extension View {
    func copyToastHost(_ toast: CopyToast = .shared) -> some View { modifier(CopyToastHost(toast: toast)) }
}
