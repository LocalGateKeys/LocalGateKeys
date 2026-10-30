import SwiftUI

/// The line under the panels: storage state and auto-lock countdown on the left, shortcuts on the right.
struct StatusLine: View {
    let autoLockRemaining: TimeInterval?
    @Environment(\.macTheme) private var theme

    static let hint = String(localized: "⌘K search · ⌘N new · ⌘L lock · ⌘/ all shortcuts")

    static func countdown(_ seconds: TimeInterval) -> String {
        let s = max(0, Int(seconds.rounded(.up)))
        return String(format: "%d:%02d", s / 60, s % 60)
    }

    var body: some View {
        HStack {
            HStack(spacing: 0) {
                Text("●").foregroundStyle(theme.live)
                Text(" Local · Encrypted")
                if let autoLockRemaining {
                    Text("   Auto-lock in \(Self.countdown(autoLockRemaining))").monospacedDigit()
                }
            }
            Spacer()
            Text(StatusLine.hint)
        }
        .font(.system(size: 12))
        .foregroundStyle(theme.textFaint)
        .padding(.horizontal, 18).padding(.vertical, 9)
    }
}
