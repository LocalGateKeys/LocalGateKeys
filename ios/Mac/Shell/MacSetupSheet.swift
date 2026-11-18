import SwiftUI
import AppSharedMac

/// Set up LocalGateKeys (UX plan workstream 4; Windows `app/onboarding.py`, Android `OnboardingScreen`): one page
/// per open step, Skip on each, Skip setup on the first. Opens by itself once on a new Mac, again from Show setup
/// (palette), the vault card or Settings › Show setup again. A step whose action opens a page (Settings, Import,
/// Devices & connections) closes the sheet; Import and the Safari step count as done when opened, Touch ID and the
/// recovery phrase when they are turned on (`MainWindow.detectSetup`).
struct MacSetupSheet: View {
    let onboarding: Onboarding
    let onPick: (PaletteAction) -> Void
    @Environment(\.macTheme) private var theme
    @State private var step: SetupStep
    private let first: SetupStep

    init(onboarding: Onboarding, onPick: @escaping (PaletteAction) -> Void) {
        self.onboarding = onboarding; self.onPick = onPick
        let first = onboarding.firstPage()
        self.first = first
        _step = State(initialValue: first)
    }

    /// The page each step opens; nil: the step only advances.
    static func action(_ step: SetupStep) -> PaletteAction? {
        switch step {
        case .vault: nil
        case .unlock: .settings(.unlocking)
        case .importItems: .importFile
        case .phrase: .recoveryCentre
        case .autofill: .devices
        }
    }

    /// Opening the page finishes the step (Touch ID and the phrase are done only once they are on).
    static func completesOnAction(_ step: SetupStep) -> Bool { step != .unlock && step != .phrase }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(Onboarding.title).font(.title2.weight(.semibold)).foregroundStyle(theme.text)
                Spacer()
                Text(Onboarding.pageCount(step)).font(.system(size: 12)).foregroundStyle(theme.textMuted)
            }
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: step.icon).font(.system(size: 22)).frame(width: 30).foregroundStyle(theme.accent)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text(step.title).font(.system(size: 15, weight: .semibold)).foregroundStyle(theme.text)
                        .accessibilityAddTraits(.isHeader)
                    Text(step.text).font(.system(size: 13)).foregroundStyle(theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .glassField()
            // Long labels (German: "Einrichtung überspringen", "Touch ID einrichten") do not fit one row at 460 pt:
            // the buttons then stack instead of pushing the sheet's content past its edges.
            ViewThatFits(in: .horizontal) {
                HStack {
                    skipSetupButton
                    Spacer()
                    stepButtons
                }
                VStack(alignment: .trailing, spacing: 8) {
                    HStack { Spacer(); stepButtons }
                    HStack { skipSetupButton; Spacer() }
                }
            }
        }
        .padding(22)
        .frame(width: 460)
    }

    @ViewBuilder private var skipSetupButton: some View {
        if step == first {
            Button(Onboarding.skipSetup) { onboarding.closePages() }.buttonStyle(PillButtonStyle(primary: false))
                .keyboardShortcut(.cancelAction)
        }
    }

    @ViewBuilder private var stepButtons: some View {
        if step != .vault {
            Button(Onboarding.skip, action: advance).buttonStyle(PillButtonStyle(primary: false))
        }
        Button(step.action, action: perform).buttonStyle(PillButtonStyle(primary: true))
            .keyboardShortcut(.defaultAction)
    }

    private func perform() {
        if Self.completesOnAction(step) { onboarding.complete(step) }
        guard let action = Self.action(step) else { return advance() }
        onboarding.closePages()
        onPick(action)
    }

    private func advance() {
        if let next = onboarding.next(after: step) { step = next } else { onboarding.closePages() }
    }
}
