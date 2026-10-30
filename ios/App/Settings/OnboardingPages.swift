import SwiftUI
import AppShared

/// The setup pages (UX plan workstream 4, Android `OnboardingScreen`): one page per open step, Skip on each, Skip
/// setup on the first. A step whose action opens another screen (Import, Settings, AutoFill settings) counts as
/// done and closes the pages; the steps left go to the vault's "Finish setting up" card. `onAction` runs that
/// step's action once the pages are closed.
struct OnboardingPages: View {
    let onboarding: Onboarding
    let onAction: (SetupStep) -> Void
    @State private var step: SetupStep
    private let first: SetupStep

    init(onboarding: Onboarding, onAction: @escaping (SetupStep) -> Void) {
        self.onboarding = onboarding; self.onAction = onAction
        let first = onboarding.firstPage()
        self.first = first
        _step = State(initialValue: first)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text(Onboarding.pageCount(step)).font(.subheadline.weight(.medium)).foregroundStyle(Palette.secondaryText)
                    Spacer()
                    if step == first {
                        Button(Onboarding.skipSetup) { onboarding.closePages() }
                            .foregroundStyle(Palette.accentText)
                            .frame(minHeight: 44)
                            .accessibilityIdentifier("onboarding-skip-setup")
                    }
                }
                Spacer(minLength: 24)
                VStack(alignment: .leading, spacing: 8) {
                    Image(systemName: step.icon).font(.system(size: 30, weight: .medium)).foregroundStyle(Palette.accentText)
                        .accessibilityHidden(true)
                    Text(step.title).font(.title2.weight(.semibold)).foregroundStyle(Palette.text)
                        .accessibilityAddTraits(.isHeader)
                    Text(step.text).foregroundStyle(Palette.secondaryText).fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(20)
                .lgkGroupSurface()
                Button(action: perform) {
                    Text(step.action).font(.body.weight(.semibold)).foregroundStyle(Palette.onAccent)
                        .frame(maxWidth: .infinity, minHeight: 50)
                        .background(Palette.accent, in: Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("onboarding-action")
                if step != .vault {
                    Button(Onboarding.skip, action: advance)
                        .foregroundStyle(Palette.accentText)
                        .frame(maxWidth: .infinity, minHeight: 48)
                        .accessibilityIdentifier("onboarding-skip")
                }
            }
            .padding(24)
        }
        .lgkAuroraBackground()
        .accessibilityIdentifier("onboarding")
    }

    private func perform() {
        onboarding.complete(step)
        switch step {
        case .vault, .unlock: advance()
        case .importItems, .phrase, .autofill:
            onboarding.closePages()
            onAction(step)
        }
    }

    private func advance() {
        if let next = onboarding.next(after: step) { step = next } else { onboarding.closePages() }
    }
}

/// "Finish setting up · 3 of 5" at the top of the vault: tap to open the pages again, Hide to put it away.
struct SetupCard: View {
    let text: String
    let onOpen: () -> Void
    let onHide: () -> Void

    var body: some View {
        HStack(spacing: 4) {
            Button(action: onOpen) {
                HStack {
                    Image(systemName: "checklist").foregroundStyle(Palette.accentText).accessibilityHidden(true)
                    Text(text).foregroundStyle(Palette.text).frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(minHeight: 48)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("setup-card-open")
            Button(Onboarding.hide, action: onHide)
                .foregroundStyle(Palette.secondaryText)
                .frame(minHeight: 48)
                .padding(.horizontal, 8)
                .accessibilityIdentifier("setup-card-hide")
        }
        .padding(.leading, 16).padding(.trailing, 4)
        .lgkGroupSurface()
        .padding(.top, 8)
    }
}
