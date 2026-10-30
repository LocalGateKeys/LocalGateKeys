import SwiftUI
import AppSharedMac

/// The four overview cards (Windows `Overview.svelte`, mockup `.cards`): Password health, Coming up,
/// Backup & recovery, Generator, two per row.
struct OverviewCards: View {
    let model: OverviewModel
    let onGenerator: () -> Void
    var onBackup: () -> Void = {}
    @Environment(\.macTheme) private var theme

    var body: some View {
        Grid(horizontalSpacing: 10, verticalSpacing: 10) {
            GridRow {
                OverviewCard(title: String(localized: "Password health")) { healthBody }
                OverviewCard(title: String(localized: "Coming up")) { comingUpBody }
            }
            GridRow {
                OverviewCard(title: String(localized: "Backup & recovery")) {
                    Pill(text: model.backupText, colour: model.backupStale ? theme.warning : nil)
                    if let warning = model.backup?.warnings.first(where: { $0 != RecoveryCentreModel.noBackupWarning }) {
                        Text(warning).font(.system(size: 12)).foregroundStyle(theme.warning).lineLimit(2).padding(.top, 4)
                    }
                    Button("Open the Recovery centre", action: onBackup)
                        .buttonStyle(.plain).foregroundStyle(theme.link).font(.system(size: 13)).padding(.top, 6)
                }
                OverviewCard(title: String(localized: "Generator")) {
                    Button("Open the password generator", action: onGenerator)
                        .buttonStyle(.plain).foregroundStyle(theme.link)
                }
            }
        }
    }

    @ViewBuilder private var healthBody: some View {
        let card = model.healthCard
        if let score = card.score {
            HStack(alignment: .firstTextBaseline, spacing: 0) {
                Text(score).font(.system(size: 22, weight: .semibold))
                Text(card.label).font(.system(size: 13)).foregroundStyle(theme.textMuted)
            }
            HStack(spacing: 6) { ForEach(card.pills, id: \.self) { Pill(text: $0) } }
                .padding(.top, 6)
        } else {
            Text(card.label).font(.system(size: 13)).foregroundStyle(theme.textMuted)
        }
    }

    @ViewBuilder private var comingUpBody: some View {
        let lines = model.comingUp
        if lines.isEmpty {
            Text("Nothing coming up").font(.system(size: 13)).foregroundStyle(theme.textMuted)
        } else {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(lines) { line in
                    HStack(spacing: 8) {
                        Text(line.date).foregroundStyle(theme.textFaint).frame(width: 48, alignment: .leading)
                        Text(line.label).lineLimit(1)
                        Spacer(minLength: 4)
                        Text(line.meta).foregroundStyle(line.overdue ? theme.danger : theme.textMuted)
                    }
                    .font(.system(size: 12.5))
                }
            }
        }
    }
}

/// Mockup `.card`: inset card, bold title, content below.
private struct OverviewCard<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(title).font(.system(size: 14, weight: .semibold)).padding(.bottom, 6)
                .accessibilityAddTraits(.isHeader)
            content
        }
        .foregroundStyle(theme.text)
        .padding(.horizontal, 14).padding(.vertical, 12)
        .frame(maxWidth: .infinity, minHeight: 96, maxHeight: .infinity, alignment: .topLeading)
        .background(theme.card, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .accessibilityElement(children: .contain)
    }
}

/// Mockup `.chip`: the small rounded count pill.
struct Pill: View {
    let text: String
    var colour: Color?
    @Environment(\.macTheme) private var theme

    var body: some View {
        Text(text).font(.system(size: 12)).lineLimit(1)
            .foregroundStyle(colour ?? theme.text)
            .padding(.horizontal, 9).padding(.vertical, 2)
            .background(theme.chip, in: Capsule())
            .fixedSize()
    }
}
