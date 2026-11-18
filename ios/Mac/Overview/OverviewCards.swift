import SwiftUI
import AppSharedMac

/// The three overview boxes (Windows `Overview.svelte`, UX refresh 2026-11-12): Password health, Coming up and
/// Backup & recovery in one row. Every text wraps; nothing is cut off.
struct OverviewCards: View {
    let model: OverviewModel
    /// Opens Reminders (the Coming up box's link); nil hides the link (no local data).
    var onReminders: (() -> Void)? = nil
    var onBackup: () -> Void = {}
    @Environment(\.macTheme) private var theme

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            OverviewCard(title: String(localized: "Password health")) { healthBody }
            OverviewCard(title: String(localized: "Coming up"), action: onReminders,
                         help: String(localized: "overview.openReminders", defaultValue: "Reminders")) { comingUpBody }
            OverviewCard(title: String(localized: "Backup & recovery"), action: onBackup,
                         help: String(localized: "overview.openRecovery", defaultValue: "Recovery centre")) {
                Pill(text: model.backupText, colour: model.backupStale ? theme.warning : nil, wraps: true, size: 11)
                if let warning = model.backup?.warnings.first(where: { $0 != RecoveryCentreModel.noBackupWarning }) {
                    wrapping(Text(warning).font(.system(size: 11.5)).foregroundStyle(theme.warning))
                }
            }
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder private var healthBody: some View {
        let card = model.healthCard
        if let score = card.score {
            (Text(score).font(.system(size: 18, weight: .semibold)).foregroundStyle(theme.text)
             + Text(verbatim: " ") + Text(card.label).font(.system(size: 12)).foregroundStyle(theme.textMuted))
                .fixedSize(horizontal: false, vertical: true)
            FlowRow(spacing: 4) { ForEach(card.pills, id: \.self) { Pill(text: $0, size: 11) } }
        } else {
            wrapping(Text(card.label).font(.system(size: 12)).foregroundStyle(theme.textMuted))
        }
    }

    @ViewBuilder private var comingUpBody: some View {
        let lines = model.comingUp
        if lines.isEmpty {
            wrapping(Text("Nothing coming up").font(.system(size: 12)).foregroundStyle(theme.textMuted))
        } else {
            ForEach(lines) { line in
                VStack(alignment: .leading, spacing: 1) {
                    wrapping(Text(line.label).font(.system(size: 12)))
                    wrapping(Text(verbatim: "\(line.date) · \(line.meta)").font(.system(size: 11))
                        .foregroundStyle(line.overdue ? theme.danger : theme.textMuted))
                }
            }
        }
    }

    private func wrapping(_ text: some View) -> some View {
        text.fixedSize(horizontal: false, vertical: true).frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Windows `.card`: a small inset box, muted title, content below; the whole box opens its page when it has one.
private struct OverviewCard<Content: View>: View {
    let title: String
    var action: (() -> Void)? = nil
    var help: String = ""
    @ViewBuilder var content: Content
    @Environment(\.macTheme) private var theme

    var body: some View {
        if let action {
            Button(action: action) { box }.buttonStyle(.plain).help(help).accessibilityHint(help)
        } else {
            box
        }
    }

    private var box: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 11.5, weight: .semibold)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            content
        }
        .foregroundStyle(theme.text)
        .padding(.horizontal, 10).padding(.vertical, 8)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(theme.card, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .contentShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .accessibilityElement(children: .contain)
    }
}

/// Pills that wrap onto the next line (Windows `.pills`: flex-wrap).
struct FlowRow: Layout {
    var spacing: CGFloat = 4

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(width: proposal.width ?? .infinity, subviews)
        return CGSize(width: proposal.width ?? rows.width, height: rows.height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        for (index, point) in arrange(width: bounds.width, subviews).points.enumerated() {
            subviews[index].place(at: CGPoint(x: bounds.minX + point.x, y: bounds.minY + point.y), proposal: .unspecified)
        }
    }

    private func arrange(width: CGFloat, _ subviews: Subviews) -> (points: [CGPoint], width: CGFloat, height: CGFloat) {
        var points: [CGPoint] = [], x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0, widest: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > 0 && x + size.width > width { x = 0; y += rowHeight + spacing; rowHeight = 0 }
            points.append(CGPoint(x: x, y: y))
            x += size.width + spacing; rowHeight = max(rowHeight, size.height); widest = max(widest, x - spacing)
        }
        return (points, widest, y + rowHeight)
    }
}

/// Mockup `.chip`: the small rounded count pill.
struct Pill: View {
    let text: String
    var colour: Color?
    /// True in the narrow overview boxes: long text wraps inside a rounded box instead of overflowing.
    var wraps = false
    /// 11 in the overview boxes (Windows `.pills span`), 12 elsewhere.
    var size: CGFloat = 12
    @Environment(\.macTheme) private var theme

    var body: some View {
        if wraps {
            Text(text).font(.system(size: size))
                .foregroundStyle(colour ?? theme.text)
                .padding(.horizontal, size < 12 ? 7 : 8).padding(.vertical, size < 12 ? 1 : 2)
                .background(theme.chip, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                .fixedSize(horizontal: false, vertical: true)
        } else {
            Text(text).font(.system(size: size)).lineLimit(1)
                .foregroundStyle(colour ?? theme.text)
                .padding(.horizontal, size < 12 ? 7 : 9).padding(.vertical, size < 12 ? 1 : 2)
                .background(theme.chip, in: Capsule())
                .fixedSize()
        }
    }
}
