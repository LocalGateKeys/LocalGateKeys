import SwiftUI
import LGKCore
import AppSharedMac

/// The sidebar's Activity (Windows `WorkspacePages.svelte`, kind "activity"): when, event, result and count,
/// newest first. Content-free by construction (`ActivityRecorder`).
struct ActivityView: View {
    let events: [LocalData.ActivityEvent]
    @Environment(\.macTheme) private var theme

    var body: some View {
        let rows = ActivityList.rows(events)
        VStack(alignment: .leading, spacing: 10) {
            Text(ActivityList.title).font(.system(size: 19, weight: .semibold))
            Text(ActivityList.subtitle).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            VStack(spacing: 0) {
                line([String(localized: "When"), String(localized: "Event"), String(localized: "Result"), String(localized: "Count")], header: true)
                if rows.isEmpty {
                    Rectangle().fill(theme.line).frame(height: 1)
                    Text(ActivityList.emptyText).foregroundStyle(theme.textMuted).padding(14)
                        .frame(maxWidth: .infinity)
                } else {
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(rows) { r in
                                Rectangle().fill(theme.line).frame(height: 1)
                                line([r.when, r.event, r.result, String(r.count)], header: false)
                            }
                        }
                    }
                }
            }
            .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
            Spacer(minLength: 0)
        }
        .foregroundStyle(theme.text)
        .padding(18)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func line(_ cells: [String], header: Bool) -> some View {
        HStack(spacing: 10) {
            Text(cells[0]).frame(maxWidth: .infinity, alignment: .leading)
            Text(cells[1]).frame(maxWidth: .infinity, alignment: .leading)
            Text(cells[2]).frame(width: 90, alignment: .leading)
            Text(cells[3]).frame(width: 50, alignment: .trailing)
        }
        .font(.system(size: header ? 11.5 : 13, weight: header ? .semibold : .regular).monospacedDigit())
        .foregroundStyle(header ? theme.textFaint : theme.text)
        .padding(.horizontal, 14).padding(.vertical, 8)
    }
}
