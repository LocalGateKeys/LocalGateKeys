import SwiftUI
import AppSharedMac

/// The import review (Windows import review, `ImportReviewModel`): one row per record with what will happen
/// to it (Add, Skip, Replace, Merge, Keep both; "Needs Pro" past the free slots), the summary and the
/// messages, then Import. Passwords are never shown. A phone backup restore uses the same sheet with
/// Windows' preview lines and Restore (it merges like a sync and never wipes the vault).
struct ImportReviewSheet: View {
    let model: ImportExportModel
    private let review: ImportReviewModel?
    private let restore: ImportExportModel.RestorePreview?
    @Environment(\.macTheme) private var theme

    init(model: ImportExportModel, review: ImportReviewModel) {
        self.model = model; self.review = review; self.restore = nil
    }

    init(model: ImportExportModel, restore: ImportExportModel.RestorePreview) {
        self.model = model; self.review = nil; self.restore = restore
    }

    static let footer = String(localized: "Nothing is written until you choose Import. Replace and merge keep the previous password in encrypted history. Protect and delete the source file afterwards.")
    static let restoreFooter = String(localized: "The backup is merged into this vault like a sync: items only on this Mac stay, and an item changed on this Mac since the backup keeps its newer version.")

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: restore == nil ? "square.and.arrow.down" : "iphone.and.arrow.forward")
                    .font(.system(size: 20)).foregroundStyle(theme.accent)
                Text(restore == nil ? String(localized: "Review import") : String(localized: "Restore phone backup")).font(.system(size: 19, weight: .semibold))
            }
            if let review { ReviewRows(model: model, review: review) }
            if let restore { restoreBody(restore) }
        }
        .padding(22)
        .frame(width: 640)
        .background(WashBackground())
        .foregroundStyle(theme.text)
    }

    private func restoreBody(_ preview: ImportExportModel.RestorePreview) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(preview.fileName).font(.system(size: 12)).foregroundStyle(theme.textMuted)
            VStack(alignment: .leading, spacing: 6) {
                ForEach(preview.lines, id: \.self) { line in
                    HStack(spacing: 8) {
                        Circle().fill(theme.accent).frame(width: 5, height: 5)
                        Text(line).font(.system(size: 13))
                    }
                }
            }
            .padding(14).frame(maxWidth: .infinity, alignment: .leading)
            .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
            Text(Self.restoreFooter).font(.callout).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            if let m = model.message { Text(m).font(.system(size: 12.5)).foregroundStyle(theme.warning) }
            HStack {
                Button("Cancel") { model.cancelRestore() }.buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Spacer()
                Button(model.busy ? String(localized: "Restoring…") : String(localized: "Restore")) { Task { await model.commitRestore() } }
                    .buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction).disabled(model.busy)
            }
        }
    }
}

/// The review rows, summary and buttons (observes the review model's decisions).
private struct ReviewRows: View {
    let model: ImportExportModel
    @ObservedObject var review: ImportReviewModel
    @State private var showingMessages = false
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(String(localized: "\(model.reviewSource) · \(review.rows.count) records. Local only; nothing is written until you choose Import. New records default to Add; duplicates and conflicts default to Skip (Keep both saves the imported copy too). Passwords are never shown here."))
                .font(.system(size: 12.5)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                Button("Add all new") { setAll { $0.base == .new ? .create : nil } }
                Button("Skip all") { setAll { _ in .skip } }
                Button("Keep both for duplicates") { setAll { $0.base != .new && !$0.isSkippedSource ? .keepBoth : nil } }
            }
            .buttonStyle(PillButtonStyle(primary: false)).controlSize(.small)
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(review.rows) { row in
                        if row.id != review.rows.first?.id { Rectangle().fill(theme.line).frame(height: 1) }
                        rowView(row)
                    }
                }
            }
            .frame(minHeight: 160, maxHeight: 340)
            .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
            Text(review.summary).font(.system(size: 13, weight: .medium))
            if !review.issues.isEmpty {
                DisclosureGroup("Messages (\(review.issues.count))", isExpanded: $showingMessages) {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(Array(review.issues.enumerated()), id: \.offset) { _, line in
                            Text("• " + line).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.system(size: 12.5))
            }
            Text(ImportReviewSheet.footer).font(.callout).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            if let m = model.message { Text(m).font(.system(size: 12.5)).foregroundStyle(theme.warning) }
            HStack {
                Button("Cancel") { model.cancelReview() }.buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Spacer()
                Button(model.busy ? String(localized: "Importing…") : String(localized: "Import")) { Task { await model.commitReview() } }
                    .buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction)
                    .disabled(model.busy || !review.rows.contains { $0.decision != .skip && !$0.limited })
            }
        }
    }

    private func setAll(_ pick: (ImportRow) -> ImportDecision?) {
        for row in review.rows { if let d = pick(row) { review.set(d, for: row.id) } }
    }

    private func rowView(_ row: ImportRow) -> some View {
        HStack(spacing: 12) {
            Image(systemName: Self.icon(row.kind)).foregroundStyle(theme.textMuted).frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(row.title.isEmpty ? String(localized: "Untitled") : row.title).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                Text(Self.detail(row)).font(.system(size: 11.5)).foregroundStyle(theme.textMuted).lineLimit(1)
            }
            Spacer(minLength: 8)
            Text(Self.statusLabel(row)).font(.system(size: 11.5, weight: .medium))
                .foregroundStyle(row.limited ? theme.warning : theme.textMuted)
                .padding(.horizontal, 8).padding(.vertical, 2).background(theme.chip, in: Capsule())
            let options = Self.options(for: row)
            if options.count > 1 && !row.limited {
                Picker("", selection: Binding(get: { row.decision }, set: { review.set($0, for: row.id) })) {
                    ForEach(options, id: \.label) { option in Text(option.label).tag(option.decision) }
                }
                .labelsHidden().frame(width: 120)
            } else {
                Text(row.limited ? String(localized: "Not imported") : row.stateLabel).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                    .frame(width: 120, alignment: .leading)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 7)
    }

    struct Option { let label: String; let decision: ImportDecision }

    /// The decisions Windows offers a row (`ImportPlan.set_decision` refuses the rest).
    static func options(for row: ImportRow) -> [Option] {
        if row.isSkippedSource { return [] }
        if row.base == .new { return [Option(label: String(localized: "Add"), decision: .create), Option(label: String(localized: "Skip"), decision: .skip)] }
        var out = [Option(label: String(localized: "Skip"), decision: .skip)]
        if let t = row.targetID, !row.inImportDuplicate, row.kind != .passkey {
            out += [Option(label: String(localized: "Replace"), decision: .replace(t)), Option(label: String(localized: "Merge"), decision: .merge(t))]
        }
        if row.kind != .passkey { out.append(Option(label: String(localized: "Keep both"), decision: .keepBoth)) }
        return out
    }

    static func statusLabel(_ row: ImportRow) -> String {
        switch row.status {
        case .new: String(localized: "New")
        case .duplicate: row.inImportDuplicate ? String(localized: "Repeated in file") : String(localized: "Already here")
        case .conflict: String(localized: "Different password")
        case .limited: String(localized: "Needs Pro")
        case .skipped: String(localized: "Unreadable")
        }
    }

    static func detail(_ row: ImportRow) -> String {
        if case .skipped(let m) = row.base { return m }
        let parts = [row.origin.isEmpty ? "" : OriginLabel.friendly(row.origin), row.username].filter { !$0.isEmpty }
        return parts.isEmpty ? row.kind.rawValue.capitalized : parts.joined(separator: " · ")
    }

    static func icon(_ kind: ImportDraft.Kind) -> String {
        switch kind {
        case .login: "globe"
        case .note: "note.text"
        case .card: "creditcard"
        case .identity: "person.text.rectangle"
        case .passkey: "person.badge.key"
        }
    }
}
