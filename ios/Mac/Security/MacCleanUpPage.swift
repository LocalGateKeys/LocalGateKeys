import SwiftUI
import Observation
import AppSharedMac

/// The clean-up sweep on this Mac (feature pack §3), apart from SwiftUI: the findings over the items travel mode
/// leaves visible, one reviewed merge or one delete at a time (Free), and the Pro bulk actions with one Undo, through
/// the iPhone's shared `HygieneActions` with this Mac's Recently deleted and item history.
@MainActor @Observable
final class MacCleanUpModel {
    private(set) var findings: [Hygiene.Finding] = []
    private(set) var items: [String: VaultItem] = [:]
    /// Pro selection mode: the items picked for Delete.
    var selecting = false
    var selected: Set<String> = []
    /// The line under the summary after an action.
    var message: String?
    /// The last bulk action can be undone (until the vault locks or the next bulk action).
    private(set) var canUndo = HygieneActions.lastBulk != nil

    @ObservationIgnored let store: any ItemStore
    @ObservationIgnored private let trash: TrashModel?
    @ObservationIgnored private let local: (any LocalDataHosting)?
    @ObservationIgnored let isPro: () -> Bool
    @ObservationIgnored private let onNeedsPro: (ProReason) -> Void
    @ObservationIgnored private let hidden: @MainActor (StoreSnapshot) -> Set<String>
    @ObservationIgnored private let now: () -> Int64
    /// Called after anything changed in the store (the window reloads its list).
    @ObservationIgnored var onChange: () -> Void = {}

    init(store: any ItemStore, trash: TrashModel?, local: (any LocalDataHosting)?, isPro: @escaping () -> Bool,
         onNeedsPro: @escaping (ProReason) -> Void,
         hidden: @escaping @MainActor (StoreSnapshot) -> Set<String> = { MacAccess.travelHidden($0) },
         now: @escaping () -> Int64 = { SystemClock().now }) {
        self.store = store; self.trash = trash; self.local = local; self.isPro = isPro; self.onNeedsPro = onNeedsPro
        self.hidden = hidden; self.now = now
    }

    var summary: Hygiene.Summary { Hygiene.summary(findings) }
    /// Merging and deleting need Recently deleted (local data).
    var canChange: Bool { trash != nil }

    /// Recomputes the findings (no network; travel-hidden items left out).
    func reload() {
        guard let snap = try? store.load() else { return }
        findings = HygieneScan.findings(snap, hidden: hidden(snap), now: now(), today: RecordDigest.today(),
                                        matcher: SafariSaveService.bundledMatcher())
        items = Dictionary(VaultItem.items(from: snap).map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        selected = selected.filter { items[$0] != nil }
        canUndo = HygieneActions.lastBulk != nil
    }

    var actions: HygieneActions? {
        guard let trash else { return nil }
        let local = local, isPro = isPro, now = now
        return HygieneActions(store: store, now: now, background: PlatformBackgroundTasks.make(),
                              moveToTrash: { ids in ids.filter { id in (try? trash.moveToTrash(id: id)) != nil } },
                              restoreFromTrash: { trash.restoreItems($0) },
                              recordHistory: { rows in
                                  guard let local, let data = local.localData else { return }
                                  try? local.commitLocalData(HistoryCapture.appending(rows, to: data, now: now(),
                                                                                      limits: .plan(isPro: isPro())))
                              })
    }

    /// Moves one item to Recently deleted (Free).
    func deleteOne(_ id: String) {
        guard let trash else { return }
        do {
            try trash.moveToTrash(id: id)
            message = String(localized: "Moved to Recently deleted")
        } catch TrashModel.Failure.readOnly {
            message = EditorModel.readOnlyItemText
        } catch TrashModel.Failure.compensation {
            message = TrashModel.compensationMessage
        } catch {
            message = TrashModel.deleteFailedMessage
        }
        changed()
    }

    /// Selection mode is Pro: without it the upgrade sheet shows instead.
    func toggleSelecting() {
        if !selecting && !isPro() {
            message = HygieneActions.bulkNeedsPro
            onNeedsPro(.hygiene)
            return
        }
        selecting.toggle()
        selected = []
    }

    func toggle(_ id: String) { if selected.contains(id) { selected.remove(id) } else { selected.insert(id) } }

    func deleteSelected() {
        guard let actions else { return }
        finished(actions.deleteMany(selected.sorted(), isPro: isPro()), done: String(localized: "Moved to Recently deleted"))
    }

    func mergeAllSameLogins() {
        guard let actions else { return }
        finished(actions.mergeAllSameLogins(findings, isPro: isPro()),
                 done: String(localized: "Same logins merged. The other copies are in Recently deleted."))
    }

    func undoBulk() {
        guard let actions else { return }
        let n = actions.undoLastBulk()
        message = String(localized: "Clean-up undone: \(n) items changed back.")
        changed()
    }

    /// A reviewed merge finished (nil: cancelled).
    func merged(_ outcome: HygieneActions.Outcome?) {
        finished(outcome, done: String(localized: "Merged. The other copy is in Recently deleted."))
    }

    private func finished(_ outcome: HygieneActions.Outcome?, done: String) {
        guard let outcome else { return }
        if outcome == .done {
            message = done
            selecting = false
            selected = []
        } else {
            message = HygieneActions.text(outcome)
            if outcome == .needsPro { onNeedsPro(.hygiene) }
        }
        changed()
    }

    private func changed() {
        reload()
        onChange()
    }

    func name(_ id: String) -> String {
        guard let item = items[id] else { return String(localized: "Untitled") }
        return item.title.isEmpty ? item.kindLabel : item.title
    }
}

/// Security centre › Clean-up: duplicates, items not changed in 2 years and expired cards and licences, each group
/// with its items. Duplicates merge one pair at a time after a review; with Pro, many items can be deleted at once
/// and every same login merged, with one Undo (cleared when the vault locks).
struct MacCleanUpPage: View {
    @Bindable var model: MacCleanUpModel
    /// Shows one item in the main list.
    let onOpen: (String) -> Void
    var onBack: (() -> Void)? = nil
    @Environment(\.macTheme) private var theme
    @State private var reviewing: Hygiene.Finding?
    @State private var confirmingBulk = false

    var body: some View {
        let summary = model.summary
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 10) {
                        if let onBack {
                            Button(action: onBack) { Image(systemName: "chevron.left") }
                                .buttonStyle(.plain).foregroundStyle(theme.textMuted)
                                .help(String(localized: "Security centre"))
                                .accessibilityLabel(String(localized: "Security centre"))
                        }
                        Text("Clean-up").font(.system(size: 19, weight: .semibold)).accessibilityAddTraits(.isHeader)
                        Spacer(minLength: 12)
                        if model.canChange && !model.findings.isEmpty {
                            Button(model.selecting ? String(localized: "Done") : String(localized: "Select")) { model.toggleSelecting() }
                                .buttonStyle(PillButtonStyle(primary: false))
                        }
                    }
                    Text("Checked on this device only. Nothing is changed until you choose.")
                        .font(.system(size: 12)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
                }
                card {
                    summaryRow(String(localized: "Duplicates"), summary.duplicates)
                    divider
                    summaryRow(String(localized: "Not changed in 2 years"), summary.notChanged)
                    divider
                    summaryRow(String(localized: "Expired"), summary.expired)
                }
                if let message = model.message {
                    Text(message).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if model.canUndo {
                    Button(String(localized: "Undo last clean-up"), action: model.undoBulk).buttonStyle(PillButtonStyle(primary: false))
                }
                if model.selecting { bulkBar }
                ForEach(model.findings) { finding in group(finding) }
            }
            .padding(18).padding(.bottom, 24)
            .frame(maxWidth: 820, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .foregroundStyle(theme.text)
        .onAppear(perform: model.reload)
        .alert(String(localized: "Delete \(model.selected.count) items"), isPresented: $confirmingBulk) {
            Button(String(localized: "Delete \(model.selected.count) items"), role: .destructive, action: model.deleteSelected)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("They go to Recently deleted. You can undo this until the vault locks.")
        }
        .sheet(item: $reviewing) { finding in
            MacMergeReviewSheet(finding: finding, model: model) { outcome in
                reviewing = nil
                model.merged(outcome)
            }
            .macThemed()
        }
    }

    private var bulkBar: some View {
        HStack(spacing: 8) {
            Button(String(localized: "Delete \(model.selected.count) items"), role: .destructive) { confirmingBulk = true }
                .buttonStyle(PillButtonStyle(primary: true)).disabled(model.selected.isEmpty)
            if model.findings.contains(where: { $0.type == .sameLogin }) {
                Button(String(localized: "Merge all same logins"), action: model.mergeAllSameLogins)
                    .buttonStyle(PillButtonStyle(primary: false))
            }
        }
    }

    private func summaryRow(_ title: String, _ count: Int) -> some View {
        HStack {
            Text(title).font(.system(size: 13))
            Spacer(minLength: 12)
            Text("\(count)").font(.system(size: 13, weight: .semibold)).monospacedDigit()
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
        .accessibilityElement(children: .combine)
    }

    private func group(_ finding: Hygiene.Finding) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(HygieneScan.label(finding.type).uppercased()).font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(theme.textFaint).accessibilityAddTraits(.isHeader)
                Spacer(minLength: 8)
                if !model.selecting && model.canChange && HygieneActions.isMergeable(finding.type) && finding.ids.count > 1 {
                    Button(String(localized: "Review and merge")) { reviewing = finding }
                        .buttonStyle(PillButtonStyle(primary: false))
                }
            }
            .padding(.leading, 4)
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(finding.ids.enumerated()), id: \.element) { index, id in
                    if index > 0 { divider }
                    if let item = model.items[id] { row(item) }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
        }
    }

    private func row(_ item: VaultItem) -> some View {
        let name = model.name(item.id)
        return HStack(spacing: 10) {
            if model.selecting {
                Toggle(isOn: Binding(get: { model.selected.contains(item.id) }, set: { _ in model.toggle(item.id) })) { EmptyView() }
                    .toggleStyle(.checkbox).labelsHidden()
                    .accessibilityLabel(name)
            }
            ItemLogo(item: item, size: 24).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(name).font(.system(size: 13)).lineLimit(1)
                Text(item.isLogin && !item.username.isEmpty ? item.username : item.kindLabel)
                    .font(.system(size: 11)).foregroundStyle(theme.textMuted).lineLimit(1)
            }
            Spacer(minLength: 8)
            if !model.selecting {
                Button(String(localized: "Open")) { onOpen(item.id) }
                    .buttonStyle(PillButtonStyle(primary: false))
                    .accessibilityLabel(String(localized: "Open") + ", " + name)
                if model.canChange {
                    Button(String(localized: "Delete"), role: .destructive) { model.deleteOne(item.id) }
                        .buttonStyle(PillButtonStyle(primary: false))
                        .accessibilityLabel(String(localized: "Delete") + ", " + name)
                }
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
    }

    private var divider: some View { Rectangle().fill(theme.panelBorder).frame(height: 1).padding(.leading, 14) }

    private func card<C: View>(@ViewBuilder _ content: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 0) { content() }
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
    }
}

/// Reviews one merge before it is written: which copy is kept, which goes to Recently deleted, and what changes in the
/// kept copy (hidden fields stay masked). Nothing is merged without this review.
struct MacMergeReviewSheet: View {
    let finding: Hygiene.Finding
    let model: MacCleanUpModel
    let onDone: (HygieneActions.Outcome?) -> Void
    @Environment(\.macTheme) private var theme
    @State private var keeperID = ""
    @State private var otherID = ""
    @State private var preview: HygieneActions.MergePreview?
    @State private var refusal: String?

    var body: some View {
        VStack(alignment: .leading, spacing: MacTheme.gap) {
            Text("Review merge").font(.title3.weight(.semibold)).foregroundStyle(theme.text)
            Text(HygieneActions.mergeReview).font(.callout).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            Picker(String(localized: "Keep"), selection: $keeperID) {
                ForEach(finding.ids, id: \.self) { id in Text(model.name(id)).tag(id) }
            }
            Picker(String(localized: "Merge into it"), selection: $otherID) {
                ForEach(finding.ids.filter { $0 != keeperID }, id: \.self) { id in Text(model.name(id)).tag(id) }
            }
            Text("What changes in the kept item").font(.system(size: 11, weight: .semibold)).foregroundStyle(theme.textFaint)
                .accessibilityAddTraits(.isHeader)
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    if let refusal {
                        Text(refusal).foregroundStyle(theme.textMuted)
                    } else if let preview, preview.changes.isEmpty && preview.collections == nil {
                        Text("Nothing changes in the kept item.").foregroundStyle(theme.textMuted)
                    } else if let preview {
                        ForEach(preview.changes) { change in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(MacItemHistoryModel.label(change.field)).font(.system(size: 11)).foregroundStyle(theme.textMuted)
                                LabeledContent(String(localized: "Now")) { Text(MacItemHistoryModel.text(change.before)) }
                                LabeledContent(String(localized: "After")) { Text(MacItemHistoryModel.text(change.after)) }
                            }
                            .font(.system(size: 12.5))
                            .accessibilityElement(children: .combine)
                        }
                        if preview.collections != nil {
                            Text("It also joins the other copy's collections.").foregroundStyle(theme.textMuted)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 280)
            HStack {
                Spacer()
                Button("Cancel") { onDone(nil) }.buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button("Merge") {
                    guard let preview, let actions = model.actions else { return }
                    onDone(actions.merge(preview))
                }
                .buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(preview == nil || !model.canChange)
            }
        }
        .padding(24).frame(width: 460)
        .background(WashBackground())
        .onAppear {
            keeperID = finding.ids.first ?? ""
            otherID = finding.ids.dropFirst().first ?? ""
            compute()
        }
        .onChange(of: keeperID) { _, keeper in
            if otherID == keeper { otherID = finding.ids.first(where: { $0 != keeper }) ?? "" }
            compute()
        }
        .onChange(of: otherID) { _, _ in compute() }
    }

    private func compute() {
        preview = nil
        refusal = nil
        guard let snap = try? model.store.load() else { refusal = HygieneActions.text(.failed); return }
        switch HygieneActions.preview(keeper: keeperID, other: otherID, in: snap, now: SystemClock().now) {
        case .success(let p): preview = p
        case .failure(let r): refusal = HygieneActions.refusalText(r)
        }
    }
}
