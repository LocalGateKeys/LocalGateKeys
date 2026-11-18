import SwiftUI
import AppShared

/// Security › Clean-up: duplicates, items not changed in 2 years, and expired cards and licences. Each group opens its
/// items. Duplicates can be merged one pair at a time after a review; with Pro, many items can be deleted at once and
/// every same login merged, with one Undo (feature pack §3.2 and §3.3). Deleted items go to Recently deleted.
struct HygieneView: View {
    let store: any ItemStore
    let pro: ProModel
    let onChange: () -> Void
    @Environment(\.phoneTrash) private var trash
    @State private var findings: [Hygiene.Finding] = []
    @State private var items: [String: VaultItem] = [:]
    @State private var reviewing: Hygiene.Finding?
    @State private var selecting = false
    @State private var selected: Set<String> = []
    @State private var confirmingBulk = false
    @State private var canUndo = HygieneActions.lastBulk != nil
    @State private var message: String?

    var body: some View {
        let summary = Hygiene.summary(findings)
        List {
            Section {
                LabeledContent("Duplicates", value: "\(summary.duplicates)")
                LabeledContent("Not changed in 2 years", value: "\(summary.notChanged)")
                LabeledContent("Expired", value: "\(summary.expired)")
            } footer: {
                Text("Checked on this device only. Nothing is changed until you choose.")
            }
            .listRowBackground(Palette.groupSurface)
            if let message {
                Text(message).font(.footnote).foregroundStyle(Palette.secondaryText).listRowBackground(Color.clear)
            }
            if canUndo {
                Button("Undo last clean-up", action: undoBulk).listRowBackground(Palette.groupSurface)
            }
            ForEach(findings) { finding in
                Section(HygieneScan.label(finding.type)) {
                    ForEach(finding.ids, id: \.self) { id in
                        if let item = items[id] { row(item) }
                    }
                    if !selecting && HygieneActions.isMergeable(finding.type) && finding.ids.count > 1 && trash != nil {
                        Button("Review and merge") { reviewing = finding }
                            .font(.subheadline.weight(.semibold)).foregroundStyle(Palette.accentText)
                    }
                }
                .listRowBackground(Palette.groupSurface)
            }
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Clean-up")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if trash != nil && !findings.isEmpty {
                    Button(selecting ? String(localized: "Done") : String(localized: "Select")) {
                        selecting.toggle()
                        selected = []
                    }
                }
            }
            ToolbarItemGroup(placement: .bottomBar) {
                if selecting {
                    Button(String(localized: "Delete \(selected.count) items"), role: .destructive) { confirmingBulk = true }
                        .disabled(selected.isEmpty)
                    Spacer()
                    if findings.contains(where: { $0.type == .sameLogin }) {
                        Button("Merge all same logins", action: mergeAll)
                    }
                }
            }
        }
        .confirmationDialog(String(localized: "Delete \(selected.count) items"), isPresented: $confirmingBulk, titleVisibility: .visible) {
            Button(String(localized: "Delete \(selected.count) items"), role: .destructive, action: deleteSelected)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("They go to Recently deleted. You can undo this until the vault locks.")
        }
        .sheet(item: $reviewing) { finding in
            NavigationStack {
                MergeReviewSheet(finding: finding, items: items, store: store, actions: actions) { outcome in
                    reviewing = nil
                    finished(outcome, done: String(localized: "Merged. The other copy is in Recently deleted."))
                }
            }
        }
        .onAppear(perform: reload)
    }

    @ViewBuilder private func row(_ item: VaultItem) -> some View {
        if selecting {
            Button {
                if selected.contains(item.id) { selected.remove(item.id) } else { selected.insert(item.id) }
            } label: {
                HStack {
                    Image(systemName: selected.contains(item.id) ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(Palette.accentText).accessibilityHidden(true)
                    VaultRow(item: item)
                }
            }
            .buttonStyle(.plain)
            .accessibilityAddTraits(selected.contains(item.id) ? .isSelected : [])
        } else {
            NavigationLink(value: item) { VaultRow(item: item) }
                .swipeActions {
                    if trash != nil {
                        Button("Delete", role: .destructive) { deleteOne(item.id) }
                    }
                }
        }
    }

    private var actions: HygieneActions? {
        guard let trash else { return nil }
        let isPro = pro.isPro
        return HygieneActions(store: store, now: { SystemClock().now }, background: PlatformBackgroundTasks.make(),
                              moveToTrash: { trash.moveToTrash(ids: $0) },
                              restoreFromTrash: { trash.restoreItems($0, isPro: isPro) },
                              recordHistory: { HistoryRecorder.shared.record($0) })
    }

    private func deleteOne(_ id: String) {
        guard let trash, trash.moveToTrash(ids: [id]) == [id] else {
            message = HygieneActions.text(.failed)
            return
        }
        let isPro = pro.isPro
        changed()
        UndoToast.shared.show(String(localized: "Moved to Recently deleted")) {
            trash.restoreItems([id], isPro: isPro)
            changed()
        }
    }

    private func deleteSelected() {
        guard let actions else { return }
        let outcome = actions.deleteMany(selected.sorted(), isPro: pro.isPro)
        finished(outcome, done: String(localized: "Moved to Recently deleted"))
    }

    private func mergeAll() {
        guard let actions else { return }
        finished(actions.mergeAllSameLogins(findings, isPro: pro.isPro),
                 done: String(localized: "Same logins merged. The other copies are in Recently deleted."))
    }

    private func undoBulk() {
        guard let actions else { return }
        let n = actions.undoLastBulk()
        message = String(localized: "Clean-up undone: \(n) items changed back.")
        changed()
    }

    private func finished(_ outcome: HygieneActions.Outcome?, done: String) {
        guard let outcome else { return }
        if outcome == .done {
            message = done
            selecting = false
            selected = []
        } else {
            message = HygieneActions.text(outcome)
        }
        changed()
    }

    private func changed() {
        canUndo = HygieneActions.lastBulk != nil
        reload()
        onChange()
    }

    private func reload() {
        guard let snap = try? store.load() else { return }
        let hidden = TravelModeBox.shared.current.hiddenIDs(in: snap)
        findings = HygieneScan.findings(snap, hidden: hidden, now: SystemClock().now, today: RecordDigest.today(),
                                        matcher: SafariSaveService.bundledMatcher())
        items = Dictionary(VaultItem.items(from: snap).map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        selected = selected.filter { items[$0] != nil }
    }
}

/// Reviews one merge before it is written: which copy is kept, which goes to Recently deleted, and what changes in
/// the kept copy (hidden fields stay masked). Nothing is merged without this review.
private struct MergeReviewSheet: View {
    let finding: Hygiene.Finding
    let items: [String: VaultItem]
    let store: any ItemStore
    let actions: HygieneActions?
    let onDone: (HygieneActions.Outcome?) -> Void
    @State private var keeperID = ""
    @State private var otherID = ""
    @State private var preview: HygieneActions.MergePreview?
    @State private var refusal: String?

    var body: some View {
        Form {
            Section {
                Picker("Keep", selection: $keeperID) {
                    ForEach(finding.ids, id: \.self) { id in Text(name(id)).tag(id) }
                }
                Picker("Merge into it", selection: $otherID) {
                    ForEach(finding.ids.filter { $0 != keeperID }, id: \.self) { id in Text(name(id)).tag(id) }
                }
            } footer: {
                Text(HygieneActions.mergeReview)
            }
            .listRowBackground(Palette.groupSurface)
            Section("What changes in the kept item") {
                if let refusal {
                    Text(refusal).foregroundStyle(Palette.secondaryText)
                } else if let preview, preview.changes.isEmpty && preview.collections == nil {
                    Text("Nothing changes in the kept item.").foregroundStyle(Palette.secondaryText)
                } else if let preview {
                    ForEach(preview.changes) { change in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(ItemHistoryActions.label(change.field)).font(.caption).foregroundStyle(Palette.secondaryText)
                            LabeledContent("Now") { Text(ItemHistoryActions.text(change.before)).textSelection(.disabled) }
                            LabeledContent("After") { Text(ItemHistoryActions.text(change.after)).textSelection(.disabled) }
                        }
                    }
                    if preview.collections != nil {
                        Text("It also joins the other copy's collections.").foregroundStyle(Palette.secondaryText)
                    }
                }
            }
            .listRowBackground(Palette.groupSurface)
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Review merge")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { onDone(nil) } }
            ToolbarItem(placement: .confirmationAction) {
                Button("Merge") {
                    guard let preview, let actions else { return }
                    onDone(actions.merge(preview))
                }
                .disabled(preview == nil || actions == nil)
            }
        }
        .onAppear {
            keeperID = finding.ids.first ?? ""
            otherID = finding.ids.dropFirst().first ?? ""
            compute()
        }
        .onChange(of: keeperID) { _, keeper in
            if otherID == keeper { otherID = finding.ids.first(where: { $0 != keeper }) ?? "" }
            compute()
        }
        .onChange(of: otherID) { compute() }
    }

    private func name(_ id: String) -> String {
        guard let item = items[id] else { return id }
        return item.title.isEmpty ? String(localized: "Untitled") : item.title
    }

    private func compute() {
        preview = nil
        refusal = nil
        guard let snap = try? store.load() else { refusal = HygieneActions.text(.failed); return }
        switch HygieneActions.preview(keeper: keeperID, other: otherID, in: snap, now: SystemClock().now) {
        case .success(let p): preview = p
        case .failure(let r): refusal = HygieneActions.refusalText(r)
        }
    }
}
