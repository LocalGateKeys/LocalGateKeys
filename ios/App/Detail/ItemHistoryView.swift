import SwiftUI
import AppShared
import LGKCore

/// Item history on this iPhone (feature pack §1): earlier versions of one item, kept on this device only and never
/// synced, with a field-level diff against the item as it is now and Restore for one field.
@MainActor
enum ItemHistoryActions {
    /// Sets `path` of the live item back to its value in `row`. `.unchanged` when the item is gone or the field
    /// already has that value; `.invalid` when the old value is not valid on this device; `.needsOwner` when the
    /// restored value would loosen an access rule (`scope.access`, `policy`) and the owner has not confirmed it yet,
    /// the same check as loosening it in Access rules (scan 2026-11-15 S-M3); `.failed` otherwise.
    static func restore(_ row: ItemHistory.Row, path: String, id: String, store: any ItemStore, clock: any UnixClock,
                        background: (any BackgroundTasking)? = nil, ownerConfirmed: Bool = false) -> SaveResult {
        do {
            var snap = try store.load()
            guard snap.meta[id]?.deleted != true, case .object(let w)? = snap.records[id],
                  case .object(let current)? = w["record"] else { return .unchanged }
            let restored: JSONValue
            do { restored = try ItemHistory.restoreField(current: current, snapshot: row.recordObject, path: path, now: clock.now) }
            catch { return .invalid }
            guard case .object(let o) = restored, o["id"] == .string(id) else { return .failed }
            let ns: LGKCore.Namespace = row.ns == LGKCore.Namespace.entry.rawValue ? .entry : .item
            let unchanged = ItemHistory.diff(before: current, after: o, kind: current["kind"]?.stringValue ?? "")
                .allSatisfy { $0.field == "password_history" }
            if unchanged { return .unchanged }
            if AccessRules.loosens(from: current, to: o), !ownerConfirmed { return .needsOwner }
            // Stored in its normal form, as before (restoreField returns the record as edited, desktop parity).
            let stored = (try? Normalise.normalForm(ns: ns, record: restored)) ?? restored
            snap.records[id] = Wrapper.make(ns: ns, record: stored)
            let change = StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync)
            let tasks = background ?? PlatformBackgroundTasks.make()
            try tasks.run("LocalGateKeys save") {
                try HistoryContext.$changeType.withValue(.restore) { try store.commit(change) }
            }
            return .saved
        } catch {
            return .failed
        }
    }

    /// A short, readable name for a dotted field path.
    static func label(_ path: String) -> String {
        switch path {
        case "title": String(localized: "Title")
        case "username": String(localized: "Username")
        case "password": String(localized: "Password")
        case "notes", "payload.notes": String(localized: "Notes")
        case "totp": String(localized: "One-time code")
        case "tags": String(localized: "Tags")
        case "favorite": String(localized: "Favorite")
        case "scope.origin", "scope.urls": String(localized: "Website")
        default:
            (path.split(separator: ".").last.map(String.init) ?? path).replacingOccurrences(of: "_", with: " ").capitalized
        }
    }

    /// One side of a change, as text.
    static func text(_ value: JSONValue?) -> String {
        switch value {
        case nil, .null?: String(localized: "(empty)")
        case .string(let s)?: s.isEmpty ? String(localized: "(empty)") : s
        case .int(let n)?: String(n)
        case .float(let f)?: String(f)
        case .bool(let b)?: b ? String(localized: "On") : String(localized: "Off")
        case .array(let a)?: String(localized: "\(a.count) entries")
        case .object(let o)?: (try? String(decoding: RecordDigest.canon(.object(o)), as: UTF8.self)) ?? ""
        }
    }

    static func changeLabel(_ type: String) -> String {
        switch ItemHistory.ChangeType(rawValue: type) {
        case .update?: String(localized: "Edited")
        case .sync?: String(localized: "Changed by sync")
        case .restore?: String(localized: "Restored")
        case .import?: String(localized: "Changed by an import")
        case .merge?: String(localized: "Merged")
        case nil: String(localized: "Changed")
        }
    }
}

/// The versions of one item, newest first.
struct ItemHistoryView: View {
    let item: VaultItem
    let store: any ItemStore
    let pro: ProModel
    let readOnly: Bool
    let onChange: () -> Void
    @State private var rows: [ItemHistory.Row] = []

    var body: some View {
        List {
            Section {
                if rows.isEmpty {
                    Text("No earlier versions on this device yet.").foregroundStyle(Palette.secondaryText)
                }
                ForEach(rows) { row in
                    NavigationLink {
                        ItemVersionView(item: item, row: row, store: store, readOnly: readOnly, onChange: { onChange(); reload() })
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(Date(timeIntervalSince1970: TimeInterval(row.createdAt)).formatted(date: .abbreviated, time: .shortened))
                                .foregroundStyle(Palette.text)
                            Text(ItemHistoryActions.changeLabel(row.changeType)).font(.caption).foregroundStyle(Palette.secondaryText)
                        }
                        .accessibilityElement(children: .combine)
                    }
                }
            } footer: {
                Text(pro.isPro
                     ? String(localized: "Kept on this device only and never synced: up to 30 versions per item for a year.")
                     : String(localized: "Kept on this device only and never synced: up to 5 versions per item for 30 days. Pro keeps 30 versions for a year."))
            }
            .listRowBackground(Palette.groupSurface)
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Item history")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear(perform: reload)
    }

    private func reload() {
        rows = ItemHistory.versions(of: item.id, in: HistoryRecorder.shared.host?.localData?.itemHistory ?? [])
    }
}

/// One earlier version: what changed since (secrets hidden until the owner confirms), and Restore for one field.
struct ItemVersionView: View {
    let item: VaultItem
    let row: ItemHistory.Row
    let store: any ItemStore
    let readOnly: Bool
    let onChange: () -> Void
    @State private var revealed = false
    @State private var changes: [ItemHistory.FieldChange] = []
    @State private var restoring: ItemHistory.FieldChange?
    @State private var message: String?

    var body: some View {
        List {
            Section {
                if changes.isEmpty {
                    Text("This version matches the item as it is now.").foregroundStyle(Palette.secondaryText)
                }
                ForEach(changes) { change in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(ItemHistoryActions.label(change.field)).font(.caption).foregroundStyle(Palette.secondaryText)
                        LabeledContent("Then") {
                            Text(ItemHistoryActions.text(change.before)).foregroundStyle(Palette.text).textSelection(.disabled)
                        }
                        LabeledContent("Now") {
                            Text(ItemHistoryActions.text(change.after)).foregroundStyle(Palette.text).textSelection(.disabled)
                        }
                        if !readOnly && ItemHistory.isRestorable(change.field) {
                            Button("Restore this field") { restoring = change }
                                .buttonStyle(.borderless).font(.caption.weight(.semibold))
                                .foregroundStyle(Palette.accentText)
                                .accessibilityLabel(String(localized: "Restore \(ItemHistoryActions.label(change.field))"))
                        }
                    }
                    .padding(.vertical, 2)
                }
            } header: {
                Text(Date(timeIntervalSince1970: TimeInterval(row.createdAt)).formatted(date: .abbreviated, time: .shortened))
            }
            .listRowBackground(Palette.groupSurface)
            if let message {
                Text(message).font(.footnote).foregroundStyle(Palette.secondaryText).listRowBackground(Color.clear)
            }
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Earlier version")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button(revealed ? String(localized: "Hide") : String(localized: "Reveal")) {
                    if revealed { revealed = false; reload() } else {
                        Task {
                            revealed = await AppPasswordGate.confirmOwner(String(localized: "Show hidden fields of an earlier version"))
                            reload()
                        }
                    }
                }
                .disabled(ScreenCaptureMonitor.shared.isCaptured)
            }
        }
        .onAppear(perform: reload)
        .onDisappear { revealed = false }
        .alert("Restore this field?", isPresented: Binding(get: { restoring != nil }, set: { if !$0 { restoring = nil } })) {
            Button("Restore") {
                if let change = restoring { restore(change) }
                restoring = nil
            }
            Button("Cancel", role: .cancel) { restoring = nil }
        } message: {
            Text("The field gets its earlier value back. The version it replaces is kept in this history.")
        }
    }

    private func reload() {
        let current: [String: JSONValue] = (try? store.load()).flatMap { snap in
            VaultItem.items(from: snap).first(where: { $0.id == item.id })?.record
        } ?? item.record
        changes = ItemHistory.diff(before: row.recordObject, after: current, kind: current["kind"]?.stringValue ?? item.kind,
                                   reveal: revealed && !ScreenCaptureMonitor.shared.isCaptured)
    }

    private func restore(_ change: ItemHistory.FieldChange, ownerConfirmed: Bool = false) {
        switch ItemHistoryActions.restore(row, path: change.field, id: item.id, store: store, clock: SystemClock(),
                                          ownerConfirmed: ownerConfirmed) {
        case .needsOwner:
            // The earlier value loosens this login's access rules: the owner confirms first, as in Access rules.
            Task {
                guard await AppPasswordGate.confirmOwner(String(localized: "Change this login's access rules")) else { return }
                restore(change, ownerConfirmed: true)
            }
        case .saved: onChange(); CopyToast.shared.show(String(localized: "Field restored")); message = nil; reload()
        case .unchanged: reload()
        case .invalid: message = String(localized: "That earlier value is not valid on this device, so it was not restored.")
        default: message = String(localized: "The field could not be restored. Try again.")
        }
    }
}
