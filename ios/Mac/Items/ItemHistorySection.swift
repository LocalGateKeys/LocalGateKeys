import SwiftUI
import Observation
import AppSharedMac

/// Item history on this Mac (feature pack §1): the earlier versions of one item from this Mac's local data (kept here
/// only, never synced), a field diff against the item as it is now with secrets shown as "[protected]" until
/// confirmed, and Restore for one field (committed as a "restore" change, so the replaced version stays in history).
@MainActor @Observable
final class MacItemHistoryModel {
    @ObservationIgnored let store: any ItemStore
    @ObservationIgnored private let rows: () -> [ItemHistory.Row]
    @ObservationIgnored let isPro: () -> Bool
    @ObservationIgnored private let now: () -> Int64

    init(store: any ItemStore, rows: @escaping () -> [ItemHistory.Row], isPro: @escaping () -> Bool,
         now: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970) }) {
        self.store = store; self.rows = rows; self.isPro = isPro; self.now = now
    }

    /// The versions of `itemID`, newest first.
    func versions(of itemID: String) -> [ItemHistory.Row] { ItemHistory.versions(of: itemID, in: rows()) }

    /// The item as stored now (falls back to `item.record`).
    func current(_ item: VaultItem) -> [String: JSONValue] {
        (try? store.load()).flatMap { snap in VaultItem.items(from: snap).first(where: { $0.id == item.id })?.record } ?? item.record
    }

    /// What changed between `row` and the item now; secrets are "[protected]" unless `reveal`.
    func changes(_ row: ItemHistory.Row, item: VaultItem, reveal: Bool) -> [ItemHistory.FieldChange] {
        let current = current(item)
        return ItemHistory.diff(before: row.recordObject, after: current, kind: current["kind"]?.stringValue ?? item.kind,
                                reveal: reveal)
    }

    /// Sets `path` of the live item back to its value in `row` (the iPhone's `ItemHistoryActions.restore`).
    /// `.needsOwner` when the restored value would loosen an access rule (`scope.access`, `policy`) and the master
    /// password has not been confirmed for it yet (scan 2026-11-15 S-M3).
    func restore(_ row: ItemHistory.Row, path: String, id: String, ownerConfirmed: Bool = false) -> SaveResult {
        do {
            var snap = try store.load()
            guard snap.meta[id]?.deleted != true, case .object(let w)? = snap.records[id],
                  case .object(let current)? = w["record"] else { return .unchanged }
            let restored: JSONValue
            do { restored = try ItemHistory.restoreField(current: current, snapshot: row.recordObject, path: path, now: now()) }
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
            try HistoryContext.$changeType.withValue(.restore) { try store.commit(change) }
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

/// The detail pane's "Item history" (collapsed by default): versions newest first; choosing one shows what changed
/// since, with Reveal (through `StrictItemGate`) and Restore this field (asks first). Read-only items show no Restore.
struct ItemHistorySection: View {
    let item: VaultItem
    let model: MacItemHistoryModel
    let gate: StrictItemGate
    let readOnly: Bool
    let onRestored: () -> Void
    @State private var expanded = false
    @State private var selected: String?
    @State private var revealed = false
    @State private var restoring: ItemHistory.FieldChange?
    @State private var message: String?
    @State private var tick = 0
    @Environment(\.macTheme) private var theme

    var body: some View {
        let versions = { _ = tick; return model.versions(of: item.id) }()
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 8) {
                if versions.isEmpty {
                    Text("No earlier versions on this device yet.").font(.system(size: 13)).foregroundStyle(theme.textMuted)
                }
                ForEach(versions) { row in
                    VStack(alignment: .leading, spacing: 6) {
                        Button {
                            selected = selected == row.id ? nil : row.id
                            revealed = false; message = nil
                        } label: {
                            HStack {
                                Text(Date(timeIntervalSince1970: TimeInterval(row.createdAt)).formatted(date: .abbreviated, time: .shortened))
                                Text(MacItemHistoryModel.changeLabel(row.changeType)).foregroundStyle(theme.textMuted)
                                Spacer()
                                Image(systemName: selected == row.id ? "chevron.down" : "chevron.right").foregroundStyle(theme.textFaint)
                            }
                            .font(.system(size: 13)).contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityElement(children: .combine)
                        .accessibilityAddTraits(.isButton)
                        if selected == row.id { versionDetail(row) }
                    }
                }
                Text(model.isPro()
                     ? String(localized: "Kept on this device only and never synced: up to 30 versions per item for a year.")
                     : String(localized: "Kept on this device only and never synced: up to 5 versions per item for 30 days. Pro keeps 30 versions for a year."))
                    .font(.system(size: 12)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
                if let message {
                    Text(message).font(.system(size: 12.5)).foregroundStyle(theme.danger).fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.top, 6)
        } label: {
            Text("Item history").font(.system(size: 12)).foregroundStyle(theme.textFaint).accessibilityAddTraits(.isHeader)
        }
        .padding(.top, 14)
        .onChange(of: item.id) { _, _ in selected = nil; revealed = false; message = nil }
        .alert("Restore this field?", isPresented: Binding(get: { restoring != nil }, set: { if !$0 { restoring = nil } })) {
            Button("Restore") {
                if let change = restoring, let row = model.versions(of: item.id).first(where: { $0.id == selected }) { restore(change, row: row) }
                restoring = nil
            }
            Button("Cancel", role: .cancel) { restoring = nil }
        } message: {
            Text("The field gets its earlier value back. The version it replaces is kept in this history.")
        }
    }

    @ViewBuilder private func versionDetail(_ row: ItemHistory.Row) -> some View {
        let changes = { _ = tick; return model.changes(row, item: item, reveal: revealed) }()
        VStack(alignment: .leading, spacing: 8) {
            if changes.isEmpty {
                Text("This version matches the item as it is now.").font(.system(size: 13)).foregroundStyle(theme.textMuted)
            }
            if changes.contains(where: \.secret) {
                Button(revealed ? String(localized: "Hide") : String(localized: "Reveal")) {
                    if revealed { revealed = false } else {
                        gate.releaseRoutine(item, action: String(localized: "Show hidden fields of an earlier version")) { revealed = true }
                    }
                }
                .buttonStyle(.plain).foregroundStyle(theme.link).font(.system(size: 13))
            }
            ForEach(changes) { change in
                VStack(alignment: .leading, spacing: 3) {
                    Text(MacItemHistoryModel.label(change.field)).font(.system(size: 12)).foregroundStyle(theme.textFaint)
                    HStack(alignment: .top, spacing: 6) {
                        Text("Then").foregroundStyle(theme.textMuted).frame(width: 44, alignment: .leading)
                        Text(MacItemHistoryModel.text(change.before)).textSelection(.disabled).lineLimit(4)
                    }
                    HStack(alignment: .top, spacing: 6) {
                        Text("Now").foregroundStyle(theme.textMuted).frame(width: 44, alignment: .leading)
                        Text(MacItemHistoryModel.text(change.after)).textSelection(.disabled).lineLimit(4)
                    }
                    if !readOnly && ItemHistory.isRestorable(change.field) {
                        Button("Restore this field") { restoring = change }
                            .buttonStyle(.plain).foregroundStyle(theme.link)
                            .accessibilityLabel(String(localized: "Restore \(MacItemHistoryModel.label(change.field))"))
                    }
                }
                .font(.system(size: 13))
            }
        }
        .padding(.leading, 12)
    }

    private func restore(_ change: ItemHistory.FieldChange, row: ItemHistory.Row) {
        // A strict login's fields change only after the master password (as editing it does).
        // That prompt (master password, no grace) is also the owner check a loosened access rule needs.
        let strict = StrictItemGate.isStrict(item)
        gate.release(item, action: String(localized: "Restore \(MacItemHistoryModel.label(change.field))")) {
            write(change, row: row, ownerConfirmed: strict)
        }
    }

    private func write(_ change: ItemHistory.FieldChange, row: ItemHistory.Row, ownerConfirmed: Bool) {
        switch model.restore(row, path: change.field, id: item.id, ownerConfirmed: ownerConfirmed) {
        case .needsOwner:
            // The earlier value loosens this login's access rules: the master password first, as in Access rules.
            gate.confirmMasterPassword(title: item.title.isEmpty ? item.kindLabel : item.title,
                                       action: String(localized: "Change this login's access rules")) {
                write(change, row: row, ownerConfirmed: true)
            }
        case .saved: message = nil; onRestored(); tick += 1
        case .unchanged: tick += 1
        case .invalid: message = String(localized: "That earlier value is not valid on this device, so it was not restored.")
        default: message = String(localized: "The field could not be restored. Try again.")
        }
    }
}
