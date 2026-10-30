import SwiftUI
import Observation
import AppShared

/// The only edits the phone makes to a passkey: a new title, or delete. Every other field (the key, the
/// credential id, the relying party) stays byte for byte as stored, so the passkey keeps signing in.
@MainActor
@Observable
final class PasskeyRenameModel {
    var title: String
    private(set) var error: String?
    /// Delete found the passkey gone already: the view says so and closes.
    private(set) var alreadyRemoved = false

    @ObservationIgnored private let store: any ItemStore
    @ObservationIgnored private let id: String
    @ObservationIgnored private let original: String
    @ObservationIgnored private let clock: any UnixClock
    @ObservationIgnored private let background: any BackgroundTasking

    init(store: any ItemStore, item: VaultItem, clock: any UnixClock, background: (any BackgroundTasking)? = nil) {
        self.store = store; self.id = item.id; self.clock = clock
        self.background = background ?? UIKitBackgroundTasks()
        original = item.record["title"]?.stringValue ?? ""
        title = original
    }

    /// Sets `title` and the `updated_at` stamp on the stored record and nothing else; the next sync view bumps
    /// it once for this device. The same title writes nothing.
    func save() -> SaveResult {
        error = nil
        guard !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { error = String(localized: "Enter a name."); return .invalid }
        guard title != original else { return .unchanged }
        do {
            var snap = try store.load()
            guard case .object(let w)? = snap.records[id], w["ns"] == .string(Namespace.item.rawValue),
                  case .object(var r)? = w["record"], r["kind"] == .string("passkey") else {
                error = String(localized: "This passkey is no longer on this iPhone."); return .failed
            }
            r["title"] = .string(title)
            r["updated_at"] = .int(clock.now)
            let record = try Normalise.normalForm(ns: .item, record: .object(r))
            snap.records[id] = Wrapper.make(ns: .item, record: record)
            let change = StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync)
            try background.run("LocalGateKeys save") { try store.commit(change) }
            return .saved
        } catch NormaliseError.rejected(let detail) {
            error = detail; return .invalid
        } catch {
            self.error = String(localized: "The passkey could not be saved on this device."); return .failed
        }
    }

    func clearAlreadyRemoved() { alreadyRemoved = false }

    /// Removes the item and writes its tombstone, as for every other item (`EditorModel.delete`).
    func delete(using move: ((String) -> SaveResult)? = nil) -> SaveResult {
        let r = move?(id) ?? EditorModel.delete(id: id, store: store, clock: clock, background: background)
        if r == .failed { error = String(localized: "The passkey could not be deleted on this device.") }
        alreadyRemoved = r == .unchanged
        return r
    }
}

struct PasskeyEditView: View {
    @State var model: PasskeyRenameModel
    let onDone: (SaveResult) -> Void
    @State private var confirmDelete = false
    @Environment(\.dismiss) private var dismiss
    @Environment(\.phoneTrash) private var trash

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $model.title).textInputAutocapitalization(.words)
                } footer: {
                    Text("Only the name can be changed. The passkey itself stays as it is.")
                }
                if let error = model.error { Text(error).foregroundStyle(.red) }
                Section {
                    Button("Delete passkey", role: .destructive) { confirmDelete = true }
                }
            }
            .navigationTitle("Edit passkey")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        switch model.save() {
                        case .saved: onDone(.saved); dismiss()
                        case .unchanged: dismiss()
                        default: break
                        }
                    }
                }
            }
            // An alert with a visible Cancel, as for other items (tester feedback 1).
            .alert("Delete this passkey?", isPresented: $confirmDelete) {
                Button("Delete", role: .destructive) {
                    if model.delete(using: trash?.mover) == .saved {
                        trash?.offerUndo(); onDone(.saved); dismiss()
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("You will no longer be able to sign in to this website with it.")
            }
            .alert(EditorModel.alreadyRemovedMessage,
                   isPresented: Binding(get: { model.alreadyRemoved }, set: { if !$0 { model.clearAlreadyRemoved() } })) {
                // The list reloads (the item is gone) and the sheet closes.
                Button("OK") { onDone(.saved); dismiss() }
            }
        }
    }
}
