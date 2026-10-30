import SwiftUI
import LocalAuthentication
import AppShared

/// A login's past passwords (UX plan workstream 8): `password_history` rows, newest first. Restoring one makes
/// it the password again; the current one goes into the history (the editor's rule), so nothing is lost.
@MainActor
enum PasswordHistory {
    struct Entry: Identifiable, Equatable {
        let id: Int
        let password: String
        let changedAt: Int64
    }

    static func entries(_ record: [String: JSONValue]) -> [Entry] {
        (record["password_history"]?.arrayValue ?? []).enumerated().compactMap { i, row in
            guard case .object(let o) = row, let password = o["password"]?.stringValue else { return nil }
            let at: Int64 = if case .int(let n)? = o["changed_at"] ?? o["replaced_at"] { n } else { 0 }
            return Entry(id: i, password: password, changedAt: at)
        }
    }

    /// Makes `entry` the login's password. `.unchanged` when it already is (or the login is gone).
    static func restore(_ entry: Entry, id: String, store: any ItemStore, clock: any UnixClock,
                        background: (any BackgroundTasking)? = nil) -> SaveResult {
        do {
            var snap = try store.load()
            guard snap.meta[id]?.deleted != true, case .object(let w)? = snap.records[id],
                  case .object(let original)? = w["record"], original["kind"] == .string("web") else { return .unchanged }
            guard original["password"]?.stringValue != entry.password else { return .unchanged }
            var edited = original
            edited["password"] = .string(entry.password)
            edited = EditorModel.withPasswordHistory(edited, original: original, now: clock.now)
            edited["updated_at"] = .int(clock.now)
            let record = try Normalise.normalForm(ns: .entry, record: .object(edited))
            guard case .object(let o) = record, o["id"] == .string(id) else { return .failed }
            snap.records[id] = Wrapper.make(ns: .entry, record: record)
            let change = StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync)
            let tasks = background ?? PlatformBackgroundTasks.make()
            try tasks.run("LocalGateKeys save") { try store.commit(change) }
            return .saved
        } catch {
            return .failed
        }
    }
}

/// The list of past passwords: masked, reveal after Face ID (or the passcode), copy, Restore this password.
struct PasswordHistoryView: View {
    let item: VaultItem
    let store: any ItemStore
    let onChange: () -> Void
    @State private var entries: [PasswordHistory.Entry] = []
    @State private var revealed = false
    @State private var restoring: PasswordHistory.Entry?
    @State private var failed = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            Section {
                ForEach(entries) { entry in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(revealed ? entry.password : String(repeating: "•", count: 10))
                                .font(.system(.body, design: .monospaced)).foregroundStyle(Palette.text)
                                .textSelection(.disabled)
                                .accessibilityLabel(revealed ? entry.password : String(localized: "Hidden password"))
                            Spacer()
                            Button {
                                SecretClipboard.shared.copy(entry.password)
                                CopyToast.shared.show(String(localized: "Old password copied"))
                            } label: { Image(systemName: "doc.on.doc") }
                                .buttonStyle(.borderless)
                                .accessibilityLabel("Copy old password")
                        }
                        HStack {
                            Text(entry.changedAt > 0
                                 ? String(localized: "Replaced \(Date(timeIntervalSince1970: TimeInterval(entry.changedAt)).formatted(date: .abbreviated, time: .shortened))")
                                 : String(localized: "Replaced at an unknown time"))
                                .font(.caption).foregroundStyle(Palette.secondaryText)
                            Spacer()
                            Button("Restore") { restoring = entry }
                                .buttonStyle(.borderless).font(.caption.weight(.semibold))
                                .foregroundStyle(Palette.accentText)
                                .accessibilityLabel("Restore this password")
                        }
                    }
                    .padding(.vertical, 2)
                }
            } footer: {
                Text("Up to \(EditorModel.historyWriteLimit) earlier passwords from the last year are kept with the login and sync with it.")
            }
            .listRowBackground(Palette.groupSurface)
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Password history")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button(revealed ? String(localized: "Hide") : String(localized: "Reveal")) {
                    if revealed { revealed = false } else { Task { revealed = await Self.confirmOwner() } }
                }
                .disabled(ScreenCaptureMonitor.shared.isCaptured)
            }
        }
        .onAppear(perform: reload)
        .onDisappear { revealed = false }
        .alert("Restore this password?", isPresented: Binding(get: { restoring != nil }, set: { if !$0 { restoring = nil } })) {
            Button("Restore") {
                if let entry = restoring { restore(entry) }
                restoring = nil
            }
            Button("Cancel", role: .cancel) { restoring = nil }
        } message: {
            Text("It becomes this login's password again. The current password moves into the history.")
        }
        .alert("The password could not be restored on this device.", isPresented: $failed) { Button("OK") {} }
    }

    private func reload() {
        guard let snap = try? store.load(), let current = VaultItem.items(from: snap).first(where: { $0.id == item.id }) else {
            entries = PasswordHistory.entries(item.record); return
        }
        entries = PasswordHistory.entries(current.record)
    }

    private func restore(_ entry: PasswordHistory.Entry) {
        switch PasswordHistory.restore(entry, id: item.id, store: store, clock: SystemClock()) {
        case .saved: onChange(); CopyToast.shared.show(String(localized: "Password restored")); reload()
        case .unchanged: reload()
        default: failed = true
        }
    }

    /// Face ID, Touch ID or the passcode, as for revealing on the Mac.
    static func confirmOwner() async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return false }
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: String(localized: "Show earlier passwords"))) ?? false
    }
}
