import SwiftUI
import AppShared

/// Writing a login's access rules (feature pack §4) apart from SwiftUI: `scope.access` and the existing
/// `policy.require_master_password` / `policy.fill`, through the normaliser, in one commit.
@MainActor
enum AccessRulesActions {
    struct Choice: Equatable {
        var settings: AccessRules.Settings
        var requireConfirm: Bool
        var autofill: Bool
    }

    static func choice(_ record: [String: JSONValue]) -> Choice {
        let scope = record["scope"]?.objectValue ?? [:]
        let policy = Normalise.policy(record["policy"]).objectValue ?? [:]
        return Choice(settings: AccessRules.settings(of: scope),
                      requireConfirm: policy["require_master_password"] == .bool(true),
                      autofill: policy["fill"] != .string("never"))
    }

    /// Setting or tightening a rule needs Pro; loosening or removing never does.
    static func needsPro(from old: Choice, to new: Choice) -> Bool {
        AccessRules.tightens(from: old.settings, to: new.settings)
            || (new.requireConfirm && !old.requireConfirm) || (!new.autofill && old.autofill)
    }

    /// Saves `new` on login `id`. `.needsOwner` when the change loosens a rule and the owner has not confirmed it yet
    /// (scan 2026-11-15: enforced here, not only by the screen).
    static func save(_ new: Choice, id: String, store: any ItemStore, isPro: Bool, clock: any UnixClock,
                     background: (any BackgroundTasking)? = nil, ownerConfirmed: Bool = false) -> SaveResult {
        do {
            var snap = try store.load()
            guard snap.meta[id]?.deleted != true, case .object(let w)? = snap.records[id],
                  case .object(let original)? = w["record"], original["kind"] == .string("web") else { return .unchanged }
            let old = choice(original)
            guard old != new else { return .unchanged }
            if needsPro(from: old, to: new), !isPro { return .needsPro }
            var edited = original
            let scope = original["scope"]?.objectValue ?? [:]
            guard let written = try? AccessRules.writing(new.settings, into: scope) else { return .invalid }
            edited["scope"] = .object(written)
            var policy = Normalise.policy(original["policy"]).objectValue ?? [:]
            policy["require_master_password"] = .bool(new.requireConfirm)
            policy["fill"] = .string(new.autofill ? "click" : "never")
            edited["policy"] = .object(policy)
            edited["updated_at"] = .int(clock.now)
            let record = try Normalise.normalForm(ns: .entry, record: .object(edited))
            guard case .object(let o) = record, o["id"] == .string(id) else { return .failed }
            if AccessRules.loosens(from: original, to: o), !ownerConfirmed { return .needsOwner }
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

/// Item › Access rules for a login (Pro to set or tighten). Synced with the login to every device.
struct AccessRulesView: View {
    let item: VaultItem
    let store: any ItemStore
    let pro: ProModel
    let onChange: () -> Void
    @State private var original = AccessRulesActions.Choice(settings: .init(), requireConfirm: false, autofill: true)
    @State private var draft = AccessRulesActions.Choice(settings: .init(), requireConfirm: false, autofill: true)
    @State private var hasExpiry = false
    @State private var expiry = Date()
    @State private var message: String?
    @State private var showUpgrade = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section {
                Toggle("Confirm it's me for every reveal, copy and fill", isOn: $draft.requireConfirm)
                Toggle("Offer in AutoFill", isOn: $draft.autofill)
                Toggle("Copy once per unlock", isOn: $draft.settings.copyOnce)
                Toggle("View only on phones", isOn: $draft.settings.phonesView)
                Toggle("Access expires", isOn: $hasExpiry)
                if hasExpiry {
                    DatePicker("Expires on", selection: $expiry, displayedComponents: .date)
                }
            } footer: {
                Text("Rules sync with this login to all your devices. Setting or tightening a rule needs Pro; loosening never does.")
            }
            .tint(Palette.accent)
            .listRowBackground(Palette.groupSurface)
            if let message {
                Text(message).font(.footnote).foregroundStyle(Palette.secondaryText).listRowBackground(Color.clear)
            }
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Access rules")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) { Button("Save", action: save) }
        }
        .onAppear(perform: load)
        .sheet(isPresented: $showUpgrade) { UpgradeView(pro: pro) }
    }

    private func load() {
        let record = (try? store.load()).flatMap { snap in VaultItem.items(from: snap).first { $0.id == item.id }?.record } ?? item.record
        original = AccessRulesActions.choice(record)
        draft = original
        hasExpiry = !original.settings.expires.isEmpty
        if hasExpiry, let d = Self.dateFormatter.date(from: original.settings.expires) { expiry = d }
    }

    private func save() {
        var next = draft
        next.settings.expires = hasExpiry ? RecordDigest.today(expiry) : ""
        write(next, ownerConfirmed: false)
    }

    private func write(_ next: AccessRulesActions.Choice, ownerConfirmed: Bool) {
        switch AccessRulesActions.save(next, id: item.id, store: store, isPro: pro.isPro, clock: SystemClock(),
                                       ownerConfirmed: ownerConfirmed) {
        case .needsOwner:
            // Loosening a rule asks the owner first (no grace), like turning off travel mode.
            Task {
                guard await AppPasswordGate.confirmOwner(String(localized: "Change this login's access rules")) else { return }
                write(next, ownerConfirmed: true)
            }
        case .saved: onChange(); CopyToast.shared.show(String(localized: "Access rules saved")); dismiss()
        case .unchanged: dismiss()
        case .needsPro: message = String(localized: "Access rules are part of Pro."); showUpgrade = true
        case .invalid: message = String(localized: "That date is not valid.")
        default: message = String(localized: "The access rules could not be saved. Try again.")
        }
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.calendar = Calendar(identifier: .gregorian)
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()
}
