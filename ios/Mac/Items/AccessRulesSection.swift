import SwiftUI
import AppSharedMac

/// Writing a website login's `scope.access` (feature pack §4.1) apart from SwiftUI, through the normaliser, in one
/// commit. "Always ask for the master password" and "Filling" stay Free in `AutofillRulesSection`; this section holds
/// copy once, view only on phones and the expiry date. Setting or tightening needs Pro; loosening never does.
@MainActor
enum MacAccessRules {
    static func settings(_ record: [String: JSONValue]) -> AccessRules.Settings {
        AccessRules.settings(of: record["scope"]?.objectValue ?? [:])
    }

    /// Saves `new` on login `id`: `.needsPro` when it sets or tightens a rule without Pro, `.invalid` for a bad date,
    /// `.unchanged` when nothing differs or the item is not a website login, `.needsOwner` when it loosens a rule and
    /// the master password has not been confirmed for it (scan 2026-11-15: enforced here, not only by the section).
    static func save(_ new: AccessRules.Settings, id: String, store: any ItemStore, isPro: Bool,
                     now: Int64 = Int64(Date().timeIntervalSince1970), ownerConfirmed: Bool = false) -> SaveResult {
        do {
            var snap = try store.load()
            guard snap.meta[id]?.deleted != true, case .object(let w)? = snap.records[id], w["ns"] == .string(Namespace.entry.rawValue),
                  case .object(let original)? = w["record"], original["kind"] == .string("web") else { return .unchanged }
            let old = settings(original)
            guard old != new else { return .unchanged }
            if AccessRules.tightens(from: old, to: new), !isPro { return .needsPro }
            guard let written = try? AccessRules.writing(new, into: original["scope"]?.objectValue ?? [:]) else { return .invalid }
            var edited = original
            edited["scope"] = .object(written)
            edited["updated_at"] = .int(now)
            let record = try Normalise.normalForm(ns: .entry, record: .object(edited))
            guard case .object(let o) = record, o["id"] == .string(id) else { return .failed }
            if AccessRules.loosens(from: original, to: o), !ownerConfirmed { return .needsOwner }
            snap.records[id] = Wrapper.make(ns: .entry, record: record)
            try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
            return .saved
        } catch {
            return .failed
        }
    }

    /// `yyyy-MM-dd` in the Gregorian calendar (the stored form).
    static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.calendar = Calendar(identifier: .gregorian)
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()
}

/// The website login detail's "Access rules" (feature pack §4): Copy once per unlock, View only on phones and Access
/// expires with its date, then Save. Pro to set or tighten (the upgrade prompt otherwise); loosening asks for the
/// master password first. Strict logins ask for the master password before any change (as `AutofillRulesSection`).
struct AccessRulesSection: View {
    let item: VaultItem
    let store: any ItemStore
    let gate: StrictItemGate
    let pro: Bool
    let onNeedsPro: () -> Void
    let onSaved: () -> Void
    @State private var original = AccessRules.Settings()
    @State private var draft = AccessRules.Settings()
    @State private var hasExpiry = false
    @State private var expiry = Date()
    @State private var message: String?
    @Environment(\.macTheme) private var theme

    private var next: AccessRules.Settings {
        var n = draft
        n.expires = hasExpiry ? RecordDigest.today(expiry) : ""
        return n
    }

    var body: some View {
        SectionLabel(String(localized: "Access rules"))
        VStack(alignment: .leading, spacing: 8) {
            row(String(localized: "Copy once per unlock")) {
                Toggle("", isOn: $draft.copyOnce).toggleStyle(.switch).labelsHidden()
                    .accessibilityLabel(String(localized: "Copy once per unlock"))
            }
            row(String(localized: "View only on phones")) {
                Toggle("", isOn: $draft.phonesView).toggleStyle(.switch).labelsHidden()
                    .accessibilityLabel(String(localized: "View only on phones"))
            }
            row(String(localized: "Access expires")) {
                Toggle("", isOn: $hasExpiry).toggleStyle(.switch).labelsHidden()
                    .accessibilityLabel(String(localized: "Access expires"))
            }
            if hasExpiry {
                row(String(localized: "Expires on")) {
                    DatePicker("", selection: $expiry, displayedComponents: .date).labelsHidden().fixedSize()
                        .accessibilityLabel(String(localized: "Expires on"))
                }
            }
            Text("Rules sync with this login to all your devices. Setting or tightening a rule needs Pro; loosening never does.")
                .font(.system(size: 12)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            if next != original {
                HStack {
                    Spacer()
                    Button(String(localized: "Cancel")) { load() }
                    Button(String(localized: "Save"), action: save).keyboardShortcut(.defaultAction)
                }
            }
            if let message {
                Text(message).font(.system(size: 12.5)).foregroundStyle(theme.danger)
            }
        }
        .onAppear(perform: load)
        .onChange(of: item) { _, _ in load() }
    }

    private func row(_ label: String, @ViewBuilder control: () -> some View) -> some View {
        HStack(alignment: .center, spacing: 10) {
            Text(label).font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            control()
        }
    }

    private func load() {
        original = MacAccessRules.settings(item.record)
        draft = original
        hasExpiry = !original.expires.isEmpty
        expiry = hasExpiry ? (MacAccessRules.dateFormatter.date(from: original.expires) ?? Date()) : Date()
        message = nil
    }

    private func save() {
        let new = next
        message = nil
        if AccessRules.tightens(from: original, to: new), !pro {
            message = String(localized: "Access rules are part of Pro.")
            onNeedsPro()
            return
        }
        // Loosening asks for the master password first (iPhone: the owner check); a strict login asks anyway.
        let loosens = AccessRules.tightens(from: new, to: original)
        if loosens || StrictItemGate.isStrict(item) {
            confirm { write(new, ownerConfirmed: true) }
        } else {
            write(new, ownerConfirmed: false)
        }
    }

    private func confirm(_ perform: @escaping () -> Void) {
        gate.confirmMasterPassword(title: item.title.isEmpty ? item.kindLabel : item.title,
                                   action: String(localized: "Change this login's access rules"), perform: perform)
    }

    private func write(_ new: AccessRules.Settings, ownerConfirmed: Bool) {
        switch MacAccessRules.save(new, id: item.id, store: store, isPro: pro, ownerConfirmed: ownerConfirmed) {
        case .needsOwner: confirm { write(new, ownerConfirmed: true) }   // a loosening the settings alone don't show
        case .saved: original = new; onSaved()
        case .unchanged: load()
        case .needsPro: message = String(localized: "Access rules are part of Pro."); onNeedsPro()
        case .invalid: message = String(localized: "That date is not valid.")
        default: message = String(localized: "The access rules could not be saved. Try again.")
        }
    }
}
