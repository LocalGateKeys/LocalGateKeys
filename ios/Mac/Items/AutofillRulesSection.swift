import SwiftUI
import AppSharedMac

/// The login detail's "Autofill rules" (Windows `LoginMore.svelte` with `login_extras.policy_save`): Filling,
/// Sign in after filling, Always ask for the master password, Offer to save changes, and on website logins
/// "AI agents may use this login" (`scope.ai_agents`). A change on a strict login asks for the master password
/// first (never Touch ID); turning sign-in to Always asks for confirmation.
struct AutofillRulesSection: View {
    let item: VaultItem
    let store: any ItemStore
    let gate: StrictItemGate
    let onSaved: () -> Void
    @State private var error: String?
    @State private var confirmingSignIn = false
    @Environment(\.macTheme) private var theme

    private var policy: [String: JSONValue] { Normalise.policy(item.record["policy"]).objectValue ?? [:] }
    private var aiAgents: Bool { AgentText.agentsMayUse(item.record) }

    var body: some View {
        SectionLabel(String(localized: "Autofill rules"))
        VStack(alignment: .leading, spacing: 8) {
            row(String(localized: "Filling")) {
                Picker("", selection: binding("fill", default: "click")) {
                    Text("On click").tag("click"); Text("Off").tag("never")
                }
                .labelsHidden().fixedSize()
            }
            row(String(localized: "Sign in after filling")) {
                Picker("", selection: Binding(get: { policy["sign_in"]?.stringValue ?? "inherit" },
                                              set: { value in
                                                  if value == "enabled" { confirmingSignIn = true } else { save(["sign_in": .string(value)]) }
                                              })) {
                    Text("Default").tag("inherit"); Text("Never").tag("never"); Text("Always").tag("enabled")
                }
                .labelsHidden().fixedSize()
            }
            row(String(localized: "Always ask for the master password")) {
                Toggle("", isOn: boolBinding("require_master_password", default: false)).toggleStyle(.switch).labelsHidden()
            }
            row(String(localized: "Offer to save changes from the browser")) {
                Toggle("", isOn: boolBinding("save_prompts", default: true)).toggleStyle(.switch).labelsHidden()
            }
            hint(String(localized: "Filling and sign-in only ever happen after your click, never when a page loads."))
            if item.kind == "web" {
                row(String(localized: "AI agents may use this login")) {
                    Toggle("", isOn: Binding(get: { aiAgents }, set: { saveAgents($0) })).toggleStyle(.switch).labelsHidden()
                }
                hint(String(localized: "An agent that controls your browser can read a password filled into the page. If a passkey is saved for the site, agents sign in with the passkey instead."))
            }
            if let error {
                Text(error).font(.system(size: 12.5)).foregroundStyle(theme.danger)
            }
        }
        .alert(String(localized: "Enable sign-in for this entry?"), isPresented: $confirmingSignIn) {
            Button(String(localized: "Enable")) { save(["sign_in": .string("enabled")]) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("LocalGateKeys may submit a supported login immediately after your click/account selection. It never bypasses MFA or CAPTCHA.")
        }
    }

    private func row(_ label: String, @ViewBuilder control: () -> some View) -> some View {
        HStack(alignment: .center, spacing: 10) {
            Text(label).font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            control()
        }
    }

    private func hint(_ text: String) -> some View {
        Text(text).font(.system(size: 12)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
    }

    private func binding(_ key: String, default value: String) -> Binding<String> {
        Binding(get: { policy[key]?.stringValue ?? value }, set: { save([key: .string($0)]) })
    }

    private func boolBinding(_ key: String, default value: Bool) -> Binding<Bool> {
        Binding(get: { policy[key].map { $0 == .bool(true) } ?? value }, set: { save([key: .bool($0)]) })
    }

    /// A rule change: strict logins ask for the master password first (Windows `routine=False`).
    private func save(_ changes: [String: JSONValue]) {
        let apply: (inout [String: JSONValue]) -> Void = { record in
            var p = Normalise.policy(record["policy"]).objectValue ?? [:]
            for (k, v) in changes { p[k] = v }
            record["policy"] = .object(p)
        }
        let action = String(localized: "Change autofill rules")
        var next = item.record
        apply(&next)
        // Loosening an access rule (filling turned back on, feature pack §4) asks for the master password even on a
        // login that is not strict (scan 2026-11-15); a strict login asks through `release` anyway.
        if AccessRules.loosens(from: item.record, to: next), !StrictItemGate.isStrict(item) {
            gate.confirmMasterPassword(title: item.title.isEmpty ? item.kindLabel : item.title, action: action) {
                write(apply)
            }
            return
        }
        gate.release(item, action: action) { write(apply) }
    }

    private func saveAgents(_ allowed: Bool) {
        gate.release(item, action: String(localized: "Change autofill rules")) {
            write { record in
                guard case .object(var scope)? = record["scope"] else { return }
                if allowed { scope[AgentText.scopeKey] = .bool(true) } else { scope.removeValue(forKey: AgentText.scopeKey) }
                record["scope"] = .object(scope)
            }
        }
    }

    private func write(_ change: (inout [String: JSONValue]) -> Void) {
        error = nil
        do {
            var snap = try store.load()
            guard case .object(let w)? = snap.records[item.id], case .string(let nsRaw)? = w["ns"],
                  let ns = Namespace(rawValue: nsRaw), ns != .heir, case .object(var record)? = w["record"] else {
                error = String(localized: "This login is no longer available."); return
            }
            let before = record
            change(&record)
            guard record != before else { return }
            record["updated_at"] = .int(Int64(Date().timeIntervalSince1970))
            let normal = try Normalise.normalForm(ns: ns, record: .object(record))
            snap.records[item.id] = Wrapper.make(ns: ns, record: normal)
            try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
            onSaved()
        } catch {
            self.error = String(localized: "Rule not saved")
        }
    }
}
