import Foundation
import Observation
import LGKCore
import AppSharedMac

/// A login's extras in the detail panel (Windows `login_extras.py`): recovery codes, custom fields and the
/// read-only password history. Records keep the desktop's shapes — `recovery_codes` a list of strings,
/// `custom_fields` rows `{name, value, hidden}` (hidden by default), `password_history` rows
/// `{password, changed_at}` newest first, at most 5.
///
/// What has been revealed (codes, hidden field values, history rows shown) lives here only, for one item at a
/// time: it is forgotten when the selection moves to another item and whenever the vault locks.
@MainActor @Observable
final class LoginExtrasModel {
    static let maxCustomFields = 50
    static let maxFieldName = 100
    static let maxFieldValue = 4096
    static let maxRecoveryCodes = 100
    static let maxRecoveryCode = 512
    static let maxHistory = 5

    static let recoveryEmptyText = String(localized: "No saved codes. Reveal to add some.")
    static let recoveryLockedText = String(localized: "Locked · this login always asks for the master password. Reveal to view or edit.")
    static let customFieldsHelp = String(localized: "Hidden fields are masked on screen and treated like passwords when exported.")
    static let customFieldsLockedText = String(localized: "Locked · this login always asks for the master password. Reveal to view or edit.")
    static let historyEmptyText = String(localized: "No previous passwords.")
    static let changedText = String(localized: "This login changed since you opened it. Reveal it again to edit.")

    struct CustomField: Identifiable, Equatable {
        let id = UUID()
        var name: String
        var value: String
        var hidden: Bool = true

        static func == (a: CustomField, b: CustomField) -> Bool {
            a.name == b.name && a.value == b.value && a.hidden == b.hidden
        }
    }

    struct HistoryRow: Equatable {
        let password: String
        let changedAt: Int64
    }

    /// The item whose extras may be revealed.
    private(set) var itemID: String?
    /// The recovery codes being viewed/edited, nil while hidden.
    var codes: [String]?
    /// The custom fields with every value, nil while hidden values are masked.
    var fields: [CustomField]?
    /// Password history rows (by index) shown in clear.
    private(set) var shownHistory: Set<Int> = []
    /// The stored login as it was when the codes / fields were revealed (stale saves are refused).
    @ObservationIgnored private var codesBase: JSONValue?
    @ObservationIgnored private var fieldsBase: JSONValue?
    /// The last save's error, if any.
    private(set) var error: String?

    init() {}

    // MARK: forgetting

    /// The detail panel shows `id`: anything revealed for another item is hidden again.
    func select(_ id: String?) {
        guard id != itemID else { return }
        hide()
        itemID = id
    }

    /// Masks everything again.
    func hide() {
        codes = nil; fields = nil; shownHistory = []; error = nil; codesBase = nil; fieldsBase = nil
    }

    /// Hides everything whenever the vault locks.
    func clear(on lock: MacLockModel) {
        lock.onLock.append { [weak self] in self?.lockReset() }
    }

    func lockReset() { hide(); itemID = nil }

    var codesRevealed: Bool { codes != nil }
    var fieldsRevealed: Bool { fields != nil }
    func historyShown(_ index: Int) -> Bool { shownHistory.contains(index) }

    // MARK: reading records

    static func recoveryCodes(of item: VaultItem) -> [String] {
        (item.record["recovery_codes"]?.arrayValue ?? []).compactMap(\.stringValue)
    }

    static func customFields(of item: VaultItem) -> [CustomField] {
        (item.record["custom_fields"]?.arrayValue ?? []).compactMap { row in
            guard let o = row.objectValue else { return nil }
            return CustomField(name: o["name"]?.stringValue ?? "", value: o["value"]?.stringValue ?? "",
                               hidden: o["hidden"] == nil || o["hidden"] == .bool(true))
        }
    }

    /// Newest first, as stored; an old build's `replaced_at` counts as `changed_at`.
    static func history(of item: VaultItem) -> [HistoryRow] {
        (item.record["password_history"]?.arrayValue ?? []).compactMap { row in
            guard let o = row.objectValue, let pw = o["password"]?.stringValue else { return nil }
            let at: Int64 = if case .int(let n)? = o["changed_at"] ?? o["replaced_at"] { n } else { 0 }
            return HistoryRow(password: pw, changedAt: at)
        }
    }

    /// "3 saved code(s) hidden. Reveal to view or edit." (Windows `recovery_count`).
    static func recoveryText(_ item: VaultItem) -> String {
        if StrictItemGate.isStrict(item) { return recoveryLockedText }
        let count = recoveryCodes(of: item).count
        return count > 0 ? String(localized: "\(count) saved code(s) hidden. Reveal to view or edit.") : recoveryEmptyText
    }

    // MARK: validation (`login_form.py`)

    /// The codes that would be saved: trimmed, blank lines dropped.
    static func cleanedCodes(_ codes: [String]) -> [String] {
        codes.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }

    static func validate(codes: [String]) -> String? {
        let cleaned = cleanedCodes(codes)
        if cleaned.count > maxRecoveryCodes { return String(localized: "At most \(maxRecoveryCodes) recovery codes") }
        if cleaned.contains(where: { $0.count > maxRecoveryCode }) {
            return String(localized: "Recovery codes are at most \(maxRecoveryCode) characters")
        }
        return nil
    }

    /// The rows that would be saved: names trimmed, rows with neither name nor value dropped.
    static func filledFields(_ fields: [CustomField]) -> [CustomField] {
        fields.filter { !$0.name.trimmingCharacters(in: .whitespaces).isEmpty || !$0.value.isEmpty }
            .map { CustomField(name: $0.name.trimmingCharacters(in: .whitespaces), value: $0.value, hidden: $0.hidden) }
    }

    static func validate(fields: [CustomField]) -> String? {
        let filled = filledFields(fields)
        if filled.count > maxCustomFields { return String(localized: "At most \(maxCustomFields) custom fields") }
        for f in filled {
            if f.name.isEmpty { return String(localized: "Give this field a name") }
            if f.name.count > maxFieldName { return String(localized: "Name is longer than \(maxFieldName) characters") }
            if f.value.count > maxFieldValue { return String(localized: "Value is longer than \(maxFieldValue) characters") }
        }
        return nil
    }

    static func json(_ fields: [CustomField]) -> JSONValue {
        .array(filledFields(fields).map { .object(["name": .string($0.name), "value": .string($0.value), "hidden": .bool($0.hidden)]) })
    }

    // MARK: revealing

    /// Shows the recovery codes for editing (a strict login asks for the master password first).
    func revealCodes(_ item: VaultItem, gate: StrictItemGate, onRevealed: @escaping () -> Void) {
        select(item.id)
        gate.releaseRoutine(item, action: String(localized: "Reveal recovery codes")) { [weak self] in
            guard let self, self.itemID == item.id else { return }
            self.codes = Self.recoveryCodes(of: item)
            self.codesBase = Self.stamp(item.record)
            onRevealed()
        }
    }

    /// Shows hidden custom field values, and makes the fields editable.
    func revealFields(_ item: VaultItem, gate: StrictItemGate, onRevealed: @escaping () -> Void) {
        select(item.id)
        gate.releaseRoutine(item, action: String(localized: "Reveal hidden fields")) { [weak self] in
            guard let self, self.itemID == item.id else { return }
            self.fields = Self.customFields(of: item)
            self.fieldsBase = Self.stamp(item.record)
            onRevealed()
        }
    }

    func showHistory(_ index: Int, of item: VaultItem, gate: StrictItemGate, onRevealed: @escaping () -> Void) {
        select(item.id)
        gate.releaseRoutine(item, action: String(localized: "Show previous password")) { [weak self] in
            guard let self, self.itemID == item.id else { return }
            self.shownHistory.insert(index)
            onRevealed()
        }
    }

    func hideHistory(_ index: Int) { shownHistory.remove(index) }

    // MARK: saving

    /// Saves the codes being edited (a strict login asks again). Returns through `onSaved` once written.
    func saveCodes(_ item: VaultItem, store: any ItemStore, clock: any UnixClock, gate: StrictItemGate, onSaved: @escaping () -> Void) {
        guard let codes else { return }
        if let message = Self.validate(codes: codes) { error = message; return }
        let cleaned = Self.cleanedCodes(codes)
        gate.releaseRoutine(item, action: String(localized: "Save recovery codes")) { [weak self] in
            guard let self else { return }
            if let stamp = self.write(item, store: store, clock: clock, expected: self.codesBase,
                                      changes: ["recovery_codes": .array(cleaned.map(JSONValue.string))]) {
                if self.itemID == item.id { self.codes = cleaned; self.rebase(stamp) }
                onSaved()
            }
        }
    }

    func saveFields(_ item: VaultItem, store: any ItemStore, clock: any UnixClock, gate: StrictItemGate, onSaved: @escaping () -> Void) {
        guard let fields else { return }
        if let message = Self.validate(fields: fields) { error = message; return }
        gate.releaseRoutine(item, action: String(localized: "Save custom fields")) { [weak self] in
            guard let self else { return }
            if let stamp = self.write(item, store: store, clock: clock, expected: self.fieldsBase,
                                      changes: ["custom_fields": Self.json(fields)]) {
                if self.itemID == item.id { self.fields = Self.filledFields(fields); self.rebase(stamp) }
                onSaved()
            }
        }
    }

    /// After our own write, every revealed section continues from the new stored version.
    private func rebase(_ stamp: JSONValue) {
        if codes != nil { codesBase = stamp }
        if fields != nil { fieldsBase = stamp }
    }

    func addField() {
        guard var f = fields, f.count < Self.maxCustomFields else { return }
        f.append(CustomField(name: "", value: ""))
        fields = f; error = nil
    }

    func removeField(_ id: UUID) { fields?.removeAll { $0.id == id }; error = nil }

    /// What identifies a stored version of the login: its whole record, canonically encoded.
    static func stamp(_ record: [String: JSONValue]) -> JSONValue {
        (try? CanonicalJSON.encode(.object(record), dialect: .utf8)).map { .string(Data($0).base64EncodedString()) } ?? .null
    }

    /// Changes only the given keys of the stored record (the rest as stored now), stamps and commits it.
    /// Refuses when the stored login is no longer the one revealed (`expected`). Returns the new stamp.
    @discardableResult
    func write(_ item: VaultItem, store: any ItemStore, clock: any UnixClock, expected: JSONValue?,
               changes: [String: JSONValue]) -> JSONValue? {
        error = nil
        do {
            var snap = try store.load()
            guard case .object(let w)? = snap.records[item.id], case .string(let nsRaw)? = w["ns"],
                  let ns = Namespace(rawValue: nsRaw), case .object(var record)? = w["record"] else {
                error = String(localized: "This login is no longer available."); return nil
            }
            guard let expected, Self.stamp(record) == expected else { error = Self.changedText; return nil }
            if changes.allSatisfy({ record[$0.key] == $0.value || (record[$0.key] == nil && $0.value == .array([])) }) { return expected }
            for (k, v) in changes { record[k] = v }
            record["updated_at"] = .int(clock.now)
            let normal = try Normalise.normalForm(ns: ns, record: .object(record))
            snap.records[item.id] = Wrapper.make(ns: ns, record: normal)
            try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
            return normal.objectValue.map(Self.stamp) ?? .null
        } catch NormaliseError.rejected(let detail) {
            error = detail; return nil
        } catch {
            self.error = String(localized: "The login could not be saved on this device."); return nil
        }
    }
}
