import Foundation
import Observation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

enum SaveResult: Equatable { case saved, unchanged, needsPro, needsPunycode, invalid, failed }

/// Create, edit and delete one record. Records go through LGKCore `Normalise.normalForm` and `Wrapper.make`,
/// and are committed through the store; deletes write a `SyncMeta` tombstone.
@MainActor
@Observable
final class EditorModel {
    let kind: EditorKind
    let isNew: Bool
    private(set) var values: [String: String] = [:]
    private(set) var error: String?
    private(set) var needsPunycode = false
    /// Inline error for the 2FA secret field.
    private(set) var totpError: String?
    /// Inline error for the Website field (`WebsiteInput` wording, never the normaliser's).
    private(set) var websiteError: String?
    /// Inline error for the Amount field.
    private(set) var amountError: String?
    var showUpgrade = false
    /// The Mac's tags field: when set, replaces the record's `tags` (already normalised). nil leaves them as stored.
    var tags: [String]?
    /// The id the last successful save wrote (a new item's generated id).
    private(set) var savedID: String?
    /// Delete found the item gone already (a sync removed it): the view says so and closes.
    private(set) var alreadyRemoved = false

    @ObservationIgnored private let store: any ItemStore
    @ObservationIgnored private let pro: ProModel
    @ObservationIgnored private let clock: any UnixClock
    @ObservationIgnored private let random: any RandomSource
    @ObservationIgnored private let id: String?
    /// The record as stored, untouched, so an unchanged save writes nothing.
    @ObservationIgnored private let original: [String: JSONValue]?
    /// Commits run inside a background task (the store holds a flock in the app-group container).
    @ObservationIgnored private let background: any BackgroundTasking
    /// The Mac records a login's replaced password in `password_history` like the desktop (`vault.py`);
    /// off by default, so the iPhone keeps the stored history untouched.
    @ObservationIgnored private let keepsPasswordHistory: Bool

    init(store: any ItemStore, pro: ProModel, editing item: VaultItem?, kind: EditorKind,
         clock: any UnixClock, random: any RandomSource, background: (any BackgroundTasking)? = nil,
         keepsPasswordHistory: Bool = false) {
        self.store = store; self.pro = pro; self.clock = clock; self.random = random
        self.keepsPasswordHistory = keepsPasswordHistory
        self.background = background ?? PlatformBackgroundTasks.make()
        self.kind = item.flatMap { EditorKind(kind: $0.kind) } ?? kind
        isNew = item == nil; id = item?.id; original = item?.record
        if let r = item?.record { values = Self.values(of: r, kind: self.kind) } else { values = self.kind.defaults }
    }

    /// The edited item's id (nil: a new item) and its record as stored, for the unsaved draft (EditorDraft.swift).
    var editingID: String? { id }
    var originalRecord: [String: JSONValue]? { original }

    /// A restored draft's form replaces the values shown (Task 6, EditorDraft.swift).
    func restore(_ form: [String: String]) {
        values = form; error = nil; needsPunycode = false; totpError = nil; websiteError = nil; amountError = nil
    }

    var titleKey: String { kind == .web ? "label" : "title" }
    /// Free plan: an existing 2FA code stays (and can be cleared); adding or changing one needs Pro.
    var totpNeedsPro: Bool { kind == .web && !pro.isPro }
    func value(_ key: String) -> String { values[key] ?? "" }
    func set(_ key: String, _ v: String) {
        values[key] = v; error = nil
        if key == "origin" || key == "url" { needsPunycode = false; websiteError = nil }
        if key == "totp" { totpError = nil }
        if key == "amount_minor" || key == "currency" { amountError = nil }
    }

    static let migrationQRMessage = String(localized: "This QR code moves several accounts out of an authenticator app. Use Scan QR code (next to New item) to add them all.")
    static let notTOTPQRMessage = String(localized: "This QR code is not a 2FA setup code.")
    static let totpCameraMessage = String(localized: "The camera is not available. Paste the setup key instead.")

    /// A QR code scanned for the 2FA field: a setup code (otpauth link or Base32 secret) fills the field,
    /// anything else leaves it as it was and explains why.
    func scanTOTP(_ code: String) {
        let text = code.trimmingCharacters(in: .whitespacesAndNewlines)
        let isOtpauth = text.lowercased().hasPrefix("otpauth")
        if text.lowercased().hasPrefix("otpauth-migration:") {
            // An authenticator export with one account fills the field; several go through Scan QR code.
            guard let batch = try? OTPMigration.parse(text), batch.batchSize == 1, batch.accounts.count == 1,
                  batch.skipped.isEmpty else { totpError = Self.migrationQRMessage; return }
            set("totp", batch.accounts[0].uri)
            return
        }
        do {
            guard try TOTP.parseField(text) != nil else { totpError = Self.notTOTPQRMessage; return }
            set("totp", text)
        } catch let e as TOTPError where isOtpauth {
            totpError = TOTP.message(for: e)
        } catch { totpError = Self.notTOTPQRMessage }
    }

    func totpCameraUnavailable() { totpError = Self.totpCameraMessage }

    /// A QR image (Photos, or an image file on the Mac) had no usable 2FA code: fixed text, never the payload.
    func totpScanFailed(_ message: String) { totpError = message }

    static func values(of r: [String: JSONValue], kind: EditorKind) -> [String: String] {
        var out: [String: String] = [:]
        let payload = r["payload"]?.objectValue ?? [:]
        for f in kind.fields {
            switch (kind, f.key) {
            case (.web, "origin"): out[f.key] = r["scope"]?.objectValue?["origin"]?.stringValue
            case (.web, "totp"): out[f.key] = r["totp"]?.objectValue?["secret"]?.stringValue
            case (.web, _), (_, "title"): out[f.key] = r[f.key]?.stringValue
            default:
                switch payload[f.key] {
                case .bool(let b)?: out[f.key] = b ? "true" : "false"
                default: out[f.key] = payload[f.key]?.stringValue
                }
            }
        }
        if kind.isPurchaseLike {
            // The desktop's empty amount is 0 in "XXX" (no currency): shown as blank fields.
            let code = payload["currency"]?.stringValue ?? ""
            let minor: Int64 = if case .int(let n)? = payload["amount_minor"] { n } else { 0 }
            out["currency"] = code == "XXX" ? "" : code
            out["amount_minor"] = minor == 0 && (code == "XXX" || code.isEmpty) ? "" : Amount.text(minor: minor, currency: code)
        }
        return out.compactMapValues { $0 }
    }

    // MARK: building the record

    /// A changed Website moves the login: the URL rows on the old site (its exact-origin row and any imported page
    /// address there) give way to the new exact origin as `urls[0]`, which the desktop treats as authoritative
    /// (`migrate_web_scope`); rows on other sites stay.
    static func movedRows(_ rows: [JSONValue], from old: String, to new: String) -> JSONValue {
        let first: JSONValue = .object(["url": .string(new), "match": .string("exact_origin")])
        let kept = rows.filter { row in
            guard let url = row.objectValue?["url"]?.stringValue ?? row.stringValue else { return false }
            guard let origin = try? Origin.originOf(url) else { return true }
            let match = row.objectValue?["match"]?.stringValue ?? "exact_origin"
            if origin.utf8.elementsEqual(old.utf8) { return false }
            return !(origin.utf8.elementsEqual(new.utf8) && match == "exact_origin")
        }
        return .array([first] + kept)
    }

    /// The record with the form applied over the original (unknown fields kept). An empty field the record
    /// never had is not added, so opening and saving changes nothing.
    func edited() throws -> [String: JSONValue] {
        var r = original ?? newRecord()
        var payload = r["payload"]?.objectValue ?? [:]
        var scope = r["scope"]?.objectValue ?? [:]
        for f in kind.fields {
            let v = values[f.key] ?? ""
            switch (kind, f.key) {
            case (.web, "origin"):
                // Required for web logins; what was typed is reduced to its origin first.
                let new = try WebsiteInput.origin(v)
                if let old = scope["origin"]?.stringValue, !old.utf8.elementsEqual(new.utf8), let rows = scope["urls"]?.arrayValue {
                    scope["urls"] = Self.movedRows(rows, from: old, to: new)
                }
                scope["origin"] = .string(new)
            case (.web, "totp"):
                r["totp"] = try Self.totp(v, current: r["totp"])
            case (.web, _), (_, "title"):
                if !v.isEmpty || r[f.key] != nil { r[f.key] = .string(v) }
            case (_, "amount_minor"), (_, "currency"):
                break   // below, together
            default:
                if f.control == .toggle {
                    if !v.isEmpty || payload[f.key] != nil { payload[f.key] = .bool(v == "true") }
                } else if !v.isEmpty || payload[f.key] != nil { payload[f.key] = .string(v) }
            }
        }
        if kind.isPurchaseLike {
            // Both or neither (the desktop refuses one alone). A saved amount is never dropped, only zeroed.
            let amount = (values["amount_minor"] ?? "").trimmingCharacters(in: .whitespaces)
            let typed = (values["currency"] ?? "").trimmingCharacters(in: .whitespaces).uppercased()
            if amount.isEmpty && payload["amount_minor"] == nil {
                payload["amount_minor"] = nil; payload["currency"] = nil
            } else {
                let code = typed.isEmpty ? (payload["currency"]?.stringValue ?? "XXX") : typed
                payload["currency"] = .string(code)
                payload["amount_minor"] = .int(try Amount.minorUnits(amount, currency: code))
            }
        }
        if kind == .web { r["scope"] = .object(scope) } else { r["payload"] = .object(payload) }
        if let tags, !(tags.isEmpty && r["tags"] == nil) { r["tags"] = .array(tags.map(JSONValue.string)) }
        return r
    }

    /// The `totp` value for the 2FA field, in the desktop editor's `config()` shape: {secret, algorithm, digits,
    /// period}; a bare secret keeps the stored algorithm/digits/period. An empty field removes it; a field
    /// showing the stored secret leaves the stored value as it was.
    static func totp(_ text: String, current: JSONValue?) throws -> JSONValue? {
        let existing = current?.objectValue
        if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return existing == nil ? current : nil }
        if let existing, existing["secret"]?.stringValue == text { return current }
        var defaults = TOTPConfig(secret: "")
        if let e = existing {
            if case .string(let a)? = e["algorithm"] { defaults.algorithm = a }
            if case .int(let d)? = e["digits"] { defaults.digits = Int(d) }
            if case .int(let p)? = e["period"] { defaults.period = Int(p) }
        }
        guard let c = try TOTP.parseField(text, defaults: defaults) else { return nil }
        return .object(["secret": .string(c.secret), "algorithm": .string(c.algorithm),
                        "digits": .int(Int64(c.digits)), "period": .int(Int64(c.period))])
    }

    private func newRecord() -> [String: JSONValue] { Self.newRecord(kind: kind, now: clock.now, random: random) }

    /// An empty record of `kind` (the Safari import starts web logins from it too).
    nonisolated static func newRecord(kind: EditorKind, now: Int64, random: any RandomSource) -> [String: JSONValue] {
        let now = JSONValue.int(now)
        var r: [String: JSONValue] = ["id": .string(uuid4(random)), "kind": .string(kind.rawValue),
                                      "created_at": now, "updated_at": now, "favorite": .bool(false), "tags": .array([])]
        if kind == .web {
            r["label"] = .string(""); r["username"] = .string(""); r["password"] = .string(""); r["scope"] = .object([:])
        } else {
            r["title"] = .string(""); r["payload"] = .object([:])
        }
        return r
    }

    /// Python `str(uuid.uuid4())`.
    nonisolated static func uuid4(_ random: any RandomSource) -> String {
        var b = random.bytes(count: 16)
        b[6] = (b[6] & 0x0F) | 0x40; b[8] = (b[8] & 0x3F) | 0x80
        let h = b.map { String(format: "%02x", $0) }.joined()
        let c = Array(h)
        return [0..<8, 8..<12, 12..<16, 16..<20, 20..<32].map { String(c[$0]) }.joined(separator: "-")
    }

    /// Byte comparison of canonical forms (Swift `String ==` is canonical equivalence; Python's is not).
    static func same(_ a: JSONValue, _ b: JSONValue) -> Bool {
        guard let x = try? CanonicalJSON.encode(a, dialect: .utf8), let y = try? CanonicalJSON.encode(b, dialect: .utf8) else { return false }
        return x == y
    }

    /// How many history rows a save writes. The owner chose 10 (UX plan workstream 8) and LGKCore reads 10
    /// (`Normalise.passwordHistoryLimit`), but the Windows normaliser (`vault_bridge.py` `_MAX_PASSWORD_HISTORY`)
    /// and Android still refuse more than 5, so a login with 6+ rows would stop syncing to them. Raise this to
    /// `Normalise.passwordHistoryLimit` in the same release as those two.
    nonisolated static let historyWriteLimit = 5
    /// History rows older than this are dropped when a password changes (owner decision: kept 365 days).
    nonisolated static let historyKeepSeconds: Int64 = 365 * 86_400

    /// `vault.py` `update_entry`: when the password actually changes (byte comparison) from a non-empty one,
    /// the old password goes first in `password_history` as `{password, changed_at}`, keeping at most
    /// `historyWriteLimit` rows from the last 365 days.
    static func withPasswordHistory(_ edited: [String: JSONValue], original: [String: JSONValue]?, now: Int64) -> [String: JSONValue] {
        guard let previous = original?["password"]?.stringValue, !previous.isEmpty,
              let new = edited["password"]?.stringValue, Array(previous.utf8) != Array(new.utf8) else { return edited }
        var out = edited
        var history = edited["password_history"]?.arrayValue ?? []
        history.removeAll { row in
            guard case .object(let o) = row else { return false }
            let at: Int64? = if case .int(let n)? = o["changed_at"] ?? o["replaced_at"] { n } else { nil }
            return at.map { now - $0 > historyKeepSeconds } ?? false
        }
        history.insert(.object(["password": .string(previous), "changed_at": .int(now)]), at: 0)
        out["password_history"] = .array(Array(history.prefix(historyWriteLimit)))
        return out
    }

    private static func withoutStamp(_ r: JSONValue) -> JSONValue {
        guard case .object(var o) = r else { return r }
        o["updated_at"] = nil
        return .object(o)
    }

    // MARK: actions

    static let punycodeMessage = String(localized: "Enter this website's domain in its xn-- (punycode) form.")
    static let alreadyRemovedMessage = String(localized: "This item was already removed")

    func save() -> SaveResult {
        error = nil; needsPunycode = false; totpError = nil; websiteError = nil; amountError = nil
        let edited: [String: JSONValue]
        do { edited = try self.edited() } catch AmountError.invalid(let message) {
            amountError = message; error = String(localized: "Check the amount."); return .invalid
        } catch let e as TOTPError {
            totpError = TOTP.message(for: e); error = String(localized: "Check the 2FA secret."); return .invalid
        } catch WebsiteInputError.needsPunycode {
            needsPunycode = true; error = Self.punycodeMessage; return .needsPunycode
        } catch WebsiteInputError.required {
            websiteError = WebsiteInput.requiredMessage; error = String(localized: "Check the website."); return .invalid
        } catch WebsiteInputError.invalid(let message) {
            websiteError = message; error = String(localized: "Check the website."); return .invalid
        } catch { self.error = String(localized: "This item cannot be saved."); return .invalid }
        // Unchanged: leave the stored bytes alone so the version vector is not bumped.
        if let original, Self.same(.object(edited), .object(original)) { return .unchanged }
        if totpNeedsPro, ProFeatures.totpChangeNeedsPro(new: edited["totp"], old: original?["totp"]) {
            totpError = ProFeatures.totpMessage; error = String(localized: "Two-factor codes need Pro."); showUpgrade = true
            return .needsPro
        }
        do {
            var snap = try store.load()
            if isNew {
                guard ItemLimit.allows(.create, snapshot: snap, isPro: pro.isPro) else { showUpgrade = true; return .needsPro }
            }
            if let original,
               let before = try? Normalise.normalForm(ns: kind.ns, record: .object(original)),
               let after = try? Normalise.normalForm(ns: kind.ns, record: .object(edited)),
               Self.same(Self.withoutStamp(before), Self.withoutStamp(after)) {
                return .unchanged
            }
            var stamped = edited
            if keepsPasswordHistory, kind == .web { stamped = Self.withPasswordHistory(stamped, original: original, now: clock.now) }
            stamped["updated_at"] = .int(clock.now)
            if case .int(let created)? = stamped["created_at"], created > clock.now { stamped["created_at"] = .int(clock.now) }
            let record = try Normalise.normalForm(ns: kind.ns, record: .object(stamped))
            guard case .object(let o) = record, case .string(let rid)? = o["id"] else { error = String(localized: "This item cannot be saved."); return .invalid }
            if let id, rid != id { error = String(localized: "This item cannot be saved."); return .invalid }
            if isNew, snap.records[rid] != nil { error = String(localized: "This item cannot be saved."); return .failed }
            snap.records[rid] = Wrapper.make(ns: kind.ns, record: record)
            let change = StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync)
            try background.run("LocalGateKeys save") { try store.commit(change) }
            savedID = rid
            return .saved
        } catch NormaliseError.needsPunycode {
            needsPunycode = true
            error = Self.punycodeMessage
            return .needsPunycode
        } catch NormaliseError.rejected(let detail) {
            error = kind.friendlyError(detail); return .invalid
        } catch {
            self.error = String(localized: "The item could not be saved on this device."); return .failed
        }
    }

    /// Removes the record and writes its tombstone the way `SyncMeta.localView` would (one bump for this
    /// device), so the next sync publishes the delete. With no sync state (meta kept after Leave) there is no
    /// device to bump with; the meta is left for `SyncMeta.localView`, which tombstones a meta whose record
    /// is gone with exactly one bump on the next join. Writing an unbumped tomb here would lose the delete.
    /// `move`: the iPhone's Recently deleted (`PhoneTrash.moveToTrash`), which saves the record before it
    /// does the same store delete; nil deletes at once.
    func delete(using move: ((String) -> SaveResult)? = nil) -> SaveResult {
        guard let id else { return .failed }
        let r = move?(id) ?? Self.delete(id: id, store: store, clock: clock, background: background)
        if r == .failed { error = String(localized: "The item could not be deleted on this device.") }
        alreadyRemoved = r == .unchanged
        return r
    }

    func clearAlreadyRemoved() { alreadyRemoved = false }

    /// `delete()` for any item id (the passkey screen shares it).
    static func delete(id: String, store: any ItemStore, clock: any UnixClock, background: any BackgroundTasking) -> SaveResult {
        do {
            var snap = try store.load()
            guard snap.records.removeValue(forKey: id) != nil else { return .unchanged }
            if let m = snap.meta[id], !m.deleted, let device = snap.sync?.deviceID {
                snap.meta[id] = SyncMeta.tomb(vv: try VersionVector.bump(m.vv, device: device), deletedAt: clock.now)
            }
            let change = StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync)
            try background.run("LocalGateKeys save") { try store.commit(change) }
            return .saved
        } catch {
            return .failed
        }
    }
}
