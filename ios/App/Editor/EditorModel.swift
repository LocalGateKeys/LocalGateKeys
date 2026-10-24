import Foundation
import Observation
import AppShared

/// The kinds the phone edits field by field: the phone kinds (LGKCore `Normalise.phoneEntryKinds` +
/// `phoneItemKinds`) that have a case here. `passkey` is a phone kind (AutoFill creates it) but has no case:
/// it is only renamed or deleted (`PasskeyRenameModel`). Desktop logins and documents stay desktop-only.
enum EditorKind: String, CaseIterable, Identifiable, Sendable {
    case web, note, card, identity
    case bankAccount = "bank_account", purchase, subscription, warranty
    case wifi, license, apiKey = "api_key", sshKey = "ssh_key", bookmark
    var id: String { rawValue }

    init?(kind: String) {
        guard Normalise.phoneEntryKinds.contains(kind) || Normalise.phoneItemKinds.contains(kind) else { return nil }
        self.init(rawValue: kind)
    }

    var ns: Namespace { self == .web ? .entry : .item }
    var label: String { VaultItem.kindLabel(rawValue) }
    var isPurchaseLike: Bool { self == .purchase || self == .warranty || self == .subscription }

    /// The New item menu, in sections.
    static let menuSections: [[EditorKind]] = [
        [.web, .note, .card, .identity],
        [.bankAccount, .purchase, .subscription, .warranty],
        [.wifi, .license, .apiKey, .sshKey, .bookmark],
    ]

    struct Field: Identifiable, Sendable {
        let key: String
        let label: String
        var secret = false
        var multiline = false
        var keyboard: Keyboard = .text
        var control: Control = .text
        var caps: Caps = .none
        /// A line under the field, for what the label cannot say.
        var hint: String?
        var id: String { key }
    }
    enum Keyboard: Sendable { case text, url, email, number, phone, decimal }
    /// `toggle` values are "true"/"false"; `date` values are ISO `YYYY-MM-DD`; `amount` is a decimal in the
    /// currency's major unit (the record stores minor units).
    enum Control: Sendable, Equatable { case text, toggle, choice([String]), date, amount }
    enum Caps: Sendable { case none, words, sentences, characters }

    private static func title(_ key: String = "title") -> Field { Field(key: key, label: "Title", caps: .sentences) }
    private static let notes = Field(key: "notes", label: "Notes", multiline: true, caps: .sentences)
    private static func words(_ key: String, _ label: String) -> Field { Field(key: key, label: label, caps: .words) }
    private static func date(_ key: String, _ label: String) -> Field { Field(key: key, label: label, control: .date) }

    /// Field keys: `label`/`title` and the record or payload key they edit.
    var fields: [Field] {
        switch self {
        case .web: [Self.title("label"), Field(key: "origin", label: "Website", keyboard: .url),
                    Field(key: "username", label: "Username", keyboard: .email), Field(key: "password", label: "Password", secret: true),
                    Field(key: "totp", label: "2FA secret (TOTP)", secret: true),
                    Self.notes]
        case .note: [Self.title(), Field(key: "body", label: "Note", multiline: true, caps: .sentences)]
        case .card: [Self.title(), Self.words("cardholder", "Cardholder"),
                     Field(key: "number", label: "Card number", secret: true, keyboard: .number),
                     Field(key: "expiry", label: "Expiry (MM/YY)"), Field(key: "cvv", label: "CVV", secret: true, keyboard: .number),
                     Field(key: "pin", label: "PIN", secret: true, keyboard: .number), Self.notes]
        case .identity: [Self.title(), Self.words("name", "Full name"),
                         Field(key: "email", label: "Email", keyboard: .email), Field(key: "phone", label: "Phone", keyboard: .phone),
                         Self.words("organization", "Organization"), Self.words("job_title", "Job title"),
                         Self.words("address_line1", "Address line 1"), Self.words("address_line2", "Address line 2"),
                         Self.words("city", "City"), Self.words("state", "State / region"),
                         Field(key: "postal_code", label: "Postal code", caps: .characters), Self.words("country", "Country")]
        case .bankAccount: [Self.title(), Self.words("bank", "Bank"), Self.words("account_holder", "Account holder"),
                            Field(key: "account_number", label: "IBAN / account number", secret: true, caps: .characters,
                                  hint: "An IBAN is checked and stored without spaces."),
                            Field(key: "routing", label: "Routing number / BIC", caps: .characters),
                            Field(key: "pin", label: "PIN", secret: true, keyboard: .number), Self.notes]
        case .purchase, .warranty, .subscription:
            [Self.title(), Self.words("product", "Product"), Self.words("vendor", "Vendor"), Self.words("provider", "Provider"),
             Field(key: "amount_minor", label: "Amount", keyboard: .decimal, control: .amount),
             Field(key: "currency", label: "Currency", caps: .characters, hint: "Three letters, for example EUR or USD."),
             Self.date("purchase_date", "Purchase date"), Self.date("renewal_date", "Renewal date"),
             Self.date("expiration_date", "Expiration date"), Field(key: "active", label: "Active", control: .toggle), Self.notes]
        case .wifi: [Self.title(), Field(key: "ssid", label: "Network name (SSID)"),
                     Field(key: "password", label: "Password", secret: true),
                     Field(key: "security", label: "Security", control: .choice(Normalise.wifiSecurityTypes)),
                     Field(key: "hidden", label: "Hidden network", control: .toggle), Self.notes]
        case .license: [Self.title(), Self.words("product", "Product"), Self.words("vendor", "Vendor"),
                        Field(key: "license_value", label: "License key / serial", secret: true),
                        Self.date("purchase_date", "Purchase date"), Self.date("expiration_date", "Expiration date"), Self.notes]
        case .apiKey: [Self.title(), Self.words("service", "Service"), Field(key: "key", label: "Key", secret: true),
                       Field(key: "secret", label: "Secret", secret: true), Self.date("expires", "Expires"), Self.notes]
        case .sshKey: [Self.title(), Field(key: "private_key", label: "Private key", secret: true, multiline: true),
                       Field(key: "public_key", label: "Public key", multiline: true,
                             hint: "An OpenSSH line (ssh-ed25519 AAAA…). The fingerprint is worked out from it."),
                       Field(key: "passphrase", label: "Passphrase", secret: true), Field(key: "fingerprint", label: "Fingerprint"),
                       Self.notes]
        case .bookmark: [Self.title(), Field(key: "url", label: "URL", keyboard: .url, hint: "http:// or https://"), Self.notes]
        }
    }

    /// What a new item of this kind starts with.
    var defaults: [String: String] {
        switch self {
        case .wifi: ["security": "wpa2"]
        case .purchase, .warranty, .subscription: ["active": "true", "currency": Amount.localCurrency]
        default: [:]
        }
    }

    /// Display names for the Wi-Fi security choices.
    static func choiceLabel(_ value: String) -> String {
        switch value {
        case "none": "None (open)"
        case "wep": "WEP"
        case "wpa": "WPA"
        case "wpa2": "WPA2"
        case "wpa3": "WPA3"
        case "wpa2-enterprise": "WPA2 Enterprise"
        case "wpa3-enterprise": "WPA3 Enterprise"
        default: value
        }
    }
}

enum AmountError: Error, Equatable { case invalid(String) }

/// Amounts: the record keeps whole minor units (cents) plus a currency code, as the desktop does; the editor
/// shows and takes the major unit (12.99).
enum Amount {
    static var localCurrency: String {
        let code = Locale.current.currency?.identifier ?? ""
        return code.count == 3 ? code : ""
    }

    /// Minor-unit digits for a currency (2 for EUR, 0 for JPY); 2 for the desktop's "no currency" XXX.
    static func fractionDigits(_ code: String) -> Int {
        guard code.count == 3, code != "XXX" else { return 2 }
        let f = NumberFormatter()
        f.numberStyle = .currency
        f.currencyCode = code
        return f.maximumFractionDigits
    }

    static func minorUnits(_ text: String, currency: String) throws -> Int64 {
        var t = text.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: " ", with: "")
        if t.isEmpty { return 0 }
        t = t.replacingOccurrences(of: ",", with: ".")
        let body = t.hasPrefix("-") ? String(t.dropFirst()) : t
        let parts = body.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count <= 2, parts.allSatisfy({ $0.allSatisfy { $0.isASCII && $0.isNumber } }),
              !parts.joined().isEmpty else {
            throw AmountError.invalid("Enter the amount as a number, for example 12.99.")
        }
        let digits = fractionDigits(currency)
        let fraction = parts.count == 2 ? String(parts[1]) : ""
        guard fraction.count <= digits else {
            throw AmountError.invalid(digits == 0 ? "This currency has no decimals." : "Use at most \(digits) decimals.")
        }
        let whole = parts[0].isEmpty ? "0" : String(parts[0])
        let combined = whole + fraction.padding(toLength: digits, withPad: "0", startingAt: 0)
        guard combined.count <= 17, let n = Int64(combined), n <= 1_000_000_000_000_000 else {
            throw AmountError.invalid("This amount is too large.")
        }
        return t.hasPrefix("-") ? -n : n
    }

    /// 129999 CHF → "1299.99"; 1500 EUR → "15.00".
    static func text(minor: Int64, currency: String) -> String {
        let digits = fractionDigits(currency)
        let sign = minor < 0 ? "-" : ""
        let s = String(minor.magnitude)
        guard digits > 0 else { return sign + s }
        let padded = String(repeating: "0", count: max(0, digits + 1 - s.count)) + s
        return sign + padded.dropLast(digits) + "." + padded.suffix(digits)
    }

    /// "CHF 1,299.99" in the person's locale.
    static func display(minor: Int64, currency: String) -> String {
        let f = NumberFormatter()
        f.numberStyle = .currency
        if currency.count == 3 && currency != "XXX" { f.currencyCode = currency } else { f.currencySymbol = "" }
        let digits = fractionDigits(currency)
        f.minimumFractionDigits = digits; f.maximumFractionDigits = digits
        let value = NSDecimalNumber(mantissa: minor.magnitude, exponent: Int16(-digits), isNegative: minor < 0)
        return (f.string(from: value) ?? text(minor: minor, currency: currency)).trimmingCharacters(in: .whitespaces)
    }
}

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

    init(store: any ItemStore, pro: ProModel, editing item: VaultItem?, kind: EditorKind,
         clock: any UnixClock, random: any RandomSource, background: (any BackgroundTasking)? = nil) {
        self.store = store; self.pro = pro; self.clock = clock; self.random = random
        self.background = background ?? UIKitBackgroundTasks()
        self.kind = item.flatMap { EditorKind(kind: $0.kind) } ?? kind
        isNew = item == nil; id = item?.id; original = item?.record
        if let r = item?.record { values = Self.values(of: r, kind: self.kind) } else { values = self.kind.defaults }
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

    static let migrationQRMessage = "This QR code moves accounts out of an authenticator app. Scan the website's own 2FA setup code instead, or import the export on your PC."
    static let notTOTPQRMessage = "This QR code is not a 2FA setup code."
    static let totpCameraMessage = "The camera is not available. Paste the setup key instead."

    /// A QR code scanned for the 2FA field: a setup code (otpauth link or Base32 secret) fills the field,
    /// anything else leaves it as it was and explains why.
    func scanTOTP(_ code: String) {
        let text = code.trimmingCharacters(in: .whitespacesAndNewlines)
        let isOtpauth = text.lowercased().hasPrefix("otpauth")
        if text.lowercased().hasPrefix("otpauth-migration:") { totpError = Self.migrationQRMessage; return }
        do {
            guard try TOTP.parseField(text) != nil else { totpError = Self.notTOTPQRMessage; return }
            set("totp", text)
        } catch let e as TOTPError where isOtpauth {
            totpError = TOTP.message(for: e)
        } catch { totpError = Self.notTOTPQRMessage }
    }

    func totpCameraUnavailable() { totpError = Self.totpCameraMessage }

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
                scope["origin"] = .string(try WebsiteInput.origin(v))
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

    private static func withoutStamp(_ r: JSONValue) -> JSONValue {
        guard case .object(var o) = r else { return r }
        o["updated_at"] = nil
        return .object(o)
    }

    // MARK: actions

    static let punycodeMessage = "Enter this website's domain in its xn-- (punycode) form."
    static let alreadyRemovedMessage = "This item was already removed"

    func save() -> SaveResult {
        error = nil; needsPunycode = false; totpError = nil; websiteError = nil; amountError = nil
        let edited: [String: JSONValue]
        do { edited = try self.edited() } catch AmountError.invalid(let message) {
            amountError = message; error = "Check the amount."; return .invalid
        } catch let e as TOTPError {
            totpError = TOTP.message(for: e); error = "Check the 2FA secret."; return .invalid
        } catch WebsiteInputError.needsPunycode {
            needsPunycode = true; error = Self.punycodeMessage; return .needsPunycode
        } catch WebsiteInputError.required {
            websiteError = WebsiteInput.requiredMessage; error = "Check the website."; return .invalid
        } catch WebsiteInputError.invalid(let message) {
            websiteError = message; error = "Check the website."; return .invalid
        } catch { self.error = "This item cannot be saved."; return .invalid }
        // Unchanged: leave the stored bytes alone so the version vector is not bumped.
        if let original, Self.same(.object(edited), .object(original)) { return .unchanged }
        if totpNeedsPro, ProFeatures.totpChangeNeedsPro(new: edited["totp"], old: original?["totp"]) {
            totpError = ProFeatures.totpMessage; error = "Two-factor codes need Pro."; showUpgrade = true
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
            stamped["updated_at"] = .int(clock.now)
            if case .int(let created)? = stamped["created_at"], created > clock.now { stamped["created_at"] = .int(clock.now) }
            let record = try Normalise.normalForm(ns: kind.ns, record: .object(stamped))
            guard case .object(let o) = record, case .string(let rid)? = o["id"] else { error = "This item cannot be saved."; return .invalid }
            if let id, rid != id { error = "This item cannot be saved."; return .invalid }
            if isNew, snap.records[rid] != nil { error = "This item cannot be saved."; return .failed }
            snap.records[rid] = Wrapper.make(ns: kind.ns, record: record)
            let change = StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync)
            try background.run("LocalGateKeys save") { try store.commit(change) }
            return .saved
        } catch NormaliseError.needsPunycode {
            needsPunycode = true
            error = Self.punycodeMessage
            return .needsPunycode
        } catch NormaliseError.rejected(let detail) {
            error = detail; return .invalid
        } catch {
            self.error = "The item could not be saved on this device."; return .failed
        }
    }

    /// Removes the record and writes its tombstone the way `SyncMeta.localView` would (one bump for this
    /// device), so the next sync publishes the delete. With no sync state (meta kept after Leave) there is no
    /// device to bump with; the meta is left for `SyncMeta.localView`, which tombstones a meta whose record
    /// is gone with exactly one bump on the next join. Writing an unbumped tomb here would lose the delete.
    func delete() -> SaveResult {
        guard let id else { return .failed }
        let r = Self.delete(id: id, store: store, clock: clock, background: background)
        if r == .failed { error = "The item could not be deleted on this device." }
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
