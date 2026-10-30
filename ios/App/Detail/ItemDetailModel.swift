import Foundation
import Observation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

struct DetailField: Identifiable, Equatable, Sendable {
    let id: String
    let label: String
    let value: String
    let isSecret: Bool
    var isMultiline: Bool { value.contains("\n") }
}

struct TOTPState: Equatable, Sendable {
    let code: String
    let period: Int
    let secondsRemaining: Int
    /// 1 at the start of a period, approaching 0 at its end: what the ring draws.
    var fractionRemaining: Double { Double(secondsRemaining) / Double(period) }
}

/// Item detail: the fields to show, reveal state, copy, and the TOTP code and ring.
@MainActor
@Observable
final class ItemDetailModel {
    let item: VaultItem
    let fields: [DetailField]
    private(set) var revealed: Set<String> = []
    /// The screen is recorded, mirrored or shared (`ScreenCaptureMonitor`): every secret is masked and the
    /// reveals are dropped, so nothing comes back on its own afterwards (audit 2026-10-24 L-8).
    var screenCaptured = false {
        didSet { if screenCaptured { revealed = [] } }
    }
    private(set) var totp: TOTPState?
    private(set) var lastCopied: String?

    @ObservationIgnored private let clipboard: any SecretCopying
    @ObservationIgnored private let clock: any UnixClock
    @ObservationIgnored private let totpSpec: (secret: String, algorithm: String, digits: Int, period: Int)?

    static let mask = "••••••••"

    /// Desktop `PROTECTED_FIELD_LABELS`: the fields the editor masks.
    static let maskedPayloadFields: [String: [(String, String)]] = [
        "card": [("number", String(localized: "Card number")), ("cvv", "CVV"), ("pin", "PIN")],
        "bank_account": [("account_number", String(localized: "IBAN / account number")), ("pin", "PIN")],
        "ssh_key": [("private_key", String(localized: "Private key")), ("passphrase", String(localized: "Passphrase"))],
        "api_key": [("key", String(localized: "Key")), ("secret", String(localized: "Secret"))],
        "wifi": [("password", String(localized: "Password"))],
        "passkey": [("private_key", String(localized: "Private key"))],   // never shown: passkeys take the `passkeyFields` path
        "license": [("license_value", String(localized: "License key / serial"))],
    ]

    /// `concealSecrets` false ("Hide passwords until tapped" off): protected fields start revealed.
    init(item: VaultItem, clipboard: any SecretCopying, clock: any UnixClock, concealSecrets: Bool = true) {
        self.item = item; self.clipboard = clipboard; self.clock = clock
        fields = Self.fields(for: item)
        if !concealSecrets { revealed = Set(fields.filter(\.isSecret).map(\.id)) }
        if case .object(let t)? = item.record["totp"], case .string(let secret)? = t["secret"] {
            func int(_ k: String, _ d: Int) -> Int { if case .int(let n)? = t[k] { return Int(n) }; return d }
            totpSpec = (secret, t["algorithm"]?.stringValue ?? "SHA1", int("digits", 6), int("period", 30))
        } else {
            totpSpec = nil
        }
        tick()
    }

    /// Kinds the phone cannot edit (desktop logins, documents) can still be deleted from the detail screen;
    /// passkeys have their own rename/delete sheet.
    static func offersDeleteOnly(kind: String) -> Bool {
        EditorKind(kind: kind) == nil && kind != "passkey"
    }

    static func fields(for item: VaultItem) -> [DetailField] {
        let r = item.record
        var out: [DetailField] = []
        func add(_ id: String, _ label: String, _ value: String?, secret: Bool = false) {
            if let value, !value.isEmpty { out.append(DetailField(id: id, label: label, value: value, isSecret: secret)) }
        }
        if item.isLogin {
            add("username", String(localized: "Username"), item.username)
            add("password", String(localized: "Password"), r["password"]?.stringValue, secret: true)
            add("target", item.kind == "web" ? String(localized: "Website") : String(localized: "Application"), item.target)
            add("notes", String(localized: "Notes"), r["notes"]?.stringValue)
            return out
        }
        if item.kind == "passkey" { return passkeyFields(item) }
        let payload = r["payload"]?.objectValue ?? [:]
        let masked = maskedPayloadFields[item.kind] ?? []
        let maskedKeys = Set(masked.map(\.0))
        for (key, label) in masked { add(key, label, payload[key]?.stringValue, secret: true) }
        for key in payload.keys.sorted(by: Scalars.less) where !maskedKeys.contains(key) && !hiddenPayloadKeys.contains(key) {
            switch payload[key] {
            case .bool(let b)?:
                // A Wi-Fi network is shown as hidden only when it is; "Active" always says which.
                if key != "hidden" || b { add(key, label(key), b ? String(localized: "Yes") : String(localized: "No")) }
            case .int(let n)? where key == "amount_minor":
                let code = payload["currency"]?.stringValue ?? "XXX"
                if n != 0 || code != "XXX" { add(key, String(localized: "Amount"), Amount.display(minor: n, currency: code)) }
            case .string(let v)? where key == "security":
                add(key, String(localized: "Security"), EditorKind.choiceLabel(v))
            case .string(let v)? where dateKeys.contains(key):
                add(key, label(key), Self.displayDate(v))
            default:
                add(key, label(key), payload[key]?.stringValue)
            }
        }
        for (i, f) in (payload["fields"]?.arrayValue ?? []).enumerated() {
            guard case .object(let o) = f else { continue }
            add("field-\(i)", o["name"]?.stringValue ?? String(localized: "Field"), o["value"]?.stringValue, secret: o["hidden"] == .bool(true))
        }
        return out
    }

    /// Payload keys never listed: bookkeeping, or shown through another row (currency with the amount).
    static let hiddenPayloadKeys: Set<String> = ["fields", "template_id", "document_ids", "last4", "number_format", "currency",
                                                 "attachment_id"]
    static let dateKeys: Set<String> = ["purchase_date", "expiration_date", "renewal_date", "expires"]
    static let labelOverrides: [String: String] = [
        "url": "URL", "ssid": String(localized: "Network name"), "routing": String(localized: "Routing number / BIC"), "license_value": String(localized: "License key"),
        "hidden": String(localized: "Hidden network"), "key_format": String(localized: "Key format"), "job_title": String(localized: "Job title"),
    ]
    static func label(_ key: String) -> String { labelOverrides[key] ?? VaultItem.kindLabel(key) }

    /// `yyyy-MM-dd` in UTC (the editor's `OptionalDateField.formatter`).
    static let isoDate: DateFormatter = {
        let f = DateFormatter()
        f.calendar = Calendar(identifier: .gregorian)
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    /// "2026-12-31" in the person's date style; anything else (an ISO week date) as stored.
    static func displayDate(_ iso: String) -> String {
        guard let d = isoDate.date(from: iso), isoDate.string(from: d) == iso else { return iso }
        let f = DateFormatter()
        f.dateStyle = .medium; f.timeStyle = .none
        f.timeZone = TimeZone(identifier: "UTC")
        return f.string(from: d)
    }

    /// Site, user, created date and whether it can sign in. Never the private key, credential id or user
    /// handle: nothing here is secret, so nothing can be revealed or copied that would let someone sign in.
    static func passkeyFields(_ item: VaultItem) -> [DetailField] {
        let payload = item.record["payload"]?.objectValue ?? [:]
        var out: [DetailField] = []
        func add(_ id: String, _ label: String, _ value: String?) {
            if let value, !value.isEmpty { out.append(DetailField(id: id, label: label, value: value, isSecret: false)) }
        }
        add("relying_party_id", String(localized: "Website"), payload["relying_party_id"]?.stringValue)
        add("user_name", String(localized: "User"), payload["user_name"]?.stringValue)
        add("created", String(localized: "Created"), payload["created"]?.stringValue)
        let usable = PasskeyRecord.from(.object(item.record), id: item.id)?.key != nil
        add("status", String(localized: "Status"), usable ? String(localized: "Can sign in") : String(localized: "Backup only"))
        add("notes", String(localized: "Notes"), payload["notes"]?.stringValue)
        return out
    }

    func displayValue(_ field: DetailField) -> String {
        field.isSecret && !revealed.contains(field.id) ? Self.mask : field.value
    }

    func isRevealed(_ field: DetailField) -> Bool { revealed.contains(field.id) }

    func toggleReveal(_ field: DetailField) {
        guard !screenCaptured else { return }
        if revealed.contains(field.id) { revealed.remove(field.id) } else { revealed.insert(field.id) }
    }

    func copy(_ field: DetailField) { clipboard.copy(field.value); lastCopied = field.label }

    /// True when there was a code to copy.
    @discardableResult
    func copyTOTP() -> Bool {
        guard let code = totp?.code else { return false }
        clipboard.copy(code); lastCopied = String(localized: "Code")
        return true
    }

    /// Recomputes the code; the view calls this once a second.
    func tick() {
        guard let s = totpSpec else { totp = nil; return }
        let now = clock.now
        guard let code = try? TOTP.code(secret: s.secret, algorithm: s.algorithm, digits: s.digits, period: s.period, at: now) else {
            totp = nil; return
        }
        totp = TOTPState(code: code, period: s.period, secondsRemaining: s.period - Int(now % Int64(s.period)))
    }
}
