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

/// One line of the read-only Token section; `expired` adds the Expired badge.
struct TokenRow: Identifiable, Equatable, Sendable {
    let id: String
    let label: String
    let value: String
    var expired = false
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

    /// This screen's model for `stored`, the item as saved now, when a screen pushed on top of it (access rules, a
    /// restored field, an earlier password) changed it; nil when it is unchanged. The detail screen stays open after
    /// those, so without this a rule set just now applied only once the item was opened again (simulator check
    /// 2026-11-16: "Confirm it's me" saved, then Reveal showed the password without asking). Secrets start masked
    /// when `concealSecrets` (the caller passes true for a login whose rules mask them); the screen-capture state is
    /// kept.
    func reloaded(_ stored: VaultItem, concealSecrets: Bool) -> ItemDetailModel? {
        guard stored.id == item.id, stored != item else { return nil }
        let next = ItemDetailModel(item: stored, clipboard: clipboard, clock: clock, concealSecrets: concealSecrets)
        next.screenCaptured = screenCaptured
        return next
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

    // MARK: Wi-Fi QR

    private var wifiPayload: [String: JSONValue] { item.record["payload"]?.objectValue ?? [:] }

    /// A Wi-Fi item whose security type a plain QR can express (not enterprise): the "Show QR" button is offered.
    var offersWifiQR: Bool {
        item.kind == "wifi"
            && WifiQR.text(ssid: "", password: "", security: wifiPayload["security"]?.stringValue ?? "wpa2", hidden: false) != nil
    }

    /// The Wi-Fi item's password field, when it has one.
    var wifiPasswordField: DetailField? { fields.first { $0.id == "password" } }

    /// The QR text, only while the password is revealed (showing the QR needs the same permission as revealing the
    /// password); an open network has no password and needs no reveal. Nil for enterprise and other kinds.
    var wifiQRText: String? {
        guard offersWifiQR else { return nil }
        if let pw = wifiPasswordField, !revealed.contains(pw.id) { return nil }
        let p = wifiPayload
        var hidden = false
        if case .bool(let b)? = p["hidden"] { hidden = b }
        return WifiQR.text(ssid: p["ssid"]?.stringValue ?? "", password: p["password"]?.stringValue ?? "",
                           security: p["security"]?.stringValue ?? "wpa2", hidden: hidden)
    }

    // MARK: JWT token

    /// The decoded JWT of a revealed API-key value (`key`, `secret`), or nil: other kinds, a hidden value, or a value
    /// that is not a token. The signature is never checked. A hidden value is never decoded.
    func token(for field: DetailField) -> JWTInfo? {
        guard item.kind == "api_key", field.id == "key" || field.id == "secret",
              field.isSecret, revealed.contains(field.id) else { return nil }
        return JWTView.decode(field.value)
    }

    /// The Token section's lines: algorithm and type, issuer, subject, audience and the three dates (empty ones left out).
    func tokenRows(_ info: JWTInfo) -> [TokenRow] {
        func text(_ name: String) -> String {
            if case .object(let c) = info.claims, case .string(let s)? = c[name] { return String(s.prefix(200)) }
            return ""
        }
        var typ = ""
        if case .object(let h) = info.header, case .string(let s)? = h["typ"] { typ = String(s.prefix(200)) }
        var audience = ""
        if case .object(let c) = info.claims {
            if case .array(let list)? = c["aud"] {
                audience = list.compactMap { (v: JSONValue) -> String? in if case .string(let s) = v { return String(s.prefix(200)) } else { return nil } }
                    .prefix(10).joined(separator: ", ")
            } else { audience = text("aud") }
        }
        func time(_ seconds: Int64?) -> String { seconds.map(Self.tokenTime) ?? "" }
        let rows = [
            TokenRow(id: "alg", label: String(localized: "Algorithm"), value: [info.alg ?? "", typ].filter { !$0.isEmpty }.joined(separator: " · ")),
            TokenRow(id: "iss", label: String(localized: "Issuer"), value: text("iss")),
            TokenRow(id: "sub", label: String(localized: "Subject"), value: text("sub")),
            TokenRow(id: "aud", label: String(localized: "Audience"), value: audience),
            TokenRow(id: "iat", label: String(localized: "Issued"), value: time(info.issued)),
            TokenRow(id: "nbf", label: String(localized: "Not before"), value: time(info.notBefore)),
            TokenRow(id: "exp", label: String(localized: "Expires"), value: time(info.expires), expired: info.expired(now: clock.now)),
        ]
        return rows.filter { !$0.value.isEmpty }
    }

    /// A token time as a local date and time.
    static func tokenTime(_ seconds: Int64) -> String {
        tokenTimeFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
    }

    private static let tokenTimeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium; f.timeStyle = .short
        return f
    }()

    private static let expiryFormatter: DateFormatter = {
        let f = DateFormatter()
        f.calendar = Calendar(identifier: .gregorian)
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    /// "Set expiry from token": the token has an `exp` and the item has no expiry yet.
    func canSetExpiry(from info: JWTInfo) -> Bool { info.expires != nil && !fields.contains { $0.id == "expires" } }

    /// The item's `expires` value for `info`: the token's local date, `yyyy-MM-dd`. Nil without an `exp`.
    static func expiryDate(_ info: JWTInfo) -> String? {
        guard let exp = info.expires else { return nil }
        return expiryFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(exp)))
    }

    /// Writes `expires` through the editor's own save, so the change is normalised, stamped and synced like an edit.
    static func setExpiry(_ date: String, item: VaultItem, store: any ItemStore, pro: ProModel) -> SaveResult {
        let editor = EditorModel(store: store, pro: pro, editing: item, kind: .apiKey,
                                 clock: SystemClock(), random: SystemRandomSource())
        editor.set("expires", date)
        return editor.save()
    }

    /// `limit`: cleared after at most that many seconds (copy once, feature pack §4.1); nil: the user's setting.
    func copy(_ field: DetailField, clearAfterAtMost limit: Int64? = nil) {
        if let limit { clipboard.copy(field.value, clearAfterAtMost: limit) } else { clipboard.copy(field.value) }
        lastCopied = field.label
    }

    /// True when there was a code to copy. `limit` as in `copy(_:clearAfterAtMost:)`.
    @discardableResult
    func copyTOTP(clearAfterAtMost limit: Int64? = nil) -> Bool {
        guard let code = totp?.code else { return false }
        if let limit { clipboard.copy(code, clearAfterAtMost: limit) } else { clipboard.copy(code) }
        lastCopied = String(localized: "Code")
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
