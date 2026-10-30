import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

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
    /// The editor title for a new item ("New website login"): one key per kind, so each language words it.
    var newTitle: String {
        switch self {
        case .web: String(localized: "New website login")
        case .note: String(localized: "New note")
        case .card: String(localized: "New payment card")
        case .identity: String(localized: "New identity")
        case .bankAccount: String(localized: "New bank account")
        case .purchase: String(localized: "New purchase")
        case .subscription: String(localized: "New subscription")
        case .warranty: String(localized: "New warranty")
        case .wifi: String(localized: "New wi-fi network")
        case .license: String(localized: "New license")
        case .apiKey: String(localized: "New api key")
        case .sshKey: String(localized: "New ssh key")
        case .bookmark: String(localized: "New bookmark")
        }
    }
    /// The editor title for an existing item ("Edit website login").
    var editTitle: String {
        switch self {
        case .web: String(localized: "Edit website login")
        case .note: String(localized: "Edit note")
        case .card: String(localized: "Edit payment card")
        case .identity: String(localized: "Edit identity")
        case .bankAccount: String(localized: "Edit bank account")
        case .purchase: String(localized: "Edit purchase")
        case .subscription: String(localized: "Edit subscription")
        case .warranty: String(localized: "Edit warranty")
        case .wifi: String(localized: "Edit wi-fi network")
        case .license: String(localized: "Edit license")
        case .apiKey: String(localized: "Edit api key")
        case .sshKey: String(localized: "Edit ssh key")
        case .bookmark: String(localized: "Edit bookmark")
        }
    }
    /// The unsaved-draft prompt (`EditorDraftText`), one sentence per kind.
    var leftWhileEditingText: String {
        switch self {
        case .web: String(localized: "You left the app while editing a website login. Your changes were kept on this iPhone.")
        case .note: String(localized: "You left the app while editing a note. Your changes were kept on this iPhone.")
        case .card: String(localized: "You left the app while editing a payment card. Your changes were kept on this iPhone.")
        case .identity: String(localized: "You left the app while editing a identity. Your changes were kept on this iPhone.")
        case .bankAccount: String(localized: "You left the app while editing a bank account. Your changes were kept on this iPhone.")
        case .purchase: String(localized: "You left the app while editing a purchase. Your changes were kept on this iPhone.")
        case .subscription: String(localized: "You left the app while editing a subscription. Your changes were kept on this iPhone.")
        case .warranty: String(localized: "You left the app while editing a warranty. Your changes were kept on this iPhone.")
        case .wifi: String(localized: "You left the app while editing a wi-fi network. Your changes were kept on this iPhone.")
        case .license: String(localized: "You left the app while editing a license. Your changes were kept on this iPhone.")
        case .apiKey: String(localized: "You left the app while editing a api key. Your changes were kept on this iPhone.")
        case .sshKey: String(localized: "You left the app while editing a ssh key. Your changes were kept on this iPhone.")
        case .bookmark: String(localized: "You left the app while editing a bookmark. Your changes were kept on this iPhone.")
        }
    }
    /// A field label inside a sentence ("Clear expiration date", "Copy password"): lower-cased as English writes it,
    /// kept as is in German, where nouns keep their capital.
    static func midSentence(_ label: String) -> String {
        Bundle.main.preferredLocalizations.first?.hasPrefix("de") == true ? label : label.lowercased()
    }

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

    private static func title(_ key: String = "title") -> Field { Field(key: key, label: String(localized: "Title"), caps: .sentences) }
    private static let notes = Field(key: "notes", label: String(localized: "Notes"), multiline: true, caps: .sentences)
    private static func words(_ key: String, _ label: String) -> Field { Field(key: key, label: label, caps: .words) }
    private static func date(_ key: String, _ label: String) -> Field { Field(key: key, label: label, control: .date) }

    /// A normaliser message ("label cannot be empty") with the field's on-screen name ("Title can't be empty").
    /// The message may lead with up to two words ("item title", "card number"); the longest key wins.
    func friendlyError(_ detail: String) -> String {
        let words = detail.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        var best: (label: String, rest: String, keyLength: Int)?
        for f in fields {
            let name = f.key.replacingOccurrences(of: "_", with: " ")
            for skip in 0...min(2, words.count) {
                let tail = words.dropFirst(skip).joined(separator: " ")
                guard tail.hasPrefix(name + " "), name.count > (best?.keyLength ?? 0) else { continue }
                best = (f.label, String(tail.dropFirst(name.count)), name.count)
            }
        }
        guard let best else { return detail }
        return best.label + best.rest.replacingOccurrences(of: " cannot ", with: " can't ")
    }

    /// Field keys: `label`/`title` and the record or payload key they edit.
    var fields: [Field] {
        switch self {
        case .web: [Self.title("label"), Field(key: "origin", label: String(localized: "Website"), keyboard: .url),
                    Field(key: "username", label: String(localized: "Username"), keyboard: .email), Field(key: "password", label: String(localized: "Password"), secret: true),
                    Field(key: "totp", label: String(localized: "2FA secret (TOTP)"), secret: true),
                    Self.notes]
        case .note: [Self.title(), Field(key: "body", label: String(localized: "Note"), multiline: true, caps: .sentences)]
        case .card: [Self.title(), Self.words("cardholder", String(localized: "Cardholder")),
                     Field(key: "number", label: String(localized: "Card number"), secret: true, keyboard: .number),
                     Field(key: "expiry", label: String(localized: "Expiry (MM/YY)")), Field(key: "cvv", label: "CVV", secret: true, keyboard: .number),
                     Field(key: "pin", label: "PIN", secret: true, keyboard: .number), Self.notes]
        case .identity: [Self.title(), Self.words("name", String(localized: "Full name")),
                         Field(key: "email", label: String(localized: "Email"), keyboard: .email), Field(key: "phone", label: String(localized: "Phone"), keyboard: .phone),
                         Self.words("organization", String(localized: "Organization")), Self.words("job_title", String(localized: "Job title")),
                         Self.words("address_line1", String(localized: "Address line 1")), Self.words("address_line2", String(localized: "Address line 2")),
                         Self.words("city", String(localized: "City")), Self.words("state", String(localized: "State / region")),
                         Field(key: "postal_code", label: String(localized: "Postal code"), caps: .characters), Self.words("country", String(localized: "Country"))]
        case .bankAccount: [Self.title(), Self.words("bank", String(localized: "Bank")), Self.words("account_holder", String(localized: "Account holder")),
                            Field(key: "account_number", label: String(localized: "IBAN / account number"), secret: true, caps: .characters,
                                  hint: String(localized: "An IBAN is checked and stored without spaces.")),
                            Field(key: "routing", label: String(localized: "Routing number / BIC"), caps: .characters),
                            Field(key: "pin", label: "PIN", secret: true, keyboard: .number), Self.notes]
        case .purchase, .warranty, .subscription:
            [Self.title(), Self.words("product", String(localized: "Product")), Self.words("vendor", String(localized: "Vendor")), Self.words("provider", String(localized: "Provider")),
             Field(key: "amount_minor", label: String(localized: "Amount"), keyboard: .decimal, control: .amount),
             Field(key: "currency", label: String(localized: "Currency"), caps: .characters, hint: String(localized: "Three letters, for example EUR or USD.")),
             Self.date("purchase_date", String(localized: "Purchase date")), Self.date("renewal_date", String(localized: "Renewal date")),
             Self.date("expiration_date", String(localized: "Expiration date")), Field(key: "active", label: String(localized: "Active"), control: .toggle), Self.notes]
        case .wifi: [Self.title(), Field(key: "ssid", label: String(localized: "Network name (SSID)")),
                     Field(key: "password", label: String(localized: "Password"), secret: true),
                     Field(key: "security", label: String(localized: "Security"), control: .choice(Normalise.wifiSecurityTypes)),
                     Field(key: "hidden", label: String(localized: "Hidden network"), control: .toggle), Self.notes]
        case .license: [Self.title(), Self.words("product", String(localized: "Product")), Self.words("vendor", String(localized: "Vendor")),
                        Field(key: "license_value", label: String(localized: "License key / serial"), secret: true),
                        Self.date("purchase_date", String(localized: "Purchase date")), Self.date("expiration_date", String(localized: "Expiration date")), Self.notes]
        case .apiKey: [Self.title(), Self.words("service", String(localized: "Service")), Field(key: "key", label: String(localized: "Key"), secret: true),
                       Field(key: "secret", label: String(localized: "Secret"), secret: true), Self.date("expires", String(localized: "Expires")), Self.notes]
        case .sshKey: [Self.title(), Field(key: "private_key", label: String(localized: "Private key"), secret: true, multiline: true),
                       Field(key: "public_key", label: String(localized: "Public key"), multiline: true,
                             hint: String(localized: "An OpenSSH line (ssh-ed25519 AAAA…). The fingerprint is worked out from it.")),
                       Field(key: "passphrase", label: String(localized: "Passphrase"), secret: true), Field(key: "fingerprint", label: String(localized: "Fingerprint")),
                       Self.notes]
        case .bookmark: [Self.title(), Field(key: "url", label: "URL", keyboard: .url, hint: String(localized: "http:// or https://")), Self.notes]
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
        case "none": String(localized: "None (open)")
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
            throw AmountError.invalid(String(localized: "Enter the amount as a number, for example 12.99."))
        }
        let digits = fractionDigits(currency)
        let fraction = parts.count == 2 ? String(parts[1]) : ""
        guard fraction.count <= digits else {
            throw AmountError.invalid(digits == 0 ? String(localized: "This currency has no decimals.") : String(localized: "Use at most \(digits) decimals."))
        }
        let whole = parts[0].isEmpty ? "0" : String(parts[0])
        let combined = whole + fraction.padding(toLength: digits, withPad: "0", startingAt: 0)
        guard combined.count <= 17, let n = Int64(combined), n <= 1_000_000_000_000_000 else {
            throw AmountError.invalid(String(localized: "This amount is too large."))
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
