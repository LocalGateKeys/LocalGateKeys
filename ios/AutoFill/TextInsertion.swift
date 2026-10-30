import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// UX plan workstream 11: card and identity fields the AutoFill extension offers through the system's
/// text-insertion request (iOS 18+ "AutoFill > Passwords" on any text field; `prepareInterfaceForUserChoosingTextToInsert`).
/// UI-free, compiled into the iPhone and Mac extensions and their tests. The list is built only after the
/// extension's Face ID / Touch ID unlock, and the snapshot is dropped as soon as the request finishes.
///
/// Rules (same as desktop card fill):
/// - the card number and the security code always need the unlock that built this list (no cached snapshot);
/// - the security code is never pre-selected or offered first: it is listed last for its card and
///   `isPreselectable` is false;
/// - PINs, notes and every other secret field are never offered.
struct TextInsertionField: Identifiable, Equatable, Sendable {
    enum Kind: String, Sendable, CaseIterable {
        // Card
        case cardNumber, cardExpiry, cardholder, cardSecurityCode
        // Identity
        case name, email, phone, organization, address, addressLine1, addressLine2, city, state, postalCode, country
    }

    let recordID: String
    /// The item's title (the list's section header).
    let itemTitle: String
    let kind: Kind
    /// What the row says ("Card number", "Email", ...).
    let label: String
    /// The text inserted when the row is picked.
    let value: String
    /// What the row shows: masked for the card number and the security code.
    let display: String

    var id: String { recordID + "/" + kind.rawValue }
    var isCard: Bool { [.cardNumber, .cardExpiry, .cardholder, .cardSecurityCode].contains(kind) }
    /// Never pre-selected nor listed first: the security code.
    var isPreselectable: Bool { kind != .cardSecurityCode }
}

enum TextInsertionCatalog {
    /// Card fields in list order; the security code is last on purpose.
    static let cardFields: [(key: String, kind: TextInsertionField.Kind, label: String)] = [
        ("number", .cardNumber, String(localized: "Card number")),
        ("expiry", .cardExpiry, String(localized: "Expiry")),
        ("cardholder", .cardholder, String(localized: "Cardholder")),
        ("cvv", .cardSecurityCode, String(localized: "Security code")),
    ]

    static let identityFields: [(key: String, kind: TextInsertionField.Kind, label: String)] = [
        ("name", .name, String(localized: "Full name")),
        ("email", .email, String(localized: "Email")),
        ("phone", .phone, String(localized: "Phone")),
        ("organization", .organization, String(localized: "Organization")),
        ("address_line1", .addressLine1, String(localized: "Address line 1")),
        ("address_line2", .addressLine2, String(localized: "Address line 2")),
        ("city", .city, String(localized: "City")),
        ("state", .state, String(localized: "State / region")),
        ("postal_code", .postalCode, String(localized: "Postal code")),
        ("country", .country, String(localized: "Country")),
    ]

    /// Every live card and identity in the snapshot, cards first, each group by title; within an item the
    /// catalog's order, empty fields left out. Identities with an address also get one "Address" row
    /// (the lines joined by newlines) after the separate lines' first row.
    static func fields(_ snapshot: StoreSnapshot) -> [TextInsertionField] {
        var cards: [(String, [TextInsertionField])] = [], people: [(String, [TextInsertionField])] = []
        for id in snapshot.records.keys.sorted(by: Scalars.less) {
            if snapshot.meta[id]?.deleted == true { continue }
            guard case .object(let w)? = snapshot.records[id], case .string(let ns)? = w["ns"],
                  ns == Namespace.item.rawValue || ns == Namespace.entry.rawValue,
                  case .object(let r)? = w["record"], case .string(let kind)? = r["kind"] else { continue }
            let payload: [String: JSONValue]
            if case .object(let p)? = r["payload"] { payload = p } else { payload = [:] }
            var title = ""
            if case .string(let t)? = r["title"] { title = t }
            if title.isEmpty, case .string(let t)? = r["label"] { title = t }
            switch kind {
            case "card":
                let rows = card(id: id, title: title.isEmpty ? String(localized: "Payment card") : title, payload: payload)
                if !rows.isEmpty { cards.append((title, rows)) }
            case "identity":
                let rows = identity(id: id, title: title.isEmpty ? String(localized: "Identity") : title, payload: payload)
                if !rows.isEmpty { people.append((title, rows)) }
            default: continue
            }
        }
        func byTitle(_ a: (String, [TextInsertionField]), _ b: (String, [TextInsertionField])) -> Bool {
            a.0.localizedCaseInsensitiveCompare(b.0) == .orderedAscending
        }
        return cards.sorted(by: byTitle).flatMap(\.1) + people.sorted(by: byTitle).flatMap(\.1)
    }

    static func text(_ payload: [String: JSONValue], _ key: String) -> String {
        guard case .string(let s)? = payload[key] else { return "" }
        return s.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func card(id: String, title: String, payload: [String: JSONValue]) -> [TextInsertionField] {
        cardFields.compactMap { f in
            var value = text(payload, f.key)
            if f.kind == .cardNumber { value = value.filter { !$0.isWhitespace && $0 != "-" } }
            guard !value.isEmpty else { return nil }
            let display: String
            switch f.kind {
            case .cardNumber: display = "•••• " + String(value.suffix(4))
            case .cardSecurityCode: display = "•••"
            default: display = value
            }
            return TextInsertionField(recordID: id, itemTitle: title, kind: f.kind, label: f.label, value: value, display: display)
        }
    }

    static func identity(id: String, title: String, payload: [String: JSONValue]) -> [TextInsertionField] {
        var rows = identityFields.compactMap { f -> TextInsertionField? in
            let value = text(payload, f.key)
            guard !value.isEmpty else { return nil }
            return TextInsertionField(recordID: id, itemTitle: title, kind: f.kind, label: f.label, value: value, display: value)
        }
        let line1 = text(payload, "address_line1"), line2 = text(payload, "address_line2")
        let cityLine = [text(payload, "postal_code"), text(payload, "city")].filter { !$0.isEmpty }.joined(separator: " ")
        let lines = [line1, line2, cityLine, text(payload, "state"), text(payload, "country")].filter { !$0.isEmpty }
        if lines.count > 1, let at = rows.firstIndex(where: { $0.kind == .addressLine1 || $0.kind == .city }) {
            let full = lines.joined(separator: "\n")
            rows.insert(TextInsertionField(recordID: id, itemTitle: title, kind: .address, label: String(localized: "Address"), value: full,
                                           display: lines.joined(separator: ", ")), at: at)
        }
        return rows
    }
}
