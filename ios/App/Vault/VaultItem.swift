import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// One live record, decoded from its synced wrapper, with the list projection the desktop shows
/// (`agent.py` `_summary_title`, `row_target`, `kind_label`).
struct VaultItem: Identifiable, Equatable, Sendable {
    let id: String
    let kind: String
    let title: String
    let username: String
    /// The WEBSITE / APPLICATION column.
    let target: String
    /// Cards only: "•••• 6411" (plus " · 08/27" with an expiry). Never the full number; nil when the number
    /// is missing or shorter than 4 digits.
    let cardSummary: String?
    let tags: [String]
    let favorite: Bool
    let updatedAt: Int64
    /// The record's `created_at`, 0 when missing (the sort rule).
    let createdAt: Int64
    let record: [String: JSONValue]

    var kindLabel: String { Self.kindLabel(kind) }
    var isLogin: Bool { kind == "web" || kind == "desktop" }

    /// Live records of the snapshot: no tombstones, no licence states, nothing that fails to unwrap.
    static func items(from snapshot: StoreSnapshot) -> [VaultItem] {
        snapshot.records.compactMap { id, wrapper in
            if snapshot.meta[id]?.deleted == true { return nil }
            guard case .object(let w) = wrapper, case .string(let ns)? = w["ns"], ns != Namespace.license.rawValue,
                  case .object(let r)? = w["record"] else { return nil }
            return VaultItem(id: id, record: r)
        }
    }

    init?(id: String, record r: [String: JSONValue]) {
        guard case .string(let kind)? = r["kind"] else { return nil }
        self.id = id; self.kind = kind; self.record = r
        let scope = r["scope"]?.objectValue ?? [:]
        var title = r["title"]?.stringValue ?? r["label"]?.stringValue ?? ""
        if kind == "web", let origin = scope["origin"]?.stringValue, title == origin { title = Self.friendlyOriginLabel(origin) }
        self.title = title
        username = r["username"]?.stringValue ?? ""
        tags = (r["tags"]?.arrayValue ?? []).compactMap(\.stringValue)
        favorite = r["favorite"] == .bool(true)
        if case .int(let n)? = r["updated_at"] { updatedAt = n } else { updatedAt = 0 }
        if case .int(let n)? = r["created_at"] { createdAt = n } else { createdAt = 0 }
        target = Self.safeDisplay(Self.rowTarget(kind: kind, scope: scope, payload: r["payload"]?.objectValue ?? [:]))
        cardSummary = kind == "card" ? Self.cardSummary(payload: r["payload"]?.objectValue ?? [:]) : nil
    }

    /// The list subtitle: username, else the card's masked last four, else the target, else the kind.
    var listSubtitle: String {
        if !username.isEmpty { return username }
        if let cardSummary { return cardSummary }
        return target.isEmpty ? kindLabel : target
    }

    /// "•••• 6411", or "•••• 6411 · 08/27" with an expiry. Only the last four digits ever leave the payload.
    static func cardSummary(payload: [String: JSONValue]) -> String? {
        let digits = (payload["number"]?.stringValue ?? "").filter(\.isASCII).filter(\.isNumber)
        guard digits.count >= 4 else { return nil }
        var s = "•••• " + String(digits.suffix(4))
        let expiry = safeDisplay(payload["expiry"]?.stringValue ?? "", maxLength: 10).trimmingCharacters(in: .whitespaces)
        if !expiry.isEmpty { s += " · " + expiry }
        return s
    }

    // MARK: desktop parity

    static let kindLabelOverrides: [String: String] = [
        "web": String(localized: "Website login"), "desktop": String(localized: "Desktop login"), "card": String(localized: "Payment card"), "bank_account": String(localized: "Bank account"),
        "ssh_key": String(localized: "SSH key"), "api_key": String(localized: "API key"), "wifi": String(localized: "Wi-Fi network"), "passkey": String(localized: "Passkey"),
        // The rest read as the fallback below would ("note" -> "Note"), listed so they translate.
        "note": String(localized: "Note"), "identity": String(localized: "Identity"), "purchase": String(localized: "Purchase"),
        "subscription": String(localized: "Subscription"), "warranty": String(localized: "Warranty"),
        "license": String(localized: "License"), "bookmark": String(localized: "Bookmark"), "document": String(localized: "Document"),
    ]

    /// `agent.py` `kind_label`.
    static func kindLabel(_ kind: String) -> String {
        if let l = kindLabelOverrides[kind] { return l }
        let s = kind.replacingOccurrences(of: "_", with: " ").trimmingCharacters(in: .whitespaces)
        guard let first = s.first else { return String(localized: "Item") }
        return first.uppercased() + s.dropFirst().lowercased()
    }

    static let targetFields: [String: [String]] = [
        "passkey": ["relying_party_id"], "api_key": ["service"], "wifi": ["ssid"], "bank_account": ["bank"],
        "license": ["vendor", "product"], "purchase": ["vendor", "product"], "warranty": ["vendor", "product"],
        "subscription": ["vendor", "provider", "product"], "ssh_key": ["fingerprint"],
    ]

    /// `agent.py` `row_target`.
    static func rowTarget(kind: String, scope: [String: JSONValue], payload: [String: JSONValue]) -> String {
        switch kind {
        case "web": return scope["origin"]?.stringValue ?? ""
        case "desktop":
            let path = scope["exe_path"]?.stringValue ?? ""
            return path.split(whereSeparator: { $0 == "/" || $0 == "\\" }).last.map(String.init) ?? ""
        case "bookmark":
            return (payload["url"]?.stringValue).flatMap { URLComponents(string: $0)?.host } ?? ""
        case "card":
            let b = payload["brand"]?.stringValue ?? ""
            return b.prefix(1).uppercased() + b.dropFirst().lowercased()
        default:
            return (targetFields[kind] ?? []).compactMap { payload[$0]?.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }.joined(separator: " · ")
        }
    }

    /// `vault.py` `friendly_origin_label` (`OriginLabel`, shared with the Safari import).
    static func friendlyOriginLabel(_ origin: String) -> String { OriginLabel.friendly(origin) }

    /// `agent.py` `_safe_display`: control characters become spaces, at most 120 characters.
    static func safeDisplay(_ s: String, maxLength: Int = 120) -> String {
        String(String.UnicodeScalarView(s.unicodeScalars.map { sc in
            let cat = sc.properties.generalCategory
            let printable = !(cat == .control || cat == .format || cat == .surrogate || cat == .privateUse
                              || cat == .unassigned || cat == .lineSeparator || cat == .paragraphSeparator
                              || (cat == .spaceSeparator && sc != " "))
            return printable ? sc : " "
        }.prefix(maxLength)))
    }
}

extension JSONValue {
    var stringValue: String? { if case .string(let s) = self { return s }; return nil }
    var objectValue: [String: JSONValue]? { if case .object(let o) = self { return o }; return nil }
    var arrayValue: [JSONValue]? { if case .array(let a) = self { return a }; return nil }
}

extension VaultItem {
    /// Desktop `web_page_address`: a web login's origin, or the first `starts_with` row on that same origin (an
    /// imported full page address, 2026-10-29). Display and Open website only; matching uses every row.
    static func pageAddress(_ scope: [String: JSONValue]?) -> String? {
        guard let origin = scope?["origin"]?.stringValue else { return nil }
        for row in scope?["urls"]?.arrayValue ?? [] {
            guard let o = row.objectValue, o["match"]?.stringValue == "starts_with", let url = o["url"]?.stringValue,
                  let rowOrigin = try? Origin.originOf(url), rowOrigin.utf8.elementsEqual(origin.utf8) else { continue }
            return url
        }
        return origin
    }
}
