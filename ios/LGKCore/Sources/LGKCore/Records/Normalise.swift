import Foundation
import Crypto

public enum NormaliseError: Error, Equatable, Sendable {
    /// The desktop would refuse this record (detail is for humans only).
    case rejected(String)
    /// A non-ASCII host: the editor asks for the `xn--` form.
    case needsPunycode
    /// A kind the phone never edits; such records pass through untouched.
    case notPhoneKind
}

/// The phone's record normaliser: desktop `vault_bridge.normal_form` for web logins (`entry`) and every
/// synced typed kind (`item`). It is used only for records the phone edits; every other record (desktop
/// logins, documents) is stored and republished exactly as received. Where Python's behaviour is hard to
/// match exactly (non-ASCII bookmark hosts, odd base64), the phone refuses rather than guesses.
public enum Normalise {
    /// Most `password_history` rows a login may hold when read (UX plan workstream 8: 10, owner decision
    /// 2026-10-27). Writers keep their own cap (`EditorModel.historyWriteLimit`) until every platform reads 10.
    public static let passwordHistoryLimit = 10

    typealias Obj = [String: JSONValue]
    static let maxInt63 = Int64.max

    public static let phoneEntryKinds: Set<String> = ["web"]
    /// Everything the desktop syncs except `document` (its file never leaves the PC).
    public static let phoneItemKinds: Set<String> = ["note", "card", "identity", "passkey", "bookmark", "license",
                                                     "purchase", "warranty", "subscription", "bank_account", "ssh_key",
                                                     "api_key", "wifi"]
    /// Desktop `item_schema.ITEM_KINDS`; a kind outside it is rejected, not passed through.
    static let itemKinds: Set<String> = ["web", "desktop", "note", "bookmark", "document", "license", "purchase", "warranty",
                                         "subscription", "identity", "card", "bank_account", "ssh_key", "api_key", "wifi",
                                         "passkey"]

    static let entryFields: Set<String> = ["id", "kind", "label", "username", "password", "scope", "created_at", "updated_at",
                                           "favorite", "tags", "notes", "totp", "recovery_codes", "custom_fields", "policy",
                                           "password_history", "site_icon"]
    static let localTrustScopeKeys = ["sign_in_selector", "embedded_web_fill_approved", "browser_approval",
                                      "browser_approvals", "sync_pairing", "pairing_secret", "pairing_state"]
    static let matchModes: Set<String> = ["exact_origin", "host", "base_domain", "starts_with"]

    public static func normalForm(ns: Namespace, record: JSONValue) throws -> JSONValue {
        switch ns {
        case .entry: return try entry(record)
        case .item: return try item(record)
        case .license: throw NormaliseError.notPhoneKind
        }
    }

    // MARK: helpers

    static func reject(_ detail: String) -> NormaliseError { .rejected(detail) }

    static func len(_ s: String) -> Int { s.unicodeScalars.count }

    @discardableResult
    static func text(_ v: JSONValue?, _ field: String, _ limit: Int, allowEmpty: Bool) throws -> String {
        guard case .string(let s)? = v else { throw reject("\(field) must be text") }
        if !allowEmpty && s.isEmpty { throw reject("\(field) cannot be empty") }
        if len(s) > limit { throw reject("\(field) is too long") }
        if s.unicodeScalars.contains("\u{0}") { throw reject("\(field) contains a null character") }
        return s
    }

    /// Python `str.strip()`.
    static func pyStrip(_ s: String) -> String {
        var a = Array(s.unicodeScalars)
        while let f = a.first, Origin.isPySpace(f) { a.removeFirst() }
        while let l = a.last, Origin.isPySpace(l) { a.removeLast() }
        return String(String.UnicodeScalarView(a))
    }

    static func isASCIIDigits(_ s: String) -> Bool { !s.isEmpty && s.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }

    /// `uuid.UUID(text)` re-rendered: lower-case 8-4-4-4-12.
    static func uuid(_ v: JSONValue?, _ field: String) throws -> String {
        var s = try text(v, field, 128, allowEmpty: false)
        s = s.replacingOccurrences(of: "urn:", with: "").replacingOccurrences(of: "uuid:", with: "")
        var sc = Array(s.unicodeScalars)
        while sc.first == "{" || sc.first == "}" { sc.removeFirst() }
        while sc.last == "{" || sc.last == "}" { sc.removeLast() }
        let hex = String(String.UnicodeScalarView(sc.filter { $0 != "-" })).lowercased()
        guard hex.utf8.count == 32, hex.unicodeScalars.allSatisfy(\.properties.isASCIIHexDigit) else {
            throw reject("\(field) must be a UUID")
        }
        let h = Array(hex)
        return [0..<8, 8..<12, 12..<16, 16..<20, 20..<32].map { String(h[$0]) }.joined(separator: "-")
    }

    static func timestamp(_ v: JSONValue?, _ field: String) throws -> Int64 {
        guard case .int(let n)? = v, n >= 0 else { throw reject("\(field) must be a bounded UTC timestamp") }
        return n
    }

    // MARK: entries (web logins)

    static func entry(_ record: JSONValue) throws -> JSONValue {
        guard case .object(var rec) = record else { throw reject("Unsupported credential type") }
        if case .string(let kind)? = rec["kind"], kind == "desktop" { throw NormaliseError.notPhoneKind }
        let unknown = Set(rec.keys).subtracting(entryFields)
        if !unknown.isEmpty { throw reject("Credential contains unsupported fields: \(unknown.sorted())") }
        // vault._validate_legacy_payload
        guard rec["kind"] == .string("web") else { throw reject("Unsupported credential type") }
        for (field, limit) in [("id", 128), ("label", 512), ("username", 512), ("password", 4096)] {
            try text(rec[field], field, limit, allowEmpty: field == "username" || field == "password")
        }
        guard case .object(var scope)? = rec["scope"] else { throw reject("Credential scope is missing") }
        let originText: String
        switch scope["origin"] {
        case nil: originText = ""
        case .string(let s)?: originText = s
        default: throw reject("Origin must be a non-empty string shorter than 2049 characters")
        }
        scope["origin"] = .string(try origin { try Origin.canonicalize(originText) })
        if let tags = rec["tags"], case .array = tags {} else if rec["tags"] != nil { throw reject("Invalid tags") }
        rec["policy"] = policy(rec["policy"])
        // _canonical_entry
        for name in ["created_at", "updated_at"] where rec[name] != nil {
            guard case .int(let n)? = rec[name], n >= 0 else { throw reject("Credential \(name) is malformed") }
        }
        if let f = rec["favorite"], case .bool = f {} else if rec["favorite"] != nil { throw reject("Credential favorite is malformed") }
        let tags = try list(rec["tags"] ?? .array([]), max: 20, "Credential tags are malformed")
        for t in tags { try text(t, "tag", 40, allowEmpty: false) }
        if rec["notes"] != nil { try text(rec["notes"], "notes", 20000, allowEmpty: true) }
        let codes = try list(rec["recovery_codes"] ?? .array([]), max: 100, "Credential recovery codes are malformed")
        for c in codes { try text(c, "recovery code", 512, allowEmpty: false) }
        let fields = try list(rec["custom_fields"] ?? .array([]), max: 50, "Custom fields are malformed")
        for row in fields { try scalarDict(row, "custom field") }
        if let totp = rec["totp"], totp != .null {
            try scalarDict(totp, "TOTP")
            try checkTOTP(totp)
        }
        let history = try list(rec["password_history"] ?? .array([]), max: passwordHistoryLimit, "Password history is malformed")
        var canonicalHistory: [JSONValue] = []
        for row in history {
            guard case .object(let r) = row, Set(r.keys).isSubset(of: ["password", "changed_at", "replaced_at"]) else {
                throw reject("Password history is malformed")
            }
            let changed = r["changed_at"] ?? r["replaced_at"] ?? .null
            guard case .int(let at) = changed, at >= 0 else { throw reject("Credential password history time is malformed") }
            canonicalHistory.append(.object(["password": .string(try text(r["password"], "password", 4096, allowEmpty: true)),
                                             "changed_at": .int(at)]))
        }
        if rec["password_history"] != nil { rec["password_history"] = .array(canonicalHistory) }
        if let icon = rec["site_icon"], case .string = icon {} else if rec["site_icon"] != nil {
            throw reject("Credential icon is malformed")
        }
        if let urls = scope["urls"] { scope["urls"] = try webURLs(urls) }
        rec["scope"] = .object(scope)
        let size = try CanonicalJSON.encode(.object(rec), dialect: .utf8).count
        if size > 512 * 1024 { throw reject("Credential is too large") }
        // _strip_entry_local
        rec["site_icon"] = nil
        for key in localTrustScopeKeys { scope[key] = nil }
        rec["scope"] = .object(scope)
        if case .object(var p)? = rec["policy"] { p["sign_in"] = nil; rec["policy"] = .object(p) }
        return .object(rec)
    }

    static func origin(_ body: () throws -> String) throws -> String {
        do { return try body() } catch OriginError.needsPunycode { throw NormaliseError.needsPunycode } catch OriginError.invalid(let m) {
            throw reject(m)
        }
    }

    static func list(_ v: JSONValue, max: Int, _ message: String) throws -> [JSONValue] {
        guard case .array(let a) = v, a.count <= max else { throw reject(message) }
        return a
    }

    /// access_policy.normalized_policy
    static func policy(_ raw: JSONValue?) -> JSONValue {
        let p: Obj
        if case .object(let o)? = raw { p = o } else { p = [:] }
        let fill = p["fill"] ?? .string("click")
        let signIn = p["sign_in"] ?? .string("inherit")
        return .object([
            "fill": fill == .string("click") || fill == .string("never") ? fill : .string("never"),
            "sign_in": [.string("inherit"), .string("never"), .string("enabled")].contains(signIn) ? signIn : .string("never"),
            "require_master_password": .bool((p["require_master_password"] ?? .bool(false)) == .bool(true)),
            "save_prompts": .bool((p["save_prompts"] ?? .bool(true)) == .bool(true)),
        ])
    }

    static func scalarDict(_ v: JSONValue, _ name: String) throws {
        guard case .object(let o) = v, o.count <= 16 else { throw reject("\(name) is malformed") }
        for (key, value) in o {
            try text(.string(key), "\(name) key", 100, allowEmpty: false)
            switch value {
            case .null, .bool, .int: break
            case .float(let d): if !d.isFinite { throw reject("\(name) is malformed") }
            case .string: try text(value, name, 4096, allowEmpty: true)
            default: throw reject("\(name) is malformed")
            }
        }
    }

    static func checkTOTP(_ v: JSONValue) throws {
        guard case .object(let t) = v else { return }
        for name in ["secret", "algorithm"] where t[name] != nil {
            guard case .string? = t[name] else { throw reject("TOTP \(name) must be text") }
        }
        if let d = t["digits"] {
            guard case .int(let n) = d, (6...8).contains(n) else { throw reject("TOTP digits are unsupported") }
        }
        if let p = t["period"] {
            guard case .int(let n) = p, (15...120).contains(n) else { throw reject("TOTP period is unsupported") }
        }
    }

    /// item_schema.validate_web_urls
    static func webURLs(_ value: JSONValue) throws -> JSONValue {
        if value == .null { return .array([]) }
        guard case .array(let rows) = value, rows.count <= 20 else { throw reject("urls must be a list of at most 20 rows") }
        var out: [JSONValue] = []
        var seen = Set<[UInt32]>()
        for raw in rows {
            var row: Obj
            switch raw {
            case .string: row = ["url": raw]
            case .object(let o): row = o
            default: throw reject("url row must be an object")
            }
            if !Set(row.keys).isSubset(of: ["url", "match"]) { throw reject("url row contains unsupported data") }
            guard case .string(let mode) = row["match"] ?? .string("exact_origin"), matchModes.contains(mode) else {
                throw reject("url match mode is unsupported")
            }
            let rawURL = try text(row["url"] ?? .string(""), "url", 4096, allowEmpty: false)
            let url = try origin {
                if mode == "exact_origin" { return try Origin.canonicalize(rawURL) }
                let u = try Origin.normalizeURL(rawURL)
                if u.hasPrefix("http://") { _ = try Origin.canonicalize(try Origin.originOf(u)) }
                return u
            }
            if !seen.insert(Array((url + "\u{0}" + mode).unicodeScalars.map(\.value))).inserted { continue }
            out.append(.object(["url": .string(url), "match": .string(mode)]))
        }
        return .array(out)
    }

    // MARK: typed items

    static func item(_ record: JSONValue) throws -> JSONValue {
        guard case .object(let rec) = record else { throw reject("catalog item must be an object") }
        let allowed: Set<String> = ["id", "kind", "title", "created_at", "updated_at", "revision", "favorite", "tags",
                                    "collection_ids", "payload"]
        if !Set(rec.keys).isSubset(of: allowed) { throw reject("catalog item contains unsupported fields") }
        let kind = try text(rec["kind"] ?? .string(""), "item kind", 32, allowEmpty: false)
        guard itemKinds.contains(kind) else { throw reject("Unsupported item kind: \(kind)") }
        guard phoneItemKinds.contains(kind) else { throw NormaliseError.notPhoneKind }
        let id = try uuid(rec["id"], "item id")
        let title = try text(rec["title"] ?? .string(""), "item title", 512, allowEmpty: false)
        let created = try timestamp(rec["created_at"], "created_at")
        let updated = try timestamp(rec["updated_at"], "updated_at")
        if updated < created { throw reject("updated_at cannot be earlier than created_at") }
        if let r = rec["revision"] { guard case .int(let n) = r, n >= 1 else { throw reject("item revision is malformed") } }
        let favorite = rec["favorite"] ?? .bool(false)
        guard case .bool = favorite else { throw reject("favorite must be boolean") }
        let tags = try normalizeTags(rec["tags"] ?? .array([]))
        try collectionIDs(rec["collection_ids"] ?? .array([]))
        var payload = try validatePayload(kind, rec["payload"] ?? .object([:]))
        payload["document_ids"] = nil
        return .object(["id": .string(id), "kind": .string(kind), "title": .string(title), "created_at": .int(created),
                        "updated_at": .int(updated), "favorite": favorite, "tags": .array(tags.map(JSONValue.string)),
                        "payload": .object(payload)])
    }

    static func casefold(_ s: String) -> String { Casefold.fold(s) }

    /// `normalizeTags` for editors: stripped, 1–40 characters, case-insensitive duplicates dropped keeping the
    /// first spelling, at most 20.
    public static func tags(_ list: [String]) throws -> [String] { try normalizeTags(.array(list.map(JSONValue.string))) }

    static func normalizeTags(_ v: JSONValue) throws -> [String] {
        if v == .null { return [] }
        guard case .array(let a) = v else { throw reject("tags must be a list of text values") }
        var out: [String] = []
        // Keyed on code points: Swift String equality is canonical equivalence, Python's is not.
        var seen = Set<[UInt32]>()
        for t in a {
            let tag = pyStrip(try text(t, "tag", 40, allowEmpty: false))
            if tag.isEmpty { continue }
            if seen.insert(casefold(tag).unicodeScalars.map(\.value)).inserted { out.append(tag) }
        }
        if out.count > 20 { throw reject("At most 20 tags are supported per item") }
        return out
    }

    static func collectionIDs(_ v: JSONValue) throws {
        if v == .null { return }
        guard case .array(let a) = v else { throw reject("collection_ids must be a list") }
        var seen = Set<String>()
        for x in a { seen.insert(try uuid(x, "collection id")) }
        if seen.count > 20 { throw reject("An item cannot belong to more than 20 collections") }
    }

    static func optionalTemplateID(_ p: Obj) throws -> JSONValue {
        guard let t = p["template_id"], t != .null else { return .null }
        return .string(try text(t, "template id", 128, allowEmpty: false))
    }

    static func validatePayload(_ kind: String, _ value: JSONValue) throws -> Obj {
        guard case .object(let p) = value else { throw reject("\(kind) payload must be an object") }
        switch kind {
        case "note":
            if !Set(p.keys).isSubset(of: ["body", "fields", "template_id"]) { throw reject("note payload contains unsupported data") }
            let body = try text(p["body"] ?? .string(""), "note body", 20_000, allowEmpty: true)
            return ["body": .string(body), "fields": .array(try customFields(p["fields"] ?? .null)),
                    "template_id": try optionalTemplateID(p)]
        case "identity": return try identity(p)
        case "card": return try card(p)
        case "passkey": return try passkey(p)
        case "bookmark":
            if !Set(p.keys).isSubset(of: ["url", "notes", "template_id"]) { throw reject("bookmark payload contains unsupported data") }
            return ["url": .string(try bookmarkURL(p["url"] ?? .string(""))),
                    "notes": .string(try text(p["notes"] ?? .string(""), "bookmark notes", 20_000, allowEmpty: true)),
                    "template_id": try optionalTemplateID(p)]
        case "license": return try license(p)
        case "purchase", "warranty", "subscription": return try purchaseLike(kind, p)
        case "bank_account": return try bankAccount(p)
        case "ssh_key": return try sshKey(p)
        case "api_key": return try apiKey(p)
        case "wifi": return try wifi(p)
        default: throw NormaliseError.notPhoneKind
        }
    }

    /// Python `str.split()` with no separator: runs of whitespace, no empty parts.
    static func pySplit(_ s: String) -> [String] {
        var out: [String] = [], cur: [Unicode.Scalar] = []
        for c in s.unicodeScalars {
            if Origin.isPySpace(c) {
                if !cur.isEmpty { out.append(String(String.UnicodeScalarView(cur))); cur = [] }
            } else { cur.append(c) }
        }
        if !cur.isEmpty { out.append(String(String.UnicodeScalarView(cur))) }
        return out
    }

    /// Code-point order, as Python compares `str`.
    static func pyLess(_ a: String, _ b: String) -> Bool {
        a.unicodeScalars.map(\.value).lexicographicallyPrecedes(b.unicodeScalars.map(\.value))
    }

    // MARK: bookmarks

    /// item_schema.validate_bookmark_url. Stricter than the desktop in two places it is not worth matching:
    /// a non-ASCII host asks for the `xn--` form, and a bracketed host must be an IPv6 address.
    static func bookmarkURL(_ v: JSONValue) throws -> String {
        let url = try text(v, "bookmark URL", 4096, allowEmpty: false)
        if url.unicodeScalars.contains(where: { $0.value < 32 || Origin.isPySpace($0) }) {
            throw reject("bookmark URL contains whitespace or a control character")
        }
        let parts: Origin.Split
        do { parts = try Origin.split(url) } catch { throw reject("bookmark URL is malformed") }
        guard parts.scheme == "http" || parts.scheme == "https" else { throw reject("bookmark URL must use http or https") }
        guard !parts.netloc.isEmpty, parts.hostname != nil else { throw reject("bookmark URL must contain a host") }
        if parts.hasUserInfo { throw reject("bookmark URL must not contain embedded credentials") }
        if !parts.netloc.unicodeScalars.allSatisfy(\.isASCII) { throw NormaliseError.needsPunycode }
        if let open = parts.netloc.firstIndex(of: "["), let close = parts.netloc.firstIndex(of: "]"), open < close,
           Origin.ipv6(String(parts.netloc[parts.netloc.index(after: open)..<close])) == nil {
            throw reject("bookmark URL is malformed")
        }
        return url
    }

    // MARK: licences, purchases, warranties, subscriptions

    /// item_schema `_uuid_list`: at most `limit` UUIDs, no duplicates.
    @discardableResult
    static func uuidList(_ v: JSONValue?, _ field: String, limit: Int) throws -> [String] {
        guard let v, v != .null else { return [] }
        guard case .array(let a) = v, a.count <= limit else { throw reject("\(field) must be a list of at most \(limit) IDs") }
        var seen = Set<String>(), out: [String] = []
        for x in a {
            let id = try uuid(x, field)
            if !seen.insert(id).inserted { throw reject("\(field) contains a duplicate ID") }
            out.append(id)
        }
        return out
    }

    static func license(_ p: Obj) throws -> Obj {
        let allowed: Set<String> = ["license_value", "product", "vendor", "purchase_date", "expiration_date", "document_ids",
                                    "notes", "template_id"]
        if !Set(p.keys).isSubset(of: allowed) { throw reject("license payload contains unsupported data") }
        let expiration = try isoDate(p["expiration_date"] ?? .string(""), "expiration date")
        let purchase = try isoDate(p["purchase_date"] ?? .string(""), "purchase date")
        if !purchase.isEmpty && !expiration.isEmpty && pyLess(expiration, purchase) {
            throw reject("expiration date cannot precede purchase date")
        }
        return [
            "license_value": .string(try text(p["license_value"] ?? .string(""), "license value", 4096, allowEmpty: true)),
            "product": .string(try text(p["product"] ?? .string(""), "product", 512, allowEmpty: true)),
            "vendor": .string(try text(p["vendor"] ?? .string(""), "vendor", 512, allowEmpty: true)),
            "purchase_date": .string(purchase),
            "expiration_date": .string(expiration),
            "document_ids": .array(try uuidList(p["document_ids"] ?? .array([]), "document_ids", limit: 50).map(JSONValue.string)),
            "notes": .string(try text(p["notes"] ?? .string(""), "license notes", 20_000, allowEmpty: true)),
            "template_id": try optionalTemplateID(p),
        ]
    }

    /// item_schema `_currency`: three ASCII letters, upper-cased.
    static func currency(_ v: JSONValue) throws -> String {
        let raw = try text(v, "currency", 3, allowEmpty: false)
        // Python upper-cases some non-ASCII letters to ASCII ones; the phone takes ASCII only.
        guard raw.unicodeScalars.allSatisfy(\.isASCII) else { throw reject("currency must be a three-letter code") }
        let c = raw.uppercased()
        guard c.unicodeScalars.count == 3, c.unicodeScalars.allSatisfy({ ("A"..."Z").contains($0) }) else {
            throw reject("currency must be a three-letter code")
        }
        return c
    }

    static func purchaseLike(_ kind: String, _ p: Obj) throws -> Obj {
        let allowed: Set<String> = ["product", "vendor", "provider", "purchase_date", "expiration_date", "renewal_date",
                                    "amount_minor", "currency", "document_ids", "notes", "active", "template_id"]
        if !Set(p.keys).isSubset(of: allowed) { throw reject("\(kind) payload contains unsupported data") }
        let purchase = try isoDate(p["purchase_date"] ?? .string(""), "purchase date")
        let expiration = try isoDate(p["expiration_date"] ?? .string(""), "expiration date")
        let renewal = try isoDate(p["renewal_date"] ?? .string(""), "renewal date")
        if !purchase.isEmpty && !expiration.isEmpty && pyLess(expiration, purchase) {
            throw reject("expiration date cannot precede purchase date")
        }
        if !purchase.isEmpty && !renewal.isEmpty && pyLess(renewal, purchase) {
            throw reject("renewal date cannot precede purchase date")
        }
        if p["amount_minor"] == nil && p["currency"] != nil { throw reject("currency requires amount_minor") }
        if p["amount_minor"] != nil && p["currency"] == nil { throw reject("amount_minor requires currency") }
        guard case .int(let amount) = p["amount_minor"] ?? .int(0), (-1_000_000_000_000_000...1_000_000_000_000_000).contains(amount) else {
            throw reject("amount_minor must be a bounded integer in minor currency units")
        }
        let code = try currency(p["currency"] ?? .string("XXX"))
        let active = p["active"] ?? .bool(true)
        guard case .bool = active else { throw reject("active must be boolean") }
        return [
            "product": .string(try text(p["product"] ?? .string(""), "product", 512, allowEmpty: true)),
            "vendor": .string(try text(p["vendor"] ?? .string(""), "vendor", 512, allowEmpty: true)),
            "provider": .string(try text(p["provider"] ?? .string(""), "provider", 512, allowEmpty: true)),
            "purchase_date": .string(purchase),
            "expiration_date": .string(expiration),
            "renewal_date": .string(renewal),
            "amount_minor": .int(amount),
            "currency": .string(code),
            "document_ids": .array(try uuidList(p["document_ids"] ?? .array([]), "document_ids", limit: 50).map(JSONValue.string)),
            "notes": .string(try text(p["notes"] ?? .string(""), "\(kind) notes", 20_000, allowEmpty: true)),
            "active": active,
            "template_id": try optionalTemplateID(p),
        ]
    }

    // MARK: bank accounts

    /// item_schema `_IBAN_RE`: `^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$`.
    static func looksLikeIBAN(_ s: String) -> Bool {
        let c = Array(s.unicodeScalars)
        guard (15...34).contains(c.count) else { return false }
        func upper(_ x: Unicode.Scalar) -> Bool { ("A"..."Z").contains(x) }
        func digit(_ x: Unicode.Scalar) -> Bool { ("0"..."9").contains(x) }
        return upper(c[0]) && upper(c[1]) && digit(c[2]) && digit(c[3]) && c[4...].allSatisfy { upper($0) || digit($0) }
    }

    /// item_schema.validate_iban's mod-97 check on a compact upper-case IBAN.
    static func ibanChecksumOK(_ s: String) -> Bool {
        let c = Array(s.unicodeScalars)
        var rem = 0
        for x in c[4...] + c[..<4] {
            let v = ("0"..."9").contains(x) ? Int(x.value) - 48 : Int(x.value) - 55
            rem = (v < 10 ? rem * 10 + v : rem * 100 + v) % 97
        }
        return rem == 1
    }

    static func bankAccount(_ p: Obj) throws -> Obj {
        let allowed: Set<String> = ["bank", "account_holder", "account_number", "number_format", "routing", "pin", "notes",
                                    "template_id"]
        if !Set(p.keys).isSubset(of: allowed) { throw reject("bank account payload contains unsupported data") }
        var account = pyStrip(try text(p["account_number"] ?? .string(""), "account number", 64, allowEmpty: true))
        var format = ""
        if !account.isEmpty {
            let compact = account.replacingOccurrences(of: " ", with: "").uppercased()
            if looksLikeIBAN(compact) {
                // Python upper-cases non-ASCII letters too (ß → SS); refuse those rather than risk a mismatch.
                guard account.unicodeScalars.allSatisfy(\.isASCII) else { throw reject("IBAN is malformed") }
                guard ibanChecksumOK(compact) else { throw reject("IBAN failed its checksum") }
                account = compact
                format = "iban"
            } else {
                if account.unicodeScalars.contains(where: { $0.value < 32 }) {
                    throw reject("account number contains a control character")
                }
                format = "other"
            }
        }
        let rawRouting = pyStrip(try text(p["routing"] ?? .string(""), "routing or BIC", 34, allowEmpty: true))
        guard rawRouting.unicodeScalars.allSatisfy(\.isASCII) else { throw reject("routing or BIC must be alphanumeric") }
        let routing = rawRouting.uppercased()
        if !routing.isEmpty && !routing.unicodeScalars.allSatisfy({ ("A"..."Z").contains($0) || ("0"..."9").contains($0) || $0 == "-" }) {
            throw reject("routing or BIC must be alphanumeric")
        }
        return [
            "bank": .string(try text(p["bank"] ?? .string(""), "bank", 256, allowEmpty: true)),
            "account_holder": .string(try text(p["account_holder"] ?? .string(""), "account holder", 256, allowEmpty: true)),
            "account_number": .string(account),
            "number_format": .string(format),
            "routing": .string(routing),
            "pin": .string(try digits(p["pin"] ?? .string(""), "bank PIN", 4, 8)),
            "notes": .string(try text(p["notes"] ?? .string(""), "bank account notes", 20_000, allowEmpty: true)),
            "template_id": try optionalTemplateID(p),
        ]
    }

    // MARK: SSH keys

    static let pemFormats: [(String, String)] = [
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "openssh"),
        ("-----BEGIN RSA PRIVATE KEY-----", "pem-rsa"),
        ("-----BEGIN EC PRIVATE KEY-----", "pem-ec"),
        ("-----BEGIN DSA PRIVATE KEY-----", "pem-dsa"),
        ("-----BEGIN ENCRYPTED PRIVATE KEY-----", "pem-pkcs8-encrypted"),
        ("-----BEGIN PRIVATE KEY-----", "pem-pkcs8"),
        ("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----", "ssh2"),
        ("PuTTY-User-Key-File-", "putty"),
    ]
    static let opensshKeyTypes = ["ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-"]

    /// item_schema.sniff_private_key_format
    static func keyFormat(_ privateKey: String) -> String {
        let s = pyStrip(privateKey)
        if s.isEmpty { return "" }
        for (header, name) in pemFormats where s.unicodeScalars.starts(with: header.unicodeScalars) {
            let head = String(String.UnicodeScalarView(s.unicodeScalars.prefix(512)))
            if name == "pem-rsa" && Scalars.contains(head, "Proc-Type: 4,ENCRYPTED") { return "pem-rsa-encrypted" }
            return name
        }
        return "unknown"
    }

    /// item_schema.openssh_fingerprint: `SHA256:<base64, unpadded>` for an OpenSSH public key line, "" otherwise.
    static func opensshFingerprint(_ publicKey: String) throws -> String {
        let parts = pySplit(publicKey)
        guard parts.count >= 2, opensshKeyTypes.contains(where: { parts[0].unicodeScalars.starts(with: $0.unicodeScalars) }) else {
            return ""
        }
        let b64 = parts[1]
        // `b64decode(validate=True)`: the standard alphabet, then at most two `=` at the very end.
        let body = b64.unicodeScalars.prefix { ("A"..."Z").contains($0) || ("a"..."z").contains($0) || ("0"..."9").contains($0)
            || $0 == "+" || $0 == "/" }
        let pad = b64.unicodeScalars.dropFirst(body.count)
        guard pad.count <= 2, pad.allSatisfy({ $0 == "=" }), let blob = Data(base64Encoded: b64) else {
            throw reject("OpenSSH public key is not valid base64")
        }
        if blob.isEmpty { throw reject("OpenSSH public key is empty") }
        var digest = Data(SHA256.hash(data: blob)).base64EncodedString()
        while digest.hasSuffix("=") { digest.removeLast() }
        return "SHA256:" + digest
    }

    static func sshKey(_ p: Obj) throws -> Obj {
        let allowed: Set<String> = ["private_key", "public_key", "passphrase", "fingerprint", "key_format", "notes", "template_id"]
        if !Set(p.keys).isSubset(of: allowed) { throw reject("SSH key payload contains unsupported data") }
        let privateKey = try text(p["private_key"] ?? .string(""), "private key", 20_000, allowEmpty: true)
        let publicKey = try text(p["public_key"] ?? .string(""), "public key", 20_000, allowEmpty: true)
        let computed = try opensshFingerprint(publicKey)
        let fingerprint = computed.isEmpty
            ? pyStrip(try text(p["fingerprint"] ?? .string(""), "fingerprint", 128, allowEmpty: true)) : computed
        return [
            "private_key": .string(privateKey),
            "public_key": .string(publicKey),
            "passphrase": .string(try text(p["passphrase"] ?? .string(""), "passphrase", 4096, allowEmpty: true)),
            "fingerprint": .string(fingerprint),
            "key_format": .string(keyFormat(privateKey)),
            "notes": .string(try text(p["notes"] ?? .string(""), "SSH key notes", 20_000, allowEmpty: true)),
            "template_id": try optionalTemplateID(p),
        ]
    }

    // MARK: API keys, Wi-Fi

    static func apiKey(_ p: Obj) throws -> Obj {
        if !Set(p.keys).isSubset(of: ["service", "key", "secret", "expires", "notes", "template_id"]) {
            throw reject("API key payload contains unsupported data")
        }
        return [
            "service": .string(try text(p["service"] ?? .string(""), "service", 512, allowEmpty: true)),
            "key": .string(try text(p["key"] ?? .string(""), "API key", 4096, allowEmpty: true)),
            "secret": .string(try text(p["secret"] ?? .string(""), "API secret", 4096, allowEmpty: true)),
            "expires": .string(try isoDate(p["expires"] ?? .string(""), "API key expiry")),
            "notes": .string(try text(p["notes"] ?? .string(""), "API key notes", 20_000, allowEmpty: true)),
            "template_id": try optionalTemplateID(p),
        ]
    }

    public static let wifiSecurityTypes = ["none", "wep", "wpa", "wpa2", "wpa3", "wpa2-enterprise", "wpa3-enterprise"]

    static func wifi(_ p: Obj) throws -> Obj {
        if !Set(p.keys).isSubset(of: ["ssid", "password", "security", "hidden", "notes", "template_id"]) {
            throw reject("Wi-Fi payload contains unsupported data")
        }
        guard case .string(let rawSecurity) = p["security"] ?? .string("wpa2") else { throw reject("Wi-Fi security type must be text") }
        var security = casefold(pyStrip(rawSecurity))
        if security.isEmpty { security = "wpa2" }
        guard wifiSecurityTypes.contains(security) else { throw reject("Wi-Fi security type is unsupported") }
        let hidden = p["hidden"] ?? .bool(false)
        guard case .bool = hidden else { throw reject("Wi-Fi hidden flag must be boolean") }
        return [
            "ssid": .string(try text(p["ssid"] ?? .string(""), "SSID", 32, allowEmpty: true)),
            "password": .string(try text(p["password"] ?? .string(""), "Wi-Fi password", 4096, allowEmpty: true)),
            "security": .string(security),
            "hidden": hidden,
            "notes": .string(try text(p["notes"] ?? .string(""), "Wi-Fi notes", 20_000, allowEmpty: true)),
            "template_id": try optionalTemplateID(p),
        ]
    }

    static func customFields(_ v: JSONValue) throws -> [JSONValue] {
        if v == .null { return [] }
        guard case .array(let a) = v, a.count <= 50 else { throw reject("template fields must be a list of at most 50 values") }
        return try a.map { f in
            guard case .object(let o) = f else { throw reject("template field must be an object") }
            if !Set(o.keys).isSubset(of: ["name", "value", "hidden"]) { throw reject("template field contains unsupported data") }
            return .object([
                "name": .string(try text(o["name"] ?? .string(""), "field name", 100, allowEmpty: false)),
                "value": .string(try text(o["value"] ?? .string(""), "field value", 4096, allowEmpty: true)),
                "hidden": .bool((o["hidden"] ?? .bool(false)) == .bool(true)),
            ])
        }
    }

    static let identityLimits: [String: Int] = [
        "name": 256, "given_name": 128, "middle_name": 128, "family_name": 128, "organization": 256, "company": 256,
        "job_title": 160, "email": 320, "phone": 64, "address": 1024, "address_line1": 256, "address_line2": 256,
        "city": 128, "state": 128, "postal_code": 64, "country": 128, "website": 2048,
    ]

    static func identity(_ p: Obj) throws -> Obj {
        if !Set(p.keys).isSubset(of: Set(identityLimits.keys).union(["template_id"])) {
            throw reject("identity payload contains unsupported fields")
        }
        var out: Obj = [:]
        var total = 0
        for (field, limit) in identityLimits where p[field] != nil {
            let t = try text(p[field], "identity field \(field)", limit, allowEmpty: true)
            out[field] = .string(t)
            total += len(t)
        }
        if total > 8192 { throw reject("identity payload is too large") }
        if let t = p["template_id"] {
            out["template_id"] = t == .null ? .null : .string(try text(t, "template id", 128, allowEmpty: false))
        }
        return out
    }

    // MARK: cards

    static func cardNumber(_ v: JSONValue) throws -> String {
        let t = try text(v, "card number", 64, allowEmpty: true)
        let digits = t.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "-", with: "")
        if digits.isEmpty { return "" }
        guard isASCIIDigits(digits) else { throw reject("card number must contain digits only") }
        guard (12...19).contains(digits.utf8.count) else { throw reject("card number must be 12 to 19 digits") }
        return digits
    }

    static func luhn(_ digits: String) -> Bool {
        var total = 0
        for (i, c) in digits.utf8.reversed().enumerated() {
            var d = Int(c) - 48
            if i % 2 == 1 { d *= 2; if d > 9 { d -= 9 } }
            total += d
        }
        return total % 10 == 0
    }

    static func cardBrand(_ digits: String) -> String {
        let n = digits.utf8.count
        func prefix(_ k: Int) -> Int { Int(digits.prefix(k))! }
        let p2 = prefix(2), p3 = prefix(3), p4 = prefix(4), p6 = prefix(6)
        if [34, 37].contains(p2) && n == 15 { return "amex" }
        if digits.hasPrefix("4") && [13, 16, 19].contains(n) { return "visa" }
        if ((51...55).contains(p2) || (2221...2720).contains(p4)) && n == 16 { return "mastercard" }
        if (p4 == 6011 || (622126...622925).contains(p6) || (644...649).contains(p3) || p2 == 65) && (16...19).contains(n) {
            return "discover"
        }
        if ((300...305).contains(p3) || p4 == 3095 || [36, 38, 39].contains(p2)) && (14...19).contains(n) { return "diners" }
        if (3528...3589).contains(p4) && (16...19).contains(n) { return "jcb" }
        if p2 == 62 && (16...19).contains(n) { return "unionpay" }
        if (p2 == 50 || (56...69).contains(p2)) && (12...19).contains(n) { return "maestro" }
        return "unknown"
    }

    static func cardExpiry(_ v: JSONValue) throws -> String {
        let t = pyStrip(try text(v, "card expiry", 10, allowEmpty: true))
        if t.isEmpty { return "" }
        let sc = Array(t.unicodeScalars)
        func isDigit(_ c: Unicode.Scalar) -> Bool { c.value >= 0x30 && c.value <= 0x39 }
        var i = 0
        while i < sc.count, isDigit(sc[i]) { i += 1 }
        let month = String(String.UnicodeScalarView(sc[0..<i]))
        var j = i
        while j < sc.count, Origin.isPySpace(sc[j]) { j += 1 }
        guard (1...2).contains(month.count), j < sc.count, sc[j] == "/" || sc[j] == "-" else {
            throw reject("card expiry must be MM/YY")
        }
        j += 1
        while j < sc.count, Origin.isPySpace(sc[j]) { j += 1 }
        var year = String(String.UnicodeScalarView(sc[j...]))
        guard isASCIIDigits(year), year.count == 2 || year.count == 4 else { throw reject("card expiry must be MM/YY") }
        let m = Int(month)!
        guard (1...12).contains(m) else { throw reject("card expiry month must be 01-12") }
        if year.count == 4 {
            guard year.hasPrefix("20") else { throw reject("card expiry year is out of range") }
            year = String(year.dropFirst(2))
        }
        return (m < 10 ? "0" : "") + "\(m)/\(year)"
    }

    static func digits(_ v: JSONValue, _ field: String, _ lo: Int, _ hi: Int) throws -> String {
        let t = pyStrip(try text(v, field, hi + 16, allowEmpty: true))
        if t.isEmpty { return "" }
        guard isASCIIDigits(t), (lo...hi).contains(t.utf8.count) else { throw reject("\(field) must be \(lo) to \(hi) digits") }
        return t
    }

    static func card(_ p: Obj) throws -> Obj {
        let allowed: Set<String> = ["cardholder", "number", "brand", "last4", "expiry", "cvv", "pin", "billing_address_id",
                                    "notes", "template_id"]
        if !Set(p.keys).isSubset(of: allowed) { throw reject("card payload contains unsupported data") }
        let number = try cardNumber(p["number"] ?? .string(""))
        if !number.isEmpty && !luhn(number) { throw reject("card number failed its checksum") }
        let billingRaw = p["billing_address_id"] ?? .string("")
        let billing = billingRaw == .null || billingRaw == .string("") ? "" : try uuid(billingRaw, "billing address id")
        return [
            "cardholder": .string(try text(p["cardholder"] ?? .string(""), "cardholder", 256, allowEmpty: true)),
            "number": .string(number),
            "brand": .string(number.isEmpty ? "" : cardBrand(number)),
            "last4": .string(String(number.suffix(4))),
            "expiry": .string(try cardExpiry(p["expiry"] ?? .string(""))),
            "cvv": .string(try digits(p["cvv"] ?? .string(""), "card CVV", 3, 4)),
            "pin": .string(try digits(p["pin"] ?? .string(""), "card PIN", 4, 8)),
            "billing_address_id": .string(billing),
            "notes": .string(try text(p["notes"] ?? .string(""), "card notes", 20_000, allowEmpty: true)),
            "template_id": try optionalTemplateID(p),
        ]
    }

    // MARK: passkeys

    static let passkeyFields: Set<String> = ["relying_party_id", "user_handle", "credential_id", "private_key", "algorithm",
                                             "created", "notes", "template_id", "user_name", "user_display_name", "rp_name",
                                             "discoverable"]
    static let passkeyAlgorithms: Set<String> = ["ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA"]

    /// item_schema `_HOSTNAME_RE`: 1-253 characters of dot-separated `[a-z0-9]` labels (inner `-`), each 1-63 long.
    static func isHostname(_ s: String) -> Bool {
        let b = Array(s.unicodeScalars)
        guard (1...253).contains(b.count) else { return false }
        for label in s.split(separator: ".", omittingEmptySubsequences: false) {
            let l = Array(label.unicodeScalars)
            guard (1...63).contains(l.count), l.first != "-", l.last != "-" else { return false }
            guard l.allSatisfy({ ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "-" }) else { return false }
        }
        return true
    }

    /// item_schema `_base64url`: text up to 1024, stripped, `^[A-Za-z0-9_\-]+=*$` when non-empty.
    static func base64url(_ v: JSONValue, _ field: String) throws -> String {
        let t = pyStrip(try text(v, field, 1024, allowEmpty: true))
        if t.isEmpty { return t }
        let sc = Array(t.unicodeScalars)
        var i = 0
        while i < sc.count, ("A"..."Z").contains(sc[i]) || ("a"..."z").contains(sc[i]) || ("0"..."9").contains(sc[i])
                || sc[i] == "_" || sc[i] == "-" { i += 1 }
        let body = i
        while i < sc.count, sc[i] == "=" { i += 1 }
        guard body > 0, i == sc.count else { throw reject("\(field) must be base64url text") }
        return t
    }

    /// item_schema `_date` (allow_empty): None or "" gives "", else Python 3.12 `date.fromisoformat` on up to 10
    /// characters: `YYYY-MM-DD`, `YYYYMMDD`, `YYYY-Www[-D]`, `YYYYWww[D]`. The text is kept as given.
    static func isoDate(_ v: JSONValue?, _ field: String) throws -> String {
        if v == nil || v == .null || v == .string("") { return "" }
        let t = try text(v, field, 10, allowEmpty: false)
        guard t.unicodeScalars.allSatisfy({ $0.isASCII }) else { throw reject("\(field) must be an ISO date (YYYY-MM-DD)") }
        let c = Array(t.utf8)
        func num(_ r: Range<Int>) -> Int? {
            guard r.upperBound <= c.count, c[r].allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return nil }
            return Int(String(decoding: c[r], as: UTF8.self))
        }
        func fail() -> NormaliseError { reject("\(field) must be an ISO date (YYYY-MM-DD)") }
        guard c.count >= 7, let year = num(0..<4), year >= 1 else { throw fail() }
        let dash = c[4] == UInt8(ascii: "-")
        let rest = Array(c[(dash ? 5 : 4)...])
        if rest.first == UInt8(ascii: "W") {
            // ISO week date
            let w = Array(rest.dropFirst())
            let week: Int, day: Int
            func n(_ a: ArraySlice<UInt8>) -> Int? {
                a.isEmpty || !a.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) ? nil : Int(String(decoding: a, as: UTF8.self))
            }
            if w.count == 2 { guard let x = n(w[0..<2]) else { throw fail() }; week = x; day = 1 }
            else if dash && w.count == 4 && w[2] == UInt8(ascii: "-") {
                guard let x = n(w[0..<2]), let d = n(w[3..<4]) else { throw fail() }; week = x; day = d
            } else if !dash && w.count == 3 {
                guard let x = n(w[0..<2]), let d = n(w[2..<3]) else { throw fail() }; week = x; day = d
            } else { throw fail() }
            guard (1...7).contains(day), week >= 1 else { throw fail() }
            if week > 52 {
                // A year has week 53 when it starts on a Thursday, or a Wednesday in a leap year.
                let jan1 = weekday(year, 1, 1)  // 1 = Monday
                guard week == 53, jan1 == 4 || (jan1 == 3 && isLeap(year)) else { throw fail() }
            }
            return t
        }
        let month: Int, dayOfMonth: Int
        if dash {
            guard c.count == 10, c[7] == UInt8(ascii: "-"), let m = num(5..<7), let d = num(8..<10) else { throw fail() }
            month = m; dayOfMonth = d
        } else {
            guard c.count == 8, let m = num(4..<6), let d = num(6..<8) else { throw fail() }
            month = m; dayOfMonth = d
        }
        let days = [31, isLeap(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        guard (1...12).contains(month), (1...days[month - 1]).contains(dayOfMonth) else { throw fail() }
        return t
    }

    static func isLeap(_ y: Int) -> Bool { y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) }

    /// ISO weekday (1 = Monday) by Sakamoto's method.
    static func weekday(_ y0: Int, _ m: Int, _ d: Int) -> Int {
        let t = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4]
        let y = m < 3 ? y0 - 1 : y0
        let w = (y + y / 4 - y / 100 + y / 400 + t[m - 1] + d) % 7  // 0 = Sunday
        return w == 0 ? 7 : w
    }

    /// item_schema.validate_passkey_fields
    static func passkey(_ p: Obj) throws -> Obj {
        if !Set(p.keys).isSubset(of: passkeyFields) { throw reject("passkey payload contains unsupported data") }
        let rpID = casefold(pyStrip(try text(p["relying_party_id"] ?? .string(""), "relying party id", 253, allowEmpty: true)))
        if !rpID.isEmpty && !isHostname(rpID) { throw reject("relying party id must be a bare hostname") }
        let algorithm: String
        switch p["algorithm"] {
        case nil, .null?, .string("")?: algorithm = ""
        case .string(let a)? where passkeyAlgorithms.contains(a): algorithm = a
        default: throw reject("passkey algorithm is unsupported")
        }
        let discoverable = p["discoverable"] ?? .bool(true)
        guard case .bool = discoverable else { throw reject("passkey discoverable flag must be true or false") }
        func t(_ k: String, _ field: String, _ limit: Int) throws -> JSONValue {
            .string(try text(p[k] ?? .string(""), field, limit, allowEmpty: true))
        }
        return [
            "relying_party_id": .string(rpID),
            "user_handle": .string(try base64url(p["user_handle"] ?? .string(""), "user handle")),
            "credential_id": .string(try base64url(p["credential_id"] ?? .string(""), "credential id")),
            "private_key": try t("private_key", "passkey private key", 20_000),
            "algorithm": .string(algorithm),
            "created": .string(try isoDate(p["created"], "passkey created date")),
            "notes": try t("notes", "passkey notes", 20_000),
            "user_name": try t("user_name", "passkey user name", 256),
            "user_display_name": try t("user_display_name", "passkey display name", 256),
            "rp_name": try t("rp_name", "passkey site name", 256),
            "discoverable": discoverable,
            "template_id": try optionalTemplateID(p),
        ]
    }
}
