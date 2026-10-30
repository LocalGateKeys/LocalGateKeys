import Foundation

/// A received item in this device's vault form. Every platform seals the stored record (the spec's shape:
/// `scope` for a login, `payload` for a typed item). Packages from early builds may carry the display shape
/// instead (top-level `urls` / `fields`); both become the desktop's stored shape (`item_schema`:
/// `scope.origin == urls[0]`, `scope.urls` rows; the typed `payload`, as Python `share.stored_form`) and then
/// pass the same `Normalise` a synced peer record passes.
extension Share {
    public static var cannotSaveHere: ShareError { ShareError("not-shareable", String(localized: "This kind of item can't be saved on this device.", bundle: .module)) }

    private static let localTrustScopeKeys = ["sign_in_selector", "embedded_web_fill_approved", "browser_approval",
                                              "browser_approvals", "sync_pairing", "pairing_secret", "pairing_state"]

    /// What only means something in one vault: linked document ids, a card's billing identity, trust approvals.
    /// Applied before sealing and again before saving.
    public static func withoutLocalRefs(_ item: [String: JSONValue]) -> [String: JSONValue] {
        var rec = item
        if case .object(var p)? = rec["payload"] {
            if p["document_ids"] != nil { p["document_ids"] = .array([]) }
            if case .string(let b)? = p["billing_address_id"], !b.isEmpty { p["billing_address_id"] = .string("") }
            rec["payload"] = .object(p)
        }
        if case .object(var s)? = rec["scope"] {
            for k in localTrustScopeKeys { s[k] = nil }
            rec["scope"] = .object(s)
        }
        return rec
    }

    /// The namespace and the normal form to store (new id, not a favourite); `cannotSaveHere` otherwise.
    public static func vaultForm(_ item: [String: JSONValue], id: String, now: Int64) throws -> (Namespace, JSONValue) {
        guard case .string(let kind)? = item["kind"] else { throw cannotSaveHere }
        var rec = withoutLocalRefs(item)
        rec["id"] = .string(id)
        rec["favorite"] = .bool(false)
        rec["updated_at"] = .int(now)
        var created: Int64 = -1
        if case .int(let n)? = rec["created_at"] { created = n }
        if created < 0 || created > now { rec["created_at"] = .int(now) }
        if rec["tags"] == nil { rec["tags"] = .array([]) }
        let ns: Namespace
        if Normalise.phoneEntryKinds.contains(kind) {
            ns = .entry
            if rec["label"] == nil, let t = rec["title"] { rec["label"] = t }
            rec["title"] = nil
            if rec["username"] == nil { rec["username"] = .string("") }
            if rec["password"] == nil { rec["password"] = .string("") }
            if let urls = rec.removeValue(forKey: "urls"), rec["scope"] == nil {
                let rows = (try? Normalise.webURLs(urls)) ?? .array([])
                var scope: [String: JSONValue] = [:]
                if case .array(let a) = rows, case .object(let first)? = a.first, case .string(let u)? = first["url"] {
                    let origin = first["match"] == .string("exact_origin") ? u : ((try? Origin.originOf(u)) ?? u)
                    scope["origin"] = .string(origin)
                    scope["urls"] = rows
                } else {
                    scope["origin"] = .string("")
                }
                rec["scope"] = .object(scope)
            }
            if rec["scope"] == nil { rec["scope"] = .object(["origin": .string("")]) }
        } else if Normalise.phoneItemKinds.contains(kind), kind != "passkey" {
            ns = .item
            if rec["title"] == nil, let l = rec["label"] { rec["title"] = l }
            rec["label"] = nil
            if let fields = rec.removeValue(forKey: "fields"), rec["payload"] == nil { rec["payload"] = fields }
            if rec["payload"] == nil { rec["payload"] = .object([:]) }
        } else {
            throw cannotSaveHere
        }
        guard let normal = try? Normalise.normalForm(ns: ns, record: .object(rec)) else { throw cannotSaveHere }
        return (ns, normal)
    }
}
