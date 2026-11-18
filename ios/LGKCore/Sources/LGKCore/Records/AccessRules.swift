import Foundation

/// Per-login access rules (feature pack contract §4): the synced `scope.access` object of a `web` login
/// (`{"copy": "once", "phones": "view", "expires": "2027-03-31"}`) read together with the existing `policy`
/// (`require_master_password`, `fill`). Unknown keys or values read as the strictest rule. Typed items have none.
public enum AccessRules {
    public static let scopeKey = "access"
    public static let knownKeys: Set<String> = ["copy", "phones", "expires"]

    public enum DeviceClass: String, Sendable { case phone, computer }

    /// `effective(record, device_class, today)`.
    public struct Effective: Equatable, Sendable {
        /// Strict re-authentication on every reveal, copy and fill.
        public var reauth: Bool
        /// May be autofilled (and published to the system's AutoFill suggestions).
        public var autofill: Bool
        /// Copy once per unlock, then confirm again.
        public var copyOnce: Bool
        /// View only on phones (reveal with system auth; copy, autofill, share, export refused).
        public var phoneView: Bool
        /// The `expires` date has come (or is malformed): shown as an "expired" banner.
        public var expired: Bool
        /// The rule holds a key from a newer version, so every rule is on.
        public var unknownRule: Bool
        /// The date the rule expired on, when it is a valid date (for the banner).
        public var expiresOn: String?

        public init(reauth: Bool, autofill: Bool, copyOnce: Bool, phoneView: Bool, expired: Bool,
                    unknownRule: Bool = false, expiresOn: String? = nil) {
            self.reauth = reauth; self.autofill = autofill; self.copyOnce = copyOnce; self.phoneView = phoneView
            self.expired = expired; self.unknownRule = unknownRule; self.expiresOn = expiresOn
        }

        /// No rule at all.
        public static let open = Effective(reauth: false, autofill: true, copyOnce: false, phoneView: false, expired: false)

        /// True when any rule changes what the app may do (the agent gate and export treat such a login as ruled).
        public var anyRule: Bool { reauth || !autofill || copyOnce || phoneView || expired }

        /// On this device class: copying, sharing and exporting are refused (view only on a phone).
        public func refusesCopy(on device: DeviceClass) -> Bool { phoneView && device == .phone }
    }

    /// The rules of `record` on `device` at `today` (`YYYY-MM-DD`, the device's local date).
    public static func effective(_ record: [String: JSONValue], device: DeviceClass, today: String) -> Effective {
        let strictPolicy = requiresMasterPassword(record)
        let fillClick = !fillNever(record)
        var copyOnce = false, phoneView = false, expired = false, unknown = false
        var expiresOn: String?
        let scope: [String: JSONValue] = if case .object(let s)? = record["scope"] { s } else { [:] }
        if let raw = scope[scopeKey] {
            if case .object(let access) = raw, Set(access.keys).isSubset(of: knownKeys) {
                if let c = access["copy"] { copyOnce = c != .string("normal") }
                if let p = access["phones"] { phoneView = p != .string("full") }
                if let e = access["expires"], e != .string("") {
                    if case .string(let date) = e, isDashDate(date) {
                        expiresOn = date
                        expired = !scalarOrder(today, date)   // today >= date
                    } else {
                        expired = true
                    }
                }
            } else {
                unknown = true
            }
        }
        if unknown {
            return Effective(reauth: true, autofill: false, copyOnce: true, phoneView: true, expired: false, unknownRule: true)
        }
        let reauth = strictPolicy || expired
        let autofill = fillClick && !expired && !(phoneView && device == .phone)
        return Effective(reauth: reauth, autofill: autofill, copyOnce: copyOnce, phoneView: phoneView, expired: expired,
                         expiresOn: expiresOn)
    }

    /// Strict `YYYY-MM-DD` naming a real day (`Normalise.isoDate` rules, dash form only).
    public static func isDashDate(_ s: String) -> Bool { LocalData.isISODate(s) }

    /// `policy.require_master_password` read with "unknown = strictest" (scan 2026-11-15 A-L1): any stored value other
    /// than `false` asks every time (records from other devices are stored verbatim, so a non-boolean can arrive).
    public static func requiresMasterPassword(_ record: [String: JSONValue]) -> Bool {
        guard case .object(let p)? = record["policy"], let value = p["require_master_password"] else { return false }
        return value != .bool(false)
    }

    /// `policy.fill` is anything but `"click"` (the normaliser reads an unknown value as `"never"`).
    public static func fillNever(_ record: [String: JSONValue]) -> Bool {
        guard case .object(let p) = Normalise.policy(record["policy"]) else { return true }
        return p["fill"] != .string("click")
    }

    // MARK: - Loosening

    /// True when `new` weakens a protection `old` has (scan 2026-11-15 W-M3, S-M3, A-M2): `require_master_password` or
    /// `fill: never` turned off; copy once or view only on phones removed; the expiry removed or moved later; or a rule
    /// from a newer version (an `access` that is not an object, or holds unknown keys) replaced by one this build reads.
    /// Every such change needs the owner check (strict, no grace) first, whether it comes from a rules editor or from
    /// restoring a field of an earlier version. Tightening never does. Works on whole records, so any path counts.
    public static func loosens(from old: [String: JSONValue], to new: [String: JSONValue]) -> Bool {
        if requiresMasterPassword(old) && !requiresMasterPassword(new) { return true }
        if fillNever(old) && !fillNever(new) { return true }
        func access(_ r: [String: JSONValue]) -> JSONValue? {
            if case .object(let scope)? = r["scope"] { return scope[scopeKey] }
            return nil
        }
        /// nil for a value that reads as all rules on (not an object, or an unknown key).
        func known(_ v: JSONValue) -> [String: JSONValue]? {
            if case .object(let o) = v, Set(o.keys).isSubset(of: knownKeys) { return o }
            return nil
        }
        guard let oldValue = access(old) else { return false }   // no rule before: nothing to loosen
        let newValue = access(new)
        if let newValue, known(newValue) == nil { return false }  // all rules on after
        guard let o = known(oldValue) else { return true }        // all rules on before, fewer after
        let n: [String: JSONValue] = newValue.flatMap(known) ?? [:]
        func on(_ v: JSONValue?, normal: String) -> Bool { v != nil && v != .string(normal) }
        if on(o["copy"], normal: "normal") && !on(n["copy"], normal: "normal") { return true }
        if on(o["phones"], normal: "full") && !on(n["phones"], normal: "full") { return true }
        let oldExpiry = o["expires"], newExpiry = n["expires"]
        let oldSet = oldExpiry != nil && oldExpiry != .string("")
        // The old expiry is strictly the stricter one: the new one is none, later, or a valid date after a malformed one.
        return oldSet && oldExpiry != newExpiry && earlierExpiry(oldExpiry, newExpiry) == oldExpiry
    }

    // MARK: - Writing

    /// The settings a person edits. `expires` "" means none.
    public struct Settings: Equatable, Sendable {
        public var copyOnce: Bool
        public var phonesView: Bool
        public var expires: String
        public init(copyOnce: Bool = false, phonesView: Bool = false, expires: String = "") {
            self.copyOnce = copyOnce; self.phonesView = phonesView; self.expires = expires
        }
    }

    /// The known settings read from a stored `scope.access` (unknown keys are not settings; they are kept on write).
    public static func settings(of scope: [String: JSONValue]) -> Settings {
        guard case .object(let a)? = scope[scopeKey] else { return Settings() }
        let expires: String = if case .string(let e)? = a["expires"] { e } else { "" }
        return Settings(copyOnce: a["copy"] != nil && a["copy"] != .string("normal"),
                        phonesView: a["phones"] != nil && a["phones"] != .string("full"), expires: expires)
    }

    /// `scope` with `settings` written in the write form: only non-default keys, an empty `access` removed. Keys this
    /// build does not know are kept byte for byte; an `access` that is not an object is replaced only when `settings`
    /// differ from what it reads as (all rules on).
    public static func writing(_ settings: Settings, into scope: [String: JSONValue]) throws -> [String: JSONValue] {
        if !settings.expires.isEmpty, !isDashDate(settings.expires) { throw NormaliseError.rejected("access expiry is not a date") }
        var access: [String: JSONValue] = if case .object(let a)? = scope[scopeKey] { a } else { [:] }
        access["copy"] = settings.copyOnce ? .string("once") : nil
        access["phones"] = settings.phonesView ? .string("view") : nil
        access["expires"] = settings.expires.isEmpty ? nil : .string(settings.expires)
        var out = scope
        out[scopeKey] = access.isEmpty ? nil : .object(access)
        return out
    }

    /// True when `new` sets or tightens any rule compared with `old` (needs Pro); loosening or removing never does.
    public static func tightens(from old: Settings, to new: Settings) -> Bool {
        if new.copyOnce && !old.copyOnce { return true }
        if new.phonesView && !old.phonesView { return true }
        if !new.expires.isEmpty && (old.expires.isEmpty || scalarOrder(new.expires, old.expires)) { return true }
        return false
    }

    // MARK: - Merge "stricter"

    /// The stricter of two `scope.access` values (nil = absent): per key the stricter value, `expires` the earlier
    /// date (a malformed date counts as expired now, so it wins). Unknown keys of both are kept (first `a`'s value).
    /// A value that is not an object reads as all rules on, so it is kept as is. nil when both are absent or empty.
    public static func stricter(_ a: JSONValue?, _ b: JSONValue?) -> JSONValue? {
        func obj(_ v: JSONValue?) -> [String: JSONValue]?? {
            guard let v, v != .null else { return .some(nil) }   // JSON null is absent (desktop `None`)
            if case .object(let o) = v { return .some(o) }
            return nil   // not an object
        }
        guard let oa = obj(a) else { return a }
        guard let ob = obj(b) else { return b }
        let x = oa ?? [:], y = ob ?? [:]
        var out: [String: JSONValue] = [:]
        for (k, v) in y where !knownKeys.contains(k) { out[k] = v }
        for (k, v) in x where !knownKeys.contains(k) { out[k] = v }
        func strictOnce(_ v: JSONValue?, normal: String) -> Bool { v != nil && v != .string(normal) }
        if strictOnce(x["copy"], normal: "normal") || strictOnce(y["copy"], normal: "normal") {
            out["copy"] = strictOnce(x["copy"], normal: "normal") ? x["copy"] : y["copy"]
        }
        if strictOnce(x["phones"], normal: "full") || strictOnce(y["phones"], normal: "full") {
            out["phones"] = strictOnce(x["phones"], normal: "full") ? x["phones"] : y["phones"]
        }
        if let e = earlierExpiry(x["expires"], y["expires"]) { out["expires"] = e }
        return out.isEmpty ? nil : .object(out)
    }

    /// The stricter `expires`: none ("" or absent) loses to any date; a malformed value wins over a date.
    static func earlierExpiry(_ a: JSONValue?, _ b: JSONValue?) -> JSONValue? {
        func set(_ v: JSONValue?) -> Bool { v != nil && v != .string("") }
        switch (set(a), set(b)) {
        case (false, false): return nil
        case (true, false): return a
        case (false, true): return b
        case (true, true):
            guard case .string(let da)? = a, isDashDate(da) else { return a }
            guard case .string(let db)? = b, isDashDate(db) else { return b }
            return scalarOrder(db, da) ? b : a
        }
    }

    /// The keeper's `policy` (`a`) tightened by `b` for a merge (Python `stricter_policy`): `fill` never if `b`'s is,
    /// `require_master_password` if either sets it (a non-boolean value of the keeper's is strict and becomes true);
    /// the keeper's other keys stay as they are. Nil when neither is an object: the merge then leaves `policy` out.
    public static func stricterPolicy(_ a: JSONValue?, _ b: JSONValue?) -> JSONValue? {
        let aIsObject: Bool = if case .object(_)? = a { true } else { false }
        let bIsObject: Bool = if case .object(_)? = b { true } else { false }
        guard aIsObject || bIsObject else { return nil }
        var out: [String: JSONValue] = if case .object(let o)? = a { o } else { [:] }
        if let value = out["require_master_password"], value != .bool(false) { out["require_master_password"] = .bool(true) }
        if bIsObject, case .object(let other) = Normalise.policy(b) {
            if other["fill"] == .string("never") { out["fill"] = .string("never") }
            if other["require_master_password"] == .bool(true) { out["require_master_password"] = .bool(true) }
        }
        return aIsObject || !out.isEmpty ? .object(out) : nil
    }
}
