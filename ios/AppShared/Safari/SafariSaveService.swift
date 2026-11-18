import Foundation
import LGKCore

/// The App Store `pro_unlimited` entitlement as StoreKit holds it on the device (verified, not revoked).
public protocol SafariProEntitlement: Sendable {
    func isEntitled() async -> Bool
}

/// What the Safari extension's native handler asks: `classify` a login captured in Safari, or `save` it
/// into the sealed inbox for the app to import at its next unlock.
///
/// Requests and replies are plist-compatible dictionaries (they cross `SFExtensionMessageKey`):
///
/// | action | request keys | reply |
/// |---|---|---|
/// | `classify` | `origin`[, `username`, `password`] | `{"status": "new" \| "exists" \| "filled" \| "full" \| "unavailable"}` plus the site verdict |
/// | `save` | `origin`, `username`, `password`, `status`[, `lookalike_confirmed`] | `{"stored": true}` or `{"stored": false, "error": "full" \| "inbox_full" \| "invalid" \| "unavailable" \| "lookalike_site"}` |
/// | `same_site` | `origin`, `other` | `{"same": true \| false}` |
/// | `pending_count` | | `{"count": "<n>"}` (decimal) |
/// | `open_app_supported`, `open_app` | | Mac handler only (see below); `{"error": "unsupported"}` here |
/// | anything else | | `{"error": "unsupported"}` |
///
/// `pending_count` feeds the toolbar button's badge and popup: the number of logins waiting in the inbox, and
/// nothing else (no site, username or password leaves this process). It is `"0"` while an erase is pending, during
/// a duress session or hold, without the inbox key or folder, and when nothing is waiting; damaged and expired
/// blobs are not counted. It reads, never writes. `open_app_supported` (`{"supported": true | false}`, whether the
/// popup shows "Open LocalGateKeys") and `open_app` (`{"opened": true | false}`) are answered by the Mac handler
/// itself, before this service; here, so on the iPhone, both are `unsupported` and the popup hides the button.
///
/// Reply values are Strings and Bools only. `save` ignores the `status` it is sent and classifies again.
/// Keys are only read here, never created (the app creates them at unlock).
///
/// The site verdict (phishing shield, sub-plan 09; `siteVerdict`): `site` (`exact`, `related`, `lookalike` or
/// `unknown`) and `site_reason`, plus for a lookalike `site_matched` (the saved domain it imitates) and, for the same
/// name on another ending, `site_pair` (an opaque id for the extension's remembered "Same account" answer). It is
/// computed here from the sealed list of saved registrable domains (`SafariSites`, Ruling T5b), which never leaves
/// this process; a subdomain login therefore shows as related, not verified. Without the list (before the app's
/// first publish) there is no verdict here and the app checks the login when it imports it. `classify`
/// with only an origin answers the verdict and `"status": "unavailable"`. `save` on a lookalike is refused with
/// `lookalike_site` and the verdict until the extension has asked the guard question and sends
/// `lookalike_confirmed: "true"` (the desktop broker's review R1 rule).
///
/// `classify` never compares passwords (audit 2026-10-24 M-3 / L-7): it answers only whether a login with
/// that origin and username exists, and at most `SafariProbeLimit.perOrigin` times a minute per origin
/// (`unavailable` past that). `save` puts every login in the inbox, an unchanged one included; the app
/// compares the password when it imports, drops an unchanged one and asks before saving the rest.
///
/// `filled` (iPhone): an `exists` login that the AutoFill extension has just filled, so the extension shows no prompt (it
/// prompts for `new`, `exists` and `full` only). AutoFill leaves a "just filled" marker in the Safari group
/// (`SafariFillMarker`: keyed hashes and the fill time, under `safariFillKey`) for the filled login's saved origin and,
/// from a list, the page's origin; it matches either origin with the same username up to 2 minutes after the fill, and
/// once used only that origin and username, for 20 seconds more (a repeated capture of one submit). Only `exists` becomes
/// `filled`: `new`, `full` and `unavailable` never change. The marker is checked after the per-origin limit has counted
/// the request, so a marker never lets a page past that limit, and not at all during a duress session or hold or while
/// an erase is pending (those answer before the index is read). The answer never depends on the password (M-3): the
/// marker holds nothing made from one. `save` ignores it. No `safariFillKey` (before the app's first unlock with it, and on the Mac): never `filled`.
///
/// Everything it reads is in the Safari app group (audit 2026-11-10, `SafariSaveFiles`): the extension holds no other
/// group, so it never sees the vault, its settings or the duress files. What it needs from the app comes as files
/// the app writes there: the index and site list, the `plan-full` and erase-pending markers and the duress flag.
public struct SafariSaveService: Sendable {
    let keychain: any KeychainVault
    let files: @Sendable () throws -> URL
    let entitlement: any SafariProEntitlement
    let now: @Sendable () -> Int64
    let random: any RandomSource
    let matcher: URLMatcher
    /// True while a duress-password session is open or the real vault is held (sub-plan 08): the real index is
    /// never read then.
    let blocked: @Sendable () -> Bool

    /// - Parameters:
    ///   - keychain: reads `safariIndexKey`, `safariInboxKey` and, for `filled`, `safariFillKey` (the extension passes a Keychain vault
    ///     without an `LAContext`: both slots open without Face ID while the phone is unlocked).
    ///   - files: the `SafariSave` folder (`index.json`, `sites.bin`, `inbox/`, the `plan-full` marker; the
    ///     erase-pending marker beside it).
    ///   - matcher: the Public Suffix List for `same_site` (bundled in the extension, as in AutoFill).
    ///   - blocked: the duress flag the app mirrors into the Safari group (`SafariSaveService.duressBlocked`).
    public init(keychain: any KeychainVault,
                files: @escaping @Sendable () throws -> URL = { try SafariSaveFiles.directory() },
                entitlement: any SafariProEntitlement,
                now: @escaping @Sendable () -> Int64 = { SystemClock().now },
                random: any RandomSource = SystemRandomSource(),
                matcher: URLMatcher = SafariSaveService.bundledMatcher(),
                blocked: @escaping @Sendable () -> Bool = { SafariSaveService.duressBlocked() }) {
        self.keychain = keychain; self.files = files
        self.entitlement = entitlement; self.now = now; self.random = random
        self.matcher = matcher; self.blocked = blocked
    }

    /// The duress state as the app mirrors it into the Safari group (`PhoneDuress.syncMirror`): its session marker or
    /// an unfinished hold, read with `PhoneDuress`'s own rules (an unreadable hold fails closed). False without the
    /// Safari group.
    public static func duressBlocked(mirror: DuressFiles? = SafariSaveFiles.duressMirror()) -> Bool {
        guard let mirror else { return false }
        return PhoneDuress(files: mirror, session: DuressSession()).servicesBlocked()
    }

    /// An erase is pending (the marker beside `files`); also true when the folder cannot be resolved.
    func erasePending() -> Bool {
        guard let dir = try? files() else { return true }
        return FileManager.default.fileExists(atPath: SafariSaveFiles.erasePendingURL(beside: dir).path)
    }

    /// The desktop's Public Suffix List snapshot, bundled by project.yml. Missing or truncated: every host
    /// is its own registrable domain, so `same_site` answers false for different hosts (fails closed).
    public static func bundledMatcher(_ bundle: Bundle = .main) -> URLMatcher {
        let rules = bundle.url(forResource: "public_suffix_list", withExtension: "dat")
            .flatMap { try? String(contentsOf: $0, encoding: .utf8) }
            .flatMap(PublicSuffixRules.load(listText:))
        return URLMatcher(rules: rules)
    }

    /// Native statuses of `classify`.
    public enum Status: String, Sendable {
        case new
        /// A login with this origin and username is in the vault (its password may or may not differ).
        case exists
        /// `exists`, and AutoFill has just filled it on this page (`SafariFillMarker`): no prompt.
        case filled
        case full
        case unavailable
    }

    /// Errors of a refused `save`.
    public enum SaveError: String, Error, Sendable {
        case full
        case inboxFull = "inbox_full"
        case invalid
        case unavailable
    }

    /// Dispatches on `request["action"]`. Never throws: every failure is a reply.
    public func handle(_ request: [String: Any]) async -> [String: Any] {
        // Only Strings leave the dictionary, so nothing non-Sendable lives across a suspension point.
        let action = request["action"] as? String
        let origin = request["origin"] as? String
        let username = request["username"] as? String
        let password = request["password"] as? String
        let confirmed = request["lookalike_confirmed"] as? String == "true"
        switch action {
        case "same_site":
            return ["same": sameSite(origin, request["other"] as? String)]
        case "pending_count":
            return ["count": String(pendingCount())]
        case "classify":
            let status = await classify(origin: origin, username: username, password: password)
            var reply: [String: Any] = ["status": status.rawValue]
            for (key, value) in siteVerdict(origin) ?? [:] { reply[key] = value }
            return reply
        case "save":
            if !confirmed, let verdict = siteVerdict(origin), verdict["site"] == "lookalike" {
                var reply: [String: Any] = ["stored": false, "error": "lookalike_site"]
                for (key, value) in verdict { reply[key] = value }
                return reply
            }
            if let error = await save(origin: origin, username: username, password: password) {
                return ["stored": false, "error": error.rawValue]
            }
            return ["stored": true]
        default:
            return ["error": "unsupported"]
        }
    }

    /// `unavailable` when an erase is pending, the keys are missing, there is no container, the index
    /// is damaged, the origin asked too often (`SafariProbeLimit`), or the login cannot be saved at all (bad
    /// origin, empty username or password); else the index's answer, with `full` for a new login when the
    /// free vault is full. The password is checked to be present, never compared.
    public func classify(origin: String?, username: String?, password: String?) async -> Status {
        switch await evaluate(origin: origin, username: username, password: password, probe: true) {
        case .failure(.invalid), .failure(.unavailable), .failure(.inboxFull): return .unavailable
        case .failure(.full): return .full
        case .success(let c):
            switch c.status {
            case .new: return .new
            case .exists: return c.filled ? .filled : .exists
            }
        }
    }

    /// nil when stored; else why not. A login already in the vault is stored too: only the app, behind
    /// Face ID, compares its password (and drops it at import when unchanged).
    public func save(origin: String?, username: String?, password: String?) async -> SaveError? {
        let c: Classified
        switch await evaluate(origin: origin, username: username, password: password, probe: false) {
        case .failure(let e): return e
        case .success(let value): c = value
        }
        do {
            let inbox = SafariInbox(directory: c.files.appendingPathComponent(SafariInbox.directoryName, isDirectory: true),
                                    key: c.inboxKey, now: now, random: random)
            try inbox.add(origin: c.origin, username: c.username, password: c.password)
            return nil
        } catch SafariInboxError.full {
            return .inboxFull
        } catch SafariInboxError.invalid {
            return .invalid
        } catch {
            return .unavailable
        }
    }

    /// Whether a login captured on `other` may be offered on `origin` after the sign-in moved there, e.g.
    /// `https://login.paddle.com` to `https://vendors.paddle.com`: two different hosts with the same scheme
    /// and port whose registrable domains (Public Suffix List) are equal. Never across a public suffix, so
    /// two tenants of a shared hosting suffix (`a.github.io`, `b.github.io`) are not the same site; never
    /// for IP addresses. Any origin that cannot be saved answers false.
    public func sameSite(_ origin: String?, _ other: String?) -> Bool {
        guard let origin, let other, let a = Self.canonicalOrigin(origin), let b = Self.canonicalOrigin(other),
              a != b, let ua = URLComponents(string: a), let ub = URLComponents(string: b),
              ua.scheme == ub.scheme, ua.port == ub.port,
              let hostA = ua.host, let hostB = ub.host,
              let baseA = try? matcher.baseDomain(hostA), let baseB = try? matcher.baseDomain(hostB) else { return false }
        // An IP address or a host that is itself a public suffix is its own base domain, so two different
        // ones never compare equal.
        return baseA == baseB && baseA.contains(".")
    }

    /// Logins waiting in the inbox for the app's next unlock (see `pending_count` in the type doc). 0 when an erase
    /// is pending or services are blocked (checked before any key is read), or without the inbox key or folder.
    /// Damaged blobs and ones past `SafariInbox.lifetime` are not counted; nothing is deleted here. It uses
    /// `SafariInbox.count`, which never builds a username or password string.
    public func pendingCount() -> Int {
        if erasePending() || blocked() { return 0 }
        guard let key = try? keychain.read(.safariInboxKey), key.count == 32, let directory = try? files() else { return 0 }
        let inbox = SafariInbox(directory: directory.appendingPathComponent(SafariInbox.directoryName, isDirectory: true),
                                key: key, now: now, random: random)
        return inbox.count(now: now())
    }

    // MARK: site verdict

    /// The phishing-shield verdict for the page `origin` against the sealed site list (see the type doc); nil when an
    /// erase is pending, the origin is not one the extension saves for, or the index key or the list is missing or
    /// does not open (the extension then falls back to its own mixed-script check). Never counts against the
    /// per-origin limit: it reveals no username or password, and the desktop answers it the same way.
    public func siteVerdict(_ origin: String?) -> [String: String]? {
        if erasePending() { return nil }
        guard let origin, let canonical = Self.canonicalOrigin(origin),
              let key = try? keychain.read(.safariIndexKey), key.count == 32,
              let directory = try? files(),
              let blob = try? Data(contentsOf: SafariSites.url(in: directory)),
              let saved = SafariSites.open(Array(blob), indexKey: key) else { return nil }
        let lookalike = Lookalike(rules: matcher.rules)
        let verdict = lookalike.shield(canonical, saved: saved)
        var reply = ["site": verdict.kind, "site_reason": verdict.reason]
        if verdict.kind == "lookalike", let matched = verdict.matched {
            if let host = lookalike.host(matched) { reply["site_matched"] = host }
            if verdict.reason == "other-suffix" {
                reply["site_pair"] = SafariSites.pairID(indexKey: key, origin: canonical, saved: matched)
            }
        }
        AutoFillTrace.log("safari site: host=\(host: canonical) lookalike=\(verdict.kind == "lookalike")")
        return reply
    }

    // MARK: classification

    struct Classified: Sendable {
        let status: SafariLoginStatus
        /// Canonical (`Origin.canonicalize`).
        let origin: String
        let username: String
        let password: String
        let files: URL
        let inboxKey: [UInt8]
        /// `classify` only: an `exists` login AutoFill has just filled (`SafariFillMarker`).
        var filled = false
    }

    /// The shared path of `classify` and `save`: checks in the order erase pending, input, keys, files,
    /// index, the per-origin limit (`probe`, classify only), then (new logins only) the free limit.
    func evaluate(origin: String?, username: String?, password: String?, probe: Bool) async -> Result<Classified, SaveError> {
        if erasePending() { AutoFillTrace.log("safari evaluate: erase pending or no folder"); return .failure(.unavailable) }
        guard let origin, let username, let password, !username.isEmpty, !password.isEmpty,
              let canonical = Self.canonicalOrigin(origin) else {
            AutoFillTrace.log("safari evaluate: invalid host=\(host: origin) user=\(!(username ?? "").isEmpty) pass=\(!(password ?? "").isEmpty)")
            return .failure(.invalid)
        }
        let indexKey: [UInt8]?, inboxKey: [UInt8]?
        do { indexKey = try keychain.read(.safariIndexKey) } catch {
            AutoFillTrace.log("safari evaluate: index key read \(error: error)"); return .failure(.unavailable)
        }
        do { inboxKey = try keychain.read(.safariInboxKey) } catch {
            AutoFillTrace.log("safari evaluate: inbox key read \(error: error)"); return .failure(.unavailable)
        }
        guard let indexKey, indexKey.count == 32, let inboxKey, inboxKey.count == 32 else {
            AutoFillTrace.log("safari evaluate: keys missing index=\(indexKey != nil) inbox=\(inboxKey != nil)")
            return .failure(.unavailable)
        }
        let files: URL
        do { files = try self.files() } catch {
            AutoFillTrace.log("safari evaluate: files \(error: error)"); return .failure(.unavailable)
        }
        if blocked() {
            // Review I2: as for an empty index (every login new, no probe count, no free-limit answer), so nothing
            // tells which sites the held vault holds. A save still goes to the sealed inbox, reviewed at the next
            // real unlock.
            AutoFillTrace.log("safari evaluate: services blocked")
            return .success(Classified(status: .new, origin: canonical, username: username, password: password,
                                       files: files, inboxKey: inboxKey))
        }
        guard let index = Self.readIndex(in: files) else {
            AutoFillTrace.log("safari evaluate: index unreadable"); return .failure(.unavailable)
        }
        if probe, !SafariProbeLimit(directory: files, key: indexKey, now: now).allow(origin: canonical) {
            AutoFillTrace.log("safari evaluate: host=\(host: canonical) over the per-origin limit")
            return .failure(.unavailable)
        }
        AutoFillTrace.log("safari evaluate: host=\(host: canonical) entries=\(index.entries.count)")
        let status = index.classify(origin: canonical, username: username, key: indexKey)
        if status == .new, await isVaultFull(files: files) { return .failure(.full) }
        var classified = Classified(status: status, origin: canonical, username: username, password: password,
                                    files: files, inboxKey: inboxKey)
        // After the per-origin limit, and for `exists` only (see the type doc); `save` never looks.
        if probe, status == .exists {
            classified.filled = justFilled(files: files, origin: canonical, username: username)
        }
        return .success(classified)
    }

    /// Whether AutoFill has just filled this login (`SafariFillMarker.matches`). False without `safariFillKey`.
    func justFilled(files: URL, origin: String, username: String) -> Bool {
        guard let key = try? keychain.read(.safariFillKey), key.count == SafariKeys.length else { return false }
        let filled = SafariFillMarker(directory: files, key: key, now: now).matches(origin: origin, username: username)
        if filled { AutoFillTrace.log("safari evaluate: host=\(host: origin) just filled") }
        return filled
    }

    /// The published index; empty when the app has not published one yet; nil when it cannot be read
    /// or is damaged.
    static func readIndex(in files: URL) -> SafariIndex? {
        let url = SafariSaveFiles.indexURL(in: files)
        guard FileManager.default.fileExists(atPath: url.path) else { return SafariIndex(entries: []) }
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? SafariIndex.decode(Array(data))
    }

    /// Full when the app's `plan-full` marker is in `files` (the free vault was full at its last commit or unlock,
    /// with no synced licence) and StoreKit has no `pro_unlimited` (asked only then).
    func isVaultFull(files: URL) async -> Bool {
        guard FileManager.default.fileExists(atPath: SafariSaveFiles.planFullURL(in: files).path) else { return false }
        return await !entitlement.isEntitled()
    }

    /// `https:` origins, and `http:` only on `localhost` or `127.0.0.1`, canonicalised as the vault does.
    /// nil for anything else.
    static func canonicalOrigin(_ raw: String) -> String? {
        guard let parts = URLComponents(string: raw), let scheme = parts.scheme?.lowercased(),
              let host = parts.host?.lowercased(), !host.isEmpty else { return nil }
        switch scheme {
        case "https": break
        case "http": guard host == "localhost" || host == "127.0.0.1" else { return nil }
        default: return nil
        }
        guard let canonical = try? Origin.canonicalize(raw) else { return nil }
        return canonical
    }
}
