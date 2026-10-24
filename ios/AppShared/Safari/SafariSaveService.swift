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
/// | `classify` | `origin`, `username`, `password` | `{"status": "new" \| "exists" \| "full" \| "unavailable"}` |
/// | `save` | `origin`, `username`, `password`, `status` | `{"stored": true}` or `{"stored": false, "error": "full" \| "inbox_full" \| "invalid" \| "unavailable"}` |
/// | `same_site` | `origin`, `other` | `{"same": true \| false}` |
/// | anything else | | `{"error": "unsupported"}` |
///
/// Reply values are Strings and Bools only. `save` ignores the `status` it is sent and classifies again.
/// Keys are only read here, never created (the app creates them at unlock).
///
/// `classify` never compares passwords (audit 2026-10-24 M-3 / L-7): it answers only whether a login with
/// that origin and username exists, and at most `SafariProbeLimit.perOrigin` times a minute per origin
/// (`unavailable` past that). `save` puts every login in the inbox, an unchanged one included; the app
/// compares the password when it imports, drops an unchanged one and asks before saving the rest.
public struct SafariSaveService: Sendable {
    let keychain: any KeychainVault
    let files: @Sendable () throws -> URL
    let vaultDirectory: @Sendable () throws -> URL
    let settings: AppSettings
    let entitlement: any SafariProEntitlement
    let now: @Sendable () -> Int64
    let random: any RandomSource
    let matcher: URLMatcher

    /// - Parameters:
    ///   - keychain: reads `safariIndexKey` and `safariInboxKey` (the extension passes a Keychain vault
    ///     without an `LAContext`: both slots open without Face ID while the phone is unlocked).
    ///   - files: the `SafariSave` folder (`index.json`, `inbox/`).
    ///   - vaultDirectory: the `LocalStore` folder, for its plain committed revision.
    ///   - matcher: the Public Suffix List for `same_site` (bundled in the extension, as in AutoFill).
    public init(keychain: any KeychainVault,
                files: @escaping @Sendable () throws -> URL = { try SafariSaveFiles.directory() },
                vaultDirectory: @escaping @Sendable () throws -> URL = { try AppGroup.vaultDirectory() },
                settings: AppSettings,
                entitlement: any SafariProEntitlement,
                now: @escaping @Sendable () -> Int64 = { SystemClock().now },
                random: any RandomSource = SystemRandomSource(),
                matcher: URLMatcher = SafariSaveService.bundledMatcher()) {
        self.keychain = keychain; self.files = files; self.vaultDirectory = vaultDirectory
        self.settings = settings; self.entitlement = entitlement; self.now = now; self.random = random
        self.matcher = matcher
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
        switch action {
        case "same_site":
            return ["same": sameSite(origin, request["other"] as? String)]
        case "classify":
            let status = await classify(origin: origin, username: username, password: password)
            return ["status": status.rawValue]
        case "save":
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
            case .exists: return .exists
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

    // MARK: classification

    struct Classified: Sendable {
        let status: SafariLoginStatus
        /// Canonical (`Origin.canonicalize`).
        let origin: String
        let username: String
        let password: String
        let files: URL
        let inboxKey: [UInt8]
    }

    /// The shared path of `classify` and `save`: checks in the order erase pending, input, keys, files,
    /// index, the per-origin limit (`probe`, classify only), then (new logins only) the free limit.
    func evaluate(origin: String?, username: String?, password: String?, probe: Bool) async -> Result<Classified, SaveError> {
        if settings.erasePending { AutoFillTrace.log("safari evaluate: erase pending"); return .failure(.unavailable) }
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
        guard let index = Self.readIndex(in: files) else {
            AutoFillTrace.log("safari evaluate: index unreadable"); return .failure(.unavailable)
        }
        if probe, !SafariProbeLimit(directory: files, key: indexKey, now: now).allow(origin: canonical) {
            AutoFillTrace.log("safari evaluate: host=\(host: canonical) over the per-origin limit")
            return .failure(.unavailable)
        }
        AutoFillTrace.log("safari evaluate: host=\(host: canonical) entries=\(index.entries.count)")
        let status = index.classify(origin: canonical, username: username, key: indexKey)
        if status == .new, await isVaultFull() { return .failure(.full) }
        return .success(Classified(status: status, origin: canonical, username: username, password: password,
                                   files: files, inboxKey: inboxKey))
    }

    /// The published index; empty when the app has not published one yet; nil when it cannot be read
    /// or is damaged.
    static func readIndex(in files: URL) -> SafariIndex? {
        let url = SafariSaveFiles.indexURL(in: files)
        guard FileManager.default.fileExists(atPath: url.path) else { return SafariIndex(entries: []) }
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? SafariIndex.decode(Array(data))
    }

    /// Full when the hint names the committed revision and StoreKit has no `pro_unlimited` (asked only then).
    func isVaultFull() async -> Bool {
        guard let hinted = settings.planFullRevision,
              let directory = try? self.vaultDirectory(),
              LocalStore.committedRevision(directory: directory) == hinted else { return false }
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
