import Crypto
import Foundation

/// The parts of a login that vault health looks at.
public struct HealthLogin: Sendable, Equatable {
    public let id: String
    public let title: String
    public let password: String
    public let hasTOTP: Bool
    /// nil = unknown, never counted as old.
    public let updatedAt: Date?
    /// Every saved URL (`scope.origin`, `scope.urls[].url`), for the not-HTTPS and site feature checks.
    public let urls: [String]

    public init(id: String, title: String, password: String, hasTOTP: Bool, updatedAt: Date?, urls: [String] = []) {
        self.id = id
        self.title = title
        self.password = password
        self.hasTOTP = hasTOTP
        self.updatedAt = updatedAt
        self.urls = urls
    }
}

/// Memoises strength scores by SHA-256 of the password, so repeated health
/// computations do not re-run the estimator. Holds digests and scores only.
public final class StrengthCache: @unchecked Sendable {
    private let lock = NSLock()
    private var scores: [Data: Int] = [:]

    public init() {}

    func score(for password: String, digest: Data) -> Int {
        lock.lock()
        if let cached = scores[digest] { lock.unlock(); return cached }
        lock.unlock()
        let value = PasswordStrength.estimate(password).score
        lock.lock()
        scores[digest] = value
        lock.unlock()
        return value
    }

    /// Forgets every cached score (call on lock).
    public func removeAll() {
        lock.lock()
        scores.removeAll()
        lock.unlock()
    }
}

/// Vault-wide health, matching the desktop `vault_health` and overview score.
public struct VaultHealth: Sendable, Equatable {
    public static let oldAfter: TimeInterval = 365 * 86_400

    public let total: Int
    public let weak: Set<String>
    public let reused: Set<String>
    /// The site supports TOTP and the login has none; empty without site features.
    public let noTwoFactor: Set<String>
    /// Not part of the score; shown in the Security centre only.
    public let old: Set<String>
    public let breached: Set<String>
    /// Not part of the score: a saved URL is plain http:// on a host that is not loopback.
    public let insecure: Set<String>
    /// Not part of the score: the site supports passkeys and none is saved for its registrable domain.
    public let passkeyAvailable: Set<String>
    /// nil when there are no logins.
    public let score: Int?
    public let label: String
    /// Logins counted against the score: weak ∪ reused ∪ breached.
    public let attention: Set<String>

    public static func compute(_ logins: [HealthLogin], breached: Set<String>, now: Date,
                               cache: StrengthCache = StrengthCache(), features: SiteFeatures = .empty,
                               passkeyDomains: Set<String> = []) -> VaultHealth {
        var weak = Set<String>(), noTwoFactor = Set<String>(), old = Set<String>()
        var insecure = Set<String>(), passkeyAvailable = Set<String>()
        var byDigest: [Data: [String]] = [:]
        let ids = Set(logins.map(\.id))
        for login in logins {
            if login.password.isEmpty {
                weak.insert(login.id)
            } else {
                let digest = Data(SHA256.hash(data: Data(login.password.utf8)))
                byDigest[digest, default: []].append(login.id)
                if cache.score(for: login.password, digest: digest) <= 1 { weak.insert(login.id) }
            }
            let web = URLMatcher.webHosts(login.urls)
            if web.insecure { insecure.insert(login.id) }
            let domains: Set<String> = features.isEmpty ? [] : Set(web.hosts.compactMap { features.registrableDomain(of: $0) })
            if !login.hasTOTP, domains.contains(where: { features.supports(host: $0, feature: "totp") }) {
                noTwoFactor.insert(login.id)
            }
            if domains.contains(where: { features.supports(host: $0, feature: "passkey") && !passkeyDomains.contains($0) }) {
                passkeyAvailable.insert(login.id)
            }
            if let updated = login.updatedAt, now.timeIntervalSince(updated) > oldAfter { old.insert(login.id) }
        }
        let reused = Set(byDigest.values.filter { $0.count > 1 }.flatMap { $0 })
        let breachedLogins = breached.intersection(ids)
        let attention = weak.union(reused).union(breachedLogins)
        let total = logins.count
        let score: Int? = total == 0 ? nil
            : Int((100.0 * Double(total - attention.count) / Double(total)).rounded(.toNearestOrEven))
        let label: String
        switch score {
        case nil: label = String(localized: "No logins yet", bundle: .module)
        case let s? where s >= 80: label = String(localized: "Good", bundle: .module)
        case let s? where s >= 50: label = String(localized: "Fair", bundle: .module)
        default: label = String(localized: "Poor", bundle: .module)
        }
        return VaultHealth(total: total, weak: weak, reused: reused, noTwoFactor: noTwoFactor, old: old,
                           breached: breachedLogins, insecure: insecure, passkeyAvailable: passkeyAvailable, score: score, label: label, attention: attention)
    }

    /// The single tag shown on a row: "Breached" > "Weak" > "Reused".
    public func tag(for id: String) -> String? {
        if breached.contains(id) { return String(localized: "Breached", bundle: .module) }
        if weak.contains(id) { return String(localized: "Weak", bundle: .module) }
        if reused.contains(id) { return String(localized: "Reused", bundle: .module) }
        return nil
    }
}
