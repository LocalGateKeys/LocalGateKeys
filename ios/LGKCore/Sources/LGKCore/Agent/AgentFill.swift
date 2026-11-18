import Foundation

/// One login offered in the page's picker for an agent's approved sign-in (Windows `_fill_grant_browser` choices).
public struct AgentFillChoice: Equatable, Sendable {
    public let entryID: String
    public let label: String
    public let username: String
    public let favorite: Bool
    public let match: URLMatchMode
    public init(entryID: String, label: String, username: String, favorite: Bool, match: URLMatchMode) {
        self.entryID = entryID; self.label = label; self.username = username; self.favorite = favorite; self.match = match
    }
}

/// The browser side of an agent's approved sign-in on the Mac (Windows `browser_broker._fill_grant_browser`).
///
/// The Safari extension asks only after the user's own click on the LocalGateKeys icon in a sign-in field. Only an
/// armed, unexpired, unused grant whose approved hosts include the page's exact host takes effect (`takeForOrigin`
/// marks it used); the page then gets the approved logins as picker choices and an offer token, and the user picks
/// one with a second click. The password leaves the app only for that pick (`AgentReleaseBook.take`).
public enum AgentFillOffer {
    /// The approved logins this page may offer: in the grant, still allowed for agents, not strict or fill-never, no
    /// passkey for the site by now (its password is never filled for an agent), and matching the page URL. Sorted
    /// like the Windows picker: match mode, favourites first, label, user name.
    public static func choices(grant: AgentGrant, pageURL: String, vault: any AgentVault,
                               matcher: URLMatcher) -> [AgentFillChoice] {
        let passkeys = vault.passkeys()
        var choices: [AgentFillChoice] = []
        for login in vault.logins() where login.kind == "web" && grant.entryIDs.contains(login.id) {
            let record = login.record
            guard AgentText.agentsMayUse(record), AgentPolicy.usable(record) else { continue }
            var username = ""
            if case .string(let name)? = record["username"] { username = name }
            let sitePasskeys = AgentText.sitePasskeys(username: username, hosts: grant.hosts.sorted(by: AgentGate.pyLess),
                                                      domain: grant.domain, passkeys: passkeys, matcher: matcher)
            guard sitePasskeys.isEmpty else { continue }
            guard let rank = matcher.matchRank(URLMatcher.entryURLs(record), candidate: pageURL) else { continue }
            var favorite = false
            if case .bool(let flag)? = record["favorite"] { favorite = flag }
            choices.append(AgentFillChoice(entryID: login.id, label: login.title, username: username, favorite: favorite,
                                           match: URLMatchMode.allCases[rank]))
        }
        return choices.sorted { a, b in
            if a.match.rank != b.match.rank { return a.match.rank < b.match.rank }
            if a.favorite != b.favorite { return a.favorite }
            let la = Casefold.fold(a.label), lb = Casefold.fold(b.label)
            if !AgentText.pyEqual(la, lb) { return AgentGate.pyLess(la, lb) }
            return AgentGate.pyLess(Casefold.fold(a.username), Casefold.fold(b.username))
        }
    }
}

/// Offer tokens for the page's picker: one per offer, bound to the page origin and the offered logins, valid for
/// `ttl` seconds, and used up by the first pick (right or wrong). Thread-safe.
public final class AgentReleaseBook: @unchecked Sendable {
    public static let ttl: Double = 60
    public static let maxOffers = 32

    private struct Offer {
        let origin: String
        let entryIDs: Set<String>
        let expires: Double
    }

    private let clock: @Sendable () -> Double
    private let newID: @Sendable () -> String
    private let lock = NSLock()
    private var offers: [String: Offer] = [:]

    public init(clock: @escaping @Sendable () -> Double = { Date().timeIntervalSince1970 },
                newID: @escaping @Sendable () -> String = { AgentGate.randomID() }) {
        self.clock = clock
        self.newID = newID
    }

    /// The canonical origin, or nil when it is not an https origin.
    static func canonical(_ origin: String) -> String? {
        guard let value = try? Origin.canonicalize(origin), value.hasPrefix("https://") else { return nil }
        return value
    }

    /// A new token for these logins on this page; nil for a page that is not https or no logins.
    public func issue(origin: String, entryIDs: [String]) -> String? {
        guard let origin = Self.canonical(origin), !entryIDs.isEmpty else { return nil }
        lock.lock()
        defer { lock.unlock() }
        let now = clock()
        offers = offers.filter { $0.value.expires > now }
        while offers.count >= Self.maxOffers, let oldest = offers.min(by: { $0.value.expires < $1.value.expires }) {
            offers.removeValue(forKey: oldest.key)
        }
        let token = newID()
        offers[token] = Offer(origin: origin, entryIDs: Set(entryIDs), expires: now + Self.ttl)
        return token
    }

    /// The login to release for this pick, or nil. The token is used up either way.
    public func take(token: String?, entryID: String?, origin: String) -> String? {
        guard let token, let entryID, !token.isEmpty, !entryID.isEmpty else { return nil }
        lock.lock()
        let offer = offers.removeValue(forKey: token)
        lock.unlock()
        guard let offer, offer.expires > clock(), let origin = Self.canonical(origin),
              AgentText.pyEqual(origin, offer.origin), offer.entryIDs.contains(entryID) else { return nil }
        return entryID
    }
}
