import Foundation

/// The Local Agent Gate (Windows `agent_gate.py`): per-task, user-approved access for AI agents (MCP clients).
///
/// No reply carries a password, a one-time code or a private key. An agent can list site titles and domains (after
/// the user approved that once for its session), ask for a one-use grant to sign in to one site (the user approves
/// each request; there is no "always" answer), and have the Safari extension offer that site's login when the user
/// clicks the LocalGateKeys icon on the page. The password is then written into the page, so the page, and any agent
/// that automates that browser, can read it. Logins that ask for the master password every time, logins set to never
/// fill and logins the owner did not switch to "AI agents may use this login" do not exist for an agent. A login with
/// a saved passkey for the approved site never has its password filled: the grant is a passkey grant.
///
/// Grants live five minutes, are used once, and are bound to the exact sign-in hosts and logins the user approved and
/// to the MCP session that asked. Every call is written to the access log (`agent.*` events, no content).
///
/// Thread-safe: every method may be called from any thread; approvals and waits block the calling thread (a socket
/// connection's), never the main thread. Pinned by `tests/vectors/agent/gate.json` (`AgentVectorsTests`).
public final class AgentGate: @unchecked Sendable {
    public static let grantTTL: Double = 300
    public static let armTTL: Double = 60
    public static let lockedWait: Double = 30
    public static let fillWait: Double = 60
    public static let maxPurpose = 300
    public static let maxGrants = 32
    public static let maxListed = 50
    public static let rateWindow: Double = 60
    /// Approval requests per agent session per minute.
    public static let ratePerClient = 3
    /// Approval requests from all agents per minute.
    public static let rateTotal = 10
    /// Told to the agent when this build cannot see the passkey ceremony (`passkeyOutcomes` false).
    public static let passkeyUnseenNote = "LocalGateKeys on this Mac does not see the passkey sign-in itself. Check the page to "
        + "see whether it went through; ask again with request_login if it did not."

    public struct Settings: Equatable, Sendable {
        public var agentsEnabled: Bool
        public var requireHello: Bool
        public init(agentsEnabled: Bool, requireHello: Bool) {
            self.agentsEnabled = agentsEnabled; self.requireHello = requireHello
        }
    }

    private let session: @Sendable () -> (any AgentVault)?
    private let settings: @Sendable () -> Settings
    private let confirm: @Sendable (AgentApprovalRequest) -> Bool
    private let activity: (@Sendable (String, String) -> Void)?
    private let isPro: @Sendable () -> Bool
    private let requestUnlock: (@Sendable () -> Void)?
    private let clock: @Sendable () -> Double
    private let matcher: URLMatcher
    private let newID: @Sendable () -> String
    private let lockedWait: Double
    private let fillWait: Double
    private let passkeyOutcomes: Bool
    private let waitForFinish: @Sendable (AgentGrant, Double) -> Bool

    private let lock = NSLock()
    private var grants: [(id: String, grant: AgentGrant)] = []   // insertion order, like a Python dict
    private var asked: [(at: Double, who: String)] = []
    private var asking = false
    private var listingOK: Set<String> = []

    /// - Parameters:
    ///   - session: the open vault, nil while locked.
    ///   - confirm: the user's answer in the approval view (blocking); only `true` approves.
    ///   - activity: writes one access-log event (event, result); a failure there releases or blocks nothing.
    ///   - passkeyOutcomes: false when this build cannot see the site's passkey ceremony (the Mac: the system passkey
    ///     sheet runs it through AutoFill), so `fillLogin` with a passkey grant answers at once instead of waiting.
    ///   - waitForFinish: tests replace the wait for the browser (default: the grant's own signal).
    public init(session: @escaping @Sendable () -> (any AgentVault)?, settings: @escaping @Sendable () -> Settings,
                confirm: @escaping @Sendable (AgentApprovalRequest) -> Bool,
                activity: (@Sendable (String, String) -> Void)? = nil, isPro: @escaping @Sendable () -> Bool,
                requestUnlock: (@Sendable () -> Void)? = nil,
                clock: @escaping @Sendable () -> Double = { ProcessInfo.processInfo.systemUptime },
                matcher: URLMatcher, newID: @escaping @Sendable () -> String = AgentGate.randomID,
                lockedWait: Double = AgentGate.lockedWait, fillWait: Double = AgentGate.fillWait,
                passkeyOutcomes: Bool = true,
                waitForFinish: @escaping @Sendable (AgentGrant, Double) -> Bool = { $0.signal.wait(timeout: $1) }) {
        self.session = session; self.settings = settings; self.confirm = confirm; self.activity = activity
        self.isPro = isPro; self.requestUnlock = requestUnlock; self.clock = clock; self.matcher = matcher
        self.newID = newID; self.lockedWait = lockedWait; self.fillWait = fillWait
        self.passkeyOutcomes = passkeyOutcomes; self.waitForFinish = waitForFinish
    }

    /// `secrets.token_urlsafe(18)`: 24 URL-safe characters.
    public static func randomID() -> String {
        var generator = SystemRandomNumberGenerator()
        let bytes = (0..<18).map { _ in UInt8.random(in: 0...255, using: &generator) }
        return Data(bytes).base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    // MARK: checks

    private func log(_ event: String, _ result: String) { activity?(event, result) }

    private func gate() -> AgentRefusal? {
        if !settings().agentsEnabled { return .disabled }
        if !isPro() { return .pro }
        return nil
    }

    /// The open vault, or nil after the unlock prompt went unanswered for `lockedWait` seconds.
    private func unlocked() -> (any AgentVault)? {
        if let open = session() { return open }
        requestUnlock?()
        let deadline = Date().addingTimeInterval(lockedWait)
        while Date() < deadline {
            Thread.sleep(forTimeInterval: min(0.1, max(0, deadline.timeIntervalSinceNow)))
            if let open = session() { return open }
        }
        return nil
    }

    private func ready(_ event: String) -> Result<any AgentVault, AgentRefusal> {
        if let refused = gate() {
            log(event, "denied")
            return .failure(refused)
        }
        guard let open = unlocked() else {
            log(event, "locked")
            return .failure(.locked)
        }
        return .success(open)
    }

    // MARK: vault reads (no secrets)

    /// One login an agent may use, on one registrable domain.
    struct Row {
        let id: String
        let title: String
        let domain: String
        let hosts: Set<String>
        let username: String
    }

    /// `_logins`: (id, title, registrable domain, URL hosts on it, user name) of each web login an agent may use:
    /// opted in by the owner, not strict, fill not "never". Every other login does not exist for an agent.
    func rows(_ vault: any AgentVault) -> [Row] {
        var rows: [Row] = []
        for login in vault.logins() where login.kind == "web" {
            let record = login.record
            guard AgentText.agentsMayUse(record), AgentPolicy.usable(record) else { continue }
            let urls = URLMatcher.entryURLs(record).map(\.url)
            var username = ""
            if case .string(let name)? = record["username"] { username = name }
            var byDomain: [String: Set<String>] = [:]
            for url in urls {
                guard let domain = AgentText.registrableDomain(url, matcher: matcher) else { continue }
                var hosts = byDomain[domain] ?? []
                if let host = AgentText.siteHost(url) { hosts.insert(host) }
                byDomain[domain] = hosts
            }
            for domain in byDomain.keys.sorted(by: Self.pyLess) {
                rows.append(Row(id: login.id, title: login.title, domain: domain, hosts: byDomain[domain] ?? [],
                                username: username))
            }
        }
        return rows
    }

    /// Python string order (code points).
    static func pyLess(_ a: String, _ b: String) -> Bool {
        Array(a.unicodeScalars.map(\.value)).lexicographicallyPrecedes(Array(b.unicodeScalars.map(\.value)))
    }

    // MARK: tools

    /// `list_sites`: titles and registrable domains, after the user allowed listing once for this agent session.
    public func listSites(_ client: AgentClient, query: String = "") -> Result<[AgentSite], AgentRefusal> {
        let vault: any AgentVault
        switch ready("agent.search") {
        case .failure(let refused): return .failure(refused)
        case .success(let open): vault = open
        }
        if !locked({ listingOK.contains(client.clientID) }) {
            // The list of sign-in sites is a private inventory: the user allows it once per agent session.
            guard takeTurn(client) else {
                log("agent.search", "denied")
                return .failure(.rateLimited)
            }
            defer { locked { asking = false } }
            let request = AgentApprovalRequest(action: .list, agent: Self.agentName(client), process: AgentText.clean(client.process, limit: 80),
                                               site: "", purpose: "", hello: settings().requireHello)
            guard approved(request) else {
                log("agent.search", "denied")
                return .failure(.denied)
            }
            locked { _ = listingOK.insert(client.clientID) }
        }
        let needle = Casefold.fold(AgentText.clean(query, limit: 100))
        var seen: Set<String> = []
        var out: [AgentSite] = []
        for row in rows(vault) {
            if !needle.isEmpty && !AgentText.pyContains(Casefold.fold(row.title), needle)
                && !AgentText.pyContains(row.domain, needle) { continue }
            // Python compares code points, not canonically equivalent strings.
            let key = row.title.unicodeScalars.map { String($0.value, radix: 16) }.joined(separator: ",") + "|" + row.domain
            if seen.contains(key) { continue }
            seen.insert(key)
            out.append(AgentSite(title: row.title, domain: row.domain))
            if out.count >= Self.maxListed { break }
        }
        log("agent.search", "ok")
        return .success(out)
    }

    /// `request_login`: one approval, then a grant for the exact sign-in hosts and logins shown in it.
    public func requestLogin(_ client: AgentClient, site: String?, purpose: String?) -> Result<AgentGrant, AgentRefusal> {
        guard let domain = AgentText.registrableDomain(site, matcher: matcher), let host = AgentText.siteHost(site) else {
            log("agent.request", "failed")
            return .failure(.invalid)
        }
        let vault: any AgentVault
        switch ready("agent.request") {
        case .failure(let refused): return .failure(refused)
        case .success(let open): vault = open
        }
        var matches = rows(vault).filter { $0.domain == domain }
        var hosts: Set<String>
        if host != domain {
            // A named sign-in host: only that host, and only logins saved for it (or for the bare domain).
            matches = matches.filter { $0.hosts.contains(host) || $0.hosts.contains(domain) }
            hosts = [host]
        } else {
            // A bare domain: the exact hosts the matching logins are saved for, never any other host on it.
            hosts = matches.reduce(into: Set<String>()) { $0.formUnion($1.hosts) }
            if hosts.contains(domain) { hosts.insert("www." + domain) }
        }
        if matches.isEmpty || hosts.isEmpty {
            log("agent.request", "not_found")
            return .failure(.notFound)
        }
        // A saved passkey for these hosts makes this a passkey grant: no password of the site is filled for an agent.
        let passkeys = vault.passkeys()
        let passkeyIDs = matches.reduce(into: Set<String>()) { ids, row in
            ids.formUnion(AgentText.sitePasskeys(username: row.username, hosts: Array(hosts), domain: domain,
                                                 passkeys: passkeys, matcher: matcher))
        }
        guard takeTurn(client) else {
            log("agent.request", "denied")
            return .failure(.rateLimited)
        }
        defer { locked { asking = false } }
        return askAndGrant(client, domain: domain, purpose: purpose, hosts: hosts,
                           entryIDs: Set(matches.map(\.id)), passkeyIDs: passkeyIDs)
    }

    /// One approval on screen at a time, and at most a few per minute: an agent cannot flood the user.
    private func takeTurn(_ client: AgentClient) -> Bool {
        let now = clock()
        return locked {
            asked = asked.filter { now - $0.at < Self.rateWindow }
            let mine = asked.filter { $0.who == client.clientID }.count
            if asking || mine >= Self.ratePerClient || asked.count >= Self.rateTotal { return false }
            asked.append((now, client.clientID))
            asking = true
            return true
        }
    }

    static func agentName(_ client: AgentClient) -> String {
        let name = AgentText.clean(client.name, limit: 80)
        return name.isEmpty ? "MCP client" : name
    }

    private func askAndGrant(_ client: AgentClient, domain: String, purpose: String?, hosts: Set<String>,
                             entryIDs: Set<String>, passkeyIDs: Set<String>) -> Result<AgentGrant, AgentRefusal> {
        var shown = hosts.sorted(by: Self.pyLess).joined(separator: ", ")
        if Normalise.len(shown) > AgentText.maxSite {
            shown = AgentText.prefix(shown, AgentText.maxSite - 1) + "\u{2026}"
        }
        let request = AgentApprovalRequest(action: .signIn, agent: Self.agentName(client),
                                           process: AgentText.clean(client.process, limit: 80), site: shown,
                                           purpose: AgentText.clean(purpose, limit: Self.maxPurpose),
                                           hello: settings().requireHello,
                                           method: passkeyIDs.isEmpty ? .password : .passkey)
        guard approved(request) else {
            log("agent.request", "denied")
            return .failure(.denied)
        }
        let expires = clock() + Self.grantTTL
        let grant = AgentGrant(id: newID(), domain: domain, clientID: client.clientID, expires: expires, hosts: hosts,
                               entryIDs: entryIDs, passkeyIDs: passkeyIDs)
        if !passkeyIDs.isEmpty {
            // The site's own passkey sign-in starts the ceremony, so a passkey grant is armed for its whole life; the
            // owner's passkey dialog and verification still decide.
            grant.armedUntil = expires
        }
        locked {
            expire()
            grants.append((grant.id, grant))
            while grants.count > Self.maxGrants { grants.removeFirst() }
        }
        log("agent.request", "ok")
        return .success(grant)
    }

    /// The only way to approve: the user's answer in the approval view. A failure or timeout is a no.
    private func approved(_ request: AgentApprovalRequest) -> Bool { confirm(request) }

    // MARK: grants

    /// Caller holds the lock.
    private func expire() {
        let now = clock()
        grants.removeAll { $0.grant.expires <= now }
    }

    private func owned(_ client: AgentClient, _ grantID: String?) -> Result<AgentGrant, AgentRefusal> {
        guard let grantID else { return .failure(.invalid) }
        return locked {
            guard let index = grants.firstIndex(where: { $0.id == grantID }) else { return .failure(.expired) }
            let grant = grants[index].grant
            if grant.clientID != client.clientID { return .failure(.notYours) }
            if grant.expires <= clock() {
                grants.remove(at: index)
                return .failure(.expired)
            }
            if !grant.passkeyIDs.isEmpty { return .success(grant) }   // armed since approval
            if grant.used || grant.armedUntil != 0 { return .failure(.used) }
            return .success(grant)
        }
    }

    /// `fill_login`: arm the grant for the Safari extension and wait until the sign-in page takes it. The extension
    /// asks (`takeForOrigin`) only when the user clicks the LocalGateKeys icon in a sign-in field on an approved host;
    /// the user then picks the login in the picker. A passkey grant fills nothing: it waits for the site's passkey
    /// sign-in and reports whether it went through.
    public func fillLogin(_ client: AgentClient, grant grantID: String?, tabHint: String = "") -> Result<AgentFillResult, AgentRefusal> {
        if let refused = gate() {
            log("agent.fill", "denied")
            return .failure(refused)
        }
        let grant: AgentGrant
        switch owned(client, grantID) {
        case .failure(let refused):
            log("agent.fill", "denied")
            return .failure(refused)
        case .success(let found): grant = found
        }
        if !grant.passkeyIDs.isEmpty {
            if !passkeyOutcomes {
                log("agent.fill", "open")
                return .success(AgentFillResult(filled: false, site: grant.domain, method: .passkey, note: Self.passkeyUnseenNote))
            }
            guard waitForFinish(grant, fillWait) else {
                log("agent.fill", "skipped")
                return .failure(.noPasskey)
            }
            let signed = locked { grant.outcome == "passkey" }
            log("agent.fill", signed ? "ok" : "open")
            return .success(AgentFillResult(filled: signed, site: grant.domain, method: .passkey,
                                            note: signed ? nil : "The passkey sign-in did not complete. Ask again with request_login."))
        }
        locked { grant.armedUntil = min(grant.expires, clock() + Self.armTTL) }
        if !waitForFinish(grant, fillWait) {
            let used = locked { () -> Bool in
                if !grant.used { grant.armedUntil = 0 }   // unarmed again: the agent may retry with the same grant
                return grant.used
            }
            if !used {
                log("agent.fill", "skipped")
                return .failure(.noTab)
            }
        }
        let filled = locked { grant.outcome == "filled" }
        log("agent.fill", filled ? "ok" : "open")
        return .success(AgentFillResult(filled: filled, site: grant.domain, method: .password,
                                        note: filled ? nil : "The user picks the login on the page."))
    }

    /// (registrable domain, exact host) of an https page, or nil when agents are off, Pro ended or the origin does
    /// not qualify.
    private func page(_ origin: String) -> (domain: String, host: String?)? {
        guard gate() == nil, let domain = AgentText.originDomain(origin, matcher: matcher) else { return nil }
        let host = (try? Origin.canonicalize(origin)).flatMap(AgentText.siteHost)
        return (domain, host)
    }

    /// Armed, unused, unexpired grants of one kind whose approved hosts include this page's exact host. Caller holds
    /// the lock.
    private func armed(for page: (domain: String, host: String?), passkey: Bool) -> [AgentGrant] {
        let now = clock()
        return grants.map { $0.grant }.filter { grant in
            grant.domain == page.domain && page.host.map(grant.hosts.contains) == true && !grant.used
                && grant.armedUntil > now && grant.expires > now && grant.passkeyIDs.isEmpty != passkey
        }
    }

    /// The extension's side: the armed password grant whose approved hosts include this page's exact host, marked
    /// used. A passkey grant is never handed out here. Nothing is handed out when agent access was turned off, or Pro
    /// ended, after the grant was approved.
    public func takeForOrigin(_ origin: String) -> AgentGrant? {
        guard let page = page(origin) else { return nil }
        return locked {
            guard let grant = armed(for: page, passkey: false).first else { return nil }
            grant.used = true
            return grant
        }
    }

    /// Whether a passkey grant waits for this page's passkey sign-in.
    public func passkeyPending(_ origin: String) -> Bool {
        guard let page = page(origin) else { return false }
        return locked { !armed(for: page, passkey: true).isEmpty }
    }

    /// The passkey side: the passkey grant for this page whose passkeys include one of the offered credentials, marked
    /// used (one assertion).
    public func takePasskeyForOrigin(_ origin: String, credentialIDs: [String]) -> AgentGrant? {
        guard let page = page(origin) else { return nil }
        let offered = Set(credentialIDs)
        return locked {
            guard let grant = armed(for: page, passkey: true).first(where: { !$0.passkeyIDs.isDisjoint(with: offered) }) else {
                return nil
            }
            grant.used = true
            return grant
        }
    }

    /// The live grant with this id (tests and the app's own bookkeeping); nil once expired or dropped.
    func grant(_ id: String) -> AgentGrant? { locked { grants.first(where: { $0.id == id })?.grant } }

    /// `filled` (one login, filled at once), `picker` (the user chooses on the page), `passkey` (the page received a
    /// passkey assertion) or `none` (nothing was offered or signed).
    public func finish(_ grant: AgentGrant, outcome: String) {
        locked { grant.outcome = outcome }
        grant.signal.set()
    }
}

/// `normalized_policy` as the gate reads it: usable unless it asks for the master password every time (any stored
/// `require_master_password` other than `false`, unknown = strictest) or never fills (a malformed `fill` counts as never).
public enum AgentPolicy {
    public static func usable(_ record: [String: JSONValue]) -> Bool {
        var policy: [String: JSONValue] = [:]
        if case .object(let raw)? = record["policy"] { policy = raw }
        if AccessRules.requiresMasterPassword(record) { return false }
        let fill = policy["fill"] ?? .string("click")
        return fill == .string("click")
    }
}

/// What the gate reads from the open vault: logins (as stored records) and passkey names. Never key material.
public protocol AgentVault: Sendable {
    func logins() -> [AgentLoginRecord]
    func passkeys() -> [AgentPasskey]
}

/// One item of the vault as the gate sees it: id, title, kind and the stored record (scope, policy, username).
public struct AgentLoginRecord: Sendable {
    public let id: String
    public let title: String
    public let kind: String
    public let record: [String: JSONValue]
    public init(id: String, title: String, kind: String, record: [String: JSONValue]) {
        self.id = id; self.title = title; self.kind = kind; self.record = record
    }
}

/// Who is asking: the MCP session (one per `lgk mcp` process, with the peer's pid), its client name and its program.
public struct AgentClient: Equatable, Sendable {
    public let clientID: String
    public let name: String
    public let process: String
    public init(clientID: String, name: String, process: String) {
        self.clientID = clientID; self.name = name; self.process = process
    }
}

public struct AgentSite: Equatable, Sendable {
    public let title: String
    public let domain: String
    public init(title: String, domain: String) { self.title = title; self.domain = domain }
}

public enum AgentMethod: String, Sendable { case password, passkey }

/// The answer to `fill_login` (never a value).
public struct AgentFillResult: Equatable, Sendable {
    public let filled: Bool
    public let site: String
    public let method: AgentMethod
    public let note: String?
}

public enum AgentRefusal: String, Error, Sendable, CaseIterable {
    case disabled, pro, locked, invalid, denied, expired, used
    case notFound = "not_found", notYours = "not_yours", rateLimited = "rate_limited", noTab = "no_tab"
    case noPasskey = "no_passkey"
}

/// What the approval view shows. Every field is plain text, shown as text, never markup; `purpose` is a quote.
public struct AgentApprovalRequest: Equatable, Sendable {
    public enum Action: String, Sendable { case list, signIn = "sign_in" }
    public let action: Action
    public let agent: String
    public let process: String
    public let site: String
    public let purpose: String
    public let hello: Bool
    public let method: AgentMethod
    public init(action: Action, agent: String, process: String, site: String, purpose: String, hello: Bool,
                method: AgentMethod = .password) {
        self.action = action; self.agent = agent; self.process = process; self.site = site; self.purpose = purpose
        self.hello = hello; self.method = method
    }
}

/// One grant. Its mutable state is changed only under the gate's lock.
public final class AgentGrant: @unchecked Sendable {
    public let id: String
    public let domain: String
    public let clientID: String
    public let expires: Double
    /// The exact page hosts the grant is good for.
    public let hosts: Set<String>
    /// The logins the user approved.
    public let entryIDs: Set<String>
    /// Credential ids of the approved logins' passkeys for the site. Non-empty: a passkey grant, never a password fill.
    public let passkeyIDs: Set<String>
    var used = false
    var armedUntil: Double = 0
    var outcome = ""
    /// Set by `finish`; `fillLogin` waits on it.
    public let signal = AgentSignal()

    init(id: String, domain: String, clientID: String, expires: Double, hosts: Set<String>, entryIDs: Set<String>,
         passkeyIDs: Set<String>) {
        self.id = id; self.domain = domain; self.clientID = clientID; self.expires = expires; self.hosts = hosts
        self.entryIDs = entryIDs; self.passkeyIDs = passkeyIDs
    }

    public var method: AgentMethod { passkeyIDs.isEmpty ? .password : .passkey }
}

/// `threading.Event`: set once, waited on by any number of threads.
public final class AgentSignal: @unchecked Sendable {
    private let condition = NSCondition()
    private var flag = false

    public init() {}

    public var isSet: Bool {
        condition.lock()
        defer { condition.unlock() }
        return flag
    }

    public func set() {
        condition.lock()
        flag = true
        condition.broadcast()
        condition.unlock()
    }

    /// True once set; false when `timeout` seconds pass first.
    public func wait(timeout: Double) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        let deadline = Date().addingTimeInterval(max(0, timeout))
        while !flag {
            if !condition.wait(until: deadline) { return flag }
        }
        return true
    }
}
