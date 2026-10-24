import Foundation
import AuthenticationServices
import AppShared

/// One credential identity as data: `ASPasswordCredentialIdentity` (username and domain) or
/// `ASPasskeyCredentialIdentity` (relying party, user name, credential id, user handle). Never a secret.
enum IdentityEntry: Equatable, Sendable {
    case password(domain: String, username: String, recordID: String)
    case passkey(rpID: String, userName: String, credentialID: Data, userHandle: Data, recordID: String)

    init(domain: String, username: String, recordID: String) {
        self = .password(domain: domain, username: username, recordID: recordID)
    }

    /// The system identity published for it; its `recordIdentifier` is the store item id that
    /// `prepareInterfaceToProvideCredential` looks up.
    var systemIdentity: any ASCredentialIdentity {
        switch self {
        case let .password(domain, username, recordID):
            ASPasswordCredentialIdentity(serviceIdentifier: ASCredentialServiceIdentifier(identifier: domain, type: .domain),
                                         user: username, recordIdentifier: recordID)
        case let .passkey(rpID, userName, credentialID, userHandle, recordID):
            ASPasskeyCredentialIdentity(relyingPartyIdentifier: rpID, userName: userName,
                                        credentialID: credentialID, userHandle: userHandle, recordIdentifier: recordID)
        }
    }

    var recordID: String {
        switch self {
        case .password(_, _, let id), .passkey(_, _, _, _, let id): id
        }
    }
}

/// The part of `ASCredentialIdentityStore` the app uses, so tests can record calls.
protocol CredentialIdentityStoring: Sendable {
    func isEnabled() async -> Bool
    func replace(_ identities: [IdentityEntry]) async throws
    func removeAll() async throws
}

struct SystemCredentialIdentityStore: CredentialIdentityStoring {
    func isEnabled() async -> Bool { await ASCredentialIdentityStore.shared.state().isEnabled }

    func replace(_ identities: [IdentityEntry]) async throws {
        let list: [any ASCredentialIdentity] = identities.map(\.systemIdentity)
        try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(list)
    }

    func removeAll() async throws { try await ASCredentialIdentityStore.shared.removeAllCredentialIdentities() }
}

/// Main app: after each sync, replaces the system's AutoFill identities with the vault's web logins.
/// The extension never runs this (it never writes anything).
struct IdentityStoreSync: Sendable {
    let identityStore: any CredentialIdentityStoring
    let matcher: URLMatcher
    /// "Show logins in the QuickType bar": when off, nothing is published and existing identities are removed.
    /// "Include exact-site logins" widens `domains` to exact-origin and host rows.
    let settings: AppSettings

    init(identityStore: any CredentialIdentityStoring = SystemCredentialIdentityStore(),
         matcher: URLMatcher = AutoFillMatcher.bundled().matcher, settings: AppSettings = .shared) {
        self.identityStore = identityStore; self.matcher = matcher; self.settings = settings
    }

    /// The domains QuickType may offer a row under. `base_domain` rows get their host and registrable
    /// domain: a QuickType fill hands the extension only the stored identity, never the page URL, and iOS
    /// matches a `.domain` identity loosely (subdomains included), which is already that row's own scope.
    /// `exact_origin` and `host` rows get their exact host only when "Include exact-site logins" is on, and
    /// only for https on the default port (never the registrable domain): iOS may then also offer them on
    /// other pages of that domain, which the user accepted by turning the switch on. Otherwise, and for
    /// every `starts_with` row, none: those logins fill only through the list path, where the extension
    /// checks the page URL.
    func domains(_ row: URLRow) -> [String] {
        guard let host = try? URLMatcher.hostOf(row.url) else { return [] }
        switch row.mode {
        case .baseDomain: return [host] + ((try? matcher.baseDomain(host)).map { [$0] } ?? [])
        case .host, .exactOrigin:
            guard settings.quickTypeExactSites, let origin = try? Origin.originOf(row.url),
                  Scalars.equal(origin, "https://" + host) else { return [] }
            return [host]
        case .startsWith: return []
        }
    }

    /// Username + domain for every live web login (`domains` per row), deduplicated by code points,
    /// ordered by item id then row.
    func identities(_ snapshot: StoreSnapshot) -> [IdentityEntry] {
        var out: [IdentityEntry] = []
        for (record, login) in AutoFillMatcher.logins(snapshot) {
            var found: [String] = []
            func add(_ d: String?) {
                guard let d, !d.isEmpty, !found.contains(where: { Scalars.equal($0, d) }) else { return }
                found.append(d)
            }
            for row in URLMatcher.entryURLs(record) { domains(row).forEach { add($0) } }
            out += found.map { IdentityEntry(domain: $0, username: login.username, recordID: login.id) }
        }
        return out
    }

    /// Relying party, user name, credential id and user handle for every live, usable passkey (never the key),
    /// ordered by item id. Empty when "Offer passkeys" is off.
    func passkeyIdentities(_ snapshot: StoreSnapshot) -> [IdentityEntry] {
        guard settings.offerPasskeys else { return [] }
        return snapshot.records.keys.sorted(by: Scalars.less).compactMap { id in
            guard snapshot.meta[id]?.deleted != true, let item = snapshot.records[id],
                  let pk = PasskeyRecord.from(item, id: id), pk.key != nil, !pk.rpID.isEmpty else { return nil }
            return .passkey(rpID: pk.rpID, userName: pk.userName, credentialID: Data(pk.credentialID),
                            userHandle: Data(pk.userHandle), recordID: pk.itemID)
        }
    }

    /// Replaces the identities when AutoFill is enabled for this app; otherwise does nothing. With QuickType
    /// turned off in Settings, or while "Erase this iPhone's vault" is pending, removes them all instead.
    func refresh(_ snapshot: StoreSnapshot) async {
        guard !settings.erasePending else { return await removeAll() }
        // An erase could not remove the old identities: retry now (only possible while AutoFill is on).
        if settings.identityRemovalPending, await identityStore.isEnabled() {
            if (try? await identityStore.removeAll()) != nil { settings.identityRemovalPending = false }
        }
        guard settings.showInQuickType else { return await removeAll() }
        guard await identityStore.isEnabled() else { return }
        let all = identities(snapshot) + passkeyIdentities(snapshot)
        do { try await identityStore.replace(all) }
        catch {
            AutoFillTrace.log("identities.replace failed error=\(error: error)")
            try? await identityStore.removeAll(); return
        }   // never leave stale identities behind
        AutoFillTrace.log("identities.replace count=\(all.count) revision=\(snapshot.revision)")
        // QuickType turned off while the replace ran: take them back out.
        if !settings.showInQuickType { await removeAll() }
    }

    /// Removes every identity this app published (QuickType turned off, or the vault erased).
    func removeAll() async { try? await identityStore.removeAll() }
}
