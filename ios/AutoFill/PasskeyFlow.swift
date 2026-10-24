import Foundation
import AppShared

/// What the extension hands back for a passkey sign-in (`ASPasskeyAssertionCredential`). No key material.
struct PasskeyAssertion: Equatable, Sendable {
    let userHandle: Data
    let rpID: String
    let signature: Data
    let clientDataHash: Data
    let authenticatorData: Data
    let credentialID: Data
}

/// A row of the passkey list: what the user picks from. No key material (only `assert` loads the key).
struct PasskeyCandidate: Equatable, Sendable {
    let itemID: String
    let title: String
    let rpID: String
    let userName: String
    let credentialID: Data
}

/// What iOS asked to create (`ASPasskeyCredentialRequest` for registration), as plain data.
struct PasskeyRegistrationRequest: Equatable, Sendable {
    let rpID: String
    let rpName: String
    let userName: String
    let userDisplayName: String
    let userHandle: Data
    let clientDataHash: Data
    /// COSE algorithm identifiers the site accepts (ES256 = -7).
    let algorithms: [Int]
}

/// What the extension hands back for a passkey creation (`ASPasskeyRegistrationCredential`). No key material.
struct PasskeyRegistration: Equatable, Sendable {
    let rpID: String
    let clientDataHash: Data
    let credentialID: Data
    let attestationObject: Data
}

/// The App Store `pro_unlimited` entitlement, read locally (`Transaction.currentEntitlements`).
protocol ProEntitlementChecking: Sendable {
    func isEntitled() async -> Bool
}

/// No StoreKit (tests' default): only a synced licence counts.
struct NoEntitlement: ProEntitlementChecking { func isEntitled() async -> Bool { false } }

/// Republishes the AutoFill identities from a committed snapshot (`IdentityStoreSync.refresh`).
protocol PasskeyIdentityRefreshing: Sendable {
    func refresh(_ snapshot: StoreSnapshot) async
}
extension IdentityStoreSync: PasskeyIdentityRefreshing {}

/// Passkeys, apart from UIKit. Reuses `CredentialFlow.unlock()` (erase-pending refusal, Face ID, snapshot
/// cache) and refuses before any prompt when "Offer passkeys" is off. Signing in never writes the store
/// (the sign counter is always zero). Creating a passkey is the extension's only write: one atomic
/// `LocalStore` commit (its flock serializes it with the app), never a sync.
@MainActor
final class PasskeyFlow {
    enum Failure: Error, Equatable {
        /// "Offer passkeys" is off in the app's settings.
        case passkeysOff
        /// No live passkey item with that id for that relying party.
        case notFound
        /// The item is not ES256 or its private key does not parse (desktop `usable_record`).
        case unusable
        /// The site does not accept ES256: cancelled as `.failed`, so iOS offers another way to create it.
        case unsupportedAlgorithm
        /// The free plan is full and there is no Pro (entitlement or valid synced licence).
        case needsPro
        /// The store kept changing under the commit.
        case storeBusy
    }

    static let signInReason = "Sign in with your passkey"
    static let createReason = "Create a passkey"
    /// COSE ES256.
    static let es256 = -7

    let credentials: CredentialFlow
    let pro: any ProEntitlementChecking
    let licenseKeys: [String: [UInt8]]
    let identities: (any PasskeyIdentityRefreshing)?
    let random: any RandomSource
    /// Local calendar date `YYYY-MM-DD` (desktop `date.today().isoformat()`).
    let today: @Sendable () -> String

    init(credentials: CredentialFlow, pro: any ProEntitlementChecking = NoEntitlement(),
         licenseKeys: [String: [UInt8]] = LicenseKeys.production, identities: (any PasskeyIdentityRefreshing)? = nil,
         random: any RandomSource = SystemRandomSource(), today: @escaping @Sendable () -> String = PasskeyFlow.localToday) {
        self.credentials = credentials; self.pro = pro; self.licenseKeys = licenseKeys
        self.identities = identities; self.random = random; self.today = today
    }

    nonisolated static func localToday() -> String {
        let f = DateFormatter()
        f.calendar = Calendar(identifier: .gregorian); f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = .current; f.dateFormat = "yyyy-MM-dd"
        return f.string(from: Date())
    }

    /// Off -> erase pending (in `CredentialFlow.unlock`) -> Face ID -> work.
    private func unlock(reason: String, beforeAuth: () async throws -> Void = {}) async throws -> StoreSnapshot {
        try Task.checkCancellation()
        guard credentials.settings.offerPasskeys else { throw Failure.passkeysOff }
        if credentials.settings.erasePending { credentials.reset(); throw CredentialFlow.Failure.erasePending }
        try await beforeAuth()
        try Task.checkCancellation()
        return try await credentials.unlock(reason: reason)
    }

    /// The stored relying party is casefolded; iOS may pass any case. Exact host only, never parent/child.
    private static func matches(_ record: PasskeyRecord, rpID: String) -> Bool {
        !record.rpID.isEmpty && record.rpID == PasskeyRecord.normaliseRPID(rpID)
    }

    private static func live(_ snapshot: StoreSnapshot, _ id: String) -> PasskeyRecord? {
        guard snapshot.meta[id]?.deleted != true, let item = snapshot.records[id] else { return nil }
        return PasskeyRecord.from(item, id: id)
    }

    /// Usable passkeys for `rpID`, ordered by item id. An empty `allowed` list (discoverable sign-in) offers
    /// every one of them; otherwise only those whose credential id is listed.
    func candidates(rpID: String, allowed: [Data]) async throws -> [PasskeyCandidate] {
        let s = try await unlock(reason: Self.signInReason)
        return s.records.keys.sorted(by: Scalars.less).compactMap { id in
            guard let r = Self.live(s, id), r.key != nil, Self.matches(r, rpID: rpID) else { return nil }
            guard allowed.isEmpty || allowed.contains(Data(r.credentialID)) else { return nil }
            return PasskeyCandidate(itemID: r.itemID, title: r.title, rpID: r.rpID, userName: r.userName,
                                    credentialID: Data(r.credentialID))
        }
    }

    /// Signs `authenticatorData ‖ clientDataHash` with the item's key. The key lives only in this call.
    func assert(recordID: String, rpID: String, clientDataHash: Data, userVerified: Bool) async throws -> PasskeyAssertion {
        let s = try await unlock(reason: Self.signInReason)
        guard let r = Self.live(s, recordID), Self.matches(r, rpID: rpID) else { throw Failure.notFound }
        guard let key = r.key else { throw Failure.unusable }
        let ad = authenticatorData(rpID: r.rpID, userVerified: userVerified, attested: nil)
        let sig = try key.sign(authData: ad, clientDataHash: Array(clientDataHash))
        return PasskeyAssertion(userHandle: Data(r.userHandle), rpID: r.rpID, signature: Data(sig),
                                clientDataHash: clientDataHash, authenticatorData: Data(ad), credentialID: Data(r.credentialID))
    }

    /// Creates an ES256 passkey: a new `passkey` item shaped as desktop `create_credential` writes it, committed
    /// like `EditorModel` creates items (normal form, `Wrapper.make`, no sync meta, so the app's next sync
    /// stamps it), then the AutoFill identities are republished from the committed store. UV is set because
    /// Face ID ran for this request (the driver resets the flow after each one).
    func register(rpID: String, rpName: String, userName: String, userDisplayName: String, userHandle: Data,
                  clientDataHash: Data, algorithms: [Int]) async throws -> (credentialID: Data, attestationObject: Data) {
        var entitled: Bool?   // StoreKit asked at most once, and only when the free plan is full
        let first = try await unlock(reason: Self.createReason) {
            guard algorithms.contains(Self.es256) else { throw Failure.unsupportedAlgorithm }
            // Over the limit at the store's current revision with no synced licence (`LocalStore` hint):
            // without the App Store entitlement, refuse before the Face ID prompt.
            if let hinted = credentials.settings.planFullRevision, hinted == credentials.opener.committedRevision() {
                entitled = await pro.isEntitled()
                guard entitled == true else { throw Failure.needsPro }
            }
        }
        guard let store = credentials.store else { throw Failure.storeBusy }
        func isPro(_ snap: StoreSnapshot) async -> Bool {
            if ItemLimit.validLicense(in: snap, keys: licenseKeys) != nil { return true }
            if entitled == nil { entitled = await pro.isEntitled() }
            return entitled == true
        }
        // The unlock's snapshot is the first commit base; StoreKit is read before the loop only when it is full.
        if !ItemLimit.allows(.create, snapshot: first, isPro: false), !(await isPro(first)) { throw Failure.needsPro }
        let key = PasskeyKey.generate()
        let credentialID = random.bytes(count: Passkey.credentialIDLength)
        let made = PasskeyRecord.newPayload(rpID: rpID, rpName: rpName, userName: userName, userDisplayName: userDisplayName,
                                            userHandle: Array(userHandle), credentialID: credentialID, key: key, today: today())
        let now = JSONValue.int(credentials.clock.now)
        let id = Self.uuid4(random)
        let record = try Normalise.normalForm(ns: .item, record: .object([
            "id": .string(id), "kind": .string("passkey"), "title": .string(made.title), "payload": made.fields,
            "created_at": now, "updated_at": now, "favorite": .bool(false), "tags": .array([]),
        ]))
        let wrapper = Wrapper.make(ns: .item, record: record)
        var committed: StoreSnapshot?
        var base: StoreSnapshot? = first
        // One retry when the app committed between our load and commit (`LocalStoreError.stale`).
        for _ in 0..<2 where committed == nil {
            var snap = try base ?? store.load()
            base = nil
            // Re-checked on every base: the app may have added items since the unlock.
            if !ItemLimit.allows(.create, snapshot: snap, isPro: false), !(await isPro(snap)) { throw Failure.needsPro }
            guard snap.records[id] == nil else { throw Failure.storeBusy }
            try Task.checkCancellation()   // cancelled before the write: nothing is created
            // "Erase this iPhone's vault" may have started during Face ID or a retry: never write into it.
            if credentials.settings.erasePending { credentials.reset(); throw CredentialFlow.Failure.erasePending }
            snap.records[id] = wrapper
            do {
                try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
                committed = StoreSnapshot(records: snap.records, meta: snap.meta, sync: snap.sync, revision: snap.revision + 1)
            } catch LocalStoreError.stale { continue }
        }
        guard let committed else { throw Failure.storeBusy }
        credentials.reset()   // the pre-commit snapshot is out of date
        if let identities { await identities.refresh(committed) }
        let authData = authenticatorData(rpID: PasskeyRecord.normaliseRPID(rpID), userVerified: true,
                                         attested: (credentialID, coseES256Key(key.publicKey)))
        return (Data(credentialID), Data(noneAttestationObject(authData: authData)))
    }

    /// Python `str(uuid.uuid4())`, as `EditorModel.uuid4` (the extension cannot link the app's code).
    static func uuid4(_ random: any RandomSource) -> String {
        var b = random.bytes(count: 16)
        b[6] = (b[6] & 0x0F) | 0x40; b[8] = (b[8] & 0x3F) | 0x80
        let c = Array(b.map { String(format: "%02x", $0) }.joined())
        return [0..<8, 8..<12, 12..<16, 16..<20, 20..<32].map { String(c[$0]) }.joined(separator: "-")
    }
}
