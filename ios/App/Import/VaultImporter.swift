import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// What one import did, for the notice.
struct ImportResult: Equatable, Sendable {
    var added: Int
    var updated: Int
    /// Already in the vault (same password, or the same passkey), and duplicates within the import.
    var unchanged: Int
    /// New items left out because the free vault is full.
    var needsPro: Int
    /// Items the source had that this app cannot store (including 2FA codes that could not be read).
    var unsupported: Int

    /// "12 added · 3 updated · 2 already saved · 5 waiting: upgrade to Pro, then import again · 1 not supported";
    /// zero parts are left out.
    var notice: String {
        var parts: [String] = []
        if added > 0 { parts.append(String(localized: "\(added) added")) }
        if updated > 0 { parts.append(String(localized: "\(updated) updated")) }
        if unchanged > 0 { parts.append(String(localized: "\(unchanged) already saved")) }
        if needsPro > 0 { parts.append(String(localized: "\(needsPro) waiting: upgrade to Pro, then import again")) }
        if unsupported > 0 { parts.append(String(localized: "\(unsupported) not supported")) }
        return parts.joined(separator: " · ")
    }
}

/// Stores imported logins and passkeys (Safari export, CSV, Credential Exchange) in one commit.
/// Logins match a live web login with the same canonical origin and exact username: a new password replaces
/// the old one (pushed to `password_history`, at most 5), the same password changes nothing. Passkeys match
/// on relying party and credential id and are never overwritten. New items need a free slot or Pro; the rest
/// are counted `needsPro`. A stale commit is matched again against the new vault and retried once.
@MainActor
final class VaultImporter {
    nonisolated static let historyLimit = 5

    let store: any ItemStore
    let isPro: () -> Bool
    let now: () -> Date
    let random: any RandomSource
    /// Runs after a commit that changed the vault. The app passes `SyncCoordinator.noteLocalEdit`, as after
    /// a Safari import or an editor save: it republishes the AutoFill identities and schedules a sync.
    let afterCommit: () -> Void

    init(store: any ItemStore, isPro: @escaping () -> Bool, now: @escaping () -> Date, random: any RandomSource,
         afterCommit: @escaping () -> Void = {}) {
        self.store = store; self.isPro = isPro; self.now = now; self.random = random; self.afterCommit = afterCommit
    }

    func importCandidates(_ candidates: [ImportCandidate], unsupported: Int) throws -> ImportResult {
        var (snapshot, result, changed) = try plan(candidates, unsupported: unsupported)
        guard changed else { return result }
        do { try commit(snapshot) } catch LocalStoreError.stale {
            (snapshot, result, changed) = try plan(candidates, unsupported: unsupported)
            guard changed else { return result }
            try commit(snapshot)
        }
        afterCommit()
        return result
    }

    private func commit(_ s: StoreSnapshot) throws {
        try store.commit(StoreChange(baseRevision: s.revision, records: s.records, meta: s.meta, sync: s.sync))
    }

    private func plan(_ candidates: [ImportCandidate], unsupported: Int) throws
        -> (StoreSnapshot, ImportResult, Bool) {
        var snap = try store.load()
        var r = ImportResult(added: 0, updated: 0, unchanged: 0, needsPro: 0, unsupported: unsupported)
        let pro = isPro()
        let date = now()
        let stamp = Int64(date.timeIntervalSince1970)
        var changed = false
        /// (canonical origin, username) of the logins seen so far: the first one in the import wins, later
        /// duplicates count as already saved, so importing the same file twice changes nothing.
        var seen: Set<[String]> = []
        for c in candidates {
            switch c.kind {
            case .login(let f):
                guard let origin = (try? WebsiteInput.origin(f.url)).flatMap({ try? Origin.canonicalize($0) }) else { r.unsupported += 1; continue }
                var totp: JSONValue?
                if let uri = f.otpauth, !uri.isEmpty {
                    if (try? TOTP.parseOtpauthURI(uri)) != nil, let t = try? EditorModel.totp(uri, current: nil) { totp = t }
                    else { r.unsupported += 1 }
                }
                // Byte-wise key (Swift String equality is canonical equivalence; the vault compares bytes).
                let key = [origin, f.username].map { $0.utf8.map { String($0) }.joined(separator: ",") }
                if !seen.insert(key).inserted { r.unchanged += 1; continue }
                if let id = Self.match(origin: origin, username: f.username, in: snap),
                   case .object(let w)? = snap.records[id], case .object(let stored)? = w["record"] {
                    let old = stored["password"]?.stringValue ?? ""
                    let samePassword = old.utf8.elementsEqual(f.password.utf8)
                    let addTOTP = (stored["totp"] == nil || stored["totp"] == .null) && totp != nil
                    if samePassword && !addTOTP { r.unchanged += 1; continue }
                    var record = samePassword ? stored : Self.withNewPassword(stored, f.password, at: stamp)
                    if addTOTP { record["totp"] = totp; record["updated_at"] = .int(stamp) }
                    guard Self.put(record, ns: .entry, into: &snap) != nil else { r.unsupported += 1; continue }
                    r.updated += 1; changed = true
                } else {
                    guard ItemLimit.allows(.create, snapshot: snap, isPro: pro) else { r.needsPro += 1; continue }
                    var record = EditorModel.newRecord(kind: .web, now: stamp, random: random)
                    let title = c.title   // label: the source's title, else the site
                    record["label"] = .string(title.isEmpty ? OriginLabel.friendly(origin) : title)
                    record["username"] = .string(f.username)
                    record["password"] = .string(f.password)
                    record["scope"] = .object(["origin": .string(origin)])
                    if !f.notes.isEmpty { record["notes"] = .string(f.notes) }
                    if let totp { record["totp"] = totp }
                    guard Self.put(record, ns: .entry, into: &snap, isNew: true) != nil else { r.unsupported += 1; continue }
                    r.added += 1; changed = true
                }
            case .passkey(let p):
                let rp = PasskeyRecord.normaliseRPID(p.rpID)
                let cred = base64URLNoPad(Array(p.credentialID))
                if Self.hasPasskey(rp: rp, credentialID: cred, in: snap) { r.unchanged += 1; continue }
                guard let key = PasskeyKey(pkcs8B64URL: base64URLNoPad(Array(p.pkcs8))) else { r.unsupported += 1; continue }
                guard ItemLimit.allows(.create, snapshot: snap, isPro: pro) else { r.needsPro += 1; continue }
                let made = PasskeyRecord.newPayload(rpID: p.rpID, rpName: "", userName: p.userName,
                                                    userDisplayName: p.userDisplayName, userHandle: Array(p.userHandle),
                                                    credentialID: Array(p.credentialID), key: key, today: Self.day(date))
                let record: [String: JSONValue] = [
                    "id": .string(EditorModel.uuid4(random)), "kind": .string("passkey"),
                    "title": .string(c.title.isEmpty ? made.title : c.title), "payload": made.fields,
                    "created_at": .int(stamp), "updated_at": .int(stamp), "favorite": .bool(false), "tags": .array([]),
                ]
                guard Self.put(record, ns: .item, into: &snap, isNew: true) != nil else { r.unsupported += 1; continue }
                r.added += 1; changed = true
            case .note, .card, .identity:
                r.unsupported += 1   // the iPhone importers produce logins and passkeys only
            }
        }
        return (snap, r, changed)
    }

    // MARK: shared with SafariImporter (the logic lives in ImportReviewModel, shared with the Mac)

    /// The live web login with this canonical origin and exactly this username (desktop `_web_login_match`).
    nonisolated static func match(origin: String, username: String, in snapshot: StoreSnapshot) -> String? {
        ImportReviewModel.match(origin: origin, username: username, in: snapshot)
    }

    /// `stored` with `password` replaced; the old one goes to the front of `password_history` (at most 5).
    nonisolated static func withNewPassword(_ stored: [String: JSONValue], _ password: String, at now: Int64) -> [String: JSONValue] {
        ImportReviewModel.withNewPassword(stored, password, at: now)
    }

    /// Normalises and wraps the record into the snapshot as the editor does (see `ImportReviewModel.put`).
    @discardableResult
    nonisolated static func put(_ record: [String: JSONValue], ns: Namespace, into snapshot: inout StoreSnapshot,
                                isNew: Bool = false) -> String? {
        ImportReviewModel.put(record, ns: ns, into: &snapshot, isNew: isNew)
    }

    private static func hasPasskey(rp: String, credentialID: String, in snapshot: StoreSnapshot) -> Bool {
        for (id, w) in snapshot.records where snapshot.meta[id]?.deleted != true {
            guard case .object(let o) = w, o["ns"] == .string(Namespace.item.rawValue),
                  case .object(let rec)? = o["record"], rec["kind"] == .string("passkey"),
                  case .object(let p)? = rec["payload"] else { continue }
            if PasskeyRecord.normaliseRPID(p["relying_party_id"]?.stringValue ?? "") == rp,
               p["credential_id"]?.stringValue == credentialID { return true }
        }
        return false
    }

    private static func day(_ date: Date) -> String { ImportReviewModel.day(date) }
}
