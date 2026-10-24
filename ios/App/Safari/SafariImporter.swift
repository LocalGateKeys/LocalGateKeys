import Foundation
import Observation
import AppShared

/// What one Safari import did, for the notice.
struct SafariImportResult: Equatable, Sendable {
    /// Logins created or updated (one login saved twice counts once).
    var saved: Int
    /// New logins left in the inbox because the free vault is full.
    var waiting: Int
    /// Inbox entries that could not be opened, or new logins that never could be stored; they were deleted.
    var damaged: Int
    /// Updates the vault refused even with only the password changed (the stored login carries data this
    /// app does not know, say from a newer desktop): they stay in the inbox, never deleted.
    var kept: Int = 0

    static let nothing = SafariImportResult(saved: 0, waiting: 0, damaged: 0)

    /// "2 logins saved from Safari · 1 waiting: upgrade to Pro to import · 1 could not be read ·
    /// 1 could not be imported"; nil when there is nothing to say.
    var notice: String? {
        var parts: [String] = []
        if saved > 0 { parts.append(saved == 1 ? "1 login saved from Safari" : "\(saved) logins saved from Safari") }
        if waiting > 0 { parts.append("\(waiting) waiting: upgrade to Pro to import") }
        if damaged > 0 { parts.append("\(damaged) could not be read") }
        if kept > 0 { parts.append("\(kept) could not be imported") }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }
}

/// One login saved in Safari that waits for the user's confirmation (audit 2026-10-24 L-18). No password:
/// the sheet shows where it is from, the username and what saving it would do.
struct SafariPendingSave: Identifiable, Equatable, Sendable {
    enum Change: Equatable, Sendable {
        /// No login with this origin and username yet.
        case new
        /// Replaces the password of the login with this origin and username.
        case update
    }
    /// The inbox entry id.
    let id: String
    /// Canonical origin.
    let origin: String
    let username: String
    let change: Change
    let capturedAt: Int64
}

/// Moves the logins the Safari extension saved (`SafariInbox`) into the vault, as the desktop's `upsert_web`
/// does: a live web login with the same canonical origin and exact username gets the new password (the old
/// one goes to the front of `password_history`, at most 5); otherwise a new login is created, which needs a
/// free slot or Pro. Entries are applied oldest first, so the newest password wins. Everything goes into
/// one `StoreChange`; a stale commit is matched again and retried once. Inbox entries are deleted only after
/// the commit: imported ones, unchanged ones (same password), unreadable ones and new logins the vault
/// refuses. New logins over the free limit stay, and so do updates the vault refuses: an update is retried
/// with only the password and `updated_at` changed, and when that is refused too the entry is kept.
/// No `SyncMeta` is written: the next sync stamps the changes, as for passkeys.
///
/// The extension saves without Face ID and cannot tell an unchanged password from a new one (it never
/// compares passwords), so nothing is imported without the user: `review()` compares each password with the
/// vault, drops the unchanged ones and lists the rest, and `run(only:)` imports only the entries the user
/// confirmed (audit 2026-10-24 M-3 / L-18).
struct SafariImporter: Sendable {
    let store: any ItemStore
    let inbox: SafariInbox
    let clock: any UnixClock
    let isPro: Bool
    let random: any RandomSource

    static let historyLimit = 5

    init(store: any ItemStore, inbox: SafariInbox, clock: any UnixClock, isPro: Bool,
         random: any RandomSource = SystemRandomSource()) {
        self.store = store; self.inbox = inbox; self.clock = clock; self.isPro = isPro; self.random = random
    }

    /// What waits for confirmation, oldest first. Expires old entries; deletes entries whose password is
    /// already the vault's (nothing to confirm) and entries whose origin the vault refuses (never importable).
    /// Damaged blobs are left for `run`, which deletes and counts them. Throws when the store cannot be read.
    func review() throws -> [SafariPendingSave] {
        inbox.expire()
        let snapshot = try store.load()
        var pending: [SafariPendingSave] = [], drop: [String] = []
        for entry in inbox.entries().entries {
            guard let origin = try? Origin.canonicalize(entry.origin) else { drop.append(entry.id); continue }
            var change = SafariPendingSave.Change.new
            if let id = Self.match(origin: origin, username: entry.username, in: snapshot),
               case .object(let wrapper)? = snapshot.records[id], case .object(let stored)? = wrapper["record"] {
                // Compared here, behind the app's unlock, never in the extension.
                let old = stored["password"]?.stringValue ?? ""
                if old.utf8.elementsEqual(entry.password.utf8) { drop.append(entry.id); continue }
                change = .update
            }
            pending.append(SafariPendingSave(id: entry.id, origin: origin, username: entry.username, change: change,
                                             capturedAt: entry.capturedAt))
        }
        inbox.remove(ids: drop)
        return pending
    }

    /// Imports the entries named by `approved` (every waiting entry when nil); the others stay in the inbox.
    /// Damaged blobs are always deleted and counted. Throws when the store cannot be read or the commit fails
    /// (twice stale included); the inbox is then left as it was, for the next run.
    func run(only approved: Set<String>? = nil) throws -> SafariImportResult {
        inbox.expire()
        let (waiting, damaged) = inbox.entries()
        let entries = approved.map { ids in waiting.filter { ids.contains($0.id) } } ?? waiting
        var plan = Plan(snapshot: StoreSnapshot())
        if !entries.isEmpty {
            plan = try apply(entries)
            if plan.changed {
                do { try commit(plan) } catch LocalStoreError.stale {
                    // A sync or the AutoFill extension committed in between: match against the new vault once.
                    plan = try apply(entries)
                    if plan.changed { try commit(plan) }
                }
            }
        }
        inbox.remove(ids: plan.done + plan.rejected + damaged)
        return SafariImportResult(saved: plan.saved.count, waiting: plan.waiting, damaged: damaged.count + plan.rejected.count,
                                  kept: plan.kept)
    }

    // MARK: matching

    private struct Plan {
        var snapshot: StoreSnapshot
        /// Entries applied or already in the vault: deleted after the commit.
        var done: [String] = []
        /// New logins the vault refuses (Normalise): they never could be stored, so they are deleted and counted.
        var rejected: [String] = []
        var waiting = 0
        /// Updates refused even in the narrow form: left in the inbox and counted.
        var kept = 0
        /// Record ids created or updated.
        var saved: Set<String> = []
        var changed = false
    }

    private func apply(_ entries: [SafariInboxEntry]) throws -> Plan {
        var plan = Plan(snapshot: try store.load())
        let now = clock.now
        for entry in entries {
            guard let origin = try? Origin.canonicalize(entry.origin) else { plan.rejected.append(entry.id); continue }
            if let id = Self.match(origin: origin, username: entry.username, in: plan.snapshot),
               case .object(let wrapper)? = plan.snapshot.records[id], case .object(let stored)? = wrapper["record"] {
                let old = stored["password"]?.stringValue ?? ""
                if old.utf8.elementsEqual(entry.password.utf8) { plan.done.append(entry.id); continue }
                var record = stored
                var history = record["password_history"]?.arrayValue ?? []
                history.insert(.object(["password": .string(old), "changed_at": .int(now)]), at: 0)
                record["password_history"] = .array(Array(history.prefix(Self.historyLimit)))
                record["password"] = .string(entry.password)
                record["updated_at"] = .int(now)
                if case .int(let created)? = record["created_at"], created > now { record["created_at"] = .int(now) }
                if Self.put(record, for: entry, isNew: false, into: &plan) { continue }
                // Refused, most likely because of the stored login (fields a newer desktop wrote): this entry
                // may be the only copy of the new password, so it is never deleted. Retry with only the
                // password and updated_at changed (no history push); if that is refused too, keep it waiting.
                var narrow = stored
                narrow["password"] = .string(entry.password)
                narrow["updated_at"] = .int(now)
                if !Self.put(narrow, for: entry, isNew: false, into: &plan) { plan.kept += 1 }
            } else {
                guard ItemLimit.allows(.create, snapshot: plan.snapshot, isPro: isPro) else { plan.waiting += 1; continue }
                var record = EditorModel.newRecord(kind: .web, now: now, random: random)
                record["label"] = .string(OriginLabel.friendly(origin))
                record["username"] = .string(entry.username)
                record["password"] = .string(entry.password)
                record["scope"] = .object(["origin": .string(origin)])
                // A new login refused because of its own fields (a username too long for the vault) never
                // could be stored: dropped and counted.
                if !Self.put(record, for: entry, isNew: true, into: &plan) { plan.rejected.append(entry.id) }
            }
        }
        return plan
    }

    /// The live web login with this canonical origin and exactly this username (desktop `_web_login_match`).
    /// Deleted items are not matched, so an update whose login was deleted becomes a new login.
    static func match(origin: String, username: String, in snapshot: StoreSnapshot) -> String? {
        for id in snapshot.records.keys.sorted() where snapshot.meta[id]?.deleted != true {
            guard case .object(let w)? = snapshot.records[id], w["ns"] == .string(Namespace.entry.rawValue),
                  case .object(let r)? = w["record"], r["kind"] == .string("web"),
                  case .string(let raw)? = r["scope"]?.objectValue?["origin"],
                  let canonical = try? Origin.canonicalize(raw), canonical.utf8.elementsEqual(origin.utf8),
                  case .string(let user)? = r["username"], user.utf8.elementsEqual(username.utf8) else { continue }
            return id
        }
        return nil
    }

    /// Normalises and wraps the record as the editor does. false when `Normalise` refuses it (nothing is
    /// changed then; the caller decides what happens to the entry).
    private static func put(_ record: [String: JSONValue], for entry: SafariInboxEntry, isNew: Bool, into plan: inout Plan) -> Bool {
        guard let normal = try? Normalise.normalForm(ns: .entry, record: .object(record)),
              case .object(let o) = normal, case .string(let id)? = o["id"] else { return false }
        if isNew, plan.snapshot.records[id] != nil { return true }   // a random id collision: try again next run
        plan.snapshot.records[id] = Wrapper.make(ns: .entry, record: normal)
        plan.saved.insert(id)
        plan.done.append(entry.id)
        plan.changed = true
        return true
    }

    private func commit(_ plan: Plan) throws {
        let s = plan.snapshot
        try store.commit(StoreChange(baseRevision: s.revision, records: s.records, meta: s.meta, sync: s.sync))
    }
}

/// Runs the Safari import for the unlocked app: after each unlock and when the app comes back to the
/// foreground while unlocked, it lists what Safari saved (`pending`) and the unlocked view asks the user;
/// only confirmed logins are imported (audit 2026-10-24 L-18). One import at a time; the summary shows as a
/// notice.
@MainActor
@Observable
final class SafariImportModel {
    /// Bumped when the app returns to the foreground while it stayed unlocked; the unlocked view reviews then.
    private(set) var foregroundRuns = 0
    /// Logins from Safari waiting for the user's yes or no. Empty: no sheet.
    private(set) var pending: [SafariPendingSave] = []

    @ObservationIgnored private var running = false
    @ObservationIgnored private let clock: any UnixClock
    @ObservationIgnored private let background: any BackgroundTasking
    /// `<app group>/SafariSave`: the index file and the `inbox` folder.
    @ObservationIgnored private let directory: @Sendable () throws -> URL
    @ObservationIgnored private let show: @MainActor (String) -> Void

    static let noticeDuration: Duration = .seconds(4)

    init(clock: any UnixClock = SystemClock(), background: (any BackgroundTasking)? = nil,
         directory: @escaping @Sendable () throws -> URL = { try SafariSaveFiles.directory() },
         show: (@MainActor (String) -> Void)? = nil) {
        self.clock = clock
        self.background = background ?? UIKitBackgroundTasks()
        self.directory = directory
        self.show = show ?? { CopyToast.shared.show($0, for: SafariImportModel.noticeDuration) }
    }

    /// Set once `afterUnlock` has finished for the current unlock (Pro re-read, index published, first
    /// import done); cleared by `locked()`. A foreground import before then could use a stale Pro state
    /// and show a wrong "waiting: upgrade to Pro" notice, so `foregrounded()` is ignored until then.
    @ObservationIgnored private(set) var ready = false

    /// Back in the foreground while unlocked: asks the unlocked view to import, once `afterUnlock` is done.
    func foregrounded() {
        guard ready else { return }
        foregroundRuns += 1
    }

    /// The vault locked: the next unlock runs `afterUnlock` again before any foreground review, and asks
    /// again about what is still waiting.
    func locked() { ready = false; pending = [] }

    /// Right after unlock: creates the Safari keys when missing, publishes the fingerprint index from the
    /// vault as it is, then lists what waits for confirmation (`pending`). Pro is re-read first (entitlement
    /// and synced licence). If the vault locked (or the unlocked view went away, cancelling this task) while
    /// the entitlement was read, nothing else happens: no Keychain write, no commit, no notice.
    func afterUnlock(store: any ItemStore, keychain: any KeychainVault, pro: ProModel,
                     isUnlocked: @MainActor () -> Bool) async {
        ready = false
        await pro.refresh()
        guard !Task.isCancelled, isUnlocked() else { return }
        defer { ready = true }
        do { try SafariKeys.ensure(keychain: keychain) }   // without keys the Safari extension stays unavailable
        catch { AutoFillTrace.log("safari afterUnlock: keys \(error: error)") }
        AutoFillTrace.log("safari afterUnlock: keys ensured")
        if let snapshot = try? store.load() {
            pro.update(from: snapshot)
            SafariIndexPublisher(keychain: keychain, directory: directory).publish(snapshot)
        }
        review(store: store, keychain: keychain)
    }

    /// Lists what Safari saved into `pending` (unchanged logins are dropped without asking). nil when nothing
    /// ran: an import is running, there is no inbox key, or the vault could not be read.
    @discardableResult
    func review(store: any ItemStore, keychain: any KeychainVault) -> [SafariPendingSave]? {
        guard !running, let inbox = inbox(keychain) else { return nil }
        let importer = SafariImporter(store: store, inbox: inbox, clock: clock, isPro: false)
        guard let list = try? importer.review() else { return nil }
        pending = list
        return list
    }

    /// The user answered the sheet: imports the `approved` entries of `pending`, deletes the other ones (the
    /// user said no) and shows the summary. nil when nothing ran (another import, no inbox key, or the import
    /// failed: the inbox is kept for the next run, the answer is asked again).
    @discardableResult
    func confirm(_ approved: Set<String>, store: any ItemStore, keychain: any KeychainVault, isPro: Bool) -> SafariImportResult? {
        guard !running, let inbox = inbox(keychain) else { return nil }
        running = true
        defer { running = false }
        let asked = Set(pending.map(\.id))
        let yes = approved.intersection(asked)
        pending = []
        inbox.remove(ids: asked.subtracting(yes).sorted())
        let importer = SafariImporter(store: store, inbox: inbox, clock: clock, isPro: isPro)
        // The commit holds the store's flock in the app-group container: keep the app alive meanwhile.
        guard let result = try? background.run("LocalGateKeys Safari import", { try importer.run(only: yes) }) else { return nil }
        if let notice = result.notice { show(notice) }
        return result
    }

    /// "Decide later": the entries stay in the inbox (until they expire) and are asked again at the next
    /// unlock or return to the app.
    func later() { pending = [] }

    private func inbox(_ keychain: any KeychainVault) -> SafariInbox? {
        guard let key = try? keychain.read(.safariInboxKey), key.count == SafariKeys.length,
              let root = try? directory() else { return nil }
        return SafariInbox(directory: root.appendingPathComponent(SafariInbox.directoryName, isDirectory: true), key: key)
    }
}
