import Combine
import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// What the user chose for one import row (Windows `import_workflow.DECISIONS`: `add` is `create`).
enum ImportDecision: Hashable, Sendable {
    case create
    case skip
    /// Overwrite the existing item's title, password and details.
    case replace(String)
    /// Take the password and details, keep the existing item's title.
    case merge(String)
    /// Keep a secure-note copy beside the existing account (Windows `keep_both`).
    case keepBoth
}

enum ImportRowStatus: Equatable, Sendable {
    case new
    /// The same data is already in the vault, or a repeat inside the import.
    case duplicate
    /// The vault has this account or item with different data.
    case conflict
    /// No free slot left on the free plan ("Needs Pro").
    case limited
    /// The source row could not be imported; the reason is the Windows message.
    case skipped(String)
}

/// One record as it will be saved: an `ImportCandidate` normalised the Windows way (`ImportedRecord` after
/// `normalise_records`).
struct ImportDraft: Sendable, Equatable {
    enum Kind: String, Sendable { case login, note, card, identity, passkey }
    var kind: Kind
    var title = ""
    var username = ""
    var password = ""
    var notes = ""
    var totp = ""
    /// The source's addresses, as given.
    var urls: [String] = []
    var customFields: [ImportCustomField] = []
    var tags: [String] = []
    var folder = ""
    var favourite = false
    var identity: [String: String] = [:]
    var card: [String: String] = [:]
    var passkey: PasskeyFields?
}

struct ImportRow: Identifiable, Sendable {
    let id: Int
    /// 1-based row or item number in the source, for messages.
    let sourceRow: Int
    var draft: ImportDraft
    /// Values a card or identity cannot hold, kept in an "extra details" secure note.
    var extra: ImportDraft?
    /// The login's canonical website origins (the first is the primary one), at most 20.
    var webURLs: [String] = []
    var base: ImportRowStatus = .new
    var decision: ImportDecision = .create
    var targetID: String?
    /// The target record as reviewed; the commit refuses a target that changed since.
    var targetRecord: JSONValue?
    var limited = false

    var kind: ImportDraft.Kind { draft.kind }
    var title: String { draft.title }
    var origin: String { webURLs.first ?? "" }
    var username: String { draft.username }
    var hasTOTP: Bool { !draft.totp.isEmpty }
    var status: ImportRowStatus { limited ? .limited : base }
    /// A repeat of an earlier row of the same import (Windows `in_import_duplicate`).
    var inImportDuplicate: Bool { base == .duplicate && targetID == nil }
    var isSkippedSource: Bool { if case .skipped = base { return true } else { return false } }

    /// Windows `ImportRowPlan.state`, as shown in the review list.
    var stateLabel: String {
        if limited { return String(localized: "Needs Pro") }
        switch decision {
        case .create: return String(localized: "Add")
        case .skip: return String(localized: "Skip")
        case .replace: return String(localized: "Replace")
        case .merge: return String(localized: "Merge")
        case .keepBoth: return String(localized: "Keep both")
        }
    }

    /// Live items this row's decision creates, the free-plan slots it needs (Windows `new_items`).
    var newItems: Int {
        let extraCount = extra == nil ? 0 : 1
        switch decision {
        case .skip: return 0
        case .create, .keepBoth: return 1 + (kind == .login ? 0 : extraCount)
        case .replace, .merge: return kind == .login ? 0 : extraCount
        }
    }
}

struct ImportOutcome: Equatable, Sendable {
    var created: Int
    var updated: Int
    var skipped: Int
    var limited: Int
}

enum ImportReviewError: Error, Equatable {
    case targetChanged
    case targetRevisionChanged
    case itemLimit
    case invalid(row: Int, String)

    /// The Windows (`import_workflow.py`, `vault.ItemLimitReached`) wording.
    var message: String {
        switch self {
        case .targetChanged: return String(localized: "Import target changed after review")
        case .targetRevisionChanged: return String(localized: "Import target revision changed after review")
        case .itemLimit:
            return String(localized: "The free plan holds up to \(ItemLimit.freeItems) items. Upgrade to LocalGateKeys Pro for unlimited items.")
        case .invalid(let row, let m): return String(localized: "Row \(row): \(m)")
        }
    }
}

/// The review step of an import, shared by the Mac and the iPhone: a port of Windows `import_workflow.py`
/// (`normalise_records`, `classify_rows`, `ImportPlan.set_decision`/`recompute_limits`/`limit_note`,
/// `apply_import_plan`). Rows already in the vault default to Skip, repeats inside the import too (a repeat
/// with another password is kept as a secure-note copy), and on the free plan rows beyond the free slots
/// left are "Needs Pro" and imported two-factor keys are kept as hidden custom fields. `commit` writes the
/// reviewed rows in one store commit, through the store it is given (the app's `PublishingItemStore`).
@MainActor
final class ImportReviewModel: ObservableObject {
    nonisolated static let maxWebURLs = 20
    nonisolated static let maxFields = 50, maxFieldValue = 4096, maxFieldName = 100
    nonisolated static let maxTags = 20, maxTagLength = 40, maxTitle = 512
    nonisolated static let maxNoteBody = 20_000
    nonisolated static let maxDiagnostics = 50
    nonisolated static let historyLimit = 5
    nonisolated static let identityLimits: [String: Int] = [
        "name": 256, "given_name": 128, "middle_name": 128, "family_name": 128, "organization": 256, "company": 256,
        "job_title": 160, "email": 320, "phone": 64, "address": 1024, "address_line1": 256, "address_line2": 256,
        "city": 128, "state": 128, "postal_code": 64, "country": 128, "website": 2048,
    ]
    nonisolated static let identityMaxTotal = 8192

    @Published private(set) var rows: [ImportRow]
    /// Windows review messages (capped at 50 plus an "...and N more" line).
    private(set) var issues: [String]
    /// Free slots left on the free plan; nil on Pro.
    let freeSlots: Int?
    private let now: () -> Date
    private let random: any RandomSource

    init(result: LGKCore.ImportResult, snapshot: StoreSnapshot, freeSlots: Int?, now: @escaping () -> Date = Date.init,
         random: any RandomSource = SystemRandomSource()) {
        self.freeSlots = freeSlots; self.now = now; self.random = random
        var (rows, issues) = Self.normalise(result.candidates)
        issues = Self.cap(issues)
        if freeSlots != nil { issues += Self.keepTOTPAsFields(&rows) }
        Self.classify(&rows, against: snapshot)
        for skip in result.skipped {
            let row = skip.row ?? 0
            rows.append(ImportRow(id: rows.count, sourceRow: row, draft: ImportDraft(kind: .note, title: "Row \(row)"),
                                  base: .skipped(skip.message), decision: .skip))
        }
        self.rows = rows
        self.issues = Self.cap(result.skipped.map(\.message)) + issues
        recomputeLimits()
    }

    /// Free slots left on the free plan (Windows `free_item_slots`); nil on Pro.
    nonisolated static func freeSlots(snapshot: StoreSnapshot, isPro: Bool) -> Int? {
        isPro ? nil : max(0, ItemLimit.freeItems - ItemLimit.liveCount(snapshot))
    }

    // MARK: decisions

    /// Windows `ImportPlan.set_decision`: a decision the row cannot take is ignored.
    func set(_ d: ImportDecision, for id: ImportRow.ID) {
        guard let i = rows.firstIndex(where: { $0.id == id }) else { return }
        let row = rows[i]
        let allowed: Bool
        switch d {
        case .skip: allowed = true
        case .create: allowed = row.base == .new
        case .replace(let t), .merge(let t):
            allowed = !row.isSkippedSource && row.base != .new && !row.inImportDuplicate && row.kind != .passkey
                && row.targetID == t
        case .keepBoth: allowed = !row.isSkippedSource && row.base != .new && row.kind != .passkey
        }
        guard allowed else { return }
        rows[i].decision = d
        recomputeLimits()
    }

    /// Windows `recompute_limits`: rows beyond the free slots left are limited, in review order.
    private func recomputeLimits() {
        var remaining = freeSlots
        for i in rows.indices {
            let needed = rows[i].newItems
            let limited = remaining.map { needed > 0 && needed > $0 } ?? false
            rows[i].limited = limited
            if !limited, let r = remaining { remaining = r - needed }
        }
    }

    private var importedCount: Int { rows.filter { $0.decision != .skip && !$0.limited }.count }

    /// Windows `limit_note`: "" on Pro.
    var limitNote: String {
        guard let slots = freeSlots else { return "" }
        let limited = rows.filter(\.limited).count
        if limited == 0 { return String(localized: "\(slots) free slots left on the free plan") }
        let imported = importedCount
        return String(localized: "\(imported) will be imported on the free plan; \(limited) need Pro")
    }

    /// The review summary line: what will be imported, the free-plan note and what is skipped.
    var summary: String {
        var parts: [String] = []
        let limited = rows.contains(where: \.limited)
        if !limited { let imported = importedCount; parts.append(String(localized: "\(imported) will be imported")) }
        if !limitNote.isEmpty { parts.append(limitNote) }
        let skipped = rows.filter { $0.decision == .skip && !$0.limited }.count
        if skipped > 0 { parts.append(String(localized: "\(skipped) skipped")) }
        return parts.joined(separator: " · ")
    }

    // MARK: format messages

    /// Windows `detect.SUPPORTED_FORMATS` labels.
    nonisolated static func formatLabel(_ f: ImportFormat) -> String {
        switch f {
        case .appleCSV: return String(localized: "Safari passwords CSV")
        case .chrome, .edge, .brave: return String(localized: "Chrome / Edge / Brave passwords CSV")
        case .firefox: return String(localized: "Firefox logins CSV")
        case .bitwarden: return String(localized: "Bitwarden JSON")
        case .bitwardenEncrypted: return String(localized: "Bitwarden password-protected JSON")
        case .onePassword1PUX: return String(localized: "1Password export (.1pux)")
        case .onePasswordCSV: return String(localized: "1Password CSV")
        case .lastPass: return String(localized: "LastPass CSV")
        case .keePassKDBX: return String(localized: "KeePass 2 database (.kdbx)")
        case .keePassXML: return String(localized: "KeePass 2 XML export")
        case .keePassCSV: return String(localized: "KeePass / KeePassXC CSV")
        case .protonPass: return String(localized: "Proton Pass export (.zip / JSON)")
        case .dashlane: return String(localized: "Dashlane export (.zip of CSV files)")
        case .cxf: return String(localized: "Apple Passwords export")
        case .generic: return String(localized: "Generic CSV (choose columns)")
        }
    }

    /// Windows `app/import_export.py` `password_text`.
    nonisolated static func passwordPrompt(for f: ImportFormat) -> String {
        let label = formatLabel(f)
        return String(localized: "\(label) is encrypted.\nEnter the password that opens it (it is used once and not stored):")
    }

    /// The message for an importer error: a missing password asks for it by the format's name.
    nonisolated static func message(for error: ImportError, format: ImportFormat) -> String {
        if error == .needsPassword { return passwordPrompt(for: format) }
        return error.message
    }

    /// Whether to ask for the password again (wrong password, or a KeePass key file).
    nonisolated static func asksPasswordAgain(_ error: ImportError) -> Bool { error == .needsPassword || error.isWrongPassword }

    // MARK: commit

    /// Applies the reviewed rows in one commit (none when nothing changes), re-checking every target and the
    /// free slots against the store as it is now; a stale commit is planned again once.
    func commit(to store: any ItemStore) async throws -> ImportOutcome {
        do { return try apply(to: store) } catch LocalStoreError.stale { return try apply(to: store) }
    }

    private func apply(to store: any ItemStore) throws -> ImportOutcome {
        var snap = try store.load()
        let date = now()
        let stamp = Int64(date.timeIntervalSince1970)
        if freeSlots != nil {
            let needed = rows.filter { !$0.limited }.reduce(0) { $0 + $1.newItems }
            if needed > max(0, ItemLimit.freeItems - ItemLimit.liveCount(snap)) { throw ImportReviewError.itemLimit }
        }
        var out = ImportOutcome(created: 0, updated: 0, skipped: 0, limited: 0)
        for row in rows {
            if row.limited { out.limited += 1; continue }
            switch row.decision {
            case .skip: out.skipped += 1
            case .create:
                if row.kind == .login, Self.match(origin: row.origin, username: row.username, in: snap) != nil {
                    throw ImportReviewError.targetChanged
                }
                if row.kind == .passkey, let p = row.draft.passkey, Self.hasPasskey(p, in: snap) { throw ImportReviewError.targetChanged }
                try create(row.draft, row: row, into: &snap, at: stamp, date: date)
                out.created += 1
                if let e = row.extra { try create(e, row: row, into: &snap, at: stamp, date: date); out.created += 1 }
            case .keepBoth:
                if row.kind == .login {
                    var copy = Self.loginAsNote(row.draft, row.sourceRow)
                    copy.title = Self.prefix("\(row.draft.title) (imported copy)", Self.maxTitle)
                    try create(copy, row: row, into: &snap, at: stamp, date: date)
                    out.created += 1
                } else {
                    try create(row.draft, row: row, into: &snap, at: stamp, date: date)
                    out.created += 1
                    if let e = row.extra { try create(e, row: row, into: &snap, at: stamp, date: date); out.created += 1 }
                }
            case .replace(let id), .merge(let id):
                let replace = if case .replace = row.decision { true } else { false }
                try update(row, target: id, title: replace, in: &snap, at: stamp)
                out.updated += 1
                if row.kind != .login, let e = row.extra {
                    try create(e, row: row, into: &snap, at: stamp, date: date); out.created += 1
                }
            }
        }
        if out.created + out.updated > 0 {
            try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        }
        return out
    }

    private func create(_ d: ImportDraft, row: ImportRow, into snap: inout StoreSnapshot, at stamp: Int64, date: Date) throws {
        let record: [String: JSONValue]
        let ns: Namespace
        switch d.kind {
        case .login:
            var r = EditorModel.newRecord(kind: .web, now: stamp, random: random)
            r["label"] = .string(d.title)
            r["username"] = .string(d.username)
            r["password"] = .string(d.password)
            var scope: [String: JSONValue] = ["origin": .string(row.origin)]
            let pages = Self.webPages(d.urls, origins: row.webURLs)
            if row.webURLs.count > 1 || !pages.isEmpty { scope["urls"] = Self.urlRows(row.webURLs, pages: pages) }
            r["scope"] = .object(scope)
            if !d.notes.isEmpty { r["notes"] = .string(d.notes) }
            if let t = Self.totpValue(d.totp) { r["totp"] = t }
            if !d.customFields.isEmpty { r["custom_fields"] = Self.fieldsJSON(d.customFields) }
            r["tags"] = .array(d.tags.map(JSONValue.string))
            r["favorite"] = .bool(d.favourite)
            record = r; ns = .entry
        case .passkey:
            guard let p = d.passkey, let key = PasskeyKey(pkcs8B64URL: base64URLNoPad(Array(p.pkcs8))) else {
                throw ImportReviewError.invalid(row: row.sourceRow, String(localized: "the passkey's private key could not be read"))
            }
            let made = PasskeyRecord.newPayload(rpID: p.rpID, rpName: "", userName: p.userName,
                                                userDisplayName: p.userDisplayName, userHandle: Array(p.userHandle),
                                                credentialID: Array(p.credentialID), key: key, today: Self.day(date))
            record = ["id": .string(EditorModel.uuid4(random)), "kind": .string("passkey"),
                      "title": .string(d.title.isEmpty ? made.title : d.title), "payload": made.fields,
                      "created_at": .int(stamp), "updated_at": .int(stamp), "favorite": .bool(false), "tags": .array([])]
            ns = .item
        case .note, .card, .identity:
            var r = EditorModel.newRecord(kind: EditorKind(rawValue: d.kind.rawValue)!, now: stamp, random: random)
            r["title"] = .string(d.title)
            var tags = d.tags
            // The phone and the Mac have no collections: the folder becomes a tag (Windows' fallback).
            if !d.folder.isEmpty { tags = Self.cleanTags(tags + [Self.folderTag(d.folder)]) }
            r["tags"] = .array(tags.map(JSONValue.string))
            r["favorite"] = .bool(d.favourite)
            r["payload"] = .object(Self.payload(d))
            record = r; ns = .item
        }
        guard Self.put(record, ns: ns, into: &snap, isNew: true) != nil else {
            throw ImportReviewError.invalid(row: row.sourceRow, String(localized: "the item could not be saved"))
        }
    }

    private func update(_ row: ImportRow, target id: String, title: Bool, in snap: inout StoreSnapshot, at stamp: Int64) throws {
        guard snap.meta[id]?.deleted != true, case .object(let w)? = snap.records[id],
              case .object(var rec)? = w["record"] else { throw ImportReviewError.targetChanged }
        guard let reviewed = row.targetRecord, EditorModel.same(.object(rec), reviewed) else {
            throw ImportReviewError.targetRevisionChanged
        }
        let d = row.draft
        let tags = Self.cleanTags((rec["tags"]?.arrayValue ?? []).compactMap(\.stringValue) + d.tags)
        rec["tags"] = .array(tags.map(JSONValue.string))
        rec["favorite"] = .bool(d.favourite || rec["favorite"] == .bool(true))
        let ns: Namespace
        if row.kind == .login {
            if title { rec["label"] = .string(d.title) }
            if !(rec["password"]?.stringValue ?? "").utf8.elementsEqual(d.password.utf8) {
                rec = Self.withNewPassword(rec, d.password, at: stamp)
            }
            if !d.notes.isEmpty { rec["notes"] = .string(d.notes) }
            if let t = Self.totpValue(d.totp) { rec["totp"] = t }
            if !d.customFields.isEmpty { rec["custom_fields"] = Self.fieldsJSON(d.customFields) }
            let pages = Self.webPages(d.urls, origins: row.webURLs)
            if row.webURLs.count > 1 || !pages.isEmpty, case .object(var scope)? = rec["scope"] {
                // A login without rows has just its origin (desktop `web_urls` migrates it the same way).
                let existing = scope["urls"]?.arrayValue
                    ?? (scope["origin"]?.stringValue.map { [Self.urlRow($0, "exact_origin")] } ?? [])
                let added = Self.urlRows(row.webURLs, pages: pages).arrayValue!.filter { !existing.contains($0) }
                scope["urls"] = .array(Array((existing + added).prefix(Self.maxWebURLs)))
                rec["scope"] = .object(scope)
            }
            ns = .entry
        } else {
            if title { rec["title"] = .string(d.title) }
            var payload = Self.payload(d)
            if let t = rec["payload"]?.objectValue?["template_id"], t != .null { payload["template_id"] = t }
            rec["payload"] = .object(payload)
            ns = .item
        }
        rec["updated_at"] = .int(stamp)
        guard Self.put(rec, ns: ns, into: &snap) != nil else {
            throw ImportReviewError.invalid(row: row.sourceRow, String(localized: "the item could not be saved"))
        }
    }

    // MARK: normalise (Windows normalise_records)

    nonisolated static func normalise(_ candidates: [ImportCandidate]) -> ([ImportRow], [String]) {
        var rows: [ImportRow] = []
        var issues: [String] = []
        var seen: [[[UInt8]]: (Int, String)] = [:]
        var seenPasskeys: Set<String> = []
        var upgradedRows: [Int] = []
        func add(_ number: Int, _ d: ImportDraft, extra: ImportDraft? = nil, web: [String] = [],
                 base: ImportRowStatus = .new, decision: ImportDecision = .create) {
            rows.append(ImportRow(id: rows.count, sourceRow: number, draft: d, extra: extra, webURLs: web, base: base,
                                  decision: decision))
        }
        for (index, c) in candidates.enumerated() {
            let number = c.sourceRow ?? index + 1
            var d = draft(from: c)
            if hasNull(d) {
                let m = String(localized: "Row \(number): null characters in fields; skipped.")
                issues.append(m); add(number, d, base: .skipped(m), decision: .skip); continue
            }
            if !d.folder.isEmpty { d.folder = strip(d.folder.replacingOccurrences(of: "\\", with: "/"), "/ ") }
            d.tags = cleanTags(d.tags)
            fitFields(&d, number, &issues)
            switch d.kind {
            case .passkey:
                guard let p = d.passkey else { continue }
                let key = PasskeyRecord.normaliseRPID(p.rpID) + "\u{0}" + base64URLNoPad(Array(p.credentialID))
                if !seenPasskeys.insert(key).inserted { add(number, d, base: .duplicate, decision: .skip) } else { add(number, d) }
            case .login:
                let (web, other, upgraded) = webRows(d.urls)
                var reason = ""
                if web.isEmpty {
                    reason = d.urls.isEmpty
                        ? String(localized: "Row \(number): login has no website address; imported as a secure note.")
                        : String(localized: "Row \(number): login has no usable website address; imported as a secure note.")
                } else if d.password.isEmpty {
                    reason = String(localized: "Row \(number): login has no password; imported as a secure note.")
                }
                else if len(d.password) > 4096 || len(d.username) > 512 {
                    let m = String(localized: "Row \(number): password or username is longer than the vault allows; skipped.")
                    issues.append(m); add(number, d, base: .skipped(m), decision: .skip); continue
                }
                if !reason.isEmpty {
                    issues.append(reason)
                    var note = loginAsNote(d, number)
                    fitNotes(&note, number, &issues)
                    add(number, note); continue
                }
                if upgraded { upgradedRows.append(number) }
                for url in other {
                    let host = url.components(separatedBy: "://").last!.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
                    if !addField(&d, "Other website or app", url, hidden: host.contains("@")) {
                        issues.append(String(localized: "Row \(number): too many custom fields; an extra address was not imported."))
                    }
                }
                if !d.totp.isEmpty, totpValue(d.totp) == nil {
                    issues.append(String(localized: "Row \(number): one-time password secret is not valid; kept as a hidden custom field."))
                    _ = addField(&d, "One-time password (unrecognised)", d.totp, hidden: true)
                    d.totp = ""
                }
                let tag = folderTag(d.folder)
                if !tag.isEmpty { d.tags = cleanTags(d.tags + [tag]) }
                fitNotes(&d, number, &issues)
                d.title = title(d, number, fallback: web[0])
                let key = [Array(web[0].utf8), Array(d.username.utf8)]
                if let (first, password) = seen[key] {
                    if password.utf8.elementsEqual(d.password.utf8) {
                        issues.append(String(localized: "Row \(number): same account as row \(first); skipped."))
                        add(number, d, web: web, base: .duplicate, decision: .skip)
                    } else {
                        issues.append(String(localized: "Row \(number): same website and username as row \(first) but a different password; it will be kept as a secure note copy (choose Skip to drop it)."))
                        add(number, d, web: web, base: .duplicate, decision: .keepBoth)
                    }
                } else {
                    seen[key] = (number, d.password)
                    add(number, d, web: web)
                }
            case .card:
                if !d.card.isEmpty {
                    if let problem = cardProblem(d) {
                        issues.append(String(localized: "Row \(number): card details could not be stored as a payment card (\(problem)); imported as a secure note."))
                        var note = cardAsNote(d, number)
                        fitNotes(&note, number, &issues)
                        add(number, note); continue
                    }
                    d.title = title(d, number)
                    let extra = companion(d, d.title, d.customFields)
                    d.customFields = []
                    add(number, d, extra: extra.map { fitted($0, number, &issues) }); continue
                }
                var note = cardAsNote(d, number)
                fitNotes(&note, number, &issues)
                note.title = title(note, number)
                add(number, fitted(note, number, &issues))
            case .identity:
                var extraFields: [ImportCustomField] = []
                var kept: [String: String] = [:]
                var total = 0
                for name in d.identity.keys.sorted() {
                    let value = d.identity[name]!
                    guard let limit = identityLimits[name], len(value) <= limit, total + len(value) <= identityMaxTotal else {
                        extraFields.append(ImportCustomField(name: capitalize(name.replacingOccurrences(of: "_", with: " ")),
                                                             value: prefix(value, maxFieldValue), hidden: false))
                        continue
                    }
                    kept[name] = value; total += len(value)
                }
                if !extraFields.isEmpty {
                    let names = Set(extraFields.map { Casefold.fold($0.name) }).sorted().joined(separator: ", ")
                    issues.append(String(localized: "Row \(number): identity values without a matching identity field (\(names)) were kept in an 'extra details' secure note."))
                }
                d.identity = kept
                d.title = title(d, number)
                var extra = companion(d, d.title, extraFields + d.customFields, notes: d.notes)
                if extra != nil { fitNotes(&extra!, number, &issues) }
                add(number, d, extra: extra.map { fitted($0, number, &issues) })
            case .note:
                fitNotes(&d, number, &issues)
                d.title = title(d, number)
                add(number, fitted(d, number, &issues))
            }
        }
        if !upgradedRows.isEmpty {
            let shown = upgradedRows.prefix(10).map(String.init).joined(separator: ", ") + (upgradedRows.count > 10 ? " ..." : "")
            let upgradedCount = upgradedRows.count
            issues.append(String(localized: "\(upgradedCount) login(s) used plain http:// addresses and were saved for https:// (rows \(shown)); LocalGateKeys only fills passwords over HTTPS."))
        }
        return (rows, issues)
    }

    private nonisolated static func fitted(_ d: ImportDraft, _ number: Int, _ issues: inout [String]) -> ImportDraft {
        var d = d; fitFields(&d, number, &issues); return d
    }

    /// The candidate as a Windows `ImportedRecord`. A two-factor key on a note, card or identity has no field of
    /// its own there: it is kept as a hidden custom field, as Windows keeps a login's key in a secure note.
    nonisolated static func draft(from c: ImportCandidate) -> ImportDraft {
        var d = ImportDraft(kind: .note, title: c.title, urls: c.urls, customFields: c.customFields, tags: c.tags,
                            folder: c.folder, favourite: c.favourite)
        switch c.kind {
        case .login(let f):
            d.kind = .login; d.username = f.username; d.password = f.password; d.notes = f.notes; d.totp = f.otpauth ?? ""
        case .passkey(let p): d.kind = .passkey; d.passkey = p
        case .note(let f): d.kind = .note; d.notes = f.notes
        case .card(let f): d.kind = .card; d.notes = f.notes; d.card = f.values
        case .identity(let f): d.kind = .identity; d.notes = f.notes; d.identity = f.values
        }
        if d.kind != .login, d.kind != .passkey, let t = c.totp, !t.isEmpty {
            _ = addField(&d, "One-time password (otpauth)", t, hidden: true)
        }
        return d
    }

    /// Windows `_keep_totp_as_fields`: on the free plan a login's two-factor key becomes a hidden custom field.
    nonisolated static func keepTOTPAsFields(_ rows: inout [ImportRow]) -> [String] {
        var kept = 0
        for i in rows.indices where rows[i].kind == .login && !rows[i].draft.totp.isEmpty {
            if addField(&rows[i].draft, "Two-factor key (needs Pro)", rows[i].draft.totp, hidden: true) {
                rows[i].draft.totp = ""; kept += 1
            }
        }
        guard kept > 0 else { return [] }
        return [String(localized: "Two-factor codes need LocalGateKeys Pro: \(kept) keys kept as hidden custom fields.")]
    }

    // MARK: classify (Windows classify_rows)

    nonisolated static func classify(_ rows: inout [ImportRow], against snap: StoreSnapshot) {
        var logins: [[[UInt8]]: (String, [String: JSONValue])] = [:]
        var catalog: [String: (String, [String: JSONValue])] = [:]
        for id in snap.records.keys.sorted() where snap.meta[id]?.deleted != true {
            guard case .object(let w)? = snap.records[id], case .object(let r)? = w["record"] else { continue }
            if w["ns"] == .string(Namespace.entry.rawValue), r["kind"] == .string("web"),
               case .string(let raw)? = r["scope"]?.objectValue?["origin"], let origin = try? Origin.canonicalize(raw) {
                let key = [Array(origin.utf8), Array((r["username"]?.stringValue ?? "").utf8)]
                if logins[key] == nil { logins[key] = (id, r) }
            } else if w["ns"] == .string(Namespace.item.rawValue), case .string(let kind)? = r["kind"] {
                let key = kind + "\u{0}" + Casefold.fold(r["title"]?.stringValue ?? "")
                if catalog[key] == nil { catalog[key] = (id, r) }
            }
        }
        for i in rows.indices {
            let row = rows[i]
            if row.isSkippedSource { continue }
            if row.inImportDuplicate {
                // A copy kept by an earlier run of the same import is not made again.
                if row.decision == .keepBoth, row.kind == .login {
                    var copy = loginAsNote(row.draft, row.sourceRow)
                    copy.title = prefix("\(row.draft.title) (imported copy)", maxTitle)
                    if let (_, r) = catalog["note\u{0}" + Casefold.fold(copy.title)], sameItem(r, copy) { rows[i].decision = .skip }
                }
                continue
            }
            let target: (String, [String: JSONValue])
            let same: Bool
            switch row.kind {
            case .login:
                guard let t = logins[[Array(row.origin.utf8), Array(row.username.utf8)]] else { continue }
                target = t
                same = (t.1["password"]?.stringValue ?? "").utf8.elementsEqual(row.draft.password.utf8)
            case .passkey:
                guard let p = row.draft.passkey, let id = passkeyID(p, in: snap),
                      case .object(let w)? = snap.records[id], case .object(let r)? = w["record"] else { continue }
                target = (id, r); same = true
            case .note, .card, .identity:
                guard let t = catalog[row.kind.rawValue + "\u{0}" + Casefold.fold(row.title)] else { continue }
                target = t; same = sameItem(t.1, row.draft)
            }
            rows[i].targetID = target.0
            rows[i].targetRecord = .object(target.1)
            rows[i].base = same ? .duplicate : .conflict
            rows[i].decision = .skip
        }
    }

    private nonisolated static func sameItem(_ stored: [String: JSONValue], _ d: ImportDraft) -> Bool {
        let p = stored["payload"]?.objectValue ?? [:]
        switch d.kind {
        case .note:
            return p["body"]?.stringValue ?? "" == d.notes && (p["fields"] ?? .array([])) == fieldsJSON(d.customFields)
        case .card:
            let wanted = normalisedCard(d) ?? [:]
            return ["number", "expiry", "cardholder"].allSatisfy { (p[$0] ?? .string("")) == (wanted[$0] ?? .string("")) }
        case .identity:
            var stored = p; stored["template_id"] = nil
            return stored == d.identity.mapValues(JSONValue.string)
        case .login, .passkey: return false
        }
    }

    // MARK: Windows helpers

    nonisolated static func len(_ s: String) -> Int { s.unicodeScalars.count }

    /// The first `n` code points (Python slicing).
    nonisolated static func prefix(_ s: String, _ n: Int) -> String {
        String(String.UnicodeScalarView(s.unicodeScalars.prefix(n)))
    }

    nonisolated static func strip(_ s: String, _ chars: String? = nil) -> String {
        guard let chars else { return s.trimmingCharacters(in: .whitespacesAndNewlines) }
        return s.trimmingCharacters(in: CharacterSet(charactersIn: chars))
    }

    private nonisolated static func capitalize(_ s: String) -> String {
        guard let first = s.first else { return s }
        return String(first).uppercased() + s.dropFirst().lowercased()
    }

    /// Windows `_web_url`: (canonical origin, upgraded from http), or nil when the text is not a website.
    nonisolated static func webURL(_ value: String) -> (String, Bool)? {
        var text = strip(value)
        guard !text.isEmpty, !text.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) }),
              len(text) <= 2048 else { return nil }
        if !text.contains("://") {
            let host = text.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
            guard host.contains("."), !host.hasPrefix("."), !host.contains("@") else { return nil }
            text = "https://" + text
        }
        guard let sep = text.range(of: "://") else { return nil }
        let scheme = text[..<sep.lowerBound].lowercased()
        let rest = String(text[sep.upperBound...])
        let netloc = String(rest.prefix { $0 != "/" && $0 != "?" && $0 != "#" })
        if netloc.contains("@") { return nil }
        var host = netloc.lowercased()
        if host.hasPrefix("["), let close = host.firstIndex(of: "]") { host = String(host[host.index(after: host.startIndex)..<close]) }
        else if let colon = host.firstIndex(of: ":") { host = String(host[..<colon]) }
        var upgraded = false
        if scheme == "http", !["localhost", "127.0.0.1", "::1"].contains(host) { text = "https://" + rest; upgraded = true }
        guard let origin = try? Origin.canonicalize(Origin.originOf(text)) else { return nil }
        return (origin, upgraded)
    }

    /// Windows `_web_rows`: (website origins, at most 20; other addresses; any upgraded).
    nonisolated static func webRows(_ urls: [String]) -> ([String], [String], Bool) {
        var rows: [String] = [], other: [String] = [], upgradedAny = false
        for url in urls {
            guard let (origin, upgraded) = webURL(url) else { other.append(url); continue }
            upgradedAny = upgradedAny || upgraded
            if !rows.contains(where: { $0.utf8.elementsEqual(origin.utf8) }) { rows.append(origin) }
        }
        if rows.count > maxWebURLs { other += rows[maxWebURLs...]; rows = Array(rows.prefix(maxWebURLs)) }
        return (rows, other, upgradedAny)
    }

    /// Windows `_web_page` (2026-10-29): the full page address of a website URL whose origin is `origin`, or nil
    /// when it is just the site. Same upgrade rules as `webURL`; `normalize_url` form (no fragment).
    nonisolated static func webPage(_ value: String, origin: String) -> String? {
        var text = strip(value)
        if !text.contains("://") { text = "https://" + text }
        if text.prefix(7).lowercased() == "http://", !origin.hasPrefix("http://") { text = "https://" + text.dropFirst(7) }
        guard let page = try? Origin.normalizeURL(text),
              let pageOrigin = try? Origin.canonicalize(Origin.originOf(page)),
              pageOrigin.utf8.elementsEqual(origin.utf8) else { return nil }
        return page.utf8.elementsEqual(origin.utf8) || page.utf8.elementsEqual((origin + "/").utf8) ? nil : page
    }

    /// Windows `_web_rows` page rows: the full addresses of `urls` (deduplicated) on one of `origins`. They are stored
    /// as `starts_with` rows after the exact-origin rows, so they match only pages those rows already match.
    nonisolated static func webPages(_ urls: [String], origins: [String]) -> [String] {
        var out: [String] = []
        for url in urls {
            guard let (origin, _) = webURL(url), origins.contains(where: { $0.utf8.elementsEqual(origin.utf8) }),
                  let page = webPage(url, origin: origin), !out.contains(where: { $0.utf8.elementsEqual(page.utf8) }) else { continue }
            out.append(page)
        }
        return out
    }

    nonisolated static func urlRow(_ url: String, _ match: String) -> JSONValue {
        .object(["url": .string(url), "match": .string(match)])
    }

    nonisolated static func urlRows(_ origins: [String], pages: [String] = []) -> JSONValue {
        .array(Array((origins.map { urlRow($0, "exact_origin") } + pages.map { urlRow($0, "starts_with") }).prefix(maxWebURLs)))
    }

    /// Windows `_add_field`: false when the field did not fit whole.
    @discardableResult
    nonisolated static func addField(_ d: inout ImportDraft, _ name: String, _ value: String, hidden: Bool) -> Bool {
        if value.isEmpty { return true }
        if d.customFields.count >= maxFields { return false }
        d.customFields.append(ImportCustomField(name: prefix(name, maxFieldName), value: prefix(value, maxFieldValue), hidden: hidden))
        return len(value) <= maxFieldValue
    }

    /// Windows `_fit_notes`: notes past the vault limit move into "Notes (continued N)" fields.
    nonisolated static func fitNotes(_ d: inout ImportDraft, _ number: Int, _ issues: inout [String], limit: Int = maxNoteBody) {
        guard len(d.notes) > limit else { return }
        var overflow = Array(d.notes.unicodeScalars.dropFirst(limit))
        d.notes = prefix(d.notes, limit)
        var part = 1
        while !overflow.isEmpty, d.customFields.count < maxFields {
            d.customFields.append(ImportCustomField(name: "Notes (continued \(part))",
                                                    value: String(String.UnicodeScalarView(overflow.prefix(maxFieldValue))), hidden: false))
            overflow = Array(overflow.dropFirst(maxFieldValue)); part += 1
        }
        if !overflow.isEmpty {
            let count = grouped(overflow.count)
            issues.append(String(localized: "Row \(number): notes are longer than the vault allows; the last \(count) characters were not imported."))
        }
    }

    /// Windows `_fit_fields`: at most 50 fields, 100-character names, 4,096-character values.
    nonisolated static func fitFields(_ d: inout ImportDraft, _ number: Int, _ issues: inout [String]) {
        d.customFields = d.customFields.prefix(maxFields).map { f in
            let name = prefix(f.name, maxFieldName)
            var value = f.value
            if len(value) > maxFieldValue {
                let limit = grouped(maxFieldValue)
                issues.append(String(localized: "Row \(number): custom field '\(name)' was shortened to \(limit) characters."))
                value = prefix(value, maxFieldValue)
            }
            return ImportCustomField(name: name, value: value, hidden: f.hidden)
        }
    }

    private nonisolated static func grouped(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal; f.groupingSeparator = ","; f.locale = Locale(identifier: "en_US_POSIX")
        f.usesGroupingSeparator = true; f.groupingSize = 3
        return f.string(from: NSNumber(value: n)) ?? String(n)
    }

    nonisolated static func hasNull(_ d: ImportDraft) -> Bool {
        var values = [d.title, d.username, d.password, d.notes, d.totp, d.folder] + d.urls
        values += Array(d.identity.values) + Array(d.card.values)
        for f in d.customFields { values += [f.name, f.value] }
        return values.contains { $0.unicodeScalars.contains("\u{0}") }
    }

    /// Windows `_folder_tag`: "Work / Sub", the last 40 characters.
    nonisolated static func folderTag(_ folder: String) -> String {
        let parts = folder.replacingOccurrences(of: "\\", with: "/").components(separatedBy: "/").map { strip($0) }.filter { !$0.isEmpty }
        let text = parts.joined(separator: " / ")
        return strip(String(String.UnicodeScalarView(text.unicodeScalars.suffix(maxTagLength))))
    }

    /// Windows `_clean_tags`: stripped, 40 characters, no repeats, at most 20.
    nonisolated static func cleanTags(_ tags: [String]) -> [String] {
        var out: [String] = []
        for tag in tags {
            let text = prefix(strip(tag), maxTagLength)
            if !text.isEmpty, !out.contains(where: { $0.unicodeScalars.elementsEqual(text.unicodeScalars) }) { out.append(text) }
        }
        return Array(out.prefix(maxTags))
    }

    /// Windows `_title`: the title, else the fallback, username or first address, at most 512 characters.
    nonisolated static func title(_ d: ImportDraft, _ number: Int, fallback: String = "") -> String {
        let raw = [d.title, fallback, d.username, d.urls.first ?? ""].first { !$0.isEmpty } ?? "Imported row \(number)"
        let text = prefix(strip(raw), maxTitle)
        return text.isEmpty ? "Imported row \(number)" : text
    }

    /// The vault `totp` object for an `otpauth://` URI, or nil when it is not valid (Windows `totp_dict`).
    nonisolated static func totpValue(_ uri: String) -> JSONValue? {
        guard !uri.isEmpty, let c = try? TOTP.parseOtpauthURI(uri) else { return nil }
        return .object(["secret": .string(c.secret), "algorithm": .string(c.algorithm),
                        "digits": .int(Int64(c.digits)), "period": .int(Int64(c.period))])
    }

    nonisolated static func fieldsJSON(_ fields: [ImportCustomField]) -> JSONValue {
        .array(fields.map { .object(["name": .string($0.name), "value": .string($0.value), "hidden": .bool($0.hidden)]) })
    }

    /// Windows `_login_as_note`: a secure note keeping every value of a login.
    nonisolated static func loginAsNote(_ d: ImportDraft, _ number: Int) -> ImportDraft {
        var fields: [ImportCustomField] = []
        for (i, url) in d.urls.enumerated() {
            fields.append(ImportCustomField(name: i == 0 ? "Website" : "Website \(i + 1)", value: prefix(url, maxFieldValue), hidden: false))
        }
        if !d.username.isEmpty { fields.append(ImportCustomField(name: "Username", value: prefix(d.username, maxFieldValue), hidden: false)) }
        if !d.password.isEmpty { fields.append(ImportCustomField(name: "Password", value: prefix(d.password, maxFieldValue), hidden: true)) }
        if !d.totp.isEmpty {
            fields.append(ImportCustomField(name: "One-time password (otpauth)", value: prefix(d.totp, maxFieldValue), hidden: true))
        }
        fields += d.customFields
        return ImportDraft(kind: .note, title: title(d, number), notes: d.notes, customFields: Array(fields.prefix(maxFields)),
                           tags: d.tags, folder: d.folder, favourite: d.favourite)
    }

    /// Windows `_card_as_note`.
    nonisolated static func cardAsNote(_ d: ImportDraft, _ number: Int) -> ImportDraft {
        let labels = [("cardholder", "Cardholder", false), ("number", "Card number", true), ("expiry", "Expiry", false),
                      ("cvv", "Security code", true), ("pin", "PIN", true), ("brand", "Brand", false)]
        var fields = labels.compactMap { key, label, hidden in
            d.card[key].flatMap { $0.isEmpty ? nil : ImportCustomField(name: label, value: $0, hidden: hidden) }
        }
        fields += d.customFields
        return ImportDraft(kind: .note, title: title(d, number), notes: d.notes, customFields: Array(fields.prefix(maxFields)),
                           tags: d.tags, folder: d.folder, favourite: d.favourite)
    }

    /// Windows `_companion`: the "extra details" note for values a card or identity cannot hold.
    nonisolated static func companion(_ d: ImportDraft, _ title: String, _ fields: [ImportCustomField], notes: String = "") -> ImportDraft? {
        if fields.isEmpty && notes.isEmpty { return nil }
        return ImportDraft(kind: .note, title: prefix("\(title) (extra details)", maxTitle), notes: notes,
                           customFields: Array(fields.prefix(maxFields)), tags: d.tags, folder: d.folder)
    }

    /// Windows `card_payload` before validation: a `MM/20YY` expiry becomes `MM/YY`.
    nonisolated static func cardFields(_ d: ImportDraft) -> [String: JSONValue] {
        var expiry = d.card["expiry"] ?? ""
        let parts = expiry.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
        if parts.count == 2, parts[1].count == 4, parts[1].hasPrefix("20") { expiry = parts[0] + "/" + parts[1].dropFirst(2) }
        return ["cardholder": .string(d.card["cardholder"] ?? ""), "number": .string(d.card["number"] ?? ""),
                "expiry": .string(expiry), "cvv": .string(d.card["cvv"] ?? ""), "pin": .string(d.card["pin"] ?? ""),
                "notes": .string(d.notes)]
    }

    /// The card payload as the vault stores it, or nil when the vault refuses it.
    nonisolated static func normalisedCard(_ d: ImportDraft) -> [String: JSONValue]? {
        let record: JSONValue = .object(["id": .string("00000000-0000-4000-8000-000000000000"), "kind": .string("card"),
                                         "title": .string("card"), "created_at": .int(0), "updated_at": .int(0),
                                         "payload": .object(cardFields(d))])
        guard case .object(let o)? = try? Normalise.normalForm(ns: .item, record: record) else { return nil }
        return o["payload"]?.objectValue
    }

    private nonisolated static func cardProblem(_ d: ImportDraft) -> String? {
        let record: JSONValue = .object(["id": .string("00000000-0000-4000-8000-000000000000"), "kind": .string("card"),
                                         "title": .string("card"), "created_at": .int(0), "updated_at": .int(0),
                                         "payload": .object(cardFields(d))])
        do { _ = try Normalise.normalForm(ns: .item, record: record); return nil } catch {
            if case NormaliseError.rejected(let m) = error { return m }
            return "\(error)"
        }
    }

    nonisolated static func payload(_ d: ImportDraft) -> [String: JSONValue] {
        switch d.kind {
        case .card: return cardFields(d)
        case .identity: return d.identity.mapValues(JSONValue.string)
        default: return ["body": .string(d.notes), "fields": fieldsJSON(d.customFields)]
        }
    }

    // MARK: shared with VaultImporter and SafariImporter

    /// The live web login with this canonical origin and exactly this username (desktop `_web_login_match`).
    /// Deleted items are not matched.
    nonisolated static func match(origin: String, username: String, in snapshot: StoreSnapshot) -> String? {
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

    /// `stored` with `password` replaced; the old one goes to the front of `password_history` (at most 5).
    nonisolated static func withNewPassword(_ stored: [String: JSONValue], _ password: String, at now: Int64) -> [String: JSONValue] {
        var record = stored
        var history = record["password_history"]?.arrayValue ?? []
        history.insert(.object(["password": .string(stored["password"]?.stringValue ?? ""), "changed_at": .int(now)]), at: 0)
        record["password_history"] = .array(Array(history.prefix(historyLimit)))
        record["password"] = .string(password)
        record["updated_at"] = .int(now)
        if case .int(let created)? = record["created_at"], created > now { record["created_at"] = .int(now) }
        return record
    }

    /// Normalises and wraps the record into the snapshot as the editor does. The record id, or nil when
    /// `Normalise` refuses it or a new id collides.
    @discardableResult
    nonisolated static func put(_ record: [String: JSONValue], ns: Namespace, into snapshot: inout StoreSnapshot,
                                isNew: Bool = false) -> String? {
        guard let normal = try? Normalise.normalForm(ns: ns, record: .object(record)),
              case .object(let o) = normal, case .string(let id)? = o["id"] else { return nil }
        if isNew, snapshot.records[id] != nil { return nil }
        snapshot.records[id] = Wrapper.make(ns: ns, record: normal)
        return id
    }

    /// The live passkey with this relying party and credential id; passkeys are never overwritten.
    nonisolated static func passkeyID(_ p: PasskeyFields, in snapshot: StoreSnapshot) -> String? {
        let rp = PasskeyRecord.normaliseRPID(p.rpID), cred = base64URLNoPad(Array(p.credentialID))
        for id in snapshot.records.keys.sorted() where snapshot.meta[id]?.deleted != true {
            guard case .object(let o)? = snapshot.records[id], o["ns"] == .string(Namespace.item.rawValue),
                  case .object(let rec)? = o["record"], rec["kind"] == .string("passkey"),
                  case .object(let payload)? = rec["payload"] else { continue }
            if PasskeyRecord.normaliseRPID(payload["relying_party_id"]?.stringValue ?? "") == rp,
               payload["credential_id"]?.stringValue == cred { return id }
        }
        return nil
    }

    nonisolated static func hasPasskey(_ p: PasskeyFields, in snapshot: StoreSnapshot) -> Bool { passkeyID(p, in: snapshot) != nil }

    nonisolated static func day(_ date: Date) -> String {
        let f = DateFormatter()
        f.calendar = Calendar(identifier: .gregorian); f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC"); f.dateFormat = "yyyy-MM-dd"
        return f.string(from: date)
    }

    nonisolated static func cap(_ messages: [String]) -> [String] {
        guard messages.count > maxDiagnostics else { return messages }
        let extra = messages.count - maxDiagnostics
        return Array(messages.prefix(maxDiagnostics)) + [String(localized: "...and \(extra) more messages.")]
    }
}
