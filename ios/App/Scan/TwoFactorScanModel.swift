import Foundation
import Observation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// A login a scanned 2FA key could be added to.
struct ScanLoginMatch: Identifiable, Equatable, Sendable {
    let id: String
    let title: String
    let username: String
    /// The site's host, for the row.
    let site: String
    /// The login already has a 2FA key (adding replaces it).
    let hasKey: Bool
    /// Both the issuer and the account name match (a bulk import adds keys only to such a login).
    let strong: Bool
}

/// The "Scan QR code" flow shared by the iPhone (camera or Photos) and the Mac (image file, paste or drop).
/// QR payloads come from `TwoFactorQRDecoder` or the camera; they and the keys stay in memory only and are
/// dropped by `reset()`. One key goes to a login the person picks among the matches, or opens a new login
/// prefilled with the issuer and account. A Google Authenticator export lists its accounts (asking for each
/// further code of a multi-part export) and the chosen ones are imported in one commit through
/// `ImportReviewModel`, which handles duplicates and the free-plan slots. 2FA keys are Pro, as in the editor:
/// on the free plan nothing is saved and `showUpgrade` is set.
@MainActor @Observable
final class TwoFactorScanModel {
    enum Step: Equatable {
        case scanning
        /// One key, and the logins it may belong to.
        case chooseLogin(OTPAccount, [ScanLoginMatch])
        /// One key and no matching login: the view opens `newLoginEditor()`.
        case newLogin(OTPAccount)
        /// An export's accounts, with `selected`.
        case checklist
        /// Part `received` of a `total`-code export was read; the next code is needed.
        case nextPart(received: Int, total: Int)
        case finished(String)
    }

    static let wrongPartMessage = String(localized: "That isn't the next code of this export. Show the export's next QR code.")
    static let otherExportMessage = String(localized: "That code belongs to a different export. Scan the codes of one export.")
    static let nothingChosenMessage = String(localized: "Choose at least one account.")
    static let loginGoneMessage = String(localized: "That login is no longer in your vault.")
    /// Windows `password_tools.NEEDS_PASSWORD_TAG`: a login whose password is a generated placeholder.
    nonisolated static let needsPasswordTag = "needs-password"
    /// Windows `qr_accounts.NEEDS_PASSWORD_NOTE`, verbatim.
    nonisolated static let needsPasswordNote = String(localized: "Password not set — added from a 2FA QR code. Replace this generated password with your real one.")
    nonisolated static let maxScanAccounts = 256
    static let tooManyMessage = String(localized: "At most 256 accounts can be added from one scan. Add these, then scan the rest separately.")
    static func moreCodesNotice(_ n: Int) -> String {
        String(localized: "This image holds \(n + 1) QR codes; only the first was read. Crop the image to the code you want, or scan the others one at a time.")
    }

    /// Where one export account goes.
    enum Destination: Hashable, Sendable { case newLogin, existing(String) }

    /// One export account's row in the checklist (parallel to `accounts`).
    struct ExportRow: Equatable, Sendable {
        var target: Destination
        /// The new login's website (typed, or the suggestion once the person taps it).
        var website = ""
        /// The issuer when it looks like a domain ("From the QR code: x.com — use it?"); never filled silently.
        let suggestion: String?
        /// Logins offered for "Add to <login>".
        let matches: [ScanLoginMatch]
        /// The chosen login already has a 2FA key.
        var replacesKey: Bool { if case .existing(let id) = target { matches.first { $0.id == id }?.hasKey == true } else { false } }
    }

    private(set) var step: Step = .scanning
    private(set) var error: String?
    /// The export's usable accounts, in export order.
    private(set) var accounts: [OTPAccount] = []
    /// Export accounts that cannot be imported (HOTP, unsupported settings), without their keys.
    private(set) var skipped: [OTPSkippedAccount] = []
    /// Indices into `accounts` to import.
    var selected: Set<Int> = []
    /// The checklist rows of an export (parallel to `accounts`).
    var rows: [ExportRow] = []
    var showUpgrade = false
    /// Logins whose 2FA key the import would replace, waiting for "Replace" (nil when nothing to ask).
    private(set) var replaceQuestion: [String]?
    /// The single code's chosen login already has a key: the view asks before `addKey(to:confirmed: true)`.
    private(set) var confirmReplaceID: String?
    /// Information for the person (several codes in one image).
    private(set) var notice: String?
    /// Bumped by `reset()`: a decode that finishes for an earlier generation is dropped.
    private(set) var generation = 0
    @ObservationIgnored private var confirmedReplacements: Set<String> = []

    /// The scanned `otpauth://` link of a single key, kept as it was read (the editor stores it as typed).
    @ObservationIgnored private var scannedText: String?
    @ObservationIgnored private var parts: [Int: OTPMigrationBatch] = [:]
    @ObservationIgnored private var partCount = 0
    @ObservationIgnored private let store: any ItemStore
    @ObservationIgnored let pro: ProModel
    @ObservationIgnored private let clock: any UnixClock
    @ObservationIgnored private let random: any RandomSource
    @ObservationIgnored private let background: (any BackgroundTasking)?

    init(store: any ItemStore, pro: ProModel, clock: any UnixClock = SystemClock(), random: any RandomSource = SystemRandomSource(),
         background: (any BackgroundTasking)? = nil) {
        self.store = store; self.pro = pro; self.clock = clock; self.random = random; self.background = background
    }

    /// 2FA keys need Pro (the editor's rule); the views show the upgrade screen instead of scanning.
    var needsPro: Bool { !pro.isPro }

    /// The single key read, as scanned (or an export account's link): what the editor's 2FA field takes.
    var scannedKey: String? { scannedText ?? accounts.first?.uri }

    /// Accounts read so far over every part of the export.
    var receivedParts: Int { parts.count }

    // MARK: scanning

    /// QR payloads from an image or the camera (2FA codes only, as `TwoFactorQRDecoder` returns them). Only the
    /// first code is read (as on Windows); the person is told when the image held more. `generation` (taken
    /// before a decode started) drops a result that arrives after the sheet was closed or reset.
    func scanned(_ payloads: [String], generation: Int? = nil) {
        if let generation, generation != self.generation { return }
        error = nil; notice = nil
        let codes = TwoFactorQRDecoder.twoFactorTexts(payloads)
        guard let first = codes.first else { error = TwoFactorQRDecoder.Failure.notTwoFactor.message; return }
        if codes.count > 1 { notice = Self.moreCodesNotice(codes.count - 1) }
        let isExport = first.lowercased().hasPrefix("otpauth-migration:")
        if case .nextPart = step {
            guard isExport else { error = Self.wrongPartMessage; return }
            addPart(first)
            return
        }
        if isExport { addPart(first); return }
        do { single(try OTPAccount(otpauth: first), text: first) } catch let e as TOTPError {
            error = String(localized: "That QR code is not a usable 2FA key. \(TOTP.message(for: e))")
        } catch { self.error = TwoFactorQRDecoder.Failure.notTwoFactor.message }
    }

    func failed(_ failure: TwoFactorQRDecoder.Failure, generation: Int? = nil) {
        if let generation, generation != self.generation { return }
        error = failure.message
    }

    /// The camera could not start (no permission or no camera).
    func failed(message: String) { error = message }

    private func addPart(_ text: String) {
        let batch: OTPMigrationBatch
        do { batch = try OTPMigration.parse(text) } catch let e as OTPMigrationError {
            error = String(localized: "That export code could not be read: \(e.message)."); return
        } catch { self.error = TwoFactorQRDecoder.Failure.notTwoFactor.message; return }
        if partCount != 0, batch.batchSize != partCount { error = Self.otherExportMessage; return }
        if parts[batch.batchIndex] == nil {
            let total = parts.values.reduce(0) { $0 + $1.accounts.count + $1.skipped.count }
            guard total + batch.accounts.count + batch.skipped.count <= Self.maxScanAccounts else { error = Self.tooManyMessage; return }
            partCount = batch.batchSize
            parts[batch.batchIndex] = batch
        }
        if parts.count < partCount {
            step = .nextPart(received: parts.count, total: partCount)
            return
        }
        let ordered = parts.keys.sorted().compactMap { parts[$0] }
        let all = ordered.flatMap(\.accounts)
        let skips = ordered.flatMap(\.skipped)
        parts = [:]; partCount = 0
        if all.count == 1 && skips.isEmpty { single(all[0]); return }
        guard !all.isEmpty else {
            skipped = skips; accounts = []; selected = []
            error = String(localized: "None of the accounts in this export can be used here.")
            step = .checklist
            return
        }
        list(all, skipped: skips)
    }

    private func single(_ account: OTPAccount, text: String? = nil) {
        accounts = [account]; skipped = []; selected = [0]; scannedText = text
        guard let snap = try? store.load() else { step = .newLogin(account); return }
        let matches = Self.matches(for: account, in: snap)
        step = matches.isEmpty ? .newLogin(account) : .chooseLogin(account, matches)
    }

    private func list(_ all: [OTPAccount], skipped skips: [OTPSkippedAccount]) {
        accounts = all; skipped = skips; selected = Set(all.indices)
        let snap = try? store.load()
        rows = all.map { a in
            let matches = snap.map { Self.matches(for: a, in: $0) } ?? []
            let exact = snap.map { Self.exactMatches(for: a, in: $0) } ?? []
            let offered = exact.count == 1 && !matches.contains { $0.id == exact[0].id } ? [exact[0]] + matches : matches
            return ExportRow(target: exact.count == 1 ? .existing(exact[0].id) : .newLogin,
                             suggestion: Self.websiteSuggestion(a.issuer), matches: Array(offered.prefix(5)))
        }
        step = .checklist
    }

    /// Windows `guess`: the issuer when it is a bare domain ("example.com"), lower-cased.
    nonisolated static func websiteSuggestion(_ issuer: String) -> String? {
        let t = issuer.trimmingCharacters(in: .whitespaces)
        let labels = t.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, labels.allSatisfy({ !$0.isEmpty && $0.allSatisfy { ($0.isASCII && ($0.isLetter || $0.isNumber)) || $0 == "-" } })
        else { return nil }
        return t.lowercased()
    }

    /// Logins whose name is the issuer and whose username is the account, both exactly (ignoring case).
    static func exactMatches(for a: OTPAccount, in snapshot: StoreSnapshot) -> [ScanLoginMatch] {
        let issuer = Casefold.fold(a.issuer.trimmingCharacters(in: .whitespaces))
        let user = Casefold.fold(a.account.trimmingCharacters(in: .whitespaces))
        guard !issuer.isEmpty, !user.isEmpty else { return [] }
        return VaultItem.items(from: snapshot).filter { item in
            item.kind == "web" && Casefold.fold((item.record["label"]?.stringValue ?? item.title).trimmingCharacters(in: .whitespaces)) == issuer
                && Casefold.fold(item.username.trimmingCharacters(in: .whitespaces)) == user
        }.map { item in
            let origin = item.record["scope"]?.objectValue?["origin"]?.stringValue ?? ""
            return ScanLoginMatch(id: item.id, title: item.title, username: item.username,
                                  site: Casefold.fold(URL(string: origin)?.host() ?? ""),
                                  hasKey: item.record["totp"]?.objectValue?["secret"] != nil, strong: true)
        }
    }

    /// Every checked new-login row has a website.
    var canAdd: Bool {
        !selected.isEmpty && selected.allSatisfy { i in
            rows.indices.contains(i) && (rows[i].target != .newLogin || !rows[i].website.trimmingCharacters(in: .whitespaces).isEmpty)
        }
    }

    /// The person agreed to replace the keys named in `replaceQuestion`.
    func confirmReplacements() {
        for i in selected where rows.indices.contains(i) {
            if rows[i].replacesKey, case .existing(let id) = rows[i].target { confirmedReplacements.insert(id) }
        }
        replaceQuestion = nil
    }

    func cancelReplacements() { replaceQuestion = nil; confirmReplaceID = nil }

    /// Forgets the scan, its keys included.
    func reset() {
        step = .scanning; error = nil; accounts = []; skipped = []; selected = []; parts = [:]; partCount = 0; scannedText = nil
        showUpgrade = false; rows = []; replaceQuestion = nil; confirmReplaceID = nil; notice = nil; confirmedReplacements = []
        generation += 1
    }

    // MARK: matching

    /// Live web logins for the account: ones whose title or site match the issuer, or (for a code without an
    /// issuer) whose username is the account. Logins matching both come first.
    static func matches(for account: OTPAccount, in snapshot: StoreSnapshot) -> [ScanLoginMatch] {
        let issuer = Casefold.fold(account.issuer.trimmingCharacters(in: .whitespaces))
        let compact = issuer.filter { $0.isLetter || $0.isNumber }
        let user = Casefold.fold(account.account.trimmingCharacters(in: .whitespaces))
        var out: [ScanLoginMatch] = []
        for item in VaultItem.items(from: snapshot) where item.kind == "web" {
            let origin = item.record["scope"]?.objectValue?["origin"]?.stringValue ?? ""
            let host = Casefold.fold(URL(string: origin)?.host() ?? "")
            let title = Casefold.fold(item.title)
            let labels = host.split(separator: ".").map { String($0).filter { $0.isLetter || $0.isNumber } }
            let issuerHit = !issuer.isEmpty && (title.contains(issuer) || (!compact.isEmpty && labels.contains(compact))
                || (!compact.isEmpty && title.filter { $0.isLetter || $0.isNumber }.contains(compact)))
            let accountHit = !user.isEmpty && Casefold.fold(item.username) == user
            guard issuerHit || (issuer.isEmpty && accountHit) else { continue }
            out.append(ScanLoginMatch(id: item.id, title: item.title, username: item.username, site: host,
                                      hasKey: item.record["totp"]?.objectValue?["secret"] != nil,
                                      strong: issuerHit && accountHit))
        }
        return out.sorted { ($0.strong ? 0 : 1, Casefold.fold($0.title), $0.id) < ($1.strong ? 0 : 1, Casefold.fold($1.title), $1.id) }
    }

    // MARK: saving

    /// Adds the scanned key to a login through the editor's save (its validation and Pro rule).
    /// A login that already has a 2FA key is only changed with `confirmed` (else `confirmReplaceID` asks).
    @discardableResult func addKey(to id: String, confirmed: Bool = false) -> SaveResult {
        guard let account = accounts.first else { return .failed }
        error = nil; confirmReplaceID = nil
        guard let item = (try? store.load()).flatMap({ VaultItem.items(from: $0).first { $0.id == id } }), item.kind == "web" else {
            error = Self.loginGoneMessage; return .failed
        }
        if !confirmed, item.record["totp"]?.objectValue?["secret"] != nil { confirmReplaceID = id; return .invalid }
        let editor = EditorModel(store: store, pro: pro, editing: item, kind: .web, clock: clock, random: random,
                                 background: background, keepsPasswordHistory: false)
        editor.set("totp", scannedText ?? account.uri)
        let result = editor.save()
        switch result {
        case .saved, .unchanged:
            let name = item.title.isEmpty ? String(localized: "the login") : item.title
            step = .finished(result == .saved ? String(localized: "2FA key added to \(name).") : String(localized: "\(name) already has this 2FA key."))
            accounts = []
        case .needsPro: showUpgrade = true
        default: error = editor.totpError ?? editor.error ?? String(localized: "The 2FA key could not be saved.")
        }
        return result
    }

    /// A new login form prefilled with the issuer, account and key (nil on the free plan: `showUpgrade`).
    func newLoginEditor() -> EditorModel? {
        guard let account = accounts.first else { return nil }
        guard !needsPro else { showUpgrade = true; return nil }
        let editor = EditorModel(store: store, pro: pro, editing: nil, kind: .web, clock: clock, random: random,
                                 background: background, keepsPasswordHistory: true)
        editor.set("label", account.issuer.isEmpty ? account.account : account.issuer)
        editor.set("username", account.account)
        editor.set("totp", scannedText ?? account.uri)
        return editor
    }

    /// Imports the checked export accounts in one commit through `ImportReviewModel` (Windows `qr_accounts.add`):
    /// "Add to <login>" merges the key into that login (asking first when it replaces a key); "New login"
    /// creates a login for the typed website with a generated password, the tag needs-password and a note
    /// saying so. Returns the summary, or nil (with `error`, `replaceQuestion` or `showUpgrade`).
    func importSelected() async -> String? {
        error = nil
        guard !needsPro else { showUpgrade = true; return nil }
        let chosen = accounts.indices.filter { selected.contains($0) && rows.indices.contains($0) }
        guard !chosen.isEmpty else { error = Self.nothingChosenMessage; return nil }
        do {
            let snap = try store.load()
            let items = Dictionary(VaultItem.items(from: snap).map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
            struct Pick { let index: Int; let target: String?; let website: String; let username: String }
            var picks: [Pick] = []
            var unconfirmed: [String] = []
            for i in chosen {
                let a = accounts[i], row = rows[i]
                let name = a.issuer.isEmpty ? (a.account.isEmpty ? String(localized: "account \(i + 1)") : a.account) : a.issuer
                switch row.target {
                case .newLogin:
                    guard let origin = try? WebsiteInput.origin(row.website.trimmingCharacters(in: .whitespaces)) else {
                        error = String(localized: "Type the website address for \(name), for example example.com."); return nil
                    }
                    picks.append(Pick(index: i, target: nil, website: origin, username: a.account))
                case .existing(let id):
                    guard let login = items[id], login.kind == "web",
                          let origin = login.record["scope"]?.objectValue?["origin"]?.stringValue, !origin.isEmpty else {
                        error = String(localized: "The login chosen for \(name) no longer exists. Choose again."); return nil
                    }
                    if login.record["totp"]?.objectValue?["secret"] != nil, !confirmedReplacements.contains(id) {
                        unconfirmed.append(login.title.isEmpty ? origin : login.title)
                    }
                    picks.append(Pick(index: i, target: id, website: origin, username: login.username))
                }
            }
            guard unconfirmed.isEmpty else { replaceQuestion = unconfirmed; return nil }
            // Keys for chosen logins first: a new login that repeats one of them is the duplicate that is skipped.
            picks.sort { ($0.target == nil ? 1 : 0) < ($1.target == nil ? 1 : 0) }
            let generator = PasswordGenerator(random: random)
            var candidates: [ImportCandidate] = []
            for (n, p) in picks.enumerated() {
                let a = accounts[p.index]
                let title = String((a.issuer.isEmpty ? a.account : a.issuer).prefix(200))
                if let id = p.target, let login = items[id] {
                    candidates.append(ImportCandidate(title: login.title, kind: .login(LoginFields(
                        url: p.website, username: p.username, password: login.record["password"]?.stringValue ?? "",
                        notes: "", otpauth: a.uri)), sourceRow: n + 1))
                } else {
                    let password = try generator.password(GeneratorOptions())
                    candidates.append(ImportCandidate(title: title, kind: .login(LoginFields(
                        url: p.website, username: p.username, password: password, notes: Self.needsPasswordNote, otpauth: a.uri)),
                        tags: [Self.needsPasswordTag], sourceRow: n + 1))
                }
            }
            let review = ImportReviewModel(result: LGKCore.ImportResult(candidates: candidates), snapshot: snap,
                                           freeSlots: ImportReviewModel.freeSlots(snapshot: snap, isPro: pro.isPro),
                                           random: random)
            for row in review.rows {
                let p = picks[row.sourceRow - 1]
                if let id = p.target {
                    let stored = items[id]?.record["totp"]?.objectValue?["secret"]?.stringValue
                    if row.targetID == id, !row.inImportDuplicate, stored != accounts[p.index].config.secret {
                        review.set(.merge(id), for: row.id)
                    } else { review.set(.skip, for: row.id) }
                } else if row.kind != .login || row.status != .new {
                    review.set(.skip, for: row.id)
                }
            }
            let outcome = try await review.commit(to: store)
            let summary = Self.summary(outcome)
            step = .finished(summary)
            accounts = []; selected = []; rows = []; confirmedReplacements = []
            return summary
        } catch let e as ImportReviewError {
            if e == .itemLimit { showUpgrade = true } else { error = e.message }
        } catch {
            self.error = String(localized: "The accounts could not be saved on this device.")
        }
        return nil
    }

    #if DEBUG
    /// Preview hook (`LGK_MAC_SCAN`): puts the sheet on a step with made-up accounts (never real keys).
    func debugPreview(_ name: String) {
        func entry(_ i: Int, _ name: String, _ issuer: String) -> OTPMigration.Entry {
            OTPMigration.Entry(secret: Array("preview-key-\(i)-pad".utf8), name: name, issuer: issuer)
        }
        let demo = [entry(1, "alex@example.com", "GitHub"), entry(2, "alex", "Dropbox"), entry(3, "alex@example.com", "Proton"),
                    entry(4, "alex.m", "Discord")]
        switch name {
        case "checklist": scanned([OTPMigration.encode(demo)])
        case "part": scanned([OTPMigration.encode(Array(demo.prefix(2)), batchIndex: 0, batchSize: 2)])
        case "choose":
            let account = OTPAccount(issuer: "GitHub", account: "alex@example.com", config: TOTPConfig(secret: "GAYTEMZUGU3DOOBZ"))
            accounts = [account]; selected = [0]
            step = .chooseLogin(account, [ScanLoginMatch(id: "preview-1", title: "GitHub", username: "alex@example.com",
                                                         site: "github.com", hasKey: false, strong: true),
                                          ScanLoginMatch(id: "preview-2", title: "GitHub (work)", username: "alex@corp.example",
                                                         site: "github.com", hasKey: true, strong: false)])
        case "error": failed(.noQRCode)
        default: break
        }
    }
    #endif

    static func summary(_ o: ImportOutcome) -> String {
        let created = String(localized: "\(o.created) new logins with a 2FA code")
        let updated = String(localized: "2FA code added to \(o.updated) logins")
        var sentences: [String] = []
        switch (o.created > 0, o.updated > 0) {
        case (true, true): sentences.append(String(localized: "Added \(created) and \(updated)."))
        case (true, false): sentences.append(String(localized: "Added \(created)."))
        case (false, true): sentences.append(String(localized: "Added \(updated)."))
        case (false, false): sentences.append(String(localized: "Nothing was added: every ticked account is already in your vault."))
        }
        if o.created > 0 {
            sentences.append(String(localized: "New logins have a generated password and the tag needs-password: change it to your real one."))
        }
        let skipped = o.skipped + o.limited
        if skipped > 0 { sentences.append(String(localized: "\(skipped) skipped (already in your vault).")) }
        return sentences.joined(separator: " ")
    }
}

/// Sheets are presented by model (`.sheet(item:)`).
extension TwoFactorScanModel: Identifiable {
    nonisolated var id: ObjectIdentifier { ObjectIdentifier(self) }
}

/// The prefilled new login a scan asked for, as a sheet item.
struct ScannedLogin: Identifiable {
    let id = UUID()
    let editor: EditorModel
}
