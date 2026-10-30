import Foundation
import Observation
import LGKCore
import AppSharedMac

/// The colour of an issue row or panel meta (Windows `security_model.Tone`).
enum SecurityTone: Equatable { case neutral, accent, success, warning, danger }

/// The Security centre's login filters (Windows `health.FILTERS`).
enum SecurityFilter: String, CaseIterable, Identifiable, Hashable {
    case all, weak, reused, noTwoFactor, old, exposed
    var id: String { rawValue }

    var label: String {
        switch self {
        case .all: String(localized: "All")
        case .weak: String(localized: "Weak")
        case .reused: String(localized: "Reused")
        case .noTwoFactor: String(localized: "No 2FA")
        case .old: String(localized: "Old (>1 year)")
        case .exposed: String(localized: "Exposed (HIBP)")
        }
    }
}

/// One "issue to fix" row (Windows `security_model.Issue`); its button applies `filter`.
struct SecurityIssue: Equatable, Identifiable {
    enum Key: String { case breached, weak, reused, noTwoFactor, old }
    let key: Key
    let count: Int
    let title: String
    let description: String
    let tone: SecurityTone
    let actionLabel: String
    let filter: SecurityFilter
    var id: String { key.rawValue }
}

/// A panel row on the Security centre (Windows `PanelRow`); `action` is what its button does.
struct SecurityPanelRow: Equatable, Identifiable {
    enum Action: Equatable {
        case settings, toggleBreachChecks, toggleStrictOffline
        /// Opens the Import & export page.
        case importExport
        /// Opens the Recovery centre, optionally starting one of its actions.
        case recoveryCentre(RecoveryCentreModel.Initial?)
        /// Not on the Mac yet (encrypted transfer): no button.
        case later
    }
    let label: String
    let meta: String
    let buttonLabel: String?
    let action: Action
    var tone: SecurityTone = .neutral
    var id: String { label }
}

struct SecurityPanel: Equatable, Identifiable {
    let title: String
    let rows: [SecurityPanelRow]
    var id: String { title }
}

/// The Security centre (Windows `shell/security_model.py` + `app/health.py`): score, issues, filters, the
/// explicit HIBP checks and the panels. Breach results live in memory only and are dropped on lock.
@MainActor @Observable
final class SecurityModel {
    // Copy from Windows `app/health.py`.
    nonisolated static var offlineText: String { String(localized: "Strict offline mode is on. Turn it off in Privacy settings to run an explicit external check.") }
    nonisolated static var disabledText: String { String(localized: "Breach checks are off. Turning them on lets a check button send a 5-character hash prefix to HIBP. Nothing is checked automatically.") }
    nonisolated static var turnOnAndCheck: String { String(localized: "Turn on and check") }
    nonisolated static var runningText: String { String(localized: "Wait for the current breach check to finish.") }
    nonisolated static var oneTitle: String { String(localized: "Check selected password with HIBP?") }
    nonisolated static var oneText: String { String(localized: "Sends only a 5-character SHA-1 prefix over HTTPS with padding. The service sees your IP address. No password, full hash, username or website is sent.") }
    nonisolated static var allTitle: String { String(localized: "Check every password with HIBP?") }
    nonisolated static var cancelledText: String { String(localized: "Breach check cancelled.") }
    nonisolated static var subtitle: String { String(localized: "Local pattern checks are guidance, not a guarantee. Password age alone is not a reason to change it. Focus on reuse, guessability and known exposure.") }
    nonisolated static var footer: String { String(localized: "No check is performed automatically. Passwords, hashes and results are not logged.") }
    nonisolated static var footnote: String { String(localized: "Breach checks send only the first 5 characters of a password hash, and only when you start one. Strict offline mode blocks them.") }
    nonisolated static var laterText: String { String(localized: "Available in a later update") }
    nonisolated static let secondsPerRequest = 1.5
    nonisolated static let namesShown = 3

    /// Why a check did not start; `.disabled` offers "Turn on and check".
    enum Refusal: Equatable {
        case strictOffline, disabled, running
        var text: String {
            switch self {
            case .strictOffline: SecurityModel.offlineText
            case .disabled: SecurityModel.disabledText
            case .running: SecurityModel.runningText
            }
        }
    }

    /// The question asked before anything is sent.
    struct Confirmation: Identifiable, Equatable {
        let id = UUID()
        let title: String
        let text: String
        /// The logins to check; `replace` (Check all) replaces the breached set instead of adding to it.
        let logins: [HealthLogin]
        let replace: Bool
    }

    let settings: AppSettings
    /// Breached login ids from the last checks (fed to the overview's cards, chips and row tags).
    private(set) var breached: Set<String> = []
    /// Per-login result line ("Found in 3,201 breaches", "Not found", "Check failed: …").
    private(set) var exposure: [String: String] = [:]
    /// Logins whose last check found them in a breach (the result line is shown in red).
    private(set) var exposureFound: Set<String> = []
    private(set) var running = false
    /// "Checking… 3 of 12 unique passwords" while running; the result line after.
    private(set) var statusText: String?
    var refusal: (Refusal, retry: Confirmation?)?
    var confirmation: Confirmation?
    var filter: SecurityFilter = .all

    @ObservationIgnored private let transport: any BreachTransport
    @ObservationIgnored private let appVersion: String
    @ObservationIgnored private let pause: Duration
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var generation = 0

    @ObservationIgnored private let isUnlocked: @MainActor () -> Bool

    init(settings: AppSettings, transport: any BreachTransport, appVersion: String, pause: Duration = .seconds(1.5),
         isUnlocked: @escaping @MainActor () -> Bool = { true }) {
        self.settings = settings; self.transport = transport; self.appVersion = appVersion; self.pause = pause
        self.isUnlocked = isUnlocked
    }

    static var bundleVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
    }

    /// Clears breach results and cancels any running check whenever the vault locks.
    func clear(on lock: MacLockModel) {
        lock.onLock.append { [weak self] in self?.lockReset() }
    }

    /// Forgets every breach result and stops a running check (nothing it finds is kept).
    func lockReset() {
        generation += 1
        task?.cancel(); task = nil
        breached = []; exposure = [:]; exposureFound = []
        running = false; statusText = nil
        refusal = nil; confirmation = nil
        filter = .all
    }

    // MARK: starting a check

    /// "Check all passwords": refuses (strict offline / off / running) or asks the Windows question.
    func requestCheckAll(_ logins: [HealthLogin]) {
        guard isUnlocked() else { confirmation = nil; refusal = nil; return }
        let confirm = Confirmation(title: Self.allTitle, text: Self.scanAllText(unique: Self.uniqueCount(logins), logins: logins.count),
                                   logins: logins, replace: true)
        ask(confirm)
    }

    /// "Check this password" (a strict login passes the master-password gate before this).
    func requestCheckOne(_ login: HealthLogin) {
        ask(Confirmation(title: Self.oneTitle, text: Self.oneText, logins: [login], replace: false))
    }

    private func ask(_ confirm: Confirmation) {
        guard isUnlocked() else { confirmation = nil; refusal = nil; return }
        if settings.strictOfflineMode { refusal = (.strictOffline, nil); return }
        if !settings.breachCheckEnabled { refusal = (.disabled, confirm); return }
        if running { refusal = (.running, nil); return }
        refusal = nil
        confirmation = confirm
    }

    /// "Turn on and check": turns breach checks on, then asks the original question.
    func turnOnAndCheck() {
        guard let current = refusal, current.0 == .disabled else { return }
        settings.breachCheckEnabled = true
        refusal = nil
        if let retry = current.retry { ask(retry) }
    }

    /// The person agreed: runs the check in the background.
    func confirm() {
        guard let confirm = confirmation else { return }
        confirmation = nil
        guard isUnlocked() else { return }
        guard !settings.strictOfflineMode, settings.breachCheckEnabled, !running else { return ask(confirm) }
        start(confirm)
    }

    func cancelConfirmation() { confirmation = nil }

    /// Stops the running check; nothing it found is kept.
    func cancelScan() { task?.cancel() }

    /// Waits for the running check (tests).
    func waitForScan() async { await task?.value }

    private func start(_ confirm: Confirmation) {
        generation += 1
        let mine = generation
        let total = Self.uniqueCount(confirm.logins)
        running = true
        statusText = String(localized: "Checking 0 of \(total) unique passwords…")
        let defaults = UncheckedDefaults(defaults: settings.defaults)
        let checker = BreachChecker(transport: transport, appVersion: appVersion,
                                    strictOffline: { defaults.bool(AppSettings.Key.strictOfflineMode, true) },
                                    enabled: { defaults.bool(AppSettings.Key.breachCheckEnabled, false) },
                                    pause: pause)
        let logins = confirm.logins
        let (updates, sink) = AsyncStream.makeStream(of: (Int, Int).self, bufferingPolicy: .bufferingNewest(1))
        Task { [weak self] in
            for await (done, total) in updates where done > 0 {
                guard let self, self.generation == mine, self.running else { return }
                let shown = min(done, total)
                self.statusText = String(localized: "Checking… \(shown) of \(total) unique passwords")
            }
        }
        watchSettings(mine)
        task = Task { [weak self] in
            let result = await checker.scan(logins) { done, total in sink.yield((done, total)) }
            sink.finish()
            guard let self, self.generation == mine else { return }
            self.finish(result, logins: logins, replace: confirm.replace)
        }
    }

    /// Strict offline turned on or breach checks turned off: the running check stops at once (even mid-pause).
    private func watchSettings(_ mine: Int) {
        withObservationTracking {
            _ = settings.strictOfflineMode; _ = settings.breachCheckEnabled
        } onChange: { [weak self] in
            Task { @MainActor [weak self] in
                guard let self, self.generation == mine, self.running else { return }
                if self.settings.strictOfflineMode || !self.settings.breachCheckEnabled { self.task?.cancel() }
                else { self.watchSettings(mine) }
            }
        }
    }

    private func finish(_ result: BreachScanResult, logins: [HealthLogin], replace: Bool) {
        running = false; task = nil
        guard !result.cancelled, !Task.isCancelled else { statusText = Self.cancelledText; return }
        let found = result.breached
        for login in logins {
            if let count = result.counts[login.id] {
                let shown = count.formatted(.number)
                exposure[login.id] = count > 0
                    ? String(localized: "Found in \(shown) breaches")
                    : String(localized: "Not found")
                if count > 0 { exposureFound.insert(login.id) } else { exposureFound.remove(login.id) }
            } else if result.failed.contains(login.id) {
                let reason = BreachCheckError.failed.errorDescription ?? String(localized: "Check failed")
                exposure[login.id] = String(localized: "Check failed: \(reason)")
                exposureFound.remove(login.id)
            }
        }
        breached = replace ? found : breached.union(found)
        statusText = Self.resultText(result, logins: logins)
    }

    // MARK: copy

    /// Distinct non-empty passwords (each is requested once).
    nonisolated static func uniqueCount(_ logins: [HealthLogin]) -> Int {
        Set(logins.map(\.password).filter { !$0.isEmpty }).count
    }

    /// Windows `health.scan_all_text`.
    nonisolated static func scanAllText(unique: Int, logins: Int) -> String {
        let seconds = Double(unique) * secondsPerRequest
        let minutes = Int((seconds / 60).rounded(.toNearestOrEven))
        let duration = seconds < 60 ? String(localized: "under a minute") : String(localized: "about \(minutes) minutes")
        let passwords = String(localized: "\(unique) unique passwords")
        let loginsText = String(localized: "\(logins) logins")
        return String(localized: "Checks \(passwords) from \(loginsText), one request about every 1.5 seconds (\(duration)). Each request sends only a 5-character SHA-1 prefix over HTTPS. The service sees your IP address. No password, full hash, username or website is sent. You can keep using the app while it runs.")
    }

    /// Windows's job-done line: unique passwords checked, logins exposed, unique passwords whose check failed.
    nonisolated static func resultText(_ result: BreachScanResult, logins: [HealthLogin]) -> String {
        let checked = Set(logins.filter { result.counts[$0.id] != nil || result.failed.contains($0.id) }.map(\.password)).count
        let errors = Set(logins.filter { result.failed.contains($0.id) }.map(\.password)).count
        let exposed = result.counts.values.filter { $0 > 0 }.count
        return String(localized: "Checked \(checked) unique passwords · \(exposed) logins exposed · \(errors) errors. Not found does not prove a password is safe.")
    }

    /// First three names (case-insensitive order), then "and N more" (Windows `_names`).
    nonisolated static func names(_ ids: Set<String>, titles: [String: String]) -> String {
        let names = Set(ids.compactMap { titles[$0] }.filter { !$0.isEmpty })
            .sorted { $0.lowercased() == $1.lowercased() ? $0 < $1 : $0.lowercased() < $1.lowercased() }
        guard !names.isEmpty else { return "" }
        let shown = names.prefix(namesShown).joined(separator: ", ")
        let rest = names.count - min(names.count, namesShown)
        return rest > 0 ? String(localized: "\(shown) and \(rest) more") : shown
    }

    /// Windows `issues_for`, in its order.
    nonisolated static func issues(_ health: VaultHealth?, titles: [String: String]) -> [SecurityIssue] {
        guard let health else { return [] }
        let present = Set(titles.keys)
        var out: [SecurityIssue] = []
        let breached = health.breached.intersection(present)
        if !breached.isEmpty {
            out.append(SecurityIssue(key: .breached, count: breached.count, title: String(localized: "Found in a data breach"),
                                     description: String(localized: "\(names(breached, titles: titles)) · these passwords appear in known breach lists"),
                                     tone: .danger, actionLabel: String(localized: "Change passwords"), filter: .exposed))
        }
        if !health.weak.isEmpty {
            out.append(SecurityIssue(key: .weak, count: health.weak.count, title: String(localized: "Weak passwords"),
                                     description: names(health.weak, titles: titles), tone: .warning,
                                     actionLabel: String(localized: "Review \(health.weak.count)"), filter: .weak))
        }
        if !health.reused.isEmpty {
            out.append(SecurityIssue(key: .reused, count: health.reused.count, title: String(localized: "Reused passwords"),
                                     description: String(localized: "\(names(health.reused, titles: titles)) share a password with another login"),
                                     tone: .warning, actionLabel: String(localized: "Review \(health.reused.count)"), filter: .reused))
        }
        if !health.noTwoFactor.isEmpty {
            out.append(SecurityIssue(key: .noTwoFactor, count: health.noTwoFactor.count, title: String(localized: "Two-factor not set up"),
                                     description: String(localized: "Add a one-time code to these logins where the site offers it"),
                                     tone: .accent, actionLabel: String(localized: "Set up 2FA"), filter: .noTwoFactor))
        }
        if !health.old.isEmpty {
            out.append(SecurityIssue(key: .old, count: health.old.count, title: String(localized: "Not changed in over a year"),
                                     description: String(localized: "Low risk; change when convenient"), tone: .neutral,
                                     actionLabel: String(localized: "Review \(health.old.count)"), filter: .old))
        }
        return out
    }

    /// Windows `headline_for`.
    nonisolated static func headline(_ health: VaultHealth?, issues: [SecurityIssue]) -> String {
        guard let health, let score = health.score else { return String(localized: "Add logins to see how healthy your passwords are.") }
        let scored = issues.filter { [.breached, .weak, .reused].contains($0.key) }.reduce(0) { $0 + $1.count }
        if score >= 100 || scored == 0 { return String(localized: "\(health.label) overall. Nothing urgent to fix.") }
        return String(localized: "\(health.label) overall. Fixing the flagged logins below would bring you to 100.")
    }

    /// The logins a filter shows.
    nonisolated static func ids(_ filter: SecurityFilter, health: VaultHealth?, all: [String]) -> Set<String> {
        guard let health else { return filter == .all ? Set(all) : [] }
        switch filter {
        case .all: return Set(all)
        case .weak: return health.weak
        case .reused: return health.reused
        case .noTwoFactor: return health.noTwoFactor
        case .old: return health.old
        case .exposed: return health.breached
        }
    }

    /// "After 5 minutes idle · when the screen locks · on sleep" (Windows `lock_summary`).
    nonisolated static func lockSummary(idle: IdleLock, screenLock: Bool, sleep: Bool) -> String {
        var parts = [idle.seconds == nil ? String(localized: "No inactivity lock") : String(localized: "After \(idle.label) idle")]
        if screenLock { parts.append(String(localized: "when the screen locks")) }
        if sleep { parts.append(String(localized: "on sleep")) }
        return parts.joined(separator: " · ")
    }

    /// The four panels: How you unlock, Backups, Moving data and Privacy.
    func panels(touchIDAvailable: Bool, backup: RecoveryStatus? = nil, now: Date = Date()) -> [SecurityPanel] {
        Self.panels(settings: settings, touchIDAvailable: touchIDAvailable, backup: backup, now: now)
    }

    /// Windows `unlock_panel`'s Recovery phrase row.
    nonisolated static func recoveryPhraseRow(enrolled: Bool) -> SecurityPanelRow {
        SecurityPanelRow(label: String(localized: "Recovery phrase"), meta: enrolled ? RecoveryCentreModel.phraseSetText : RecoveryCentreModel.phraseNotSetText,
                         buttonLabel: enrolled ? String(localized: "Manage") : String(localized: "Set up"), action: .recoveryCentre(nil),
                         tone: enrolled ? .neutral : .warning)
    }

    /// Windows `backup_panel`: the last backup's age (a warning after `STALE_BACKUP_SECONDS`) and the backup actions.
    nonisolated static func backupPanel(_ status: RecoveryStatus, now: Date) -> SecurityPanel {
        let meta: String, tone: SecurityTone
        if let last = status.lastBackup {
            let age = max(0, now.timeIntervalSince(last))
            let text = RecoveryCentreModel.ageText(age)
            meta = text.prefix(1).uppercased() + text.dropFirst()
            tone = age > RecoveryCentreModel.staleSeconds ? .warning : .neutral
        } else {
            (meta, tone) = (String(localized: "No backup yet"), .warning)
        }
        return SecurityPanel(title: String(localized: "Backups"), rows: [
            SecurityPanelRow(label: String(localized: "Last backup"), meta: meta, buttonLabel: String(localized: "Back up now"), action: .recoveryCentre(nil), tone: tone),
            SecurityPanelRow(label: String(localized: "Check a backup"), meta: String(localized: "Open it and confirm every item is there"), buttonLabel: String(localized: "Verify"),
                             action: .recoveryCentre(.verify)),
            SecurityPanelRow(label: String(localized: "Restore from a backup"), meta: String(localized: "Bring items back from a backup file"), buttonLabel: String(localized: "Restore…"),
                             action: .recoveryCentre(.restore)),
            SecurityPanelRow(label: String(localized: "Recovery kit"), meta: String(localized: "Printable sheet for when you forget everything"), buttonLabel: String(localized: "Write kit"),
                             action: .recoveryCentre(.kit)),
        ])
    }

    static func panels(settings: AppSettings, touchIDAvailable: Bool, backup: RecoveryStatus? = nil,
                       now: Date = Date()) -> [SecurityPanel] {
        var unlock = [SecurityPanelRow(label: String(localized: "Master password"), meta: String(localized: "Always works, even when other methods are off"),
                                       buttonLabel: String(localized: "Change…"), action: .settings)]
        if touchIDAvailable || settings.touchIDUnlock {
            let on = settings.touchIDUnlock
            unlock.append(SecurityPanelRow(label: String(localized: "Touch ID"), meta: on ? String(localized: "On · fingerprint") : String(localized: "Not set up"),
                                           buttonLabel: on ? String(localized: "Manage") : String(localized: "Set up"), action: .settings))
        }
        if let backup { unlock.append(recoveryPhraseRow(enrolled: backup.phraseEnrolled)) }
        unlock.append(SecurityPanelRow(label: String(localized: "Auto-lock"),
                                       meta: lockSummary(idle: settings.idleLock, screenLock: settings.lockOnScreenLock, sleep: settings.lockOnSleep),
                                       buttonLabel: String(localized: "Edit"), action: .settings))
        let later = { (label: String) in SecurityPanelRow(label: label, meta: laterText, buttonLabel: nil, action: .later) }
        let breach = settings.breachCheckEnabled, offline = settings.strictOfflineMode
        let status = backup ?? RecoveryCentreModel.status(lastBackup: nil, lastVerified: nil, phrase: false, schedule: .off, now: now)
        return [
            SecurityPanel(title: String(localized: "How you unlock"), rows: unlock),
            backupPanel(status, now: now),
            SecurityPanel(title: String(localized: "Moving data"), rows: [
                SecurityPanelRow(label: String(localized: "Export vault"), meta: String(localized: "Encrypted backup (.lgkm) or CSV file"), buttonLabel: String(localized: "Open"),
                                 action: .importExport),
                later(String(localized: "Encrypted transfer")),
                SecurityPanelRow(label: String(localized: "Import"), meta: String(localized: "From another password manager or a phone backup"),
                                 buttonLabel: String(localized: "Open"), action: .importExport)]),
            SecurityPanel(title: String(localized: "Privacy"), rows: [
                SecurityPanelRow(label: String(localized: "Clipboard"), meta: String(localized: "Cleared \(settings.clipboardExpiry.rawValue) seconds after copying"),
                                 buttonLabel: String(localized: "Edit"), action: .settings),
                SecurityPanelRow(label: String(localized: "Breach checks"), meta: breach ? String(localized: "On · you start each check") : String(localized: "Off"),
                                 buttonLabel: breach ? String(localized: "Turn off") : String(localized: "Turn on"), action: .toggleBreachChecks),
                SecurityPanelRow(label: String(localized: "Strict offline mode"),
                                 meta: offline ? String(localized: "On · no background network access") : String(localized: "Off · no network access at all when on"),
                                 buttonLabel: offline ? String(localized: "Turn off") : String(localized: "Turn on"), action: .toggleStrictOffline),
            ]),
        ]
    }
}

/// Reads the two breach settings from the checker's actor (UserDefaults is thread-safe).
private struct UncheckedDefaults: @unchecked Sendable {
    let defaults: UserDefaults
    func bool(_ key: String, _ fallback: Bool) -> Bool { (defaults.object(forKey: key) as? Bool) ?? fallback }
}
