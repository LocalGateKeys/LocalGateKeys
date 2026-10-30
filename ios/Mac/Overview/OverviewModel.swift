import Foundation
import Observation
import LGKCore
import AppSharedMac

/// The quick filters under the list title (Windows `Chips.svelte`): "All" is the nil chip.
enum OverviewChip: String, CaseIterable, Hashable {
    case attention, noTwoFactor, expiring

    var label: String {
        switch self {
        case .attention: String(localized: "Needs attention")
        case .noTwoFactor: String(localized: "No 2FA")
        case .expiring: String(localized: "Expiring")
        }
    }
}

/// One line of the "Coming up" card (Windows `overview_model.upcoming_lines`).
struct ComingUpLine: Equatable, Identifiable {
    let id: String
    /// "OCT 5".
    let date: String
    let label: String
    /// "overdue", "today", "1 day", "12 days".
    let meta: String
    let overdue: Bool
}

/// A login with a one-time code, for the codes strip (Windows `codes_list`).
struct CodeEntry: Equatable, Identifiable {
    enum Setup: Equatable {
        /// `policy.require_master_password`: the code is shown only after the master password.
        case hidden
        case live(secret: String, algorithm: String, digits: Int, period: Int)
    }
    let id: String
    let title: String
    let username: String
    let setup: Setup

    /// The current code and seconds left, or nil when the setup key is invalid (or the entry is hidden).
    func code(at now: Int64) -> (code: String, remaining: Int, period: Int)? {
        guard case .live(let secret, let algorithm, let digits, let period) = setup, period > 0,
              let code = try? TOTP.code(secret: secret, algorithm: algorithm, digits: digits, period: period, at: now)
        else { return nil }
        let remaining = period - Int(((now % Int64(period)) + Int64(period)) % Int64(period))
        return (code, remaining, period)
    }
}

/// The overview above the item list: health card, coming up, backup, one-time codes, filter chips and
/// row tags. Health is computed off the main actor from value copies and published when done, so typing and
/// scrolling never wait for the strength estimator.
@MainActor @Observable
final class OverviewModel {
    nonisolated static let codesCollapsed = 4
    nonisolated static let comingUpDays = 90
    nonisolated static let expiringDays = 30

    /// The vault's live items; setting them recomputes health in the background.
    var items: [VaultItem] = [] { didSet { if items != oldValue { scheduleHealth() } } }
    var reminders: [LocalData.Reminder] = []
    /// Breached login ids (Task 5's breach check); empty until then.
    var breached: Set<String> = [] { didSet { if breached != oldValue { scheduleHealth() } } }
    private(set) var health: VaultHealth?
    var activeChip: OverviewChip?
    var codesExpanded = false

    @ObservationIgnored private let cache: StrengthCache
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private var generation = 0
    @ObservationIgnored private var pending: Task<Void, Never>?

    init(cache: StrengthCache, now: @escaping () -> Date = Date.init) {
        self.cache = cache; self.now = now
    }

    // MARK: health

    /// Starts a background health computation; the newest one wins.
    func scheduleHealth() {
        pending?.cancel()
        pending = Task { await self.computeHealth() }
    }

    /// Computes health now, superseding any scheduled run (tests await this directly).
    func recomputeHealth() async {
        pending?.cancel(); pending = nil
        await computeHealth()
    }

    /// Computes health off the main actor and publishes it; a newer or cancelled run is not published.
    private func computeHealth() async {
        guard !Task.isCancelled else { return }
        generation += 1
        let mine = generation
        let logins = Self.healthLogins(items), breached = breached, cache = cache, date = now()
        let result = await Task.detached(priority: .utility) {
            VaultHealth.compute(logins, breached: breached, now: date, cache: cache)
        }.value
        guard mine == generation, !Task.isCancelled else { return }
        health = result
        reconcileChip()
    }

    /// The logins the weak, reused, 2FA and breach checks look at. A login tagged needs-password (made from a 2FA
    /// QR code) holds a generated placeholder: it is left out, so the placeholder is never sent to HIBP either.
    nonisolated static func healthLogins(_ items: [VaultItem]) -> [HealthLogin] {
        items.filter { $0.isLogin && !$0.tags.contains(TwoFactorScanModel.needsPasswordTag) }.map { item in
            HealthLogin(id: item.id, title: item.title, password: item.record["password"]?.stringValue ?? "",
                        hasTOTP: item.record["totp"]?.objectValue?["secret"]?.stringValue?.isEmpty == false,
                        updatedAt: item.updatedAt > 0 ? Date(timeIntervalSince1970: TimeInterval(item.updatedAt)) : nil)
        }
    }

    /// "Weak" / "Reused" / "Breached" for a row, nil when fine or not computed yet.
    func tag(for id: String) -> String? { health?.tag(for: id) }

    // MARK: cards

    struct HealthCard: Equatable {
        /// nil when there are no logins (the card then shows only `label`).
        let score: String?
        let label: String
        let pills: [String]
    }

    nonisolated static func healthCard(_ health: VaultHealth?) -> HealthCard {
        guard let health, let score = health.score else { return HealthCard(score: nil, label: String(localized: "No logins yet"), pills: []) }
        return HealthCard(score: "\(score)", label: String(localized: " / 100 · \(health.label)"),
                          pills: [String(localized: "\(health.weak.count) weak"), String(localized: "\(health.reused.count) reused"), String(localized: "\(health.noTwoFactor.count) no 2FA")])
    }

    var healthCard: HealthCard { Self.healthCard(health) }

    var comingUp: [ComingUpLine] { Self.comingUp(reminders, items: items, today: Self.day(now())) }

    /// The Recovery centre's status (set by the window); nil reads as no backup.
    var backup: RecoveryStatus?

    /// The Backup & recovery card's pill (Windows `Overview.svelte`).
    var backupText: String {
        backup.map { RecoveryCentreModel.overviewText($0, now: now()) } ?? RecoveryCentreModel.noBackupWarning
    }

    var backupStale: Bool { backup?.stale ?? true }

    // MARK: reminders

    /// The local calendar date of `date` as "YYYY-MM-DD".
    nonisolated static func day(_ date: Date, calendar: Calendar = .current) -> String {
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }

    /// Days since 1970-01-01 for "YYYY-MM-DD", nil when malformed.
    nonisolated static func dayNumber(_ s: String) -> Int? {
        let parts = s.split(separator: "-")
        guard parts.count == 3, let y = Int(parts[0]), let m = Int(parts[1]), let d = Int(parts[2]) else { return nil }
        var utc = Calendar(identifier: .gregorian)
        utc.timeZone = TimeZone(identifier: "UTC")!
        guard let date = utc.date(from: DateComponents(year: y, month: m, day: d)),
              utc.component(.day, from: date) == d else { return nil }
        return Int((date.timeIntervalSince1970 / 86_400).rounded(.down))
    }

    /// Windows `reminders._effective_date`: due − lead; a snoozed reminder not before its snooze date.
    nonisolated static func effectiveDay(_ r: LocalData.Reminder) -> Int? {
        guard var day = dayNumber(r.dueDate) else { return nil }
        day -= r.leadDays
        if r.status == .snoozed, let snooze = dayNumber(r.snoozeUntil) { day = max(day, snooze) }
        return day
    }

    /// Not dismissed, effective date overdue or within `days` from today.
    nonisolated static func active(_ reminders: [LocalData.Reminder], today: String, days: Int) -> [LocalData.Reminder] {
        guard let t = dayNumber(today) else { return [] }
        return reminders.filter { r in
            guard r.status != .dismissed, let e = effectiveDay(r) else { return false }
            return e <= t + days
        }
    }

    nonisolated static func comingUp(_ reminders: [LocalData.Reminder], items: [VaultItem], today: String,
                                     limit: Int = 3) -> [ComingUpLine] {
        guard let t = dayNumber(today) else { return [] }
        let titles = Dictionary(items.map { ($0.id, $0.title.isEmpty ? $0.kindLabel : $0.title) }, uniquingKeysWith: { a, _ in a })
        let rows = active(reminders, today: today, days: comingUpDays)
            .compactMap { r -> (Int, String, LocalData.Reminder)? in
                guard let due = dayNumber(r.dueDate), let title = titles[r.itemID] else { return nil }
                return (due, title, r)
            }
            .sorted { ($0.0, $0.1.lowercased(), $0.2.id) < ($1.0, $1.1.lowercased(), $1.2.id) }
        return rows.prefix(limit).map { due, title, r in
            let days = due - t
            let meta = days < 0 ? String(localized: "overdue") : days == 0 ? String(localized: "today") : days == 1 ? String(localized: "1 day") : String(localized: "\(days) days")
            return ComingUpLine(id: r.id, date: dateText(r.dueDate), label: title, meta: meta, overdue: days < 0)
        }
    }

    /// "2026-10-05" → "OCT 5" (Python `%b` in the C locale, upper-cased).
    nonisolated static func dateText(_ s: String) -> String {
        if Bundle.main.preferredLocalizations.first?.hasPrefix("en") == false {
            // Other languages: the month and day in their own order and words.
            let f = DateFormatter()
            f.locale = Locale(identifier: "en_US_POSIX"); f.timeZone = TimeZone(identifier: "UTC"); f.dateFormat = "yyyy-MM-dd"
            if let date = f.date(from: s) {
                var style = Date.FormatStyle.dateTime.month(.abbreviated).day()
                style.timeZone = TimeZone(identifier: "UTC")!
                return date.formatted(style).uppercased()
            }
        }
        let months = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]
        let parts = s.split(separator: "-")
        guard parts.count == 3, let m = Int(parts[1]), (1...12).contains(m), let d = Int(parts[2]) else { return s }
        return "\(months[m - 1]) \(d)"
    }

    // MARK: chips

    func ids(for chip: OverviewChip) -> Set<String> {
        let present = Set(items.map(\.id))
        switch chip {
        case .attention: return (health?.attention ?? []).intersection(present)
        case .noTwoFactor: return (health?.noTwoFactor ?? []).intersection(present)
        case .expiring:
            return Set(Self.active(reminders, today: Self.day(now()), days: Self.expiringDays).map(\.itemID)).intersection(present)
        }
    }

    /// The chips after "All", zero-count ones left out.
    var chips: [(chip: OverviewChip, count: Int)] {
        OverviewChip.allCases.compactMap { chip in
            let n = ids(for: chip).count
            return n > 0 ? (chip, n) : nil
        }
    }

    static func chipLabel(_ chip: OverviewChip, count: Int) -> String { String(localized: "\(chip.label) · \(count)") }

    /// A chip whose count dropped to zero goes back to All (Windows `items()`).
    func reconcileChip() {
        if let c = activeChip, ids(for: c).isEmpty { activeChip = nil }
    }

    /// The list after the active chip.
    func applyChip(_ list: [VaultItem]) -> [VaultItem] {
        guard let chip = activeChip else { return list }
        let ids = ids(for: chip)
        return list.filter { ids.contains($0.id) }
    }

    // MARK: codes

    /// Logins with a 2FA secret, by title then username (case-insensitive).
    nonisolated static func codeEntries(_ items: [VaultItem]) -> [CodeEntry] {
        items.compactMap { item -> CodeEntry? in
            guard item.isLogin, let t = item.record["totp"]?.objectValue,
                  let secret = t["secret"]?.stringValue, !secret.isEmpty else { return nil }
            let strict = item.record["policy"]?.objectValue?["require_master_password"] == .bool(true)
            func int(_ k: String, _ d: Int) -> Int { if case .int(let n)? = t[k] { return Int(n) }; return d }
            let setup: CodeEntry.Setup = strict ? .hidden
                : .live(secret: secret, algorithm: t["algorithm"]?.stringValue ?? "SHA1", digits: int("digits", 6), period: int("period", 30))
            return CodeEntry(id: item.id, title: item.title.isEmpty ? item.kindLabel : item.title, username: item.username, setup: setup)
        }
        .sorted { ($0.title.lowercased(), $0.username.lowercased(), $0.id) < ($1.title.lowercased(), $1.username.lowercased(), $1.id) }
    }

    /// What the strip shows and its toggle ("Show all N" / "Show fewer", nil when everything fits).
    nonisolated static func visibleCodes(_ all: [CodeEntry], expanded: Bool) -> (shown: [CodeEntry], toggle: String?) {
        guard all.count > codesCollapsed else { return (all, nil) }
        return expanded ? (all, String(localized: "Show fewer")) : (Array(all.prefix(codesCollapsed)), String(localized: "Show all \(all.count)"))
    }

    var codes: [CodeEntry] { Self.codeEntries(items) }

    // MARK: lock

    /// Forgets everything derived from the vault.
    func clear() {
        pending?.cancel(); generation += 1
        items = []; reminders = []; breached = []
        pending?.cancel(); generation += 1
        health = nil; activeChip = nil; codesExpanded = false
    }
}
