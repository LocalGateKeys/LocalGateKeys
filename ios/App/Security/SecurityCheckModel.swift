import Foundation
import Observation
import AppShared

/// One row of the Security tab.
enum SecurityCategory: String, CaseIterable, Identifiable, Sendable {
    case breached, reused, weak, old, noTwoFactor

    var id: String { rawValue }

    var label: String {
        switch self {
        case .breached: String(localized: "Breached")
        case .reused: String(localized: "Reused")
        case .weak: String(localized: "Weak")
        case .old: String(localized: "Old")
        case .noTwoFactor: String(localized: "2FA available")
        }
    }

    var icon: String {
        switch self {
        case .breached: "exclamationmark.octagon"
        case .reused: "square.on.square"
        case .weak: "lock.open"
        case .old: "clock"
        case .noTwoFactor: "number"
        }
    }

    var explanation: String {
        switch self {
        case .breached: String(localized: "These passwords appear in known data breaches. Change them first.")
        case .reused: String(localized: "These passwords are used for more than one login. If one site leaks, the others are exposed.")
        case .weak: String(localized: "These passwords are short or easy to guess.")
        case .old: String(localized: "These passwords have not changed for over a year. Age alone is not a reason to change them.")
        case .noTwoFactor: String(localized: "These logins have no 2FA code saved. Turn on two-factor sign-in on the site if it offers it.")
        }
    }
}

/// The iPhone's Security check (UX plan workstream 2): the shared `VaultHealth` (the Mac's score and filters,
/// in LGKCore) over the vault's logins, computed when the tab opens and kept in memory only. Breach checks are
/// off by default and refused while strict offline is on; results are memory only too. "Dismiss for this item"
/// hides an item from one row on this iPhone (stored as ids only, never synced).
@MainActor @Observable
final class SecurityCheckModel {
    nonisolated static let dismissedKey = "settings.securityDismissed"
    nonisolated static let consentText = String(localized: "Breach checks send only the first 5 characters of each password's SHA-1 hash to Have I Been Pwned, over HTTPS with padding, and only when you start one. No password, full hash, username or website is sent. The service sees your IP address.")
    nonisolated static let offlineText = String(localized: "Strict offline mode is on, so breach checks are blocked. Turn it off in Settings › Breach checks.")
    nonisolated static let disabledText = String(localized: "Breach checks are off. Turn them on in Settings › Breach checks.")
    nonisolated static let cancelledText = String(localized: "Breach check cancelled.")

    private(set) var items: [VaultItem] = []
    private(set) var health: VaultHealth?
    /// Logins a breach check found (this session only).
    private(set) var breached: Set<String> = []
    private(set) var dismissed: Set<String>
    private(set) var running = false
    private(set) var statusText: String?

    @ObservationIgnored private let store: any ItemStore
    @ObservationIgnored private let settings: AppSettings
    @ObservationIgnored private let clock: () -> Date
    @ObservationIgnored private let cache = StrengthCache()
    @ObservationIgnored private var task: Task<Void, Never>?

    init(store: any ItemStore, settings: AppSettings = .shared, clock: @escaping () -> Date = Date.init) {
        self.store = store; self.settings = settings; self.clock = clock
        dismissed = Set(settings.defaults.stringArray(forKey: Self.dismissedKey) ?? [])
    }

    /// The logins the checks look at; a login made from a 2FA QR code (needs-password) holds a placeholder and is
    /// left out (the Mac's rule), so the placeholder is never sent to HIBP either.
    nonisolated static func healthLogins(_ items: [VaultItem]) -> [HealthLogin] {
        items.filter { $0.isLogin && !$0.tags.contains(TwoFactorScanModel.needsPasswordTag) }.map { item in
            HealthLogin(id: item.id, title: item.title, password: item.record["password"]?.stringValue ?? "",
                        hasTOTP: item.record["totp"]?.objectValue?["secret"]?.stringValue?.isEmpty == false,
                        updatedAt: item.updatedAt > 0 ? Date(timeIntervalSince1970: TimeInterval(item.updatedAt)) : nil)
        }
    }

    nonisolated static func ids(_ category: SecurityCategory, in health: VaultHealth) -> Set<String> {
        switch category {
        case .breached: health.breached
        case .reused: health.reused
        case .weak: health.weak
        case .old: health.old
        case .noTwoFactor: health.noTwoFactor
        }
    }

    nonisolated static func dismissKey(_ category: SecurityCategory, _ id: String) -> String { "\(category.rawValue):\(id)" }

    /// Reads the vault again and recomputes.
    func refresh() {
        guard let snap = try? store.load() else { return }
        items = VaultItem.items(from: snap)
        recompute()
    }

    private func recompute() {
        let logins = Self.healthLogins(items)
        breached.formIntersection(Set(logins.map(\.id)))
        health = VaultHealth.compute(logins, breached: breached, now: clock(), cache: cache)
    }

    func ids(_ category: SecurityCategory) -> Set<String> {
        guard let health else { return [] }
        return Set(Self.ids(category, in: health).filter { !dismissed.contains(Self.dismissKey(category, $0)) })
    }

    func count(_ category: SecurityCategory) -> Int { ids(category).count }

    func items(_ category: SecurityCategory) -> [VaultItem] {
        let wanted = ids(category)
        return VaultSearch.apply(items.filter { wanted.contains($0.id) }, query: "", filter: .all)
    }

    var score: Int? { health?.score }
    var label: String { health?.label ?? "" }

    func dismiss(_ category: SecurityCategory, id: String) {
        dismissed.insert(Self.dismissKey(category, id))
        save()
    }

    func restoreDismissed() {
        dismissed = []
        save()
    }

    private func save() {
        // Only for items still in the vault, so the list never grows without bound.
        let live = Set(items.map(\.id))
        dismissed = dismissed.filter { key in live.isEmpty || live.contains(String(key.split(separator: ":").last ?? "")) }
        settings.defaults.set(Array(dismissed).sorted(), forKey: Self.dismissedKey)
    }

    // MARK: breach check

    /// Why a breach check can't start now, nil when it can.
    var breachBlockedText: String? {
        if settings.strictOfflineMode { return Self.offlineText }
        if !settings.breachCheckEnabled { return Self.disabledText }
        return nil
    }

    /// Checks every login's password (identical ones once) with HIBP. Only after the person confirmed.
    func checkBreaches(transport: any BreachTransport = URLSessionBreachTransport(), pause: Duration = .seconds(1.5)) {
        guard !running, breachBlockedText == nil else { statusText = breachBlockedText; return }
        let logins = Self.healthLogins(items)
        let defaults = UncheckedSettingsDefaults(defaults: settings.defaults)
        let checker = BreachChecker(transport: transport, appVersion: SettingsView.shortVersion,
                                    strictOffline: { defaults.bool(AppSettings.Key.strictOfflineMode, true) },
                                    enabled: { defaults.bool(AppSettings.Key.breachCheckEnabled, false) },
                                    pause: pause)
        running = true
        statusText = String(localized: "Checking passwords…")
        task = Task { [weak self] in
            let result = await checker.scan(logins) { _, _ in }
            guard let self else { return }
            self.running = false
            if result.cancelled { self.statusText = Self.cancelledText; return }
            self.breached = result.breached
            self.recompute()
            let found = self.breached.count
            self.statusText = result.failed.isEmpty
                ? (found == 0 ? String(localized: "No breached passwords found.") : String(localized: "\(found) breached password(s) found."))
                : String(localized: "Some passwords could not be checked. Try again later.")
        }
    }

    func cancelBreachCheck() { task?.cancel() }

    /// Waits for a running check (tests).
    func settle() async { await task?.value }

    /// Lock: forget the results.
    func clear() {
        task?.cancel()
        items = []; health = nil; breached = []; statusText = nil; running = false
        cache.removeAll()
    }
}

/// Reads two settings from any thread (the checker's gates run off the main actor).
struct UncheckedSettingsDefaults: @unchecked Sendable {
    let defaults: UserDefaults
    func bool(_ key: String, _ fallback: Bool) -> Bool { (defaults.object(forKey: key) as? Bool) ?? fallback }
}
