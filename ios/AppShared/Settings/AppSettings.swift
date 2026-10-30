import Foundation
import Observation

/// How long the app may stay in the background before it locks.
public enum AutoLockDelay: Int64, CaseIterable, Identifiable, Sendable {
    case immediately = 0, oneMinute = 60, fiveMinutes = 300, fifteenMinutes = 900, oneHour = 3600
    public var id: Int64 { rawValue }
    public var label: String {
        switch self {
        case .immediately: String(localized: "Immediately")
        case .oneMinute: String(localized: "After 1 minute")
        case .fiveMinutes: String(localized: "After 5 minutes")
        case .fifteenMinutes: String(localized: "After 15 minutes")
        case .oneHour: String(localized: "After 1 hour")
        }
    }
}

/// How long the unlocked app may go without a touch before it locks. Raw value 0 is Never.
public enum IdleLock: Int64, CaseIterable, Identifiable, Sendable {
    case oneMinute = 60, fiveMinutes = 300, fifteenMinutes = 900, thirtyMinutes = 1800, never = 0
    public var id: Int64 { rawValue }
    public var seconds: Int64? { self == .never ? nil : rawValue }
    public var label: String {
        switch self {
        case .oneMinute: String(localized: "1 minute")
        case .fiveMinutes: String(localized: "5 minutes")
        case .fifteenMinutes: String(localized: "15 minutes")
        case .thirtyMinutes: String(localized: "30 minutes")
        case .never: String(localized: "Never")
        }
    }
}

/// When a copied secret leaves the clipboard. There is no "never": copies always expire.
public enum ClipboardExpiry: Int64, CaseIterable, Identifiable, Sendable {
    case thirtySeconds = 30, sixtySeconds = 60, twoMinutes = 120, fiveMinutes = 300
    public var id: Int64 { rawValue }
    public var label: String {
        switch self {
        case .thirtySeconds: String(localized: "30 seconds")
        case .sixtySeconds: String(localized: "60 seconds")
        case .twoMinutes: String(localized: "2 minutes")
        case .fiveMinutes: String(localized: "5 minutes")
        }
    }
}

public enum Appearance: String, CaseIterable, Identifiable, Sendable {
    case system, light, dark
    public var id: String { rawValue }
    public var label: String {
        switch self {
        case .system: String(localized: "System")
        case .light: String(localized: "Light")
        case .dark: String(localized: "Dark")
        }
    }
}

/// Every user preference, in the app group's UserDefaults so the AutoFill extension reads the same values.
/// Nothing secret is ever stored here: only choices, flags and the generator's options (no generated value).
/// Each read goes to UserDefaults, so a change made by the other process is seen at once.
@Observable
public final class AppSettings: @unchecked Sendable {
    public enum Key {
        /// Kept from the first build (AppLockModel's `AutoLockPreferences`).
        public static let autoLockDelay = "autoLockDelaySeconds"
        public static let idleLock = "settings.idleLockSeconds"
        public static let clipboardExpiry = "settings.clipboardExpirySeconds"
        public static let concealSecretsInDetail = "settings.concealFieldsInDetail"
        public static let showCodesRow = "settings.showCodesRow"
        public static let showWebsiteIcons = "settings.showWebsiteIcons"
        public static let copyCodeOnFill = "settings.copyCodeOnFill"
        public static let showInQuickType = "settings.showInQuickType"
        public static let quickTypeExactSites = "settings.quickTypeExactSites"
        public static let offerPasskeys = "settings.offerPasskeys"
        public static let appearance = "settings.appearance"
        public static let generatorOptions = "settings.generatorOptions"
        public static let erasePending = "settings.erasePending"
        public static let identityRemovalPending = "settings.quickTypeCleanupPending"
        public static let initials = "settings.initials"
        public static let planFullRevision = "settings.planFullRevision"
        /// Mac only: the longest an unlocked session may last (seconds); absent means off.
        public static let maxSessionSeconds = "settings.maxSessionSeconds"
        /// Mac only: lock when the screen locks / when the Mac sleeps.
        public static let lockOnScreenLock = "settings.lockOnScreenLock"
        public static let lockOnSleep = "settings.lockOnSleep"
        /// Mac only: the user turned on Touch ID unlock (the Keychain item holds the key; this is only the choice).
        public static let touchIDUnlock = "settings.touchIDUnlock"
        /// Mac only: breach checks may be started (each one still asks first); off by default.
        public static let breachCheckEnabled = "settings.breachCheckEnabled"
        /// Mac only: refuses every outside request (breach checks); on by default.
        public static let strictOfflineMode = "settings.strictOfflineMode"
        /// Mac only: reminder notifications name the item ("{title} is due"); on by default.
        public static let showItemNamesInReminders = "settings.showItemNamesInReminders"
        /// Mac only: Wi-Fi sync hosting is on (listens while unlocked); off by default.
        public static let wifiSyncOn = "settings.macWiFiSyncOn"
        /// Mac only: the address and port Wi-Fi sync listens on ("host:port", IPv6 in brackets).
        public static let wifiSyncEndpoint = "settings.macWiFiSyncEndpoint"
        /// "Not now" on the empty vault's "Import your passwords" card (this device only).
        public static let importCardDismissed = "settings.importCardDismissed"
        /// The app version whose "What's new" sheet was shown or skipped on this device.
        public static let whatsNewSeen = "settings.whatsNewSeenVersion"
        /// iPhone only: reminder notifications name the item; off by default (UX plan workstream 10).
        public static let phoneReminderNames = "settings.phoneReminderItemNames"
        /// Setup progress on this device (UX plan workstream 4; never synced): finished step names, whether the
        /// pages were seen, and the vault card's Hide.
        public static let setupDone = "settings.setupDone"
        public static let setupSeen = "settings.setupSeen"
        public static let setupCardHidden = "settings.setupCardHidden"
        public static let all = [autoLockDelay, idleLock, clipboardExpiry, concealSecretsInDetail, showCodesRow, showWebsiteIcons,
                                 copyCodeOnFill, showInQuickType, quickTypeExactSites, offerPasskeys, appearance, generatorOptions, erasePending, identityRemovalPending, initials,
                                 planFullRevision, maxSessionSeconds, lockOnScreenLock, lockOnSleep, touchIDUnlock,
                                 breachCheckEnabled, strictOfflineMode, showItemNamesInReminders, wifiSyncOn, wifiSyncEndpoint, importCardDismissed,
                                 phoneReminderNames, setupDone, setupSeen, setupCardHidden]
    }

    /// The app group's defaults (standard defaults when the group is unavailable, e.g. unsigned builds).
    public static let shared = AppSettings(defaults: UserDefaults(suiteName: AppGroup.identifier) ?? .standard)

    @ObservationIgnored public let defaults: UserDefaults
    public init(defaults: UserDefaults) { self.defaults = defaults }

    private func int(_ key: String) -> Int64? { (defaults.object(forKey: key) as? NSNumber)?.int64Value }
    private func bool(_ key: String, _ fallback: Bool) -> Bool { (defaults.object(forKey: key) as? Bool) ?? fallback }

    public var autoLockDelay: AutoLockDelay {
        get { access(keyPath: \.autoLockDelay); return int(Key.autoLockDelay).flatMap(AutoLockDelay.init) ?? .immediately }
        set { withMutation(keyPath: \.autoLockDelay) { defaults.set(newValue.rawValue, forKey: Key.autoLockDelay) } }
    }

    public var idleLock: IdleLock {
        get { access(keyPath: \.idleLock); return int(Key.idleLock).flatMap(IdleLock.init) ?? .fiveMinutes }
        set { withMutation(keyPath: \.idleLock) { defaults.set(newValue.rawValue, forKey: Key.idleLock) } }
    }

    public var clipboardExpiry: ClipboardExpiry {
        get { access(keyPath: \.clipboardExpiry); return int(Key.clipboardExpiry).flatMap(ClipboardExpiry.init) ?? .sixtySeconds }
        set { withMutation(keyPath: \.clipboardExpiry) { defaults.set(newValue.rawValue, forKey: Key.clipboardExpiry) } }
    }

    /// Item detail shows protected fields masked until the eye is tapped.
    public var concealSecretsInDetail: Bool {
        get { access(keyPath: \.concealSecretsInDetail); return bool(Key.concealSecretsInDetail, true) }
        set { withMutation(keyPath: \.concealSecretsInDetail) { defaults.set(newValue, forKey: Key.concealSecretsInDetail) } }
    }

    /// Website icons in the vault (off by default). Each download tells that site this phone has an account there.
    public var showWebsiteIcons: Bool {
        get { access(keyPath: \.showWebsiteIcons); return bool(Key.showWebsiteIcons, false) }
        set { withMutation(keyPath: \.showWebsiteIcons) { defaults.set(newValue, forKey: Key.showWebsiteIcons) } }
    }

    /// The empty vault hides its "Import your passwords" card (off by default).
    public var importCardDismissed: Bool {
        get { access(keyPath: \.importCardDismissed); return bool(Key.importCardDismissed, false) }
        set { withMutation(keyPath: \.importCardDismissed) { defaults.set(newValue, forKey: Key.importCardDismissed) } }
    }

    /// The version whose "What's new" sheet this device has seen ("" before any).
    public var whatsNewSeen: String {
        get { access(keyPath: \.whatsNewSeen); return defaults.string(forKey: Key.whatsNewSeen) ?? "" }
        set { withMutation(keyPath: \.whatsNewSeen) { defaults.set(newValue, forKey: Key.whatsNewSeen) } }
    }

    /// The Vault tab's pinned Codes row.
    public var showCodesRow: Bool {
        get { access(keyPath: \.showCodesRow); return bool(Key.showCodesRow, true) }
        set { withMutation(keyPath: \.showCodesRow) { defaults.set(newValue, forKey: Key.showCodesRow) } }
    }

    /// The AutoFill extension copies the login's 2FA code after filling.
    public var copyCodeOnFill: Bool {
        get { access(keyPath: \.copyCodeOnFill); return bool(Key.copyCodeOnFill, true) }
        set { withMutation(keyPath: \.copyCodeOnFill) { defaults.set(newValue, forKey: Key.copyCodeOnFill) } }
    }

    /// The app publishes usernames and domains to the QuickType bar.
    public var showInQuickType: Bool {
        get { access(keyPath: \.showInQuickType); return bool(Key.showInQuickType, true) }
        set { withMutation(keyPath: \.showInQuickType) { defaults.set(newValue, forKey: Key.showInQuickType) } }
    }

    /// QuickType also offers exact-origin and host logins, under their exact host (https, default port).
    /// Off by default (audit 2026-10-18 M11, re-raised as 2026-10-24 M-5): iOS matches a `.domain` identity
    /// loosely and the QuickType fill never sees the page URL, so such a login could be offered on other pages,
    /// subdomains or plain-HTTP pages of that domain. Only an explicit choice is stored, so a user who never
    /// touched the switch gets this default; the identities published under the old default are withdrawn by
    /// the identity refresh on the next unlock.
    public var quickTypeExactSites: Bool {
        get { access(keyPath: \.quickTypeExactSites); return bool(Key.quickTypeExactSites, false) }
        set { withMutation(keyPath: \.quickTypeExactSites) { defaults.set(newValue, forKey: Key.quickTypeExactSites) } }
    }

    /// The app publishes passkey identities (relying party and user name, never a key) and the AutoFill
    /// extension offers passkeys.
    public var offerPasskeys: Bool {
        get { access(keyPath: \.offerPasskeys); return bool(Key.offerPasskeys, true) }
        set { withMutation(keyPath: \.offerPasskeys) { defaults.set(newValue, forKey: Key.offerPasskeys) } }
    }

    public var appearance: Appearance {
        get { access(keyPath: \.appearance); return defaults.string(forKey: Key.appearance).flatMap(Appearance.init) ?? .system }
        set { withMutation(keyPath: \.appearance) { defaults.set(newValue.rawValue, forKey: Key.appearance) } }
    }

    /// The generator's last-used options (JSON written by the app; never a generated value). Nil: desktop defaults.
    public var generatorOptionsData: Data? {
        get { access(keyPath: \.generatorOptionsData); return defaults.data(forKey: Key.generatorOptions) }
        set { withMutation(keyPath: \.generatorOptionsData) { defaults.set(newValue, forKey: Key.generatorOptions) } }
    }

    /// Set before "Erase this iPhone's vault" starts and cleared only when it succeeds. While set, the app
    /// retries the erase before unlocking and the AutoFill extension refuses to fill.
    public var erasePending: Bool {
        get { access(keyPath: \.erasePending); return bool(Key.erasePending, false) }
        set { withMutation(keyPath: \.erasePending) { defaults.set(newValue, forKey: Key.erasePending) } }
    }

    /// Set when an erase could not remove the published AutoFill identities (usernames and domains only).
    /// The next identity refresh retries the removal and clears it.
    public var identityRemovalPending: Bool {
        get { access(keyPath: \.identityRemovalPending); return bool(Key.identityRemovalPending, false) }
        set { withMutation(keyPath: \.identityRemovalPending) { defaults.set(newValue, forKey: Key.identityRemovalPending) } }
    }

    /// The store revision at which the free plan was full with no valid synced licence (written by
    /// `LocalStore.commit`), or nil. Lets the AutoFill extension refuse a passkey creation before Face ID;
    /// it counts only while it names the store's current revision, so a stale value is ignored. Not secret:
    /// one flag and a revision number.
    public var planFullRevision: Int64? {
        get { access(keyPath: \.planFullRevision); return int(Key.planFullRevision) }
        set { withMutation(keyPath: \.planFullRevision) { defaults.set(newValue, forKey: Key.planFullRevision) } }
    }

    /// Mac only: maximum unlocked session length in seconds, nil (default) for no limit.
    public var maxSessionSeconds: Int64? {
        get { access(keyPath: \.maxSessionSeconds); return int(Key.maxSessionSeconds).flatMap { $0 > 0 ? $0 : nil } }
        set { withMutation(keyPath: \.maxSessionSeconds) { defaults.set(newValue, forKey: Key.maxSessionSeconds) } }
    }

    /// Mac only: lock when the screen locks (default on).
    public var lockOnScreenLock: Bool {
        get { access(keyPath: \.lockOnScreenLock); return bool(Key.lockOnScreenLock, true) }
        set { withMutation(keyPath: \.lockOnScreenLock) { defaults.set(newValue, forKey: Key.lockOnScreenLock) } }
    }

    /// Mac only: lock when the Mac goes to sleep (default on).
    public var lockOnSleep: Bool {
        get { access(keyPath: \.lockOnSleep); return bool(Key.lockOnSleep, true) }
        set { withMutation(keyPath: \.lockOnSleep) { defaults.set(newValue, forKey: Key.lockOnSleep) } }
    }

    /// Mac only: Touch ID unlock was turned on.
    public var touchIDUnlock: Bool {
        get { access(keyPath: \.touchIDUnlock); return bool(Key.touchIDUnlock, false) }
        set { withMutation(keyPath: \.touchIDUnlock) { defaults.set(newValue, forKey: Key.touchIDUnlock) } }
    }

    /// Mac only (Windows `breach_check_enabled`): off until the person turns it on.
    public var breachCheckEnabled: Bool {
        get { access(keyPath: \.breachCheckEnabled); return bool(Key.breachCheckEnabled, false) }
        set { withMutation(keyPath: \.breachCheckEnabled) { defaults.set(newValue, forKey: Key.breachCheckEnabled) } }
    }

    /// Mac only (Windows `strict_offline_mode`): on until the person turns it off.
    public var strictOfflineMode: Bool {
        get { access(keyPath: \.strictOfflineMode); return bool(Key.strictOfflineMode, true) }
        set { withMutation(keyPath: \.strictOfflineMode) { defaults.set(newValue, forKey: Key.strictOfflineMode) } }
    }

    /// iPhone only: reminder notifications say "{title} is due"; off (the default) says "A reminder is due".
    public var showItemNamesInPhoneReminders: Bool {
        get { access(keyPath: \.showItemNamesInPhoneReminders); return bool(Key.phoneReminderNames, false) }
        set { withMutation(keyPath: \.showItemNamesInPhoneReminders) { defaults.set(newValue, forKey: Key.phoneReminderNames) } }
    }

    /// Mac only: reminder notifications say "{title} is due"; off says "A reminder is due" (lock screen privacy).
    public var showItemNamesInReminders: Bool {
        get { access(keyPath: \.showItemNamesInReminders); return bool(Key.showItemNamesInReminders, true) }
        set { withMutation(keyPath: \.showItemNamesInReminders) { defaults.set(newValue, forKey: Key.showItemNamesInReminders) } }
    }

    /// Mac only: Wi-Fi sync hosting turned on (default off).
    public var wifiSyncOn: Bool {
        get { access(keyPath: \.wifiSyncOn); return bool(Key.wifiSyncOn, false) }
        set { withMutation(keyPath: \.wifiSyncOn) { defaults.set(newValue, forKey: Key.wifiSyncOn) } }
    }

    /// Mac only: the chosen listening address as "host:port" (nil until one is chosen). Validated by the app.
    public var wifiSyncEndpoint: String? {
        get { access(keyPath: \.wifiSyncEndpoint); return defaults.string(forKey: Key.wifiSyncEndpoint) }
        set { withMutation(keyPath: \.wifiSyncEndpoint) { defaults.set(newValue, forKey: Key.wifiSyncEndpoint) } }
    }

    /// Setup steps finished on this device (`SetupStep` raw names; unknown names are ignored when read).
    public var setupDone: [String] {
        get { access(keyPath: \.setupDone); return defaults.stringArray(forKey: Key.setupDone) ?? [] }
        set { withMutation(keyPath: \.setupDone) { defaults.set(newValue, forKey: Key.setupDone) } }
    }

    /// The setup pages were finished or skipped once (they do not open again by themselves).
    public var setupSeen: Bool {
        get { access(keyPath: \.setupSeen); return bool(Key.setupSeen, false) }
        set { withMutation(keyPath: \.setupSeen) { defaults.set(newValue, forKey: Key.setupSeen) } }
    }

    /// Hide on the vault's "Finish setting up" card (until Settings › Show setup again).
    public var setupCardHidden: Bool {
        get { access(keyPath: \.setupCardHidden); return bool(Key.setupCardHidden, false) }
        set { withMutation(keyPath: \.setupCardHidden) { defaults.set(newValue, forKey: Key.setupCardHidden) } }
    }

    /// The avatar's letters (Settings › Appearance), at most two; empty shows the person glyph.
    public var initials: String {
        get { access(keyPath: \.initials); return defaults.string(forKey: Key.initials) ?? "" }
        set { withMutation(keyPath: \.initials) { defaults.set(AvatarInitials.from(newValue) ?? "", forKey: Key.initials) } }
    }
}

/// Up to two upper-cased letters for the avatar: the first letters of the first two words, or the first two
/// letters of a single word. Nil when there are no letters.
public enum AvatarInitials {
    public static func from(_ text: String) -> String? {
        let words = text.split(whereSeparator: { $0.isWhitespace }).map { $0.filter(\.isLetter) }.filter { !$0.isEmpty }
        guard let first = words.first else { return nil }
        let letters = words.count >= 2 ? String(words[0].prefix(1)) + String(words[1].prefix(1)) : String(first.prefix(2))
        return letters.uppercased()
    }
}
