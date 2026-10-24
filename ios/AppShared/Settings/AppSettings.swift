import Foundation
import Observation

/// How long the app may stay in the background before it locks.
public enum AutoLockDelay: Int64, CaseIterable, Identifiable, Sendable {
    case immediately = 0, oneMinute = 60, fiveMinutes = 300, fifteenMinutes = 900, oneHour = 3600
    public var id: Int64 { rawValue }
    public var label: String {
        switch self {
        case .immediately: "Immediately"
        case .oneMinute: "After 1 minute"
        case .fiveMinutes: "After 5 minutes"
        case .fifteenMinutes: "After 15 minutes"
        case .oneHour: "After 1 hour"
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
        case .oneMinute: "1 minute"
        case .fiveMinutes: "5 minutes"
        case .fifteenMinutes: "15 minutes"
        case .thirtyMinutes: "30 minutes"
        case .never: "Never"
        }
    }
}

/// When a copied secret leaves the clipboard. There is no "never": copies always expire.
public enum ClipboardExpiry: Int64, CaseIterable, Identifiable, Sendable {
    case thirtySeconds = 30, sixtySeconds = 60, twoMinutes = 120, fiveMinutes = 300
    public var id: Int64 { rawValue }
    public var label: String {
        switch self {
        case .thirtySeconds: "30 seconds"
        case .sixtySeconds: "60 seconds"
        case .twoMinutes: "2 minutes"
        case .fiveMinutes: "5 minutes"
        }
    }
}

public enum Appearance: String, CaseIterable, Identifiable, Sendable {
    case system, light, dark
    public var id: String { rawValue }
    public var label: String {
        switch self {
        case .system: "System"
        case .light: "Light"
        case .dark: "Dark"
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
        public static let all = [autoLockDelay, idleLock, clipboardExpiry, concealSecretsInDetail, showCodesRow, showWebsiteIcons,
                                 copyCodeOnFill, showInQuickType, quickTypeExactSites, offerPasskeys, appearance, generatorOptions, erasePending, identityRemovalPending, initials,
                                 planFullRevision]
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
