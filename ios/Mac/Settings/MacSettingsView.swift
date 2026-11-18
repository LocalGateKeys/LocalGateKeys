import SwiftUI
import AppKit
import AppSharedMac

extension Appearance {
    /// The window's colour scheme: nil follows the system.
    var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}

/// Settings (⌘, and the sidebar's Settings): Locking, Unlocking, Privacy, Appearance and Plan. Choices go
/// straight to `AppSettings` (shared with the iPhone's values); the lock model and clipboard read them live.
@MainActor @Observable
final class MacSettingsModel {
    /// Maximum session lengths offered, in seconds; nil is Off.
    static let maxSessionChoices: [Int64?] = [nil, 3600, 4 * 3600, 8 * 3600, 12 * 3600]

    static func maxSessionLabel(_ seconds: Int64?) -> String {
        guard let seconds else { return String(localized: "Off") }
        let hours = seconds / 3600
        return hours == 1 ? String(localized: "1 hour") : String(localized: "\(hours) hours")
    }

    let settings: AppSettings
    let pro: ProModel
    @ObservationIgnored let passwords: (any MasterPasswordService)?
    /// The Mac-local data, where Recently deleted's retention lives (vault-local, never synced).
    @ObservationIgnored let local: (any LocalDataHosting)?
    @ObservationIgnored private let clock: () -> Date
    /// Run after an AutoFill setting changes (republishes or removes the identities).
    @ObservationIgnored var onAutoFillChanged: () -> Void = { MacAppEnvironment.lockState?.autoFillSettingsChanged() }

    /// A section the palette asked for (scrolled to, then cleared).
    var requestedSection: SettingsSection?
    /// The palette's Change master password: opens the sheet once Settings shows.
    var requestsPasswordChange = false

    /// The error line of the Change master password sheet.
    var passwordMessage: String?
    /// The error line of the Touch ID password prompt.
    var touchIDMessage: String?
    private(set) var busy = false

    init(settings: AppSettings, pro: ProModel, passwords: (any MasterPasswordService)?, local: (any LocalDataHosting)? = nil,
         clock: @escaping () -> Date = Date.init) {
        self.settings = settings; self.pro = pro; self.passwords = passwords; self.local = local; self.clock = clock
        self.factors = (passwords as? any FactorService).map { FactorSettingsModel(service: $0) }
        self.restoreTestWeekly = (settings.defaults.object(forKey: RestoreTestModel.weeklyKey) as? Bool) ?? true
        // Windows settings added 2026-11-14 (MacExtraSettings).
        self.idleSource = MacExtraSettings.idleSource(settings.defaults)
        self.totpConfirm = MacExtraSettings.totpConfirm(settings.defaults)
        self.documentOpenEnabled = MacExtraSettings.documentOpenEnabled(settings.defaults)
        self.automaticBackupCount = MacExtraSettings.automaticBackupCount(settings.defaults)
    }

    /// Windows `trash_retention_days` choices (1–365; 30 by default).
    static let trashRetentionChoices = [1, 7, 14, 30, 90, 180, 365]
    static func retentionLabel(_ days: Int) -> String { days == 1 ? String(localized: "1 day") : String(localized: "\(days) days") }

    /// Recently deleted settings change only while the vault (and so its local data) is open.
    var canChangeTrash: Bool { local?.localData != nil }

    /// The offered choices, plus a stored value that isn't one of them.
    var trashRetentionOptions: [Int] {
        Array(Set(Self.trashRetentionChoices + [trashRetentionDays])).sorted()
    }

    /// Windows `trash_retention_days`: how long deleted items stay before automatic emptying.
    var trashRetentionDays: Int {
        get { local?.localData?.preferences.trashRetentionDays ?? 30 }
        set { updateTrashPreferences { $0.trashRetentionDays = min(max(newValue, 1), 365) } }
    }

    /// Windows `trash_auto_purge` (on by default).
    var trashAutoPurge: Bool {
        get { local?.localData?.preferences.trashAutoPurge ?? true }
        set { updateTrashPreferences { $0.trashAutoPurge = newValue } }
    }

    /// Saves the new preference and purges what has now expired (a failed save changes nothing).
    private func updateTrashPreferences(_ change: (inout LocalData.LocalPreferences) -> Void) {
        guard let local, var data = local.localData else { return }
        change(&data.preferences)
        data.purgeExpiredTrash(now: Int64(clock().timeIntervalSince1970))
        try? local.commitLocalData(data)
    }

    var autoLock: IdleLock {
        get { settings.idleLock }
        set { settings.idleLock = newValue }
    }

    var maxSession: Int64? {
        get { settings.maxSessionSeconds }
        set { settings.maxSessionSeconds = newValue }
    }

    var lockOnScreenLock: Bool {
        get { settings.lockOnScreenLock }
        set { settings.lockOnScreenLock = newValue }
    }

    var lockOnSleep: Bool {
        get { settings.lockOnSleep }
        set { settings.lockOnSleep = newValue }
    }

    /// The iPhone's choices (30 s, 60 s, 2 min, 5 min; copies always expire) so both apps agree.
    var clipboardExpiry: ClipboardExpiry {
        get { settings.clipboardExpiry }
        set { settings.clipboardExpiry = newValue }
    }

    /// Windows `breach_check_enabled` (off by default): lets the Security centre's check buttons run.
    var breachCheckEnabled: Bool {
        get { settings.breachCheckEnabled }
        set { settings.breachCheckEnabled = newValue }
    }

    /// Windows `erase_on_sync_removal` (on by default): a verified removal notice erases this Mac's vault.
    var eraseOnSyncRemoval: Bool {
        get { settings.eraseOnSyncRemoval }
        set { settings.eraseOnSyncRemoval = newValue }
    }

    /// Windows `strict_offline_mode` (on by default): refuses every breach check.
    var strictOfflineMode: Bool {
        get { settings.strictOfflineMode }
        set { settings.strictOfflineMode = newValue }
    }

    /// Mac only (on by default): reminder notifications name the item; off says "A reminder is due".
    var showItemNamesInReminders: Bool {
        get { settings.showItemNamesInReminders }
        set { settings.showItemNamesInReminders = newValue }
    }

    /// The iPhone's "Show logins in the QuickType bar" (on by default): off removes every AutoFill identity.
    var showInQuickType: Bool {
        get { settings.showInQuickType }
        set { settings.showInQuickType = newValue; onAutoFillChanged() }
    }

    /// The iPhone's "Include exact-site logins" (off by default): exact-site logins are published for their exact host.
    var quickTypeExactSites: Bool {
        get { settings.quickTypeExactSites }
        set { settings.quickTypeExactSites = newValue; onAutoFillChanged() }
    }

    /// The iPhone's "Offer LocalGateKeys for passkeys" (on by default).
    var offerPasskeys: Bool {
        get { settings.offerPasskeys }
        set { settings.offerPasskeys = newValue; onAutoFillChanged() }
    }

    /// Windows `restore_test_weekly` (on by default): the same value the Security centre's restore test switch uses.
    var restoreTestWeekly: Bool {
        didSet { settings.defaults.set(restoreTestWeekly, forKey: RestoreTestModel.weeklyKey) }
    }

    // MARK: Windows settings added 2026-11-14 (MacExtraSettings)

    /// Windows `idle_source` (Computer by default): what resets the auto-lock timer.
    var idleSource: MacExtraSettings.IdleSource {
        didSet { settings.defaults.set(idleSource.rawValue, forKey: MacExtraSettings.idleSourceKey) }
    }

    /// Windows `totp_confirm` (off by default): ask before each copy of a 2FA code.
    var totpConfirm: Bool {
        didSet { settings.defaults.set(totpConfirm, forKey: MacExtraSettings.totpConfirmKey) }
    }

    /// Windows `document_open_enabled` (on by default): documents may open in their default app.
    var documentOpenEnabled: Bool {
        didSet { settings.defaults.set(documentOpenEnabled, forKey: MacExtraSettings.documentOpenKey) }
    }

    /// Windows `automatic_backup_count` (5 by default, 0 is Off): copies kept as you save.
    var automaticBackupCount: Int {
        didSet { settings.defaults.set(MacExtraSettings.validatedBackupCount(automaticBackupCount), forKey: MacExtraSettings.automaticBackupCountKey) }
    }

    var appearance: Appearance {
        get { settings.appearance }
        set { settings.appearance = newValue }
    }

    var touchIDOn: Bool { settings.touchIDUnlock }
    static let lockedMessage = String(localized: "Unlock LocalGateKeys to change settings.")
    /// Locking and Unlocking change only while the vault is open (Appearance, Privacy and Plan always).
    var isUnlocked: Bool { passwords?.isUnlocked ?? false }
    var canChangeLocking: Bool { isUnlocked }
    var canChangeUnlocking: Bool { isUnlocked && (passwords?.hasVault ?? false) }
    /// Settings › Duress password (sub-plan 08): the lock model, when it offers it.
    var duress: (any DuressService)? { passwords as? any DuressService }
    var touchIDAvailable: Bool { passwords?.touchIDAvailable ?? false }
    /// Key file and YubiKey (Settings › Unlocking), when the vault offers them.
    @ObservationIgnored let factors: FactorSettingsModel?
    /// "Always ask for the key file / YubiKey" is on with a factor set: Touch ID stays off.
    var touchIDBlockedByFactors: Bool {
        _ = factors?.revision   // re-read after every factor change on the page
        return settings.factorsAlwaysAsk && !((passwords as? any FactorService)?.factorSpecs.isEmpty ?? true)
    }
    /// Read from the key file when Settings opens and after the recovery phrase sheet closes.
    private(set) var recoveryPhraseSet = false
    func refreshRecoveryPhrase() { recoveryPhraseSet = passwords?.hasRecoveryPhrase ?? false }

    /// Changes the master password; false (with `passwordMessage`) when it did not.
    func changePassword(current: String, new: String, confirm: String) async -> Bool {
        guard !busy, canChangeUnlocking, let passwords else { return false }
        guard !current.isEmpty else { passwordMessage = String(localized: "Enter your current master password."); return false }
        guard new == confirm else { passwordMessage = String(localized: "The new passwords don't match."); return false }
        busy = true; passwordMessage = nil
        defer { busy = false }
        do {
            try await passwords.changePassword(old: current, new: new)
            return true
        } catch {
            passwordMessage = MacLockModel.describe(error, now: clock())
            return false
        }
    }

    /// Turns Touch ID unlock on or off after checking the master password; false (with `touchIDMessage`) when not.
    func setTouchID(_ on: Bool, password: String) async -> Bool {
        guard !busy, canChangeUnlocking, let passwords else { return false }
        busy = true; touchIDMessage = nil
        defer { busy = false }
        do {
            try await passwords.setTouchID(on, password: password)
            return true
        } catch {
            touchIDMessage = MacLockModel.describe(error, now: clock())
            return false
        }
    }

    func clearMessages() { passwordMessage = nil; touchIDMessage = nil }
}

/// The Settings tabs (UX refresh 2026-11-12). Every former section has a home:
/// General (menu bar & startup, setup, reminder notifications), Security (locking, unlocking, privacy),
/// AutoFill, Backups (Recovery centre, Recently deleted), Appearance, Plan (Pro, Licence), Advanced (Developer).
enum SettingsTab: String, CaseIterable, Identifiable, Hashable {
    case general, security, autoFill, backups, appearance, plan, advanced

    var id: String { rawValue }

    var title: String {
        switch self {
        case .general: String(localized: "settings.tab.general", defaultValue: "General")
        case .security: String(localized: "settings.tab.security", defaultValue: "Security")
        case .autoFill: String(localized: "AutoFill")
        case .backups: String(localized: "Backups")
        case .appearance: String(localized: "Appearance")
        case .plan: String(localized: "Plan")
        case .advanced: String(localized: "settings.tab.advanced", defaultValue: "Advanced")
        }
    }

    var symbol: String {
        switch self {
        case .general: "gearshape"
        case .security: "lock.shield"
        case .autoFill: "key"
        case .backups: "externaldrive"
        case .appearance: "paintbrush"
        case .plan: "checkmark.seal"
        case .advanced: "wrench.and.screwdriver"
        }
    }

    /// The tab that holds a section the palette asks for.
    static func tab(for section: SettingsSection) -> SettingsTab {
        switch section {
        case .locking, .unlocking, .privacy: .security
        case .appearance: .appearance
        case .plan: .plan
        }
    }
}

/// A row's title and the help text shown under it (also what the search field matches).
struct SettingsRowText {
    let title: String
    let detail: String?
}

/// The settings page: tabs (General … Advanced), a search field that filters rows across all tabs, and help text
/// under each row. A native tabbed window for ⌘, (`standalone`), or a tab bar inside the main window's shell panel
/// (the sidebar's Settings).
struct MacSettingsView: View {
    @Bindable var model: MacSettingsModel
    /// True in the Settings window: draws its own wash behind the cards.
    var standalone = false
    /// Both windows show every row. The main window passes its own paths; the ⌘, window leaves these nil and they
    /// open the page in the main window (opened first when none is on screen), through `QuickAccessBridge`.
    /// Backups › Recovery centre.
    var onRecoveryCentre: (() -> Void)? = nil
    /// General › Show setup again (workstream 4).
    var onShowSetup: (() -> Void)? = nil
    /// The backup schedule (Backups › Scheduled backups and the emergency kit's folders); nil uses the app's.
    var scheduleModel: BackupScheduleModel? = nil
    /// Plan › Licence.
    var onLicence: (() -> Void)? = nil
    @Environment(\.macTheme) private var theme
    @Environment(\.openWindow) private var openWindow
    @State private var tab: SettingsTab = .general
    @State private var query = ""
    @State private var changingPassword = false
    @State private var recoveryPhrase: RecoveryPhraseSheet.Mode?
    @State private var touchIDPrompt: Bool?   // the state being turned to, while asking for the password
    @AppStorage(QuickAccessSettings.showMenuBarKey) private var showMenuBarIcon = true
    @AppStorage(QuickAccessSettings.hotKeyKey) private var quickAccessHotKey = true
    @AppStorage(CaptureProtection.key) private var hideFromCapture = true
    @State private var hotKeyMessage: String?
    /// Bumped when the shortcut's keys change, so its help text shows the new keys.
    @State private var hotKeyRevision = 0
    @State private var captureRestartNote = false
    @State private var openAtLogin = false
    @State private var loginItemMessage: String?
    /// Settings › Advanced › Developer (SSH agent, keys, setup lines) and its plain-secrets scan sheet while open.
    @State private var developer = DeveloperSettingsModel()
    @State private var secretScan: SecretScanModel?

    var body: some View {
        content
        .background { if standalone { WashBackground() } }
        .onAppear { openAtLogin = LoginItem.isOn || LoginItem.needsApproval }
        .sheet(isPresented: Binding(get: { recoveryPhrase != nil }, set: { if !$0 { recoveryPhrase = nil } }),
               onDismiss: { model.refreshRecoveryPhrase() }) {
            if let passwords = model.passwords, let mode = recoveryPhrase {
                RecoveryPhraseSheet(passwords: passwords, mode: mode, onClose: { recoveryPhrase = nil },
                                    kitFacts: { EmergencyKitDocument.macFacts(schedule: schedule) }).macThemed()
            }
        }
        .onAppear { model.refreshRecoveryPhrase() }
        .sheet(isPresented: Binding(get: { secretScan != nil && model.isUnlocked }, set: { if !$0 { secretScan?.reset(); secretScan = nil } })) {
            if let secretScan {
                SecretScanSheet(model: secretScan, onClose: { secretScan.reset(); self.secretScan = nil }).macThemed()
            }
        }
        .sheet(isPresented: $changingPassword) {
            ChangePasswordSheet(model: model, onClose: { changingPassword = false }).macThemed()
        }
        .sheet(isPresented: Binding(get: { touchIDPrompt != nil }, set: { if !$0 { touchIDPrompt = nil } })) {
            TouchIDPasswordSheet(model: model, turningOn: touchIDPrompt ?? true, onClose: { touchIDPrompt = nil }).macThemed()
        }
    }

    /// ⌘, gets the native tabbed Settings window; the main window gets a tab bar above the page.
    @ViewBuilder private var content: some View {
        if standalone {
            TabView(selection: $tab) {
                ForEach(SettingsTab.allCases) { t in
                    page(t)
                        .tabItem { Label(t.title, systemImage: t.symbol) }
                        .tag(t)
                }
            }
        } else {
            VStack(alignment: .leading, spacing: 0) {
                tabBar.padding(.horizontal, 18).padding(.top, 14)
                page(tab)
            }
        }
    }

    /// The main window's tab bar (the Settings window uses the system's).
    private var tabBar: some View {
        ScrollView(.horizontal, showsIndicators: false) { tabButtons }
    }

    private var tabButtons: some View {
        HStack(spacing: 4) {
            ForEach(SettingsTab.allCases) { t in
                Button { tab = t; query = "" } label: {
                    Label(t.title, systemImage: t.symbol).labelStyle(.titleAndIcon)
                        .font(.system(size: 12.5, weight: tab == t && query.isEmpty ? .semibold : .regular))
                        .foregroundStyle(theme.text)
                        .padding(.horizontal, 10).padding(.vertical, 5)
                        .background {
                            if tab == t && query.isEmpty {
                                Capsule().fill(theme.selection)
                            }
                        }
                        .fixedSize()
                        .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(tab == t ? .isSelected : [])
            }
        }
    }

    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(theme.textFaint)
            TextField(String(localized: "settings.search", defaultValue: "Search settings"), text: $query)
                .textFieldStyle(.plain)
            if !query.isEmpty {
                Button { query = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(theme.textFaint) }
                    .buttonStyle(.plain)
                    .accessibilityLabel(String(localized: "settings.search.clear", defaultValue: "Clear search"))
            }
        }
        .font(.system(size: 13))
        .padding(.horizontal, 12).padding(.vertical, 6)
        .background(theme.card, in: Capsule())
        .overlay(Capsule().strokeBorder(theme.panelBorder))
    }

    /// One tab's page, or every tab's matching rows while searching.
    private func page(_ shownTab: SettingsTab) -> some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    HStack(alignment: .center, spacing: 12) {
                        Text(searching ? String(localized: "settings.search.results", defaultValue: "Search results") : shownTab.title)
                            .font(.system(size: 19, weight: .semibold)).foregroundStyle(theme.text)
                        Spacer(minLength: 12)
                        searchField.frame(maxWidth: 240)
                    }
                    if !model.isUnlocked {
                        Label(MacSettingsModel.lockedMessage, systemImage: "lock.fill")
                            .font(.system(size: 13)).foregroundStyle(theme.textMuted)
                    }
                    if searching {
                        ForEach(SettingsTab.allCases) { t in tabContent(t) }
                        if !anyMatch {
                            Text(String(localized: "settings.search.none", defaultValue: "No settings match your search."))
                                .font(.system(size: 13)).foregroundStyle(theme.textMuted)
                        }
                    } else {
                        tabContent(shownTab)
                    }
                }
                .padding(standalone ? 24 : 18)
                .padding(.bottom, 24)   // Plan's Buy and Restore scroll clear of the panel's edge
                .frame(maxWidth: 640, alignment: .leading)
                .frame(maxWidth: .infinity, alignment: standalone ? .center : .leading)
            }
            .onAppear { followRequests(proxy) }
            .onChange(of: model.requestedSection) { _, _ in followRequests(proxy) }
            .onChange(of: model.requestsPasswordChange) { _, _ in followRequests(proxy) }
        }
    }

    @ViewBuilder private func tabContent(_ t: SettingsTab) -> some View {
        switch t {
        case .general: generalTab
        case .security: securityTab
        case .autoFill: autoFillTab
        case .backups: backupsTab
        case .appearance: appearanceTab
        case .plan: planTab
        case .advanced: advancedTab
        }
    }

    // MARK: row texts (titles and help, also what the search matches)

    private var tAutoLock: SettingsRowText { .init(title: String(localized: "Auto-lock after inactivity"),
        detail: String(localized: "settings.help.autoLock", defaultValue: "Locks LocalGateKeys when you haven't used it for this long.")) }
    private var tScreenLock: SettingsRowText { .init(title: String(localized: "Lock when the screen locks"),
        detail: String(localized: "settings.help.screenLock", defaultValue: "Locks as soon as the Mac's screen locks or the screen saver starts.")) }
    private var tSleep: SettingsRowText { .init(title: String(localized: "Lock when the Mac sleeps"),
        detail: String(localized: "settings.help.sleep", defaultValue: "Locks before the Mac goes to sleep.")) }
    private var tMaxSession: SettingsRowText { .init(title: String(localized: "Maximum session"),
        detail: String(localized: "settings.help.maxSession", defaultValue: "Locks after this long even while you are using it.")) }
    private var tMenuBar: SettingsRowText { .init(title: String(localized: "Show in the menu bar"),
        detail: String(localized: "settings.help.menuBar", defaultValue: "A key icon in the menu bar to search and copy without opening the window.")) }
    private var tHotKey: SettingsRowText {
        _ = hotKeyRevision
        return .init(title: String(localized: "Quick access shortcut"),
                     detail: String(localized: "\(QuickAccessSettings.hotKeyLabel) opens Search Everything from any app."))
    }
    private var tLogin: SettingsRowText { .init(title: String(localized: "Open at login"),
        detail: LoginItem.needsApproval ? String(localized: "Waiting for approval in System Settings › General › Login Items.")
                                        : String(localized: "settings.help.openAtLogin", defaultValue: "Starts LocalGateKeys, locked, when you log in to this Mac.")) }
    private var tSetup: SettingsRowText { .init(title: String(localized: "Set up LocalGateKeys"),
        detail: String(localized: "Touch ID, import, recovery phrase and the Safari extension.")) }
    private var tReminderNames: SettingsRowText { .init(title: String(localized: "Show item names in reminders"),
        detail: String(localized: "Notifications can appear on the lock screen. When off, they say \u{201C}A reminder is due\u{201D}.")) }
    private var tMasterPassword: SettingsRowText { .init(title: String(localized: "Master password"),
        detail: String(localized: "Used to open your vault on this Mac.")) }
    private var tTouchID: SettingsRowText { .init(title: String(localized: "Touch ID"),
        detail: model.touchIDBlockedByFactors ? MacFactors.touchIDOff
            : model.touchIDAvailable ? String(localized: "Unlock with your fingerprint. If your fingerprints change, your master password is needed again.")
                                     : String(localized: "Touch ID isn't available on this Mac.")) }
    private var tPhrase: SettingsRowText { .init(title: String(localized: "Recovery phrase"),
        detail: model.recoveryPhraseSet
            ? String(localized: "Set. 24 words that replace a forgotten master password. Creating a new one replaces it.")
            : String(localized: "24 words that replace a forgotten master password. Shown once; write them down.")) }
    private var tClipboard: SettingsRowText { .init(title: String(localized: "Clear clipboard after"),
        detail: String(localized: "settings.help.clipboard", defaultValue: "Copied passwords and codes are removed from the clipboard after this time.")) }
    private var tBreach: SettingsRowText { .init(title: String(localized: "Breach checks"),
        detail: String(localized: "You start each check. It sends 5 characters of a hash, never the password.")) }
    private var tOffline: SettingsRowText { .init(title: String(localized: "Strict offline mode"),
        detail: String(localized: "Blocks background internet requests, website icons and breach checks")) }
    private var tCapture: SettingsRowText { .init(title: String(localized: "settings.hideFromCapture.title", defaultValue: "Hide from screenshots and screen sharing"),
        detail: String(localized: "settings.hideFromCapture.desc", defaultValue: "Other programs, screen recorders and video calls cannot capture this window")) }
    private var tErase: SettingsRowText { .init(title: DeviceRemoval.eraseSettingTitle, detail: DeviceRemoval.eraseSettingText) }
    private var tQuickType: SettingsRowText { .init(title: String(localized: "Show logins in AutoFill suggestions"),
        detail: String(localized: "Usernames and website names only, never passwords.")) }
    private var tExactSites: SettingsRowText { .init(title: String(localized: "Include exact-site logins"),
        detail: String(localized: "Suggestions are offered by domain, so a login saved for one site can also be offered on other pages of the same domain.")) }
    private var tPasskeys: SettingsRowText { .init(title: String(localized: "Offer passkeys"),
        detail: String(localized: "settings.help.passkeys", defaultValue: "Lets websites and apps sign in with passkeys saved in LocalGateKeys.")) }
    private var tPasskeyCheck: SettingsRowText { .init(title: String(localized: "Passkey check"), detail: MacPasskeyDoctor.howTo) }
    private var tRecoveryCentre: SettingsRowText { .init(title: String(localized: "Recovery centre"),
        detail: String(localized: "Full backups, restore, the recovery kit and old backups.")) }
    private var tRestoreTest: SettingsRowText { .init(title: RestoreTestModel.weeklyLabel,
        detail: String(localized: "Each week, prove that a scheduled backup restores. Nothing is stored; if no backup ran, the test runs at the next unlock.")) }
    private var tSchedule: SettingsRowText { .init(title: RecoveryCentreModel.scheduleTitle, detail: RecoveryCentreModel.scheduleText) }
    private var tAutoPurge: SettingsRowText { .init(title: String(localized: "Empty trash automatically"),
        detail: String(localized: "When off, deleted items stay in the trash until you delete them")) }
    private var tRetention: SettingsRowText { .init(title: String(localized: "Empty Recently deleted after"),
        detail: String(localized: "Used while automatic emptying is on")) }
    private var tTheme: SettingsRowText { .init(title: String(localized: "Theme"),
        detail: String(localized: "settings.help.theme", defaultValue: "Light, dark, or the same as macOS.")) }
    private var tLicence: SettingsRowText { .init(title: String(localized: "Licence"),
        detail: String(localized: "settings.help.licence", defaultValue: "Your licence key, and how to move Pro to another device.")) }
    private var tPlan: SettingsRowText { .init(title: String(localized: "Plan"),
        detail: String(localized: "Pro and purchases")) }
    private var tDeveloper: SettingsRowText { .init(title: String(localized: "developer.title", defaultValue: "Developer"),
        detail: String(localized: "settings.help.developer", defaultValue: "SSH agent, SSH keys and the scan for passwords saved in plain text.")) }

    // Windows settings added 2026-11-14 (MacExtraSettings).
    private var tIdleSource: SettingsRowText { .init(title: String(localized: "Count activity from"),
        detail: String(localized: "Computer: keyboard or mouse anywhere. Vault: using or saving items.")) }
    private var tTotpConfirm: SettingsRowText { .init(title: String(localized: "Ask before releasing 2FA codes"),
        detail: String(localized: "Confirm on this Mac each time a 2FA code is copied")) }
    private var tDocOpen: SettingsRowText { .init(title: String(localized: "Open documents in other apps"),
        detail: String(localized: "Puts a decrypted copy on this Mac while you use it; deleted when the vault locks")) }
    private var tAutoBackups: SettingsRowText { .init(title: String(localized: "Automatic backups to keep"),
        detail: String(localized: "Copies made as you save. Older ones may still hold deleted items.")) }
    private var tShortcuts: SettingsRowText { .init(title: String(localized: "Keyboard shortcuts"), detail: nil) }
    private var tConnections: SettingsRowText { .init(title: String(localized: "Devices & connections"),
        detail: String(localized: "Browser extension status and diagnostics")) }
    private var tPrivacyPolicy: SettingsRowText { .init(title: String(localized: "Privacy policy"),
        detail: String(localized: "How LocalGateKeys handles your data")) }
    private var tEula: SettingsRowText { .init(title: String(localized: "Licence agreement"),
        detail: String(localized: "The terms for using LocalGateKeys")) }
    private var extraTerms: [SettingsRowText] { [tIdleSource, tTotpConfirm, tDocOpen, tAutoBackups] + helpTerms }
    private var helpTerms: [SettingsRowText] { [tShortcuts, tConnections, tPrivacyPolicy, tEula] }

    // MARK: main window pages

    private var schedule: BackupScheduleModel? { scheduleModel ?? MacAppEnvironment.backupSchedule }

    /// From the ⌘, window: the main window shows `page` (opened when none is on screen) and comes forward.
    private func showInMainWindow(_ page: QuickAccessBridge.Page) {
        QuickAccessBridge.shared.open(page)
        if QuickAccessBridge.shared.openWindows == 0 { openWindow(id: MacAppInfo.mainWindowID) }
        QuickAccessBridge.activate()
    }

    private func openRecoveryCentre() { if let onRecoveryCentre { onRecoveryCentre() } else { showInMainWindow(.recoveryCentre) } }
    private func showSetup() { if let onShowSetup { onShowSetup() } else { showInMainWindow(.showSetup) } }
    private func openLicence() { if let onLicence { onLicence() } else { showInMainWindow(.licence) } }

    // MARK: tabs

    @ViewBuilder private var generalTab: some View {
        section(String(localized: "Menu bar & startup"), terms: [tMenuBar, tHotKey, tLogin]) {
            toggleRow(tMenuBar, isOn: $showMenuBarIcon)
            row(tHotKey) {
                // The keys can be changed (Windows `quick_access_hotkey`); the switch turns the shortcut on or off.
                ShortcutRecorder(message: $hotKeyMessage, onChange: { hotKeyRevision += 1 })
                Toggle("", isOn: Binding(get: { quickAccessHotKey }, set: { on in
                    quickAccessHotKey = on
                    GlobalHotKey.shared.apply()
                    hotKeyMessage = on && !GlobalHotKey.shared.isRegistered
                        ? String(localized: "Another app already uses \(QuickAccessSettings.hotKeyLabel).") : nil
                })).toggleStyle(.switch).labelsHidden()
            }
            if let hotKeyMessage, matches(tHotKey) {
                Text(hotKeyMessage).font(.system(size: 11)).foregroundStyle(theme.danger)
                    .padding(.horizontal, 14).padding(.bottom, 8)
            }
            row(tLogin) {
                Toggle("", isOn: Binding(get: { openAtLogin }, set: { on in
                    loginItemMessage = LoginItem.set(on); openAtLogin = LoginItem.isOn || LoginItem.needsApproval
                })).toggleStyle(.switch).labelsHidden()
            }
            if let loginItemMessage, matches(tLogin) {
                Text(loginItemMessage).font(.system(size: 11)).foregroundStyle(theme.danger)
                    .padding(.horizontal, 14).padding(.bottom, 8)
            }
        }
        section(String(localized: "settings.section.notifications", defaultValue: "Notifications"), terms: [tReminderNames]) {
            toggleRow(tReminderNames, isOn: $model.showItemNamesInReminders)
        }
        section(String(localized: "Setup"), terms: [tSetup]) {
            row(tSetup) {
                Button(Onboarding.showAgainTitle, action: showSetup).buttonStyle(PillButtonStyle(primary: false))
            }
        }
        helpSection
    }

    /// Help & diagnostics (Windows `build_help`): the shortcuts, Devices & connections, and the website's legal pages.
    /// Windows' error log has no Mac counterpart (the Mac logs to the system log, not a file).
    @ViewBuilder private var helpSection: some View {
        section(String(localized: "Help & diagnostics"), terms: helpTerms) {
            row(tShortcuts) {
                Button(String(localized: "View")) { showInMainWindow(.shortcuts) }.buttonStyle(PillButtonStyle(primary: false))
            }
            row(tConnections) {
                Button(String(localized: "Open")) { showInMainWindow(.connections) }.buttonStyle(PillButtonStyle(primary: false))
            }
            row(tPrivacyPolicy) {
                Button(String(localized: "Open")) { NSWorkspace.shared.open(MacExtraSettings.privacyPolicyURL) }
                    .buttonStyle(PillButtonStyle(primary: false))
            }
            row(tEula) {
                Button(String(localized: "Open")) { NSWorkspace.shared.open(MacExtraSettings.licenceAgreementURL) }
                    .buttonStyle(PillButtonStyle(primary: false))
            }
        }
    }

    @ViewBuilder private var securityTab: some View {
        section(String(localized: "Locking"), id: SettingsSection.locking.rawValue,
                terms: [tAutoLock, tIdleSource, tScreenLock, tSleep, tMaxSession, tTotpConfirm]) {
            pickerRow(tAutoLock, selection: $model.autoLock) {
                ForEach(IdleLock.allCases) { Text($0.label).tag($0) }
            }
            pickerRow(tIdleSource, selection: $model.idleSource) {
                ForEach(MacExtraSettings.IdleSource.allCases) { Text($0.label).tag($0) }
            }
            toggleRow(tScreenLock, isOn: $model.lockOnScreenLock)
            toggleRow(tSleep, isOn: $model.lockOnSleep)
            pickerRow(tMaxSession, selection: $model.maxSession) {
                ForEach(MacSettingsModel.maxSessionChoices, id: \.self) { Text(MacSettingsModel.maxSessionLabel($0)).tag($0) }
            }
            toggleRow(tTotpConfirm, isOn: $model.totpConfirm)
        }
        .disabled(!model.canChangeLocking)
        section(String(localized: "Unlocking"), id: SettingsSection.unlocking.rawValue,
                terms: [tMasterPassword, tTouchID, tPhrase, SettingsRowText(title: FactorTexts.section, detail: nil)]) {
            row(tMasterPassword) {
                Button("Change…") { model.clearMessages(); changingPassword = true }
                    .buttonStyle(PillButtonStyle(primary: false))
                    .disabled(!model.canChangeUnlocking)
            }
            row(tTouchID) {
                Toggle("", isOn: Binding(get: { model.touchIDOn }, set: { on in model.clearMessages(); touchIDPrompt = on }))
                    .toggleStyle(.switch).labelsHidden()
                    .disabled(!model.canChangeUnlocking || (!model.touchIDAvailable && !model.touchIDOn)
                              || (model.touchIDBlockedByFactors && !model.touchIDOn))
            }
            if let factors = model.factors, matches(SettingsRowText(title: FactorTexts.section, detail: nil)) {
                divider
                Text(FactorTexts.section.uppercased()).font(.system(size: 10, weight: .semibold)).foregroundStyle(theme.textFaint)
                    .padding(.horizontal, 14).padding(.top, 10)
                FactorSettingsRows(model: factors, touchIDOn: model.touchIDOn)
            }
            row(tPhrase) {
                HStack(spacing: 8) {
                    if model.recoveryPhraseSet {
                        Button("Remove…") { recoveryPhrase = .remove }.buttonStyle(PillButtonStyle(primary: false))
                    }
                    Button(model.recoveryPhraseSet ? String(localized: "Replace…") : String(localized: "Create…")) { recoveryPhrase = .create }
                        .buttonStyle(PillButtonStyle(primary: false))
                }
                .disabled(!model.canChangeUnlocking)
            }
        }
        .disabled(!model.canChangeUnlocking)
        // Duress password (sub-plan 08): its own card, apart from Unlocking (MacDuressSettings.swift).
        if let duress = model.duress {
            section(MacDuressText.title, id: "duress", terms: [MacDuressSection.terms]) {
                MacDuressSection(service: duress, pro: model.pro)
            }
            .disabled(!model.canChangeUnlocking)
        }
        // Travel mode (feature pack §2, Pro): this Mac only; never shown in a duress session.
        if model.isUnlocked, !DuressSession.shared.isOpen, MacAppEnvironment.lockState?.isSecondSession != true,
           let local = model.local, local.localData != nil, let store = MacAppEnvironment.lockState?.store {
            section(String(localized: "Travel mode"), id: "travel", terms: [MacTravelMode.terms]) {
                MacTravelModeSection(local: local, store: store, pro: model.pro, onNeedsPro: { query = ""; tab = .plan })
            }
        }
        section(String(localized: "Privacy"), id: SettingsSection.privacy.rawValue,
                terms: [tClipboard, tBreach, tOffline, tCapture, tErase, tDocOpen]) {
            pickerRow(tClipboard, selection: $model.clipboardExpiry) {
                ForEach(ClipboardExpiry.allCases) { Text($0.label).tag($0) }
            }
            row(tBreach) { Toggle("", isOn: $model.breachCheckEnabled).toggleStyle(.switch).labelsHidden() }
            row(tOffline) { Toggle("", isOn: $model.strictOfflineMode).toggleStyle(.switch).labelsHidden() }
            row(tCapture) {
                Toggle("", isOn: Binding(get: { hideFromCapture }, set: { on in
                    hideFromCapture = on
                    CaptureProtection.shared.apply()
                    captureRestartNote = !on
                })).toggleStyle(.switch).labelsHidden()
            }
            if captureRestartNote, matches(tCapture) {
                // macOS keeps a window shown with sharingType .none hidden (CaptureProtection).
                Text(String(localized: "settings.hideFromCapture.restart",
                            defaultValue: "Windows that are already open stay hidden until you quit and reopen LocalGateKeys."))
                    .font(.system(size: 11)).foregroundStyle(theme.textMuted)
                    .padding(.horizontal, 14).padding(.bottom, 8)
            }
            row(tErase) { Toggle("", isOn: $model.eraseOnSyncRemoval).toggleStyle(.switch).labelsHidden() }
            toggleRow(tDocOpen, isOn: $model.documentOpenEnabled)
        }
        // Privacy proof (feature pack §5): this Mac's facts as a file, signed with the sync key when sync is on.
        if model.isUnlocked, !DuressSession.shared.isOpen, MacAppEnvironment.lockState?.isSecondSession != true,
           let store = MacAppEnvironment.lockState?.store {
            section(String(localized: "Privacy proof"), id: "privacyProof", terms: [MacPrivacyProof.terms]) {
                if matches(MacPrivacyProof.terms) { MacPrivacyProofSection(store: store) }
            }
        }
    }

    @ViewBuilder private var autoFillTab: some View {
        section(String(localized: "AutoFill"), terms: [tQuickType, tExactSites, tPasskeys]) {
            row(tQuickType) { Toggle("", isOn: $model.showInQuickType).toggleStyle(.switch).labelsHidden() }
            row(tExactSites) {
                Toggle("", isOn: $model.quickTypeExactSites).toggleStyle(.switch).labelsHidden()
                    .disabled(!model.showInQuickType)
            }
            toggleRow(tPasskeys, isOn: $model.offerPasskeys)
        }
        // Passkey check (feature pack §6.2): read only; the passkey count needs the open vault.
        section(String(localized: "Passkey check"), id: "passkeyCheck", terms: [tPasskeyCheck]) {
            if matches(tPasskeyCheck) {
                MacPasskeyCheckSection(store: model.isUnlocked ? MacAppEnvironment.lockState?.store : nil,
                                       offerPasskeys: model.offerPasskeys)
            }
        }
    }

    @ViewBuilder private var backupsTab: some View {
        section(String(localized: "Backups"), terms: [tRecoveryCentre, tRestoreTest, tAutoBackups]) {
            row(tRecoveryCentre) {
                Button("Open", action: openRecoveryCentre).buttonStyle(PillButtonStyle(primary: false))
            }
            toggleRow(tRestoreTest, isOn: $model.restoreTestWeekly)
            pickerRow(tAutoBackups, selection: $model.automaticBackupCount) {
                ForEach(MacExtraSettings.backupCountOptions(current: model.automaticBackupCount), id: \.self) {
                    Text(MacExtraSettings.backupCountLabel($0)).tag($0)
                }
            }
        }
        if let schedule {
            // The Recovery centre's own controls (frequency, time, day, keep, folders, backup password).
            section(tSchedule.title, terms: [tSchedule]) {
                if matches(tSchedule) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(tSchedule.detail ?? "").font(.system(size: 11)).foregroundStyle(theme.textMuted)
                            .fixedSize(horizontal: false, vertical: true)
                        ScheduleControls(schedule: schedule, onChange: {})
                    }
                    .padding(.horizontal, 14).padding(.vertical, 10)
                }
            }
        }
        section(String(localized: "Recently deleted"), terms: [tAutoPurge, tRetention]) {
            Group {
                row(tAutoPurge) { Toggle("", isOn: $model.trashAutoPurge).toggleStyle(.switch).labelsHidden() }
                row(tRetention) {
                    Picker("", selection: $model.trashRetentionDays) {
                        ForEach(model.trashRetentionOptions, id: \.self) { Text(MacSettingsModel.retentionLabel($0)).tag($0) }
                    }
                    .labelsHidden().fixedSize()
                }
            }
            .disabled(!model.canChangeTrash)
        }
    }

    @ViewBuilder private var appearanceTab: some View {
        section(String(localized: "Appearance"), id: SettingsSection.appearance.rawValue, terms: [tTheme]) {
            row(tTheme) {
                Picker("", selection: $model.appearance) {
                    ForEach(Appearance.allCases) { Text($0.label).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden().fixedSize()
            }
        }
    }

    @ViewBuilder private var planTab: some View {
        section(String(localized: "Plan"), id: SettingsSection.plan.rawValue, terms: [tPlan, tLicence]) {
            if matches(tPlan) { PlanRows(pro: model.pro) }
            row(tLicence) {
                Button(String(localized: "Open"), action: openLicence).buttonStyle(PillButtonStyle(primary: false))
            }
        }
    }

    @ViewBuilder private var advancedTab: some View {
        section(tDeveloper.title, terms: [tDeveloper, SettingsRowText(title: "SSH", detail: nil)]) {
            Text(tDeveloper.detail ?? "").font(.system(size: 11)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 14).padding(.top, 10)
            DeveloperSettingsView(model: developer, isUnlocked: model.isUnlocked, onScan: {
                secretScan = SecretScanModel(store: { developer.agent.unlockedStore() }, isPro: { model.pro.isPro })
            })
        }
    }

    // MARK: search

    private var trimmedQuery: String { query.trimmingCharacters(in: .whitespacesAndNewlines) }
    private var searching: Bool { !trimmedQuery.isEmpty }

    private func matches(_ text: SettingsRowText) -> Bool {
        let q = trimmedQuery
        guard !q.isEmpty else { return true }
        return text.title.localizedCaseInsensitiveContains(q) || (text.detail?.localizedCaseInsensitiveContains(q) ?? false)
    }

    /// Whether any row of any tab matches (else "No settings match").
    private var anyMatch: Bool {
        let all: [SettingsRowText] = [tAutoLock, tScreenLock, tSleep, tMaxSession, tMenuBar, tHotKey, tLogin, tReminderNames,
                                      tMasterPassword, tTouchID, tPhrase, tClipboard, tBreach, tOffline, tCapture, tErase,
                                      tQuickType, tExactSites, tPasskeys, tAutoPurge, tRetention, tTheme, tPlan, tDeveloper,
                                      SettingsRowText(title: FactorTexts.section, detail: nil), SettingsRowText(title: "SSH", detail: nil)]
            + [tSetup, tRecoveryCentre, tRestoreTest, tLicence, tPasskeyCheck, MacPrivacyProof.terms] + (schedule != nil ? [tSchedule] : []) + extraTerms
        return all.contains(where: matches)
    }

    // MARK: rows

    private var divider: some View { Rectangle().fill(theme.panelBorder).frame(height: 1).padding(.leading, 14) }

    /// The palette's section or Change master password request (the main window's Settings only): its tab opens.
    private func followRequests(_ proxy: ScrollViewProxy) {
        guard !standalone else { return }
        if model.requestsPasswordChange {
            model.requestsPasswordChange = false
            model.requestedSection = .unlocking
            if model.canChangeUnlocking { model.clearMessages(); changingPassword = true }
        }
        if let section = model.requestedSection {
            model.requestedSection = nil
            query = ""
            tab = SettingsTab.tab(for: section)
            DispatchQueue.main.async { withAnimation { proxy.scrollTo(section.rawValue, anchor: .top) } }
        }
    }

    /// A group card; hidden while searching when none of its rows match.
    @ViewBuilder private func section<C: View>(_ title: String, id: String? = nil, terms: [SettingsRowText],
                                               @ViewBuilder _ content: () -> C) -> some View {
        if terms.contains(where: matches) {
            VStack(alignment: .leading, spacing: 6) {
                Text(title.uppercased()).font(.system(size: 11, weight: .semibold)).foregroundStyle(theme.textFaint)
                    .padding(.leading, 4)
                VStack(alignment: .leading, spacing: 0) { content() }
                    .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
                    .clipShape(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
            }
            .id(id ?? title)
        }
    }

    /// A row: title, the help text under it, the control on the right; a hairline above it (hidden under the card's
    /// border on the first row). Left out while searching when neither text matches.
    @ViewBuilder private func row<C: View>(_ text: SettingsRowText, @ViewBuilder _ control: () -> C) -> some View {
        if matches(text) {
            HStack(alignment: .center, spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(text.title).font(.system(size: 13)).foregroundStyle(theme.text)
                    if let detail = text.detail {
                        Text(detail).font(.system(size: 11)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: 12)
                control()
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
            .overlay(alignment: .top) { divider.offset(y: -0.5) }
        }
    }

    private func toggleRow(_ text: SettingsRowText, isOn: Binding<Bool>) -> some View {
        row(text) { Toggle("", isOn: isOn).toggleStyle(.switch).labelsHidden() }
    }

    private func pickerRow<V: Hashable, C: View>(_ text: SettingsRowText, selection: Binding<V>, @ViewBuilder _ options: () -> C) -> some View {
        row(text) {
            Picker("", selection: selection) { options() }.labelsHidden().fixedSize()
        }
    }
}

/// Plan: Pro status, or Buy and Restore purchases.
struct PlanRows: View {
    let pro: ProModel
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if pro.isPro {
                Label("Pro", systemImage: "checkmark.seal.fill").font(.system(size: 13, weight: .semibold)).foregroundStyle(theme.accent)
                Text(MacUpgradeSheet.proStatus).font(.system(size: 13)).foregroundStyle(theme.text)
            } else {
                Text("Free plan").font(.system(size: 13, weight: .semibold)).foregroundStyle(theme.text)
                Text("The free plan holds \(ItemLimit.freeItems) items. Pro unlocks unlimited items and 2FA codes, on this Mac and your iPhone.")
                    .font(.system(size: 12)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    Button(pro.price.map { String(localized: "Buy Pro – \($0)") } ?? String(localized: "Buy Pro")) { Task { await pro.buy() } }
                        .buttonStyle(PillButtonStyle(primary: true))
                        .disabled(pro.busy || !pro.canBuy)
                    Button("Restore purchases") { Task { await pro.restore() } }
                        .buttonStyle(PillButtonStyle(primary: false))
                        .disabled(pro.busy)
                    if pro.busy { ProgressView().controlSize(.small) }
                }
            }
            if let message = pro.message { Text(message).font(.system(size: 12)).foregroundStyle(theme.textMuted) }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 14).padding(.vertical, 12)
        .task { if !pro.isPro { await pro.loadPrice() } }
    }
}

/// Current password, then the new one twice.
struct ChangePasswordSheet: View {
    @Bindable var model: MacSettingsModel
    let onClose: () -> Void
    @Environment(\.macTheme) private var theme
    @State private var current = ""
    @State private var new = ""
    @State private var confirm = ""

    var body: some View {
        VStack(alignment: .leading, spacing: MacTheme.gap) {
            Text("Change master password").font(.title3.weight(.semibold)).foregroundStyle(theme.text)
            Text("Your items stay as they are; only the password that opens them changes.")
                .font(.callout).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            SecureField("Current master password", text: $current).glassField()
            SecureField("New master password", text: $new).glassField()
            SecureField("Repeat new master password", text: $confirm).glassField().onSubmit(submit)
            YubiKeyTouchBanner(prompt: YubiKeyPrompt.shared)
            MessageLine(text: model.passwordMessage)
            HStack {
                Button("Cancel", action: onClose).buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button(action: submit) {
                    if model.busy { ProgressView().controlSize(.small) } else { Text("Change password") }
                }
                .buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(model.busy || current.isEmpty || new.isEmpty || confirm.isEmpty)
            }
        }
        .disabled(model.busy)
        .padding(24).frame(width: 380)
        .background(WashBackground())
    }

    private func submit() {
        Task {
            if await model.changePassword(current: current, new: new, confirm: confirm) { onClose() }
            else { current = "" }
        }
    }
}

/// Turning Touch ID on or off asks for the master password.
struct TouchIDPasswordSheet: View {
    @Bindable var model: MacSettingsModel
    let turningOn: Bool
    let onClose: () -> Void
    @Environment(\.macTheme) private var theme
    @State private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: MacTheme.gap) {
            Text(turningOn ? String(localized: "Turn on Touch ID") : String(localized: "Turn off Touch ID")).font(.title3.weight(.semibold)).foregroundStyle(theme.text)
            Text("Enter your master password to confirm.").font(.callout).foregroundStyle(theme.textMuted)
            SecureField("Master password", text: $password).glassField().onSubmit(submit)
            YubiKeyTouchBanner(prompt: YubiKeyPrompt.shared)
            MessageLine(text: model.touchIDMessage)
            HStack {
                Button("Cancel", action: onClose).buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button(turningOn ? String(localized: "Turn on") : String(localized: "Turn off"), action: submit)
                    .buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction)
                    .disabled(model.busy || password.isEmpty)
            }
        }
        .padding(24).frame(width: 360)
        .background(WashBackground())
    }

    private func submit() {
        Task {
            if await model.setTouchID(turningOn, password: password) { onClose() } else { password = "" }
        }
    }
}

/// The ⌘, Settings window: the same page on its own wash.
struct MacSettingsWindow: View {
    let lock: MacLockModel
    @State private var model: MacSettingsModel?

    var body: some View {
        Group {
            if let model { MacSettingsView(model: model, standalone: true) }
        }
        .frame(width: 620, height: 640)
        .overlay(alignment: .bottom) { YubiKeyTouchBanner(prompt: YubiKeyPrompt.shared).frame(maxWidth: 460).padding(12) }
        .preferredColorScheme(AppSettings.shared.appearance.colorScheme)
        .macThemed()
        .onAppear {
            if model == nil { model = MacSettingsModel(settings: .shared, pro: MacAppEnvironment.pro, passwords: lock, local: lock) }
        }
    }
}
