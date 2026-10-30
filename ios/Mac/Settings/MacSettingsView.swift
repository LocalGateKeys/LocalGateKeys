import SwiftUI
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
    var touchIDAvailable: Bool { passwords?.touchIDAvailable ?? false }
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

/// The settings page: grouped glass cards on the wash (the Settings window), or inside the main window's shell
/// panel (the sidebar's Settings).
struct MacSettingsView: View {
    @Bindable var model: MacSettingsModel
    /// True in the Settings window: draws its own wash behind the cards.
    var standalone = false
    /// The main window's Settings: the Backups section opens the Recovery centre there.
    var onRecoveryCentre: (() -> Void)?
    /// The main window's Settings: Show setup again (workstream 4); nil hides the row.
    var onShowSetup: (() -> Void)? = nil
    @Environment(\.macTheme) private var theme
    @State private var changingPassword = false
    @State private var recoveryPhrase: RecoveryPhraseSheet.Mode?
    @State private var touchIDPrompt: Bool?   // the state being turned to, while asking for the password
    @AppStorage(QuickAccessSettings.showMenuBarKey) private var showMenuBarIcon = true
    @AppStorage(QuickAccessSettings.hotKeyKey) private var quickAccessHotKey = true
    @State private var hotKeyMessage: String?
    @State private var openAtLogin = false
    @State private var loginItemMessage: String?

    var body: some View {
        ScrollViewReader { proxy in
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Settings").font(.system(size: 19, weight: .semibold)).foregroundStyle(theme.text)
                if !model.isUnlocked {
                    Label(MacSettingsModel.lockedMessage, systemImage: "lock.fill")
                        .font(.system(size: 13)).foregroundStyle(theme.textMuted)
                }
                section(String(localized: "Locking")) {
                    pickerRow(String(localized: "Auto-lock after inactivity"), selection: $model.autoLock) {
                        ForEach(IdleLock.allCases) { Text($0.label).tag($0) }
                    }
                    divider
                    toggleRow(String(localized: "Lock when the screen locks"), isOn: $model.lockOnScreenLock)
                    divider
                    toggleRow(String(localized: "Lock when the Mac sleeps"), isOn: $model.lockOnSleep)
                    divider
                    pickerRow(String(localized: "Maximum session"), selection: $model.maxSession) {
                        ForEach(MacSettingsModel.maxSessionChoices, id: \.self) { Text(MacSettingsModel.maxSessionLabel($0)).tag($0) }
                    }
                }
                .disabled(!model.canChangeLocking)
                section(String(localized: "Menu bar & startup")) {
                    toggleRow(String(localized: "Show in the menu bar"), isOn: $showMenuBarIcon)
                    divider
                    row(String(localized: "Quick access shortcut"), detail: String(localized: "\(QuickAccessSettings.hotKeyLabel) opens Search Everything from any app.")) {
                        Toggle("", isOn: Binding(get: { quickAccessHotKey }, set: { on in
                            quickAccessHotKey = on
                            GlobalHotKey.shared.apply()
                            hotKeyMessage = on && !GlobalHotKey.shared.isRegistered
                                ? String(localized: "Another app already uses \(QuickAccessSettings.hotKeyLabel).") : nil
                        })).toggleStyle(.switch).labelsHidden()
                    }
                    if let hotKeyMessage {
                        Text(hotKeyMessage).font(.system(size: 11)).foregroundStyle(theme.danger)
                            .padding(.horizontal, 14).padding(.bottom, 8)
                    }
                    divider
                    row(String(localized: "Open at login"), detail: LoginItem.needsApproval ? String(localized: "Waiting for approval in System Settings › General › Login Items.") : nil) {
                        Toggle("", isOn: Binding(get: { openAtLogin }, set: { on in
                            loginItemMessage = LoginItem.set(on); openAtLogin = LoginItem.isOn || LoginItem.needsApproval
                        })).toggleStyle(.switch).labelsHidden()
                    }
                    if let loginItemMessage {
                        Text(loginItemMessage).font(.system(size: 11)).foregroundStyle(theme.danger)
                            .padding(.horizontal, 14).padding(.bottom, 8)
                    }
                }
                .onAppear { openAtLogin = LoginItem.isOn || LoginItem.needsApproval }
                section(String(localized: "Unlocking")) {
                    row(String(localized: "Master password"), detail: String(localized: "Used to open your vault on this Mac.")) {
                        Button("Change…") { model.clearMessages(); changingPassword = true }
                            .buttonStyle(PillButtonStyle(primary: false))
                            .disabled(!model.canChangeUnlocking)
                    }
                    divider
                    row(String(localized: "Touch ID"), detail: model.touchIDAvailable ? String(localized: "Unlock with your fingerprint. If your fingerprints change, your master password is needed again.")
                                                                   : String(localized: "Touch ID isn't available on this Mac.")) {
                        Toggle("", isOn: Binding(get: { model.touchIDOn }, set: { on in model.clearMessages(); touchIDPrompt = on }))
                            .toggleStyle(.switch).labelsHidden()
                            .disabled(!model.canChangeUnlocking || (!model.touchIDAvailable && !model.touchIDOn))
                    }
                    divider
                    row(String(localized: "Recovery phrase"), detail: model.recoveryPhraseSet
                        ? String(localized: "Set. 24 words that replace a forgotten master password. Creating a new one replaces it.")
                        : String(localized: "24 words that replace a forgotten master password. Shown once; write them down.")) {
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
                if let onRecoveryCentre {
                    section(String(localized: "Backups")) {
                        row(String(localized: "Recovery centre"), detail: String(localized: "Full backups, restore, the recovery kit and old backups.")) {
                            Button("Open", action: onRecoveryCentre).buttonStyle(PillButtonStyle(primary: false))
                        }
                    }
                }
                section(String(localized: "Privacy")) {
                    pickerRow(String(localized: "Clear clipboard after"), selection: $model.clipboardExpiry) {
                        ForEach(ClipboardExpiry.allCases) { Text($0.label).tag($0) }
                    }
                    divider
                    row(String(localized: "Breach checks"), detail: String(localized: "You start each check. It sends 5 characters of a hash, never the password.")) {
                        Toggle("", isOn: $model.breachCheckEnabled).toggleStyle(.switch).labelsHidden()
                    }
                    divider
                    row(String(localized: "Strict offline mode"), detail: String(localized: "Blocks background internet requests, website icons and breach checks")) {
                        Toggle("", isOn: $model.strictOfflineMode).toggleStyle(.switch).labelsHidden()
                    }
                    divider
                    row(String(localized: "Show item names in reminders"), detail: String(localized: "Notifications can appear on the lock screen. When off, they say \u{201C}A reminder is due\u{201D}.")) {
                        Toggle("", isOn: $model.showItemNamesInReminders).toggleStyle(.switch).labelsHidden()
                    }
                    divider
                    Group {
                        row(String(localized: "Empty trash automatically"), detail: String(localized: "When off, deleted items stay in the trash until you delete them")) {
                            Toggle("", isOn: $model.trashAutoPurge).toggleStyle(.switch).labelsHidden()
                        }
                        divider
                        row(String(localized: "Empty Recently deleted after"), detail: String(localized: "Used while automatic emptying is on")) {
                            Picker("", selection: $model.trashRetentionDays) {
                                ForEach(model.trashRetentionOptions, id: \.self) { Text(MacSettingsModel.retentionLabel($0)).tag($0) }
                            }
                            .labelsHidden().fixedSize()
                        }
                    }
                    .disabled(!model.canChangeTrash)
                }
                section(String(localized: "AutoFill")) {
                    row(String(localized: "Show logins in AutoFill suggestions"), detail: String(localized: "Usernames and website names only, never passwords.")) {
                        Toggle("", isOn: $model.showInQuickType).toggleStyle(.switch).labelsHidden()
                    }
                    divider
                    row(String(localized: "Include exact-site logins"), detail: String(localized: "Suggestions are offered by domain, so a login saved for one site can also be offered on other pages of the same domain.")) {
                        Toggle("", isOn: $model.quickTypeExactSites).toggleStyle(.switch).labelsHidden()
                            .disabled(!model.showInQuickType)
                    }
                    divider
                    toggleRow(String(localized: "Offer passkeys"), isOn: $model.offerPasskeys)
                }
                section(String(localized: "Appearance")) {
                    row(String(localized: "Theme"), detail: nil) {
                        Picker("", selection: $model.appearance) {
                            ForEach(Appearance.allCases) { Text($0.label).tag($0) }
                        }
                        .pickerStyle(.segmented).labelsHidden().fixedSize()
                    }
                }
                if let onShowSetup {
                    section(String(localized: "Setup")) {
                        row(String(localized: "Set up LocalGateKeys"), detail: String(localized: "Touch ID, import, recovery phrase and the Safari extension.")) {
                            Button(Onboarding.showAgainTitle, action: onShowSetup).buttonStyle(PillButtonStyle(primary: false))
                        }
                    }
                }
                section(String(localized: "Plan")) { PlanRows(pro: model.pro) }
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
        .background { if standalone { WashBackground() } }
        .sheet(isPresented: Binding(get: { recoveryPhrase != nil }, set: { if !$0 { recoveryPhrase = nil } }),
               onDismiss: { model.refreshRecoveryPhrase() }) {
            if let passwords = model.passwords, let mode = recoveryPhrase {
                RecoveryPhraseSheet(passwords: passwords, mode: mode, onClose: { recoveryPhrase = nil }).macThemed()
            }
        }
        .onAppear { model.refreshRecoveryPhrase() }
        .sheet(isPresented: $changingPassword) {
            ChangePasswordSheet(model: model, onClose: { changingPassword = false }).macThemed()
        }
        .sheet(isPresented: Binding(get: { touchIDPrompt != nil }, set: { if !$0 { touchIDPrompt = nil } })) {
            TouchIDPasswordSheet(model: model, turningOn: touchIDPrompt ?? true, onClose: { touchIDPrompt = nil }).macThemed()
        }
    }

    // MARK: rows

    private var divider: some View { Rectangle().fill(theme.panelBorder).frame(height: 1).padding(.leading, 14) }

    /// The palette's section or Change master password request (the main window's Settings only).
    private func followRequests(_ proxy: ScrollViewProxy) {
        guard !standalone else { return }
        if model.requestsPasswordChange {
            model.requestsPasswordChange = false
            model.requestedSection = .unlocking
            if model.canChangeUnlocking { model.clearMessages(); changingPassword = true }
        }
        if let section = model.requestedSection {
            model.requestedSection = nil
            DispatchQueue.main.async { withAnimation { proxy.scrollTo(section.rawValue, anchor: .top) } }
        }
    }

    private func section<C: View>(_ title: String, @ViewBuilder _ content: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased()).font(.system(size: 11, weight: .semibold)).foregroundStyle(theme.textFaint)
                .padding(.leading, 4)
            VStack(alignment: .leading, spacing: 0) { content() }
                .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
        }
        .id(title)
    }

    private func row<C: View>(_ title: String, detail: String?, @ViewBuilder _ control: () -> C) -> some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13)).foregroundStyle(theme.text)
                if let detail { Text(detail).font(.system(size: 11)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true) }
            }
            Spacer(minLength: 12)
            control()
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }

    private func toggleRow(_ title: String, isOn: Binding<Bool>) -> some View {
        row(title, detail: nil) { Toggle("", isOn: isOn).toggleStyle(.switch).labelsHidden() }
    }

    private func pickerRow<V: Hashable, C: View>(_ title: String, selection: Binding<V>, @ViewBuilder _ options: () -> C) -> some View {
        row(title, detail: nil) {
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
        .preferredColorScheme(AppSettings.shared.appearance.colorScheme)
        .macThemed()
        .onAppear {
            if model == nil { model = MacSettingsModel(settings: .shared, pro: MacAppEnvironment.pro, passwords: lock, local: lock) }
        }
    }
}
