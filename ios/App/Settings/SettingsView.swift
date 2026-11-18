import SwiftUI
import AuthenticationServices
import AppShared

/// The initials field's text. Typing is never rewritten (the setting itself keeps at most two letters, so
/// binding to it directly turned "John" into "JO" mid-word); `submit` stores "John Doe" as "JD".
struct InitialsField {
    let settings: AppSettings
    var text: String

    init(settings: AppSettings) { self.settings = settings; text = settings.initials }

    mutating func submit() {
        settings.initials = text
        text = settings.initials
    }
}

/// Settings, the fourth tab (UX plan workstream 1; it was a sheet from the avatar button): a short list of categories
/// (Lock & security, Privacy, AutoFill, Sync & data, Password generator, Appearance, About), each opening its own page
/// of sections, under the Pro section (status, Upgrade, Restore). Settings whose effect is not obvious from the name carry an ⓘ button (`InfoLabel`) that explains them. Every choice lives in `AppSettings` (app group UserDefaults; nothing secret).
struct SettingsView: View {
    let pro: ProModel
    let lock: AppLockModel
    let sync: SyncCoordinator
    /// Switches to the Sync tab (leave and reset live there).
    let openSync: () -> Void
    /// Opens straight on Import & Export (the empty vault's "Import" button).
    var openImport = false
    /// Shown as a tab (no Done button, room for the iOS 17–25 floating tab bar); false for a sheet.
    var inTab = false
    /// Called once the Import & Export shortcut has opened, so the tab can be asked again later.
    var onImportOpened: () -> Void = {}
    /// Settings › Show setup again (workstream 4); nil hides the row.
    var showSetup: (() -> Void)? = nil
    @Bindable var settings: AppSettings = .shared

    @State private var showUpgrade = false
    @State private var showingWhatsNew = false
    /// Settings › App password's setup sheet, presented here: a `.sheet` on a List Section never appears (iOS 27).
    @State private var appPasswordSetup = false
    @State private var autoFillStatus = AutoFillStatusModel.live()
    /// Typed freely; normalised to at most two letters only on submit (or when Settings closes).
    @State private var initials = InitialsField(settings: .shared)
    @Environment(\.scenePhase) private var scenePhase
    @State private var generatorOptions = GeneratorOptions()
    @State private var showGenerator = false
    @State private var eraseStep = 0
    @State private var showImport = false
    @Environment(\.dismiss) private var dismiss
    @Environment(\.phoneTrash) private var trash
    @Environment(\.phoneReminders) private var reminders

    /// Settings › Pro when a licence is held (no price, no shop: App Store guideline 3.1.3(b)).
    static let alsoUnlocksWindows = String(localized: "Also unlocks Windows: pair your PC")
    static let copyKeyLabel = String(localized: "Copy key")
    static let dataNotCollected = String(localized: "Your vault stays on your devices. When you buy Pro, the app sends the App Store receipt to our licence server so your other devices can be unlocked. The receipt has no name or email.")
    /// The website's in-app legal pages (no site menu, no shop links: App Store 3.1.1 / 3.1.3(b)); the licence
    /// agreement covers the iPhone app too.
    static let privacyPolicyURL = URL(string: "https://localgatekeys.app/legal/app/privacy.html")!
    static let licenceAgreementURL = URL(string: "https://localgatekeys.app/legal/app/eula.html")!
    /// Which logins QuickType offers, and what "Include exact-site logins" widens.
    static let quickTypeFooter = String(localized: "The QuickType bar offers logins set to match their whole domain, plus exact-site logins when \"Include exact-site logins\" is on. iOS suggests these by domain, so a login saved for one site can also be offered on other pages of the same domain. It shows usernames and website names only, never passwords.")

    /// How to turn on the Safari extension that offers to save logins.
    static let safariHelp = String(localized: "To be offered saving in Safari, turn on LocalGateKeys in Settings › Apps › Safari › Extensions and allow it on all websites.")

    /// The iOS 17–25 floating tab bar covers the bottom of a tab; iOS 26's system bar insets content itself.
    static var legacyTabBarRoom: CGFloat {
        if #available(iOS 26, *) { return 0 }
        return 96
    }

    static func syncStatus(joined: Bool, lastSyncedAt: Int64?) -> String {
        guard joined else { return String(localized: "Not set up") }
        guard let at = lastSyncedAt else { return String(localized: "On") }
        return String(localized: "Last synced \(Date(timeIntervalSince1970: TimeInterval(at)).formatted(date: .omitted, time: .shortened))")
    }

    var body: some View {
        NavigationStack {
            List {
                // Pro stays on the main list, outside the categories, with Upgrade one tap away.
                proSection
                Section {
                    categoryRow(String(localized: "Lock & security"), icon: "lock") {
                        page(String(localized: "Lock & security")) {
                            security
                            AppPasswordSection(lock: lock, showSetup: $appPasswordSetup)
                            DuressSection(lock: lock, pro: pro)
                            RestoreTestSection(pro: pro, sync: sync)
                            EmergencyAccessRow(lock: lock, sync: sync, isPro: pro.isPro)
                        }
                    }
                    categoryRow(String(localized: "Privacy"), icon: "hand.raised") {
                        page(String(localized: "Privacy")) {
                            privacy
                            breachChecks
                            remindersSection
                        }
                    }
                    categoryRow(String(localized: "AutoFill"), icon: "checkmark.circle",
                                badge: autoFillStatus.enabled == false) {
                        page(String(localized: "AutoFill")) { autoFill }
                    }
                    categoryRow(String(localized: "Sync & data"), icon: "arrow.triangle.2.circlepath") {
                        page(String(localized: "Sync & data")) {
                            syncSection
                            importExport
                            erase
                        }
                    }
                    categoryRow(String(localized: "Password generator"), icon: "wand.and.stars") {
                        page(String(localized: "Password generator")) { generator }
                    }
                    categoryRow(String(localized: "Appearance"), icon: "paintbrush") {
                        page(String(localized: "Appearance")) { appearance }
                    }
                }
                .listRowBackground(Palette.groupSurface)
                Section {
                    categoryRow(String(localized: "About"), icon: "info.circle") {
                        page(String(localized: "About")) {
                            about
                            setupSection
                            #if DEBUG
                            developer
                            #endif
                        }
                    }
                }
                .listRowBackground(Palette.groupSurface)
            }
            .scrollContentBackground(.hidden)
            .lgkAuroraBackground()
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .safeAreaPadding(.bottom, inTab ? Self.legacyTabBarRoom : 0)
            .toolbar { if !inTab { ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } } } }
            .sheet(isPresented: $showUpgrade) { UpgradeView(pro: pro) }
            .task { await autoFillStatus.refresh() }
            // Back from the Settings app (after "Open AutoFill settings"): check again.
            .onChange(of: scenePhase) { _, phase in if phase == .active { Task { await autoFillStatus.refresh() } } }
            .onDisappear { initials.submit() }
            .onAppear {
                generatorOptions = GeneratorDefaults(settings: settings).load()
                if openImport, lock.store != nil { showImport = true; onImportOpened() }
            }
            .onChange(of: openImport) { _, open in
                if open, lock.store != nil { showImport = true; onImportOpened() }
            }
            .navigationDestination(isPresented: $showImport) { importExportScreen }
        }
    }

    // MARK: categories

    /// A top-level row (icon, title, an optional attention dot, chevron) that opens one category's page.
    private func categoryRow<Destination: View>(_ title: String, icon: String, badge: Bool = false,
                                                @ViewBuilder destination: @escaping () -> Destination) -> some View {
        NavigationLink(destination: destination) {
            HStack(spacing: 14) {
                Image(systemName: icon)
                    .font(.title3)
                    .frame(width: 28)
                    .foregroundStyle(Palette.secondaryText)
                Text(title).foregroundStyle(Palette.text)
                Spacer()
                if badge {
                    Image(systemName: "exclamationmark.circle.fill")
                        .foregroundStyle(Palette.danger)
                        .accessibilityLabel(Text("Needs attention"))
                }
            }
            .padding(.vertical, 6)
        }
    }

    /// One category's page: the same grouped list look as the root.
    private func page<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        List { content() }
            .scrollContentBackground(.hidden)
            .lgkAuroraBackground()
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .safeAreaPadding(.bottom, inTab ? Self.legacyTabBarRoom : 0)
            // Presented from the category page, not the Settings root: a sheet or alert on the root never shows
            // while a page is pushed over it (iOS 27). Only one page is on screen at a time.
            .sheet(isPresented: $showingWhatsNew) { WhatsNewSheet { showingWhatsNew = false } }
            .sheet(isPresented: $appPasswordSetup) {
                if let store = AppPasswordStore.shared(), let kc = lock.keychain {
                    AppPasswordSetupView(controller: AppPasswordController(store: store, keychain: kc),
                                         onTurnedOn: { lock.lock() })
                }
            }
            // Alerts, not confirmation dialogs: iOS 26 drops a dialog's Cancel button on iPhone.
            .alert(VaultEraser.confirmText1, isPresented: eraseBinding(1)) {
                Button("Erase", role: .destructive) { eraseStep = 2 }
                Button("Cancel", role: .cancel) { eraseStep = 0 }
            }
            .alert(VaultEraser.confirmText2, isPresented: eraseBinding(2)) {
                Button(DeviceText.isPad ? String(localized: "ipad.settingsView.eraseVault", defaultValue: "Erase this iPad's vault") : String(localized: "Erase this iPhone's vault"), role: .destructive) { Task { await eraseNow() } }
                Button("Cancel", role: .cancel) { eraseStep = 0 }
            }
    }

    // MARK: sections

    private var security: some View {
        Section("Lock") {
            Picker(selection: $settings.autoLockDelay) {
                ForEach(AutoLockDelay.allCases) { Text($0.label).tag($0) }
            } label: { InfoLabel("Auto-lock after leaving the app", info: SettingInfo.autoLock) }
            Picker(selection: $settings.idleLock) {
                ForEach(IdleLock.allCases) { Text($0.label).tag($0) }
            } label: { InfoLabel("Lock when idle", info: SettingInfo.idleLock) }
            .onChange(of: settings.idleLock) { lock.noteActivity() }   // restart the timer with the new time
            Picker(selection: $settings.clipboardExpiry) {
                ForEach(ClipboardExpiry.allCases) { Text($0.label).tag($0) }
            } label: { InfoLabel("Clear clipboard after", info: SettingInfo.clipboard) }
            Button("Lock now") { dismiss(); lock.lock() }.foregroundStyle(Palette.accentText)
        }
        .listRowBackground(Palette.groupSurface)
    }

    /// What shows on screen and what the app downloads.
    private var privacy: some View {
        Section("Privacy") {
            Toggle(isOn: $settings.concealSecretsInDetail) {
                InfoLabel("Hide passwords until tapped", info: SettingInfo.conceal)
            }
            Toggle(isOn: $settings.showWebsiteIcons) {
                InfoLabel("Show website icons", info: SettingInfo.websiteIcons)
            }
            .onChange(of: settings.showWebsiteIcons) { _, on in if !on { SiteIconStore.shared.clear() } }
        }
        .listRowBackground(Palette.groupSurface)
    }

    /// Breach checks (UX plan workstream 2): off by default, and blocked while strict offline is on (as desktop).
    private var breachChecks: some View {
        Section {
            Toggle(isOn: $settings.strictOfflineMode) { InfoLabel("Strict offline mode", info: SettingInfo.strictOffline) }
            Toggle(isOn: $settings.breachCheckEnabled) { InfoLabel("Allow breach checks", info: SecurityCheckModel.consentText) }
                .disabled(settings.strictOfflineMode)
        } header: {
            Text("Breach checks")
        } footer: {
            Text(String(localized: "\(SecurityCheckModel.consentText) Nothing is checked automatically; the Security tab asks each time."))
        }
        .listRowBackground(Palette.groupSurface)
    }

    /// Expiry reminders (UX plan workstream 10): local notifications, item names off by default.
    private var remindersSection: some View {
        Section {
            Toggle(isOn: $settings.showItemNamesInPhoneReminders) {
                InfoLabel("Show item names in notifications", info: SettingInfo.reminderNames)
            }
                .onChange(of: settings.showItemNamesInPhoneReminders) { reminders?.reschedule() }
        } header: {
            Text("Reminders")
        } footer: {
            Text("Add a reminder from a card, document or subscription. Off: notifications say only \u{201C}A reminder is due\u{201D}, so nothing about the item shows on the lock screen.")
        }
        .listRowBackground(Palette.groupSurface)
    }

    private var autoFill: some View {
        Section {
            LabeledContent { Text( autoFillStatus.enabled.map { $0 ? String(localized: "On") : String(localized: "Off") } ?? "…") } label: {
                InfoLabel("AutoFill Passwords", info: SettingInfo.autoFillService)
            }
            if autoFillStatus.enabled == false {
                NavigationLink("Set up AutoFill") { AutoFillSetupView(status: autoFillStatus) }
                    .foregroundStyle(Palette.accentText)
            }
            Button("Open AutoFill settings") {
                Task { await autoFillStatus.openSettings() }
            }
            .foregroundStyle(Palette.accentText)
            if let store = lock.store {
                NavigationLink("Passkey check") { PasskeyDoctorView(store: store, status: autoFillStatus) }
            }
            if let error = autoFillStatus.openError {
                Text(error).font(.footnote).foregroundStyle(Palette.danger)
            }
            Toggle(isOn: $settings.copyCodeOnFill) { InfoLabel("Copy 2FA code when filling", info: SettingInfo.copyCode) }
            // Apple Watch codes (UX workstream 12): the watch drops its pinned 2FA secrets when the vault locks. An
            // Apple Watch pairs only with an iPhone, so the iPad leaves the row out.
            if !DeviceText.isPad {
                Toggle(isOn: Bindable(WatchCodes.shared).forgetOnLock) {
                    InfoLabel("Forget Apple Watch codes on lock", info: SettingInfo.watchCodes)
                }
            }
            Toggle(isOn: $settings.showInQuickType) { InfoLabel("Show logins in the QuickType bar", info: Self.quickTypeFooter) }
                .onChange(of: settings.showInQuickType) { sync.identitySettingsChanged() }
            Toggle(isOn: $settings.quickTypeExactSites) { InfoLabel("Include exact-site logins", info: SettingInfo.exactSites) }
                .onChange(of: settings.quickTypeExactSites) { sync.identitySettingsChanged() }
                .disabled(!settings.showInQuickType)
            Toggle(isOn: $settings.offerPasskeys) { InfoLabel("Offer LocalGateKeys for passkeys", info: SettingInfo.passkeys) }
                .onChange(of: settings.offerPasskeys) { sync.identitySettingsChanged() }
        } header: {
            Text("AutoFill")
        } footer: {
            Text(Self.safariHelp)
        }
        .listRowBackground(Palette.groupSurface)
    }

    private var appearance: some View {
        Section("Appearance") {
            Picker("Appearance", selection: $settings.appearance) {
                ForEach(Appearance.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
            Toggle(isOn: $settings.showCodesRow) { InfoLabel("Show 2FA codes in the Codes row", info: SettingInfo.codesRow) }
            TextField("Your initials", text: $initials.text)
                .textInputAutocapitalization(.words)
                .autocorrectionDisabled()
                .textContentType(nil)
                .submitLabel(.done)
                .onSubmit { initials.submit() }
        }
        .listRowBackground(Palette.groupSurface)
    }

    private var generator: some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                LabeledContent { Text(Self.summary(generatorOptions)) } label: {
                    InfoLabel("New passwords", info: SettingInfo.generator)
                }
                StrengthMeter(level: GeneratorStrength.level(options: generatorOptions))
            }
            .accessibilityElement(children: .combine)
            Button("Generate password") { showGenerator = true }
                .foregroundStyle(Palette.accentText)
                .sheet(isPresented: $showGenerator, onDismiss: {
                    generatorOptions = GeneratorDefaults(settings: settings).load()
                }) {
                    GeneratorView { SecretClipboard.shared.copy($0) }
                }
            Button("Reset to defaults") {
                GeneratorDefaults(settings: settings).reset()
                generatorOptions = GeneratorOptions()
            }
            .foregroundStyle(Palette.accentText)
        } header: {
            Text("Password generator")
        } footer: {
            Text("The generator starts from the options you used last.")
        }
        .listRowBackground(Palette.groupSurface)
    }

    @ViewBuilder private var setupSection: some View {
        if let showSetup {
            Section {
                Button(Onboarding.showAgainTitle) { showSetup() }
                    .foregroundStyle(Palette.accentText)
            }
            .listRowBackground(Palette.groupSurface)
        }
    }

    private var syncSection: some View {
        Section {
            Button { dismiss(); openSync() } label: {
                LabeledContent("Sync") {
                    HStack {
                        Text(Self.syncStatus(joined: sync.membership.joined, lastSyncedAt: sync.lastSyncedAt))
                        Image(systemName: "chevron.right").font(.footnote.weight(.semibold))
                    }
                    .foregroundStyle(Palette.secondaryText)
                }
            }
            .foregroundStyle(Palette.text)
            Toggle(isOn: $settings.autoSync) {
                InfoLabel(verbatim: SyncWording.autoSyncTitle, info: SyncWording.autoSyncText)
            }
            .foregroundStyle(Palette.text)
            // Desktop `erase_on_sync_removal` (default on): a verified removal notice erases this iPhone's vault.
            Toggle(isOn: $settings.eraseOnSyncRemoval) {
                InfoLabel(verbatim: DeviceRemoval.eraseSettingTitle, info: DeviceRemoval.eraseSettingText)
            }
            .foregroundStyle(Palette.text)
        } header: {
            Text("Sync")
        }
        .listRowBackground(Palette.groupSurface)
    }

    private var importExport: some View {
        Section("Data") {
            if let store = lock.store {
                NavigationLink("Import & Export") { importExportView(store: store) }
            }
            if let trash {
                NavigationLink(PhoneTrash.title) {
                    TrashView(trash: trash, pro: pro, onRestored: trash.onRestored)
                }
            }
            // Feature pack §2: never offered in the duress password's vault.
            if let store = lock.store, !lock.secondSession {
                NavigationLink("Travel mode") { TravelModeView(store: store, pro: pro) }
                NavigationLink("Privacy proof") { PrivacyProofView(store: store, appVersion: Self.shortVersion) }
            }
        }
        .listRowBackground(Palette.groupSurface)
    }

    /// Import & Export for the "Import" shortcut (nothing while locked).
    @ViewBuilder private var importExportScreen: some View {
        if let store = lock.store { importExportView(store: store) }
    }

    private func importExportView(store: any ItemStore) -> some View {
        ImportExportView(model: ImportExportModel(
            importer: VaultImporter(store: store, isPro: { pro.isPro }, now: { Date() },
                                    random: SystemRandomSource(), afterCommit: { sync.noteLocalEdit() }),
            exporter: VaultExporter(store: sync.store, isPro: { pro.isPro }, appVersion: Self.shortVersion,
                                    fallbackDeviceID: { [keychain = sync.deps.keychain] in
                                        try keychain.installID(random: SystemRandomSource()) },
                                    now: { Date() }, random: SystemRandomSource(),
                                    blobs: AttachmentFiles.localFolder(),
                                    leftOut: { [local = trash?.local] snap in PhoneFeaturePack.exportLeftOut(snap, local: local) }),
            local: trash?.local, blobs: AttachmentFiles.localFolder()))
    }

    private var proSection: some View {
        Section {
            LabeledContent("Status", value: pro.isPro ? String(localized: "Pro is active") : String(localized: "Free (up to \(ItemLimit.freeItems) items)"))
            if !pro.isPro {
                Button("Upgrade") { showUpgrade = true }.foregroundStyle(Palette.accentText)
            }
            if let key = pro.licenceKey {
                // The purchase's desktop licence (claimed, or synced from a PC): pairing carries it to Windows.
                Text(Self.alsoUnlocksWindows)
                Button(Self.copyKeyLabel) {
                    SecretClipboard.shared.copy(key)
                    CopyToast.shared.show(String(localized: "Key copied"))
                }
                .foregroundStyle(Palette.accentText)
            }
            Button("Restore purchases") { Task { await pro.restore() } }
                .foregroundStyle(Palette.accentText).disabled(pro.busy)
        } header: {
            Text("Pro")
        } footer: {
            if let message = pro.message { Text(message) }
        }
        .listRowBackground(Palette.groupSurface)
    }

    private var about: some View {
        Section {
            LabeledContent("Version", value: Self.version)
            Button("What's new") { showingWhatsNew = true }.foregroundStyle(Palette.accentText)
            NavigationLink("Acknowledgements") { AcknowledgementsView() }
            Link("Privacy Policy", destination: Self.privacyPolicyURL).foregroundStyle(Palette.accentText)
            Link("Licence Agreement", destination: Self.licenceAgreementURL).foregroundStyle(Palette.accentText)
        } header: {
            Text("About")
        } footer: {
            Text(Self.dataNotCollected)
        }
        .listRowBackground(Palette.groupSurface)
    }

    private var erase: some View {
        Section {
            Button(DeviceText.isPad ? String(localized: "ipad.settingsView.eraseVault", defaultValue: "Erase this iPad's vault") : String(localized: "Erase this iPhone's vault"), role: .destructive) { eraseStep = 1 }
                .foregroundStyle(Palette.danger)
        } footer: {
            Text(DeviceText.isPad ? String(localized: "ipad.settingsView.deletesVaultOnlyPc", defaultValue: "Deletes the vault on this iPad only. Your PC and the sync folder are not changed.") : String(localized: "Deletes the vault on this iPhone only. Your PC and the sync folder are not changed."))
        }
        .listRowBackground(Palette.groupSurface)
    }

    #if DEBUG
    @State private var demoMessage: String?

    /// DEBUG builds only: fake items for checking the look with a full vault.
    private var developer: some View {
        Section {
            Button("Load demo data") {
                guard let store = lock.store else { return }
                do { try DemoData.seed(into: store, now: SystemClock().now); demoMessage = String(localized: "Demo data loaded.") } catch {
                    demoMessage = String(localized: "Demo data could not be loaded.")
                }
            }
            .foregroundStyle(Palette.accentText)
            NavigationLink("AutoFill trace") { AutoFillTraceView() }
        } header: {
            Text("Developer")
        } footer: {
            if let demoMessage { Text(demoMessage) }
        }
        .listRowBackground(Palette.groupSurface)
    }
    #endif

    // MARK: actions

    /// `CFBundleShortVersionString` (the backup's `app_version`).
    static var shortVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0"
    }

    static var version: String {
        let info = Bundle.main.infoDictionary ?? [:]
        let v = info["CFBundleShortVersionString"] as? String ?? ""
        let b = info["CFBundleVersion"] as? String ?? ""
        return b.isEmpty ? v : "\(v) (\(b))"
    }

    static func summary(_ o: GeneratorOptions) -> String {
        switch o.mode {
        case .password: String(localized: "Password, \(o.length) characters")
        case .passphrase: String(localized: "Passphrase, \(o.words) words")
        case .answer: String(localized: "Answer")
        }
    }

    private func eraseBinding(_ step: Int) -> Binding<Bool> {
        Binding(get: { eraseStep == step }, set: { if !$0, eraseStep == step { eraseStep = 0 } })
    }

    private func eraseNow() async {
        eraseStep = 0
        let sync = sync, lock = lock
        dismiss()
        // Sub-plan 08 (Ruling T5a-b): in a duress session only the second vault's data goes.
        let routing = DuressRouting(inDuressSession: { lock.secondSession }, duress: PhoneDuress.shared(),
                                    throttle: AppPasswordStore.shared())
        await routing.erase(lockAndWait: {
            lock.lock()
            await sync.shutdownAndWait()
        }, real: {
            // Locks first whatever happens; a failure shows on the unlock screen and is retried before unlock.
            await lock.eraseAndLock { await sync.shutdownAndWait() }
            WatchCodes.shared.vaultErased()   // the Apple Watch forgets its pinned 2FA secrets too
        })
    }
}

/// The ⓘ explanations for Settings rows (one place, so iPhone copy stays in step with Android's `settings_info_*`).
enum SettingInfo {
    static let autoLock = String(localized: "How long the vault stays unlocked after you switch to another app or lock the phone. Shorter is safer; you unlock again with Face ID or your password.")
    static let idleLock = String(localized: "Locks the vault when you have not touched the app for this long, even while it is open on screen.")
    static let clipboard = String(localized: "Passwords and codes you copy are wiped from the clipboard after this time, so other apps cannot read them later.")
    static let conceal = String(localized: "Item pages show dots instead of passwords and other secrets until you tap them. Helps when someone can see your screen.")
    static let websiteIcons = String(localized: "Downloads each site's logo to show next to its login. That tells the site you have an account there; nothing else is sent. Turning it off deletes the saved logos.")
    static let strictOffline = String(localized: "Blocks the app's optional internet features, such as breach checks. Your vault never needs the internet to work.")
    static let reminderNames = String(localized: "When on, reminder notifications name the item (for example, which card expires). When off, they only say a reminder is due, so nothing shows on the lock screen.")
    static let autoFillService = String(localized: "Whether iOS uses LocalGateKeys to fill passwords in apps and Safari. Turn it on in the iOS Settings app with \u{201C}Open AutoFill settings\u{201D}.")
    static let copyCode = String(localized: "After filling a login that has a 2FA code, the current code is copied so you can paste it on the next screen.")
    static let watchCodes = String(localized: "When the vault locks on this iPhone, your Apple Watch deletes the 2FA codes it was showing.")
    static let exactSites = String(localized: "Also suggests logins set to match one exact site, not only logins that match the whole domain.")
    static let passkeys = String(localized: "Lets LocalGateKeys save and use passkeys when a website or app asks for one.")
    static let codesRow = String(localized: "Shows a row of your current 2FA codes at the top of the vault, so you can copy one without opening the item.")
    static let generator = String(localized: "The kind of password new items start with. The generator remembers the options you used last; Reset to defaults goes back to the original ones.")
}

/// A setting's title with an ⓘ button; tapping it shows [info] in a small popover.
struct InfoLabel: View {
    let title: Text
    let info: String
    @State private var shown = false

    init(_ title: LocalizedStringKey, info: String) { self.title = Text(title); self.info = info }
    /// For a title that is already localised.
    init(verbatim title: String, info: String) { self.title = Text(verbatim: title); self.info = info }

    var body: some View {
        // A long title wraps inside its own column; the ⓘ never drops to a line of its own.
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            title
                .fixedSize(horizontal: false, vertical: true)
            Button { shown = true } label: {
                Image(systemName: "info.circle").foregroundStyle(Palette.secondaryText)
            }
            .buttonStyle(.borderless)
            .fixedSize()
            .layoutPriority(1)
            .accessibilityLabel(Text("More information"))
            .popover(isPresented: $shown) {
                Text(info)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(idealWidth: 300)
                    .padding()
                    .presentationCompactAdaptation(.popover)
            }
        }
    }
}
