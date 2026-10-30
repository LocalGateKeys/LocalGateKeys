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

/// Settings, the fourth tab (UX plan workstream 1; it was a sheet from the avatar button): Security, AutoFill, Appearance, Password generator, Sync, Pro,
/// About and Erase. Every choice lives in `AppSettings` (app group UserDefaults; nothing secret).
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
                security
                AppPasswordSection(lock: lock, showSetup: $appPasswordSetup)
                breachChecks
                remindersSection
                autoFill
                appearance
                generator
                syncSection
                importExport
                proSection
                setupSection
                about
                erase
                #if DEBUG
                developer
                #endif
            }
            .scrollContentBackground(.hidden)
            .lgkAuroraBackground()
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .safeAreaPadding(.bottom, inTab ? Self.legacyTabBarRoom : 0)
            .toolbar { if !inTab { ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } } } }
            .sheet(isPresented: $showUpgrade) { UpgradeView(pro: pro) }
            .sheet(isPresented: $showingWhatsNew) { WhatsNewSheet { showingWhatsNew = false } }
            .sheet(isPresented: $appPasswordSetup) {
                if let store = AppPasswordStore.shared(), let kc = lock.keychain {
                    AppPasswordSetupView(controller: AppPasswordController(store: store, keychain: kc),
                                         onTurnedOn: { lock.lock() })
                }
            }
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
            // Alerts, not confirmation dialogs: iOS 26 drops a dialog's Cancel button on iPhone.
            .alert(VaultEraser.confirmText1, isPresented: eraseBinding(1)) {
                Button("Erase", role: .destructive) { eraseStep = 2 }
                Button("Cancel", role: .cancel) { eraseStep = 0 }
            }
            .alert(VaultEraser.confirmText2, isPresented: eraseBinding(2)) {
                Button("Erase this iPhone's vault", role: .destructive) { Task { await eraseNow() } }
                Button("Cancel", role: .cancel) { eraseStep = 0 }
            }
        }
    }

    // MARK: sections

    private var security: some View {
        Section("Security") {
            Picker("Auto-lock after leaving the app", selection: $settings.autoLockDelay) {
                ForEach(AutoLockDelay.allCases) { Text($0.label).tag($0) }
            }
            Picker("Lock when idle", selection: $settings.idleLock) {
                ForEach(IdleLock.allCases) { Text($0.label).tag($0) }
            }
            .onChange(of: settings.idleLock) { lock.noteActivity() }   // restart the timer with the new time
            Picker("Clear clipboard after", selection: $settings.clipboardExpiry) {
                ForEach(ClipboardExpiry.allCases) { Text($0.label).tag($0) }
            }
            Toggle("Hide passwords until tapped", isOn: $settings.concealSecretsInDetail)
            Toggle("Show 2FA codes in the Codes row", isOn: $settings.showCodesRow)
            VStack(alignment: .leading, spacing: 4) {
                Toggle("Show website icons", isOn: $settings.showWebsiteIcons)
                    .onChange(of: settings.showWebsiteIcons) { _, on in if !on { SiteIconStore.shared.clear() } }
                Text("Downloads each site's logo. That tells the site you have an account there; nothing else is sent.")
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
            }
            Button("Lock now") { dismiss(); lock.lock() }.foregroundStyle(Palette.accentText)
        }
        .listRowBackground(Palette.groupSurface)
    }

    /// Breach checks (UX plan workstream 2): off by default, and blocked while strict offline is on (as desktop).
    private var breachChecks: some View {
        Section {
            Toggle("Strict offline mode", isOn: $settings.strictOfflineMode)
            Toggle("Allow breach checks", isOn: $settings.breachCheckEnabled)
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
            Toggle("Show item names in notifications", isOn: $settings.showItemNamesInPhoneReminders)
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
            LabeledContent("AutoFill Passwords", value: autoFillStatus.enabled.map { $0 ? String(localized: "On") : String(localized: "Off") } ?? "…")
            Button("Open AutoFill settings") {
                Task { await autoFillStatus.openSettings() }
            }
            .foregroundStyle(Palette.accentText)
            if let error = autoFillStatus.openError {
                Text(error).font(.footnote).foregroundStyle(Palette.danger)
            }
            Toggle("Copy 2FA code when filling", isOn: $settings.copyCodeOnFill)
            // Apple Watch codes (UX workstream 12): the watch drops its pinned 2FA secrets when the vault locks.
            Toggle("Forget Apple Watch codes on lock", isOn: Bindable(WatchCodes.shared).forgetOnLock)
            Toggle("Show logins in the QuickType bar", isOn: $settings.showInQuickType)
                .onChange(of: settings.showInQuickType) { sync.identitySettingsChanged() }
            Toggle("Include exact-site logins", isOn: $settings.quickTypeExactSites)
                .onChange(of: settings.quickTypeExactSites) { sync.identitySettingsChanged() }
                .disabled(!settings.showInQuickType)
            Toggle("Offer LocalGateKeys for passkeys", isOn: $settings.offerPasskeys)
                .onChange(of: settings.offerPasskeys) { sync.identitySettingsChanged() }
            Text(Self.safariHelp).font(.footnote).foregroundStyle(Palette.secondaryText)
        } header: {
            Text("AutoFill")
        } footer: {
            Text(Self.quickTypeFooter)
        }
        .listRowBackground(Palette.groupSurface)
    }

    private var appearance: some View {
        Section("Appearance") {
            Picker("Appearance", selection: $settings.appearance) {
                ForEach(Appearance.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
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
                LabeledContent("New passwords", value: Self.summary(generatorOptions))
                StrengthMeter(level: GeneratorStrength.level(options: generatorOptions))
            }
            .accessibilityElement(children: .combine)
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
        Section("Sync") {
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
                                    blobs: AttachmentFiles.localFolder())))
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
            Button("Erase this iPhone's vault", role: .destructive) { eraseStep = 1 }
                .foregroundStyle(Palette.danger)
        } footer: {
            Text("Deletes the vault on this iPhone only. Your PC and the sync folder are not changed.")
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
        o.mode == .password ? String(localized: "Password, \(o.length) characters") : String(localized: "Passphrase, \(o.words) words")
    }

    private func eraseBinding(_ step: Int) -> Binding<Bool> {
        Binding(get: { eraseStep == step }, set: { if !$0, eraseStep == step { eraseStep = 0 } })
    }

    private func eraseNow() async {
        eraseStep = 0
        let sync = sync, lock = lock
        dismiss()
        // Locks first whatever happens; a failure shows on the unlock screen and is retried before unlock.
        await lock.eraseAndLock { await sync.shutdownAndWait() }
        WatchCodes.shared.vaultErased()   // the Apple Watch forgets its pinned 2FA secrets too
    }
}
