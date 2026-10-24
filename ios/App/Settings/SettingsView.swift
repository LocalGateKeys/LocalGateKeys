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

/// Settings, opened from the avatar button: Security, AutoFill, Appearance, Password generator, Sync, Pro,
/// About and Erase. Every choice lives in `AppSettings` (app group UserDefaults; nothing secret).
struct SettingsView: View {
    let pro: ProModel
    let lock: AppLockModel
    let sync: SyncCoordinator
    /// Switches to the Sync tab (leave and reset live there).
    let openSync: () -> Void
    @Bindable var settings: AppSettings = .shared

    @State private var showUpgrade = false
    @State private var autoFillStatus = AutoFillStatusModel.live()
    /// Typed freely; normalised to at most two letters only on submit (or when Settings closes).
    @State private var initials = InitialsField(settings: .shared)
    @Environment(\.scenePhase) private var scenePhase
    @State private var generatorOptions = GeneratorOptions()
    @State private var eraseStep = 0
    @Environment(\.dismiss) private var dismiss

    static let dataNotCollected = "Data not collected — LocalGateKeys has no analytics and no servers."
    /// The website's legal pages; the licence agreement covers the iPhone app too.
    static let privacyPolicyURL = URL(string: "https://localgatekeys.app/legal/privacy.html")!
    static let licenceAgreementURL = URL(string: "https://localgatekeys.app/legal/eula.html")!
    /// Which logins QuickType offers, and what "Include exact-site logins" widens.
    static let quickTypeFooter = "The QuickType bar offers logins set to match their whole domain, plus exact-site logins "
        + "when \"Include exact-site logins\" is on. iOS suggests these by domain, so a login saved for one site can "
        + "also be offered on other pages of the same domain. It shows usernames and website names only, never passwords."

    /// How to turn on the Safari extension that offers to save logins.
    static let safariHelp = "To be offered saving in Safari, turn on LocalGateKeys in Settings › Apps › Safari › Extensions "
        + "and allow it on all websites."

    static func syncStatus(joined: Bool, lastSyncedAt: Int64?) -> String {
        guard joined else { return "Not set up" }
        guard let at = lastSyncedAt else { return "On" }
        return "Last synced \(Date(timeIntervalSince1970: TimeInterval(at)).formatted(date: .omitted, time: .shortened))"
    }

    var body: some View {
        NavigationStack {
            List {
                security
                autoFill
                appearance
                generator
                syncSection
                proSection
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
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } } }
            .sheet(isPresented: $showUpgrade) { UpgradeView(pro: pro) }
            .task { await autoFillStatus.refresh() }
            // Back from the Settings app (after "Open AutoFill settings"): check again.
            .onChange(of: scenePhase) { _, phase in if phase == .active { Task { await autoFillStatus.refresh() } } }
            .onDisappear { initials.submit() }
            .onAppear { generatorOptions = GeneratorDefaults(settings: settings).load() }
            .confirmationDialog(VaultEraser.confirmText1, isPresented: eraseBinding(1), titleVisibility: .visible) {
                Button("Erase", role: .destructive) { eraseStep = 2 }
                Button("Cancel", role: .cancel) { eraseStep = 0 }
            }
            .confirmationDialog(VaultEraser.confirmText2, isPresented: eraseBinding(2), titleVisibility: .visible) {
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

    private var autoFill: some View {
        Section {
            LabeledContent("AutoFill Passwords", value: autoFillStatus.enabled.map { $0 ? "On" : "Off" } ?? "…")
            Button("Open AutoFill settings") {
                Task { await autoFillStatus.openSettings() }
            }
            .foregroundStyle(Palette.accentText)
            if let error = autoFillStatus.openError {
                Text(error).font(.footnote).foregroundStyle(Palette.danger)
            }
            Toggle("Copy 2FA code when filling", isOn: $settings.copyCodeOnFill)
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

    private var proSection: some View {
        Section {
            LabeledContent("Status", value: pro.isPro ? "Pro is active" : "Free (up to \(ItemLimit.freeItems) items)")
            if !pro.isPro {
                Button("Upgrade") { showUpgrade = true }.foregroundStyle(Palette.accentText)
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
                do { try DemoData.seed(into: store, now: SystemClock().now); demoMessage = "Demo data loaded." } catch {
                    demoMessage = "Demo data could not be loaded."
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

    static var version: String {
        let info = Bundle.main.infoDictionary ?? [:]
        let v = info["CFBundleShortVersionString"] as? String ?? ""
        let b = info["CFBundleVersion"] as? String ?? ""
        return b.isEmpty ? v : "\(v) (\(b))"
    }

    static func summary(_ o: GeneratorOptions) -> String {
        o.mode == .password ? "Password, \(o.length) characters" : "Passphrase, \(o.words) words"
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
    }
}
