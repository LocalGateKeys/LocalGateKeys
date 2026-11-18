import SwiftUI
import AppKit
import UniformTypeIdentifiers
import LGKCore
import AppSharedMac

/// The Recovery centre (Windows Backup & restore): Recovery phrase, Full backup, Scheduled backups and Old backups
/// cards, in the Windows order, with a link to Import & export. Sheets chain through `onDismiss`: the password sheet,
/// then the restore preview, then the strict master-password gate (the window's sheet).
struct RecoveryCentrePage: View {
    @Bindable var model: RecoveryCentreModel
    var onImportExport: () -> Void = {}
    /// Sub-plan 08: emergency access over this vault (nil: not available).
    var emergency: EmergencyAccess? = nil
    /// The master password prompt emergency access asks before granting now or showing a recovered phrase (audit
    /// 2026-11-10: never Touch ID or the Mac's login password). Its own gate: it is shown over this page's sheet.
    var emergencyGate: StrictItemGate? = nil
    /// The unlocked vault the estate pack note goes into (sub-plan 12); nil hides it.
    var estateStore: (any ItemStore)? = nil
    var onNeedsPro: () -> Void = {}
    /// Runs when the emergency access sheet closes: the estate pack note may have been added, so the item list reloads.
    var onVaultChange: () -> Void = {}
    @Environment(\.macTheme) private var theme
    @State private var showingEmergency = false
    @State private var phraseMode: PhraseMode?
    @State private var puttingBack: MacFullBackup.SafetyCopy?

    private struct PhraseMode: Identifiable {
        let mode: RecoveryPhraseSheet.Mode
        var id: String { mode == .create ? "create" : "remove" }
    }

    var body: some View {
        let status = model.status
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text(RecoveryCentreModel.title).font(.system(size: 19, weight: .semibold))
                Text(RecoveryCentreModel.intro).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                if let message = model.message { note(message, theme.success) }
                if let error = model.error { note(error, theme.warning) }
                ForEach(status.warnings, id: \.self) { w in
                    Label(w, systemImage: "exclamationmark.triangle").font(.system(size: 12.5)).foregroundStyle(theme.warning)
                }
                phraseCard(status)
                fullBackupCard
                scheduleCard(status)
                oldBackupsCard
                if emergency != nil { emergencyCard }
                HStack(spacing: 8) {
                    Text("Imports from other password managers, phone backups and exports are on the Import & export page.")
                        .font(.system(size: 12)).foregroundStyle(theme.textMuted)
                    Button("Open Import & export", action: onImportExport).buttonStyle(.plain).foregroundStyle(theme.link)
                        .font(.system(size: 12))
                }
            }
            .foregroundStyle(theme.text)
            .padding(18)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .disabled(model.working)
        .onAppear {
            model.refresh()
            guard let initial = model.initial else { return }
            model.initial = nil
            // After the page is up, so the panel opens over it.
            DispatchQueue.main.async { start(initial) }
        }
        .sheet(item: $phraseMode, onDismiss: { model.refresh() }) { box in
            if let passwords = model.passwords {
                RecoveryPhraseSheet(passwords: passwords, mode: box.mode, onClose: { phraseMode = nil },
                                    kitFacts: { EmergencyKitDocument.macFacts(schedule: model.scheduleModel) }).macThemed()
            }
        }
        .sheet(item: $model.form, onDismiss: { model.showReadyPreview() }) { form in
            FullBackupPasswordSheet(model: model, form: form).macThemed()
        }
        .sheet(item: $model.pendingRestore, onDismiss: { model.startApprovedRestore() }) { pending in
            RestorePreviewSheet(model: model, pending: pending).macThemed()
        }
        .alert("Back up without the Windows data?",
               isPresented: Binding(get: { model.askWithoutKeptData != nil }, set: { if !$0 { model.askWithoutKeptData = nil } })) {
            Button("Back up items only") {
                // Taken (and cleared) before the Task: the passwords are not kept on any path.
                if let asked = model.takeWithoutKeptData() {
                    Task { await model.create(folder: asked.folder, password: asked.password, confirm: asked.password,
                                              master: asked.master, withoutKeptData: true) }
                }
            }
            Button("Cancel", role: .cancel) { model.askWithoutKeptData = nil }
        } message: { Text(MacFullBackup.keptDataUnreadable.message) }
        .alert("Delete old backups?", isPresented: Binding(get: { model.pendingCleanup != nil },
                                                          set: { if !$0 { model.cancelCleanup() } })) {
            Button("Delete", role: .destructive) {
                let plan = model.pendingCleanup
                if let plan { model.confirmCleanup(plan) }
            }
            Button("Cancel", role: .cancel) { model.cancelCleanup() }
        } message: { Text(model.pendingCleanup.map(RecoveryCentreModel.cleanupQuestion) ?? "") }
        .alert("Put this safety copy back?", isPresented: Binding(get: { puttingBack != nil }, set: { if !$0 { puttingBack = nil } })) {
            Button("Put back", role: .destructive) {
                let copy = puttingBack
                puttingBack = nil
                if let copy { model.putBack(copy) }
            }
            Button("Cancel", role: .cancel) { puttingBack = nil }
        } message: {
            Text(String(localized: "This vault is replaced with the copy from \(puttingBack.map { Self.date($0.createdAtMillis) } ?? ""). A safety copy of the vault as it is now is kept on this Mac first."))
        }
    }

    // MARK: cards

    private func phraseCard(_ status: RecoveryStatus) -> some View {
        card(RecoveryCentreModel.phraseTitle) {
            Text(RecoveryPhraseSheet.intro).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            Text(model.phraseText).font(.system(size: 12.5))
                .foregroundStyle(status.phraseEnrolled ? theme.success : theme.warning)
            HStack(spacing: 8) {
                Button(status.phraseEnrolled ? String(localized: "Replace…") : String(localized: "Create…")) { phraseMode = PhraseMode(mode: .create) }
                    .buttonStyle(PillButtonStyle(primary: !status.phraseEnrolled))
                if status.phraseEnrolled {
                    Button("Remove…") { phraseMode = PhraseMode(mode: .remove) }.buttonStyle(PillButtonStyle(primary: false))
                }
            }
            .disabled(model.passwords == nil)
            Text("A printable page with where your vault and backups are and how to restore. The recovery phrase boxes stay blank.")
                .font(.system(size: 12.5)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            // Blank boxes: a phrase is never stored, so the filled kit is only offered while a new phrase is on screen.
            Button("Print emergency kit…") { EmergencyKitDocument.print(EmergencyKitDocument.macFacts(schedule: model.scheduleModel), words: nil) }
                .buttonStyle(PillButtonStyle(primary: false))
        }
    }

    private var fullBackupCard: some View {
        card(RecoveryCentreModel.fullBackupTitle) {
            Text(RecoveryCentreModel.fullBackupText).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            Text(model.lastBackupLine()).font(.system(size: 12.5))
                .foregroundStyle(model.status.stale ? theme.warning : theme.textMuted)
            HStack(spacing: 8) {
                Button("Create…") { start(.create) }.buttonStyle(PillButtonStyle(primary: true))
                Button("Verify…") { start(.verify) }.buttonStyle(PillButtonStyle(primary: false))
                Button("Restore…") { start(.restore) }.buttonStyle(PillButtonStyle(primary: false))
                Button("Recovery kit…") { start(.kit) }.buttonStyle(PillButtonStyle(primary: false))
                if model.working { ProgressView().controlSize(.small) }
            }
        }
    }

    private func scheduleCard(_ status: RecoveryStatus) -> some View {
        card(RecoveryCentreModel.scheduleTitle) {
            Text(RecoveryCentreModel.scheduleText).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            Text(status.schedule.text).font(.system(size: 12.5))
            if let w = status.schedule.warning { Text(w).font(.system(size: 12.5)).foregroundStyle(theme.warning) }
            if let schedule = model.scheduleModel { ScheduleControls(schedule: schedule, onChange: { model.refresh() }) }
        }
    }

    private var oldBackupsCard: some View {
        card(RecoveryCentreModel.oldBackupsTitle) {
            Text(RecoveryCentreModel.oldBackupsText).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            Button("Clean up…") {
                if let folder = RecoveryPanels.chooseCleanupFolder(start: model.lastFolder) { model.planCleanup(folder: folder) }
            }
            .buttonStyle(PillButtonStyle(primary: false))
            Text(RecoveryCentreModel.safetyText).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            let copies = model.safetyCopies
            if !copies.isEmpty {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(copies.enumerated()), id: \.element.name) { i, copy in
                        if i > 0 { Rectangle().fill(theme.line).frame(height: 1) }
                        HStack {
                            Image(systemName: "clock.arrow.circlepath").foregroundStyle(theme.textMuted)
                            Text("Before a restore on \(Self.date(copy.createdAtMillis))").font(.system(size: 12.5))
                            Spacer()
                            Button("Put back…") { puttingBack = copy }.buttonStyle(PillButtonStyle(primary: false))
                        }
                        .padding(.vertical, 6)
                    }
                }
            }
            let aside = model.setAside
            if !aside.isEmpty {
                Text(RecoveryCentreModel.setAsideText + " " + aside.joined(separator: ", "))
                    .font(.system(size: 12)).foregroundStyle(theme.warning).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: actions

    private func start(_ action: RecoveryCentreModel.Initial) {
        switch action {
        case .create:
            if let folder = RecoveryPanels.chooseBackupFolder(start: model.lastFolder) { model.ask(.create(folder: folder)) }
        case .verify:
            if let url = RecoveryPanels.chooseBackup(prompt: String(localized: "Verify"), message: String(localized: "Choose backup to verify")) { model.ask(.verify(url)) }
        case .restore:
            if let url = RecoveryPanels.chooseBackup(prompt: String(localized: "Restore"), message: String(localized: "Choose backup to restore")) { model.ask(.restore(url)) }
        case .kit:
            guard model.lastBackupURL != nil else { model.error = RecoveryCentreModel.kitNeedsBackup; return }
            if let url = RecoveryPanels.chooseKitDestination() { model.writeKit(to: url) }
        }
    }

    static func date(_ millis: Int64) -> String { RestorePreview.dateText(millis / 1000) }

    /// Emergency access (sub-plan 08, Task 5c): the owner's requests and the holder's shards, in a sheet.
    private var emergencyCard: some View {
        card(EmergencyAccessText.title) {
            Text(EmergencyAccessText.footer).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            Button(EmergencyAccessText.title) { showingEmergency = true }
        }
        .sheet(isPresented: $showingEmergency, onDismiss: onVaultChange) {
            if let emergency {
                EmergencyAccessView(access: emergency, gate: emergencyGate, estateStore: estateStore,
                                    isPro: MacAppEnvironment.pro.isPro,
                                    onNeedsPro: { showingEmergency = false; onNeedsPro() })
                    .formStyle(.grouped)
                    .frame(minWidth: 520, minHeight: 560)
                    .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { showingEmergency = false } } }
            }
        }
    }

    // MARK: chrome

    private func note(_ text: String, _ color: Color) -> some View {
        Text(text).font(.system(size: 12.5)).foregroundStyle(color).fixedSize(horizontal: false, vertical: true)
    }

    private func card<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.system(size: 15, weight: .semibold))
            content()
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading)
        .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
    }
}

/// The Scheduled backups card's controls (Windows Settings › Backups): how often, when, how many to keep, the folder,
/// the mirror folder and the backup password.
struct ScheduleControls: View {
    @Bindable var schedule: BackupScheduleModel
    var onChange: () -> Void
    @State private var timeText = ""
    @State private var timeError: String?
    @State private var settingPassword = false
    @State private var keySheet: BackupKeySheet.Mode?
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Picker("Scheduled backups", selection: $schedule.frequency) {
                    ForEach(Array(BackupSchedule.frequencies.enumerated()), id: \.element) { i, f in
                        Text(BackupScheduleModel.frequencyTitles[i]).tag(f)
                    }
                }
                .frame(width: 240)
                if schedule.frequency == "weekly" {
                    Picker("On", selection: $schedule.weekday) {
                        ForEach(Array(BackupSchedule.weekdays.enumerated()), id: \.offset) { i, d in Text(d).tag(i) }
                    }
                    .frame(width: 160)
                }
                if schedule.frequency != "off" {
                    TextField("12:00", text: $timeText).frame(width: 64).glassField()
                        .onSubmit { commitTime() }
                    Picker("Old scheduled backups", selection: $schedule.keep) {
                        ForEach(Array(BackupSchedule.keepChoices.enumerated()), id: \.element) { i, k in
                            Text(BackupScheduleModel.keepTitles[i]).tag(k)
                        }
                    }
                    .frame(width: 300)
                }
            }
            .font(.system(size: 12.5))
            if let timeError { Text(timeError).font(.system(size: 12)).foregroundStyle(theme.warning) }
            if schedule.frequency != "off", let next = schedule.nextText() {
                Text(next).font(.system(size: 12)).foregroundStyle(theme.textMuted)
            }
            row(String(localized: "Folder"), schedule.folder.map { $0.path } ?? BackupScheduleModel.defaultFolderText) {
                Button("Choose…") { chooseFolder() }.buttonStyle(PillButtonStyle(primary: schedule.folderNeedsChoosing))
                if schedule.folder != nil {
                    Button("Use this Mac") { schedule.clearFolder(); onChange() }.buttonStyle(PillButtonStyle(primary: false))
                }
            }
            row(String(localized: "Mirror folder"), schedule.mirror.map { $0.path } ?? String(localized: "None")) {
                Button("Choose…") { chooseMirror() }.buttonStyle(PillButtonStyle(primary: false))
                if schedule.mirror != nil {
                    Button("Remove") { schedule.clearMirror(); onChange() }.buttonStyle(PillButtonStyle(primary: false))
                }
            }
            Text(BackupScheduleModel.mirrorText).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            backupKeyRows
            if let notice = schedule.phraseNotice { Text(notice).font(.system(size: 12)).foregroundStyle(theme.warning) }
            if let notice = schedule.lastNotice { Text(notice).font(.system(size: 12)).foregroundStyle(theme.textMuted) }
        }
        .onAppear { timeText = schedule.time }
        .onChange(of: schedule.frequency) { _, _ in onChange() }
        .sheet(isPresented: $settingPassword, onDismiss: onChange) {
            SchedulePasswordSheet(schedule: schedule, onClose: { settingPassword = false }).macThemed()
        }
        .sheet(item: $keySheet, onDismiss: onChange) { mode in
            BackupKeySheet(schedule: schedule, mode: mode, onClose: { keySheet = nil }).macThemed()
        }
    }

    /// The backup key (design `backup-public-key-2026-10-31.md`): its line and actions, the upgrade notice (Q1), the
    /// pause after a rollback or a missing or damaged record (2.3, 16c) and the re-bind after a phrase change (Q2).
    @ViewBuilder private var backupKeyRows: some View {
        let state = schedule.keyState
        let paused = schedule.paused
        let ready: Bool = { if case .ready = state, !paused { return true }; return false }()
        let unreadable: Bool = { if case .unreadable = state { return true }; return false }()
        row(String(localized: "Backup password"), schedule.keyLine) {
            if ready {
                Button("Change…") { keySheet = .change }.buttonStyle(PillButtonStyle(primary: schedule.record?.setBy == "migrated"))
                Button("Forgot…") { keySheet = .reset }.buttonStyle(PillButtonStyle(primary: false))
                Button("Remove…") { keySheet = .remove }.buttonStyle(PillButtonStyle(primary: false))
            } else if paused || unreadable {
                EmptyView()   // paused: only the proof below; unreadable: nothing until it reads again
            } else if case .legacy = state {
                EmptyView()   // migrated at unlock
            } else {
                Button("Set…") { settingPassword = true }.buttonStyle(PillButtonStyle(primary: true))
                if case .damaged = state {
                    Button("Remove…") { keySheet = .remove }.buttonStyle(PillButtonStyle(primary: false))
                }
            }
        }
        if let notice = schedule.upgradeNotice {
            HStack(spacing: 8) {
                Text(notice).font(.system(size: 12)).foregroundStyle(theme.warning).fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button("Change…") { keySheet = .change }.buttonStyle(PillButtonStyle(primary: true))
                Button("Dismiss") { schedule.dismissUpgradeNotice(); onChange() }.buttonStyle(PillButtonStyle(primary: false))
            }
        }
        if let pausedNotice = schedule.pausedNotice {
            HStack(spacing: 8) {
                Text(pausedNotice).font(.system(size: 12)).foregroundStyle(theme.warning).fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button("Confirm…") { keySheet = .confirm }.buttonStyle(PillButtonStyle(primary: true))
                Button("Forgot…") { keySheet = .reset }.buttonStyle(PillButtonStyle(primary: false))
            }
        }
        if ready, schedule.needsRebind {
            HStack(spacing: 8) {
                Text(BackupScheduleModel.rebindNeededText).font(.system(size: 12)).foregroundStyle(theme.warning)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button("Enter backup password…") { keySheet = .rebind }.buttonStyle(PillButtonStyle(primary: true))
            }
        }
        if ready {
            Button("Test a backup…") { keySheet = .test }.buttonStyle(PillButtonStyle(primary: false))
        }
    }

    private func commitTime() {
        timeError = schedule.setTime(timeText)
        if timeError == nil { timeText = schedule.time; onChange() }
    }

    private func chooseFolder() {
        guard let url = RecoveryPanels.chooseScheduleFolder(message: String(localized: "Choose the folder for scheduled backups. They go into a Scheduled folder inside it.")) else { return }
        do { try schedule.chooseFolder(url) } catch { schedule.lastNotice = BackupScheduleModel.describe(error) }
        onChange()
    }

    private func chooseMirror() {
        guard let url = RecoveryPanels.chooseScheduleFolder(message: String(localized: "Choose a folder for backup copies")) else { return }
        do { try schedule.chooseMirror(url) } catch { schedule.lastNotice = BackupScheduleModel.describe(error) }
        onChange()
    }

    private func row<Buttons: View>(_ title: String, _ value: String, @ViewBuilder _ buttons: () -> Buttons) -> some View {
        HStack(spacing: 8) {
            Text(title).font(.system(size: 12.5, weight: .medium)).frame(width: 120, alignment: .leading)
            Text(value).font(.system(size: 12.5)).foregroundStyle(theme.textMuted).lineLimit(1).truncationMode(.middle)
            Spacer()
            buttons()
        }
    }
}

/// Sets the scheduled-backup password (twice) after the master password is checked.
struct SchedulePasswordSheet: View {
    let schedule: BackupScheduleModel
    var onClose: () -> Void
    @State private var password = ""
    @State private var again = ""
    @State private var master = ""
    @State private var error: String?
    @State private var working = false
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Backup password").font(.title3.weight(.semibold))
            Text(String(localized: "Scheduled backups are locked with a public key made from this password. The password itself is not stored, so keep it safe: it is needed with the master password to restore a backup. Choose one different from your master password, at least 12 characters."))
                .font(.system(size: 12.5)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            SecureField("Backup password", text: $password).glassField()
            SecureField("Confirm backup password", text: $again).glassField()
            SecureField("Master password", text: $master).glassField()
            if let error { Text(error).font(.system(size: 12.5)).foregroundStyle(theme.warning) }
            HStack {
                Spacer()
                Button("Cancel", action: onClose).buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button(working ? String(localized: "Working…") : String(localized: "Save")) {
                    // Captured now: the sheet may close before the Task runs.
                    let pw = password, pw2 = again, mp = master, schedule = self.schedule, close = onClose
                    working = true
                    Task {
                        do {
                            try await schedule.setPassword(pw, confirm: pw2, master: mp)
                            close()
                        } catch {
                            self.error = BackupScheduleModel.describe(error)
                        }
                        working = false
                    }
                }
                .buttonStyle(PillButtonStyle(primary: true)).keyboardShortcut(.defaultAction)
                .disabled(working || password.isEmpty || again.isEmpty || master.isEmpty)
            }
        }
        .padding(24).frame(width: 460).background(WashBackground()).foregroundStyle(theme.text)
    }
}

/// The passwords for creating, verifying or restoring a full backup.
struct FullBackupPasswordSheet: View {
    let model: RecoveryCentreModel
    let form: RecoveryCentreModel.PasswordForm
    @State private var password = ""
    @State private var again = ""
    @State private var master = ""
    @State private var keyLine: String?
    @Environment(\.macTheme) private var theme

    private var title: String {
        switch form.kind {
        case .create: String(localized: "Create a full backup")
        case .verify: String(localized: "Verify a backup")
        case .restore: String(localized: "Restore a backup")
        }
    }

    private var detail: String {
        switch form.kind {
        case .create(let folder):
            String(localized: "Saved in \(folder.lastPathComponent) with its checksum file. Choose a backup password different from your master password, at least 12 characters. Both are needed to restore it.")
        case .verify(let url):
            String(localized: "\(url.lastPathComponent): opened and checked item by item. Nothing on this Mac is changed.")
        case .restore(let url):
            String(localized: "\(url.lastPathComponent): you see what it holds before anything changes.")
        }
    }

    private var isCreate: Bool { if case .create = form.kind { true } else { false } }

    /// A Windows vault with a key file / YubiKey: what it also needs, asked once verify or preview said so.
    @ViewBuilder private var factorRows: some View {
        if let request = model.factorRequest, form.kind == .verify(request.url) || form.kind == .restore(request.url) {
            if request.kinds.contains(.keyFile) {
                HStack(spacing: 8) {
                    Text(request.keyFile.map { MacFactors.keyFileChosen($0.lastPathComponent) } ?? MacFactors.noKeyFileChosen)
                        .font(.system(size: 12.5)).lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 8)
                    Button(MacFactors.chooseKeyFileButton) { model.chooseRestoreKeyFile() }
                        .buttonStyle(GlassButtonStyle())
                        .disabled(model.working)
                }
            }
            if request.kinds.contains(.yubiKeyHMAC), YubiKeyPrompt.shared.waitingSlot == nil {
                Text(MacFactors.yubiKeyNeeded(slot: request.slot)).font(.system(size: 12.5))
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var actionLabel: String {
        switch form.kind {
        case .create: String(localized: "Create")
        case .verify: String(localized: "Verify")
        case .restore: String(localized: "Preview")
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(.title3.weight(.semibold))
            Text(detail).font(.system(size: 12.5)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            if let keyLine { Text(keyLine).font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true) }
            SecureField("Backup password", text: $password).glassField()
            if isCreate { SecureField("Confirm backup password", text: $again).glassField() }
            SecureField(isCreate ? String(localized: "Master password") : String(localized: "Master password when the backup was made"), text: $master).glassField()
            factorRows
            YubiKeyTouchBanner(prompt: YubiKeyPrompt.shared)
            if let e = model.error { Text(e).font(.system(size: 12.5)).foregroundStyle(theme.warning) }
            HStack {
                Spacer()
                Button("Cancel") { model.form = nil }.buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button(model.working ? String(localized: "Working…") : actionLabel) {
                    // Captured now: the sheet may close before the Task runs.
                    let pw = password, pw2 = again, mp = master, kind = form.kind
                    Task {
                        switch kind {
                        case .create(let folder): await model.create(folder: folder, password: pw, confirm: pw2, master: mp)
                        case .verify(let url): await model.verify(url: url, password: pw, master: mp)
                        case .restore(let url): await model.previewRestore(url: url, password: pw, master: mp)
                        }
                    }
                }
                .buttonStyle(PillButtonStyle(primary: true)).keyboardShortcut(.defaultAction)
                .disabled(model.working || password.isEmpty || master.isEmpty || (isCreate && again.isEmpty))
            }
        }
        .padding(24).frame(width: 460).background(WashBackground()).foregroundStyle(theme.text)
        .onAppear {
            switch form.kind {
            case .verify(let url), .restore(let url): keyLine = model.keyLine(for: url)
            case .create: keyLine = nil
            }
        }
    }
}

/// What restoring would do (counts first); Restore… then asks for the master password.
struct RestorePreviewSheet: View {
    let model: RecoveryCentreModel
    let pending: RecoveryCentreModel.PendingRestore
    @State private var keyLine: String?
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Replace this vault with the backup?").font(.title3.weight(.semibold))
            VStack(alignment: .leading, spacing: 4) {
                ForEach(pending.preview.lines, id: \.self) { Text("• " + $0).font(.system(size: 12.5)) }
            }
            if let keyLine {
                Text(keyLine).font(.system(size: 12.5)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            }
            Text("A safety copy of the vault as it is now is kept on this Mac first. Your master password is asked next.")
                .font(.system(size: 12.5)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancel") { model.pendingRestore = nil }.buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button("Restore…") { model.approveRestore(pending) }.buttonStyle(PillButtonStyle(primary: true))
            }
        }
        .padding(24).frame(width: 500).background(WashBackground()).foregroundStyle(theme.text)
        .onAppear { keyLine = model.keyLine(for: pending.url) }
    }
}

/// The backup key's sheets (design sections 6, 7, 9.2, 2.3 and Q2): change (with re-lock), reset with the recovery
/// phrase, remove (backup password or phrase), re-bind after a phrase change, confirm after a rollback, test a backup.
struct BackupKeySheet: View {
    enum Mode: String, Identifiable { case change, reset, remove, rebind, confirm, test; var id: String { rawValue } }

    let schedule: BackupScheduleModel
    let mode: Mode
    var onClose: () -> Void
    @State private var current = ""
    @State private var phrase = ""
    @State private var new = ""
    @State private var again = ""
    @State private var master = ""
    @State private var relock = true
    @State private var usePhrase = false
    @State private var error: String?
    @State private var result: String?
    @State private var working = false
    @Environment(\.macTheme) private var theme

    private var title: String {
        switch mode {
        case .change: String(localized: "Change backup password")
        case .reset: String(localized: "Reset backup password")
        case .remove: String(localized: "Remove backup password")
        case .rebind: String(localized: "Re-bind the recovery phrase")
        case .confirm: String(localized: "Confirm backup password")
        case .test: String(localized: "Test a backup")
        }
    }

    private var detail: String {
        switch mode {
        case .change: BackupScheduleModel.relockNoteText
        case .reset: schedule.resetUnavailableReason ?? String(localized: "Enter the 24 words of this vault's recovery phrase, then a new backup password twice. Backups made before the reset still need the old backup password.")
        case .remove: String(localized: "Scheduled backups stop until you set a backup password again. Existing backup files keep the password they were made with. Enter the current backup password or the recovery phrase that can reset it.")
        case .rebind: BackupScheduleModel.rebindNeededText
        case .confirm: schedule.pausedNotice ?? ""
        case .test: String(localized: "Checks the backup password and opens the newest scheduled backup with it. Nothing is restored or changed.")
        }
    }

    private var canReset: Bool { mode != .reset || schedule.resetUnavailableReason == nil }
    private var needsNew: Bool { mode == .change || mode == .reset }
    private var needsPhrase: Bool { mode == .reset || (mode == .remove && usePhrase) }
    private var needsCurrent: Bool { !needsPhrase && mode != .reset }
    /// A missing or damaged record (16c): the master password rebuilds the file's keys.
    private var needsMaster: Bool { (mode == .confirm || mode == .reset) && schedule.proofNeedsMaster }

    private var ready: Bool {
        guard canReset, !working else { return false }
        if needsCurrent && current.isEmpty { return false }
        if needsPhrase && phrase.isEmpty { return false }
        if needsNew && (new.isEmpty || again.isEmpty) { return false }
        if needsMaster && master.isEmpty { return false }
        return true
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(.title3.weight(.semibold))
            if !detail.isEmpty {
                Text(detail).font(.system(size: 12.5)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            }
            if mode == .remove {
                Toggle(String(localized: "Use the recovery phrase instead"), isOn: $usePhrase).font(.system(size: 12.5))
            }
            if needsCurrent { SecureField(String(localized: "Current backup password"), text: $current).glassField() }
            if needsPhrase && canReset {
                TextField(String(localized: "Recovery phrase (24 words)"), text: $phrase, axis: .vertical).lineLimit(3...5).glassField()
            }
            if needsNew && canReset {
                SecureField(String(localized: "New backup password"), text: $new).glassField()
                SecureField(String(localized: "Confirm new backup password"), text: $again).glassField()
            }
            if needsMaster && canReset { SecureField(String(localized: "Master password"), text: $master).glassField() }
            if mode == .change {
                Toggle(String(localized: "Re-lock existing scheduled backups"), isOn: $relock).font(.system(size: 12.5))
            }
            if let error { Text(error).font(.system(size: 12.5)).foregroundStyle(theme.warning).fixedSize(horizontal: false, vertical: true) }
            if let result { Text(result).font(.system(size: 12.5)).foregroundStyle(theme.success).fixedSize(horizontal: false, vertical: true) }
            HStack {
                Spacer()
                Button(result == nil ? String(localized: "Cancel") : String(localized: "Done"), action: onClose)
                    .buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                if result == nil {
                    Button(working ? String(localized: "Working…") : String(localized: "Continue")) { run() }
                        .buttonStyle(PillButtonStyle(primary: true)).keyboardShortcut(.defaultAction)
                        .disabled(!ready)
                }
            }
        }
        .padding(24).frame(width: 480).background(WashBackground()).foregroundStyle(theme.text)
    }

    private func run() {
        // Captured now: the sheet may close before the Task runs.
        let (schedule, mode, current, phrase, new, again, relock, usePhrase) =
            (self.schedule, self.mode, self.current, self.phrase, self.new, self.again, self.relock, self.usePhrase)
        let master = self.master
        let close = onClose
        working = true
        error = nil
        Task {
            do {
                switch mode {
                case .change:
                    result = try await schedule.changePassword(old: current, new: new, confirm: again, relock: relock)
                case .reset:
                    try await schedule.resetPassword(phrase: phrase, new: new, confirm: again, master: master)
                    result = schedule.lastNotice
                case .remove:
                    try await schedule.removeKey(proof: usePhrase ? .phrase(phrase) : .password(current))
                    close()
                case .rebind:
                    try await schedule.rebind(password: current)
                    close()
                case .confirm:
                    try await schedule.confirmKey(password: current, master: master)
                    close()
                case .test:
                    result = try await schedule.testBackup(password: current)
                }
            } catch {
                self.error = BackupScheduleModel.describe(error)
            }
            working = false
        }
    }
}

/// The Recovery centre's file panels. A backup is written beside its checksum file, so the app needs a folder it may
/// write: an `NSOpenPanel` folder, not a single `NSSavePanel` file.
@MainActor
enum RecoveryPanels {
    static var backupType: UTType? { UTType(filenameExtension: "lgk") }

    static func chooseBackupFolder(start: URL?) -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.directoryURL = start
        panel.message = String(localized: "Choose the folder for the backup. Its checksum file is saved beside it. A folder on another disk keeps it safe if this Mac fails.")
        panel.prompt = String(localized: "Back Up Here")
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func chooseScheduleFolder(message: String) -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.message = message
        panel.prompt = String(localized: "Choose")
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func chooseCleanupFolder(start: URL?) -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.directoryURL = start
        panel.message = String(localized: "Choose the folder that holds your backups.")
        panel.prompt = String(localized: "Choose")
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func chooseBackup(prompt: String, message: String) -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if let backupType { panel.allowedContentTypes = [backupType] }
        panel.message = message
        panel.prompt = prompt
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func chooseKitDestination() -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "recovery-kit.json"
        panel.canCreateDirectories = true
        panel.allowedContentTypes = [.json]
        panel.message = String(localized: "Write recovery kit (.json). Keep it with your encrypted backup.")
        panel.prompt = String(localized: "Save")
        return panel.runModal() == .OK ? panel.url : nil
    }
}

#if DEBUG
/// Screenshots: `LGK_MAC_RECOVERY_PREVIEW=page` fills the status with fixed contents.
enum RecoveryCentrePreview {
    static func status(now: Date = Date()) -> RecoveryStatus {
        RecoveryCentreModel.status(lastBackup: now.addingTimeInterval(-3 * 86_400 - 3600),
                                   lastVerified: now.addingTimeInterval(-3 * 86_400 - 3600), phrase: true,
                                   schedule: .off, now: now)
    }
}
#endif
