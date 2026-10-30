import SwiftUI
import AppKit
import AppSharedMac

/// The unlocked window (approved mockup): sidebar on the wash, the glass middle panel (search, Lock,
/// New item, then the overview, one-time codes, filter chips and item list) and the glass detail panel, three columns 210 / 480 / flexible, status line below.
struct MainWindow: View {
    let autoLockRemaining: () -> TimeInterval?
    let onLock: () -> Void
    @State private var list: VaultListModel
    @State private var sidebar: SidebarModel
    /// ⌘K: the command palette (nil while closed).
    @State private var palette: PaletteModel?
    @State private var showingShortcuts = false
    /// Setup on this Mac (workstream 4): the pages on first run, Show setup (palette), the list's card and
    /// Settings › Show setup again. Progress stays on this Mac.
    @State private var onboarding = Onboarding()
    /// The Sync status sheet (the sidebar's sync pill, palette Sync status; workstream 6).
    @State private var showingSyncStatus = false
    private let isUnlocked: @MainActor () -> Bool
    @FocusState private var searchFocused: Bool
    @FocusState private var listFocused: Bool
    /// The selected item's id; the detail panel shows it.
    @State private var selectedID: String?
    @State private var toast: String?
    @State private var toastTask: Task<Void, Never>?
    @State private var confirmingPasswordCopy = false
    @State private var keyMonitor: Any?
    @State private var saveError: String?
    @State private var editor: MacEditorSession
    @State private var pro: ProModel
    @State private var upgrade: UpgradePrompt
    @State private var choosingKind = false
    /// Scan QR code (New item menu, ⌘K): the sheet's model while open.
    @State private var scanning: TwoFactorScanModel?
    /// Set by the New item menu's Scan entry: the scan sheet opens once the menu sheet has gone.
    @State private var scanAfterMenu = false
    /// "Attach a file…" picked in the New item menu: the open panel follows once the menu has gone.
    @State private var attachAfterMenu = false
    /// The prefilled login a scan asked for, opened in the editor once the scan sheet has gone.
    @State private var scannedLogin: EditorModel?
    /// What to do once the person agrees to drop unsaved edits.
    @State private var pendingDiscard: PendingDiscard?
    /// Share… (UX workstream 9): the item whose share sheet is open.
    @State private var sharing: VaultItem?
    /// Receive a shared item… (menu, palette): the Receive sheet before any file arrived.
    @State private var receivingShare = false
    private let shareInbox: ShareInbox = MacAppEnvironment.shareInbox
    private let store: any ItemStore
    private let clipboard: MacClipboard
    @State private var settingsModel: MacSettingsModel
    @State private var overview: OverviewModel
    private let security: SecurityModel
    /// Revealed recovery codes, hidden field values and previous passwords (hidden on lock and selection change).
    private let extras: LoginExtrasModel
    /// Strict logins (`require_master_password`) release secrets only after the master password.
    @State private var gate: StrictItemGate
    private let passwords: (any MasterPasswordService)?
    /// Mac-local data (Recently deleted, activity); nil only in tests that don't need it.
    private let local: (any LocalDataHosting)?
    private let activity: ActivityRecorder?
    @State private var trash: TrashModel?
    @State private var connections: ConnectionsModel
    @State private var syncPage: SyncPageModel
    /// The Import & export page (imports, phone backup restore, exports).
    @State private var importExport: ImportExportModel
    /// The Recovery centre (full backups, restore, recovery phrase); its status feeds the overview and Security centre.
    @State private var recovery: RecoveryCentreModel
    /// The tool shown when a key rotation started, so the reopened window goes back to it (set only then).
    private static var lastTool: Tool?
    /// Apple Passwords export tokens, taken once the window is up.
    private let credentialExchange: MacCredentialExchangeInbox
    /// Reminders on typed items (nil without local data).
    @State private var reminders: RemindersModel?
    /// Mac-local collections and memberships (nil without local data).
    @State private var collections: CollectionsModel?
    @State private var managingCollections = false
    /// The item waiting for "Move to Recently deleted?".
    @State private var confirmingDelete: VaultItem?
    /// Whether the open editor creates (item.create) or edits (item.update).
    @State private var editorIsNew = false
    /// The Safari inbox import (nil in tests and the preview).
    private let safari: MacSafariImport?
    /// The sync schedule; each completed run reloads the window (nil: no sync, e.g. previews and tests).
    private let sync: MacSyncScheduler?
    @Environment(\.macTheme) private var theme

    static let titlebarHeight: CGFloat = 38

    init(store: any ItemStore, clipboard: MacClipboard = .shared, 
         pro: ProModel = MacAppEnvironment.pro, passwords: (any MasterPasswordService)? = nil,
         strengthCache: StrengthCache = StrengthCache(), reminders: [LocalData.Reminder] = [],
         security: SecurityModel = MacAppEnvironment.security, extras: LoginExtrasModel = MacAppEnvironment.loginExtras,
         local: (any LocalDataHosting)? = nil, activity: ActivityRecorder? = nil, notifier: ReminderNotifier? = nil,
         safari: MacSafariImport? = nil, sync: MacSyncScheduler? = nil, profile: DesktopProfileStore? = nil,
         schedule: BackupScheduleModel? = nil,
         credentialExchange: MacCredentialExchangeInbox = MacAppEnvironment.credentialExchange,
         isUnlocked: @escaping @MainActor () -> Bool = { MainWindow.isUnlocked(MacAppEnvironment.lockState) },
         autoLockRemaining: @escaping () -> TimeInterval?,
         onLock: @escaping () -> Void) {
        _list = State(initialValue: VaultListModel(store: store))
        _sidebar = State(initialValue: SidebarModel())
        self.isUnlocked = isUnlocked
        _settingsModel = State(initialValue: MacSettingsModel(settings: .shared, pro: pro, passwords: passwords, local: local))
        let upgrade = UpgradePrompt()
        self.local = local; self.activity = activity; self.safari = safari; self.sync = sync
        _trash = State(initialValue: local.map { local in
            TrashModel(store: store, local: local, isPro: { pro.isPro }, onNeedsPro: { upgrade.show($0) }, activity: activity)
        })
        notifier?.markUnlocked()
        _reminders = State(initialValue: local.map { RemindersModel(local: $0, notifier: notifier, activity: activity) })
        let collections = local.map { CollectionsModel(local: $0, activity: activity) }
        _collections = State(initialValue: collections)
        let overview = OverviewModel(cache: strengthCache)
        overview.reminders = reminders
        overview.breached = security.breached
        self.security = security
        self.extras = extras
        _overview = State(initialValue: overview)
        self.passwords = passwords
        let gate = StrictItemGate(passwords: passwords)
        _gate = State(initialValue: gate)
        _importExport = State(initialValue: ImportExportModel(
            store: store, isPro: { pro.isPro }, gate: gate,
            fallbackDeviceID: { try MacSyncEnvironment.keychain.installID(random: SystemRandomSource()) }, local: local,
            blobs: AttachmentFiles.localFolder()))
        let fullBackup: MacFullBackup? = profile.flatMap { profile in
            passwords.map { MacFullBackup(store: store, profile: profile, passwords: $0, gate: gate, local: local,
                                          attachmentFolder: AttachmentFiles.localFolder()) }
        }
        _recovery = State(initialValue: schedule.map { RecoveryCentreModel(backup: fullBackup, passwords: passwords, scheduleModel: $0) }
            ?? RecoveryCentreModel(backup: fullBackup, passwords: passwords))
        self.credentialExchange = credentialExchange
        _pro = State(initialValue: pro)
        let connections = ConnectionsModel(provider: Self.connectionProvider())
        connections.wifiState = { [weak sync] in ConnectionsModel.wifiState(on: AppSettings.shared.wifiSyncOn, endpoint: sync?.host?.endpoint) }
        _connections = State(initialValue: connections)
        _syncPage = State(initialValue: SyncPageModel(scheduler: sync, pro: pro, clipboard: clipboard, settings: .shared,
                                                      onNeedsPro: { upgrade.show($0) }))
        _upgrade = State(initialValue: upgrade)
        let editor = MacEditorSession(store: store, pro: pro, onNeedsPro: { upgrade.show($0) })
        editor.collections = collections
        _editor = State(initialValue: editor)
        self.store = store; self.clipboard = clipboard
        self.autoLockRemaining = autoLockRemaining
        self.onLock = onLock
    }

    var body: some View { liveChanges(window) }

    /// Split in two so the type checker finishes: the shell and its alerts, then the sheets and tasks.
    private var window: some View {
        windowSheets(windowChrome)
    }

    private var windowChrome: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: MacTheme.shellGap) {
                Sidebar(model: sidebar, onManageCollections: collections == nil ? nil : { managingCollections = true },
                        syncCoordinator: syncPage.coordinator, onSyncStatus: { showingSyncStatus = true })
                    .frame(width: 210)
                if case .tool(let tool) = sidebar.selection {
                    if tool == .generator {
                        ShellPanel { GeneratorPage() }
                    } else if tool == .settings {
                        ShellPanel {
                            MacSettingsView(model: settingsModel, onRecoveryCentre: { openRecoveryCentre(nil) },
                                            onShowSetup: { onboarding.showAgain() })
                        }
                    } else if tool == .securityCentre {
                        ShellPanel {
                            SecurityCentreView(model: security, overview: overview, items: list.items, gate: gate,
                                               touchIDAvailable: passwords?.touchIDAvailable ?? false,
                                               onSettings: { sidebar.selection = .tool(.settings) },
                                               onImportExport: { sidebar.selection = .tool(.importExport) },
                                               backup: recovery.status,
                                               onRecoveryCentre: { openRecoveryCentre($0) })
                        }
                    } else if tool == .trash, let trash {
                        ShellPanel { TrashView(model: trash, onSettings: { sidebar.selection = .tool(.settings) }) }
                    } else if tool == .reminders, let reminders {
                        ShellPanel { RemindersView(model: reminders) }
                    } else if tool == .activity, local != nil {
                        ShellPanel { ActivityView(events: local?.localData?.events ?? []) }
                    } else if tool == .devices {
                        ShellPanel { ConnectionsView(model: connections, onOpenSync: { sidebar.selection = .tool(.sync) }) }
                    } else if tool == .sync {
                        ShellPanel { SyncPage(model: syncPage) }
                    } else if tool == .importExport {
                        ShellPanel { ImportExportPage(model: importExport) }
                    } else if tool == .recoveryCentre {
                        ShellPanel { RecoveryCentrePage(model: recovery, onImportExport: { sidebar.selection = .tool(.importExport) }) }
                    } else if tool == .licence {
                        ShellPanel { LicencePage(pro: pro, clipboard: clipboard) }
                    } else {
                        ShellPanel { ComingLater(title: tool.title) }
                    }
                } else {
                    ShellPanel { middle }.frame(width: 480)
                    ShellPanel { detail }
                }
            }
            .padding(.horizontal, MacTheme.shellGap)
            StatusLine(autoLockRemaining: autoLockRemaining())
        }
        .padding(.top, Self.titlebarHeight)
        .frame(minWidth: 1100, idealWidth: 1180, minHeight: 680, idealHeight: 760)
        .background(WashBackground())
        .ignoresSafeArea()
        .focusedSceneValue(\.macWindowActions, menuActions)
        .overlay(alignment: .bottom) {
            if let toast { CopiedToast(text: toast).padding(.bottom, 44).transition(.opacity) }
        }
        .alert("Could not save", isPresented: savingFailed) {
            Button("OK", role: .cancel) {}
        } message: { Text(saveError ?? "") }
        .alert("Move to Recently deleted?", isPresented: confirmingDeleteShown) {
            Button("Move to Recently deleted", role: .destructive) { if let item = confirmingDelete { moveToTrash(item) }; confirmingDelete = nil }
            Button("Cancel", role: .cancel) { confirmingDelete = nil }
        } message: {
            Text(Self.deleteConfirmText(confirmingDelete))
        }
        .alert("Discard changes?", isPresented: pendingDiscardShown) {
            Button("Discard", role: .destructive) { discardAndContinue() }
            Button("Keep editing", role: .cancel) { pendingDiscard = nil }
        } message: { Text("Your changes to this item have not been saved.") }
    }

    private func windowSheets(_ content: some View) -> some View {
        content
        .onChange(of: credentialExchange.pending) { _, _ in takeCredentialExchange() }
        .sheet(item: $sharing) { item in
            MacShareSheet(item: item, onClose: { sharing = nil }).macThemed()
        }
        // A .lgkshare file opened from Finder or AirDrop: the code is asked for once the window is unlocked.
        .sheet(isPresented: Binding(get: { (receivingShare || shareInbox.pending != nil || shareInbox.message != nil) && isUnlocked() },
                                    set: { if !$0 { receivingShare = false; shareInbox.reject(); shareInbox.clearMessage() } })) {
            MacReceiveShareSheet(inbox: shareInbox, store: store, pro: pro,
                                 onSaved: { receivingShare = false; list.reload(); showToast(ShareText.saved) },
                                 onNeedsPro: { upgrade.show(.itemLimit) },
                                 onClose: { receivingShare = false; shareInbox.reject(); shareInbox.clearMessage() })
                .macThemed()
        }
        .sheet(isPresented: $upgrade.shown) {
            MacUpgradeSheet(pro: pro, reason: upgrade.reason, onClose: { upgrade.shown = false }).macThemed()
        }
        .sheet(item: Binding(get: { gate.pending }, set: { if $0 == nil { gate.cancel() } })) { request in
            StrictItemSheet(gate: gate, request: request).macThemed()
        }
        .sheet(isPresented: $managingCollections) {
            if let collections {
                CollectionsView(model: collections, onClose: { managingCollections = false }).macThemed()
            }
        }
        .overlay(alignment: .top) {
            if let palette {
                ZStack(alignment: .top) {
                    Color.black.opacity(0.18).ignoresSafeArea().onTapGesture { self.palette = nil }
                    CommandPalette(model: palette, onRun: runPaletteRow, onClose: { self.palette = nil })
                        .padding(.top, Self.titlebarHeight + 70)
                }
            }
        }
        .sheet(isPresented: Binding(get: { onboarding.pagesOpen && isUnlocked() },
                                    set: { if !$0 { onboarding.closePages() } })) {
            MacSetupSheet(onboarding: onboarding, onPick: { action in runAction(action) }).macThemed()
        }
        .onAppear(perform: detectSetup)
        .onChange(of: settingsModel.touchIDOn) { _, _ in detectSetup() }
        .onChange(of: settingsModel.recoveryPhraseSet) { _, _ in detectSetup() }
        .sheet(isPresented: Binding(get: { showingSyncStatus && syncPage.coordinator != nil },
                                    set: { if !$0 { showingSyncStatus = false } })) {
            if let coordinator = syncPage.coordinator {
                MacSyncStatusSheet(coordinator: coordinator,
                                   onOpenSettings: { showingSyncStatus = false; sidebar.selection = .tool(.sync) },
                                   onClose: { showingSyncStatus = false }).macThemed()
            }
        }
        .sheet(isPresented: $showingShortcuts) {
            ShortcutsSheet(onClose: { showingShortcuts = false }).macThemed()
        }
        .sheet(isPresented: $choosingKind, onDismiss: {
            // Two sheets cannot change in one update: Scan opens after the menu has gone.
            if scanAfterMenu { scanAfterMenu = false; requestScan() }
            if attachAfterMenu { attachAfterMenu = false; attachFile() }
        }) {
            NewItemMenu(onChoose: { kind in choosingKind = false; startNew(kind) }, onClose: { choosingKind = false },
                        onScan: { scanAfterMenu = true; choosingKind = false },
                        onAttachFile: { attachAfterMenu = true; choosingKind = false })
                .macThemed()
        }
        .sheet(item: $scanning, onDismiss: {
            if let login = scannedLogin { scannedLogin = nil; startScannedLogin(login) }
        }) { scan in
            MacScanSheet(model: scan, onNewLogin: { scannedLogin = $0 }, onSaved: { _ in scanSaved() },
                         onClose: { scanning = nil })
                .macThemed()
        }
        .task {
            if let safari {
                // Lists the logins saved in Safari; the sheet below asks before any is imported (Pro re-read first).
                await safari.afterUnlock(store: store, pro: pro, isUnlocked: isUnlocked)
            } else {
                await pro.refresh()
            }
        }
        .sheet(isPresented: Binding(get: { !(safari?.pending.isEmpty ?? true) && isUnlocked() },
                                    set: { if !$0 { safari?.later() } })) {
            if let safari {
                MacSafariReviewSheet(pending: safari.pending, onSave: { approved in answerSafari(approved) },
                                     onLater: { safari.later() })
                    .macThemed()
            }
        }
        .onChange(of: safari?.notice) { _, notice in
            guard let notice else { return }
            showToast(notice)
            safari?.clearNotice()
        }
        .task(id: syncCoordinatorID) {
            syncPage.coordinator?.announce = { showToast($0) }
        }
        .onAppear {
            list.reload(); sidebar.items = list.items; overview.items = list.items; installKeyMonitor()
            reminders?.items = list.items; reminders?.prune()
            collections?.items = list.items; collections?.prune(); syncCollections()
            if let snap = try? store.load() { pro.update(from: snap) }
            pro.vaultUnlocked(store: store)   // an App Store purchase not yet claimed as a licence is claimed now
            takeCredentialExchange()
            importExport.afterChange = { [store, list, reminders, collections, pro] in
                Self.afterSync(store: store, list: list, reminders: reminders, collections: collections,
                               updatePro: { pro.update(from: $0) })
            }
            recovery.backup?.afterChange = importExport.afterChange
            overview.backup = recovery.status
            // A phrase or password change relocked and reopened the window: go back to the page it was on.
            if passwords?.takeRotationReturn() == true, let tool = Self.lastTool { sidebar.selection = .tool(tool) }
            Self.lastTool = nil
            passwords?.setBeforeRotationLock { [sidebar] in
                if case .tool(let tool) = sidebar.selection { Self.lastTool = tool } else { Self.lastTool = nil }
            }
            #if DEBUG
            // Debug builds only: `LGK_MAC_SELECT=<title>` opens that item (screenshots).
            if let title = ProcessInfo.processInfo.environment["LGK_MAC_SELECT"] {
                selectedID = shown.first { $0.title == title }?.id
            }
            // `LGK_MAC_EDIT=1` opens the selected item in edit mode; `LGK_MAC_NEW=1` opens the New item chooser.
            if ProcessInfo.processInfo.environment["LGK_MAC_EDIT"] == "1", let item = selectedItem { startEdit(item) }
            if ProcessInfo.processInfo.environment["LGK_MAC_NEW"] == "1" { choosingKind = true }
            // `LGK_MAC_SCAN=start|choose|checklist|part` opens the Scan QR code sheet at that step (screenshots).
            if let step = ProcessInfo.processInfo.environment["LGK_MAC_SCAN"] {
                let scan = TwoFactorScanModel(store: store, pro: pro)
                scan.debugPreview(step)
                scanning = scan
            }
            // `LGK_MAC_PALETTE=<query>` opens the palette with that query; `LGK_MAC_SHORTCUTS=1` the shortcuts sheet.
            if let q = ProcessInfo.processInfo.environment["LGK_MAC_PALETTE"] { openPalette(); palette?.query = q }
            if ProcessInfo.processInfo.environment["LGK_MAC_SHORTCUTS"] == "1" { showingShortcuts = true }
            // `LGK_MAC_TOOL=settings` opens Settings in the window; `LGK_MAC_UPGRADE=1` shows the Pro sheet.
            if ProcessInfo.processInfo.environment["LGK_MAC_TOOL"] == "settings" { sidebar.selection = .tool(.settings) }
            // `LGK_MAC_TOOL=security` opens the Security centre.
            if ProcessInfo.processInfo.environment["LGK_MAC_TOOL"] == "security" { sidebar.selection = .tool(.securityCentre) }
            if ProcessInfo.processInfo.environment["LGK_MAC_UPGRADE"] == "1" { upgrade.show(.itemLimit) }
            // `LGK_MAC_TOOL=trash` opens Recently deleted, `activity` the Activity history.
            if ProcessInfo.processInfo.environment["LGK_MAC_TOOL"] == "trash" { sidebar.selection = .tool(.trash) }
            if ProcessInfo.processInfo.environment["LGK_MAC_TOOL"] == "activity" { sidebar.selection = .tool(.activity) }
            if ProcessInfo.processInfo.environment["LGK_MAC_TOOL"] == "devices" { sidebar.selection = .tool(.devices) }
            if ProcessInfo.processInfo.environment["LGK_MAC_TOOL"] == "reminders" { sidebar.selection = .tool(.reminders) }
            if ProcessInfo.processInfo.environment["LGK_MAC_TOOL"] == "licence" { sidebar.selection = .tool(.licence) }
            debugSyncLaunch()
            // `LGK_MAC_COLLECTION=<name>` selects that collection in the sidebar.
            if let name = ProcessInfo.processInfo.environment["LGK_MAC_COLLECTION"],
               let c = sidebar.collections.first(where: { $0.name == name }) { sidebar.selection = .collection(c.id) }
            #endif
        }
        .onAppear { takeQuickAccess() }
        .onChange(of: QuickAccessBridge.shared.pending) { _, _ in takeQuickAccess() }
        .onChange(of: QuickAccessBridge.shared.paletteRequests) { _, _ in openPalette() }
        .onDisappear { pro.vaultLocked(); palette = nil; gate.lockReset(); importExport.reset(); if let keyMonitor { NSEvent.removeMonitor(keyMonitor) }; keyMonitor = nil }
        .onChange(of: local?.localData?.trash.count) { _, _ in
            // A restore wrote items back: show them and recount the free plan.
            list.reload()
            collections?.prune()   // a purge lets its memberships go
            if let snap = try? store.load() { pro.update(from: snap) }
        }
        .onChange(of: list.items) { _, items in
            sidebar.items = items; overview.items = items; overview.reconcileChip()
            // A deleted item takes its reminders (and their notifications) with it.
            reminders?.items = items; reminders?.prune()
            collections?.items = items; collections?.prune()
        }
        .onChange(of: sync?.syncRevision) { _, _ in
            // A sync run finished (or a peer's merge was served): show what it brought.
            Self.afterSync(store: store, list: list, reminders: reminders, collections: collections,
                           updatePro: { pro.update(from: $0) })
        }
        .onChange(of: local?.localData?.collections) { _, _ in syncCollections() }
        .onChange(of: local?.localData?.memberships) { _, _ in syncCollections() }
        .onChange(of: local?.localData?.reminders) { _, now in
            // Coming up and the Expiring chip follow reminder changes live.
            overview.reminders = now ?? []; overview.reconcileChip()
        }
    }

    /// The settings, breach, backup and selection changes the window follows.
    private func liveChanges<V: View>(_ content: V) -> some View {
        content
            .onChange(of: settingsModel.showItemNamesInReminders) { _, _ in reminders?.reschedule() }
            .onChange(of: security.breached) { _, breached in overview.breached = breached }
            .onChange(of: recovery.status) { _, status in overview.backup = status }
            .onChange(of: overview.activeChip) { _, _ in keepSelectionVisible() }
            .onChange(of: sidebar.selection) { _, _ in keepSelectionVisible() }
            .onChange(of: list.query) { _, _ in keepSelectionVisible() }
    }

    /// The Passwords app handed over an export: open Import & export and read it into the review.
    private func takeCredentialExchange() {
        guard isUnlocked(), let token = credentialExchange.take() else { return }
        sidebar.selection = .tool(.importExport)
        importExport.receivedExchange(token: token)
        Task { await importExport.importFromApplePasswords() }
    }

    // MARK: middle panel

    /// After each completed sync run: reload the list, drop reminders and collection memberships of items
    /// that are gone, and update Pro from the store (a desktop licence received through sync unlocks it).
    static func afterSync(store: any ItemStore, list: VaultListModel, reminders: RemindersModel?,
                          collections: CollectionsModel?, updatePro: (StoreSnapshot) -> Void) {
        list.reload()
        reminders?.items = list.items; reminders?.prune()
        collections?.items = list.items; collections?.prune()
        if let snap = try? store.load() { updatePro(snap) }
    }

    private var middle: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").foregroundStyle(theme.textFaint)
                    TextField("Search this profile", text: $list.query)
                        .textFieldStyle(.plain).focused($searchFocused)
                        .onKeyPress(.downArrow) {
                            // ↓ moves into the results.
                            if selectedID == nil || !shown.contains(where: { $0.id == selectedID }) { selectedID = shown.first?.id }
                            listFocused = true
                            return .handled
                        }
                    Text("⌘K").font(.system(size: 12)).foregroundStyle(theme.textFaint)
                }
                .padding(.horizontal, 14).padding(.vertical, 7)
                .background(theme.card, in: Capsule())
                .overlay(Capsule().strokeBorder(theme.panelBorder))
                Button("Lock", action: onLock).buttonStyle(PillButtonStyle(primary: false))
                Button("New item", action: requestNew)
                    .buttonStyle(PillButtonStyle(primary: true))
            }
            .foregroundStyle(theme.text)
            .padding(.bottom, 10)

            if isUnlocked(), let text = onboarding.cardText {
                MacSetupCard(text: text, onOpen: { onboarding.showAgain() }, onHide: { onboarding.hideCard() })
            }
            itemList
        }
        .padding(.horizontal, 14).padding(.vertical, 12)
    }

    private var shown: [VaultItem] {
        overview.applyChip(ItemListFilter.apply(list.items, selection: sidebar.selection, query: list.query,
                                                 memberships: sidebar.memberships))
    }

    /// The overview shows only on All items with no search and no chip.
    private var showsOverview: Bool { sidebar.selection == .all && list.query.isEmpty && overview.activeChip == nil }

    /// Above the rows, scrolling with them: overview cards and codes, then the title, count and chips.
    private var listHeader: some View {
        VStack(alignment: .leading, spacing: 0) {
            if showsOverview {
                OverviewCards(model: overview, onGenerator: { sidebar.selection = .tool(.generator) },
                              onBackup: { openRecoveryCentre(nil) })
                CodesStrip(model: overview, items: list.items, onCopy: copyCode).padding(.top, 14)
            }
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(sidebar.title).font(.system(size: 19, weight: .semibold)).foregroundStyle(theme.text)
                Text(countLabel).font(.system(size: 12)).foregroundStyle(theme.textFaint)
            }
            .padding(.horizontal, 2).padding(.top, showsOverview ? 16 : 6).padding(.bottom, 8)
            FilterChips(model: overview).padding(.bottom, 8)
        }
    }

    private var selectedItem: VaultItem? { selectedID.flatMap { id in list.items.first { $0.id == id } } }

    private var countLabel: String { shown.count == 1 ? String(localized: "1 item") : String(localized: "\(shown.count) items") }

    @ViewBuilder private var itemList: some View {
        if let error = list.loadError {
            Text(error).foregroundStyle(theme.danger)
        } else {
            ItemListView(items: shown, selection: guardedSelection, focused: $listFocused, onOpen: { _ in listFocused = true },
                         tag: { overview.tag(for: $0) }, header: AnyView(listHeader),
                         emptyText: list.query.isEmpty && overview.activeChip == nil ? String(localized: "No items here yet.") : String(localized: "No items match your search."))
        }
    }

    // MARK: detail panel

    @ViewBuilder private var detail: some View {
        if let model = editor.model {
            MacEditorView(session: editor, model: model, item: editor.editingID.flatMap { id in list.items.first { $0.id == id } },
                          onSaved: finishedEditing, onCancel: requestCancel)
                .id(ObjectIdentifier(model))
        } else if let item = selectedItem {
            DetailPanel(item: item, clipboard: clipboard, gate: gate,
                        onToggleFavourite: { toggleFavourite(item) },
                        onCopied: { _ in copied(item) },
                        onEdit: MacEditorSession.canEdit(item) ? { startEdit(item) } : nil,
                        onDelete: trash != nil && !editor.isActive ? { confirmingDelete = item } : nil,
                        reminders: reminders,
                        extras: extras, store: store,
                        onExtrasSaved: { extrasSaved(item) },
                        onRevealed: { activity?.record(.credentialReveal, itemID: item.id, count: 1) },
                        collectionNames: CollectionsModel.canBeMember(item)
                            ? (collections?.collections.filter { sidebar.memberships[item.id]?.contains($0.id) ?? false }.map(\.name) ?? [])
                            : [],
                        onShare: Share.canShare(item.record) ? { shareItem(item) } : nil)
                .id(item.id)
        } else {
            Text("Select an item")
                .foregroundStyle(theme.textMuted)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    /// The sidebar's Collections group follows the local data; a deleted collection's row falls back to All items.
    private func syncCollections() {
        sidebar.collections = local?.localData?.collections ?? []
        sidebar.memberships = local?.localData?.memberships ?? [:]
        if case .collection(let id) = sidebar.selection, !sidebar.collections.contains(where: { $0.id == id }) {
            sidebar.selection = .all
        }
    }

    // MARK: editing

    enum PendingDiscard: Equatable { case select(String?), new, cancel, scan }

    // Changing the sidebar row while editing does not ask: the unsaved edits are kept and the form comes back
    // in the detail panel when a list is shown again (only list selection, Cancel and New item ask to discard).

    /// The list selection; moving away from an item with unsaved edits asks first.
    private var guardedSelection: Binding<String?> {
        Binding(get: { selectedID }, set: { id in
            guard id != selectedID || editor.isActive else { return }
            if editor.isDirty { pendingDiscard = .select(id) } else { editor.cancel(); selectedID = id }
        })
    }

    /// Opening the editor shows a strict login's secrets, so it asks first.
    private func startEdit(_ item: VaultItem) {
        gate.release(item, action: String(localized: "Edit")) { editorIsNew = false; editor.startEdit(item) }
    }

    private func requestNew() {
        if editor.isDirty { pendingDiscard = .new; return }
        editor.cancel()
        guard editor.allowsNew() else { return }
        choosingKind = true
    }

    private func requestCancel() {
        if editor.isDirty { pendingDiscard = .cancel } else { editor.cancel() }
    }

    private func discardAndContinue() {
        let action = pendingDiscard
        pendingDiscard = nil
        editor.cancel()
        switch action {
        case .select(let id)?: selectedID = id
        case .new?: if editor.allowsNew() { choosingKind = true }
        case .scan?: requestScan()
        case .cancel?, nil: break
        }
    }

    /// Scan QR code: 2FA keys are Pro (the editor's rule), so the free plan gets the upgrade sheet instead.
    private func requestScan() {
        guard isUnlocked() else { return }
        if editor.isDirty { pendingDiscard = .scan; return }
        guard pro.isPro else { upgrade.show(.twoFactor); return }
        scanning = TwoFactorScanModel(store: store, pro: pro)
    }

    /// The new login a scanned code asked for, prefilled and open in the editor (not saved yet).
    private func startScannedLogin(_ login: EditorModel) {
        guard isUnlocked() else { return }
        editor.cancel()
        if sidebar.selection.isTool { sidebar.selection = .all }
        editorIsNew = true
        editor.startPrefilled(login)
    }

    /// A scan added a key or imported accounts: the list and the free-plan count follow.
    /// "Attach a file…" (task 12): Pro only; the new document is selected.
    private func attachFile() {
        guard isUnlocked() else { return }
        guard pro.isPro else { upgrade.show(.attachments); return }
        switch MacAttachFile.run(store: store, isPro: pro.isPro) {
        case .saved?:
            list.reload()
            showToast(String(localized: "File attached"))
        case .needsPro?: upgrade.show(.attachments)
        case .tooLarge?: showToast(DocumentFiles.tooLargeMessage)
        case .unavailable?, .failed?: showToast(String(localized: "The file could not be saved on this Mac."))
        case nil: break
        }
    }

    private func scanSaved() {
        list.reload()
        if let snap = try? store.load() { pro.update(from: snap) }
        showToast(String(localized: "2FA saved"))
    }

    private func startNew(_ kind: EditorKind) {
        if sidebar.selection.isTool { sidebar.selection = .all }
        editorIsNew = true
        editor.startNew(kind)
    }

    /// After Save: the list reloads and the saved item is selected (shown under All items if hidden).
    private func finishedEditing(_ id: String?) {
        list.reload()
        if let snap = try? store.load() { pro.update(from: snap) }
        guard let id else { return }
        activity?.record(editorIsNew ? .itemCreate : .itemUpdate, itemID: id)
        if !shown.contains(where: { $0.id == id }) { sidebar.selection = .all; list.query = "" }
        selectedID = id
    }

    private func toggleFavourite(_ item: VaultItem) {
        do {
            try ItemActions.setFavourite(id: item.id, !item.favorite, store: store, clock: SystemClock())
            activity?.record(.itemUpdate, itemID: item.id)
        } catch {
            saveError = String(localized: "The item could not be saved on this device.")
        }
        list.reload()
    }

    // MARK: deleting

    /// "Move {name} to Recently deleted? You can restore it from Trash later." (Windows `trash`).
    static func deleteConfirmText(_ item: VaultItem?) -> String {
        let name = item.map { $0.title.isEmpty ? String(localized: "this item") : $0.title } ?? String(localized: "this item")
        return String(localized: "Move \(name) to Recently deleted? You can restore it from Trash later.")
    }

    /// ⌫ or the Delete button: asks first (`confirmingDelete`), then moves the item to Recently deleted.
    private func requestDelete() -> Bool {
        guard trash != nil, !editor.isActive, let item = selectedItem else { return false }
        confirmingDelete = item
        return true
    }

    private func moveToTrash(_ item: VaultItem) {
        guard let trash else { return }
        do {
            try trash.moveToTrash(id: item.id)
            if selectedID == item.id { selectedID = nil }
            showToast(String(localized: "Moved to Recently deleted"))
        } catch TrashModel.Failure.notFound {
        } catch TrashModel.Failure.compensation {
            saveError = TrashModel.compensationMessage
        } catch {
            saveError = TrashModel.deleteFailedMessage
        }
        list.reload()
        if let snap = try? store.load() { pro.update(from: snap) }
    }

    /// Recovery codes or custom fields were saved from the detail panel.
    private func extrasSaved(_ item: VaultItem) {
        activity?.record(.itemUpdate, itemID: item.id)
        list.reload()
        showToast(String(localized: "Saved"))
    }

    /// A value left the app through a copy button or shortcut (content-free event).
    /// Share…: a strict item asks for the master password first, as for showing its secret.
    private func shareItem(_ item: VaultItem) {
        guard isUnlocked() else { return }
        gate.release(item, action: String(localized: "Share")) { sharing = item }
    }

    private func copied(_ item: VaultItem) {
        activity?.record(.credentialCopy, itemID: item.id, count: 1)
        showToast(String(localized: "Copied"))
    }

    /// The selection stays only while its item is listed.
    private func keepSelectionVisible() {
        if let id = selectedID, !shown.contains(where: { $0.id == id }) { selectedID = nil }
    }

    /// The Safari review sheet's answer: one commit, then the list (and the free-plan count) follow it.
    private func answerSafari(_ approved: Set<String>) {
        guard let safari else { return }
        guard isUnlocked() else { return safari.later() }
        let result = safari.confirm(approved, store: store, isPro: pro.isPro, activity: activity,
                                    onNeedsPro: { reason in
            // After the review sheet has gone: two sheets cannot change in the same update.
            Task {
                try? await Task.sleep(for: .milliseconds(400))
                if isUnlocked() { upgrade.show(reason) }
            }
        })
        if let result, result.saved > 0 {
            list.reload()
            if let snap = try? store.load() { pro.update(from: snap) }
        }
    }

    private var savingFailed: Binding<Bool> {
        Binding(get: { saveError != nil }, set: { if !$0 { saveError = nil } })
    }
    private var confirmingDeleteShown: Binding<Bool> {
        Binding(get: { confirmingDelete != nil }, set: { if !$0 { confirmingDelete = nil } })
    }
    private var pendingDiscardShown: Binding<Bool> {
        Binding(get: { pendingDiscard != nil }, set: { if !$0 { pendingDiscard = nil } })
    }
    private var syncCoordinatorID: ObjectIdentifier? { syncPage.coordinator.map { ObjectIdentifier($0) } }

    private func showToast(_ text: String) {
        toastTask?.cancel()
        withAnimation(.easeOut(duration: 0.15)) { toast = text }
        toastTask = Task {
            try? await Task.sleep(for: .seconds(1.6))
            guard !Task.isCancelled else { return }
            withAnimation(.easeIn(duration: 0.2)) { toast = nil }
        }
    }

    static var expiryLabel: String { AppSettings.shared.clipboardExpiry.label }

    // MARK: copy shortcuts

    /// ⇧⌘C username, ⌘C password, ⌘T one-time code of the selected item. A local key monitor, so a text
    /// field being edited (the search field) keeps its own ⌘C; anywhere else in the window the item's copy wins
    /// over Edit › Copy.
    private func installKeyMonitor() {
        guard keyMonitor == nil else { return }
        keyMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            let handled = MainActor.assumeIsolated { handleKey(event) }
            return handled ? nil : event
        }
    }

    private func handleKey(_ event: NSEvent) -> Bool {
        let mods = event.modifierFlags.intersection(.deviceIndependentFlagsMask).subtracting([.capsLock, .numericPad, .function])
        // ⌫ / ⌦ (or ⌘⌫) on the focused item list: "Move to Recently deleted?" first.
        if Self.isDeleteKey(event.keyCode), mods.isEmpty || mods == [.command], event.window?.isKeyWindow == true,
           !(event.window?.firstResponder is NSText), listFocused, !sidebar.selection.isTool,
           confirmingDelete == nil, !confirmingPasswordCopy {
            return requestDelete()
        }
        if Self.opensShortcuts(characters: event.characters, modifiers: mods, inTextField: event.window?.firstResponder is NSText),
           event.window?.isKeyWindow == true, palette == nil, !showingShortcuts {
            showingShortcuts = true
            return true
        }
        guard mods.contains(.command), let key = event.charactersIgnoringModifiers?.lowercased() else { return false }
        guard event.window?.isKeyWindow == true, selectedItem != nil, !confirmingPasswordCopy else { return false }
        let responder: CopyShortcutPolicy.Responder =
            event.window?.firstResponder is NSText ? .text : (listFocused ? .itemList : .other)
        guard CopyShortcutPolicy.intercepts(key: key, shift: mods.contains(.shift), responder: responder,
                                                listShown: !sidebar.selection.isTool) else { return false }
        switch (key, mods) {
        case ("c", [.command, .shift]): return copyUsername()
        case ("c", [.command]):
            guard Self.password(of: selectedItem) != nil else { return false }
            requestCopyPassword()
            return true
        case ("t", [.command]): return copyCode()
        default: return false
        }
    }

    /// `?` (with or without ⇧, as keyboards differ) outside a text field opens the shortcuts sheet.
    static func opensShortcuts(characters: String?, modifiers: NSEvent.ModifierFlags, inTextField: Bool) -> Bool {
        characters == "?" && modifiers.subtracting(.shift).isEmpty && !inTextField
    }

    /// Opens the Recovery centre, optionally starting one of its actions (Security centre rows).
    private func openRecoveryCentre(_ initial: RecoveryCentreModel.Initial?) {
        recovery.initial = initial
        sidebar.selection = .tool(.recoveryCentre)
    }

    #if DEBUG
    /// `LGK_MAC_TOOL=sync` opens Sync; `LGK_MAC_SYNC_PREVIEW=page|confirm` fills it with fixed contents.
    private func debugSyncLaunch() {
        let env = ProcessInfo.processInfo.environment
        if env["LGK_MAC_TOOL"] == "sync" { sidebar.selection = .tool(.sync) }
        // `LGK_MAC_TOOL=import` opens Import & export; `LGK_MAC_IMPORT_PREVIEW=review|restore` opens the review sheet.
        if env["LGK_MAC_TOOL"] == "import" { sidebar.selection = .tool(.importExport) }
        // `LGK_MAC_TOOL=recovery` opens the Recovery centre; `LGK_MAC_RECOVERY_PREVIEW=page` fixes its status.
        if env["LGK_MAC_TOOL"] == "recovery" { sidebar.selection = .tool(.recoveryCentre) }
        if env["LGK_MAC_RECOVERY_PREVIEW"] == "page" { recovery.previewStatus = RecoveryCentrePreview.status() }
        if let p = env["LGK_MAC_IMPORT_PREVIEW"] { importExport.showPreview(p) }
        if let p = env["LGK_MAC_SYNC_PREVIEW"] {
            syncPage.preview = SyncPagePreview.make(p)
            syncPage.showingQR = p == "confirm"
        }
    }
    #endif

    // MARK: palette

    /// Fails closed: no lock model (it is held weakly) counts as locked.
    static func connectionProvider() -> any ConnectionStateProviding {
        #if DEBUG
        if ProcessInfo.processInfo.environment["LGK_MAC_SHELL_PREVIEW"] == "1" { return PreviewConnectionState() }
        #endif
        return SystemConnectionState()
    }

    static func isUnlocked(_ lock: MacLockModel?) -> Bool { lock?.state == .unlocked }

    private func openPalette() {
        guard isUnlocked() else { return }
        palette = PaletteModel(items: { [list] in list.items },
                               collections: { [sidebar] in sidebar.collections },
                               memberships: { [sidebar] in sidebar.memberships },
                               isUnlocked: isUnlocked)
    }

    /// Runs a palette row through the window's own paths: item rows only select (the detail panel and its gates
    /// release secrets), Lock goes through onLock, Change master password opens the Settings sheet that asks
    /// for the current password, and the Security centre starts no request by itself.
    private func runPaletteRow(_ row: PaletteRow) {
        guard let model = palette else { return }
        palette = nil
        guard model.allows(row) else { return }
        switch row.target {
        case .item(let id):
            guard list.items.contains(where: { $0.id == id }) else { return }
            if sidebar.selection.isTool { sidebar.selection = .all }
            if !shown.contains(where: { $0.id == id }) { sidebar.selection = .all; list.query = ""; overview.activeChip = nil }
            guardedSelection.wrappedValue = id
            listFocused = true
        case .action(let action):
            runAction(action)
        }
    }

    /// Steps finished elsewhere count as done: Touch ID unlock on, a recovery phrase set (it was confirmed by
    /// retyping three of its words when it was made).
    private func detectSetup() {
        if settingsModel.touchIDOn { onboarding.complete(.unlock) }
        if passwords?.hasRecoveryPhrase == true { onboarding.complete(.phrase) }
    }

    /// A palette action (or a Show setup step) through the window's own paths.
    private func runAction(_ action: PaletteAction) {
        guard isUnlocked() || action == .shortcuts else { return }
        switch action {
        case .generatePassword: sidebar.selection = .tool(.generator)
        case .newItem: requestNew()
        case .scanQR: requestScan()
        case .lockNow: onLock()
        case .changeMasterPassword:
            sidebar.selection = .tool(.settings); settingsModel.requestsPasswordChange = true
        case .securityCentre: sidebar.selection = .tool(.securityCentre)
        case .reminders: sidebar.selection = .tool(.reminders)
        case .trash: sidebar.selection = .tool(.trash)
        case .activity: sidebar.selection = .tool(.activity)
        case .devices: sidebar.selection = .tool(.devices)
        case .sync: sidebar.selection = .tool(.sync)
        case .importFile:
            sidebar.selection = .tool(.importExport)
            if let url = MacFilePanels.chooseImport() { Task { await importExport.importFile(url: url) } }
        case .export: sidebar.selection = .tool(.importExport)
        case .recoveryCentre: openRecoveryCentre(nil)
        case .settings(let section):
            sidebar.selection = .tool(.settings); settingsModel.requestedSection = section
        case .shortcuts: showingShortcuts = true
        case .securityCheck: sidebar.selection = .tool(.securityCentre)
        case .syncStatus:
            if syncPage.coordinator != nil { showingSyncStatus = true } else { sidebar.selection = .tool(.sync) }
        case .showSetup: onboarding.showAgain()
        case .receiveShare: receivingShare = true
        }
    }

    /// Delete (⌫, key code 51) and forward delete (⌦, 117).
    static func isDeleteKey(_ code: UInt16) -> Bool { code == 51 || code == 117 }

    static func password(of item: VaultItem?) -> String? {
        guard let item, item.isLogin, let p = item.record["password"]?.stringValue, !p.isEmpty else { return nil }
        return p
    }

    @discardableResult private func copyUsername() -> Bool {
        guard let item = selectedItem, item.isLogin, !item.username.isEmpty else { return false }
        gate.release(item, action: String(localized: "Copy username")) { clipboard.copy(item.username, concealed: false); copied(item) }
        return true
    }

    private func requestCopyPassword() {
        // Windows asks for routine re-authentication instead of a one-off "Copy password?" question.
        copyPassword()
    }

    private func copyPassword() {
        guard let item = selectedItem, let p = Self.password(of: item) else { return }
        gate.releaseRoutine(item, action: String(localized: "Copy password")) { clipboard.copy(p, concealed: true); copied(item) }
    }

    @discardableResult private func copyCode() -> Bool {
        guard let item = selectedItem, Self.hasCode(item) else { return false }
        gate.release(item, action: String(localized: "Copy one-time code")) { copyCode(of: item) }
        return true
    }

    /// A tile of the codes strip: hidden codes ask for the master password first.
    private func copyCode(_ entry: CodeEntry) {
        guard let item = list.items.first(where: { $0.id == entry.id }) else { return }
        gate.release(item, action: String(localized: "Copy one-time code")) { copyCode(of: item) }
    }

    @discardableResult private func copyCode(of item: VaultItem) -> Bool {
        guard case .object(let t)? = item.record["totp"], let secret = t["secret"]?.stringValue else { return false }
        func int(_ k: String, _ d: Int) -> Int { if case .int(let n)? = t[k] { return Int(n) }; return d }
        guard let code = try? TOTP.code(secret: secret, algorithm: t["algorithm"]?.stringValue ?? "SHA1", digits: int("digits", 6),
                                        period: int("period", 30), at: SystemClock().now) else { return false }
        clipboard.copy(code, concealed: true); copied(item)
        return true
    }

    /// A copy asked for from the menu bar: the same gate and clipboard as the list's copy commands. A strict
    /// item's master password sheet needs the window, so the app comes forward for it.
    private func takeQuickAccess() {
        guard let request = QuickAccessBridge.shared.pending, isUnlocked() else { return }
        QuickAccessBridge.shared.pending = nil
        guard let item = list.items.first(where: { $0.id == request.itemID }) else { return }
        switch request.copy {
        case .username:
            guard item.isLogin, !item.username.isEmpty else { return }
            gate.release(item, action: String(localized: "Copy username")) { clipboard.copy(item.username, concealed: false); copied(item) }
        case .password:
            guard let p = Self.password(of: item) else { return }
            gate.releaseRoutine(item, action: String(localized: "Copy password")) { clipboard.copy(p, concealed: true); copied(item) }
        case .code:
            guard Self.hasCode(item) else { return }
            gate.release(item, action: String(localized: "Copy one-time code")) { copyCode(of: item) }
        }
        if gate.pending != nil { QuickAccessBridge.activate() }
    }

    // MARK: menu commands

    /// What the menu bar's items do in this window (Commands.swift); an item is greyed out when nil here.
    private var menuActions: MacWindowActions {
        let item = selectedItem
        let listShown = !sidebar.selection.isTool
        let copyAllowed = Self.menuCopyAllowed(listShown: listShown, listFocused: listFocused)
        return MacWindowActions(
            search: { palette = nil; if sidebar.selection.isTool { sidebar.selection = .all }; searchFocused = true },
            palette: openPalette,
            shortcuts: { palette = nil; showingShortcuts = true },
            newItem: requestNew,
            copyUsername: copyAllowed && item?.isLogin == true && item?.username.isEmpty == false ? { copyUsername() } : nil,
            copyPassword: copyAllowed && Self.password(of: item) != nil ? { requestCopyPassword() } : nil,
            copyCode: copyAllowed && item.map(Self.hasCode) == true ? { copyCode() } : nil,
            edit: listShown && !editor.isActive && item.map(MacEditorSession.canEdit) == true ? { if let item { startEdit(item) } } : nil,
            save: listShown && editor.isActive ? { saveEditor() } : nil,
            receiveShare: { palette = nil; if isUnlocked() { receivingShare = true } })
    }

    /// The Item menu's copy entries work only from the focused item list (as the ⌘C/⇧⌘C/⌘T policy).
    static func menuCopyAllowed(listShown: Bool, listFocused: Bool) -> Bool { listShown && listFocused }

    static func hasCode(_ item: VaultItem) -> Bool {
        if case .object(let t)? = item.record["totp"], t["secret"]?.stringValue?.isEmpty == false { return true }
        return false
    }

    private func saveEditor() {
        if editor.save() == .saved || editor.model == nil { finishedEditing(editor.lastSavedID) }
    }
}

/// The capsule buttons of the middle panel (mockup `.btn` and `.btn.pri`).
struct PillButtonStyle: ButtonStyle {
    let primary: Bool
    @Environment(\.macTheme) private var theme
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 14, weight: primary ? .medium : .regular))
            .padding(.horizontal, 16).padding(.vertical, 7)
            .foregroundStyle(primary ? theme.onAccent : theme.text)
            .background(primary ? theme.accent : theme.card, in: Capsule())
            .overlay(Capsule().strokeBorder(primary ? .clear : theme.panelBorder))
            .opacity(configuration.isPressed ? 0.8 : (enabled ? 1 : 0.5))
            .fixedSize()
    }
}

/// The screen for a tool that has none yet.
struct ComingLater: View {
    let title: String
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(spacing: 6) {
            Text(title).font(.system(size: 19, weight: .semibold)).foregroundStyle(theme.text)
            Text("Coming in a later update").foregroundStyle(theme.textMuted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// The free plan's refusal (Task 8 shows the Pro sheet instead).
@MainActor @Observable
final class UpgradePrompt {
    static let itemLimitMessage = String(localized: "The free plan holds 4 items. Upgrade to Pro to add more.")
    static let twoFactorMessage = String(localized: "Adding or changing a 2FA code needs Pro.")
    /// Windows `PRO_REQUIRED`, "this Mac" for "this PC".
    static let syncMessage = String(localized: "Device sync is part of LocalGateKeys Pro. Everything already on this Mac stays here and keeps working; with Pro, sync resumes where it left off.")
    var shown = false
    private(set) var reason: ProReason = .itemLimit
    var message: String { Self.message(reason) }
    static func message(_ reason: ProReason) -> String {
        switch reason {
        case .itemLimit: itemLimitMessage
        case .twoFactor: twoFactorMessage
        case .sync: syncMessage
        case .attachments: DocumentFiles.proMessage
        }
    }
    func show(_ reason: ProReason) { self.reason = reason; shown = true }
}

/// The sidebar's Generator: the generator in the main area, copy only.
struct GeneratorPage: View {
    @Environment(\.macTheme) private var theme
    var body: some View {
        VStack {
            GeneratorPopover()
                .background(theme.card.opacity(0.5), in: RoundedRectangle(cornerRadius: MacTheme.radiusCard, style: .continuous))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
