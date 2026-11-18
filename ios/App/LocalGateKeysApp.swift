import SwiftUI
import AppShared

@main
struct LocalGateKeysApp: App {
    /// Refuses third-party keyboards (`AppDelegate`).
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var lock: AppLockModel
    /// Idle-lock activity for the whole window (sheets and typing included), never competing for touches.
    @State private var activity: ActivityMonitor
    /// The app-switcher cover, in its own window so it also hides presented sheets.
    @State private var cover = PrivacyCoverController.live()
    @State private var pro = ProModel(purchases: StoreKitPurchases(), claimer: WorkerLicenceClaim(),
                                      claimFlags: LicenceClaimFlags(defaults: .standard))
    @State private var safariImport = SafariImportModel()
    /// A Credential Exchange token, kept in memory until the vault is unlocked.
    @State private var credentialExchange = CredentialExchangeModel()
    /// Shared items (`.lgkshare`) received from AirDrop or Files, kept in private storage until opened.
    @State private var shareInbox = ShareInbox()
    private let settings = AppSettings.shared
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // Audit 2026-11-10: the Safari extension's files live in its own app group; an earlier build's inbox and index
        // move there, and the duress and erase flags it reads are mirrored (before anything reads them).
        SafariGroupMigration.runAtLaunch()
        let lock = AppLockModel(unlocker: SystemUnlocker(), clock: SystemClock(), scheduler: DispatchLockScheduler(),
                                settings: .shared, clipboard: .shared, eraser: VaultEraser.live(),
                                factors: LivePhoneFactorSource())
        VaultExporter.removeLeftoverExports()
        ShareOutbox.purge()   // shared-item files left by a crash while the Share sheet was open
        AttachmentFiles.purgeOpenCopies()   // clear copies of attached files left by a crash during a preview
        _lock = State(initialValue: lock)
        AppPasswordGate.lock = lock   // the owner checks ask for the app password while it is on
        _activity = State(initialValue: ActivityMonitor { lock.noteActivity() })
    }

    var body: some Scene {
        WindowGroup {
            RootView(lock: lock, pro: pro, safariImport: safariImport, credentialExchange: credentialExchange)
                .background(ActivityWindowReader(monitor: activity))
                .tint(Palette.accent)
                .preferredColorScheme(settings.appearance.colorScheme)
                // Privacy cover for the app-switcher snapshot: never shows a revealed secret. The window cover
                // sits above sheets; this overlay is the fallback should no window scene be available.
                .overlay { if scenePhase != .active { PrivacyCover() } }
                .task { pro.startObserving(); await pro.refresh() }
                // Passwords app > Export Data to Another App: imported once the vault is unlocked.
                .onContinueUserActivity(CredentialExchangeModel.activityType) { credentialExchange.received($0) }
                // A .lgkshare file from AirDrop or Files: moved into private storage, opened after unlock.
                // A codes widget tap: the Vault tab's Codes row (after the unlock).
                .onOpenURL { url in
                    if CodesTimeline.isOpenURL(url) { CodesLinkRoute.shared.pending = true }
                    // A 2FA setup link (Camera, Safari, "Set Up Codes In"): opened in the scan flow after the unlock.
                    else if TwoFactorLinkRoute.isTwoFactorLink(url) {
                        TwoFactorLinkRoute.shared.deliver(url)
                        if lock.settledUnlocked { TwoFactorLinkRoute.shared.release() }
                    }
                    else { shareInbox.deliver(fileURL: url) }
                }
                .environment(\.shareInbox, shareInbox)
                // Apple Watch codes (UX workstream 12): "Forget on watch" when the vault locks, and at launch (the
                // vault starts locked; a lock the app was killed before processing still empties the widgets).
                .onChange(of: lock.state, initial: true) { _, state in if state == .locked { WatchCodes.shared.vaultLocked() } }
                // A 2FA setup link waits for the unlock (and the foreground lock check) before the scan flow opens.
                .onChange(of: lock.state) { _, state in
                    if state == .locked { TwoFactorLinkRoute.shared.vaultLocked() }
                    else if lock.settledUnlocked { TwoFactorLinkRoute.shared.release() }
                }
                .onChange(of: lock.secondSession) { shareInbox.vaultChanged() }
                // Review M5: `secondSession` stays true across a lock, so a duress session opened again fires no change
                // above; every duress unlock clears what the inbox holds as well.
                .onChange(of: lock.state) { _, state in if state == .unlocked, lock.secondSession { shareInbox.vaultChanged() } }
                .onChange(of: scenePhase, initial: true) { _, phase in
                    cover.sceneChanged(phase)
                    switch phase {
                    case .background:
                        lock.didEnterBackground()
                        // Widgets: with "Forget on lock", no code shows once the vault would have auto-locked.
                        WatchCodes.shared.didEnterBackground(lockDeadline: lock.backgroundLockDeadline)
                    case .active:
                        ScreenCaptureMonitor.shared.refresh()   // a recording may have started meanwhile
                        // Prompts only at launch and after the background (a launch-time .task could fire in
                        // the background), never when the Face ID sheet itself toggles inactive -> active.
                        Task {
                            let wasUnlocked = lock.state == .unlocked
                            await lock.sceneBecameActive()
                            // Back from Safari while still unlocked (not locked by the delay just checked):
                            // ask about what it saved. An unlock asks on its own (UnlockedRoot), and until that
                            // first review has finished (Pro re-read) this call is ignored.
                            if wasUnlocked, lock.state == .unlocked { safariImport.foregrounded() }
                            if lock.state == .unlocked { WatchCodes.shared.foregroundedUnlocked() }
                            if lock.settledUnlocked { TwoFactorLinkRoute.shared.release() }
                        }
                    default: break
                    }
                }
        }
    }
}

struct RootView: View {
    let lock: AppLockModel
    let pro: ProModel
    let safariImport: SafariImportModel
    let credentialExchange: CredentialExchangeModel

    var body: some View {
        if lock.state == .unlocked, let store = lock.store, let keychain = lock.keychain {
            UnlockedRoot(store: store, keychain: keychain, pro: pro, lock: lock, safariImport: safariImport,
                         credentialExchange: credentialExchange)
        } else {
            UnlockView(model: lock)
        }
    }
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Palette.background.ignoresSafeArea()
            Image("BrandMark").resizable().aspectRatio(contentMode: .fit).frame(width: 96, height: 96)
        }
    }
}

/// Everything shown while unlocked. Owns the sync coordinator for this unlock: unlocking is "app open",
/// so the first sync starts here; locking drops it with the store.
struct UnlockedRoot: View {
    let store: any ItemStore
    let keychain: any KeychainVault
    let pro: ProModel
    let lock: AppLockModel
    let safariImport: SafariImportModel
    let credentialExchange: CredentialExchangeModel
    /// Built once per unlock (not on every RootView evaluation); shut down when the vault locks.
    @State private var sync: SyncCoordinator?
    /// Task 6: this unlock's unsaved-draft file, the draft offered after the unlock and the one being continued.
    @State private var drafts: EditorDraftStore?
    @State private var draftOffer: DraftOffer?
    @State private var continuing: DraftOffer?
    /// Sub-plan 08: emergency access requests to announce (owner's devices).
    @State private var heirNotice: [String] = []
    /// Wi-Fi host mode for this unlock (spec 2026-11-13-phone-wifi-host-design): listens only while the scene is
    /// active, the vault unlocked and the setting on; shut down with the coordinator.
    @State private var wifiHost: PhoneWiFiHost?
    @State private var wasInBackground = false
    @Environment(\.shareInbox) private var shareInbox
    @Environment(\.scenePhase) private var scenePhase

    struct DraftOffer: Identifiable {
        let id = UUID()
        let draft: EditorDraft
        let status: EditorDraft.Status
        let item: VaultItem?
    }

    var body: some View {
        Group {
            if let sync {
                RootTabs(model: VaultListModel(store: store), store: store, pro: pro, sync: sync, lock: lock, wifiHost: wifiHost)
                    .modifier(ForcedCompactWidth())
                    .environment(\.editorDrafts, drafts)
                    // Once after a recovery-phrase reset dropped the key file / YubiKey.
                    .alert(lock.unlockNotice ?? "", isPresented: Binding(get: { lock.unlockNotice != nil },
                                                                       set: { if !$0 { lock.dismissUnlockNotice() } })) {
                        Button("OK") { lock.dismissUnlockNotice() }
                    }
                    .task {
                        offerDraft()
                        // Sub-plan 08: a duress session never reads what Safari saved (that is the real vault's).
                        guard !lock.secondSession else { return }
                        // Lists the logins saved from Safari; the sheet below asks before any is imported.
                        await safariImport.afterUnlock(store: store, keychain: keychain, pro: pro,
                                                       isUnlocked: { lock.state == .unlocked })
                        // Republish the AutoFill suggestions on each unlock too, so a changed default (or a
                        // vault that never syncs) still reaches Safari's QuickType bar.
                        sync.refreshIdentities()
                        await sync.sync(.appOpen)
                        let access = EmergencyAccess.live(store: store, sync: sync)
                        heirNotice = await Task.detached(priority: .utility) { HeirNotices.shared.check(access) }.value
                    }
                    .onChange(of: safariImport.foregroundRuns) {
                        guard lock.state == .unlocked, !lock.secondSession else { return }
                        safariImport.review(store: store, keychain: keychain)
                    }
                    // Audit 2026-10-24 L-18: nothing saved in Safari reaches the vault without a yes here.
                    .sheet(isPresented: Binding(get: { !safariImport.pending.isEmpty && lock.state == .unlocked && !lock.secondSession },
                                                set: { if !$0 { safariImport.later() } })) {
                        SafariReviewSheet(pending: safariImport.pending, onSave: { approved in
                            guard lock.state == .unlocked else { return safariImport.later() }
                            if let result = safariImport.confirm(approved, store: store, keychain: keychain, isPro: pro.isPro),
                               result.saved > 0 {
                                sync.noteLocalEdit()   // the list reloads when that sync completes
                            }
                        }, onLater: { safariImport.later() })
                    }
                    // Credential Exchange: runs on unlock, or at once when the token arrives while unlocked.
                    // The data is read into a review; nothing is written before Import there (scan A10-L1).
                    // A duress session drops the token unread and shows nothing (the export is the real vault's).
                    .onChange(of: credentialExchange.pendingToken, initial: true) { _, token in
                        guard token != nil, lock.state == .unlocked else { return }
                        startCredentialExchange()
                    }
                    .onChange(of: credentialExchange.isRunning) { _, running in
                        // A token that arrived during a run starts its own run afterwards.
                        guard !running, credentialExchange.pendingToken != nil, lock.state == .unlocked else { return }
                        startCredentialExchange()
                    }
                    .alert(CredentialExchangeText.reviewTitle,
                           isPresented: Binding(get: { credentialExchange.review != nil && lock.state == .unlocked && !lock.secondSession },
                                                set: { if !$0 { credentialExchange.discard(); startCredentialExchange() } }),
                           presenting: credentialExchange.review) { _ in
                        Button(CredentialExchangeText.importLabel) {
                            credentialExchange.confirm(importer: credentialExchangeImporter())
                            startCredentialExchange()
                        }
                        Button("Cancel", role: .cancel) { credentialExchange.discard(); startCredentialExchange() }
                    } message: { review in
                        Text(CredentialExchangeText.reviewMessage(added: review.counts.added, changed: review.counts.updated))
                    }
                    .alert(EditorDraftText.title, isPresented: Binding(get: { draftOffer != nil && lock.state == .unlocked },
                                                                        set: { if !$0 { draftOffer = nil } }),
                           presenting: draftOffer) { offer in
                        Button(EditorDraftText.continueLabel) { draftOffer = nil; continuing = offer }
                        Button(EditorDraftText.discardLabel, role: .destructive) { draftOffer = nil; drafts?.delete() }
                    } message: { offer in
                        Text(EditorDraftText.message(offer.status, kind: offer.draft.kind))
                    }
                    .sheet(item: $continuing) { offer in
                        // The same item when it is unchanged; otherwise the values continue as a new item.
                        let model = EditorModel(store: store, pro: pro, editing: offer.status == .sameItem ? offer.item : nil,
                                                kind: offer.draft.kind, clock: SystemClock(), random: SystemRandomSource(),
                                                keepsPasswordHistory: true)
                        let _ = model.restore(offer.draft.values)
                        EditorView(model: model, pro: pro) { result in
                            if result == .saved { sync.noteLocalEdit() }
                        }
                        .environment(\.editorDrafts, drafts)
                    }
                    // Leave and Reset of the sync profile delete the draft too (joined -> not joined).
                    .onChange(of: sync.membership.joined) { was, now in
                        if was, !now { drafts?.delete() }
                    }
                    // A shared item that arrived (AirDrop, Files): asked for its code once the vault is unlocked.
                    // Closing it (Reject, swipe down) deletes the package; a refusal stays on screen until closed.
                    .sheet(isPresented: Binding(get: { (shareInbox?.pending != nil || shareInbox?.message != nil)
                                                       && lock.state == .unlocked },
                                                set: { if !$0 { shareInbox?.reject(); shareInbox?.clearMessage() } })) {
                        if let shareInbox {
                            ReceiveShareSheet(inbox: shareInbox, store: store, pro: pro, onSaved: {
                                sync.noteLocalEdit()
                                CopyToast.shared.show(ShareText.saved, for: .seconds(3))
                            })
                        }
                    }
                    // Sub-plan 08: new emergency access requests, once per app run (the owner's devices).
                    .alert(EmergencyAccessText.title, isPresented: Binding(get: { !heirNotice.isEmpty && lock.state == .unlocked },
                                                                           set: { if !$0 { heirNotice = [] } })) {
                        Button("OK") { heirNotice = [] }
                    } message: {
                        Text(heirNotice.joined(separator: "\n\n"))
                    }
                    .alert("Import from Apple Passwords",
                           isPresented: Binding(get: { credentialExchange.message != nil && lock.state == .unlocked },
                                                set: { if !$0 { credentialExchange.message = nil } })) {
                        Button("OK") { credentialExchange.message = nil }
                    } message: {
                        Text(credentialExchange.message ?? "")
                    }
            } else {
                AuroraBackground()
            }
        }
        .onAppear {
            #if DEBUG
            if sync == nil, DemoData.requestedAtLaunch { try? DemoData.seed(into: store, now: SystemClock().now) }
            #endif
            // Received shared items: verified revoke notices in the sync folder (best effort; never in the duress
            // password's vault, which does not sync).
            if !lock.secondSession, let dir = try? AppGroup.vaultDirectory() {
                shareInbox?.revokedIDs = { [keychain] in
                    ShareRevokedReader.read(watchURL: SyncDependencies.watchFileURL(in: dir), keychain: keychain)
                }
            } else {
                shareInbox?.revokedIDs = { [] }
            }
            if sync == nil {
                var deps = SyncDependencies.live(keychain: keychain)
                deps.inert = lock.secondSession   // sub-plan 08: the duress password's vault never syncs
                deps.autoSync = { AppSettings.shared.autoSync }
                if lock.secondSession { deps.attachmentBlobs = nil; deps.watchFile = nil }
                // Feature pack §2 and §4: travel-hidden items and logins whose rules refuse autofill are not published.
                var identities = IdentityStoreSync(oneTimeCodes: IdentityStoreSync.platformOneTimeCodes)
                // Travel mode is read from this vault's local data file each time, so no unlock order can publish
                // a hidden item (the in-memory box covers a file that can't be read).
                identities.omit = { [store] snap in
                    // A file that is there but can't be read hides everything (scan 2026-11-15 S-L4).
                    let travel = (store as? LocalStore).map {
                        PhoneLocalDataFile.travel(for: $0, missing: TravelModeBox.shared.current)
                    } ?? TravelModeBox.shared.current
                    return AutoFillGate.omitted(snap, travel: travel, today: RecordDigest.today())
                }
                deps.autoFill = identities
                let coordinator = SyncCoordinator(store: store, deps: deps)
                // Shared collections are created, joined and synced only with Pro (sub-plan 07).
                coordinator.isPro = { [pro] in pro.isPro }
                // A verified removal notice: erase (setting on) after this run has finished, never from inside it.
                coordinator.onRemovalNotice = { [weak coordinator, lock = lock] in
                    guard AppSettings.shared.eraseOnSyncRemoval, let coordinator else { return }
                    Task {
                        await lock.eraseAfterRemoval { await coordinator.shutdownAndWait() }
                        WatchCodes.shared.vaultErased()   // the Apple Watch forgets its pinned 2FA secrets too
                    }
                }
                sync = coordinator
                // Wi-Fi host mode (never in the duress password's vault, which does not sync).
                if wifiHost == nil, !lock.secondSession {
                    let host = PhoneWiFiHost.live(store: store, coordinator: coordinator, lock: lock, pro: pro)
                    host?.setForeground(scenePhase == .active)
                    wifiHost = host
                }
            }
            pro.vaultUnlocked(store: store)   // an App Store purchase not yet claimed as a licence is claimed now
            // Travel mode (scan 2026-11-15 S-L3): read from this vault's local data file before the widgets' codes are
            // written, so a hidden code never shows between the unlock and the vault screen opening its local data.
            if let local = store as? LocalStore {
                TravelModeBox.shared.current = PhoneLocalDataFile.travel(for: local, missing: TravelModeBox.shared.current)
            }
            WatchCodes.shared.vaultUnlocked(store: store, isPro: pro.isPro)   // the widgets' pinned codes are written again
            if drafts == nil, let file = EditorDraftStore.location() {
                drafts = EditorDraftStore(file: file, keychain: { lock.state == .unlocked ? lock.keychain : nil })
            }
        }
        // Wi-Fi host mode: the background stops the listener (and closes its connections), the foreground starts it
        // again; `.inactive` (Control Centre, the Face ID sheet) changes nothing. Pro gained or lost re-reads the gating.
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .active:
                wifiHost?.setForeground(true)
                // Back from the background while still unlocked: sync again ("Sync automatically"). The Face ID sheet
                // and Control Centre only make the scene inactive, so they start nothing.
                if wasInBackground, lock.state == .unlocked, let sync { Task { await sync.sync(.foreground) } }
                wasInBackground = false
            case .background:
                wifiHost?.setForeground(false)
                wasInBackground = true
            default: break
            }
        }
        .onChange(of: pro.isPro) { wifiHost?.proChanged() }
        .onChange(of: lock.state) { _, state in if state != .unlocked { wifiHost?.shutdown() } }
        .onDisappear {
            pro.vaultLocked()
            wifiHost?.shutdown()
            sync?.shutdown()
            safariImport.locked()   // the next unlock's afterUnlock runs before any foreground import
        }
    }

    /// Once per unlock: a draft left from before is offered (expired or unreadable ones are deleted by `load`).
    private func offerDraft() {
        guard draftOffer == nil, continuing == nil, let draft = drafts?.load(),
              let snapshot = try? store.load() else { return }
        let items = VaultItem.items(from: snapshot)
        draftOffer = DraftOffer(draft: draft, status: draft.status(in: items),
                                item: items.first { $0.id == draft.itemID })
    }

    private func credentialExchangeImporter() -> VaultImporter {
        let importer = VaultImporter(store: store, isPro: { pro.isPro }, now: { Date() }, random: SystemRandomSource(),
                                     afterCommit: { sync?.noteLocalEdit() })
        // Kept for "Undo this import" in Settings › Import & Export (feature pack §6.1).
        importer.onJournal = { ImportExportModel.saveJournal($0, local: HistoryRecorder.shared.host) }
        return importer
    }

    /// Reads a pending Credential Exchange token into a review (unlocked, real vault only); a duress session
    /// drops it unread with no notice.
    private func startCredentialExchange() {
        guard credentialExchange.pendingToken != nil, lock.state == .unlocked else { return }
        if lock.secondSession { credentialExchange.dropPending(); return }
        credentialExchange.start(importer: credentialExchangeImporter())
    }
}

/// The question before a Credential Exchange import writes anything (scan A10-L1).
enum CredentialExchangeText {
    static let reviewTitle = String(localized: "Import passwords?")
    static let importLabel = String(localized: "Import")
    static func reviewMessage(added: Int, changed: Int) -> String {
        String(localized: "\(added) logins will be added and \(changed) existing logins will be changed (a changed password keeps the old one in its history).")
    }
}
