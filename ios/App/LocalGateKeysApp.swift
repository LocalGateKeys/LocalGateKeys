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
        let lock = AppLockModel(unlocker: SystemUnlocker(), clock: SystemClock(), scheduler: DispatchLockScheduler(),
                                settings: .shared, clipboard: .shared, eraser: VaultEraser.live())
        VaultExporter.removeLeftoverExports()
        ShareOutbox.purge()   // shared-item files left by a crash while the Share sheet was open
        AttachmentFiles.purgeOpenCopies()   // clear copies of attached files left by a crash during a preview
        _lock = State(initialValue: lock)
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
                .onOpenURL { shareInbox.deliver(fileURL: $0) }
                .environment(\.shareInbox, shareInbox)
                // Apple Watch codes (UX workstream 12): "Forget on watch" when the vault locks.
                .onChange(of: lock.state) { _, state in if state == .locked { WatchCodes.shared.vaultLocked() } }
                .onChange(of: scenePhase, initial: true) { _, phase in
                    cover.sceneChanged(phase)
                    switch phase {
                    case .background: lock.didEnterBackground()
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
    @Environment(\.shareInbox) private var shareInbox

    struct DraftOffer: Identifiable {
        let id = UUID()
        let draft: EditorDraft
        let status: EditorDraft.Status
        let item: VaultItem?
    }

    var body: some View {
        Group {
            if let sync {
                RootTabs(model: VaultListModel(store: store), store: store, pro: pro, sync: sync, lock: lock)
                    .environment(\.editorDrafts, drafts)
                    .task {
                        offerDraft()
                        // Lists the logins saved from Safari; the sheet below asks before any is imported.
                        await safariImport.afterUnlock(store: store, keychain: keychain, pro: pro,
                                                       isUnlocked: { lock.state == .unlocked })
                        // Republish the AutoFill suggestions on each unlock too, so a changed default (or a
                        // vault that never syncs) still reaches Safari's QuickType bar.
                        sync.refreshIdentities()
                        await sync.sync(.appOpen)
                    }
                    .onChange(of: safariImport.foregroundRuns) {
                        guard lock.state == .unlocked else { return }
                        safariImport.review(store: store, keychain: keychain)
                    }
                    // Audit 2026-10-24 L-18: nothing saved in Safari reaches the vault without a yes here.
                    .sheet(isPresented: Binding(get: { !safariImport.pending.isEmpty && lock.state == .unlocked },
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
                    .onChange(of: credentialExchange.pendingToken, initial: true) { _, token in
                        guard token != nil, lock.state == .unlocked else { return }
                        credentialExchange.start(importer: VaultImporter(
                            store: store, isPro: { pro.isPro }, now: { Date() }, random: SystemRandomSource(),
                            afterCommit: { sync.noteLocalEdit() }))
                    }
                    .onChange(of: credentialExchange.isRunning) { _, running in
                        // A token that arrived during a run starts its own run afterwards.
                        guard !running, credentialExchange.pendingToken != nil, lock.state == .unlocked else { return }
                        credentialExchange.start(importer: VaultImporter(
                            store: store, isPro: { pro.isPro }, now: { Date() }, random: SystemRandomSource(),
                            afterCommit: { sync.noteLocalEdit() }))
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
            if sync == nil { sync = SyncCoordinator(store: store, deps: .live(keychain: keychain)) }
            pro.vaultUnlocked(store: store)   // an App Store purchase not yet claimed as a licence is claimed now
            if drafts == nil, let file = EditorDraftStore.location() {
                drafts = EditorDraftStore(file: file, keychain: { lock.state == .unlocked ? lock.keychain : nil })
            }
        }
        .onDisappear {
            pro.vaultLocked()
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
}
