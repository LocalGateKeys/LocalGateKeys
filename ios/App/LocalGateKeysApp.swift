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
    @State private var pro = ProModel(purchases: StoreKitPurchases())
    @State private var safariImport = SafariImportModel()
    private let settings = AppSettings.shared
    @Environment(\.scenePhase) private var scenePhase

    init() {
        let lock = AppLockModel(unlocker: SystemUnlocker(), clock: SystemClock(), scheduler: DispatchLockScheduler(),
                                settings: .shared, clipboard: .shared, eraser: VaultEraser.live())
        _lock = State(initialValue: lock)
        _activity = State(initialValue: ActivityMonitor { lock.noteActivity() })
    }

    var body: some Scene {
        WindowGroup {
            RootView(lock: lock, pro: pro, safariImport: safariImport)
                .background(ActivityWindowReader(monitor: activity))
                .tint(Palette.accent)
                .preferredColorScheme(settings.appearance.colorScheme)
                // Privacy cover for the app-switcher snapshot: never shows a revealed secret. The window cover
                // sits above sheets; this overlay is the fallback should no window scene be available.
                .overlay { if scenePhase != .active { PrivacyCover() } }
                .task { pro.startObserving(); await pro.refresh() }
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

    var body: some View {
        if lock.state == .unlocked, let store = lock.store, let keychain = lock.keychain {
            UnlockedRoot(store: store, keychain: keychain, pro: pro, lock: lock, safariImport: safariImport)
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
    /// Built once per unlock (not on every RootView evaluation); shut down when the vault locks.
    @State private var sync: SyncCoordinator?

    var body: some View {
        Group {
            if let sync {
                RootTabs(model: VaultListModel(store: store), store: store, pro: pro, sync: sync, lock: lock)
                    .task {
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
            } else {
                AuroraBackground()
            }
        }
        .onAppear {
            #if DEBUG
            if sync == nil, DemoData.requestedAtLaunch { try? DemoData.seed(into: store, now: SystemClock().now) }
            #endif
            if sync == nil { sync = SyncCoordinator(store: store, deps: .live(keychain: keychain)) }
        }
        .onDisappear {
            sync?.shutdown()
            safariImport.locked()   // the next unlock's afterUnlock runs before any foreground import
        }
    }
}
