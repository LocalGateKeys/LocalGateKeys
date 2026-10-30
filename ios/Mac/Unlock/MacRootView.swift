import SwiftUI
import AppKit
import AppSharedMac

/// Builds the app's lock model: the vault in the app group container (Application Support when the group is
/// unavailable, e.g. an unsigned build), the system Keychain (sync slots in the app-only group) and the Touch ID item.
@MainActor
enum MacAppEnvironment {
    static func vaultDirectory() -> URL {
        #if DEBUG
        // Debug builds only: point the app at a throwaway vault (screenshots, manual checks).
        if let path = ProcessInfo.processInfo.environment["LGK_MAC_VAULT_DIR"], !path.isEmpty {
            return URL(fileURLWithPath: path, isDirectory: true)
        }
        #endif
        if let dir = try? AppGroup.vaultDirectory() { return dir }
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return support.appendingPathComponent("LocalGateKeys/Vault", isDirectory: true)
    }

    static func makeLockModel() -> MacLockModel {
        let vault = MacVault(directory: vaultDirectory(), keychain: MacSyncEnvironment.keychain,
                             biometric: SystemBiometricKeyStore(accessGroup: AppGroup.keychainAccessGroup))
        let model = MacLockModel(vault: vault, settings: .shared, events: MacSystemEvents())
        // Locking clears a copied secret, if the pasteboard still holds it; a pending strict-login release is
        // dropped by the window's gate (MainWindow) and verifyPassword refuses across a lock.
        model.onLock.append { MacClipboard.shared.clearIfOurs() }
        // Breach results are memory-only and dropped on lock; a running check is cancelled.
        security.clear(on: model)
        // Revealed recovery codes, hidden custom field values and previous passwords are hidden again.
        loginExtras.clear(on: model)
        // No vault (erased or never made) or a new one: reminder notifications of an old vault go.
        wireReminderReset(model: model) { await notifier.removeAll() }
        // AutoFill identities: published at unlock and after every commit; a new or missing vault removes them.
        let identities = MacIdentityPublisher(store: SystemCredentialIdentityStore(), settings: .shared)
        model.identities = identities
        wireReminderReset(model: model) { await identities.removeAll() }
        // Safari: the index follows every commit; the inbox is reviewed after each unlock (MainWindow).
        model.safariIndex = SafariIndexPublisher(keychain: safariKeychain)
        model.onLock.append { safari.locked() }
        // Sync: at unlock, every 5 minutes and 10 s after an edit; shut down (listener stopped) on lock.
        syncScheduler = MacSyncScheduler(lock: model, settings: .shared)
        syncScheduler?.hostingAllowed = { pro.isPro }   // hosting needs Pro; joining is free
        // Scheduled backups: at unlock, on wake and every 15 minutes while unlocked; the secret and the folders sit in
        // the app-only Keychain group (none in a build without it: scheduled backups are unavailable then).
        let schedule = BackupScheduleModel(keychain: MacSyncEnvironment.syncKeychain,
                                           secrets: { [weak model] in model?.scheduleSecrets }, passwords: model)
        backupSchedule = schedule
        backupScheduler = MacBackupScheduler.live(lock: model, model: schedule)
        lockState = model
        return model
    }

    /// Reminder notifications go when a vault is created over an old one, and at launch when there is no vault.
    static func wireReminderReset(model: MacLockModel, removeAll: @escaping () async -> Void) {
        model.onFreshVault.append { Task { await removeAll() } }
        if model.state == .noVault { Task { await removeAll() } }
    }

    /// The Security centre's breach results and running check, for the whole app (cleared on lock).
    static let security = SecurityModel(settings: .shared, transport: URLSessionBreachTransport(),
                                        appVersion: SecurityModel.bundleVersion,
                                        isUnlocked: { lockState?.state == .unlocked })
    /// What the login detail has revealed (hidden on lock and on selection change).
    static let loginExtras = LoginExtrasModel()
    /// The sync schedule for the whole app (one coordinator and Wi-Fi host per unlock).
    static var syncScheduler: MacSyncScheduler?
    /// Scheduled backups for the whole app (settings, status and the runner).
    static var backupSchedule: BackupScheduleModel?
    static var backupScheduler: MacBackupScheduler?
    /// The lock model the Security centre checks before any request.
    nonisolated(unsafe) static weak var lockState: MacLockModel?

    /// The Safari save keys: their own Keychain group when it is usable (signed builds), else the default one.
    static let safariKeychain: any KeychainVault = SafariKeys.appVault(base: SystemKeychainVault())
    /// The Safari inbox import at unlock (review sheet in the main window).
    static let safari = MacSafariImport(keychain: safariKeychain)

    /// Pro for the whole app (window, Settings and the upgrade sheet share one purchase state).
    static let pro = ProModel(purchases: StoreKitPurchases(), claimer: WorkerLicenceClaim(),
                              claimFlags: LicenceClaimFlags(defaults: .standard))
    /// Apple Passwords export tokens (Credential Exchange), held until the vault is unlocked.
    static let credentialExchange = MacCredentialExchangeInbox()
    /// Shared items (`.lgkshare`) opened from Finder or AirDrop, held in private storage until opened.
    static let shareInbox = ShareInbox()
    /// Reminder notifications through the real notification centre (scheduling starts at the first unlock).
    static let notifier = ReminderNotifier(centre: SystemNotificationCentre(), settings: .shared)

    static var touchIDAvailable: Bool { SystemBiometricKeyStore(accessGroup: AppGroup.keychainAccessGroup).isAvailable }
}

/// Switches between the create, lock and unlocked screens; any key or mouse event in the app counts as activity.
struct MacRootView: View {
    @Bindable var model: MacLockModel
    @State private var monitor: Any?

    var body: some View {
        Group {
            #if DEBUG
            if let preview = MacShellPreview.store {
                MainWindow(store: preview, passwords: MacShellPreview.passwords,
                           reminders: MacShellPreview.local.localData?.reminders ?? [], local: MacShellPreview.local,
                           activity: ActivityRecorder(host: MacShellPreview.local), isUnlocked: { true }, autoLockRemaining: { 14 * 60 + 15 }, onLock: {})
            } else {
                screen
            }
            #else
            screen
            #endif
        }
        .preferredColorScheme(colorScheme)
        .macThemed()
        .onAppear { QuickAccessBridge.shared.openWindows += 1 }
        .onDisappear { QuickAccessBridge.shared.openWindows -= 1 }
        // A .lgkshare file opened from Finder or AirDrop: kept until the window is unlocked. Store builds take
        // no licence links or keys (Pro comes from the App Store or a licence state received by sync).
        .onOpenURL { url in _ = MacAppEnvironment.shareInbox.deliver(fileURL: url) }
        // Apple Passwords › Export Data to Another App (macOS 26): the import waits for the unlocked window.
        .onContinueUserActivity(CredentialExchangeModel.activityType) { MacAppEnvironment.credentialExchange.receive($0) }
        // The open window takes the link instead of SwiftUI opening a second one.
        .handlesExternalEvents(preferring: ["*"], allowing: ["*"])
        .task {
            ShareOutbox.purge()   // shared-item files left by a crash while a Share sheet was open
            MacAppEnvironment.pro.startObserving(); await MacAppEnvironment.pro.refresh()
        }
        // A purchase, or a desktop licence received through sync: Wi-Fi hosting may start (or stop).
        .onChange(of: MacAppEnvironment.pro.isPro) { _, _ in MacAppEnvironment.syncScheduler?.proChanged() }
        .onAppear {
            monitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .rightMouseDown, .scrollWheel, .mouseMoved]) { event in
                MainActor.assumeIsolated { model.noteActivity() }
                return event
            }
        }
        .onDisappear { if let monitor { NSEvent.removeMonitor(monitor) } }
    }

    /// Settings › Appearance (debug builds: `LGK_MAC_APPEARANCE` wins, for screenshots).
    private var colorScheme: ColorScheme? {
        let chosen = AppSettings.shared.appearance.colorScheme
        #if DEBUG
        return MacShellPreview.scheme ?? chosen
        #else
        return chosen
        #endif
    }

    @ViewBuilder private var screen: some View {
        switch model.state {
        case .noVault: CreateVaultView(model: model, touchIDAvailable: MacAppEnvironment.touchIDAvailable)
                .frame(minWidth: 720, minHeight: 480)
        case .locked: UnlockView(model: model).frame(minWidth: 720, minHeight: 480)
        case .unlocked:
            if let store = model.store {
                MainWindow(store: store, passwords: model, strengthCache: model.strengthCache,
                           reminders: model.localData?.reminders ?? [], local: model, activity: model.activity, notifier: MacAppEnvironment.notifier,
                           safari: MacAppEnvironment.safari, sync: MacAppEnvironment.syncScheduler,
                           profile: model.desktopProfile, schedule: MacAppEnvironment.backupSchedule,
                           isUnlocked: { model.state == .unlocked },
                           autoLockRemaining: { model.autoLockRemaining }, onLock: { model.lock() })
                    .overlay(alignment: .top) {
                        VStack(spacing: 8) {
                            if let notice = model.localDataNotice {
                                HStack(spacing: 10) {
                                    Image(systemName: "exclamationmark.triangle")
                                    Text(notice).font(.callout)
                                    Button("OK") { model.localDataNotice = nil }
                                }
                                .padding(.horizontal, 14).padding(.vertical, 8)
                                .background(.regularMaterial, in: Capsule())
                            }
                            if let notice = model.recoveryNotice {
                                HStack(spacing: 10) {
                                    Image(systemName: "key")
                                    Text(notice).font(.callout).fixedSize(horizontal: false, vertical: true)
                                    Button("OK") { model.recoveryNotice = nil }
                                }
                                .padding(.horizontal, 14).padding(.vertical, 8)
                                .frame(maxWidth: 640)
                                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
                            }
                        }
                        .padding(.top, 44)
                    }
            }
        }
    }
}

#if DEBUG
/// Debug builds only: `LGK_MAC_SHELL_PREVIEW=1` opens the window shell on a throwaway in-memory-keyed vault
/// seeded with the demo items, without touching the real vault (screenshots).
@MainActor
enum MacShellPreview {
    /// `LGK_MAC_APPEARANCE=light|dark` forces the preview's colour scheme.
    static var scheme: ColorScheme? {
        switch ProcessInfo.processInfo.environment["LGK_MAC_APPEARANCE"] { case "light": .light; case "dark": .dark; default: nil }
    }

    /// Settings › Unlocking in the preview: a stand-in that accepts nothing.
    static let passwords: any MasterPasswordService = PreviewPasswords()

    private final class PreviewPasswords: MasterPasswordService {
        var hasVault: Bool { true }
        var isUnlocked: Bool { true }
        var touchIDAvailable: Bool { true }
        func changePassword(old: String, new: String) async throws { throw MacVaultError.wrongPassword(retryAfter: nil) }
        func setTouchID(_ on: Bool, password: String) async throws { throw MacVaultError.wrongPassword(retryAfter: nil) }
        func verifyPassword(_ password: String) async throws { throw MacVaultError.wrongPassword(retryAfter: nil) }
    }

    /// Recently deleted and activity in memory; `LGK_MAC_TRASH=<title>,<title>` deletes those demo items first.
    static let local: InMemoryLocalData = {
        let local = InMemoryLocalData()
        // `LGK_MAC_COLLECTIONS=1` adds the starter collections, puts demo items in Personal and Travel and tags them.
        if let store, ProcessInfo.processInfo.environment["LGK_MAC_COLLECTIONS"] == "1", var data = local.localData {
            data.ensureStarterCollections(now: Int64(Date().timeIntervalSince1970))
            let byName = Dictionary(uniqueKeysWithValues: data.collections.map { ($0.name, $0.id) })
            let plan: [(String, [String], [String])] = [
                ("Wi-Fi at home", ["Personal"], ["home", "network"]), ("Home Wi-Fi", ["Personal"], ["home"]),
                ("Door code", ["Personal"], ["home"]), ("Passport", ["Travel", "Personal"], ["documents"]),
                ("Driving licence", ["Travel"], ["documents"]),
            ]
            let items = VaultItem.items(from: (try? store.load()) ?? StoreSnapshot())
            for (title, names, tags) in plan {
                guard let item = items.first(where: { $0.title == title }) else { continue }
                data.memberships[item.id] = names.compactMap { byName[$0] }
                edit(title: title, in: store) { $0["tags"] = .array(tags.map(JSONValue.string)) }
            }
            try? local.commitLocalData(data)
        }
        // `LGK_MAC_REMINDERS=1` adds reminders to the first typed demo items (overdue, today, upcoming, snoozed).
        if let store, ProcessInfo.processInfo.environment["LGK_MAC_REMINDERS"] == "1", var data = local.localData {
            let typed = VaultItem.items(from: (try? store.load()) ?? StoreSnapshot()).filter(RemindersModel.canHaveReminder)
            let today = OverviewModel.dayNumber(OverviewModel.day(Date())) ?? 0
            func day(_ offset: Int) -> String {
                let c = ReminderNotifier.components(day: today + offset)
                return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
            }
            let plan: [(Int, Int, LocalData.Reminder.Status, String)] = [(-2, 0, .pending, ""), (0, 0, .pending, ""),
                                                                         (12, 3, .snoozed, day(10)), (40, 0, .pending, "")]
            for (item, p) in zip(typed, plan) {
                data.reminders.append(LocalData.Reminder(id: UUID().uuidString.lowercased(), itemID: item.id, dueDate: day(p.0),
                                                         leadDays: p.1, status: p.2, snoozeUntil: p.3))
            }
            try? local.commitLocalData(data)
        }
        guard let store, let titles = ProcessInfo.processInfo.environment["LGK_MAC_TRASH"] else { return local }
        let recorder = ActivityRecorder(host: local)
        recorder.record(.sessionUnlock)
        let trash = TrashModel(store: store, local: local, isPro: { true }, onNeedsPro: { _ in }, activity: recorder)
        let items = VaultItem.items(from: (try? store.load()) ?? StoreSnapshot())
        for title in titles.split(separator: ",") {
            if let item = items.first(where: { $0.title == String(title) }) {
                recorder.record(.credentialCopy, itemID: item.id, count: 1)
                try? trash.moveToTrash(id: item.id)
            }
        }
        return local
    }()

    static let store: (any ItemStore)? = {
        guard ProcessInfo.processInfo.environment["LGK_MAC_SHELL_PREVIEW"] == "1" else { return nil }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-shell-\(UUID().uuidString)", isDirectory: true)
        guard let store = try? LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault()) else { return nil }
        store.limitHints = nil
        try? DemoData.seed(into: store, now: Int64(Date().timeIntervalSince1970))
        // `LGK_MAC_STRICT=<title>` turns on "require master password" for that login.
        if let title = ProcessInfo.processInfo.environment["LGK_MAC_STRICT"] { makeStrict(title: title, in: store) }
        // `LGK_MAC_EXTRAS=<title>` gives that login recovery codes, custom fields and a password history.
        if let title = ProcessInfo.processInfo.environment["LGK_MAC_EXTRAS"] { addExtras(title: title, in: store) }
        return store
    }()

    private static func addExtras(title: String, in store: any ItemStore) {
        let now = Int64(Date().timeIntervalSince1970)
        edit(title: title, in: store) { record in
            record["recovery_codes"] = .array(["7F3K-92QD", "M4XP-0L8T", "QW2R-5YH6", "ZK81-UV4C"].map(JSONValue.string))
            record["custom_fields"] = .array([
                .object(["name": .string("Customer number"), "value": .string("40-118-2290"), "hidden": .bool(false)]),
                .object(["name": .string("Security answer"), "value": .string("blue harbour"), "hidden": .bool(true)]),
            ])
            record["password_history"] = .array([
                .object(["password": .string("demo-Pass-old-2"), "changed_at": .int(now - 40 * 86_400)]),
                .object(["password": .string("demo-Pass-old-1"), "changed_at": .int(now - 400 * 86_400)]),
            ])
        }
    }

    private static func makeStrict(title: String, in store: any ItemStore) {
        edit(title: title, in: store) { record in
            var policy = record["policy"]?.objectValue ?? [:]
            policy["require_master_password"] = .bool(true)
            record["policy"] = .object(policy)
        }
    }

    private static func edit(title: String, in store: any ItemStore, _ change: (inout [String: JSONValue]) -> Void) {
        guard var snap = try? store.load() else { return }
        for (id, w) in snap.records {
            guard case .object(var wrapper) = w, case .string(let nsRaw)? = wrapper["ns"], let ns = Namespace(rawValue: nsRaw),
                  case .object(var record)? = wrapper["record"], VaultItem(id: id, record: record)?.title == title else { continue }
            change(&record)
            guard let normal = try? Normalise.normalForm(ns: ns, record: .object(record)) else { return }
            wrapper = Wrapper.make(ns: ns, record: normal).objectValue ?? wrapper
            snap.records[id] = .object(wrapper)
        }
        try? store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
    }
}
#endif
