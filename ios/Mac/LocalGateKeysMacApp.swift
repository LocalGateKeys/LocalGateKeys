import SwiftUI
import AppSharedMac

@main
struct LocalGateKeysMacApp: App {
    /// Receives the Passwords app's Export to App handoff (Credential Exchange).
    @NSApplicationDelegateAdaptor(MacAppDelegate.self) private var appDelegate
    /// The open profile and its lock model (rebuilt when another profile is chosen).
    @State private var session = MacProfileSession()
    private var lock: MacLockModel { session.lock }
    @AppStorage(QuickAccessSettings.showMenuBarKey) private var showMenuBarIcon = true

    init() {
        // The unlock throttle's high-water mark lives in the Keychain, outside the vault folder (PENDING: restoring
        // the folder reset the throttle); the AutoFill extension uses the same marks.
        UnlockThrottle.markStore = KeychainThrottleMarks(accessGroup: AppGroup.keychainAccessGroup)
        // Audit 2026-11-10: the Safari extension's files live in its own app group; an earlier build's inbox and index
        // (every profile's) move there, and the active profile and duress flags it reads are mirrored.
        SafariGroupMigration.runAtLaunch()
        // Clear copies of attached files left by a crash during Quick Look (task 12).
        AttachmentFiles.purgeOpenCopies()
        // Documents opened in other apps (Settings › Privacy): left by a crash, and deleted again at quit.
        MacDocumentOpen.startSweeping()
        // ⌃⌥K from any app: brings the window forward with Search Everything (the unlock screen while locked).
        GlobalHotKey.shared.onPress = {
            QuickAccessBridge.activate()
            QuickAccessBridge.shared.requestPalette()
        }
        GlobalHotKey.shared.apply()
        // Out of screenshots and screen sharing (Settings › Privacy); runs once NSApp exists.
        Task { @MainActor in CaptureProtection.shared.start() }
    }

    /// 1180×760; debug builds take `LGK_MAC_WINDOW_SIZE=WxH` (screenshots at the minimum size).
    static var defaultWindowSize: CGSize {
        #if DEBUG
        if let v = ProcessInfo.processInfo.environment["LGK_MAC_WINDOW_SIZE"]?.split(separator: "x").compactMap({ Double($0) }),
           v.count == 2 { return CGSize(width: v[0], height: v[1]) }
        #endif
        return CGSize(width: 1180, height: 760)
    }

    var body: some Scene {
        WindowGroup(MacAppInfo.displayName, id: MacAppInfo.mainWindowID) {
            MacRootView(model: lock, session: session)
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(Self.defaultWindowSize)
        .windowResizability(.contentMinSize)
        .commands { MacCommands(lock: lock, session: session) }

        // ⌘, (LocalGateKeys › Settings…); the sidebar's Settings shows the same page in the window.
        Settings {
            MacSettingsWindow(lock: lock)
        }

        // The tray of the Windows app: search and copy without the window (Settings › Menu bar & startup).
        // Only Settings changes the choice: macOS writes `false` back when the menu bar has no room for the icon,
        // and taking that write re-inserts the icon in a loop (a core at 100 %).
        // The icon shows at a glance whether the vault is open (a padlock while locked).
        MenuBarExtra(MacAppInfo.displayName, systemImage: lock.state == .unlocked ? "key.viewfinder" : "lock.fill",
                     isInserted: Binding(get: { showMenuBarIcon }, set: { _ in })) {
            MenuBarPanel(lock: lock).macThemed()
        }
        .menuBarExtraStyle(.window)
    }
}
