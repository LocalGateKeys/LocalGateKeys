import SwiftUI
import AppSharedMac

@main
struct LocalGateKeysMacApp: App {
    @State private var lock = MacAppEnvironment.makeLockModel()
    @AppStorage(QuickAccessSettings.showMenuBarKey) private var showMenuBarIcon = true

    init() {
        // Clear copies of attached files left by a crash during Quick Look (task 12).
        AttachmentFiles.purgeOpenCopies()
        // ⌃⌥K from any app: brings the window forward with Search Everything (the unlock screen while locked).
        GlobalHotKey.shared.onPress = {
            QuickAccessBridge.activate()
            QuickAccessBridge.shared.requestPalette()
        }
        GlobalHotKey.shared.apply()
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
            MacRootView(model: lock)
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(Self.defaultWindowSize)
        .windowResizability(.contentMinSize)
        .commands { MacCommands(lock: lock) }

        // ⌘, (LocalGateKeys › Settings…); the sidebar's Settings shows the same page in the window.
        Settings {
            MacSettingsWindow(lock: lock)
        }

        // The tray of the Windows app: search and copy without the window (Settings › Menu bar & startup).
        // Only Settings changes the choice: macOS writes `false` back when the menu bar has no room for the icon,
        // and taking that write re-inserts the icon in a loop (a core at 100 %).
        MenuBarExtra(MacAppInfo.displayName, systemImage: "key.viewfinder",
                     isInserted: Binding(get: { showMenuBarIcon }, set: { _ in })) {
            MenuBarPanel(lock: lock).macThemed()
        }
        .menuBarExtraStyle(.window)
    }
}
