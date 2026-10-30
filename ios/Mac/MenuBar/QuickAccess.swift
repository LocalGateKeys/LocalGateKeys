import AppKit
import Carbon.HIToolbox
import Observation
import ServiceManagement

/// The Windows tray, quick access hotkey and "Start with Windows", for the Mac: a menu bar icon, a global
/// shortcut (⌃⌥K, Windows' Ctrl+Alt+K) and a login item. Per device, never synced.
enum QuickAccessSettings {
    static let showMenuBarKey = "settings.mac.showMenuBarIcon"
    static let hotKeyKey = "settings.mac.quickAccessHotKey"
    /// Shown in Settings and the shortcuts sheet.
    static let hotKeyLabel = "⌃⌥K"
}

/// Hands the menu bar's requests to the main window, which owns the strict-item gate, the clipboard and the
/// activity log, so a copy from the menu bar goes through the same checks as one from the item list.
@MainActor @Observable
final class QuickAccessBridge {
    enum Copy: Equatable { case username, password, code }
    struct Request: Equatable { let id = UUID(); let itemID: String; let copy: Copy }

    static let shared = QuickAccessBridge()

    /// The copy waiting for the main window; it clears it once handled.
    var pending: Request?
    /// Bumped by the global shortcut: the main window opens Search Everything.
    private(set) var paletteRequests = 0
    /// Main windows on screen; the menu bar opens one when none is.
    var openWindows = 0

    func copy(_ itemID: String, _ copy: Copy) { pending = Request(itemID: itemID, copy: copy) }

    func requestPalette() { paletteRequests += 1 }

    /// Brings the app forward (the gate's master password sheet, the unlock screen, the palette).
    static func activate() { NSApp.activate(ignoringOtherApps: true) }
}

/// A system-wide shortcut through Carbon's RegisterEventHotKey: no Accessibility permission, and the key is
/// never seen by other apps while registered.
@MainActor
final class GlobalHotKey {
    static let shared = GlobalHotKey()

    private var ref: EventHotKeyRef?
    private var handler: EventHandlerRef?
    var onPress: () -> Void = {}

    var isRegistered: Bool { ref != nil }

    /// ⌃⌥K; returns false when another app already holds it.
    @discardableResult func register() -> Bool {
        guard ref == nil else { return true }
        if handler == nil {
            var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
            InstallEventHandler(GetApplicationEventTarget(), { _, _, _ in
                MainActor.assumeIsolated { GlobalHotKey.shared.onPress() }
                return noErr
            }, 1, &spec, nil, &handler)
        }
        let id = EventHotKeyID(signature: OSType(0x4C474B51), id: 1)   // 'LGKQ'
        let status = RegisterEventHotKey(UInt32(kVK_ANSI_K), UInt32(controlKey | optionKey), id,
                                         GetApplicationEventTarget(), 0, &ref)
        if status != noErr { ref = nil }
        return ref != nil
    }

    func unregister() {
        if let ref { UnregisterEventHotKey(ref) }
        ref = nil
    }

    /// Applies the saved choice (default on).
    func apply(_ defaults: UserDefaults = .standard) {
        if defaults.object(forKey: QuickAccessSettings.hotKeyKey) as? Bool ?? true { register() } else { unregister() }
    }
}

/// Open at login (SMAppService, macOS 13+): the app itself is the login item, listed in System Settings ›
/// General › Login Items where it can also be turned off.
enum LoginItem {
    static var isOn: Bool { SMAppService.mainApp.status == .enabled }
    /// Turned on here but waiting for approval in System Settings.
    static var needsApproval: Bool { SMAppService.mainApp.status == .requiresApproval }

    /// Returns an error line for Settings, or nil.
    static func set(_ on: Bool) -> String? {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            return nil
        } catch {
            return on ? String(localized: "macOS didn't allow opening at login. Check System Settings › General › Login Items.")
                      : String(localized: "macOS didn't remove the login item. Turn it off in System Settings › General › Login Items.")
        }
    }
}
