import AppKit
import Carbon.HIToolbox
import Observation
import ServiceManagement

/// The Windows tray, quick access hotkey and "Start with Windows", for the Mac: a menu bar icon, a global
/// shortcut (⌃⌥K, Windows' Ctrl+Alt+K) and a login item. Per device, never synced.
enum QuickAccessSettings {
    static let showMenuBarKey = "settings.mac.showMenuBarIcon"
    static let hotKeyKey = "settings.mac.quickAccessHotKey"
    /// The keys (Windows `quick_access_hotkey`, changed in Settings › Menu bar & startup); ⌃⌥K when never changed.
    static let hotKeyComboKey = "settings.mac.quickAccessHotKeyCombo"
    /// Shown in Settings and the shortcuts sheet.
    static var hotKeyLabel: String { HotKeyCombo.load().label }
}

/// A global shortcut: a key code and Carbon modifiers, with the key's name as shown.
struct HotKeyCombo: Codable, Equatable, Sendable {
    var keyCode: UInt32
    var modifiers: UInt32
    var key: String

    /// ⌃⌥K, Windows' Ctrl+Alt+K.
    static let standard = HotKeyCombo(keyCode: UInt32(kVK_ANSI_K), modifiers: UInt32(controlKey | optionKey), key: "K")

    /// "⌃⌥⇧⌘K", in the order macOS shows them.
    var label: String {
        var s = ""
        if modifiers & UInt32(controlKey) != 0 { s += "⌃" }
        if modifiers & UInt32(optionKey) != 0 { s += "⌥" }
        if modifiers & UInt32(shiftKey) != 0 { s += "⇧" }
        if modifiers & UInt32(cmdKey) != 0 { s += "⌘" }
        return s + key
    }

    /// Needs ⌃, ⌥ or ⌘ and a named key: ⇧ alone would take a typed character from every app (Windows asks for Ctrl,
    /// Alt or Win as well).
    var isValid: Bool {
        modifiers & UInt32(controlKey | optionKey | cmdKey) != 0 && !key.isEmpty
    }

    static func carbonModifiers(_ flags: NSEvent.ModifierFlags) -> UInt32 {
        var m: UInt32 = 0
        if flags.contains(.control) { m |= UInt32(controlKey) }
        if flags.contains(.option) { m |= UInt32(optionKey) }
        if flags.contains(.shift) { m |= UInt32(shiftKey) }
        if flags.contains(.command) { m |= UInt32(cmdKey) }
        return m
    }

    /// Keys named by their function, not the character they type.
    private static let namedKeys: [Int: String] = [
        kVK_Space: "Space", kVK_LeftArrow: "←", kVK_RightArrow: "→", kVK_UpArrow: "↑", kVK_DownArrow: "↓",
        kVK_F1: "F1", kVK_F2: "F2", kVK_F3: "F3", kVK_F4: "F4", kVK_F5: "F5", kVK_F6: "F6", kVK_F7: "F7",
        kVK_F8: "F8", kVK_F9: "F9", kVK_F10: "F10", kVK_F11: "F11", kVK_F12: "F12",
    ]
    /// Keys that can't be a shortcut (Escape cancels the recording).
    private static let refusedKeys: Set<Int> = [kVK_Escape, kVK_Return, kVK_Tab, kVK_Delete, kVK_ForwardDelete, kVK_ANSI_KeypadEnter]

    /// The name shown for a key: a letter, digit or punctuation key as typed (upper case), or a named key; nil for keys
    /// that can't be a shortcut.
    static func keyName(keyCode: Int, characters: String?) -> String? {
        if let name = namedKeys[keyCode] { return name }
        guard !refusedKeys.contains(keyCode), let c = characters, c.count == 1, let scalar = c.unicodeScalars.first,
              scalar.properties.isAlphabetic || scalar.properties.numericType != nil || ",./;'[]\\-=`".unicodeScalars.contains(scalar)
        else { return nil }
        return c.uppercased()
    }

    /// The combination a key press makes (nil when the key can't be a shortcut).
    init?(keyCode: Int, flags: NSEvent.ModifierFlags, characters: String?) {
        guard let name = Self.keyName(keyCode: keyCode, characters: characters) else { return nil }
        self.init(keyCode: UInt32(keyCode), modifiers: Self.carbonModifiers(flags), key: name)
    }

    init(keyCode: UInt32, modifiers: UInt32, key: String) {
        self.keyCode = keyCode; self.modifiers = modifiers; self.key = key
    }

    /// The saved combination; ⌃⌥K when none (or an unreadable or invalid one) is saved.
    static func load(_ defaults: UserDefaults = .standard) -> HotKeyCombo {
        guard let data = defaults.data(forKey: QuickAccessSettings.hotKeyComboKey),
              let combo = try? JSONDecoder().decode(HotKeyCombo.self, from: data), combo.isValid else { return .standard }
        return combo
    }

    /// Saves the combination (the standard one removes the saved value).
    func save(_ defaults: UserDefaults = .standard) {
        guard self != .standard, let data = try? JSONEncoder().encode(self) else {
            defaults.removeObject(forKey: QuickAccessSettings.hotKeyComboKey); return
        }
        defaults.set(data, forKey: QuickAccessSettings.hotKeyComboKey)
    }
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

    /// A main window page asked for from Settings (its Recovery centre, Licence, Show setup again, and Help's shortcuts and
    /// Devices & connections).
    enum Page: Equatable, Sendable { case recoveryCentre, licence, showSetup, shortcuts, connections }
    struct PageRequest: Equatable { let id = UUID(); let page: Page }
    /// The page waiting for the main window; it clears it once shown (kept while locked, shown after unlock).
    var pendingPage: PageRequest?

    func open(_ page: Page) { pendingPage = PageRequest(page: page) }

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

    /// The saved shortcut (⌃⌥K unless changed); returns false when another app already holds it.
    @discardableResult func register(_ combo: HotKeyCombo = .load()) -> Bool {
        guard ref == nil else { return true }
        if handler == nil {
            var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
            InstallEventHandler(GetApplicationEventTarget(), { _, _, _ in
                MainActor.assumeIsolated { GlobalHotKey.shared.onPress() }
                return noErr
            }, 1, &spec, nil, &handler)
        }
        let id = EventHotKeyID(signature: OSType(0x4C474B51), id: 1)   // 'LGKQ'
        let status = RegisterEventHotKey(combo.keyCode, combo.modifiers, id,
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
        if defaults.object(forKey: QuickAccessSettings.hotKeyKey) as? Bool ?? true { register(.load(defaults)) } else { unregister() }
    }

    /// Settings › Quick access shortcut: saves `combo` and registers it when the shortcut is on. When another app holds
    /// it, the previous combination is saved and registered again and false is returned.
    @discardableResult func change(to combo: HotKeyCombo, defaults: UserDefaults = .standard) -> Bool {
        guard combo.isValid else { return false }
        let previous = HotKeyCombo.load(defaults)
        unregister()
        combo.save(defaults)
        guard defaults.object(forKey: QuickAccessSettings.hotKeyKey) as? Bool ?? true else { return true }
        if register(combo) { return true }
        previous.save(defaults)
        register(previous)
        return false
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
