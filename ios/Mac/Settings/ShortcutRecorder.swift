import SwiftUI
import AppKit
import Carbon.HIToolbox
import AppSharedMac

/// Settings › Menu bar & startup › Quick access shortcut: shows the keys, and records new ones (Windows lets the
/// person type `quick_access_hotkey`). Click, then press the new shortcut; Escape cancels. The global shortcut is
/// off while recording, so pressing the current keys records them instead of opening Search Everything.
struct ShortcutRecorder: View {
    /// Shown under the row: a refused combination, or keys another app holds.
    @Binding var message: String?
    /// Called after a change was saved and registered.
    var onChange: () -> Void = {}
    @State private var combo = HotKeyCombo.load()
    @State private var recording = false
    @State private var monitor: Any?

    static let pressText = String(localized: "Press the new shortcut…")
    static let refusedText = String(localized: "Use Control, Option or Command with a key.")

    var body: some View {
        HStack(spacing: 6) {
            Button(recording ? Self.pressText : combo.label) { recording ? stop() : start() }
                .buttonStyle(PillButtonStyle(primary: recording))
                .accessibilityLabel(String(localized: "Quick access shortcut"))
            if !recording, combo != .standard {
                Button(String(localized: "Reset")) { apply(.standard) }.buttonStyle(PillButtonStyle(primary: false))
            }
        }
        .onDisappear { stop() }
    }

    private func start() {
        message = nil
        recording = true
        GlobalHotKey.shared.unregister()
        monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            MainActor.assumeIsolated { record(event) }
            return nil
        }
    }

    private func stop() {
        if let monitor { NSEvent.removeMonitor(monitor) }
        monitor = nil
        guard recording else { return }
        recording = false
        GlobalHotKey.shared.apply()
    }

    private func record(_ event: NSEvent) {
        if Int(event.keyCode) == kVK_Escape { stop(); return }
        let flags = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
        guard let new = HotKeyCombo(keyCode: Int(event.keyCode), flags: flags,
                                    characters: event.characters(byApplyingModifiers: [])), new.isValid else {
            message = Self.refusedText
            return
        }
        if let monitor { NSEvent.removeMonitor(monitor) }
        monitor = nil
        recording = false
        apply(new)
    }

    private func apply(_ new: HotKeyCombo) {
        // The shortcut is the real vault's setting: a duress session (sub-plan 08) changes nothing.
        if DuressSession.shared.isOpen {
            message = MacDuressText.generic
        } else if GlobalHotKey.shared.change(to: new) {
            message = nil
        } else {
            message = String(localized: "Another app already uses \(new.label).")
        }
        combo = HotKeyCombo.load()
        onChange()
    }
}
