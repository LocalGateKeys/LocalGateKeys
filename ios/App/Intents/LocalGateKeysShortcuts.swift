import AppIntents

#if os(iOS)
/// Sub-plan 06: "Copy code" as an App Shortcut (Siri, Spotlight and the Shortcuts app) on the iPhone. Siri asks
/// which pinned code to copy. The phrase's translations are in App/Intents/AppShortcuts.xcstrings. The Mac app
/// pins no codes, so it offers no App Shortcut.
struct LocalGateKeysShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: CopyCodeIntent(),
                    phrases: ["Copy my \(.applicationName) code"],
                    shortTitle: "Copy code",
                    systemImageName: "number.square")
    }
}
#endif
