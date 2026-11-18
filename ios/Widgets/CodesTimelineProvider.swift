import Foundation
import WidgetKit
import AppShared

/// What the codes widget shows from `date` on.
struct CodesEntry: TimelineEntry {
    let date: Date
    let content: CodesWidgetEntry.Content
}

/// Sub-plan 06: the codes widget's timeline. It only reads what the app stored in `PinnedCodeStore`: the pin
/// list in the app group's defaults and the pinned codes in their own Keychain group (`LGKCodesKeychainGroup`,
/// readable only while the iPhone is unlocked). It never writes, migrates or deletes anything, and opens no
/// network connection. The app asks WidgetKit for a new timeline after every change to the store.
struct CodesTimelineProvider: TimelineProvider {
    /// The widget gallery and placeholders: a made-up code, never a real one.
    static let sample = CodesEntry(date: Date(timeIntervalSince1970: 0),
                                   content: .codes([CodesWidgetEntry.Code(title: "LocalGateKeys", code: "123456")]))
    /// How long a "Unlock iPhone" widget waits before it tries again (the Keychain opens when the iPhone does).
    static let lockedRetry: TimeInterval = 15 * 60

    func placeholder(in context: Context) -> CodesEntry {
        CodesEntry(date: Date(), content: Self.sample.content)
    }

    func getSnapshot(in context: Context, completion: @escaping (CodesEntry) -> Void) {
        let now = Date()
        if context.isPreview {
            completion(CodesEntry(date: now, content: Self.sample.content))
        } else {
            completion(Self.entries(now: now).first ?? CodesEntry(date: now, content: .empty))
        }
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<CodesEntry>) -> Void) {
        let now = Date()
        let entries = Self.entries(now: now)
        completion(Timeline(entries: entries, policy: Self.policy(for: entries, now: now)))
    }

    /// Codes: a new timeline after the last (codeless) entry. "Unlock iPhone": try again later. Nothing pinned or
    /// nothing to show: wait for the app, which reloads the widgets when it pins, unpins or unlocks.
    static func policy(for entries: [CodesEntry], now: Date) -> TimelineReloadPolicy {
        if entries.count > 1 { return .atEnd }
        if entries.first?.content == .phoneLocked { return .after(now.addingTimeInterval(lockedRetry)) }
        return .never
    }

    /// The timeline from the store, read fresh each time.
    static func entries(now: Date) -> [CodesEntry] {
        let defaults = UserDefaults(suiteName: AppGroup.identifier) ?? .standard
        let keychain: any KeychainAccess
        let system: SystemKeychainAccess?
        if let group = AppGroup.codesKeychainAccessGroup {
            let access = SystemKeychainAccess(accessGroup: group)
            system = access
            keychain = access
        } else {
            system = nil
            keychain = NoKeychainAccess()   // unsigned build: nothing to read
        }
        let store = PinnedCodeStore(defaults: defaults, keychain: keychain)
        let found = CodesTimeline.widgetEntries(store: store, now: now, phoneLocked: {
            system?.needsDeviceUnlock(key: PinnedCodeStore.secretsKey) ?? false
        })
        return found.map { CodesEntry(date: $0.date, content: $0.content) }
    }
}
