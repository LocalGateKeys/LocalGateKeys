import Foundation

/// Sub-plan 06: the timeline of the iPhone widgets that show the pinned 2FA codes, without WidgetKit (so it is
/// testable). An entry starts at `now` and at each period boundary of the codes after it, so a code is never
/// shown past its period. The widget's timeline ends with a codeless entry, so a widget whose reload is late
/// (WidgetKit budget) never keeps an expired code on screen.
public enum CodesTimeline {
    /// A widget tap opens the app here: the Vault tab, at its Codes row.
    public static let openURL = URL(string: "localgatekeys://codes")!
    /// Code entries in one widget timeline (10 minutes of 30-second codes), then a reload.
    public static let widgetEntryCount = 20

    /// True for the widgets' `openURL` (scheme and host only; anything else is not a widget tap).
    public static func isOpenURL(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "localgatekeys" && url.host?.lowercased() == "codes"
    }

    /// `count` entries from `now`: each entry's date and the codes (title and digits) valid from that date until
    /// the next entry. Codes with invalid parameters are left out; with no valid code there is one empty entry.
    public static func entries(from codes: [WatchCode], now: Date, count: Int) -> [(date: Date, codes: [(title: String, code: String)])] {
        let start = now.timeIntervalSince1970
        guard count > 0, start.isFinite, start >= 0, start < 1e15 else { return [] }
        var t = Int64(start.rounded(.down))
        let valid = codes.filter { $0.period > 0 && $0.current(at: t) != nil }
        var date = now
        var out: [(date: Date, codes: [(title: String, code: String)])] = []
        while out.count < count {
            let shown = valid.compactMap { (c: WatchCode) -> (title: String, code: String)? in
                guard let current = c.current(at: t) else { return nil }
                return (title: c.title, code: current.code)
            }
            out.append((date: date, codes: shown))
            guard let next = valid.map({ (t / Int64($0.period) + 1) * Int64($0.period) }).min() else { break }
            t = next
            date = Date(timeIntervalSince1970: TimeInterval(next))
        }
        return out
    }

    /// The Apple Watch complication's timeline for one code: `count` spans from `now`, each holding the digits
    /// valid from its `date` until its `end` (the code's next period boundary, where the next span starts), and the
    /// start of that period for the countdown ring. [] for an invalid code, a bad date or a count of 0.
    public static func spans(of code: WatchCode, now: Date, count: Int) -> [CodeSpan] {
        guard count > 0 else { return [] }
        let all = entries(from: [code], now: now, count: count + 1)
        var out: [CodeSpan] = []
        for (entry, next) in zip(all, all.dropFirst()) {
            guard let shown = entry.codes.first else { break }
            out.append(CodeSpan(date: entry.date, periodStart: next.date.addingTimeInterval(-TimeInterval(code.period)),
                                end: next.date, title: shown.title, code: shown.code))
        }
        return out
    }

    /// The widget's whole timeline from the pinned-code store (which it only reads):
    /// - nothing pinned: one `.empty` entry (an unpinned code is never shown, even if its secret is stale);
    /// - pins but no readable code: `.phoneLocked` when `phoneLocked()` (the Keychain item is readable only
    ///   while the iPhone is unlocked), else `.openApp` (forgotten on lock, or past `expiresAt`);
    /// - codes: `count` code entries, cut at `expiresAt`, then one `.openApp` entry where the last code
    ///   runs out (or at `expiresAt`).
    public static func widgetEntries(store: PinnedCodeStore, now: Date, count: Int = widgetEntryCount,
                                     phoneLocked: () -> Bool) -> [CodesWidgetEntry] {
        guard !store.pinnedIDs.isEmpty else { return [CodesWidgetEntry(date: now, content: .empty)] }
        let expiresAt = store.expiresAt
        let shown = store.codes(at: now)
        if shown.isEmpty {
            var content = CodesWidgetEntry.Content.openApp
            if let expiresAt, now >= expiresAt {
                content = .openApp
            } else if phoneLocked() {
                content = .phoneLocked
            }
            return [CodesWidgetEntry(date: now, content: content)]
        }
        let n = max(1, count)
        let all = entries(from: shown.map { $0.0 }, now: now, count: n + 1)
        var out: [CodesWidgetEntry] = []
        for e in all.prefix(n) {
            if let expiresAt, e.date >= expiresAt { break }
            let codes = e.codes.map { CodesWidgetEntry.Code(title: $0.title, code: $0.code) }
            out.append(CodesWidgetEntry(date: e.date, content: codes.isEmpty ? .openApp : .codes(codes)))
        }
        var end: Date? = all.count > n ? all[n].date : nil
        if let expiresAt { end = min(end ?? expiresAt, expiresAt) }
        if let end, end > (out.last?.date ?? now) { out.append(CodesWidgetEntry(date: end, content: .openApp)) }
        if out.isEmpty { out.append(CodesWidgetEntry(date: now, content: .openApp)) }
        return out
    }
}

/// One code of the Apple Watch complication: `code` is shown from `date` until `end`; its period began at
/// `periodStart` (at or before `date`), which the countdown ring starts from.
public struct CodeSpan: Equatable, Sendable {
    public let date: Date
    public let periodStart: Date
    public let end: Date
    public let title: String
    public let code: String

    public init(date: Date, periodStart: Date, end: Date, title: String, code: String) {
        self.date = date; self.periodStart = periodStart; self.end = end; self.title = title; self.code = code
    }
}

/// One entry of the codes widget's timeline.
public struct CodesWidgetEntry: Equatable, Sendable {
    public struct Code: Equatable, Sendable {
        public let title: String
        public let code: String
        public init(title: String, code: String) { self.title = title; self.code = code }
    }

    public enum Content: Equatable, Sendable {
        /// The pinned codes (at most `PinnedCodeStore.maxShown`), in pin order.
        case codes([Code])
        /// No code is pinned.
        case empty
        /// Codes are pinned, but the iPhone is locked (their Keychain item cannot be read).
        case phoneLocked
        /// Codes are pinned, but there is no current code to show (forgotten when the vault locked, hidden at
        /// the auto-lock deadline, or the timeline ran out): open the app.
        case openApp
    }

    public let date: Date
    public let content: Content

    public init(date: Date, content: Content) { self.date = date; self.content = content }
}
