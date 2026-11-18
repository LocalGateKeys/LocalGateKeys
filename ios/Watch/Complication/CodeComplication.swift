import SwiftUI
import WidgetKit
import LGKCore

/// Sub-plan 06 task 4: the Apple Watch complication. It shows the first pinned 2FA code and a ring for the
/// seconds left in its period. It only reads the watch app's own Keychain item (`KeychainWatchStore`, in the
/// watch's codes Keychain group, readable only while the watch is unlocked): no new sync channel, no network, no
/// write. Forget on lock, an unpin or an erase deletes that item, and the watch app then reloads the complication.
@main
struct CodeComplication: Widget {
    static let kind = "app.localgatekeys.watch.code"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: Self.kind, provider: CodeComplicationProvider()) { entry in
            CodeComplicationView(entry: entry)
        }
        .configurationDisplayName("Pinned codes")
        .description("Your pinned two-factor codes.")
        .supportedFamilies([.accessoryRectangular, .accessoryCircular])
    }
}

/// What the complication shows from `date` on.
struct CodeComplicationEntry: TimelineEntry, Sendable {
    enum Content: Equatable, Sendable {
        /// The first pinned code, valid until `span.end`.
        case code(CodeSpan)
        /// Nothing stored on the watch: nothing pinned, or forgotten on lock.
        case empty
        /// The watch is locked: its Keychain item cannot be read.
        case locked
        /// The end of a timeline (the last code ran out before WidgetKit reloaded): open the app.
        case openApp
    }

    let date: Date
    let content: Content
}

/// Reads the watch Keychain fresh on each call; never writes, moves or deletes anything.
struct CodeComplicationProvider: TimelineProvider {
    /// Code entries in one timeline: 30 minutes of 30-second codes (ruling). The code changes at each period
    /// boundary from these entries alone; the reload at the end (about 48 a day, plus each store change) bounds
    /// the future codes held in WidgetKit's cache, and how long a code can stay after a forget that is delayed, to
    /// 30 minutes (SECURITY.md, Apple Watch).
    static let entryCount = 60
    /// How long a "Unlock Apple Watch" complication waits before it tries again (at most 48 reloads in a day the
    /// watch spends locked; opening the app or any store change reloads it at once).
    static let lockedRetry: TimeInterval = 30 * 60

    /// The face gallery and placeholders: a made-up code, never a real one.
    static func sample(now: Date) -> CodeComplicationEntry {
        CodeComplicationEntry(date: now, content: .code(CodeSpan(
            date: now, periodStart: now, end: now.addingTimeInterval(30), title: "LocalGateKeys", code: "123456")))
    }

    func placeholder(in context: Context) -> CodeComplicationEntry {
        Self.sample(now: Date())
    }

    func getSnapshot(in context: Context, completion: @escaping (CodeComplicationEntry) -> Void) {
        let now = Date()
        if context.isPreview {
            completion(Self.sample(now: now))
        } else {
            completion(Self.entries(now: now).first ?? CodeComplicationEntry(date: now, content: .empty))
        }
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<CodeComplicationEntry>) -> Void) {
        let now = Date()
        let entries = Self.entries(now: now)
        completion(Timeline(entries: entries, policy: Self.policy(for: entries, now: now)))
    }

    /// Codes: a new timeline after the last (codeless) entry, 30 minutes on. Locked: try again later. Nothing
    /// stored: wait for the watch app, which reloads the complication whenever the stored codes change and when it
    /// is opened (reloads from the app in the foreground do not count against the budget).
    static func policy(for entries: [CodeComplicationEntry], now: Date) -> TimelineReloadPolicy {
        if entries.count > 1 { return .atEnd }
        if entries.first?.content == .locked { return .after(now.addingTimeInterval(lockedRetry)) }
        return .never
    }

    /// One entry per period of the first pinned code (from `CodesTimeline`), then a codeless entry where the last
    /// one runs out, so a late reload never leaves an expired code on the face.
    static func entries(now: Date, store: KeychainWatchStore = KeychainWatchStore()) -> [CodeComplicationEntry] {
        entries(now: now, read: store.codes(at: now))
    }

    /// The timeline for one Keychain read (tests pass the read directly).
    static func entries(now: Date, read: WatchKeychainRead) -> [CodeComplicationEntry] {
        switch read {
        case .locked:
            return [CodeComplicationEntry(date: now, content: .locked)]
        case .nothing:
            return [CodeComplicationEntry(date: now, content: .empty)]
        case .codes(let codes):
            guard let first = codes.first else { return [CodeComplicationEntry(date: now, content: .empty)] }
            let spans = CodesTimeline.spans(of: first, now: now, count: entryCount)
            guard let last = spans.last else { return [CodeComplicationEntry(date: now, content: .openApp)] }
            return spans.map { CodeComplicationEntry(date: $0.date, content: .code($0)) }
                + [CodeComplicationEntry(date: last.end, content: .openApp)]
        }
    }
}

struct CodeComplicationView: View {
    let entry: CodeComplicationEntry
    /// Tests render a family directly (WidgetKit's environment value cannot be set outside a widget).
    var familyOverride: WidgetFamily? = nil
    @Environment(\.widgetFamily) private var environmentFamily
    private var family: WidgetFamily { familyOverride ?? environmentFamily }
    /// Wrist down (Always On): the digits and the account are hidden, so a lowered wrist shows neither.
    @Environment(\.isLuminanceReduced) private var isLuminanceReduced
    /// `.privacy` while the system shows the redacted version (watch locked).
    @Environment(\.redactionReasons) private var redactionReasons

    /// The digits and the account are hidden (wrist down or redacted): VoiceOver then reads neither.
    private var isHidden: Bool { isLuminanceReduced || redactionReasons.contains(.privacy) }

    var body: some View {
        content
            .containerBackground(for: .widget) { Color.clear }
    }

    @ViewBuilder private var content: some View {
        switch entry.content {
        case .code(let span):
            if family == .accessoryCircular { circular(span) } else { rectangular(span) }
        case .empty:
            message("Pin a code in LocalGateKeys", systemImage: "pin")
        case .locked:
            message("Unlock Apple Watch to see codes", systemImage: "lock")
        case .openApp:
            message("Open LocalGateKeys to show codes", systemImage: "arrow.up.forward.app")
        }
    }

    private func rectangular(_ span: CodeSpan) -> some View {
        HStack(spacing: 6) {
            VStack(alignment: .leading, spacing: 0) {
                // Wrist down the account is hidden too ("2FA code"); locked, the system redacts it.
                Text(isLuminanceReduced || span.title.isEmpty ? String(localized: "2FA code") : span.title)
                    .font(.headline)
                    .lineLimit(1)
                    .widgetAccentable()
                    .privacySensitive()
                codeText(Self.grouped(span.code), font: .title2)
            }
            Spacer(minLength: 0)
            ring(span)
                .frame(width: 26, height: 26)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(spokenLabel(span))
    }

    private func circular(_ span: CodeSpan) -> some View {
        ZStack {
            AccessoryWidgetBackground()
            ring(span)
            // "745" over "690": six digits do not fit across the circle on one line.
            codeText(Self.halves(span.code), font: .system(.footnote, design: .rounded))
                .multilineTextAlignment(.center)
                .padding(6)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(spokenLabel(span))
    }

    /// The account and the digits one by one, or only "2FA code" while they are hidden.
    private func spokenLabel(_ span: CodeSpan) -> Text {
        if isHidden { return Text("2FA code") }
        return Text(verbatim: (span.title.isEmpty ? "" : span.title + ", ") + Self.spoken(span.code))
    }

    /// The seconds left in the code's period, animated by the system between timeline entries.
    private func ring(_ span: CodeSpan) -> some View {
        ProgressView(timerInterval: span.periodStart...span.end, countsDown: true,
                     label: { EmptyView() }, currentValueLabel: { EmptyView() })
            .progressViewStyle(.circular)
            .widgetAccentable()
    }

    /// The digits, privacy-sensitive (redacted by the system while the watch is locked) and hidden wrist down.
    /// VoiceOver uses the container's `spokenLabel(_:)`.
    private func codeText(_ shown: String, font: Font) -> some View {
        Text(verbatim: isLuminanceReduced ? Self.masked(shown) : shown)
            .font(font.monospacedDigit().weight(.semibold))
            .lineLimit(2)
            .minimumScaleFactor(0.5)
            .privacySensitive()
    }

    @ViewBuilder private func message(_ text: LocalizedStringKey, systemImage: String) -> some View {
        if family == .accessoryCircular {
            ZStack {
                AccessoryWidgetBackground()
                Image(systemName: systemImage)
                    .font(.title3)
                    .widgetAccentable()
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text(text))
        } else {
            HStack(spacing: 6) {
                Image(systemName: systemImage)
                    .font(.title3)
                    .widgetAccentable()
                Text(text)
                    .font(.footnote)
                    .lineLimit(3)
                    .minimumScaleFactor(0.8)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        }
    }

    /// "123456" as "123 456" (and "1234 5678").
    static func grouped(_ code: String) -> String { split(code, separator: " ") }

    /// "123456" as "123" over "456", for the circle.
    static func halves(_ code: String) -> String { split(code, separator: "\n") }

    private static func split(_ code: String, separator: String) -> String {
        guard code.count > 4 else { return code }
        let cut = code.index(code.startIndex, offsetBy: code.count / 2)
        return String(code[..<cut]) + separator + String(code[cut...])
    }

    /// Every digit as a dot, keeping the grouping ("••• •••").
    static func masked(_ shown: String) -> String {
        String(shown.map { $0.isNumber ? "•" : $0 })
    }

    /// The digits one by one for VoiceOver ("1 2 3 4 5 6").
    static func spoken(_ code: String) -> String {
        code.map { String($0) }.joined(separator: " ")
    }
}
