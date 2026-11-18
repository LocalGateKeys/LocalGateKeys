import SwiftUI
import LGKCore

/// UX plan workstream 12: the Apple Watch app. A list of the 2FA codes pinned on the iPhone, generated on the
/// watch (they work with the phone away). Codes show inside this app and, from sub-plan 06, in its complication
/// (the first pinned code, read from the same Keychain item); no widget elsewhere, no notification. The watch's
/// wrist detection and passcode guard them (Keychain `WhenUnlockedThisDeviceOnly`); the list is also dropped
/// whenever the app is not active.
@main
struct LocalGateKeysWatchApp: App {
    @State private var list: WatchCodesList
    private let receiver: WatchSessionReceiver
    @Environment(\.scenePhase) private var scenePhase

    init() {
        #if DEBUG
        let list = WatchDemoStore.requested ? WatchCodesList(store: WatchDemoStore()) : WatchCodesList()
        #else
        let list = WatchCodesList()
        #endif
        _list = State(initialValue: list)
        receiver = WatchSessionReceiver(list: list)
    }

    var body: some Scene {
        WindowGroup {
            CodeListView(list: list, active: scenePhase == .active)
                .onChange(of: scenePhase, initial: true) { _, phase in
                    if phase == .active { list.reload() } else { list.hide() }
                }
        }
        // A message from the iPhone that arrives while the app is not running (Forget on lock, an unpin) is
        // applied at once, so the complication stops showing the code without waiting for the app to be opened.
        .backgroundTask(.watchConnectivity) {
            await WatchSessionReceiver.drainPendingDeliveries()
        }
    }
}

struct CodeListView: View {
    let list: WatchCodesList
    let active: Bool

    var body: some View {
        NavigationStack {
            Group {
                if list.codes.isEmpty {
                    Text(WatchText.emptyHint)
                        .font(.footnote).multilineTextAlignment(.center).foregroundStyle(.secondary)
                } else {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        List(list.codes) { code in
                            CodeRow(code: code, now: Int64(context.date.timeIntervalSince1970))
                        }
                    }
                }
            }
            .navigationTitle("Codes")
        }
        .redacted(reason: active ? [] : .privacy)
    }
}

struct CodeRow: View {
    let code: WatchCode
    let now: Int64

    var body: some View {
        let current = code.current(at: now)
        let urgent = current.map { Self.isUrgent(secondsRemaining: $0.secondsRemaining) } ?? false
        VStack(alignment: .leading, spacing: 2) {
            Text(code.title.isEmpty ? String(localized: "2FA code") : code.title).font(.caption).lineLimit(1)
            HStack(spacing: 6) {
                Text(current.map { Self.grouped($0.code) } ?? "—")
                    .font(.system(.title2, design: .monospaced).weight(.semibold))
                    .minimumScaleFactor(0.6).lineLimit(1)
                    .foregroundStyle(urgent ? Color.orange : Color.primary)
                    .privacySensitive()
                Spacer(minLength: 0)
                if let current {
                    CountdownRing(secondsRemaining: current.secondsRemaining, period: code.period, urgent: urgent)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }

    /// The ring and digits turn orange in the last 5 seconds of a code.
    static func isUrgent(secondsRemaining: Int) -> Bool { secondsRemaining <= 5 }

    /// The share of the period still left, 0...1, for the countdown ring.
    static func fraction(secondsRemaining: Int, period: Int) -> Double {
        guard period > 0 else { return 0 }
        return min(1, max(0, Double(secondsRemaining) / Double(period)))
    }

    /// "123 456" / "1234 5678".
    static func grouped(_ code: String) -> String {
        guard code.count >= 6 else { return code }
        let mid = code.index(code.startIndex, offsetBy: code.count / 2)
        return String(code[..<mid]) + " " + String(code[mid...])
    }
}

/// A small ring that empties as the code's period runs out, with the seconds left inside.
struct CountdownRing: View {
    let secondsRemaining: Int
    let period: Int
    let urgent: Bool

    var body: some View {
        let tint: Color = urgent ? .orange : .accentColor
        ZStack {
            Circle().stroke(tint.opacity(0.25), lineWidth: 3)
            Circle()
                .trim(from: 0, to: CodeRow.fraction(secondsRemaining: secondsRemaining, period: period))
                .stroke(tint, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text("\(secondsRemaining)")
                .font(.caption2.monospacedDigit())
                .foregroundStyle(urgent ? Color.orange : Color.secondary)
        }
        .frame(width: 26, height: 26)
    }
}
