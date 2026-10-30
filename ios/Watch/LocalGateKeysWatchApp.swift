import SwiftUI
import LGKCore

/// UX plan workstream 12: the Apple Watch app. A list of the 2FA codes pinned on the iPhone, generated on the
/// watch (they work with the phone away). Codes show only inside this app: no complication, no widget, no
/// notification. The watch's wrist detection and passcode guard them (Keychain `WhenUnlockedThisDeviceOnly`);
/// the list is also dropped whenever the app is not active.
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
    }
}

struct CodeListView: View {
    let list: WatchCodesList
    let active: Bool

    var body: some View {
        NavigationStack {
            Group {
                if list.codes.isEmpty {
                    Text("Pin a 2FA code on your iPhone: open the item and choose Show on Apple Watch.")
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
        VStack(alignment: .leading, spacing: 2) {
            Text(code.title.isEmpty ? String(localized: "2FA code") : code.title).font(.caption).lineLimit(1)
            HStack {
                Text(current.map { Self.grouped($0.code) } ?? "—")
                    .font(.system(.title3, design: .monospaced)).privacySensitive()
                Spacer()
                if let current {
                    Text("\(current.secondsRemaining)").font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }

    /// "123 456" / "1234 5678".
    static func grouped(_ code: String) -> String {
        guard code.count >= 6 else { return code }
        let mid = code.index(code.startIndex, offsetBy: code.count / 2)
        return String(code[..<mid]) + " " + String(code[mid...])
    }
}
