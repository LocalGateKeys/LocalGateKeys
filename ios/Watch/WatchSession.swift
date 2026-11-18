import Foundation
import Observation
import os
import WatchConnectivity
import WidgetKit
import LGKCore

/// The watch end of WatchConnectivity: receives the iPhone's `WatchMessage`s and keeps the list the app
/// draws. The watch never sends secrets back and never asks the phone for anything.
@MainActor @Observable
final class WatchCodesList {
    private(set) var codes: [WatchCode] = []
    @ObservationIgnored let store: any WatchSecretStoring
    /// Holds the send order of the last applied message (not secret).
    @ObservationIgnored private let defaults: UserDefaults
    static let lastSequenceKey = "watch.lastMessageSequence"
    /// Asks WidgetKit for a new complication timeline (the complication reads the same Keychain item).
    @ObservationIgnored private let reloadComplications: @MainActor () -> Void

    init(store: any WatchSecretStoring = KeychainWatchStore(), defaults: UserDefaults = .standard,
         reloadComplications: @escaping @MainActor () -> Void = { WidgetCenter.shared.reloadAllTimelines() }) {
        self.store = store
        self.defaults = defaults
        self.reloadComplications = reloadComplications
    }

    /// Reads the Keychain (only possible while the watch is unlocked). Called when the app becomes active, so
    /// the complication is also refreshed then (an "Open LocalGateKeys" or "Unlock" complication shows codes
    /// again); a reload from the app in the foreground does not use the complication's daily budget.
    func reload() {
        codes = store.load()
        reloadComplications()
    }

    /// Hidden (app inactive or in the background): the decoded secrets leave memory.
    func hide() { codes = [] }

    /// A message from the iPhone. Any change to the stored codes (pin, unpin, Forget on lock, erase) also
    /// refreshes the complication, so it never keeps showing a code that is gone from the watch.
    func received(_ userInfo: [String: Any]) {
        let stored = (defaults.object(forKey: Self.lastSequenceKey) as? NSNumber)?.int64Value
        var last = stored
        let next = WatchInbox.apply(userInfo, to: store, lastSequence: &last)
        // Kept even when the message is ignored, so an implausible stored order is repaired (removed) at once.
        if last != stored {
            if let last { defaults.set(NSNumber(value: last), forKey: Self.lastSequenceKey) }
            else { defaults.removeObject(forKey: Self.lastSequenceKey) }
        }
        if let next {
            codes = next
            reloadComplications()
        }
    }
}

final class WatchSessionReceiver: NSObject, WCSessionDelegate, @unchecked Sendable {
    @MainActor let list: WatchCodesList

    @MainActor init(list: WatchCodesList) {
        self.list = list
        super.init()
        if WCSession.isSupported() {
            WCSession.default.delegate = self
            WCSession.default.activate()
        }
    }

    /// Logs a failed activation (review 2026-11-15) so a watch that never receives codes can be diagnosed.
    /// The error text carries no secret.
    nonisolated func session(_ session: WCSession, activationDidCompleteWith state: WCSessionActivationState, error: Error?) {
        if let error {
            Logger(subsystem: "app.localgatekeys.watch", category: "session")
                .error("WatchConnectivity activation failed (state \(state.rawValue)): \(String(describing: error), privacy: .public)")
        }
    }

    /// The app was launched in the background for a WatchConnectivity delivery (e.g. Forget on lock while a
    /// complication is on the face): keep the launch alive until the session has handed over what is pending and
    /// the main actor has applied it (store cleared, complication reloaded). At most about 10 seconds.
    nonisolated static func drainPendingDeliveries() async {
        guard WCSession.isSupported() else { return }
        for _ in 0..<50 {
            if WCSession.default.activationState == .activated, !WCSession.default.hasContentPending { break }
            try? await Task.sleep(for: .milliseconds(200))
        }
        // `received` runs in a main-actor task queued by the delegate: let it run before the launch ends.
        await MainActor.run {}
        try? await Task.sleep(for: .milliseconds(200))
        await MainActor.run {}
    }

    /// `transferUserInfo` from the iPhone: delivered once, in order.
    nonisolated func session(_ session: WCSession, didReceiveUserInfo userInfo: [String: Any]) {
        // Only the one Data value crosses the actor hop.
        guard let data = userInfo[WatchMessage.key] as? Data else { return }
        Task { @MainActor in self.list.received([WatchMessage.key: data]) }
    }
}
