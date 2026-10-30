import Foundation
import Observation
import WatchConnectivity
import LGKCore

/// The watch end of WatchConnectivity: receives the iPhone's `WatchMessage`s and keeps the list the app
/// draws. The watch never sends secrets back and never asks the phone for anything.
@MainActor @Observable
final class WatchCodesList {
    private(set) var codes: [WatchCode] = []
    @ObservationIgnored let store: any WatchSecretStoring

    init(store: any WatchSecretStoring = KeychainWatchStore()) {
        self.store = store
    }

    /// Reads the Keychain (only possible while the watch is unlocked).
    func reload() { codes = store.load() }

    /// Hidden (app inactive or in the background): the decoded secrets leave memory.
    func hide() { codes = [] }

    func received(_ userInfo: [String: Any]) {
        if let next = WatchInbox.apply(userInfo, to: store) { codes = next }
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

    nonisolated func session(_ session: WCSession, activationDidCompleteWith state: WCSessionActivationState, error: Error?) {}

    /// `transferUserInfo` from the iPhone: delivered once, in order.
    nonisolated func session(_ session: WCSession, didReceiveUserInfo userInfo: [String: Any]) {
        // Only the one Data value crosses the actor hop.
        guard let data = userInfo[WatchMessage.key] as? Data else { return }
        Task { @MainActor in self.list.received([WatchMessage.key: data]) }
    }
}
