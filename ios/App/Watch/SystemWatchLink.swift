import Foundation
import WatchConnectivity
import AppShared

/// WatchConnectivity on the iPhone (UX workstream 12). Each message replaces the last: any transfer still
/// queued is cancelled first, so an older set of secrets is never delivered after a newer one (or a forget).
/// `transferUserInfo` delivers once, in order, even when the watch app is not running.
final class SystemWatchLink: NSObject, WCSessionDelegate, WatchSending, @unchecked Sendable {
    @MainActor static let shared = SystemWatchLink()

    /// The message waiting for activation to finish (main actor only).
    @MainActor private var pending: WatchMessage?

    override init() {
        super.init()
        if WCSession.isSupported() {
            WCSession.default.delegate = self
            WCSession.default.activate()
        }
    }

    @MainActor var isAvailable: Bool {
        guard WCSession.isSupported() else { return false }
        let s = WCSession.default
        return s.activationState == .activated && s.isPaired && s.isWatchAppInstalled
    }

    @MainActor func send(_ message: WatchMessage) {
        guard WCSession.isSupported() else { return }
        let s = WCSession.default
        guard s.activationState == .activated else { pending = message; return }
        guard s.isPaired, s.isWatchAppInstalled else { return }
        guard let info = try? message.userInfo() else { return }
        for t in s.outstandingUserInfoTransfers where t.userInfo[WatchMessage.key] != nil { t.cancel() }
        s.transferUserInfo(info)
    }

    // MARK: WCSessionDelegate (delivered on a background queue)

    nonisolated func session(_ session: WCSession, activationDidCompleteWith state: WCSessionActivationState, error: Error?) {
        guard state == .activated else { return }
        Task { @MainActor in
            guard let m = self.pending else { return }
            self.pending = nil
            self.send(m)
        }
    }

    nonisolated func sessionDidBecomeInactive(_ session: WCSession) {}

    /// Switching to another watch: activate again for the new one.
    nonisolated func sessionDidDeactivate(_ session: WCSession) { WCSession.default.activate() }
}
