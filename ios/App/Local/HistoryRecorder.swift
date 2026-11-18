import Foundation
import os
import AppShared

/// Item history on this iPhone (feature pack §1): the store's commits hand their rows here (see
/// `SystemUnlock.bootstrap`), and they are appended to this unlock's local data and pruned to the plan's limits.
/// Rows that arrive before the local data is open wait (a few hundred at most). Failures are logged, never shown:
/// history is best effort and never blocks a save.
@MainActor
final class HistoryRecorder {
    static let shared = HistoryRecorder()
    private static let log = Logger(subsystem: "app.localgatekeys", category: "history")
    static let maxPending = 500

    private weak var local: (any PhoneLocalHosting)?
    private var isPro: () -> Bool = { false }
    private var pending: [ItemHistory.Row] = []
    var clock: () -> Int64 = { Int64(Date().timeIntervalSince1970) }

    /// This unlock's local data (the History screen reads its rows), nil while locked.
    var host: (any PhoneLocalHosting)? { local }

    /// The local data of this unlock (RootTabs opens it).
    func attach(_ local: any PhoneLocalHosting, isPro: @escaping () -> Bool) {
        self.local = local
        self.isPro = isPro
        let waiting = pending
        pending = []
        if !waiting.isEmpty { record(waiting) }
    }

    /// The vault locked: nothing more is recorded until the next unlock attaches.
    func detach() {
        local = nil
        isPro = { false }
        pending = []
    }

    func record(_ rows: [ItemHistory.Row]) {
        guard let local, let data = local.localData else {
            pending = Array((pending + rows).suffix(Self.maxPending))
            return
        }
        let next = HistoryCapture.appending(rows, to: data, now: clock(), limits: .plan(isPro: isPro()))
        do { try local.commitLocalData(next) } catch {
            Self.log.error("Item history save failed: \(String(describing: type(of: error)), privacy: .public)")
        }
    }

    /// Rows pruned again to the current plan (after a plan change or at unlock).
    func prune() {
        guard let local, let data = local.localData else { return }
        let next = HistoryCapture.appending([], to: data, now: clock(), limits: .plan(isPro: isPro()))
        guard next.itemHistory != data.itemHistory else { return }
        try? local.commitLocalData(next)
    }
}
