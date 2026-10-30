import Foundation
import Observation
import AppShared

/// The app's one pin list, over the live WatchConnectivity link.
@MainActor
enum WatchCodes {
    static let shared = WatchCodesModel(link: SystemWatchLink.shared)
}

/// Sends one `WatchMessage` to the paired watch's LocalGateKeys app (the live one is `SystemWatchLink`).
@MainActor
protocol WatchSending: AnyObject {
    /// A watch is paired and has the LocalGateKeys watch app installed.
    var isAvailable: Bool { get }
    func send(_ message: WatchMessage)
}

/// UX plan workstream 12, iPhone side: which 2FA codes are pinned to the Apple Watch, and when the watch
/// gets them or forgets them. Pins are item ids in the app's own defaults (no secret). The secrets leave the
/// phone only in a `WatchMessage` over WatchConnectivity (encrypted between the paired devices by Apple;
/// never through a server), and only on the Pro plan, like all 2FA.
@MainActor @Observable
final class WatchCodesModel {
    static let pinsKey = "watch.pinnedItemIDs"
    static let forgetOnLockKey = "watch.forgetOnLock"

    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored let link: any WatchSending
    private(set) var pins: [String]
    /// "Forget on watch" when the vault locks (default off: the watch keeps working with the phone away).
    var forgetOnLock: Bool {
        didSet { defaults.set(forgetOnLock, forKey: Self.forgetOnLockKey) }
    }

    init(link: any WatchSending, defaults: UserDefaults = .standard) {
        self.link = link; self.defaults = defaults
        pins = defaults.stringArray(forKey: Self.pinsKey) ?? []
        forgetOnLock = defaults.bool(forKey: Self.forgetOnLockKey)
    }

    var watchAvailable: Bool { link.isAvailable }
    func isPinned(_ itemID: String) -> Bool { pins.contains(itemID) }
    var canPinMore: Bool { pins.count < WatchMessage.maxPins }

    enum ToggleResult: Equatable { case pinned, unpinned, limitReached, needsPro }

    /// "Show on Apple Watch" / unpin for one item, then the whole pinned set is sent again (so an unpinned
    /// secret is removed from the watch).
    @discardableResult
    func toggle(_ itemID: String, snapshot: StoreSnapshot, isPro: Bool) -> ToggleResult {
        let pinning = !pins.contains(itemID)
        if pinning && !isPro { return .needsPro }
        guard let next = WatchPins.toggle(itemID, in: pins) else { return .limitReached }
        pins = next
        defaults.set(pins, forKey: Self.pinsKey)
        send(snapshot: snapshot, isPro: isPro)
        return pinning ? .pinned : .unpinned
    }

    /// Sends the pinned codes (none without Pro). Called after a pin change.
    func send(snapshot: StoreSnapshot, isPro: Bool) {
        let codes = isPro ? WatchPins.codes(pins: pins, snapshot: snapshot) : []
        link.send(codes.isEmpty ? .forget : .replace(codes))
    }

    /// The vault locked: with "Forget on watch" on, the watch drops every secret (it gets them again on the
    /// next pin change after unlock).
    func vaultLocked() {
        guard forgetOnLock, !pins.isEmpty else { return }
        link.send(.forget)
    }

    /// "Erase this iPhone's vault": the watch forgets and the pins go.
    func vaultErased() {
        let had = !pins.isEmpty
        pins = []
        defaults.removeObject(forKey: Self.pinsKey)
        if had { link.send(.forget) }
    }
}
