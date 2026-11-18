import Foundation
import LGKCore
import AppSharedMac

/// The Safari index of this Mac without the items travel mode hides (feature pack §2.3, `SafariIndex.fingerprints`):
/// the records `TravelModeBox.shared.current` hides are left out before `base` writes `index.json` and the site
/// list, so the Safari extension never sees them. The base publisher is unchanged; `MacLockModel` republishes
/// when travel mode changes.
final class MacTravelSafariIndex: SafariIndexPublishing, @unchecked Sendable {
    let base: any SafariIndexPublishing
    let travel: @Sendable () -> TravelMode

    init(base: any SafariIndexPublishing, travel: @escaping @Sendable () -> TravelMode = { TravelModeBox.shared.current }) {
        self.base = base
        self.travel = travel
    }

    func publish(_ snapshot: StoreSnapshot) {
        base.publish(Self.filtered(snapshot, travel: travel()))
    }

    /// `snapshot` without the live records `travel` hides (unchanged when travel mode is off).
    static func filtered(_ snapshot: StoreSnapshot, travel: TravelMode) -> StoreSnapshot {
        let hidden = travel.hiddenIDs(in: snapshot)
        guard !hidden.isEmpty else { return snapshot }
        var out = snapshot
        for id in hidden { out.records[id] = nil }
        return out
    }
}
