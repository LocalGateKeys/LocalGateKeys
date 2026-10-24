/// Plausibility of a REMOTE version vector next to the local one (desktop `engine.implausible_vv`, audit
/// 2026-10-24 M-6). A counter counts one device's edits of ONE item, so honest values stay tiny; a peer holding
/// the group key could otherwise publish 2^53-1 and make the next local edit of that item overflow.
/// Shared cases: `tests/vectors/sync/hardening_cases.json` (`vv`).
public enum Plausibility {
    public static let maxVVCounter: Int64 = 1 << 40
    public static let maxUnknownVVCounter: Int64 = 1 << 20
    public static let maxVVStep: Int64 = 1 << 20
    public static let maxVVKeys = 512

    /// `too-many-keys`, `implausible-counter` or nil. A key that advances past the local counter must stay
    /// within its bound (`maxVVCounter` for a key in `known` or in the local vector, else
    /// `maxUnknownVVCounter`) or within `maxVVStep` of the local counter. A missing local vector is empty.
    public static func implausibleVV(_ remote: [String: Int64], local: [String: Int64]?, known: Set<String>) -> String? {
        let base = local ?? [:]
        if remote.count > maxVVKeys { return "too-many-keys" }
        for (dev, n) in remote {
            let b = base[dev] ?? 0
            if n <= b { continue }
            let limit = (known.contains(dev) || base[dev] != nil) ? maxVVCounter : maxUnknownVVCounter
            if n > limit && n - b > maxVVStep { return "implausible-counter" }
        }
        return nil
    }
}
