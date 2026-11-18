import Foundation

/// When each peer last synced in this process, even with no changes: a clean Wi-Fi exchange, or its cloud folder
/// heartbeat (desktop `sync/seen.py`, Android `PeerSeenAt`). In memory only: a no-change sync writes nothing to the
/// store. A time only moves forward, so a replayed old heartbeat changes nothing.
public enum PeerSeenAt {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var times: [String: [String: Int64]] = [:]

    public static func note(groupID: String, peer: String, now: Int64) {
        lock.lock(); defer { lock.unlock() }
        let at = max(0, now)
        if at > times[groupID]?[peer] ?? -1 { times[groupID, default: [:]][peer] = at }
    }

    /// `saved` with any newer in-memory time of the same group.
    public static func merged(groupID: String, saved: [String: Int64]) -> [String: Int64] {
        lock.lock(); defer { lock.unlock() }
        return saved.merging(times[groupID] ?? [:]) { max($0, $1) }
    }

    public static func clear() {
        lock.lock(); defer { lock.unlock() }
        times = [:]
    }
}
