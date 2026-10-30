import Foundation
import Crypto

/// Finding the paired host on the local network after its address changed (desktop `sync.discovery`,
/// Android `core.lan.Discovery`, Bonjour / mDNS).
///
/// A host announces `serviceType` with a neutral instance name (`LocalGateKeys-xxxx`) and the TXT record
/// `{"v": "1", "t": <tag>}`; the tag changes every UTC day and only group members can compute it. It only
/// says where to dial: identity is still the pinned keys checked by the session hello. Format pinned by
/// `tests/vectors/sync/discovery.json`.
public enum Discovery {
    public static let serviceType = "_lgksync._tcp"
    public static let txtVersion = "1"
    /// At most this many announced addresses are dialled per run (plan: security rules).
    public static let maxCandidates = 4

    static let discoverInfo = Array("localgatekeys|sync|discover|v1|".utf8)
    static let tagBytes = 10
    static let day: Int64 = 86_400

    /// HKDF-SHA256 over the group key, salt = group id, info = `localgatekeys|sync|discover|v1|<epoch>`.
    public static func discoveryKey(_ groupKey: GroupKey) -> [UInt8] {
        CryptoBox.hkdf(ikm: groupKey.key, salt: Array(groupKey.groupID.utf8),
                       info: discoverInfo + Array(String(groupKey.epoch).utf8), length: 32)
    }

    /// The UTC date `YYYY-MM-DD` of a Unix time in seconds.
    public static func utcDay(_ now: Int64) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let c = calendar.dateComponents([.year, .month, .day], from: Date(timeIntervalSince1970: TimeInterval(now)))
        return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }

    /// base32(HMAC-SHA256(discovery key, host device id + "|" + day)[:10]), lowercase, no padding (16 characters).
    public static func tag(_ groupKey: GroupKey, hostDeviceID: String, day: String) -> String {
        let message = Array(hostDeviceID.utf8) + Array("|".utf8) + Array(day.utf8)
        let mac = Array(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: discoveryKey(groupKey))))
        return base32Lower(Array(mac.prefix(tagBytes)))
    }

    /// The tags accepted for `hostDeviceID` at `now`: today's and yesterday's (UTC), so a skewed clock still matches.
    public static func acceptedTags(_ groupKey: GroupKey, hostDeviceID: String, now: Int64) -> Set<String> {
        [tag(groupKey, hostDeviceID: hostDeviceID, day: utcDay(now)),
         tag(groupKey, hostDeviceID: hostDeviceID, day: utcDay(now - day))]
    }

    /// The TXT record a host announces at `now`.
    public static func txtRecord(_ groupKey: GroupKey, hostDeviceID: String, now: Int64) -> [String: String] {
        ["v": txtVersion, "t": tag(groupKey, hostDeviceID: hostDeviceID, day: utcDay(now))]
    }

    /// `LocalGateKeys-` and four lowercase hex digits (random per listener start).
    public static func instanceName(random: any RandomSource) -> String {
        "LocalGateKeys-" + random.bytes(count: 2).map { String(format: "%02x", $0) }.joined()
    }

    /// One resolved announcement: the host address text, the port and the TXT record.
    public struct Announcement: Equatable, Sendable {
        public let host: String
        public let port: Int
        public let txt: [String: String]
        public init(host: String, port: Int, txt: [String: String]) { self.host = host; self.port = port; self.txt = txt }
    }

    /// The addresses worth dialling, in browse order: version 1, an accepted tag, a private LAN address, a valid
    /// port; duplicates and `alreadyTried` (the pinned address) dropped; at most `maxCandidates`.
    public static func candidates(_ found: [Announcement], accepted: Set<String>, alreadyTried: LanEndpoint?) -> [LanEndpoint] {
        var out: [LanEndpoint] = []
        for a in found {
            if out.count >= maxCandidates { break }
            guard a.txt["v"] == txtVersion, let t = a.txt["t"], accepted.contains(t) else { continue }
            guard (1...65535).contains(a.port), LanAddress.isLAN(a.host), routable(a.host) else { continue }
            guard let e = try? LanEndpoint(validating: a.host, port: a.port) else { continue }
            if e != alreadyTried && !out.contains(e) { out.append(e) }
        }
        return out
    }

    /// Discovery dials only a dotted IPv4 address outside loopback (127/8), link-local (169.254/16) and 0/8: an
    /// announcement is unauthenticated, so it must not aim the phone at its own services. The pinned address
    /// keeps the wider `LanAddress.isLAN` rule.
    public static func routable(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4, parts.allSatisfy({ !$0.isEmpty && $0.count <= 3 && $0.allSatisfy { $0 >= "0" && $0 <= "9" } }) else {
            return false
        }
        let b = parts.map { Int($0)! }
        guard b.allSatisfy({ $0 <= 255 }) else { return false }
        return b[0] != 127 && b[0] != 0 && !(b[0] == 169 && b[1] == 254)
    }

    private static let alphabet = Array("abcdefghijklmnopqrstuvwxyz234567")

    static func base32Lower(_ data: [UInt8]) -> String {
        var out = ""
        var buffer = 0, bits = 0
        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                out.append(alphabet[(buffer >> (bits - 5)) & 31])
                bits -= 5
            }
            buffer &= (1 << bits) - 1
        }
        if bits > 0 { out.append(alphabet[(buffer << (5 - bits)) & 31]) }
        return out
    }
}
