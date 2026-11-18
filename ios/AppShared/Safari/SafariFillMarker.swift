import Foundation
import LGKCore

/// The "just filled" marker. On the iPhone the AutoFill extension fills passwords, so the Safari extension never
/// knows a fill happened and asked "Save / update?" after every sign-in to a saved account. When AutoFill hands over a
/// password it writes this marker; `SafariSaveService.classify` then answers `filled` instead of `exists` for that site
/// and username, and the extension shows no prompt.
///
/// AutoFill names up to two origins (`maxOrigins`): the filled login's own saved origin (`scope.origin`, what
/// `SafariIndex` matches for `exists`, and the only one a QuickType fill knows, since iOS hands over no page URL then),
/// and the page's origin when the list request named one and it differs. Each is canonicalised as the Safari extension's
/// `origin` is (`pageOrigin`); one that the extension does not save for is dropped.
///
/// `<SafariSave>/fill-marker.json`, the latest fill only: canonical JSON
/// `{"at":<fill time>,"logins":["<b64 HMAC of origin and username>", ...],"version":3}` (1 or 2 hashes, sorted, no
/// duplicates) and, once used, `"login"` (the hash that matched) and `"used"` (when it first matched). Keyed by
/// `safariFillKey` (its own 32 random bytes, not the index key), so the file names no site or username. It holds
/// nothing made from a password, and `matches` never looks at one (audit 2026-10-24 M-3: the answer must not depend
/// on the password, or a page script could test guesses against the one just filled). `filled` only says "AutoFill
/// just filled this username here", which the page already knows. A file in another format (an earlier build's)
/// reads as damaged and is deleted.
///
/// Matching (`matches`, classify with a username and password only):
/// - unused: the origin and username of any of the hashes, at most `unboundLifetime` seconds after the fill. The first
///   match marks the whole marker used by that origin and username.
/// - used: only that same origin and username, at most `graceLifetime` seconds after the first match; the other
///   origin no longer matches. A repeated capture of the same submit stays quiet; a later sign-in (the filled
///   password was refused and the user typed another) gets the normal prompt.
/// - anything else is ignored; an expired, damaged or future marker is deleted when seen.
///
/// Best effort, like `SafariProbeLimit`: two requests racing may both see the unused marker, and any read or write
/// error just means "no marker".
public struct SafariFillMarker: Sendable {
    public static let fileName = "fill-marker.json"
    /// How long after the fill an unused marker matches.
    public static let unboundLifetime: Int64 = 120
    /// How long after its first match a used marker still matches the same origin and username.
    public static let graceLifetime: Int64 = 20
    /// The login's saved origin and the page's origin.
    public static let maxOrigins = 2
    static let version: Int64 = 3

    let directory: URL
    let key: [UInt8]
    let now: @Sendable () -> Int64

    /// - Parameters:
    ///   - directory: the `SafariSave` folder of the Safari group.
    ///   - key: `safariFillKey` (32 bytes; any other length matches and writes nothing).
    public init(directory: URL, key: [UInt8], now: @escaping @Sendable () -> Int64) {
        self.directory = directory; self.key = key; self.now = now
    }

    var url: URL { directory.appendingPathComponent(Self.fileName, isDirectory: false) }

    // MARK: AutoFill

    /// The origin of a page URL or a saved login's origin, canonicalised as the Safari extension's `origin` is
    /// (`SafariSaveService.canonicalOrigin`: https, or http on localhost and 127.0.0.1); nil for anything else. The
    /// path, query, fragment and any user info are dropped, as in `location.origin`.
    public static func pageOrigin(_ pageURL: String) -> String? {
        guard let parts = URLComponents(string: pageURL), let scheme = parts.scheme, let host = parts.host, !host.isEmpty
        else { return nil }
        var origin = scheme + "://" + (host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host)
        if let port = parts.port { origin += ":\(port)" }
        return SafariSaveService.canonicalOrigin(origin)
    }

    /// The origins a marker is written for: each canonicalised (`pageOrigin`), the unusable ones dropped, duplicates
    /// dropped, the first `maxOrigins` kept in order.
    public static func usableOrigins(_ candidates: [String]) -> [String] {
        var out: [String] = []
        for raw in candidates {
            guard let o = pageOrigin(raw), !out.contains(o) else { continue }
            out.append(o)
            if out.count == maxOrigins { break }
        }
        return out
    }

    /// AutoFill handed the password of `username` over for `origins` (the login's saved origin and the page's origin,
    /// see the type doc): replaces the marker. False, and nothing written, when none of them is an origin the Safari
    /// extension saves for, for an empty username, without the Safari folder or `safariFillKey`, or while the app's
    /// erase-pending marker is there. Never throws: a marker must never delay or fail a fill. The caller checks the
    /// duress state and the app's own erase flag first (`CredentialFlow.recordFill`).
    @discardableResult
    public static func recordFill(origins candidates: [String], username: String,
                                  keychain: any KeychainVault = SystemKeychainVault(accessGroup: AppGroup.keychainAccessGroup),
                                  directory: () throws -> URL = { try SafariSaveFiles.directory() },
                                  now: Int64 = SystemClock().now) -> Bool {
        let origins = usableOrigins(candidates)
        guard !username.isEmpty, !origins.isEmpty else { return false }
        guard let dir = try? directory() else {
            AutoFillTrace.log("safari fill marker: no Safari folder"); return false
        }
        guard !FileManager.default.fileExists(atPath: SafariSaveFiles.erasePendingURL(beside: dir).path) else {
            AutoFillTrace.log("safari fill marker: erase pending"); return false
        }
        let key: [UInt8]
        do {
            guard let k = try keychain.read(.safariFillKey), k.count == SafariKeys.length else {
                AutoFillTrace.log("safari fill marker: no key"); return false
            }
            key = k
        } catch {
            AutoFillTrace.log("safari fill marker: key read \(error: error)"); return false
        }
        let t = now
        let ok = SafariFillMarker(directory: dir, key: key, now: { t }).record(origins: origins, username: username)
        AutoFillTrace.log("safari fill marker: hosts=\(hosts: origins) written=\(ok)")
        return ok
    }

    /// Writes a new unused marker for `origins` (canonical, at most `maxOrigins`) and `username`. False when it could
    /// not be written.
    @discardableResult
    func record(origins: [String], username: String) -> Bool {
        guard key.count == SafariKeys.length, !origins.isEmpty, origins.count <= Self.maxOrigins else { return false }
        var logins: [String] = []
        for origin in origins {
            guard let h = loginMAC(origin: origin, username: username) else { return false }
            logins.append(h)
        }
        return write(Entry(at: now(), logins: Array(Set(logins)).sorted(), bound: nil))
    }

    // MARK: the Safari extension

    /// Whether a `classify` of `origin` (canonical) and `username` follows the latest fill (see the type doc). Marks an
    /// unused marker used on its first match. Only for a login the index says `exists`. The password is not a
    /// parameter on purpose: the answer must never depend on it.
    public func matches(origin: String, username: String) -> Bool {
        guard key.count == SafariKeys.length, !username.isEmpty,
              FileManager.default.fileExists(atPath: url.path) else { return false }
        guard let entry = read() else { remove(); return false }
        let t = now()
        let (since, overflow) = t.subtractingReportingOverflow(entry.bound?.used ?? entry.at)
        let lifetime = entry.bound == nil ? Self.unboundLifetime : Self.graceLifetime
        guard !overflow, since >= 0, since <= lifetime, entry.bound.map({ $0.used >= entry.at }) ?? true
        else { remove(); return false }
        guard let login = loginMAC(origin: origin, username: username), entry.logins.contains(login) else { return false }
        if let bound = entry.bound { return bound.login == login }
        _ = write(Entry(at: entry.at, logins: entry.logins, bound: Bound(login: login, used: t)))
        return true
    }

    // MARK: file

    struct Bound: Equatable {
        /// The login hash (base64 HMAC) that matched first, and when.
        let login: String
        let used: Int64
    }

    struct Entry: Equatable {
        let at: Int64
        /// Base64 HMACs of origin and username, sorted.
        let logins: [String]
        let bound: Bound?
    }

    func loginMAC(origin: String, username: String) -> String? {
        SafariIndex.mac([.string("fill-login"), .string(origin), .string(username)], key: key).map { Base64.encode($0) }
    }

    func read() -> Entry? {
        guard let data = try? Data(contentsOf: url), data.count <= 1024,
              case .object(let o)? = try? CanonicalJSON.parse(Array(data)),
              o["version"] == .int(Self.version), case .int(let at)? = o["at"], case .array(let rows)? = o["logins"]
        else { return nil }
        var logins: [String] = []
        for row in rows {
            guard case .string(let h) = row else { return nil }
            logins.append(h)
        }
        guard !logins.isEmpty, logins.count <= Self.maxOrigins else { return nil }
        switch (o["login"], o["used"]) {
        case (nil, nil): return Entry(at: at, logins: logins, bound: nil)
        case (.string(let login)?, .int(let used)?): return Entry(at: at, logins: logins, bound: Bound(login: login, used: used))
        default: return nil
        }
    }

    func write(_ entry: Entry) -> Bool {
        var o: [String: JSONValue] = ["version": .int(Self.version), "at": .int(entry.at),
                                      "logins": .array(entry.logins.map { .string($0) })]
        if let bound = entry.bound { o["login"] = .string(bound.login); o["used"] = .int(bound.used) }
        guard let bytes = try? CanonicalJSON.encode(.object(o), dialect: .utf8) else { return false }
        return (try? SafariSaveFiles.writeAtomically(bytes, to: url)) != nil
    }

    func remove() { try? FileManager.default.removeItem(at: url) }
}
