import Foundation
import CryptoKit
import LGKCore

/// How a login captured in Safari relates to the vault, as far as the fingerprint index can tell: whether a
/// login with that origin and username exists. Never whether the password matches (audit 2026-10-24 M-3 /
/// L-7): the extension answers without Face ID, so a password comparison would let a page script or someone
/// holding the unlocked phone test guesses. The app compares the password itself at import time.
public enum SafariLoginStatus: String, Sendable {
    case new
    case exists
}

public enum SafariIndexError: Error, Equatable, Sendable {
    case malformed
}

/// The fingerprint index `<app group>/SafariSave/index.json`: for every live `web` login, an HMAC of its
/// (origin, username) under the device-only index key. The Safari extension classifies a captured login
/// against it without reading the vault. Version 2 holds no password fingerprint (version 1 did; a version 1
/// file left by an earlier build is still read, its password fingerprints ignored, until the app republishes).
///
/// HMAC input is the canonical JSON of `["login", origin, username]`, so no separator inside a field can make
/// two logins collide.
public struct SafariIndex: Equatable, Sendable {
    public struct Entry: Hashable, Sendable {
        public let login: [UInt8]
        public init(login: [UInt8]) { self.login = login }
    }

    public static let version: Int64 = 2
    /// The earlier format with a password fingerprint per entry: read (logins only), never written.
    static let legacyVersion: Int64 = 1
    static let macLength = 32

    /// Sorted and without duplicates, so equal indexes encode to the same bytes.
    public let entries: [Entry]
    private let logins: Set<[UInt8]>

    public init(entries: [Entry]) {
        self.entries = Set(entries).sorted { a, b in a.login.lexicographicallyPrecedes(b.login) }
        logins = Set(entries.map(\.login))
    }

    public static func == (a: SafariIndex, b: SafariIndex) -> Bool { a.entries == b.entries }

    /// The index of `records` (a `StoreSnapshot`'s id -> synced wrapper). Only `ns == "entry"` wrappers
    /// whose record is `kind == "web"` count. Deleted items are not in `records` (their tombstones live
    /// in the sync meta only), so they never appear. A record whose origin is not a valid origin is skipped.
    /// Collection states (`StoreSnapshot.itemRecords`) never count.
    public static func fingerprints(records: [String: JSONValue], key: [UInt8]) -> SafariIndex {
        var out: [Entry] = []
        for (id, wrapper) in records where !CollectionStates.isReserved(id, wrapper) {
            guard case .object(let w) = wrapper, w["ns"] == .string(Namespace.entry.rawValue),
                  case .object(let rec)? = w["record"], rec["kind"] == .string("web"),
                  case .object(let scope)? = rec["scope"], case .string(let rawOrigin)? = scope["origin"],
                  let origin = try? Origin.canonicalize(rawOrigin) else { continue }
            guard let username = text(rec["username"]),
                  let login = loginMAC(origin: origin, username: username, key: key) else { continue }
            out.append(Entry(login: login))
        }
        return SafariIndex(entries: out)
    }

    /// `exists` when a login with this origin and username is in the vault, else `new`. The origin is
    /// canonicalised first; one that is not a valid origin matches nothing (`new`). A wrong key never matches.
    public func classify(origin: String, username: String, key: [UInt8]) -> SafariLoginStatus {
        guard let canonical = try? Origin.canonicalize(origin) else { return .new }
        if let l = Self.loginMAC(origin: canonical, username: username, key: key), logins.contains(l) {
            return .exists
        }
        return .new
    }

    /// `{"entries":[{"login":"<b64>"}],"version":2}` as canonical JSON.
    public func encoded() throws -> [UInt8] {
        let rows: [JSONValue] = entries.map { .object(["login": .string(Base64.encode($0.login))]) }
        return try CanonicalJSON.encode(.object(["version": .int(Self.version), "entries": .array(rows)]), dialect: .utf8)
    }

    /// Reads `encoded()` output, or a version 1 file (`{"login","secret"}` rows; the secrets are checked for
    /// shape and dropped). Anything else (another version, extra fields, bad base64, a MAC that is not 32
    /// bytes) throws `SafariIndexError.malformed`.
    public static func decode(_ bytes: [UInt8]) throws -> SafariIndex {
        guard case .object(let o)? = try? CanonicalJSON.parse(bytes), Set(o.keys) == ["version", "entries"],
              case .int(let v)? = o["version"], v == version || v == legacyVersion,
              case .array(let rows)? = o["entries"] else { throw SafariIndexError.malformed }
        let rowKeys: Set<String> = v == version ? ["login"] : ["login", "secret"]
        var out: [Entry] = []
        out.reserveCapacity(rows.count)
        for row in rows {
            guard case .object(let r) = row, Set(r.keys) == rowKeys,
                  case .string(let l)? = r["login"], let login = try? Base64.decodeStrict(l),
                  login.count == macLength else { throw SafariIndexError.malformed }
            if v == legacyVersion {
                guard case .string(let s)? = r["secret"], let secret = try? Base64.decodeStrict(s),
                      secret.count == macLength else { throw SafariIndexError.malformed }
            }
            out.append(Entry(login: login))
        }
        return SafariIndex(entries: out)
    }

    // MARK: MACs

    static func loginMAC(origin: String, username: String, key: [UInt8]) -> [UInt8]? {
        mac([.string("login"), .string(origin), .string(username)], key: key)
    }

    /// HMAC-SHA256 over the canonical JSON array; nil only if the array cannot be encoded.
    static func mac(_ parts: [JSONValue], key: [UInt8]) -> [UInt8]? {
        guard let message = try? CanonicalJSON.encode(.array(parts), dialect: .utf8) else { return nil }
        return Array(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    /// A missing username is empty (as the editor allows); any other non-string skips the record.
    private static func text(_ v: JSONValue?) -> String? {
        switch v {
        case nil, .null?: return ""
        case .string(let s)?: return s
        default: return nil
        }
    }
}

/// Files of Safari save in the Safari app group container (`AppGroup.safariContainerURL`, audit 2026-11-10: the
/// Safari extensions hold that group only, never the shared one with the vault):
///
/// - `SafariSave/` (`directory()`): `index.json`, `sites.bin`, `probes.json`, `inbox/` and the `plan-full` marker
///   (present while the free vault is full, written by the app at each commit and unlock, `SafariIndexPublisher`);
/// - `SafariSave.erase-pending` beside it (present while an erase is pending, `AppSettings.erasePending`), outside
///   the folder so the erase that deletes the folder leaves it in place;
/// - `Duress/` (`duressMirror`): copies of the duress hold and session marker (`PhoneDuress`);
/// - Mac: `active-profile` (the profile the app opened last) and `Profiles/<id>/SafariSave` for the other profiles.
///
/// Builds before the Safari group kept `SafariSave/` in the shared group (`legacyLocation`); the app moves it at
/// launch (`SafariGroupMigration`).
public enum SafariSaveFiles {
    public static let directoryName = "SafariSave"
    public static let indexFileName = "index.json"
    public static let planFullFileName = "plan-full"
    public static let erasePendingFileName = "SafariSave.erase-pending"
    public static let duressDirectoryName = "Duress"
    public static let activeProfileFileName = "active-profile"

    /// `<Safari group>/SafariSave`, created when missing and excluded from backups (its contents are sealed
    /// or keyed under device-only Keychain items, so a restored copy is useless). Throws
    /// `LocalStoreError.noContainer` without the Safari group container, like `AppGroup.vaultDirectory()`.
    public static func directory() throws -> URL {
        let dir = try location()
        do { try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true) }
        catch { throw LocalStoreError.io("create \(directoryName)") }
        LocalStore.excludeFromBackup(dir)
        return dir
    }

    /// Where `directory()` lives, without creating it (erase deletes it). Throws `LocalStoreError.noContainer`
    /// without the Safari group container.
    public static func location() throws -> URL {
        guard let base = AppGroup.safariContainerURL else { throw LocalStoreError.noContainer }
        return folder(in: base, profile: activeProfileID(safariRoot: base))
    }

    /// The pre-Safari-group place of `location()`, in the shared group (nil without that container, as in the Safari
    /// extensions). Read only by the launch migration and erased with the vault.
    public static func legacyLocation() -> URL? {
        guard let base = AppGroup.containerURL else { return nil }
        #if os(macOS)
        return folder(in: base, profile: ProfileRegistry.shared()?.active().id)
        #else
        return folder(in: base, profile: nil)
        #endif
    }

    /// `<root>/SafariSave`, or for another Mac profile `<root>/Profiles/<id>/SafariSave` (the default profile keeps
    /// the first folder). An id that is not a profile id (`ProfileRegistry.isValidID`) is the default profile.
    static func folder(in root: URL, profile id: String?) -> URL {
        #if os(macOS)
        // Mac profiles: saves and the index belong to the profile the app opened last, so a login saved in Safari is
        // imported into that profile, not whichever unlocks next.
        if let id, id != ProfileScope.defaultID, ProfileRegistry.isValidID(id) {
            return root.appendingPathComponent("Profiles", isDirectory: true).appendingPathComponent(id, isDirectory: true)
                .appendingPathComponent(directoryName, isDirectory: true)
        }
        #endif
        return root.appendingPathComponent(directoryName, isDirectory: true)
    }

    /// The Mac profile the app opened last: the registry where it is readable (the app), else the copy the app keeps
    /// in the Safari group (`recordActiveProfile`, read by the Safari extension). Nil on the iPhone.
    static func activeProfileID(safariRoot: URL) -> String? {
        #if os(macOS)
        if let registry = ProfileRegistry.shared() { return registry.active().id }
        guard let data = FileManager.default.contents(atPath: safariRoot.appendingPathComponent(activeProfileFileName).path),
              data.count <= 64, let text = String(data: data, encoding: .utf8) else { return nil }
        let id = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return ProfileRegistry.isValidID(id) ? id : nil
        #else
        return nil
        #endif
    }

    /// Mac app: keeps the Safari extension's copy of the active profile id (each registry write, and at launch).
    public static func recordActiveProfile(_ id: String, safariRoot: URL? = AppGroup.safariContainerURL) {
        #if os(macOS)
        guard let safariRoot, ProfileRegistry.isValidID(id) else { return }
        try? writeAtomically(Array(id.utf8), to: safariRoot.appendingPathComponent(activeProfileFileName))
        #endif
    }

    public static func indexURL(in directory: URL) -> URL {
        directory.appendingPathComponent(indexFileName, isDirectory: false)
    }

    /// Present while the free vault is full (no synced licence): the Safari extension then asks StoreKit before it
    /// offers to save a new login.
    public static func planFullURL(in directory: URL) -> URL {
        directory.appendingPathComponent(planFullFileName, isDirectory: false)
    }

    /// Present while an erase is pending: the Safari extension answers nothing. Beside the `SafariSave` folder.
    public static func erasePendingURL(beside directory: URL) -> URL {
        directory.deletingLastPathComponent().appendingPathComponent(erasePendingFileName, isDirectory: false)
    }

    /// The duress hold and session copies the Safari extension reads (`PhoneDuress.servicesBlocked` over them).
    public static func duressMirror(safariRoot: URL? = AppGroup.safariContainerURL) -> DuressFiles? {
        guard let safariRoot else { return nil }
        let dir = safariRoot.appendingPathComponent(duressDirectoryName, isDirectory: true)
        return DuressFiles(dir: dir, hold: dir.appendingPathComponent("vault.hold.json"),
                           real: dir.appendingPathComponent("unused.bin"))
    }

    /// The app: sets or clears the erase-pending marker of the open profile. Best effort; a no-op without the Safari
    /// group (unsigned builds, the AutoFill extension).
    public static func setErasePending(_ on: Bool) {
        guard let dir = try? location() else { return }
        setMarker(erasePendingURL(beside: dir), on)
    }

    /// Creates (empty) or removes the marker file `url`. Best effort.
    static func setMarker(_ url: URL, _ on: Bool) {
        let fm = FileManager.default
        if on {
            if !fm.fileExists(atPath: url.path) { try? writeAtomically([], to: url) }
        } else {
            try? fm.removeItem(at: url)
        }
    }

    /// Writes a temp file next to `url` (file protection `completeUntilFirstUserAuthentication`), then
    /// renames it over `url`, so readers see the old file or the new one, never a partial one. Creates
    /// the parent directory when missing. Errors name the file only, never its contents.
    public static func writeAtomically(_ bytes: [UInt8], to url: URL) throws {
        let dir = url.deletingLastPathComponent()
        let fm = FileManager.default
        let tmp = dir.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp", isDirectory: false)
        do {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true)
            try Data(bytes).write(to: tmp, options: [.withoutOverwriting, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            try? fm.removeItem(at: tmp)
            throw LocalStoreError.io("write \(url.lastPathComponent)")
        }
        guard rename(tmp.path, url.path) == 0 else {
            try? fm.removeItem(at: tmp)
            throw LocalStoreError.io("rename \(url.lastPathComponent)")
        }
    }
}

/// Publishes the fingerprint index after each commit (`LocalStore.safariIndex`).
public protocol SafariIndexPublishing: AnyObject, Sendable {
    /// Best effort: never throws, and a failure never fails the commit.
    func publish(_ snapshot: StoreSnapshot)
}

/// Writes `index.json` (and the sealed site list `sites.bin`, `SafariSites`) from a committed snapshot when the
/// index key is in the Keychain. Without the key (the app has not created it yet) nothing is written. Every error
/// is swallowed.
public final class SafariIndexPublisher: SafariIndexPublishing {
    let keychain: any KeychainVault
    let directory: @Sendable () throws -> URL
    let random: any RandomSource
    /// The Public Suffix List for the site list's registrable domains (bundled in the app).
    let matcher: URLMatcher

    public init(keychain: any KeychainVault,
                directory: @escaping @Sendable () throws -> URL = { try SafariSaveFiles.directory() },
                random: any RandomSource = SystemRandomSource(),
                matcher: URLMatcher = SafariSaveService.bundledMatcher()) {
        self.keychain = keychain; self.directory = directory; self.random = random; self.matcher = matcher
    }

    public func publish(_ snapshot: StoreSnapshot) {
        do {
            guard let key = try keychain.read(.safariIndexKey), key.count == 32 else {
                AutoFillTrace.log("safari publish: no index key"); return
            }
            let bytes = try SafariIndex.fingerprints(records: snapshot.itemRecords, key: key).encoded()
            let dir = try directory()
            // The plan check the Safari extension makes before a new login (it cannot read the vault): the same rule
            // as `AppSettings.planFullRevision`, from this commit's snapshot.
            SafariSaveFiles.setMarker(SafariSaveFiles.planFullURL(in: dir), LocalStore.isPlanFull(snapshot))
            try SafariSaveFiles.writeAtomically(bytes, to: SafariSaveFiles.indexURL(in: dir))
            AutoFillTrace.log("safari publish: wrote \(bytes.count) bytes, \(snapshot.itemRecords.count) records")
            // The phishing shield's saved domains (sub-plan 09, Ruling T5b), sealed under a subkey of the same key.
            let sites = try SafariSites.seal(SafariSites.domains(records: snapshot.itemRecords, matcher: matcher), indexKey: key, random: random)
            try SafariSaveFiles.writeAtomically(sites, to: SafariSites.url(in: dir))
        } catch {
            AutoFillTrace.log("safari publish: \(error: error)")
            // Best effort: the next commit or unlock publishes again.
        }
    }
}
