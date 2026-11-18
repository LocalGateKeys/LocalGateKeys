import Foundation
import CryptoKit
import LGKCore

/// Why a duress-password change was refused (desktop `duress.DuressError`, Android `DuressException`): `same` /
/// `close` (equal to or one edit from the app password), `near_duress` (a new app password too near the duress
/// password), `mismatch`, `hours`, `exists`, `needs_password` (the app password is off), `pro`, `unavailable` or
/// `generic` (the plain "couldn't save" every refusal inside a duress session ends with).
public struct DuressError: Error, Equatable, Sendable {
    public let code: String
    public init(_ code: String) { self.code = code }
}

/// Where the second vault lives (sub-plan 08, Task 5c; Android `DuressFiles`): its own folder `.lgk-d` in the app
/// group with its own app-password file, store (with its own local data: Recently deleted and reminders) and sealed
/// settings, so nothing it writes touches the real vault's files. `hold` (until when the real vault is held) and
/// `real` (the real vault's sealed duress record) sit beside the real vault.
public struct DuressFiles: Sendable {
    public static let dirName = ".lgk-d"
    public let dir: URL
    public let hold: URL
    public let real: URL

    public init(dir: URL, hold: URL, real: URL) { self.dir = dir; self.hold = hold; self.real = real }

    public var record: URL { dir.appendingPathComponent("app-password.json") }
    public var vault: URL { dir.appendingPathComponent("Vault", isDirectory: true) }
    public var config: URL { dir.appendingPathComponent("config.bin") }
    /// Present while a second-vault session is open in the app.
    public var session: URL { dir.appendingPathComponent("session") }

    public static func under(_ container: URL) -> DuressFiles {
        DuressFiles(dir: container.appendingPathComponent(dirName, isDirectory: true),
                    hold: container.appendingPathComponent("vault.hold.json"),
                    real: container.appendingPathComponent("duress.bin"))
    }
}

/// The open duress session of this process (the app; the AutoFill extension never opens one). The hold file on disk
/// is what other processes see.
public final class DuressSession: @unchecked Sendable {
    public static let shared = DuressSession()
    public init() {}
    private let lock = NSLock()
    private var open = false
    private var dir: URL?
    public var isOpen: Bool { lock.withLock { open } }
    /// The open session's second-vault folder (`DuressFiles.dir`), nil while none is open: on the Mac each profile has
    /// its own, so its documents and received shares follow the session rather than one fixed container.
    public var secondDir: URL? { lock.withLock { open ? dir : nil } }
    public func set(_ on: Bool, dir: URL? = nil) { lock.withLock { open = on; self.dir = on ? dir : nil } }
}

/// The duress password on the iPhone (sub-plan 08, Task 5c; Android `DuressVault`, desktop `duress.py`): a second
/// app password that opens a separate, plausible vault (`DuressFiles`) and holds the real one for the chosen hours.
/// It needs the app password (the unlock screen's password field is what a coercer sees).
///
/// Ruling T4: the second Argon2id runs only when this vault exists (`configured`); then both run on every
/// app-password unlock, so the time taken does not tell which one opened. While held, the real app password, the
/// Face ID shortcut and the recovery phrase are all refused as if wrong. A session opened here gets no sync, no
/// Safari or AutoFill data and no passkeys, and nothing on screen names it. Blocking: call off the main actor. Never
/// logs or stores a password.
public final class PhoneDuress: @unchecked Sendable {
    public static let minHours = 1
    public static let maxHours = 168
    public static let defaultHours = 24
    /// The hours Settings offers.
    public static let hourChoices = [1, 2, 4, 8, 12, 24, 48, 72, 168]
    /// Passwords longer than this keep only the exact checks.
    static let nearLimit = 256
    static let configInfo = Array("LocalGateKeys duress config v1".utf8)
    static let realInfo = Array("LocalGateKeys duress real v1".utf8)

    public let files: DuressFiles
    /// The copies of the hold and the session marker in the Safari app group (`SafariSaveFiles.duressMirror`), kept in
    /// step with `files` here so the Safari extension, which holds no other group, can tell it is blocked
    /// (`SafariSaveService.duressBlocked`); nil in the extensions and tests.
    public let mirror: DuressFiles?
    private let random: any RandomSource
    private let now: @Sendable () -> Int64
    private let bootTime: @Sendable () -> BootTime
    private let params: MasterKeyFile.KDFParams
    public let session: DuressSession

    /// Which boot this is and its monotonic seconds (`CLOCK_MONOTONIC`: asleep included, never moved by setting the
    /// date). The hold counts on it as well as on the wall clock (audit 2026-11-10).
    public struct BootTime: Sendable, Equatable {
        public let boot: String?
        public let seconds: Int64
        public init(boot: String?, seconds: Int64) { self.boot = boot; self.seconds = seconds }
    }

    public init(files: DuressFiles, mirror: DuressFiles? = nil, random: any RandomSource = SystemRandomSource(),
                params: MasterKeyFile.KDFParams = .default, session: DuressSession = .shared,
                now: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970) },
                bootTime: @escaping @Sendable () -> BootTime = { PhoneDuress.systemBootTime() }) {
        self.files = files; self.mirror = mirror; self.random = random; self.params = params; self.session = session
        self.now = now; self.bootTime = bootTime
    }

    public static func systemBootTime() -> BootTime {
        BootTime(boot: bootSessionID(), seconds: Int64(SystemMonotonicClock().seconds))
    }

    /// This boot's identifier (`kern.bootsessionuuid`, as `SystemBootClock.bootID`), nil when unknown.
    static func bootSessionID() -> String? {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &buf, &size, nil, 0) == 0 else { return nil }
        let id = String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return id.isEmpty ? nil : id
    }

    /// The app's duress files, or nil without the app-group container. Mirrored into the Safari group when the process
    /// holds it (the app; never the AutoFill extension).
    public static func shared() -> PhoneDuress? {
        AppGroup.containerURL.map { PhoneDuress(files: .under($0), mirror: SafariSaveFiles.duressMirror()) }
    }

    public var configured: Bool { FileManager.default.fileExists(atPath: files.record.path) }

    private func readRecord() -> MasterKeyFile? {
        guard let data = FileManager.default.contents(atPath: files.record.path) else { return nil }
        return try? JSONDecoder().decode(MasterKeyFile.self, from: data)
    }

    private func writeRecord(_ file: MasterKeyFile) throws {
        let enc = JSONEncoder()
        enc.outputFormatting = .sortedKeys
        try enc.encode(file).write(to: files.record, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    /// The second vault's local key for `password` (the caller zeroes it), else nil; one Argon2id run when configured.
    public func tryOpen(password: String) -> [UInt8]? {
        guard let file = readRecord() else { return nil }
        return try? file.open(password: password)
    }

    // MARK: the hold

    /// Until when (Unix seconds) the real vault is held, else nil. An unreadable hold file fails closed.
    ///
    /// Audit 2026-11-10: setting the date forward does not end the hold. A hold written with its monotonic anchor
    /// (`mono`, `boot`) ends only once the wall clock has passed `until` and the monotonic clock has also counted the
    /// hold's length (`until - since`). A restart sets the monotonic clock back to zero, so after one only the time
    /// since that restart counts: a restart can make the hold longer, never shorter. A hold an earlier build wrote
    /// (no anchor) uses the wall clock alone, as before.
    public func heldUntil(at time: Int64? = nil) -> Int64? {
        let t = time ?? now()
        let fm = FileManager.default
        guard fm.fileExists(atPath: files.hold.path) else { return nil }
        guard let data = fm.contents(atPath: files.hold.path) else { return t + 60 }   // cannot even look: a minute
        let until: Int64
        if data.count <= 4096, case .object(let o)? = try? CanonicalJSON.parse(Array(data)), case .int(let u)? = o["until"] {
            until = u
            if case .int(let since)? = o["since"], case .int(let mono)? = o["mono"], until > since {
                var boot: String?
                if case .string(let b)? = o["boot"] { boot = b }
                let remaining = Self.monotonicRemaining(length: until - since, mono: mono, boot: boot, now: bootTime())
                if remaining > 0 { return max(until, t + remaining) }
            }
        } else {
            let modified = (try? fm.attributesOfItem(atPath: files.hold.path)[.modificationDate] as? Date) ?? Date()
            until = Int64(modified.timeIntervalSince1970) + Int64(Self.maxHours) * 3600
        }
        return until > t ? until : nil
    }

    /// The seconds of a hold of `length` still to run on the monotonic clock, anchored at `mono` in boot `boot`. After
    /// a restart (another boot, or the clock below the anchor) only the seconds since that restart count, so the count
    /// is never more than the time that really passed.
    static func monotonicRemaining(length: Int64, mono: Int64, boot: String?, now: BootTime) -> Int64 {
        let restarted = (boot != nil && now.boot != nil && boot != now.boot) || now.seconds < mono
        let counted = restarted ? now.seconds : now.seconds - mono
        return length - max(counted, 0)
    }

    public func held() -> Bool { heldUntil() != nil }

    /// A duress session is open (in this process, or in the app as seen from an extension through the marker) or
    /// the real vault is held: AutoFill, passkeys, Safari Save and real reminders offer nothing.
    public func servicesBlocked() -> Bool {
        session.isOpen || FileManager.default.fileExists(atPath: files.session.path) || held()
    }

    /// The second vault opened: the session flag and its marker for the extensions (review M5: a hold that ends
    /// while the session is still open blocks nothing, the marker does). A marker left by a killed app keeps the
    /// extensions closed until the next real unlock, which fails closed.
    public func openSession() {
        session.set(true, dir: files.dir)
        try? Data().write(to: files.session, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        syncMirror()
    }

    /// A lock or a real unlock: no second-vault session any more.
    public func closeSession() {
        session.set(false)
        try? FileManager.default.removeItem(at: files.session)
        syncMirror()
    }

    /// Makes the Safari group's copies match the files here: the session marker while one is open, the hold file's
    /// bytes while it exists (an unreadable hold becomes an empty copy, which reads as held: fails closed). Called after
    /// each change and at every app launch (copies from before the Safari group, or a change a crash cut short).
    /// Best effort; a no-op without a mirror.
    public func syncMirror() {
        guard let mirror else { return }
        let fm = FileManager.default
        try? fm.createDirectory(at: mirror.dir, withIntermediateDirectories: true)
        LocalStore.excludeFromBackup(mirror.dir)
        if session.isOpen || fm.fileExists(atPath: files.session.path) {
            if !fm.fileExists(atPath: mirror.session.path) {
                try? Data().write(to: mirror.session, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            }
        } else {
            try? fm.removeItem(at: mirror.session)
        }
        if fm.fileExists(atPath: files.hold.path) {
            let bytes = fm.contents(atPath: files.hold.path) ?? Data()
            if fm.contents(atPath: mirror.hold.path) != bytes {
                try? bytes.write(to: mirror.hold, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            }
        } else {
            try? fm.removeItem(at: mirror.hold)
        }
    }

    /// Holds the real vault after a duress unlock; returns until when. Never shortens an earlier hold.
    @discardableResult
    public func trip(decoyKey: [UInt8]) throws -> Int64 {
        let t = now()
        var until = t + Int64(hours(decoyKey: decoyKey)) * 3600
        if let earlier = heldUntil(at: t) { until = max(until, earlier) }
        // The monotonic anchor (audit 2026-11-10); an earlier build reads only `since` and `until`.
        let clock = bootTime()
        var fields: [String: JSONValue] = ["version": .int(1), "since": .int(t), "until": .int(until),
                                           "mono": .int(clock.seconds)]
        if let boot = clock.boot { fields["boot"] = .string(boot) }
        let body: JSONValue = .object(fields)
        try Data(try CanonicalJSON.encode(body, dialect: .utf8))
            .write(to: files.hold, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        syncMirror()
        return until
    }

    /// After a real unlock: removes a finished hold; returns when the duress password was used (else nil).
    @discardableResult
    public func release() -> Int64? {
        let fm = FileManager.default
        guard fm.fileExists(atPath: files.hold.path), heldUntil() == nil else { return nil }
        var since: Int64 = 0
        if let data = fm.contents(atPath: files.hold.path), case .object(let o)? = try? CanonicalJSON.parse(Array(data)),
           case .int(let s)? = o["since"] { since = s }
        try? fm.removeItem(at: files.hold)
        syncMirror()
        return since
    }

    // MARK: sealed records

    private func seal(_ key: [UInt8], info: [UInt8], _ value: JSONValue) throws -> Data {
        var k = CryptoBox.hkdf(ikm: key, salt: [], info: info, length: 32)
        defer { for i in k.indices { k[i] = 0 } }
        let nonce = random.bytes(count: 12)
        return Data(nonce + (try CryptoBox.sealGCM(key: k, nonce: nonce, plaintext: try CanonicalJSON.encode(value, dialect: .utf8), aad: info)))
    }

    private func open(_ key: [UInt8], info: [UInt8], _ url: URL) -> [String: JSONValue]? {
        guard let data = FileManager.default.contents(atPath: url.path), data.count > 12 + 16 else { return nil }
        var k = CryptoBox.hkdf(ikm: key, salt: [], info: info, length: 32)
        defer { for i in k.indices { k[i] = 0 } }
        let bytes = Array(data)
        guard let plain = try? CryptoBox.openGCM(key: k, nonce: Array(bytes[0..<12]), ciphertext: Array(bytes[12...]), aad: info),
              case .object(let o)? = try? CanonicalJSON.parse(plain) else { return nil }
        return o
    }

    /// The hours this second vault holds the real one for (from its own sealed settings).
    public func hours(decoyKey: [UInt8]) -> Int {
        if case .int(let h)? = open(decoyKey, info: Self.configInfo, files.config)?["hours"],
           (Int64(Self.minHours)...Int64(Self.maxHours)).contains(h) { return Int(h) }
        return Self.defaultHours
    }

    /// The real vault's duress hours, for Settings (nil: not set up or unreadable).
    public func realHours(realKey: [UInt8]) -> Int? {
        guard configured, case .int(let h)? = open(realKey, info: Self.realInfo, files.real)?["hours"] else { return nil }
        return Int(h)
    }

    // MARK: setup, removal and the real password's distance

    /// Creates the second vault for the real session (`realKey`). `appPassword` is the real app password, already
    /// checked by the caller; a duress password equal to it or one edit away is refused. `seed` fills the new vault's
    /// store. Inside a duress session (`decoySession`) every check runs and then `generic` is thrown with nothing
    /// written. Argon2id runs once (call it off the main actor).
    public func setup(realKey: [UInt8], appPassword: String, duressPassword: String, hours: Int, decoySession: Bool,
                      seed: (any ItemStore) throws -> Void) throws {
        guard (Self.minHours...Self.maxHours).contains(hours) else { throw DuressError("hours") }
        if Self.withinOneEdit(appPassword, duressPassword) {
            throw DuressError(appPassword.utf8.elementsEqual(duressPassword.utf8) ? "same" : "close")
        }
        if decoySession { throw DuressError("generic") }
        if configured { throw DuressError("exists") }
        let fm = FileManager.default
        try? fm.removeItem(at: files.dir)   // leftovers of an earlier second vault
        var key = random.bytes(count: 32)
        defer { for i in key.indices { key[i] = 0 } }
        do {
            try fm.createDirectory(at: files.dir, withIntermediateDirectories: true)
            LocalStore.excludeFromBackup(files.dir)
            let record = try MasterKeyFile.seal(localKey: key, password: duressPassword, params: params, random: random)
            let store = try LocalStore(directory: files.vault, key: key, random: random)
            try seed(store)
            try seal(key, info: Self.configInfo, .object(["hours": .int(Int64(hours))]))
                .write(to: files.config, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            var real: [String: JSONValue] = ["hours": .int(Int64(hours)), "created": .int(now())]
            if let near = nearRecord(duressPassword) { real["near"] = near }
            try seal(realKey, info: Self.realInfo, .object(real))
                .write(to: files.real, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            // Last: the record is what makes the second vault exist.
            try writeRecord(record)
        } catch {
            try? fm.removeItem(at: files.dir)
            try? fm.removeItem(at: files.real)
            throw error
        }
    }

    /// Removes the second vault, its hold and the real vault's record. False when there was none.
    @discardableResult
    public func remove(decoySession: Bool) throws -> Bool {
        if decoySession { throw DuressError("generic") }
        let existed = configured
        _ = eraseAll()
        return existed
    }

    #if os(iOS)
    /// "Change app password" inside a duress session (Ruling T5a-b): changes the second vault's password only, with no
    /// visible refusal. `current` must open the second vault's record to the open session's key (`decoyKey`); nothing
    /// is tried against the real vault (no oracle there). Throttled like the real change through `throttle` (the app
    /// password's one wrong-try count): refused during the delay before any Argon2id run, a wrong current password
    /// counted, a right one resets the count.
    public func changeSecondPassword(decoyKey: [UInt8], current: String, new: String, throttle: AppPasswordStore) throws {
        let wait = throttle.waitSeconds()
        if wait > 0 { throw AppPasswordError.wait(seconds: wait) }
        var opened = tryOpen(password: current) ?? []
        defer { for i in opened.indices { opened[i] = 0 } }
        guard !opened.isEmpty, Envelope.same(opened, decoyKey) else {
            throttle.noteWrongTry()
            throw AppPasswordError.wrongPassword
        }
        throttle.clearFailures()
        try writeRecord(try MasterKeyFile.seal(localKey: decoyKey, password: new, params: params, random: random))
    }
    #endif

    /// The second vault's password changed inside its own session (the Mac's "Change master password" there): its
    /// record is sealed again over the same key under `password`, with this vault's KDF parameters. The caller has
    /// checked the current password against the record and the throttle. Argon2id runs once (call it off the main actor).
    public func resealSecond(key: [UInt8], password: String) throws {
        guard configured else { throw DuressError("generic") }
        try writeRecord(try MasterKeyFile.seal(localKey: key, password: password, params: params, random: random))
    }

    /// The real vault's sealed duress record (`files.real`) sealed again under `newKey`, for a key rotation of the real
    /// vault (the Mac's password change, recovery phrase change or recovery); nil when there is none or it cannot be
    /// read under `oldKey` (then it is left as it is).
    public func resealedReal(oldKey: [UInt8], newKey: [UInt8]) -> Data? {
        guard FileManager.default.fileExists(atPath: files.real.path),
              let fields = open(oldKey, info: Self.realInfo, files.real) else { return nil }
        return try? seal(newKey, info: Self.realInfo, .object(fields))
    }

    /// "Erase this iPhone's vault" inside a duress session (Ruling T5a-b): only the second vault's data goes (its
    /// store and local data); the real vault, the hold and the second vault's password stay, so the duress password
    /// then opens an empty vault. True when that data is gone.
    @discardableResult
    public func eraseSecondVault() -> Bool {
        let fm = FileManager.default
        let keep: Set<String> = [files.record.lastPathComponent, files.config.lastPathComponent]
        var ok = true
        for name in (try? fm.contentsOfDirectory(atPath: files.dir.path)) ?? [] where !keep.contains(name) {
            let url = files.dir.appendingPathComponent(name)
            if (try? fm.removeItem(at: url)) == nil, fm.fileExists(atPath: url.path) { ok = false }
        }
        return ok
    }

    /// Erase, turning the app password off, or removal: everything of the second vault goes (true when nothing is left).
    @discardableResult
    public func eraseAll() -> Bool {
        let fm = FileManager.default
        for url in [files.dir, files.hold, files.real] { try? fm.removeItem(at: url) }
        syncMirror()
        return ![files.dir, files.hold, files.real].contains { fm.fileExists(atPath: $0.path) }
    }

    /// Before the real app password changes (or is reset with the recovery phrase): refuses the duress password and
    /// anything one edit from it (`near_duress`), from the fingerprint kept at setup and an exact try of the second
    /// vault. A duress session checks nothing (desktop review R2: no oracle against the real vault from there).
    public func checkNewPassword(realKey: [UInt8], newPassword: String, decoySession: Bool) throws {
        if decoySession || !configured { return }
        if let near = open(realKey, info: Self.realInfo, files.real)?["near"], isNear(near, newPassword) {
            throw DuressError("near_duress")
        }
        if var key = tryOpen(password: newPassword) {
            for i in key.indices { key[i] = 0 }
            throw DuressError("near_duress")
        }
    }

    // MARK: the one-edit fingerprint (desktop `_near_record`)

    private static func mac(_ key: [UInt8], _ tag: String, _ data: [UInt8]) -> [UInt8] {
        let code = HMAC<SHA256>.authenticationCode(for: Array(tag.utf8) + data, using: SymmetricKey(data: key))
        return Array(Array(code).prefix(16))
    }

    private static func utf8(_ points: [UInt32]) -> [UInt8] {
        var s = String.UnicodeScalarView()
        for p in points { if let u = Unicode.Scalar(p) { s.append(u) } }
        return Array(String(s).utf8)
    }

    private static func points(_ text: String) -> [UInt32] { text.unicodeScalars.map(\.value) }

    private struct NearHashes { let whole: [UInt8]; let deletions: Set<String>; let positional: Set<String> }

    private static func nearHashes(_ key: [UInt8], _ password: String) -> NearHashes {
        let p = points(password)
        var deletions = Set<String>(), positional = Set<String>()
        for i in p.indices {
            var rest = p; rest.remove(at: i)
            let bytes = utf8(rest)
            deletions.insert(Base64.encode(mac(key, "U|", bytes)))
            positional.insert(Base64.encode(mac(key, "P\(i)|", bytes)))
        }
        return NearHashes(whole: mac(key, "U|", utf8(p)), deletions: deletions, positional: positional)
    }

    private func nearRecord(_ password: String) -> JSONValue? {
        guard Self.points(password).count <= Self.nearLimit else { return nil }
        var key = random.bytes(count: 32)
        defer { for i in key.indices { key[i] = 0 } }
        let h = Self.nearHashes(key, password)
        return .object(["key": .string(Base64.encode(key)), "whole": .string(Base64.encode(h.whole)),
                        "deletions": .array(h.deletions.sorted().map { .string($0) }),
                        "positional": .array(h.positional.sorted().map { .string($0) })])
    }

    private func isNear(_ record: JSONValue, _ password: String) -> Bool {
        guard case .object(let r) = record, case .string(let k)? = r["key"], case .string(let w)? = r["whole"],
              case .array(let d)? = r["deletions"], case .array(let p)? = r["positional"],
              let key = try? Base64.decodeStrict(k), let wholeBytes = try? Base64.decodeStrict(w) else { return false }
        guard Self.points(password).count <= Self.nearLimit + 1 else { return false }
        let whole = Base64.encode(wholeBytes)
        let deletions = Set(d.compactMap { if case .string(let s) = $0 { return s } else { return nil } })
        let positional = Set(p.compactMap { if case .string(let s) = $0 { return s } else { return nil } })
        let mine = Self.nearHashes(key, password)
        let m = Base64.encode(mine.whole)
        return m == whole || deletions.contains(m) || mine.deletions.contains(whole) || !positional.isDisjoint(with: mine.positional)
    }

    /// Whether two passwords are equal or one insertion, deletion or substitution apart (Unicode code points).
    public static func withinOneEdit(_ first: String, _ second: String) -> Bool {
        var a = points(first), b = points(second)
        if a.count < b.count { swap(&a, &b) }
        if a.count - b.count > 1 { return false }
        var i = 0
        while i < b.count && a[i] == b[i] { i += 1 }
        if a.count == b.count { return Array(a[min(i + 1, a.count)...]) == Array(b[min(i + 1, b.count)...]) }
        return Array(a[min(i + 1, a.count)...]) == Array(b[i...])
    }
}

/// Which vault an app-password unlock opened.
public enum DuressOpened: Sendable {
    case real([UInt8])
    case second([UInt8])
}

#if os(iOS)
/// The app-password unlock with the duress password (Android `VaultOpener.openWithDuress`): the real vault first,
/// then the second one. Without a second vault only the real derivation runs (Ruling T4). With one, both run on every
/// try (a held real password still costs its derivation), so the time does not tell which opened.
public enum DuressUnlock {
    /// Call it detached (Argon2id runs on the calling task).
    public static func open(password: String, factors: FactorSecrets, store: AppPasswordStore,
                            duress: PhoneDuress?) async throws -> DuressOpened {
        guard let duress, duress.configured else {
            let key = try await store.open(password: password, factors: factors)
            duress?.release()
            return .real(key)
        }
        let wait = store.waitSeconds()
        if wait > 0 { throw AppPasswordError.wait(seconds: wait) }
        let held = duress.held()
        let before = store.failureCount
        var real: [UInt8]?
        var realError: (any Error)?
        do { real = try await store.open(password: password, factors: factors) } catch { realError = error }
        if held, var k = real {
            // While held the real password is refused as if wrong (and counted as one).
            for i in k.indices { k[i] = 0 }
            real = nil
            store.noteWrongTry(after: before)
            realError = AppPasswordError.wrongPassword
        }
        let second = duress.tryOpen(password: password)
        if let real {
            if var s = second { for i in s.indices { s[i] = 0 } }
            duress.release()
            return .real(real)
        }
        if var s = second {
            store.clearFailures()   // a wrong real try was counted by `open`; this unlock is a right one
            do { try duress.trip(decoyKey: s) } catch {
                for i in s.indices { s[i] = 0 }
                throw AppPasswordError.wrongPassword
            }
            return .second(s)
        }
        // Neither: a missing key file or YubiKey of the real vault says so (never counted), else a wrong password.
        throw realError ?? AppPasswordError.wrongPassword
    }

    /// The local key from the recovery phrase; while the real vault is held a right phrase is refused as wrong after
    /// the same work and counted like a wrong one (no faster answer, no different delay). Call it detached.
    public static func openPhrase(_ phrase: String, store: AppPasswordStore, duress: PhoneDuress?) throws -> [UInt8] {
        let held = duress.map { $0.configured && $0.held() } ?? false
        let before = store.failureCount
        var key = try store.open(phrase: phrase)
        guard held else { return key }
        for i in key.indices { key[i] = 0 }
        store.noteWrongTry(after: before)
        throw AppPasswordError.wrongPhrase
    }
}
#endif
