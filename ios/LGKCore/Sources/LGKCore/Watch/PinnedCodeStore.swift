import Foundation
#if canImport(Security)
import Security
#endif

/// The Keychain surface `PinnedCodeStore` needs: one item per key. Tests inject an in-memory one.
public protocol KeychainAccess: Sendable {
    func store(_ data: Data, key: String) throws
    func load(key: String) -> Data?
    func delete(key: String)
}

/// Sub-plan 06: the 2FA codes pinned on the iPhone, in storage the app's widgets can read too.
/// Pins (item ids only, no secret) are in the app group's defaults. The pinned codes' TOTP parameters are one
/// Keychain item in a Keychain access group of their own (`LGK_CODES_KEYCHAIN_GROUP`, holding nothing else), this
/// device only, never synchronised. With "Forget on lock", `expiresAt` is when the vault counts as locked (the
/// app may be suspended or killed before it can delete the secrets): no code is shown from then on. Only what a code needs is stored (title and TOTP parameters, as `WatchCode`): never a
/// password, username, note or website. At most `maxShown` secrets are kept, the first pins in pin order.
/// Nothing here opens a network connection or logs.
public final class PinnedCodeStore {
    /// The pin list in the app group's defaults.
    public static let pinsKey = "codes.pinnedItemIDs"
    /// Where the iPhone app kept the pin list before (its own `UserDefaults.standard`).
    public static let legacyPinsKey = "watch.pinnedItemIDs"
    /// The Keychain item holding the pinned codes.
    public static let secretsKey = "pinned-codes"
    /// When the codes stop being shown (Unix seconds, app-group defaults); absent: no limit.
    public static let expiryKey = "codes.expiresAt"
    /// Widgets and Shortcuts show at most this many codes; only these secrets are stored.
    public static let maxShown = 4

    /// One code as shown: the code's parameters, its current digits and the seconds left in its period.
    public typealias Shown = (WatchCode, code: String, secondsRemaining: Int)

    private let defaults: UserDefaults
    private let keychain: any KeychainAccess

    public init(defaults: UserDefaults, keychain: any KeychainAccess) {
        self.defaults = defaults
        self.keychain = keychain
    }

    /// The pinned item ids, in pin order (no duplicates, at most `WatchMessage.maxPins`).
    public var pinnedIDs: [String] {
        get { Self.clean(defaults.stringArray(forKey: Self.pinsKey) ?? []) }
        set {
            let ids = Self.clean(newValue)
            if ids.isEmpty { defaults.removeObject(forKey: Self.pinsKey) } else { defaults.set(ids, forKey: Self.pinsKey) }
        }
    }

    /// No code is shown at or after this time (nil: no limit). Not a secret; the widgets end their timeline here.
    public var expiresAt: Date? {
        get {
            guard defaults.object(forKey: Self.expiryKey) != nil else { return nil }
            let t = defaults.double(forKey: Self.expiryKey)
            return Date(timeIntervalSince1970: t.isFinite ? t : 0)   // an unreadable stamp hides everything
        }
        set {
            if let newValue { defaults.set(newValue.timeIntervalSince1970, forKey: Self.expiryKey) }
            else { defaults.removeObject(forKey: Self.expiryKey) }
        }
    }

    /// Stores the secrets of the pinned codes among `codes` (the first `maxShown`, in pin order). A code that is
    /// not pinned is never stored; no pinned code (or a Keychain failure) leaves no secret at all.
    public func replace(_ codes: [WatchCode]) {
        let byID = Dictionary(codes.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        let kept = Array(pinnedIDs.compactMap { byID[$0] }.prefix(Self.maxShown))
        guard !kept.isEmpty, let data = try? WatchMessage.replace(kept).encoded() else {
            forgetSecrets()
            return
        }
        do { try keychain.store(data, key: Self.secretsKey) } catch { forgetSecrets() }
    }

    /// The pinned codes at `date`, in pin order, at most `maxShown`. Empty after `forgetSecrets()` and at or
    /// after `expiresAt`; a code that was unpinned since its secret was stored is not shown.
    public func codes(at date: Date) -> [Shown] {
        let ids = pinnedIDs
        let t = date.timeIntervalSince1970
        if let expiresAt, date >= expiresAt { return [] }
        guard !ids.isEmpty, t.isFinite, t >= 0, t < 1e15,
              let data = keychain.load(key: Self.secretsKey),
              case .replace(let stored)? = try? WatchMessage.decode(data) else { return [] }
        let byID = Dictionary(stored.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        let now = Int64(t.rounded(.down))
        return ids.compactMap { byID[$0] }.prefix(Self.maxShown).compactMap { (c: WatchCode) -> Shown? in
            guard let current = c.current(at: now) else { return nil }
            return (c, code: current.code, secondsRemaining: current.secondsRemaining)
        }
    }

    /// Deletes every stored secret ("Forget Apple Watch codes on lock"); the pin list stays.
    public func forgetSecrets() {
        keychain.delete(key: Self.secretsKey)
    }

    /// Deletes the pin list, the expiry and every secret (vault erased).
    public func removeAll() {
        pinnedIDs = []
        expiresAt = nil
        forgetSecrets()
    }

    /// Moves the pin list from the app's old defaults (`legacyPinsKey`) once, then removes the old key. Pins
    /// already in the new place win. No secret was ever stored on the iPhone before (the watch keeps its own
    /// copy in the watch Keychain), so there is no old secret to move.
    public func migrateLegacy(from legacy: UserDefaults) {
        guard legacy.object(forKey: Self.legacyPinsKey) != nil else { return }
        let old = legacy.stringArray(forKey: Self.legacyPinsKey) ?? []
        if pinnedIDs.isEmpty { pinnedIDs = old }
        legacy.removeObject(forKey: Self.legacyPinsKey)
    }

    /// No empty or repeated ids, at most `WatchMessage.maxPins`.
    private static func clean(_ ids: [String]) -> [String] {
        var seen = Set<String>()
        return Array(ids.filter { !$0.isEmpty && seen.insert($0).inserted }.prefix(WatchMessage.maxPins))
    }
}

/// No Keychain (the codes' group is not configured, e.g. an unsigned build): nothing is stored, nothing is shown.
public struct NoKeychainAccess: KeychainAccess {
    public struct Unavailable: Error {}
    public init() {}
    public func store(_ data: Data, key: String) throws { throw Unavailable() }
    public func load(key: String) -> Data? { nil }
    public func delete(key: String) {}
}

#if canImport(Security)
/// The system Keychain: generic passwords in `accessGroup` (nil: the app's default group),
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` like every other LocalGateKeys Keychain item (the watch's codes
/// included), never synchronised, data protection Keychain on the Mac.
public struct SystemKeychainAccess: KeychainAccess {
    public static let service = "app.localgatekeys.pinned-codes"
    public let accessGroup: String?

    public init(accessGroup: String?) {
        self.accessGroup = accessGroup
    }

    private func query(_ key: String) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: Self.service,
                                kSecAttrAccount as String: key,
                                kSecAttrSynchronizable as String: false,
                                kSecUseDataProtectionKeychain as String: true]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    public func store(_ data: Data, key: String) throws {
        delete(key: key)
        var q = query(key)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }

    public func load(key: String) -> Data? {
        var q = query(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    public func delete(key: String) {
        SecItemDelete(query(key) as CFDictionary)
    }

    /// True when `key` cannot be read until the device is unlocked (`errSecInteractionNotAllowed`): the widgets
    /// then show "Unlock iPhone", not "open the app". The data read on success is dropped at once.
    public func needsDeviceUnlock(key: String) -> Bool {
        var q = query(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecInteractionNotAllowed
    }
}
#endif
