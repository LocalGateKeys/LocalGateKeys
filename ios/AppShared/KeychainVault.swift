import Foundation
import Security
import LocalAuthentication
import LGKCore

/// The secrets kept in the Keychain. Raw values are the Keychain account names.
/// Sync secrets (device identity, group key, keyring) live in the sealed store blob, not here.
public enum VaultSlot: String, CaseIterable, Sendable {
    case localKey = "local-key"
    case helloCounter = "hello-counter"
    case peerCounters = "peer-counters"
    case folderBookmark = "folder-bookmark"
    /// The one LAN peer this phone was paired with by QR (canonical JSON, public keys and endpoint only).
    case pairedPeer = "paired-peer"
    /// This installation's sync install id (Keychain items are this-device-only, so a restore gets a new one).
    case installID = "install-id"
    /// Safari save: HMAC key of the fingerprint index (32 random bytes, created by the app at unlock).
    case safariIndexKey = "safari-index-key"
    /// Safari save: AES-256-GCM key of the inbox the Safari extension writes (32 random bytes).
    case safariInboxKey = "safari-inbox-key"

    /// Slots only the main app reads (sync). They live in the app-only Keychain access group, never the
    /// group shared with the AutoFill extension.
    public static let appOnly: Set<VaultSlot> = [.pairedPeer, .installID, .folderBookmark]

    /// Slots the Safari extension reads without Face ID: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
    /// with no `.userPresence`, in their own Safari group (`SafariKeychainVault`; audit 2026-10-24 L-8), which
    /// is the only group the Safari extension is entitled to. Never `appOnly`.
    public static let deviceUnlocked: Set<VaultSlot> = [.safariIndexKey, .safariInboxKey]
}

/// The Keychain slots sync uses, and only those.
public enum SyncSlot: Sendable, CaseIterable {
    case pairedPeer, installID, folderBookmark, peerCounters
    public var vaultSlot: VaultSlot {
        switch self {
        case .pairedPeer: .pairedPeer
        case .installID: .installID
        case .folderBookmark: .folderBookmark
        case .peerCounters: .peerCounters
        }
    }
}

/// The narrow Keychain surface the sync code depends on (not the local key, not the hello counter block).
public protocol SyncKeychain: AnyObject, Sendable {
    func readSlot(_ slot: SyncSlot) throws -> [UInt8]?
    func writeSlot(_ slot: SyncSlot, _ bytes: [UInt8]) throws
    func deleteSlot(_ slot: SyncSlot) throws
}

public enum KeychainVaultError: Error, Equatable {
    case status(OSStatus)
    case accessControl
    case malformed(VaultSlot)
}

/// Byte storage for secrets. Tests use `InMemoryKeychainVault`; the app and extension use `SystemKeychainVault`.
public protocol KeychainVault: SyncKeychain {
    func read(_ slot: VaultSlot) throws -> [UInt8]?
    func write(_ slot: VaultSlot, _ bytes: [UInt8]) throws
    func delete(_ slot: VaultSlot) throws
}

extension KeychainVault {
    public func readSlot(_ slot: SyncSlot) throws -> [UInt8]? { try read(slot.vaultSlot) }
    public func writeSlot(_ slot: SyncSlot, _ bytes: [UInt8]) throws { try write(slot.vaultSlot, bytes) }
    public func deleteSlot(_ slot: SyncSlot) throws { try delete(slot.vaultSlot) }

    public func readInt64(_ slot: VaultSlot) throws -> Int64? {
        guard let b = try read(slot) else { return nil }
        guard b.count == 8 else { throw KeychainVaultError.malformed(slot) }
        return b.reduce(Int64(0)) { ($0 << 8) | Int64($1) }
    }

    public func writeInt64(_ slot: VaultSlot, _ v: Int64) throws {
        try write(slot, (0..<8).reversed().map { UInt8(truncatingIfNeeded: v >> ($0 * 8)) })
    }
}

extension SyncKeychain {
    /// The paired LAN peer, or nil. A stored peer whose endpoint is not a LAN address is refused.
    public func pairedPeer() throws -> PinnedPeer? {
        guard let b = try readSlot(.pairedPeer) else { return nil }
        guard case .object(let o) = try CanonicalJSON.parse(b),
              case .string(let id)? = o["device_id"], case .string(let group)? = o["group_id"],
              case .string(let sign)? = o["signing_public"], case .string(let exch)? = o["exchange_public"],
              let signing = try? Base64.decodeStrict(sign), let exchange = try? Base64.decodeStrict(exch) else {
            throw KeychainVaultError.malformed(.pairedPeer)
        }
        var endpoint: LanEndpoint?
        if case .object(let e)? = o["endpoint"] {
            guard case .string(let host)? = e["host"], case .int(let port)? = e["port"],
                  let ep = try? LanEndpoint(validating: host, port: Int(port)) else { throw KeychainVaultError.malformed(.pairedPeer) }
            endpoint = ep
        }
        return PinnedPeer(deviceID: id, groupID: group, signingPublic: signing, exchangePublic: exchange, endpoint: endpoint)
    }

    public func setPairedPeer(_ peer: PinnedPeer) throws {
        var o: [String: JSONValue] = [
            "device_id": .string(peer.deviceID), "group_id": .string(peer.groupID),
            "signing_public": .string(Base64.encode(peer.signingPublic)),
            "exchange_public": .string(Base64.encode(peer.exchangePublic)), "endpoint": .null,
        ]
        if let ep = peer.endpoint { o["endpoint"] = .object(["host": .string(ep.host), "port": .int(Int64(ep.port))]) }
        try writeSlot(.pairedPeer, try CanonicalJSON.encode(.object(o), dialect: .utf8))
    }

    /// This installation's install id, created (32 hex chars) on first use.
    public func installID(random: any RandomSource) throws -> String {
        if let b = try readSlot(.installID) {
            guard let s = String(bytes: b, encoding: .utf8), !s.isEmpty else { throw KeychainVaultError.malformed(.installID) }
            return s
        }
        let id = random.bytes(count: 16).map { String(format: "%02x", $0) }.joined()
        try writeSlot(.installID, Array(id.utf8))
        return id
    }
}

/// Whether a Keychain item exists, from an attributes-only query that never shows UI or decrypts.
public enum KeychainItemPresence: Equatable, Sendable { case absent, present, unknown }

/// A vault that can tell whether a slot's item still exists without reading its secret
/// (`VaultEraser` uses it when a delete is refused while the device cannot authenticate).
public protocol KeychainPresenceChecking {
    func presence(_ slot: VaultSlot) -> KeychainItemPresence
}

/// Keychain generic passwords, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` + `.userPresence`, in the
/// shared access group so the AutoFill extension reads the same items. `VaultSlot.deviceUnlocked` slots
/// get no `.userPresence` (readable whenever the device is unlocked).
public final class SystemKeychainVault: KeychainVault, @unchecked Sendable {
    public static let service = "com.localgatekeys.vault"
    let accessGroup: String?
    /// An authenticated context lets one Face ID prompt cover several reads.
    let context: LAContext?

    public init(accessGroup: String? = AppGroup.keychainAccessGroup, context: LAContext? = nil) {
        self.accessGroup = accessGroup; self.context = context
    }

    private func base(_ slot: VaultSlot) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: Self.service,
                                kSecAttrAccount as String: slot.rawValue,
                                kSecUseDataProtectionKeychain as String: true]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        if let context { q[kSecUseAuthenticationContext as String] = context }
        return q
    }

    public func read(_ slot: VaultSlot) throws -> [UInt8]? {
        var q = base(slot)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecItemNotFound { return nil }
        guard st == errSecSuccess, let d = out as? Data else { throw KeychainVaultError.status(st) }
        return Array(d)
    }

    public func write(_ slot: VaultSlot, _ bytes: [UInt8]) throws {
        // Update in place (keeps the item's access control); add only when absent. Never delete first,
        // so a crash mid-write cannot lose the local key or a reserved counter block.
        let st = SecItemUpdate(base(slot) as CFDictionary, [kSecValueData as String: Data(bytes)] as CFDictionary)
        if st == errSecSuccess { return }
        guard st == errSecItemNotFound else { throw KeychainVaultError.status(st) }
        let flags: SecAccessControlCreateFlags = VaultSlot.deviceUnlocked.contains(slot) ? [] : .userPresence
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       flags, nil) else { throw KeychainVaultError.accessControl }
        var q = base(slot)
        q[kSecValueData as String] = Data(bytes)
        q[kSecAttrAccessControl as String] = ac
        let added = SecItemAdd(q as CFDictionary, nil)
        guard added == errSecSuccess else { throw KeychainVaultError.status(added) }
    }

    public func delete(_ slot: VaultSlot) throws {
        let st = SecItemDelete(base(slot) as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw KeychainVaultError.status(st) }
    }
}

extension SystemKeychainVault: KeychainPresenceChecking {
    /// Attributes only (no data, so the item's `.userPresence` ACL is not evaluated), with a context that
    /// forbids any authentication UI. Anything but found / not found is `.unknown`.
    public func presence(_ slot: VaultSlot) -> KeychainItemPresence {
        let noUI = LAContext()
        noUI.interactionNotAllowed = true
        var q = base(slot)
        q[kSecUseAuthenticationContext as String] = noUI
        q[kSecReturnAttributes as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        switch SecItemCopyMatching(q as CFDictionary, &out) {
        case errSecSuccess: return .present
        case errSecItemNotFound: return .absent
        default: return .unknown
        }
    }
}

/// The app's view of the two Safari keys (`VaultSlot.deviceUnlocked`): they live in the Safari access group,
/// the only Keychain group the Safari extension is entitled to (audit 2026-10-24 L-8; earlier builds kept them
/// in the group shared with AutoFill, which gave the extension that whole group). Keys an earlier build left
/// in the shared group are moved on first use, byte for byte, so the inbox sealed under the old key still
/// opens: copied to the Safari group, then deleted from the shared one. Every other slot goes to `base`.
public final class SafariKeychainVault: KeychainVault, @unchecked Sendable {
    public let base: any KeychainVault
    public let safari: any KeychainVault
    /// The shared group, read and cleaned without an authentication context (these slots need no Face ID).
    public let legacy: any KeychainVault
    private let lock = NSLock()

    public init(base: any KeychainVault, safari: any KeychainVault, legacy: any KeychainVault) {
        self.base = base; self.safari = safari; self.legacy = legacy
    }

    /// Moves both Safari keys still in the shared group. Safe to call on every unlock.
    public func migrate() throws { for slot in VaultSlot.deviceUnlocked { _ = try read(slot) } }

    public func read(_ slot: VaultSlot) throws -> [UInt8]? {
        guard VaultSlot.deviceUnlocked.contains(slot) else { return try base.read(slot) }
        return try lock.withLock {
            if let b = try safari.read(slot) {
                try? legacy.delete(slot)   // best effort: a leftover copy from an interrupted move
                return b
            }
            guard let old = try legacy.read(slot) else { return nil }
            try safari.write(slot, old)  // copy first, so a crash never loses the key (or the inbox it opens)
            try? legacy.delete(slot)     // best effort; the next read retries the cleanup
            return old
        }
    }

    public func write(_ slot: VaultSlot, _ bytes: [UInt8]) throws {
        guard VaultSlot.deviceUnlocked.contains(slot) else { return try base.write(slot, bytes) }
        try lock.withLock { try safari.write(slot, bytes); try? legacy.delete(slot) }
    }

    public func delete(_ slot: VaultSlot) throws {
        guard VaultSlot.deviceUnlocked.contains(slot) else { return try base.delete(slot) }
        try lock.withLock { try safari.delete(slot); try? legacy.delete(slot) }
    }
}

/// The main app's vault: `VaultSlot.appOnly` slots go to the app-only access group (the AutoFill extension
/// cannot read them); every other slot stays in the shared group. Items written by earlier builds to the
/// shared group are moved on first use: copied to the app-only group, then deleted from the shared one.
public final class AppKeychainVault: KeychainVault, @unchecked Sendable {
    public let shared: any KeychainVault
    public let appOnly: any KeychainVault
    private let lock = NSLock()

    public init(shared: any KeychainVault, appOnly: any KeychainVault) {
        self.shared = shared; self.appOnly = appOnly
    }

    /// The app-only group to use, or nil to keep sync slots in the shared group: nil when none is configured
    /// or it lacks the team prefix (unsigned builds expand `$(AppIdentifierPrefix)` to nothing), or when
    /// `probe` (a read of the app-only group) fails with a missing-entitlement error.
    public static func appOnlyGroup(configured: String?, probe: (String) throws -> Void) -> String? {
        guard let g = configured, !g.isEmpty, !g.hasPrefix("."), !g.contains("$(") else { return nil }
        do { try probe(g) } catch KeychainVaultError.status(errSecMissingEntitlement) { return nil } catch {}
        return g
    }

    /// Moves every app-only slot still in the shared group. Safe to call on every unlock.
    public func migrate() throws { for slot in VaultSlot.appOnly { _ = try read(slot) } }

    public func read(_ slot: VaultSlot) throws -> [UInt8]? {
        guard VaultSlot.appOnly.contains(slot) else { return try shared.read(slot) }
        return try lock.withLock {
            if let b = try appOnly.read(slot) {
                try? shared.delete(slot)   // best effort: a leftover copy from an interrupted move
                return b
            }
            guard let old = try shared.read(slot) else { return nil }
            try appOnly.write(slot, old)  // copy first, so a crash never loses the item
            try? shared.delete(slot)      // best effort; the next read retries the cleanup
            return old
        }
    }

    public func write(_ slot: VaultSlot, _ bytes: [UInt8]) throws {
        guard VaultSlot.appOnly.contains(slot) else { return try shared.write(slot, bytes) }
        try lock.withLock { try appOnly.write(slot, bytes); try? shared.delete(slot) }
    }

    public func delete(_ slot: VaultSlot) throws {
        guard VaultSlot.appOnly.contains(slot) else { return try shared.delete(slot) }
        try lock.withLock { try appOnly.delete(slot); try? shared.delete(slot) }
    }
}

/// Test double and in-process vault. Records every slot read for assertions.
public final class InMemoryKeychainVault: KeychainVault, @unchecked Sendable {
    private var items: [VaultSlot: [UInt8]] = [:]
    private var log: [VaultSlot] = []
    private let lock = NSLock()

    public init() {}
    public var reads: [VaultSlot] { lock.withLock { log } }

    public func read(_ slot: VaultSlot) throws -> [UInt8]? { lock.withLock { log.append(slot); return items[slot] } }
    public func write(_ slot: VaultSlot, _ bytes: [UInt8]) throws { lock.withLock { items[slot] = bytes } }
    public func delete(_ slot: VaultSlot) throws { _ = lock.withLock { items.removeValue(forKey: slot) } }
}

/// LAN hello counters in the Keychain (`CounterStore`). Each write is a synchronous SecItem call, so a
/// reserved block is durable before `persistHelloCounter` returns. Main app only.
public final class VaultCounterStore: CounterStore, @unchecked Sendable {
    let vault: any KeychainVault
    private let lock = NSLock()
    public init(vault: any KeychainVault) { self.vault = vault }

    public func persistedHelloCounter() throws -> Int64 { try lock.withLock { try vault.readInt64(.helloCounter) ?? 0 } }
    public func persistHelloCounter(_ last: Int64) throws { try lock.withLock { try vault.writeInt64(.helloCounter, last) } }

    public func lastAcceptedCounter(peer: String) throws -> Int64 {
        try lock.withLock { try peers()[peer] ?? 0 }
    }

    public func setLastAcceptedCounter(_ counter: Int64, peer: String) throws {
        try lock.withLock {
            var p = try peers(); p[peer] = counter
            let obj = JSONValue.object(p.mapValues { .int($0) })
            try vault.write(.peerCounters, try CanonicalJSON.encode(obj, dialect: .utf8))
        }
    }

    private func peers() throws -> [String: Int64] {
        guard let b = try vault.read(.peerCounters) else { return [:] }
        guard case .object(let o) = try CanonicalJSON.parse(b) else { throw KeychainVaultError.malformed(.peerCounters) }
        return try o.mapValues { guard case .int(let n) = $0 else { throw KeychainVaultError.malformed(.peerCounters) }; return n }
    }
}
