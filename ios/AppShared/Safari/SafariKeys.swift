import Foundation
import LGKCore

/// The two device-only Safari save keys (`VaultSlot.safariIndexKey`, `.safariInboxKey`). The app creates
/// them after each unlock; the Safari extension only reads them, and does nothing while they are missing.
/// They live in the Safari Keychain group (`AppGroup.safariKeychainAccessGroup`, audit 2026-10-24 L-8).
public enum SafariKeys {
    public static let length = 32

    /// The Safari group when it is usable: configured, with the team prefix (unsigned builds expand
    /// `$(AppIdentifierPrefix)` to nothing) and entitled (`probe` does not fail with errSecMissingEntitlement).
    public static func group(configured: String? = AppGroup.safariKeychainAccessGroup,
                             probe: (String) throws -> Void = { _ = try SystemKeychainVault(accessGroup: $0).read(.safariIndexKey) }) -> String? {
        AppKeychainVault.appOnlyGroup(configured: configured, probe: probe)
    }

    /// The app's vault for the Safari keys and everything else: `base` for other slots; the Safari keys in the
    /// Safari group, moved there from the shared group on first use. `base` itself when the Safari group is
    /// unusable (unsigned builds keep the keys where they were).
    public static func appVault(base: any KeychainVault, group: String? = SafariKeys.group()) -> any KeychainVault {
        guard let group else { return base }
        return SafariKeychainVault(base: base, safari: SystemKeychainVault(accessGroup: group), legacy: SystemKeychainVault())
    }

    /// What the Safari extension reads: its own group only, without an `LAContext` (no Face ID). With no
    /// usable group configured, the default group (the first, and only, one in its entitlements).
    public static func extensionVault() -> any KeychainVault {
        SystemKeychainVault(accessGroup: group())
    }

    /// Creates each key that is missing (or not 32 bytes) from `length` random bytes; an existing key is
    /// kept, so the inbox and the index stay readable. Keychain errors are thrown.
    public static func ensure(keychain: any KeychainVault, random: any RandomSource = SystemRandomSource()) throws {
        for slot in [VaultSlot.safariIndexKey, .safariInboxKey] {
            if let key = try keychain.read(slot), key.count == length { continue }
            try keychain.write(slot, random.bytes(count: length))
        }
    }
}
