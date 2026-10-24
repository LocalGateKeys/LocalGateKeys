import Foundation

/// The app group shared by the app and the AutoFill extension. Identifiers come from Info.plist
/// (`LGKAppGroup`, `LGKKeychainGroup`), which project.yml fills from BUNDLE_PREFIX.
public enum AppGroup {
    public static let fallbackIdentifier = "group.app.localgatekeys.localgatekeys"

    public static var identifier: String {
        (Bundle.main.object(forInfoDictionaryKey: "LGKAppGroup") as? String) ?? fallbackIdentifier
    }

    public static var keychainAccessGroup: String? {
        Bundle.main.object(forInfoDictionaryKey: "LGKKeychainGroup") as? String
    }

    /// The main app's own Keychain access group (`LGKAppKeychainGroup`, app Info.plist only). Nil in the
    /// AutoFill extension, which has no entitlement for it.
    public static var appKeychainAccessGroup: String? {
        Bundle.main.object(forInfoDictionaryKey: "LGKAppKeychainGroup") as? String
    }

    /// The Safari extension's own Keychain access group (`LGKSafariKeychainGroup`: app and Safari extension
    /// Info.plist). Holds only the two Safari keys; the Safari extension is entitled to no other group.
    public static var safariKeychainAccessGroup: String? {
        Bundle.main.object(forInfoDictionaryKey: "LGKSafariKeychainGroup") as? String
    }

    /// The shared container, or nil when the entitlement is missing (unsigned builds, tests).
    public static var containerURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)
    }

    /// Where `LocalStore` keeps its files.
    public static func vaultDirectory() throws -> URL {
        guard let base = containerURL else { throw LocalStoreError.noContainer }
        return base.appendingPathComponent("Vault", isDirectory: true)
    }
}
