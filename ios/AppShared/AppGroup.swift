import Foundation

/// The app group shared by the app, the AutoFill extension and the widgets, and the Safari extensions' own group.
/// Identifiers come from Info.plist (`LGKAppGroup`, `LGKSafariAppGroup`, `LGKKeychainGroup`), which project.yml fills
/// from BUNDLE_PREFIX.
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

    /// The pinned 2FA codes' own Keychain access group (`LGKCodesKeychainGroup`: the app, and the widget
    /// extension that shows the codes). It holds only the pinned codes, so the widget reaches no vault or sync
    /// secret. Nil when not configured or unexpanded (unsigned builds): then nothing is stored.
    public static var codesKeychainAccessGroup: String? {
        usableGroup(Bundle.main.object(forInfoDictionaryKey: "LGKCodesKeychainGroup") as? String)
    }

    /// `group` when it is a real access group: not empty, with its team prefix, no unexpanded build setting.
    public static func usableGroup(_ group: String?) -> String? {
        guard let g = group, !g.isEmpty, !g.hasPrefix("."), !g.contains("$(") else { return nil }
        return g
    }

    /// The shared container, or nil when the entitlement is missing (unsigned builds, tests) or in a Safari web
    /// extension (`isSafariOnly`).
    public static var containerURL: URL? {
        if isSafariOnly { return nil }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)
    }

    // MARK: the Safari group (audit 2026-11-10)

    /// The Safari web extensions' own app group (`LGKSafariAppGroup`: the iPhone and Mac apps, the two Safari
    /// extensions and the iPhone AutoFill extension, which writes only the "just filled" marker there,
    /// `LGK_SAFARI_APP_GROUP` in project.yml). It holds only what the extension needs (`SafariSaveFiles`):
    /// the sealed save inbox, the fingerprint index and site list, the plan-full and erase-pending markers, the
    /// duress block flag and, on the Mac, the active profile's id. Never the vault, its keys or the duress files, which
    /// stay in the shared group the Safari extensions are not entitled to. Must be registered in the Apple developer
    /// portal (App Groups) and enabled on the app's App ID and the Safari extension's App ID
    /// (`<BUNDLE_PREFIX>.app.safari`), and the iPhone AutoFill extension's (`<BUNDLE_PREFIX>.app.autofill`), before a
    /// signed build (ios/RELEASE.md).
    public static var safariIdentifier: String? {
        guard let id = Bundle.main.object(forInfoDictionaryKey: "LGKSafariAppGroup") as? String,
              !id.isEmpty, !id.contains("$(") else { return nil }
        return id
    }

    /// The Safari group's container, or nil when not configured or not entitled (unsigned builds, tests, the Mac
    /// AutoFill extension and the widgets, which do not hold it).
    public static var safariContainerURL: URL? {
        safariIdentifier.flatMap { FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: $0) }
    }

    /// True in the Safari web extensions: their Info.plist names the Safari group and not the shared one (they are
    /// entitled to the Safari group only). Nothing there may resolve the shared container: on the Mac a sandboxed
    /// process gets a path for a group it is not entitled to, and touching it fails or asks the user.
    public static var isSafariOnly: Bool {
        Bundle.main.object(forInfoDictionaryKey: "LGKAppGroup") == nil
            && Bundle.main.object(forInfoDictionaryKey: "LGKSafariAppGroup") != nil
    }

    /// Where `LocalStore` keeps its files.
    public static func vaultDirectory() throws -> URL {
        guard let base = containerURL else { throw LocalStoreError.noContainer }
        return base.appendingPathComponent("Vault", isDirectory: true)
    }
}
