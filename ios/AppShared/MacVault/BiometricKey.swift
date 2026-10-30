#if os(macOS)
import Foundation
import Security
import LocalAuthentication

/// Where the local vault key is kept for Touch ID unlock.
public protocol BiometricKeyStore: Sendable {
    func store(_ key: [UInt8]) throws
    func load(reason: String) async throws -> [UInt8]
    func remove() throws
    var isAvailable: Bool { get }
}

public enum BiometricKeyError: Error, Equatable {
    /// The user cancelled the prompt: not a reason to drop Touch ID.
    case cancelled
    case notFound
    case status(OSStatus)
    case accessControl
}

/// A Keychain item `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` + `.biometryCurrentSet`, never synced:
/// adding or removing a finger invalidates it, and the app and the AutoFill extension fall back to the master password.
public final class SystemBiometricKeyStore: BiometricKeyStore {
    public static let service = "com.localgatekeys.mac.touchid"
    public static let account = "local-key"
    public let accessGroup: String?

    public init(accessGroup: String? = nil) { self.accessGroup = accessGroup }

    private func base() -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: Self.service,
                                kSecAttrAccount as String: Self.account,
                                kSecAttrSynchronizable as String: false,
                                kSecUseDataProtectionKeychain as String: true]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    public var isAvailable: Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    public func store(_ key: [UInt8]) throws {
        try remove()   // the access control of an existing item cannot be updated in place
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       .biometryCurrentSet, nil) else { throw BiometricKeyError.accessControl }
        var q = base()
        q[kSecValueData as String] = Data(key)
        q[kSecAttrAccessControl as String] = ac
        let st = SecItemAdd(q as CFDictionary, nil)
        guard st == errSecSuccess else { throw BiometricKeyError.status(st) }
    }

    public func load(reason: String) async throws -> [UInt8] {
        let query = base()
        return try await Task.detached {
            let ctx = LAContext()
            ctx.localizedReason = reason
            var q = query
            q[kSecReturnData as String] = true
            q[kSecMatchLimit as String] = kSecMatchLimitOne
            q[kSecUseAuthenticationContext as String] = ctx
            var out: CFTypeRef?
            let st = SecItemCopyMatching(q as CFDictionary, &out)
            switch st {
            case errSecSuccess:
                guard let d = out as? Data else { throw BiometricKeyError.status(st) }
                return Array(d)
            case errSecUserCanceled: throw BiometricKeyError.cancelled
            case errSecItemNotFound: throw BiometricKeyError.notFound
            default: throw BiometricKeyError.status(st)
            }
        }.value
    }

    public func remove() throws {
        let st = SecItemDelete(base() as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw BiometricKeyError.status(st) }
    }
}
#endif
