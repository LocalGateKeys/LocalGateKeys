import Foundation
import Security
import LGKCore

/// Where the watch keeps its pinned codes: one generic-password item in the watch Keychain, readable only
/// while the watch is unlocked and never migrated to another device. Nothing is written anywhere else (no
/// files, no defaults, no complication).
protocol WatchSecretStoring: Sendable {
    func load() -> [WatchCode]
    func save(_ codes: [WatchCode]) throws
    func removeAll()
}

struct KeychainWatchStore: WatchSecretStoring {
    static let service = "app.localgatekeys.watch.codes"
    static let account = "pinned"

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: Self.service,
         kSecAttrAccount as String: Self.account]
    }

    func load() -> [WatchCode] {
        var q = query
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data,
              case .replace(let codes)? = try? WatchMessage.decode(data) else { return [] }
        return codes
    }

    func save(_ codes: [WatchCode]) throws {
        removeAll()
        guard !codes.isEmpty else { return }
        var q = query
        q[kSecValueData as String] = try WatchMessage.replace(codes).encoded()
        // The wrist-detection passcode lock is what guards the codes: locked watch, unreadable item.
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }

    func removeAll() { SecItemDelete(query as CFDictionary) }
}

/// Applies a message from the iPhone: `replace` stores exactly the pinned set (an unpinned code is gone),
/// `forget` deletes everything. A malformed message changes nothing.
enum WatchInbox {
    static func apply(_ userInfo: [String: Any], to store: any WatchSecretStoring) -> [WatchCode]? {
        guard let message = try? WatchMessage.from(userInfo: userInfo) else { return nil }
        switch message {
        case .forget:
            store.removeAll()
            return []
        case .replace(let codes):
            do { try store.save(codes) } catch { store.removeAll(); return [] }
            return codes
        }
    }
}
