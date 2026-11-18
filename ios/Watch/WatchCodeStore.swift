import Foundation
import Security
import LGKCore

/// Where the watch keeps its pinned codes: one generic-password item in the watch Keychain, readable only
/// while the watch is unlocked and never migrated to another device. The item sits in the watch's own codes
/// Keychain group (`LGKWatchCodesKeychainGroup`), which only the watch app and its complication are entitled to.
/// Nothing is written anywhere else (no files, no defaults, no app group).
protocol WatchSecretStoring: Sendable {
    func load() -> [WatchCode]
    func save(_ codes: [WatchCode]) throws
    func removeAll()
}

/// The code list's text with no code pinned. It names the iPhone's pin button, "Show in widgets and on Apple Watch"
/// since sub-plan 06 (it said "Show on Apple Watch" before; checked on the simulator 2026-11-16).
enum WatchText {
    static var emptyHint: String {
        String(localized: "Pin a 2FA code on your iPhone: open the item and choose Show in widgets and on Apple Watch.")
    }
}

/// What a read of the watch Keychain found.
enum WatchKeychainRead: Equatable, Sendable {
    case codes([WatchCode])
    /// No item: nothing pinned, forgotten on lock, erased, or an unreadable item.
    case nothing
    /// The watch is locked: the item opens when the watch is unlocked.
    case locked
}

struct KeychainWatchStore: WatchSecretStoring {
    static let service = "app.localgatekeys.watch.codes"
    static let account = "pinned"

    /// The watch's codes Keychain group from Info.plist, or nil when it is missing or not expanded (unsigned
    /// builds, tests).
    static var codesAccessGroup: String? {
        guard let g = Bundle.main.object(forInfoDictionaryKey: "LGKWatchCodesKeychainGroup") as? String,
              !g.isEmpty, !g.hasPrefix("."), !g.contains("$(") else { return nil }
        return g
    }

    /// The group the item is stored in and read from. nil: the app's own default group, as before the
    /// complication (which then shows nothing: it is entitled to the codes group only).
    let accessGroup: String?

    init(accessGroup: String? = KeychainWatchStore.codesAccessGroup) {
        self.accessGroup = accessGroup
    }

    /// The item in `group`, or in every group the caller is entitled to when `group` is nil.
    private func query(group: String?) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: Self.service,
                                kSecAttrAccount as String: Self.account]
        if let group { q[kSecAttrAccessGroup as String] = group }
        return q
    }

    private func read(group: String?) -> WatchKeychainRead {
        var q = query(group: group)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecInteractionNotAllowed { return .locked }
        guard status == errSecSuccess, let data = out as? Data,
              case .replace(let codes)? = try? WatchMessage.decode(data) else { return .nothing }
        return .codes(codes)
    }

    /// The app's read. A copy that a build before the complication left in the app's default group is moved
    /// into the codes group once, so the complication can show it. Never called by the complication.
    func load() -> [WatchCode] {
        guard let group = accessGroup else {
            if case .codes(let codes) = read(group: nil) { return codes }
            return []
        }
        switch read(group: group) {
        case .codes(let codes):
            return codes
        case .locked:
            return []
        case .nothing:
            // Nothing in the codes group, so a match in any group is the old copy.
            guard case .codes(let legacy) = read(group: nil) else { return [] }
            // `save` deletes every copy first; if the add then fails, the codes are gone until the iPhone sends
            // them again (as when a message from the iPhone cannot be stored).
            guard (try? save(legacy)) != nil else { return [] }
            return legacy
        }
    }

    func save(_ codes: [WatchCode]) throws {
        removeAll()
        guard !codes.isEmpty else { return }
        var q = query(group: accessGroup)
        q[kSecValueData as String] = try WatchMessage.replace(codes).encoded()
        // The wrist-detection passcode lock is what guards the codes: locked watch, unreadable item.
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }

    /// Every copy, in the codes group and in the app's default group (an old build's copy). The complication
    /// reads this same item, so an unpin, Forget on lock or an erase also clears what it can show.
    func removeAll() { SecItemDelete(query(group: nil) as CFDictionary) }

    /// The complication's read (it never writes, moves or deletes anything): the pinned codes valid at `now`, in
    /// pin order, at most `PinnedCodeStore.maxShown`. Without a usable codes group: nothing.
    func codes(at now: Date) -> WatchKeychainRead {
        guard let group = accessGroup else { return .nothing }
        let found = read(group: group)
        guard case .codes(let all) = found else { return found }
        let t = now.timeIntervalSince1970
        guard t.isFinite, t >= 0, t < 1e15 else { return .nothing }
        let valid = all.filter { $0.period > 0 && $0.current(at: Int64(t)) != nil }
        return valid.isEmpty ? .nothing : .codes(Array(valid.prefix(PinnedCodeStore.maxShown)))
    }
}

/// Applies a message from the iPhone: `replace` stores exactly the pinned set (an unpinned code is gone),
/// `forget` deletes everything. A malformed message changes nothing. `lastSequence` is the send order of the last
/// message applied (updated here, `WatchMessage.ordering`): a code update not newer than it is ignored, so one
/// that lands after a later Forget on lock never brings the codes back; a forget is always applied.
enum WatchInbox {
    static func apply(_ userInfo: [String: Any], to store: any WatchSecretStoring,
                      lastSequence: inout Int64?, now: Date = Date()) -> [WatchCode]? {
        guard let decoded = try? WatchMessage.sequenced(from: userInfo) else { return nil }
        let order = WatchMessage.ordering(of: decoded.message, sequence: decoded.sequence,
                                          lastApplied: lastSequence, now: now)
        lastSequence = order.lastApplied
        guard order.apply else { return nil }
        switch decoded.message {
        case .forget:
            store.removeAll()
            return []
        case .replace(let codes):
            do { try store.save(codes) } catch { store.removeAll(); return [] }
            return codes
        }
    }
}
