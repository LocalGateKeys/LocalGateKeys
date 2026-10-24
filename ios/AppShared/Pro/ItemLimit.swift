import Foundation
@_exported import LGKCore

/// Desktop licence public keys (`licensing.LICENSE_KEYS`, key id -> raw Ed25519 key). The desktop ships this
/// keys; keep both in step (checked by `test_license_keys_match_desktop`).
public enum LicenseKeys {
    public static let production: [String: [UInt8]] = [
        "9f76e21ed03c0482": [0xF8, 0x7E, 0x9C, 0xEA, 0x9C, 0x40, 0xFD, 0x00, 0x13, 0x5D, 0x76, 0x35, 0x44, 0xF1, 0x84, 0x71,
                             0x7F, 0x39, 0x1E, 0x94, 0x57, 0x5C, 0xA6, 0x0B, 0xFD, 0x7A, 0xF3, 0x93, 0x06, 0xB6, 0x3A, 0x06],
    ]
}

/// The free plan's item limit (spec "Item limit and in-app purchase"). Shared with the AutoFill extension,
/// which checks it before creating a passkey.
public enum ItemLimit {
    public static let freeItems = 4

    public enum Action: Sendable { case create, restore, edit, delete, autofill }

    /// Live synced items: logins and typed items; tombstones, licence states and kinds that never sync excluded.
    public static func liveCount(_ snapshot: StoreSnapshot) -> Int {
        snapshot.records.reduce(0) { n, entry in
            let (id, wrapper) = entry
            if snapshot.meta[id]?.deleted == true { return n }
            guard case .object(let w) = wrapper, case .string(let ns)? = w["ns"], ns != Namespace.license.rawValue,
                  case .object(let r)? = w["record"], r["kind"] != .string("document") else { return n }
            return n + 1
        }
    }

    /// Only creating or restoring needs a free slot or Pro; nothing that exists is ever blocked.
    public static func allows(_ action: Action, snapshot: StoreSnapshot, isPro: Bool) -> Bool {
        switch action {
        case .create, .restore: isPro || liveCount(snapshot) < freeItems
        case .edit, .delete, .autofill: true
        }
    }

    /// The first stored licence state that verifies with LGKCore `License` under `keys`.
    public static func validLicense(in snapshot: StoreSnapshot, keys: [String: [UInt8]]) -> LicenseInfo? {
        guard !keys.isEmpty else { return nil }
        for (id, wrapper) in snapshot.records.sorted(by: { Scalars.less($0.key, $1.key) }) where id.hasPrefix(License.idPrefix) {
            guard case .object(let w) = wrapper, w["ns"] == .string(Namespace.license.rawValue), let bundle = w["record"],
                  let info = try? License.verify(bundle: bundle, keys: keys),
                  Scalars.equal(License.stateID(licenseID: info.licenseID), id) else { continue }
            return info
        }
        return nil
    }
}

/// Pro-only features (desktop `licensing.Feature`). On the phone only two-factor codes need a check here:
/// attachments are not created on the phone, and sync needs Pro on the PC (a free PC never syncs), which is
/// also how the phone receives a desktop licence.
public enum ProFeatures {
    public static let totpMessage = "Adding or changing two-factor codes needs LocalGateKeys Pro. Codes you already saved keep working."

    /// Whether saving `new` over `old` needs Pro: adding or changing a code does; keeping or removing one never does.
    public static func totpChangeNeedsPro(new: JSONValue?, old: JSONValue?) -> Bool {
        guard let new, new != .null else { return false }
        return new != old
    }
}
