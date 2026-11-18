import Foundation
import AppShared

/// The iPhone's reading of the feature pack's device-local state (travel mode) together with the synced access rules.
@MainActor
enum PhoneFeaturePack {
    static func travel(_ local: (any PhoneLocalHosting)?) -> TravelMode { local?.localData?.travel ?? .off }

    /// Items left out of the unencrypted CSV and CXF exports on this phone: travel-hidden items (§2) and logins whose
    /// rules refuse copying and export on phones (§4: view only, or a rule from a newer version).
    static func exportLeftOut(_ snapshot: StoreSnapshot, local: (any PhoneLocalHosting)?, today: String = RecordDigest.today()) -> Set<String> {
        var out = travel(local).hiddenIDs(in: snapshot)
        for (id, wrapper) in snapshot.itemRecords where snapshot.meta[id]?.deleted != true {
            guard case .object(let w) = wrapper, w["ns"] == .string(Namespace.entry.rawValue),
                  case .object(let record)? = w["record"] else { continue }
            if AccessRules.effective(record, device: .phone, today: today).refusesCopy(on: .phone) { out.insert(id) }
        }
        return out
    }

    /// The rules of one item on this phone today (`.open` for typed items).
    static func rules(_ item: VaultItem, today: String = RecordDigest.today()) -> AccessRules.Effective {
        guard item.kind == "web" || item.kind == "desktop" else { return .open }
        return AccessRules.effective(item.record, device: .phone, today: today)
    }
}

/// Access rules on this iPhone (feature pack §4) at the reveal and copy points: the detail screen and the list's
/// long-press menu. `require_master_password` and an expired rule ask the owner (a fresh system check, no grace) on
/// every reveal and copy; view only on phones refuses copying and asks before a reveal; copy once asks again after
/// the first copy in this unlock.
@MainActor
final class AccessGate {
    static let shared = AccessGate()
    /// Items copied once in this unlock (copy once). Memory only: cleared on lock.
    private var copied: Set<String> = []
    /// The owner check; tests replace it.
    var confirmOwner: (String) async -> Bool = { await AppPasswordGate.confirmOwner($0) }
    var today: () -> String = { RecordDigest.today() }

    func reset() { copied = [] }

    static let viewOnlyMessage = String(localized: "This login is view only on phones: it can't be copied, shared, exported or autofilled here.")

    /// Copy once (§4.1): a copy of the item's secrets is cleared after at most 10 s (as the Mac's `StrictItemGate`).
    static let copyOnceClearSeconds: Int64 = 10

    /// May `item` be copied now? Shows why not (view only) or asks the owner when a rule needs it. `secret` false (the
    /// username or another plain field): copy once neither counts it nor asks for it, as on the Mac (§4.1 counts the
    /// item's secrets only).
    func mayCopy(_ item: VaultItem, secret: Bool = true) async -> Bool {
        let rules = PhoneFeaturePack.rules(item, today: today())
        if rules.refusesCopy(on: .phone) {
            CopyToast.shared.show(Self.viewOnlyMessage)
            return false
        }
        let once = secret && rules.copyOnce
        if rules.reauth || (once && copied.contains(item.id)) {
            guard await confirmOwner(String(localized: "Copy from a protected login")) else { return false }
        }
        if once { copied.insert(item.id) }
        return true
    }

    /// How long a copy of `item`'s secrets may stay on the clipboard: 10 s under copy once, else nil (the user's
    /// setting). Every copy of such a login's secrets uses it, as on the Mac.
    func copyLimit(_ item: VaultItem) -> Int64? {
        PhoneFeaturePack.rules(item, today: today()).copyOnce ? Self.copyOnceClearSeconds : nil
    }

    /// May a secret of `item` be shown now? Asks the owner when a rule needs it.
    func mayReveal(_ item: VaultItem) async -> Bool {
        guard masksSecrets(item) else { return true }
        return await confirmOwner(String(localized: "Show a protected login"))
    }

    /// Whether `item`'s secrets, its live 2FA code included, stay masked until `mayReveal` passes: re-authenticate
    /// (`require_master_password`, an expired rule, a rule from a newer version) or view only on phones.
    func masksSecrets(_ item: VaultItem) -> Bool {
        let rules = PhoneFeaturePack.rules(item, today: today())
        return rules.reauth || rules.phoneView
    }

    /// Whether the detail screen opens `item` with its secrets masked: the "Hide passwords until tapped" setting, or
    /// always when its rules mask them (with the setting off, a protected login's password was shown unasked).
    func concealsOnOpen(_ item: VaultItem, setting: Bool) -> Bool { setting || masksSecrets(item) }

    /// May `item` be shared from this phone (view only refuses)?
    func mayShare(_ item: VaultItem) -> Bool { !PhoneFeaturePack.rules(item, today: today()).refusesCopy(on: .phone) }
}
