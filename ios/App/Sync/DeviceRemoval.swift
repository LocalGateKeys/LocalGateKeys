import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// Removing devices from the cloud-folder group, shared by the iPhone Sync tab and the Mac Sync page (Windows
/// `app/sync.py` `remove_device`, `lost_device`, `remove_orphans`; `sync_view.py` `rotation_plan` and
/// `lost_device_checklist`). One rotation removes every chosen device: a new sync key and password for the confirmed
/// members that stay, and a signed removal notice for each removed one (`FolderSync.rotate`), which makes that device
/// erase itself if it comes back online with "Erase this device if it is removed from sync" on. Pro only.
enum DeviceRemoval {
    /// The removal waiting for its new sync password (entered twice).
    struct Plan: Equatable, Identifiable {
        /// The devices to remove (keyring members other than this device), in list order.
        let ids: [String]
        let names: [String]
        /// The rotation intro, the QR-pairing warning and who keeps the key (Windows `rotation_plan`).
        let intro: String
        /// Confirmed members other than this device: the only ones the new key is wrapped to (audit M10).
        let keep: [String]
        /// "I lost a device": the checklist follows the removal.
        let lost: Bool
        var id: String { ids.joined(separator: ",") + (lost ? "|lost" : "") }
    }

    // Windows copy ("this iPhone" / "this Mac" for "this PC").
    static var rotationIntro: String { String(localized: "Enter a NEW sync password. Your other cloud-folder devices pick up the change on their next sync; a device set up later joins with the new password.") }
    static var passwordAdvice: String { String(localized: "Write this password down. Never reuse an earlier sync password.") }
    static var mismatchText: String { String(localized: "The two passwords don't match.") }
    static var removeLabel: String { String(localized: "sync.removeADevice", defaultValue: "Remove a device…") }
    static var lostLabel: String { String(localized: "sync.iLostADevice", defaultValue: "I lost a device…") }
    static var lostTitle: String { String(localized: "syncPage.lostTitle", defaultValue: "I lost a device") }
    static var lostIntro: String { String(localized: "syncPage.lostIntroFolder", defaultValue: "Pick the lost device. It is removed from sync, your other devices move to a NEW sync password, and the lost device erases its vault if it ever goes online again with LocalGateKeys running.") }
    static var removeTitle: String { String(localized: "Remove devices") }
    static var chooseText: String { String(localized: "Choose the devices to remove.") }
    static func removedText(_ names: [String]) -> String {
        let list = names.joined(separator: ", ")
        return String(localized: "sync.removedList", defaultValue: "Removed: \(list).")
    }

    /// What to do after "I lost a device" removed it from the cloud-folder group (Windows `lost_device_checklist(folder=True)`).
    static var lostChecklist: [String] {
        [String(localized: "sync.lostChecklistPasswords", defaultValue: "Change the passwords of your important accounts first: email, banking, shopping, and any password you use in more than one place."),
         String(localized: "sync.lostChecklistEncrypted", defaultValue: "The copy on the lost device stays encrypted, but it is only as safe as your master password. If your master password is short or used anywhere else, change the passwords in this vault."),
         String(localized: "sync.lostChecklistEraseFolder", defaultValue: "The lost device erases its copy only if it goes online with LocalGateKeys running, its erase setting on, and the sync folder in reach. Someone who keeps it offline or copies the vault file first is not stopped."),
         String(localized: "sync.lostChecklistCloudSignOut", defaultValue: "Sign the lost device out of the cloud account that holds the sync folder, so it can no longer read the folder."),
         String(localized: "sync.lostChecklistFindDevice", defaultValue: "If you can, lock or erase the device remotely through the account it is signed in to (for an Apple device, Find My).")]
    }

    /// Keyring member names (`[device id: name]`) of the stored group, sanitised; unreadable ones "Unnamed device".
    static func memberNames(_ state: SyncGroupState?) -> [String: String] {
        guard let state, let bytes = state.keyring, let ring = try? CanonicalJSON.parse(bytes),
              let gk = try? GroupKey(groupID: state.groupID, epoch: state.epoch, key: state.key) else { return [:] }
        var out: [String: String] = [:]
        for (id, name) in Keyring.memberNames(ring, key: gk) {
            out[id] = SyncWording.labeled(name ?? SyncWording.unnamedDevice, id)
        }
        return out
    }

    /// "this iPhone" / "this Mac" in the list of who keeps the key.
    static var thisDeviceLower: String {
        SyncWording.onDevice(phone: DeviceText.isPad ? String(localized: "ipad.sync.thisPc", defaultValue: "this iPad") : String(localized: "sync.thisPc.phone", defaultValue: "this iPhone"), mac: String(localized: "this Mac"))
    }

    /// Who keeps the group key when `removing` is removed (Windows `rotation_plan`, audit M10): the confirmed
    /// members other than this device; unconfirmed members are left out and lose access.
    static func keepList(_ state: SyncGroupState, removing: Set<String>) -> [String] {
        let unacked = Set(state.unackedMembers)
        return state.members.filter { $0 != state.deviceID && !removing.contains($0) && !unacked.contains($0) }
    }

    /// Windows `rotation_plan` text.
    static func keepText(_ state: SyncGroupState, removing: Set<String>, names: [String: String]) -> String {
        func shown(_ id: String) -> String { names[id] ?? SyncWording.shortID(id) }
        let keep = keepList(state, removing: removing).map(shown) + [thisDeviceLower]
        var text = String(localized: "The new sync key goes only to: \(keep.joined(separator: ", ")).")
        let unacked = Set(state.unackedMembers)
        let lose = state.members.filter { unacked.contains($0) && !removing.contains($0) && $0 != state.deviceID }
        if !lose.isEmpty {
            text += String(localized: " Not confirmed, so they lose access: \(lose.map(shown).joined(separator: ", ")). To keep one, cancel and choose These are my devices first.")
        }
        return text
    }

    /// The removal of `ids` (members other than this device; others are ignored), or nil when none is left.
    /// `qrPeers`: names of the devices paired by QR code that are not being removed (they must pair again).
    static func plan(_ state: SyncGroupState, removing ids: [String], names: [String: String], qrPeers: [String],
                     lost: Bool) -> Plan? {
        let members = Set(state.members)
        var chosen: [String] = []
        for id in ids where id != state.deviceID && members.contains(id) && !chosen.contains(id) { chosen.append(id) }
        guard !chosen.isEmpty else { return nil }
        let gone = Set(chosen)
        var intro = lost ? lostIntro + "\n\n" + rotationIntro : rotationIntro
        if !qrPeers.isEmpty {
            intro += String(localized: "\n\nDevices paired by QR code can't follow a password change and must be paired again afterwards: \(qrPeers.joined(separator: ", ")).")
        }
        intro += "\n\n" + keepText(state, removing: gone, names: names)
        return Plan(ids: chosen, names: chosen.map { names[$0] ?? SyncWording.shortID($0) }, intro: intro,
                    keep: keepList(state, removing: gone), lost: lost)
    }

    // MARK: the removed device

    /// The setting (Windows `settings.eraseOnSyncRemoval`), default on.
    static var eraseSettingTitle: String { String(localized: "settings.eraseOnSyncRemoval.title", defaultValue: "Erase this device if it is removed from sync") }
    static var eraseSettingText: String {
        SyncWording.onDevice(
            phone: DeviceText.isPad ? String(localized: "ipad.settings.eraseOnSyncRemoval.desc", defaultValue: "When another of your devices removes this iPad from sync, this iPad erases its vault the next time LocalGateKeys is unlocked here and reaches the sync folder. Backups you exported are never touched.") : String(localized: "settings.eraseOnSyncRemoval.desc.phone", defaultValue: "When another of your devices removes this iPhone from sync, this iPhone erases its vault the next time LocalGateKeys is unlocked here and reaches the sync folder. Backups you exported are never touched."),
            mac: String(localized: "settings.eraseOnSyncRemoval.desc.mac", defaultValue: "When another of your devices removes this Mac from sync, this Mac erases its vault the next time it reaches the sync folder. Scheduled backups are kept, because they also need the backup password. It only works if the Mac goes online with LocalGateKeys running. Backups you exported are never touched."))
    }

    /// The one-time notice after an erase (Windows `app.erasedTitle` / `app.erasedMessage`).
    static var erasedTitle: String {
        SyncWording.onDevice(phone: DeviceText.isPad ? String(localized: "ipad.app.erasedTitle", defaultValue: "The vault was erased from this iPad") : String(localized: "app.erasedTitle.phone", defaultValue: "The vault was erased from this iPhone"),
                             mac: String(localized: "app.erasedTitle.mac", defaultValue: "The vault was erased from this Mac"))
    }
    static var erasedMessage: String {
        SyncWording.onDevice(
            phone: DeviceText.isPad ? String(localized: "ipad.app.erasedMessage", defaultValue: "Another of your devices removed this iPad from sync, so LocalGateKeys erased the vault from this iPad. Your other devices still have it. To use it here again, restore a backup or start a new vault, then join sync with the current sync password.") : String(localized: "app.erasedMessage.phone", defaultValue: "Another of your devices removed this iPhone from sync, so LocalGateKeys erased the vault from this iPhone. Your other devices still have it. To use it here again, restore a backup or start a new vault, then join sync with the current sync password."),
            mac: String(localized: "app.erasedMessage.mac", defaultValue: "Another of your devices removed this Mac from sync, so LocalGateKeys erased the vault from this Mac. Your other devices still have it. To use it here again, restore a backup or create a new vault, then join sync with the current sync password."))
    }

    /// The Mac notice plus, when the erase kept scheduled backups (`MacVaultEraser.keepScheduledBackups`), where they
    /// are (one path per line) and what opens them. The iPhone has no scheduled backups: always the plain notice.
    static func erasedMessage(keptFolders: String?) -> String {
        guard let folders = keptFolders, !folders.isEmpty else { return erasedMessage }
        let kept = String(localized: "app.erasedKeptBackups.mac", defaultValue: "The scheduled backups of this vault were kept, in:\n\(folders)\nTo restore one you need its backup password and the vault's master password.")
        return erasedMessage + "\n\n" + kept
    }
}
