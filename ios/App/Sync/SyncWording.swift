import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// The desktop's Sync screen copy (`src/localvault/sync_ui.py` `ISSUE_COPY`, `ERROR_COPY`, `issue_text`,
/// leave/reset texts), copied verbatim; `docs/SYNC.md` "What the Sync screen warnings mean" is the
/// shortened table of the same messages. The tables keep the desktop text byte for byte; text shown here uses
/// the `.phone` / `.mac` catalog entries (`pc`, `onDevice`), which say "iPhone" / "Mac" where the desktop says "PC".
enum SyncWording {
    static let nameLimit = 40
    static let unnamedDevice = "Unnamed device"
    /// After a sync that changed items here (desktop `synced_items_text`).
    static func itemsUpdated(_ count: Int) -> String {
        String(localized: "sync.itemsUpdated", defaultValue: "\(count) items updated from your other devices.")
    }
    /// The name this phone puts in the keyring: generic, never the user's device name (desktop "Windows PC").
    static let deviceName = "iPhone"
    /// What this device is called in the copy where the desktop says "PC": "iPhone", or "Mac" on the Mac.
    #if os(macOS)
    static let thisDevice = "Mac"
    #else
    static let thisDevice = "iPhone"
    #endif

    /// Copy where the desktop says "PC": the desktop text when `here` is false (`desktopText`), else this device's own
    /// catalog entry (`<windows key>.phone` on the iPhone, `.mac` on the Mac) so translators word it for the device.
    static func pc(_ here: Bool, _ desktop: @autoclosure () -> String, phone: @autoclosure () -> String,
                   mac: @autoclosure () -> String) -> String {
        here ? onDevice(phone: phone(), mac: mac()) : desktop()
    }

    /// This device's wording: the `.phone` entry on the iPhone, the `.mac` entry on the Mac.
    static func onDevice(phone: @autoclosure () -> String, mac: @autoclosure () -> String) -> String {
        #if os(macOS)
        return mac()
        #else
        return phone()
        #endif
    }

    static func issueCopy(_ kind: String, subject s: String = "", here: Bool = false) -> String? {
        switch kind {
        // keyring and membership (cloud folder)
        case "keyring-restored": pc(here, String(localized: "sync.theSyncFolderHadAn", defaultValue: "The sync folder had an older or altered key file. This PC put the trusted copy back; sync continues."), phone: String(localized: "sync.theSyncFolderHadAn.phone", defaultValue: "The sync folder had an older or altered key file. This iPhone put the trusted copy back; sync continues."), mac: String(localized: "sync.theSyncFolderHadAn.mac", defaultValue: "The sync folder had an older or altered key file. This Mac put the trusted copy back; sync continues."))
        case "folder-has-other-group": pc(here, String(localized: "sync.thisSyncFolderNowHolds", defaultValue: "This sync folder now holds a different sync group. Sync stopped and nothing was written. Leave sync, or reset sync on this PC, then join the right folder."), phone: String(localized: "sync.thisSyncFolderNowHolds.phone", defaultValue: "This sync folder now holds a different sync group. Sync stopped and nothing was written. Leave sync, or reset sync on this iPhone, then join the right folder."), mac: String(localized: "sync.thisSyncFolderNowHolds.mac", defaultValue: "This sync folder now holds a different sync group. Sync stopped and nothing was written. Leave sync, or reset sync on this Mac, then join the right folder."))
        case "rotation-conflict": String(localized: "sync.twoDevicesChangedTheSync", defaultValue: "Two devices changed the sync password at the same time. Sync stopped. Join the folder again with the newest sync password.")
        case "removed-or-conflict": String(localized: "sync.thisDeviceMayHaveBeen", defaultValue: "This device may have been removed from sync. Re-join if that isn't expected.")
        case "rejoin-required": pc(here, String(localized: "sync.thisPcMustJoinSync", defaultValue: "This PC must join sync again (it missed a password change, or it was removed). Join the folder again with the current sync password."), phone: String(localized: "sync.thisPcMustJoinSync.phone", defaultValue: "This iPhone must join sync again (it missed a password change, or it was removed). Join the folder again with the current sync password."), mac: String(localized: "sync.thisPcMustJoinSync.mac", defaultValue: "This Mac must join sync again (it missed a password change, or it was removed). Join the folder again with the current sync password."))
        case "member-dropped": String(localized: "sync.disappearedFromTheMemberList", defaultValue: "\(s) disappeared from the member list without a password change. If you did not remove it, change the sync password.")
        case "tampered": pc(here, String(localized: "sync.theKeyFileInThe", defaultValue: "The key file in the sync folder was altered. Sync stopped. If this keeps happening, reset sync on this PC and join again."), phone: String(localized: "sync.theKeyFileInThe.phone", defaultValue: "The key file in the sync folder was altered. Sync stopped. If this keeps happening, reset sync on this iPhone and join again."), mac: String(localized: "sync.theKeyFileInThe.mac", defaultValue: "The key file in the sync folder was altered. Sync stopped. If this keeps happening, reset sync on this Mac and join again."))
        case "keyring-corrupt": pc(here, String(localized: "sync.theKeyFileInThe2", defaultValue: "The key file in the sync folder is damaged. Reset sync on this PC, or restore the folder."), phone: String(localized: "sync.theKeyFileInThe2.phone", defaultValue: "The key file in the sync folder is damaged. Reset sync on this iPhone, or restore the folder."), mac: String(localized: "sync.theKeyFileInThe2.mac", defaultValue: "The key file in the sync folder is damaged. Reset sync on this Mac, or restore the folder."))
        case "keyring-missing": pc(here, String(localized: "sync.theKeyFileInThe3", defaultValue: "The key file in the sync folder is missing. Check the folder, or reset sync on this PC."), phone: String(localized: "sync.theKeyFileInThe3.phone", defaultValue: "The key file in the sync folder is missing. Check the folder, or reset sync on this iPhone."), mac: String(localized: "sync.theKeyFileInThe3.mac", defaultValue: "The key file in the sync folder is missing. Check the folder, or reset sync on this Mac."))
        case "keyring-unreadable": String(localized: "sync.theKeyFileInThe4", defaultValue: "The key file in the sync folder could not be read. Check that the cloud app has downloaded it.")
        case "unsafe-member": String(localized: "sync.aDeviceInTheMember", defaultValue: "A device in the member list has a name that is not a safe file name; it is ignored.")
        case "bad-name": String(localized: "sync.theNameOfInThe", defaultValue: "The name of \(s) in the key file could not be read; it is shown as Unnamed device. Sync continues.")
        case "state-corrupt": pc(here, String(localized: "sync.thisVaultSSyncSettings", defaultValue: "This vault's sync settings are damaged. Reset sync on this PC, then join again."), phone: String(localized: "sync.thisVaultSSyncSettings.phone", defaultValue: "This vault's sync settings are damaged. Reset sync on this iPhone, then join again."), mac: String(localized: "sync.thisVaultSSyncSettings.mac", defaultValue: "This vault's sync settings are damaged. Reset sync on this Mac, then join again."))
        case "identity-mismatch": pc(here, String(localized: "sync.thisPcSSyncIdentity", defaultValue: "This PC's sync identity does not match its pairing. Reset sync on this PC and pair again."), phone: String(localized: "sync.thisPcSSyncIdentity.phone", defaultValue: "This iPhone's sync identity does not match its pairing. Reset sync on this iPhone and pair again."), mac: String(localized: "sync.thisPcSSyncIdentity.mac", defaultValue: "This Mac's sync identity does not match its pairing. Reset sync on this Mac and pair again."))
        case "not-joined": pc(here, String(localized: "syncStatusPage.off", defaultValue: "Sync is not set up on this PC."), phone: String(localized: "syncStatusPage.off.phone", defaultValue: "Sync is not set up on this iPhone."), mac: String(localized: "syncStatusPage.off.mac", defaultValue: "Sync is not set up on this Mac."))
        // device files
        case "stale-self": pc(here, String(localized: "sync.thisPcHadNotSynced", defaultValue: "This PC had not synced for over a year. Items deleted elsewhere more than a year ago may come back; delete them again if they do."), phone: String(localized: "sync.thisPcHadNotSynced.phone", defaultValue: "This iPhone had not synced for over a year. Items deleted elsewhere more than a year ago may come back; delete them again if they do."), mac: String(localized: "sync.thisPcHadNotSynced.mac", defaultValue: "This Mac had not synced for over a year. Items deleted elsewhere more than a year ago may come back; delete them again if they do."))
        case "stale-device": String(localized: "sync.hasNotSyncedForOver", defaultValue: "\(s) has not synced for over a year and is ignored. Remove that device if it is gone.")
        case "ignored-file": String(localized: "sync.unknownFilesInTheSync", defaultValue: "Unknown files in the sync folder were ignored (\(s)). Cloud apps sometimes make copies like these; you can delete them.")
        case "corrupt": String(localized: "sync.isDamagedOrCouldNot", defaultValue: "\(s) is damaged or could not be verified and was skipped. Nothing was changed.")
        case "keyring-rollback": pc(here, String(localized: "sync.theKeyFileInThe5", defaultValue: "The key file in the sync folder was replaced by an older copy and could not be put back. Sync stopped. Check the folder, or reset sync on this PC and join again."), phone: String(localized: "sync.theKeyFileInThe5.phone", defaultValue: "The key file in the sync folder was replaced by an older copy and could not be put back. Sync stopped. Check the folder, or reset sync on this iPhone and join again."), mac: String(localized: "sync.theKeyFileInThe5.mac", defaultValue: "The key file in the sync folder was replaced by an older copy and could not be put back. Sync stopped. Check the folder, or reset sync on this Mac and join again."))
        case "rollback": String(localized: "sync.wasReplacedByAnOlder", defaultValue: "\(s) was replaced by an older copy (for example from the cloud's file history) and was skipped.")
        case "suspicious-rewrite": String(localized: "sync.wasRewrittenWithoutANew", defaultValue: "\(s) was rewritten without a new version number and was skipped. Someone with access to the folder may have altered it.")
        case "epoch-mismatch": String(localized: "sync.wasWrittenWithAnotherSync", defaultValue: "\(s) was written with another sync key and is ignored until that device syncs again.")
        case "device-mismatch": String(localized: "sync.holdsDataOfADifferent", defaultValue: "\(s) holds data of a different device and was skipped.")
        case "unreadable": String(localized: "sync.couldNotBeReadAnd", defaultValue: "\(s) could not be read and was skipped.")
        case "folder-missing": String(localized: "sync.theSyncFolderIsNot", defaultValue: "The sync folder is not available. Check that the cloud app is running and the folder exists.")
        case "folder-unreadable": String(localized: "sync.theSyncFolderCouldNot", defaultValue: "The sync folder could not be read. Check that the cloud app is running.")
        case "write-failed": pc(here, String(localized: "sync.thisPcCouldNotWrite", defaultValue: "This PC could not write its sync file. Check that the folder is available and not read-only."), phone: String(localized: "sync.thisPcCouldNotWrite.phone", defaultValue: "This iPhone could not write its sync file. Check that the folder is available and not read-only."), mac: String(localized: "sync.thisPcCouldNotWrite.mac", defaultValue: "This Mac could not write its sync file. Check that the folder is available and not read-only."))
        case "too-large": String(localized: "sync.theSyncDataIsOver", defaultValue: "The sync data is over the sync limit (20,000 items or 64 MB). Some changes were not sent.")
        case "counter-resynced": String(localized: "sync.thisVaultWasRestoredFrom", defaultValue: "This vault was restored from an older copy; sync caught up automatically.")
        case "signer-changed": String(localized: "sync.hasADifferentSigningKey", defaultValue: "\(s) has a different signing key in the sync folder's member list than before. If you did not set that device up again, remove devices you do not trust.")
        // merging
        case "trash-full": String(localized: "sync.syncCouldNotMoveDeleted", defaultValue: "Sync could not move deleted items to the trash because the trash is full. Empty the trash, then sync again.")
        case "history-quota": String(localized: "sync.syncCouldNotKeepItem", defaultValue: "Sync could not keep item history because the history limit was reached. Clear old history, then sync again.")
        case "bad-peer-data": String(localized: "sync.dataFromCouldNotBe", defaultValue: "Data from \(s) could not be read and was skipped.")
        case "bad-peer-record": pc(here, String(localized: "sync.oneItemFromCouldNot", defaultValue: "One item from \(s) could not be read on this PC and was skipped; everything else synced. Updating LocalGateKeys on this PC usually fixes this."), phone: String(localized: "sync.oneItemFromCouldNot.phone", defaultValue: "One item from \(s) could not be read on this iPhone and was skipped; everything else synced. Updating LocalGateKeys on this iPhone usually fixes this."), mac: String(localized: "sync.oneItemFromCouldNot.mac", defaultValue: "One item from \(s) could not be read on this Mac and was skipped; everything else synced. Updating LocalGateKeys on this Mac usually fixes this."))
        case "update-needed": pc(here, String(localized: "sync.oneItemNeedsANewer", defaultValue: "One item needs a newer LocalGateKeys on this PC. Update LocalGateKeys; that item waits until then."), phone: String(localized: "sync.oneItemNeedsANewer.phone", defaultValue: "One item needs a newer LocalGateKeys on this iPhone. Update LocalGateKeys; that item waits until then."), mac: String(localized: "sync.oneItemNeedsANewer.mac", defaultValue: "One item needs a newer LocalGateKeys on this Mac. Update LocalGateKeys; that item waits until then."))
        case "busy": String(localized: "sync.itemsChangedWhileSyncingSync", defaultValue: "Items changed while syncing; sync tries again shortly.")
        case "apply-failed": String(localized: "sync.changesFromYourOtherDevices", defaultValue: "Changes from your other devices could not be saved. Sync tries again later.")
        case "local-data": pc(here, String(localized: "sync.someItemsOnThisPc", defaultValue: "Some items on this PC could not be read for sync."), phone: String(localized: "sync.someItemsOnThisPc.phone", defaultValue: "Some items on this iPhone could not be read for sync."), mac: String(localized: "sync.someItemsOnThisPc.mac", defaultValue: "Some items on this Mac could not be read for sync."))
        case "error": String(localized: "sync.syncHitAnUnexpectedProblem", defaultValue: "Sync hit an unexpected problem. Details are in the error log.")
        // Wi-Fi
        case "epoch-behind": pc(here, String(localized: "sync.thisPcHasAnOlder", defaultValue: "This PC has an older sync key than \(s). Leave sync on this PC, then pair it again."), phone: String(localized: "sync.thisPcHasAnOlder.phone", defaultValue: "This iPhone has an older sync key than \(s). Leave sync on this iPhone, then pair it again."), mac: String(localized: "sync.thisPcHasAnOlder.mac", defaultValue: "This Mac has an older sync key than \(s). Leave sync on this Mac, then pair it again."))
        case "peer-epoch-behind": String(localized: "sync.hasAnOlderSyncKey", defaultValue: "\(s) has an older sync key. Pair it again with Show QR code.")
        case "offer-used-or-expired": String(localized: "sync.thisPairingCodeWasUsed", defaultValue: "This pairing code was used up or expired. Show a new code.")
        case "too-many-peers": String(localized: "sync.theOtherDeviceAlreadyHas", defaultValue: "The other device already has the most paired devices. Remove one there first.")
        case "peer-update-needed": pc(here, String(localized: "sync.runsAnOlderLocalgatekeysAnd", defaultValue: "\(s) runs an older LocalGateKeys and cannot sync over Wi-Fi with this PC. Update LocalGateKeys on that device."), phone: String(localized: "sync.runsAnOlderLocalgatekeysAnd.phone", defaultValue: "\(s) runs an older LocalGateKeys and cannot sync over Wi-Fi with this iPhone. Update LocalGateKeys on that device."), mac: String(localized: "sync.runsAnOlderLocalgatekeysAnd.mac", defaultValue: "\(s) runs an older LocalGateKeys and cannot sync over Wi-Fi with this Mac. Update LocalGateKeys on that device."))
        case "lan-update-needed": pc(here, String(localized: "sync.anotherDeviceRunsANewer", defaultValue: "Another device runs a newer Wi-Fi sync. Update LocalGateKeys on this PC."), phone: String(localized: "sync.anotherDeviceRunsANewer.phone", defaultValue: "Another device runs a newer Wi-Fi sync. Update LocalGateKeys on this iPhone."), mac: String(localized: "sync.anotherDeviceRunsANewer.mac", defaultValue: "Another device runs a newer Wi-Fi sync. Update LocalGateKeys on this Mac."))
        case "lan-not-listening": String(localized: "sync.wiFiSyncIsNot", defaultValue: "Wi-Fi sync is not listening yet.")
        case "listen-failed": String(localized: "sync.wiFiSyncCouldNot", defaultValue: "Wi-Fi sync could not start listening. Check the address and port, and that no other app uses that port.")
        case "no-endpoint": pc(here, String(localized: "sync.hasNoNetworkAddressIt", defaultValue: "\(s) has no network address; it connects to this PC instead."), phone: String(localized: "sync.hasNoNetworkAddressIt.phone", defaultValue: "\(s) has no network address; it connects to this iPhone instead."), mac: String(localized: "sync.hasNoNetworkAddressIt.mac", defaultValue: "\(s) has no network address; it connects to this Mac instead."))
        case "unreachable": String(localized: "sync.aDeviceCouldNotBe", defaultValue: "A device could not be reached on this network. Check that it is on the same Wi-Fi and that LocalGateKeys is unlocked there.")
        case "unknown-peer": String(localized: "sync.aDeviceThatIsNot", defaultValue: "A device that is not paired tried to sync and was refused.")
        case "peer-revoked": String(localized: "sync.wasRemovedFromSyncAnd", defaultValue: "\(s) was removed from sync and was not contacted.")
        case "peer-mismatch": String(localized: "sync.didNotMatchItsPairing", defaultValue: "\(s) did not match its pairing and was not synced.")
        case "group-mismatch": String(localized: "sync.belongsToADifferentSync", defaultValue: "\(s) belongs to a different sync group.")
        case "peer-not-joined": String(localized: "sync.theOtherDeviceIsNot", defaultValue: "The other device is not set up for sync.")
        case "peer-rejoin-required": String(localized: "sync.theOtherDeviceMustJoin", defaultValue: "The other device must join sync again on that device.")
        case "peer-refused": String(localized: "sync.theOtherDeviceRefusedTo", defaultValue: "The other device refused to sync.")
        case "bad-reply": pc(here, String(localized: "sync.anotherDeviceSentAReply", defaultValue: "Another device sent a reply this PC could not understand."), phone: String(localized: "sync.anotherDeviceSentAReply.phone", defaultValue: "Another device sent a reply this iPhone could not understand."), mac: String(localized: "sync.anotherDeviceSentAReply.mac", defaultValue: "Another device sent a reply this Mac could not understand."))
        case "bad-chunk": pc(here, String(localized: "sync.anotherDeviceSentDataThis", defaultValue: "Another device sent data this PC could not understand."), phone: String(localized: "sync.anotherDeviceSentDataThis.phone", defaultValue: "Another device sent data this iPhone could not understand."), mac: String(localized: "sync.anotherDeviceSentDataThis.mac", defaultValue: "Another device sent data this Mac could not understand."))
        case "bad-message": pc(here, String(localized: "sync.anotherDeviceSentDataThis", defaultValue: "Another device sent data this PC could not understand."), phone: String(localized: "sync.anotherDeviceSentDataThis.phone", defaultValue: "Another device sent data this iPhone could not understand."), mac: String(localized: "sync.anotherDeviceSentDataThis.mac", defaultValue: "Another device sent data this Mac could not understand."))
        case "refused": String(localized: "sync.theOtherDeviceRefusedThe", defaultValue: "The other device refused the pairing.")
        case "bad-offer": String(localized: "sync.thatIsNotAValid", defaultValue: "That is not a valid LocalGateKeys pairing code.")
        case "already-joined": String(localized: "sync.thisVaultIsAlreadyIn", defaultValue: "This vault is already in a sync group. Leave sync first.")
        // rollback witnesses (plan Part B, Task B4), word for word from the desktop
        case "vault-rollback": String(localized: "sync.anotherDeviceInYourSync", defaultValue: "Another device in your sync group saw a newer copy of this vault. If you did not restore a backup, someone may have replaced the vault file with an old copy. Sync brings back the newer items your other devices hold. Change your master password if you did not expect this.")
        case "peer-vault-rollback": String(localized: "sync.isNowUsingAnOlder", defaultValue: "\(s) is now using an older copy of its vault. If nobody restored a backup there, check that device.")
        case "witness-implausible": String(localized: "sync.reportedAnImpossibleVersionNumber", defaultValue: "\(s) reported an impossible version number for this vault; it was ignored.")
        case "rollback-acknowledged": String(localized: "sync.youRestoredAnOlderBackup", defaultValue: "You restored an older backup. Your other devices were told this copy is the current one.")
        // attachment sync (2026-10-29)
        case "attachment-missing": String(localized: "sync.aFileAttachedOnAnother", defaultValue: "A file attached on another device has not arrived yet. Its item appears after a sync that receives the file.")
        case "attachment-refused": String(localized: "sync.aFileFromAnotherDevice", defaultValue: "A file from another device failed its integrity check and was not saved.")
        default: nil
        }
    }

    /// Title of the `vault-rollback` message and the label of its acknowledge button (desktop Task B4 copy).
    static var rollbackTitle: String { String(localized: "sync.thisVaultIsOlderThan", defaultValue: "This vault is older than one your other devices have seen") }
    static var rollbackAction: String { String(localized: "sync.thisWasMeKeepThis", defaultValue: "This was me — keep this copy") }
    static var rollbackConfirmTitle: String { String(localized: "sync.keepThisCopyOfThe", defaultValue: "Keep this copy of the vault?") }
    static var rollbackConfirmText: String { onDevice(phone: String(localized: "sync.chooseThisOnlyIfYou.phone", defaultValue: "Choose this only if you restored this iPhone's vault from a backup yourself. Your other devices are told this copy is now the current one, and the warning stops.\n\nIf you did not restore a backup, choose Cancel, check recent changes and change your master password."), mac: String(localized: "sync.chooseThisOnlyIfYou.mac", defaultValue: "Choose this only if you restored this Mac's vault from a backup yourself. Your other devices are told this copy is now the current one, and the warning stops.\n\nIf you did not restore a backup, choose Cancel, check recent changes and change your master password.")) }
    static var peerRollbackDismiss: String { String(localized: "toast.dismiss", defaultValue: "Dismiss") }
    /// Shown with their own buttons (desktop `ROLLBACK_KINDS`).
    static let rollbackKinds: Set<String> = ["vault-rollback", "peer-vault-rollback"]

    static func epochBehindFolderCopy(subject s: String, here: Bool = false) -> String {
        pc(here, String(localized: "sync.thisPcHasAnOlder2", defaultValue: "This PC has an older sync key than \(s). Let the cloud folder finish syncing, or join the folder again with the newest sync password."), phone: String(localized: "sync.thisPcHasAnOlder2.phone", defaultValue: "This iPhone has an older sync key than \(s). Let the cloud folder finish syncing, or join the folder again with the newest sync password."), mac: String(localized: "sync.thisPcHasAnOlder2.mac", defaultValue: "This Mac has an older sync key than \(s). Let the cloud folder finish syncing, or join the folder again with the newest sync password."))
    }
    static func installMismatchCopy(here: Bool = false) -> String { pc(here, String(localized: "sync.thisVaultWasSetUp", defaultValue: "This vault was set up for sync on another PC. Join the folder again on this PC, or reset sync."), phone: String(localized: "sync.thisVaultWasSetUp.phone", defaultValue: "This vault was set up for sync on another device. Join the folder again on this iPhone, or reset sync."), mac: String(localized: "sync.thisVaultWasSetUp.mac", defaultValue: "This vault was set up for sync on another device. Join the folder again on this Mac, or reset sync.")) }
    static func selfDroppedCopy(here: Bool = false) -> String { pc(here, String(localized: "sync.thisPcWasDroppedFrom", defaultValue: "This PC was dropped from the member list. Join the folder again."), phone: String(localized: "sync.thisPcWasDroppedFrom.phone", defaultValue: "This iPhone was dropped from the member list. Join the folder again."), mac: String(localized: "sync.thisPcWasDroppedFrom.mac", defaultValue: "This Mac was dropped from the member list. Join the folder again.")) }
    static var genericCopy: String { String(localized: "sync.syncReportedAProblemDetails", defaultValue: "Sync reported a problem. Details are in the error log.") }
    static let deviceSuffix = ".lgksync"

    static let fileKinds: Set<String> = ["corrupt", "rollback", "suspicious-rewrite", "epoch-mismatch", "device-mismatch",
                                         "unreadable", "stale-device"]
    static let deviceKinds: Set<String> = ["member-dropped", "bad-name", "bad-peer-data", "bad-peer-record", "epoch-behind",
                                           "peer-epoch-behind", "no-endpoint", "peer-revoked", "peer-mismatch", "group-mismatch",
                                           "peer-update-needed", "signer-changed", "peer-vault-rollback", "witness-implausible"]
    /// Issues that stop sync until the user acts; the screen offers Reset sync.
    static let resetKinds: Set<String> = ["folder-has-other-group", "rotation-conflict", "removed-or-conflict", "state-corrupt",
                                          "keyring-corrupt", "tampered", "identity-mismatch", "keyring-rollback"]
    static let errorKinds: Set<String> = resetKinds.union([
        "rejoin-required", "keyring-missing", "keyring-unreadable", "folder-missing", "folder-unreadable",
        "write-failed", "epoch-behind", "error", "listen-failed", "local-data", "apply-failed", "too-large",
        "vault-rollback",
    ])
    static let noticeKinds: Set<String> = ["counter-resynced", "keyring-restored", "busy", "ignored-file", "stale-self",
                                           "unreachable", "no-endpoint", "lan-not-listening", "not-joined",
                                           "peer-vault-rollback", "rollback-acknowledged", "witness-implausible",
                                           "attachment-missing"]
    static let priority = [
        "vault-rollback", "state-corrupt", "folder-has-other-group", "rotation-conflict", "removed-or-conflict", "rejoin-required",
        "tampered", "keyring-rollback", "keyring-corrupt", "identity-mismatch", "keyring-missing", "keyring-unreadable", "folder-missing",
        "folder-unreadable", "epoch-behind", "listen-failed", "write-failed", "too-large", "trash-full",
        "history-quota", "member-dropped", "rollback", "suspicious-rewrite", "corrupt", "bad-peer-data",
        "bad-peer-record", "update-needed",
    ]

    static func errorCopy(_ kind: String, subject s: String = "", here: Bool = false) -> String? {
        switch kind {
        case "password": String(localized: "sync.thatSyncPasswordIsNot", defaultValue: "That sync password is not right for this folder.")
        case "password-reused": String(localized: "sync.chooseANewSyncPassword", defaultValue: "Choose a new sync password; it must differ from the current one.")
        case "weak-password": String(localized: "sync.theSyncPasswordNeedsAt", defaultValue: "The sync password needs at least 12 characters and a Strong rating.")
        case "folder-in-use": String(localized: "sync.thisFolderAlreadyHoldsA", defaultValue: "This folder already holds a sync group. Use Join a folder instead.")
        case "no-group": String(localized: "sync.thereIsNoSyncGroup", defaultValue: "There is no sync group in this folder yet. Create one, or choose the folder your other device uses.")
        case "different-group": String(localized: "sync.thisVaultAlreadySyncsWith", defaultValue: "This vault already syncs with another group. Leave sync first.")
        case "keyring-changed": String(localized: "sync.anotherDeviceChangedTheSync", defaultValue: "Another device changed the sync folder at the same moment. Try again.")
        case "folder-error": String(localized: "sync.theFolderCouldNotBe", defaultValue: "The folder could not be used. Check that it exists and is writable.")
        case "folder-missing": String(localized: "sync.thatFolderDoesNotExist", defaultValue: "That folder does not exist or is not available.")
        case "too-many-members": String(localized: "sync.thisSyncGroupAlreadyHas", defaultValue: "This sync group already has the most devices (16). Remove one first.")
        case "cannot-remove-self": pc(here, String(localized: "sync.thisPcCannotRemoveItself", defaultValue: "This PC cannot remove itself. Use Leave sync instead."), phone: String(localized: "sync.thisPcCannotRemoveItself.phone", defaultValue: "This iPhone cannot remove itself. Use Leave sync instead."), mac: String(localized: "sync.thisPcCannotRemoveItself.mac", defaultValue: "This Mac cannot remove itself. Use Leave sync instead."))
        case "already-joined": String(localized: "sync.thisVaultIsAlreadyIn", defaultValue: "This vault is already in a sync group. Leave sync first.")
        case "not-joined": String(localized: "sync.thisVaultIsNotIn", defaultValue: "This vault is not in a sync group.")
        case "rejoin-required": pc(here, String(localized: "sync.thisVaultWasSetUp2", defaultValue: "This vault was set up for sync on another PC. Join the folder again on this PC."), phone: String(localized: "sync.thisVaultWasSetUp2.phone", defaultValue: "This vault was set up for sync on another device. Join the folder again on this iPhone."), mac: String(localized: "sync.thisVaultWasSetUp2.mac", defaultValue: "This vault was set up for sync on another device. Join the folder again on this Mac."))
        case "not-member": String(localized: "sync.thatDeviceIsNotIn", defaultValue: "That device is not in this sync group.")
        case "missed-rotation": pc(here, String(localized: "sync.thisPcMissedAPassword", defaultValue: "This PC missed a password change. Join the folder again with the current sync password."), phone: String(localized: "sync.thisPcMissedAPassword.phone", defaultValue: "This iPhone missed a password change. Join the folder again with the current sync password."), mac: String(localized: "sync.thisPcMissedAPassword.mac", defaultValue: "This Mac missed a password change. Join the folder again with the current sync password."))
        case "offer-used-or-expired": String(localized: "sync.thisPairingCodeWasUsed", defaultValue: "This pairing code was used up or expired. Show a new code.")
        case "unreachable": String(localized: "sync.theOtherDeviceCouldNot", defaultValue: "The other device could not be reached. Check that both are on the same Wi-Fi and that the other device shows its code.")
        case "too-many-peers": String(localized: "sync.theOtherDeviceAlreadyHas", defaultValue: "The other device already has the most paired devices. Remove one there first.")
        case "declined": String(localized: "sync.theOtherDeviceDeclinedOr", defaultValue: "The other device declined, or nobody chose Accept there in time. Show a new code there and choose Accept when both screens show the same code.")
        case "update-needed": pc(here, String(localized: "sync.updateLocalgatekeysOnThisPc", defaultValue: "Update LocalGateKeys on this PC to pair with that device."), phone: String(localized: "sync.updateLocalgatekeysOnThisPc.phone", defaultValue: "Update LocalGateKeys on this iPhone to pair with that device."), mac: String(localized: "sync.updateLocalgatekeysOnThisPc.mac", defaultValue: "Update LocalGateKeys on this Mac to pair with that device."))
        case "bad-offer": String(localized: "sync.thatIsNotAValid", defaultValue: "That is not a valid LocalGateKeys pairing code.")
        case "refused": String(localized: "sync.theOtherDeviceRefusedThe2", defaultValue: "The other device refused the pairing. Show a new code and try again.")
        case "not-our-offer": String(localized: "sync.thisPairingCodeBelongsTo", defaultValue: "This pairing code belongs to another sync group. Show a new code.")
        case "already-has-folder": String(localized: "sync.thisSyncGroupAlreadyUses", defaultValue: "This sync group already uses a cloud folder.")
        case "folder-has-other-group": String(localized: "sync.thatFolderHoldsADifferent", defaultValue: "That folder holds a different sync group. Choose another folder, or the folder your other device added to this group.")
        case "different-group-key": String(localized: "sync.thatFolderSSyncGroup", defaultValue: "That folder's sync group does not match this vault's group. Choose the folder your other device added to this group.")
        case "epoch-mismatch": pc(here, String(localized: "sync.theSyncKeyInThat", defaultValue: "The sync key in that folder changed after this PC was paired. Leave sync on this PC, then use Join a folder with the current sync password."), phone: String(localized: "sync.theSyncKeyInThat.phone", defaultValue: "The sync key in that folder changed after this iPhone was paired. Leave sync on this iPhone, then use Join a folder with the current sync password."), mac: String(localized: "sync.theSyncKeyInThat.mac", defaultValue: "The sync key in that folder changed after this Mac was paired. Leave sync on this Mac, then use Join a folder with the current sync password."))
        case "already-member": pc(here, String(localized: "sync.thisPcIsAlreadyIn", defaultValue: "This PC is already in that folder's sync group."), phone: String(localized: "sync.thisPcIsAlreadyIn.phone", defaultValue: "This iPhone is already in that folder's sync group."), mac: String(localized: "sync.thisPcIsAlreadyIn.mac", defaultValue: "This Mac is already in that folder's sync group."))
        default: nil
        }
    }
    static var stepFailedCopy: String { String(localized: "sync.syncCouldNotFinishThat", defaultValue: "Sync could not finish that step. Details are in the error log.") }

    static var leaveText: String { onDevice(phone: String(localized: "sync.leaveSyncOnThisPc.phone", defaultValue: "Leave sync on this iPhone?\n\nThis iPhone stops syncing. Your items stay on this iPhone. Its last sync file stays in the sync folder, so your other devices still receive the changes made here.\n\nOn one of your other devices, open Sync and remove this iPhone (Remove a device). That deletes its file and changes the sync password, so this iPhone can no longer read anything new."), mac: String(localized: "sync.leaveSyncOnThisPc.mac", defaultValue: "Leave sync on this Mac?\n\nThis Mac stops syncing. Your items stay on this Mac. Its last sync file stays in the sync folder, so your other devices still receive the changes made here.\n\nOn one of your other devices, open Sync and remove this Mac (Remove a device). That deletes its file and changes the sync password, so this Mac can no longer read anything new.")) }
    static var leaveWifiText: String { onDevice(phone: String(localized: "sync.leaveSyncOnThisPc2.phone", defaultValue: "Leave sync on this iPhone?\n\nThis iPhone stops Wi-Fi sync and forgets its paired devices. Your items stay on this iPhone.\n\nOn your other devices, remove this iPhone from their paired devices. To sync again, pair again with a QR code."), mac: String(localized: "sync.leaveSyncOnThisPc2.mac", defaultValue: "Leave sync on this Mac?\n\nThis Mac stops Wi-Fi sync and forgets its paired devices. Your items stay on this Mac.\n\nOn your other devices, remove this Mac from their paired devices. To sync again, pair again with a QR code.")) }
    /// Second confirmation of Leave (the desktop asks once; the phone asks twice like Reset).
    static var leaveText2: String { onDevice(phone: String(localized: "Are you sure? Leave sync on this iPhone now?"), mac: String(localized: "Are you sure? Leave sync on this Mac now?")) }
    static var resetText1: String { onDevice(phone: String(localized: "sync.resetSyncOnThisPc.phone", defaultValue: "Reset sync on this iPhone?\n\nThis forgets this vault's sync group, its keys and its sync history. Your items stay on this iPhone. To sync again you join a folder or pair again."), mac: String(localized: "sync.resetSyncOnThisPc.mac", defaultValue: "Reset sync on this Mac?\n\nThis forgets this vault's sync group, its keys and its sync history. Your items stay on this Mac. To sync again you join a folder or pair again.")) }
    static var resetText2: String { onDevice(phone: String(localized: "sync.areYouSureThisCannot.phone", defaultValue: "Are you sure? This cannot be undone. Reset sync on this iPhone now?"), mac: String(localized: "sync.areYouSureThisCannot.mac", defaultValue: "Are you sure? This cannot be undone. Reset sync on this Mac now?")) }
    static var leftText: String { onDevice(phone: String(localized: "sync.thisPcLeftSyncRemove.phone", defaultValue: "This iPhone left sync. Remove it on one of your other devices."), mac: String(localized: "sync.thisPcLeftSyncRemove.mac", defaultValue: "This Mac left sync. Remove it on one of your other devices.")) }
    static func resetResultText(_ cleared: Bool) -> String {
        cleared ? onDevice(phone: String(localized: "sync.syncWasResetOnThis.phone", defaultValue: "Sync was reset on this iPhone."), mac: String(localized: "sync.syncWasResetOnThis.mac", defaultValue: "Sync was reset on this Mac."))
            : String(localized: "sync.thereWasNothingToReset", defaultValue: "There was nothing to reset.")
    }
    static var passwordBackoffText: String { String(localized: "Too many wrong sync passwords. Wait 30 seconds, then try again.") }

    // MARK: Wi-Fi pairing (phone only: "the PC" here is the inviting desktop, never rewritten)

    /// Shown under the verification code while the inviting device waits for its user's Accept.
    static var verificationCodeHint: String { String(localized: "Check that the other device shows this code, then choose Accept there.") }

    /// The 6-digit verification code as both screens show it: "123 456".
    static func verificationCodeText(_ code: String) -> String {
        guard code.count == 6 else { return code }
        return String(code.prefix(3)) + " " + String(code.suffix(3))
    }

    /// `host:port`, IPv6 in brackets.
    static func hostPort(_ e: LanEndpoint) -> String { e.host.contains(":") ? "[\(e.host)]:\(e.port)" : "\(e.host):\(e.port)" }

    static func enrollFailureText(_ e: EnrollConnectError) -> String {
        let at = hostPort(e.endpoint)
        switch e.failure {
        case .localNetworkDenied:
            return String(localized: "LocalGateKeys is not allowed to use the local network, so it could not reach \(at). Allow Local Network for LocalGateKeys in Settings › Privacy & Security › Local Network, then scan the code again.")
        case .closedByPeer:
            return String(localized: "The PC at \(at) closed the connection: the code has probably expired or is no longer waiting. Show a new code on the PC and scan it again.")
        case .cancelled:
            return String(localized: "Pairing was cancelled.")
        default: break
        }
        if let subnet = e.offSubnet {
            return String(localized: "The code points to \(e.endpoint.host) but this \(thisDevice) is on \(subnet). On the PC, set the sync address to its Wi-Fi IPv4 address (ipconfig) and show a new code.")
        }
        switch e.failure {
        case .refused:
            return String(localized: "Nothing is listening at \(at). Open Sync on the PC, choose Show QR code, and scan the new code.")
        case .unreachable:
            return String(localized: "\(at) cannot be reached from this \(thisDevice). Check that the PC is on this Wi-Fi and that the code shows the PC's Wi-Fi address.")
        case .timedOut:
            return String(localized: "\(at) did not answer. Check that Windows Firewall allows LocalGateKeys on Private networks, and that the PC is on this Wi-Fi.")
        default:
            return String(localized: "Could not connect to \(at). Check that the PC is on this Wi-Fi and shows its code.")
        }
    }

    // MARK: rendering (desktop issue_text / _issue_views)

    enum Severity: Int, Comparable { case error = 0, warning = 1, notice = 2
        static func < (a: Severity, b: Severity) -> Bool { a.rawValue < b.rawValue }
    }

    struct IssueView: Equatable, Identifiable {
        let kind: String
        let severity: Severity
        let text: String
        let resetOffered: Bool
        /// The peer id of a `peer-vault-rollback` (its Dismiss button); empty for every other kind.
        var detail: String = ""
        var id: String { kind + "|" + text }
    }

    static func severity(_ kind: String) -> Severity {
        if errorKinds.contains(kind) { return .error }
        if noticeKinds.contains(kind) { return .notice }
        return .warning
    }

    static func head(_ detail: String) -> String {
        guard let r = detail.range(of: ": ") else { return detail.trimmingCharacters(in: .whitespaces) }
        return String(detail[..<r.lowerBound]).trimmingCharacters(in: .whitespaces)
    }

    static func effectiveKind(_ kind: String, _ detail: String) -> String {
        if kind == "rollback" && !head(detail).hasSuffix(deviceSuffix) { return "keyring-rollback" }
        return kind
    }

    /// Desktop `sanitize_name`: control/format characters dropped, whitespace collapsed, at most `limit`.
    static func sanitize(_ value: String, limit: Int = nameLimit) -> String {
        var out = ""
        for ch in value.unicodeScalars {
            let cat = ch.properties.generalCategory
            switch cat {
            case .spaceSeparator, .lineSeparator, .paragraphSeparator: out.unicodeScalars.append(" ")
            case .control where ch == "\r" || ch == "\n" || ch == "\t": out.unicodeScalars.append(" ")
            case .control, .format, .surrogate, .privateUse, .unassigned: continue
            default: out.unicodeScalars.append(ch)
            }
        }
        var text = out.split(whereSeparator: { $0 == " " }).joined(separator: " ")
        if text.isEmpty { return unnamedDevice }
        if text.unicodeScalars.count > limit {
            let kept = String(String.UnicodeScalarView(text.unicodeScalars.prefix(max(1, limit - 1))))
            text = kept.replacingOccurrences(of: "\\s+$", with: "", options: .regularExpression) + "…"
        }
        return text
    }

    static func shortID(_ id: String) -> String {
        let short = String(String.UnicodeScalarView(sanitize(id, limit: 9).unicodeScalars.prefix(8)))
        return String(localized: "sync.deviceShortId", defaultValue: "Device \(short)")
    }

    static func subject(_ kind: String, _ detail: String, names: [String: String], ownID: String?, here: Bool = false) -> String {
        var kind = kind
        var head = detail.isEmpty ? "" : Self.head(detail)
        if kind == "bad-peer-record" { head = detail.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).first.map { String($0).trimmingCharacters(in: .whitespaces) } ?? "" }
        if kind == "device-mismatch" && !head.hasSuffix(deviceSuffix) { kind = "bad-peer-data" }
        if deviceKinds.contains(kind) {
            if head.isEmpty { return String(localized: "sync.anotherDevice", defaultValue: "Another device") }
            // Code-point comparison (device ids and names come from peers; Swift `==` is canonical equivalence).
            if let ownID, Scalars.equal(head, ownID) { return pc(here, String(localized: "sync.thisPc", defaultValue: "this PC"), phone: String(localized: "sync.thisPc.phone", defaultValue: "this iPhone"), mac: String(localized: "sync.thisPc.mac", defaultValue: "this Mac")) }
            let name = kind != "bad-name" ? names.first(where: { Scalars.equal($0.key, head) })?.value : nil
            if let name, !name.isEmpty { return sanitize(name) }
            return shortID(head)
        }
        if fileKinds.contains(kind) {
            if head.isEmpty { return String(localized: "sync.aSyncFile", defaultValue: "A sync file") }
            let name = sanitize(head, limit: 60)
            return String(localized: "sync.theFileName", defaultValue: "The file \(name)")
        }
        if kind == "ignored-file" { return detail.isEmpty ? String(localized: "sync.someFiles", defaultValue: "some files") : sanitize(detail, limit: 120) }
        return ""
    }

    /// Desktop `issue_text` (with "PC" as on the desktop).
    static func desktopText(_ issue: SyncIssue, names: [String: String] = [:], ownID: String? = nil, folder: Bool = false, here: Bool = false) -> String {
        let detail = issue.detail
        let kind = effectiveKind(issue.kind, detail)
        if kind == "rejoin-required" && detail == "install-mismatch" { return installMismatchCopy(here: here) }
        if kind == "member-dropped", let ownID, Scalars.equal(detail, ownID) { return selfDroppedCopy(here: here) }
        let subject = subject(kind, detail, names: names, ownID: ownID, here: here)
        let text: String
        if kind == "device-mismatch" && !head(detail).hasSuffix(deviceSuffix) {
            text = String(localized: "sync.sentDataSignedForA", defaultValue: "\(subject) sent data signed for a different device; it was skipped.")
        } else if kind == "epoch-behind" && folder {
            text = epochBehindFolderCopy(subject: subject, here: here)
        } else if let copy = issueCopy(kind, subject: subject, here: here) {
            text = copy
        } else {
            return genericCopy
        }
        guard let first = text.first else { return text }
        return first.uppercased() + text.dropFirst()
    }

    /// The desktop text as shown on the phone.
    static func text(_ issue: SyncIssue, names: [String: String] = [:], ownID: String? = nil, folder: Bool = false) -> String {
        desktopText(issue, names: names, ownID: ownID, folder: folder, here: true)
    }

    /// Deduplicated (kind + detail, then identical text) and sorted by importance (desktop `_issue_views`).
    static func views(_ issues: [SyncIssue], names: [String: String] = [:], ownID: String? = nil, folder: Bool = false) -> [IssueView] {
        var seen = Set<String>(), texts = Set<String>()
        var out: [IssueView] = []
        for issue in issues {
            let kind = effectiveKind(issue.kind, issue.detail)
            guard seen.insert(kind + "\u{0}" + issue.detail).inserted else { continue }
            let text = text(issue, names: names, ownID: ownID, folder: folder)
            guard texts.insert(text).inserted else { continue }
            out.append(IssueView(kind: kind, severity: severity(kind), text: text, resetOffered: resetKinds.contains(kind),
                                 detail: kind == "peer-vault-rollback" ? issue.detail : ""))
        }
        func rank(_ v: IssueView) -> (Int, Int) { (v.severity.rawValue, priority.firstIndex(of: v.kind) ?? priority.count) }
        return out.enumerated().sorted { rank($0.element) < rank($1.element) || (rank($0.element) == rank($1.element) && $0.offset < $1.offset) }.map(\.element)
    }

    /// Desktop `error_text` for a refused action (reason code).
    static func errorText(reason: String) -> String {
        if let t = errorCopy(reason, here: true) { return t }
        if issueCopy(reason) != nil { return text(SyncIssue(reason)) }
        return stepFailedCopy
    }

    /// English-only rewrite of "PC" to this device (tests and English literals). Shown copy uses the `.phone` /
    /// `.mac` catalog entries instead, so translations need no rewriting; on those this is a no-op.
    static func onPhone(_ text: String) -> String {
        text.replacingOccurrences(of: "another PC", with: "another device")
            .replacingOccurrences(of: "\\bPC\\b", with: thisDevice, options: .regularExpression)
    }

    // MARK: Find again (plan 2026-10-29-sync-ip-change, section 4)

    #if os(macOS)
    static var hostNotFoundTitle: String { String(localized: "Can't find the paired device on this network.") }
    static var findAgainHint: String { String(localized: "On the other device open Sync and choose Show QR code, then paste its code text here. Only the address is updated; the pairing stays as it is.") }
    #else
    static var hostNotFoundTitle: String { String(localized: "Can't find your PC on this network.") }
    static var findAgainHint: String { String(localized: "On your PC open Sync and choose Show QR code, then scan it. Only the address is updated; the pairing stays as it is.") }
    #endif
    static var findAgainAction: String { String(localized: "syncPage.findAgain", defaultValue: "Find again") }

    static func findAgainText(_ refusal: PeerAddressRefresh.Refusal) -> String {
        switch refusal {
        case .notAPairingCode: return String(localized: "That is not a LocalGateKeys pairing code.")
        case .otherDevice: return String(localized: "That code is from a different device than the one this \(thisDevice) is paired with. Nothing was changed. To sync with that device, leave sync and pair again.")
        case .notLAN: return String(localized: "That code's address is not on a local network. Nothing was changed.")
        }
    }

    static func foundAgainText(_ e: LanEndpoint) -> String { String(localized: "Address updated to \(hostPort(e)). Syncing…") }
}

/// "Sync status you can tap" (UX plan 2026-10-27 workstream 6, Android `SyncStatusSummary`, Windows
/// `app/sync_status.py`): the pill ("Synced 2 min ago · 3 devices" with a green, orange or red dot) and the Sync
/// status sheet's device rows. Pure: built from the coordinator's membership and issues.
struct SyncStatusSummary: Equatable {
    enum Dot: Equatable { case green, orange, red }

    enum Route: Equatable {
        case wifi, folder, both
        var label: String {
            switch self {
            case .wifi: String(localized: "Wi-Fi")
            case .folder: String(localized: "sync.cloudFolder", defaultValue: "Cloud folder")
            case .both: String(localized: "Wi-Fi and cloud folder")
            }
        }
    }

    /// One other device: `lastSynced` is when this device last accepted its changes (nil: never).
    struct Device: Equatable, Identifiable {
        let id: String
        let name: String
        let route: Route
        let lastSynced: Int64?
        let warning: String?
    }

    let pill: String
    let dot: Dot
    let devices: [Device]

    static let day: Int64 = 86_400
    static let staleDays: Int64 = 30
    static var title: String { String(localized: "syncStatusPage.title", defaultValue: "Sync status") }
    static var syncNow: String { String(localized: "syncStatusPage.syncNow", defaultValue: "Sync now") }
    static var openSettings: String { String(localized: "syncStatusPage.openSettings", defaultValue: "Open sync settings") }
    static var never: String { String(localized: "settings.never", defaultValue: "Never") }
    static var notSeen: String { String(localized: "syncStatus.notSeenIn30Days", defaultValue: "Not seen in 30 days") }
    #if os(macOS)
    static var thisDevice: String { String(localized: "This Mac") }
    #else
    static var thisDevice: String { String(localized: "This iPhone") }
    #endif

    /// Nil when this device does not sync.
    static func make(membership: SyncCoordinator.Membership, issues: [SyncWording.IssueView], lastSyncedAt: Int64?,
                     now: Int64) -> SyncStatusSummary? {
        guard membership.joined else { return nil }
        let wifi = Set(membership.wifiPeers)
        let folder = Set(membership.hasFolder ? membership.members : [])
        let ids = wifi.union(folder).subtracting([membership.deviceID ?? ""]).sorted()
        let devices = ids.map { id -> Device in
            let route: Route = wifi.contains(id) && folder.contains(id) ? .both : (wifi.contains(id) ? .wifi : .folder)
            let at = membership.peerSyncedAt[id]
            let warning: String? = if let at, now - at > staleDays * day { notSeen } else { nil }
            let name = membership.names[id].map { SyncWording.sanitize($0) } ?? SyncWording.shortID(id)
            return Device(id: id, name: name, route: route, lastSynced: at, warning: warning)
        }
        let dot: Dot
        if issues.contains(where: { $0.severity == .error }) {
            dot = .red
        } else if lastSyncedAt.map({ now - $0 > day }) ?? true {
            dot = .orange
        } else if issues.contains(where: { $0.severity == .warning }) || devices.contains(where: { $0.warning != nil }) {
            dot = .orange
        } else {
            dot = .green
        }
        let count = devices.count + 1
        let time = lastSyncedAt.map { at in
            let elapsed = ago(now - at)
            return String(localized: "syncStatus.synced", defaultValue: "Synced \(elapsed)")
        } ?? String(localized: "status.sync.never", defaultValue: "Not synced yet")
        let deviceCount = String(localized: "syncStatus.deviceCount", defaultValue: "\(count) devices")
        return SyncStatusSummary(pill: "\(time) · \(deviceCount)", dot: dot, devices: devices)
    }

    /// "just now", "2 min ago", "3 h ago", "1 day ago", "4 days ago".
    static func ago(_ seconds: Int64) -> String {
        let s = max(0, seconds)
        if s < 60 { return String(localized: "overview.age.justNow", defaultValue: "just now") }
        if s < 3600 { let v = s / 60; return String(localized: "syncStatus.minAgo", defaultValue: "\(v) min ago") }
        if s < day { let v = s / 3600; return String(localized: "syncStatus.hAgo", defaultValue: "\(v) h ago") }
        let days = s / day
        return String(localized: "overview.age.days", defaultValue: "\(days) days ago")
    }

    /// "Last synced 14:02 (12 min ago)" or "Never".
    static func lastSyncedText(_ at: Int64?, now: Int64, timeZone: TimeZone = .current, locale: Locale = .current) -> String {
        guard let at else { return never }
        let f = DateFormatter()
        f.locale = locale; f.timeZone = timeZone
        f.dateStyle = .none; f.timeStyle = .short
        let clock = f.string(from: Date(timeIntervalSince1970: TimeInterval(at)))
        let elapsed = ago(now - at)
        return String(localized: "syncStatus.lastSynced", defaultValue: "Last synced \(clock) (\(elapsed))")
    }

    /// The dot's spoken name (VoiceOver).
    static func dotDescription(_ dot: Dot) -> String {
        switch dot {
        case .green: String(localized: "Sync is up to date")
        case .orange: String(localized: "status.sync.attention", defaultValue: "Sync needs attention")
        case .red: String(localized: "Sync has a problem")
        }
    }
}
