import Foundation
import AppSharedMac

/// What restoring a full backup by replacing would do, shown before anything is written (Windows Recovery centre
/// "Preview restore"): what the backup holds, how it compares with this Mac's vault, and the counts.
struct RestorePreview: Equatable, Sendable {
    /// The profile the backup was made from (Windows profile folder name, or the Mac's name).
    let profileName: String
    let createdAt: Int64?
    /// Website and desktop logins in the backup.
    let logins: Int
    /// Other items (cards, notes, passkeys, …) in the backup.
    let otherItems: Int
    /// Windows documents: kept for the next backup but not shown on the Mac.
    let keptOnly: Int
    let attachments: Int
    let recoveryPhraseEnrolled: Bool
    /// Items in this Mac's vault now.
    let currentItems: Int
    /// Items in the backup that are not in this vault.
    let added: Int
    /// Items in both that differ (the backup's copy replaces this Mac's).
    let replaced: Int
    let unchanged: Int
    /// Items here that the backup does not have: they move to Recently deleted.
    let removed: Int
    /// true: the backup is newer than the newest change here; false: older; nil: unknown.
    let backupIsNewer: Bool?
    /// This Mac is in a sync group: the other devices get the restored vault on the next sync.
    let syncs: Bool

    var items: Int { logins + otherItems }

    nonisolated static func dateText(_ seconds: Int64) -> String {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f.string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
    }

    /// The preview text.
    var lines: [String] {
        var out: [String] = []
        if let createdAt { out.append(String(localized: "Backup of \(profileName), made \(Self.dateText(createdAt))")) } else { out.append(String(localized: "Backup of \(profileName)")) }
        out.append(String(localized: "\(logins) logins and \(otherItems) other items"))
        if attachments > 0 { out.append(String(localized: "\(attachments) attachments (kept for the desktop app)")) }
        if keptOnly > 0 { out.append(String(localized: "\(keptOnly) documents (kept for the desktop app)")) }
        switch backupIsNewer {
        case true?: out.append(String(localized: "The backup is newer than the vault on this Mac"))
        case false?: out.append(String(localized: "The backup is older than the vault on this Mac"))
        case nil: break
        }
        out.append(String(localized: "\(added) new items, \(replaced) items replaced by the backup's copy, \(unchanged) unchanged"))
        if removed > 0 { out.append(String(localized: "\(removed) items not in the backup move to Recently deleted")) }
        if syncs { out.append(String(localized: "Your other devices get the restored vault the next time they sync")) }
        return out
    }
}
