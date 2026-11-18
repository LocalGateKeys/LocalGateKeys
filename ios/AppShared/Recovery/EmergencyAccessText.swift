import Foundation
import LGKCore

/// The words of emergency access on iPhone and Mac (sub-plan 08; Android `heir_*`, same English so the translations
/// carry over).
public enum EmergencyAccessText {
    public static let title = String(localized: "Emergency access")
    public static let collusion = String(localized: "Enough holders acting together (as many as the plan needs) can open your backup at once: the waiting period and your devices' refusal only stop honest requests. Pick people who would not act together.")
    public static let notHome = String(localized: "This plan was made on another of your devices and reached this one by sync. You can deny or grant requests here; the emergency access backups come from the device that made it.")
    public static let planSection = String(localized: "Your plan")
    public static let noPlan = String(localized: "Plans are made in LocalGateKeys on your computer. Once your devices sync, the plan shows here and you can deny or grant requests from this phone.")
    public static let footer = String(localized: "Requests from the people who hold shards of your plan, and shards someone gave you.")
    public static let folder = String(localized: "Shared folder")
    public static let noFolder = String(localized: "none chosen")
    public static let chooseFolder = String(localized: "Choose folder")
    public static let folderSet = String(localized: "Shared folder set for this plan on this device.")
    public static let requests = String(localized: "Access requests")
    public static let noRequests = String(localized: "No requests.")
    public static let grantedLine = String(localized: "Access granted")
    public static let deny = String(localized: "Deny")
    public static let grant = String(localized: "Grant now")
    public static let grantTitle = String(localized: "Grant access now")
    public static let grantPhrase = String(localized: "Your recovery phrase")
    public static let flooded = String(localized: "The emergency access folder holds too many request files, so some may not have been read. Check the folder.")
    public static let receive = String(localized: "I was given access")
    public static let receiveMeta = String(localized: "Use a shard someone gave you to ask for access to their vault.")
    public static let shardsTitle = String(localized: "Shards")
    public static let noShards = String(localized: "No shards added yet.")
    public static let addFile = String(localized: "Add a shard file")
    public static let paste = String(localized: "Or paste a scanned shard code")
    public static let addText = String(localized: "Add")
    public static let clear = String(localized: "Remove the shards")
    public static let request = String(localized: "Ask for access")
    public static let refresh = String(localized: "Check again")
    public static let stateNone = String(localized: "You have not asked for access yet.")
    public static let stateDenied = String(localized: "The owner denied your request. You can ask again.")
    public static let stateNoBackup = String(localized: "No recent backup: the owner's app has not written a backup to the shared folder since the plan was made.")
    public static let stateReady = String(localized: "Ready: you can now show the owner's recovery phrase. It opens the owner's vault in LocalGateKeys on their computer (Forgot your master password?). Keep it as safe as the vault itself.")
    public static let showPhrase = String(localized: "Show the recovery phrase")
    public static let phraseTitle = String(localized: "The owner's recovery phrase")
    public static let addShardFirst = String(localized: "Add your shard and choose the shared folder first.")
    public static let noFileChosen = String(localized: "No file was chosen.")

    public static func planLine(k: Int, n: Int, days: Int, made: String) -> String {
        String(localized: "\(k) of \(n) holders needed, waiting period \(days) days, made on \(made)")
    }
    public static func requestLine(holder: String, date: String, daysLeft: Int) -> String {
        String(localized: "\(holder) asked for access on \(date). Days left: \(daysLeft)")
    }
    public static func grantConfirm(_ holder: String) -> String {
        String(localized: "\(holder) will be able to open your latest backup at once, without the waiting period. Do this only after speaking with \(holder) yourself.")
    }
    public static func deniedMessage(_ holder: String) -> String { String(localized: "The request from \(holder) was denied.") }
    public static func grantedMessage(_ holder: String) -> String { String(localized: "Access granted to \(holder).") }
    public static func requestNotice(holder: String, daysLeft: Int) -> String {
        String(localized: "\(holder) asked for emergency access to your vault. Days left to deny it: \(daysLeft).")
    }
    public static func shardLine(index: Int, holder: String) -> String { String(localized: "Shard \(index) (\(holder))") }
    public static func planOf(owner: String, k: Int) -> String { String(localized: "Owner: \(owner). Shards needed: \(k).") }
    public static func shardAdded(_ owner: String) -> String { String(localized: "Shard of \(owner) added.") }
    public static func requestSent(days: Int) -> String {
        String(localized: "Request sent. The owner's devices can refuse it during the waiting period (\(days) days).")
    }
    public static func stateWaiting(_ days: Int) -> String { String(localized: "The waiting period is not over. Days left: \(days).") }
    public static func stateNeedMore(_ missing: Int) -> String { String(localized: "Shards still needed: \(missing).") }

    /// The holder's status line.
    public static func state(_ s: HeirStatus) -> String {
        switch s.state {
        case "denied": stateDenied
        case "waiting": stateWaiting(s.daysLeft)
        case "need-more": stateNeedMore(s.missing)
        case "no-backup": stateNoBackup
        case "ready": stateReady
        default: stateNone
        }
    }

    /// A refusal from the heir code in words.
    public static func message(_ error: Error) -> String {
        var reason = "", missing = 0, daysLeft = 0
        if let e = error as? HeirFlowError { reason = e.reason; missing = e.missing; daysLeft = e.daysLeft }
        else if let e = error as? HeirError { reason = e.reason; missing = e.missing }
        switch reason {
        case "no-folder": return String(localized: "The shared folder is not available.")
        case "no-request": return String(localized: "There is no access request yet. Ask for access first.")
        case "denied": return String(localized: "The owner denied this request.")
        case "stale-plan": return String(localized: "Your recovery phrase was replaced after this plan was made. Make a new plan and re-issue the shards.")
        case "check-failed": return String(localized: "These shards do not recover the owner's recovery phrase.")
        case "mixed-plans": return String(localized: "These shards come from different plans.")
        case "duplicate": return String(localized: "This shard was already added.")
        case "wrong-phrase": return String(localized: "This is not the recovery phrase the plan was made from.")
        case "waiting": return stateWaiting(daysLeft)
        case "need-more": return stateNeedMore(missing)
        case "no-backup": return stateNoBackup
        default: return String(localized: "This emergency access file is damaged.")
        }
    }
}
