import Foundation
import AppSharedMac

/// Access rules on this Mac (feature pack §4): a login's synced `scope.access` together with its `policy`, read
/// for a computer (view only on phones does not apply here). `require_master_password`, an expired rule and a rule
/// from a newer version ask for the master password on every reveal, copy and fill (`StrictItemGate`); copy once asks
/// again after the first copy in an unlock; `policy.fill` never, an expired or an unknown rule keep the login out of
/// AutoFill. Typed items have no access rules; their `policy.require_master_password` still counts.
enum MacAccess {
    /// Posted (main thread) when travel mode changed on this Mac: the window and the menu bar reload their lists.
    static let travelModeChanged = Notification.Name("app.localgatekeys.mac.travelModeChanged")

    /// The rules of `record` on this Mac at `today` (`YYYY-MM-DD`, local date).
    static func rules(_ record: [String: JSONValue], today: String = RecordDigest.today()) -> AccessRules.Effective {
        let kind: String = if case .string(let k)? = record["kind"] { k } else { "" }
        if kind == "web" || kind == "desktop" { return AccessRules.effective(record, device: .computer, today: today) }
        guard AccessRules.requiresMasterPassword(record) else { return .open }   // any value but false (scan A-L1)
        var strict = AccessRules.Effective.open
        strict.reauth = true
        return strict
    }

    /// The master password before every release of this item's secrets.
    static func requiresMasterPassword(_ record: [String: JSONValue], today: String = RecordDigest.today()) -> Bool {
        rules(record, today: today).reauth
    }

    /// The banner a login's rules show in the detail pane: an expired rule or one from a newer version; nil otherwise.
    static func banner(_ rules: AccessRules.Effective) -> String? {
        if rules.unknownRule { return String(localized: "This login has a rule from a newer version, so the strictest rules apply here.") }
        guard rules.expired else { return nil }
        if let date = rules.expiresOn { return String(localized: "Access expired on \(date). Confirming it's you is needed for every use.") }
        return String(localized: "Access has expired. Confirming it's you is needed for every use.")
    }

    /// Items this Mac leaves out of unencrypted exports (CSV, CXF): travel-hidden items (§2).
    @MainActor
    static func exportLeftOut(_ snapshot: StoreSnapshot) -> Set<String> {
        TravelModeBox.shared.current.hiddenIDs(in: snapshot)
    }

    /// Items travel mode hides on this Mac right now (list, search, menu bar, collections, checks).
    @MainActor
    static func travelHidden(_ snapshot: StoreSnapshot) -> Set<String> {
        TravelModeBox.shared.current.hiddenIDs(in: snapshot)
    }
}
