import Foundation

/// The words of the duress password (sub-plan 08; Android `DuressText`, same English so the translations carry
/// over). Nothing here ever says "decoy".
public enum DuressText {
    public static let generic = String(localized: "Couldn't save the change. Try again later.")
    public static let section = String(localized: "Duress password")
    public static let note = String(localized: "A second app password for when someone forces you to unlock. It opens a separate vault with a few sample items. After it is used, this vault refuses its app password, the Face ID shortcut and the recovery phrase for the hours you choose.")
    public static let statusOff = String(localized: "Not set up.")
    public static let setUp = String(localized: "Set up")
    public static let password = String(localized: "Duress password")
    public static let confirm = String(localized: "Repeat duress password")
    public static let current = String(localized: "Current app password")
    public static let hoursLabel = String(localized: "Hours to refuse the app password")
    public static let removeTitle = String(localized: "Remove the duress password?")
    public static let removeText = String(localized: "The second vault it opens is deleted. This cannot be undone.")
    public static let remove = String(localized: "Remove duress password")
    public static let removed = String(localized: "Duress password removed.")
    public static let needsAppPassword = String(localized: "Turn on the app password first: the duress password is a second app password.")
    public static let proOnly = String(localized: "The duress password needs LocalGateKeys Pro.")
    public static let unavailable = String(localized: "This is not available right now.")

    /// "Set up. ... for N hours." (Settings, real vault only).
    public static func statusOn(hours: Int) -> String {
        String(localized: "Set up. After the duress password is used, this vault refuses its app password for \(hours) hours.")
    }

    public static func message(_ e: DuressError) -> String {
        switch e.code {
        case "same": String(localized: "The duress password must be different from your app password.")
        case "close": String(localized: "The duress password is too close to your app password. Change more than one character.")
        case "near_duress": String(localized: "This app password is too close to your duress password. Choose one that differs in more than one character.")
        case "mismatch": String(localized: "The duress passwords do not match.")
        case "hours": String(localized: "Choose between \(PhoneDuress.minHours) and \(PhoneDuress.maxHours) hours.")
        case "exists": String(localized: "A duress password is already set up. Remove it first.")
        case "needs_password": needsAppPassword
        case "pro": proOnly
        case "unavailable": unavailable
        default: generic
        }
    }
}
