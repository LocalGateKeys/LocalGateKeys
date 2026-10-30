import Foundation

/// The iPhone's command palette (UX plan workstream 5): the vault search doubles as the palette. A query that
/// starts with `>` lists actions instead of items (the Windows and Mac palette's `>` prefix); the words after it
/// filter them by title and keywords. A hardware keyboard opens the search with ⌘K.
enum PhoneCommand: String, CaseIterable, Identifiable {
    case newItem = "new-item"
    case generatePassword = "generate-password"
    case scanQR = "scan-qr"
    case lockNow = "lock"
    case syncNow = "sync-now"
    case syncStatus = "sync-status"
    case securityCheck = "security-check"
    case trash
    case settings
    case importExport = "import-export"
    case autoFill = "autofill-settings"
    case syncSettings = "sync-settings"
    case showSetup = "show-setup"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .newItem: String(localized: "New item")
        case .generatePassword: String(localized: "Generate password")
        case .scanQR: String(localized: "Scan QR code")
        case .lockNow: String(localized: "Lock now")
        case .syncNow: String(localized: "Sync now")
        case .syncStatus: String(localized: "Sync status")
        case .securityCheck: String(localized: "Security check")
        case .trash: String(localized: "Recently deleted")
        case .settings: String(localized: "Settings")
        case .importExport: String(localized: "Import & Export")
        case .autoFill: String(localized: "AutoFill settings")
        case .syncSettings: String(localized: "Sync settings")
        case .showSetup: String(localized: "Show setup again")
        }
    }

    var icon: String {
        switch self {
        case .newItem: "plus"
        case .generatePassword: "wand.and.stars"
        case .scanQR: "qrcode.viewfinder"
        case .lockNow: "lock"
        case .syncNow: "arrow.triangle.2.circlepath"
        case .syncStatus: "dot.radiowaves.left.and.right"
        case .securityCheck: "checkmark.shield"
        case .trash: "trash"
        case .settings: "gearshape"
        case .importExport: "square.and.arrow.down"
        case .autoFill: "key.viewfinder"
        case .syncSettings: "arrow.triangle.2.circlepath.circle"
        case .showSetup: "checklist"
        }
    }

    /// Extra words the filter matches (lower case).
    var keywords: [String] {
        switch self {
        case .newItem: ["add", "create", "login", "card", "note"]
        case .generatePassword: ["generator", "random", "passphrase"]
        case .scanQR: ["2fa", "totp", "camera", "code"]
        case .lockNow: ["close", "lock"]
        case .syncNow: ["refresh", "devices"]
        case .syncStatus: ["devices", "last", "status"]
        case .securityCheck: ["weak", "reused", "health", "audit"]
        case .trash: ["trash", "deleted", "restore", "bin"]
        case .settings: ["preferences", "options"]
        case .importExport: ["import", "export", "csv", "backup"]
        case .autoFill: ["autofill", "fill", "quicktype", "passkeys"]
        case .syncSettings: ["wifi", "folder", "pair"]
        case .showSetup: ["onboarding", "setup", "guide", "help"]
        }
    }

    /// The query's command filter: nil when the query is an item search (no leading `>`), else the words after
    /// the `>` (trimmed; empty lists every action).
    static func filter(_ query: String) -> String? {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard q.hasPrefix(">") else { return nil }
        return String(q.dropFirst()).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The actions for a `>` query, in list order; nil for an item search. Every word must match the title or
    /// a keyword (case and diacritics ignored).
    static func matches(_ query: String) -> [PhoneCommand]? {
        guard let filter = filter(query) else { return nil }
        let words = filter.split(whereSeparator: \.isWhitespace).map { fold(String($0)) }
        guard !words.isEmpty else { return allCases }
        return allCases.filter { c in
            let hay = ([c.title] + c.keywords).map(fold)
            return words.allSatisfy { w in hay.contains { $0.contains(w) } }
        }
    }

    private static func fold(_ s: String) -> String {
        s.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
    }
}
