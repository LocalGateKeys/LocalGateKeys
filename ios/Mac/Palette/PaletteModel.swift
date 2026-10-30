import Foundation
import Observation
import LGKCore

/// The Settings sections the palette can open (Windows `_SETTINGS_SECTIONS`, the ones the Mac has).
enum SettingsSection: String, CaseIterable, Hashable, Sendable {
    case locking = "Locking", unlocking = "Unlocking", privacy = "Privacy", appearance = "Appearance", plan = "Plan"

    var title: String {
        switch self {
        case .locking: String(localized: "Locking")
        case .unlocking: String(localized: "Unlocking")
        case .privacy: String(localized: "Privacy")
        case .appearance: String(localized: "Appearance")
        case .plan: String(localized: "Plan")
        }
    }

    var subtitle: String {
        switch self {
        case .locking: String(localized: "Auto-lock and idle timeouts")
        case .unlocking: String(localized: "Master password and Touch ID")
        case .privacy: String(localized: "Clipboard, breach checks and trash")
        case .appearance: String(localized: "Theme")
        case .plan: String(localized: "Pro and purchases")
        }
    }

    var keywords: [String] {
        switch self {
        case .locking: ["lock", "timeout", "idle", "auto-lock", "sleep"]
        case .unlocking: ["touch", "fingerprint", "biometric", "password"]
        case .privacy: ["clipboard", "breach", "offline", "trash"]
        case .appearance: ["theme", "dark", "light"]
        case .plan: ["licence", "license", "pro", "upgrade", "purchase", "restore"]
        }
    }
}

/// What a palette action row does; the window carries it out through its own gated paths.
enum PaletteAction: Hashable, Sendable {
    case generatePassword, newItem, scanQR, lockNow, changeMasterPassword, securityCentre, reminders, trash, activity, devices, sync
    case importFile, export, recoveryCentre
    /// UX plan workstream 5 (Windows `security-check`, `sync-status`, `show-setup`).
    case securityCheck, syncStatus, showSetup
    /// Receive a shared item (`.lgkshare` file or pasted QR text).
    case receiveShare
    case settings(SettingsSection?)
    case shortcuts
}

/// A palette command (Windows `shell/commands.py` `Command`).
struct PaletteCommand: Sendable {
    let id: String
    let title: String
    let subtitle: String
    let group: PaletteModel.Group
    let action: PaletteAction
    let keywords: [String]
    var requiresUnlock = true
}

/// One row of the palette: a command or a saved item.
struct PaletteRow: Identifiable, Equatable, Sendable {
    enum Target: Hashable, Sendable { case action(PaletteAction), item(String) }
    let target: Target
    let title: String
    let subtitle: String
    let group: PaletteModel.Group
    var id: String {
        switch target {
        case .item(let id): "item:\(id)"
        case .action(let a): "action:\(a)"
        }
    }
}

/// The command palette's query and results (Windows `Palette.svelte`, `palette_results`, `tools.py` prefixes).
@MainActor @Observable
final class PaletteModel {
    enum Group: String, CaseIterable, Sendable { case actions = "Actions", items = "Items", settings = "Settings", help = "Help"

        var title: String {
            switch self {
            case .actions: String(localized: "Actions")
            case .items: String(localized: "Items")
            case .settings: String(localized: "Settings")
            case .help: String(localized: "Help")
            }
        }
    }

    static let placeholder = String(localized: "Search items and actions — > actions, # tags, @ collections")
    static let limit = 12
    static let minItemRows = 4

    nonisolated static let commands: [PaletteCommand] = [
        PaletteCommand(id: "generate-password", title: String(localized: "Generate password"), subtitle: String(localized: "Create a strong password"), group: .actions,
                       action: .generatePassword, keywords: ["passphrase", "random"]),
        PaletteCommand(id: "new-item", title: String(localized: "New item"), subtitle: String(localized: "Add a login, card, note or other item"), group: .actions,
                       action: .newItem, keywords: ["add", "create", "login", "card", "note"]),
        PaletteCommand(id: "scan-qr", title: String(localized: "Scan QR code"), subtitle: String(localized: "Add a 2FA code or an authenticator export from an image"),
                       group: .actions, action: .scanQR,
                       keywords: ["2fa", "totp", "otp", "two-factor", "authenticator", "google", "qr", "image", "screenshot"]),
        PaletteCommand(id: "lock-now", title: String(localized: "Lock now"), subtitle: String(localized: "Lock the vault"), group: .actions,
                       action: .lockNow, keywords: ["secure"]),
        PaletteCommand(id: "change-master", title: String(localized: "Change master password"), subtitle: String(localized: "Choose a new master password"),
                       group: .actions, action: .changeMasterPassword, keywords: ["passphrase", "credentials"]),
        PaletteCommand(id: "security-centre", title: String(localized: "Security centre"), subtitle: String(localized: "Weak, reused and 2FA-missing items"),
                       group: .actions, action: .securityCentre,
                       keywords: ["2fa", "health", "weak", "reused", "breach", "audit", "center"]),
        PaletteCommand(id: "security-check", title: String(localized: "Security check"), subtitle: String(localized: "Weak, reused, old and breached passwords"),
                       group: .actions, action: .securityCheck, keywords: ["security", "check", "weak", "reused", "breach", "health"]),
        PaletteCommand(id: "reminders", title: String(localized: "Reminders"), subtitle: String(localized: "Expiring and overdue items"), group: .actions,
                       action: .reminders, keywords: ["expiry", "due", "rotate"]),
        PaletteCommand(id: "trash", title: String(localized: "Trash"), subtitle: String(localized: "Recently deleted items"), group: .actions,
                       action: .trash, keywords: ["deleted", "restore"]),
        PaletteCommand(id: "activity", title: String(localized: "Activity"), subtitle: String(localized: "Recent vault activity"), group: .actions,
                       action: .activity, keywords: ["log", "history", "audit"]),
        PaletteCommand(id: "devices", title: String(localized: "Devices & connections"), subtitle: String(localized: "Safari extension and AutoFill status"),
                       group: .actions, action: .devices, keywords: ["safari", "autofill", "extension", "browser"]),
        PaletteCommand(id: "sync", title: String(localized: "Sync"), subtitle: String(localized: "Wi-Fi sync, pairing and sync groups"), group: .actions,
                       action: .sync, keywords: ["wifi", "wi-fi", "pair", "qr", "devices", "cloud", "folder"]),
        PaletteCommand(id: "sync-status", title: String(localized: "Sync status"), subtitle: String(localized: "When each of your devices last synced"),
                       group: .actions, action: .syncStatus, keywords: ["sync", "devices", "last", "status"]),
        PaletteCommand(id: "receive-share", title: String(localized: "Receive a shared item…"), subtitle: String(localized: "Open a .lgkshare file or paste its QR text"),
                       group: .actions, action: .receiveShare, keywords: ["share", "shared", "airdrop", "lgkshare", "receive"]),
        PaletteCommand(id: "import", title: String(localized: "Import…"), subtitle: String(localized: "Import from another password manager or a phone backup"),
                       group: .actions, action: .importFile,
                       keywords: ["csv", "bitwarden", "1password", "lastpass", "keepass", "chrome", "restore", "backup", "lgkm"]),
        PaletteCommand(id: "export", title: String(localized: "Export…"), subtitle: String(localized: "Encrypted backup or CSV file"), group: .actions,
                       action: .export, keywords: ["backup", "csv", "lgkm", "save"]),
        PaletteCommand(id: "recovery-centre", title: String(localized: "Recovery centre"), subtitle: String(localized: "Full backups, restore and the recovery phrase"),
                       group: .actions, action: .recoveryCentre,
                       keywords: ["backup", "restore", "recovery", "phrase", "kit", "verify", "center", "safety"]),
        PaletteCommand(id: "settings", title: String(localized: "Settings"), subtitle: String(localized: "Open settings"), group: .settings,
                       action: .settings(nil), keywords: ["preferences", "options"]),
    ] + SettingsSection.allCases.map { s in
        PaletteCommand(id: "settings-\(s.rawValue.lowercased())", title: s.title, subtitle: s.subtitle, group: .settings,
                       action: .settings(s), keywords: ["settings"] + s.keywords)
    } + [
        // Unlike Windows it needs the unlocked window: every setup step opens a page of the vault.
        PaletteCommand(id: "show-setup", title: String(localized: "Show setup"), subtitle: String(localized: "Touch ID, import, recovery phrase and Safari extension"),
                       group: .help, action: .showSetup, keywords: ["onboarding", "setup", "guide", "tour", "help"]),
        PaletteCommand(id: "shortcuts", title: String(localized: "Keyboard shortcuts"), subtitle: String(localized: "See every shortcut"), group: .help,
                       action: .shortcuts, keywords: ["keys", "hotkeys", "help"], requiresUnlock: false),
    ]

    var query = "" { didSet { highlighted = 0 } }
    /// The highlighted row (↑/↓, Return runs it).
    var highlighted = 0
    @ObservationIgnored private let items: () -> [VaultItem]
    @ObservationIgnored private let collections: () -> [LocalData.Collection]
    @ObservationIgnored private let memberships: () -> [String: [String]]
    @ObservationIgnored private let isUnlocked: () -> Bool

    init(items: @escaping () -> [VaultItem], collections: @escaping () -> [LocalData.Collection] = { [] },
         memberships: @escaping () -> [String: [String]] = { [:] }, isUnlocked: @escaping () -> Bool) {
        self.items = items; self.collections = collections; self.memberships = memberships; self.isUnlocked = isUnlocked
    }

    var rows: [PaletteRow] {
        Self.results(query, items: items(), collections: collections(), memberships: memberships(), unlocked: isUnlocked())
    }

    func move(_ step: Int) {
        let n = rows.count
        guard n > 0 else { highlighted = 0; return }
        highlighted = min(max(highlighted + step, 0), n - 1)
    }

    var highlightedRow: PaletteRow? { let r = rows; return r.indices.contains(highlighted) ? r[highlighted] : nil }

    /// Whether a row may still run now (rechecked at the moment it runs: the vault may have locked meanwhile).
    func allows(_ row: PaletteRow) -> Bool {
        if isUnlocked() { return true }
        if case .action(let a) = row.target { return Self.commands.contains { $0.action == a && !$0.requiresUnlock } }
        return false
    }

    // MARK: results

    static func results(_ query: String, items: [VaultItem], collections: [LocalData.Collection] = [],
                        memberships: [String: [String]] = [:], unlocked: Bool, limit: Int = limit) -> [PaletteRow] {
        var text = query.trimmingCharacters(in: .whitespaces)
        var scope: Group?
        if text.hasPrefix(">") {
            scope = .actions; text = String(text.dropFirst()).trimmingCharacters(in: .whitespaces)
        } else if text.hasPrefix("#") {
            scope = .items; text = "tag:" + String(text.dropFirst()).trimmingCharacters(in: .whitespaces)
        } else if text.hasPrefix("@") {
            guard unlocked else { return [] }
            let needle = Casefold.fold(String(text.dropFirst()).trimmingCharacters(in: .whitespaces))
            let ids = Set(collections.filter { needle.isEmpty || Casefold.fold($0.name).contains(needle) }.map(\.id))
            let matched = items.filter { CollectionsModel.canBeMember($0) && !(Set(memberships[$0.id] ?? []).isDisjoint(with: ids)) }
                .sorted { (Casefold.fold($0.title), $0.id) < (Casefold.fold($1.title), $1.id) }
            return matched.prefix(min(limit, 12)).map(itemRow)
        }
        let commands = Self.commands.filter { (unlocked || !$0.requiresUnlock) && (scope == nil || $0.group == scope) }
        guard !text.isEmpty || scope == .items else {
            return Array(commands.map(commandRow).prefix(max(0, limit)))
        }

        let tokens = VaultSearch.parse(text)
        var ranked: [(Int, Int, PaletteCommand)] = []
        for (i, c) in commands.enumerated() {
            let f = ["title": VaultSearch.casefold(c.title), "keywords": VaultSearch.casefold(c.keywords.joined(separator: " "))]
            var r = VaultSearch.rankExact, hit = true
            for (field, token) in tokens {
                guard field == nil, let t = VaultSearch.tokenRank(f, nil, token) else { hit = false; break }
                r = max(r, t)
            }
            if hit { ranked.append((r, i, c)) }
        }
        ranked.sort { ($0.0, $0.1) < ($1.0, $1.1) }

        var byGroup: [Group: [PaletteRow]] = [:]
        for (_, _, c) in ranked { byGroup[c.group, default: []].append(commandRow(c)) }
        let itemRows = unlocked && (scope == nil || scope == .items)
            ? VaultSearch.rank(items, query: text).map(itemRow) : []

        let limit = max(0, limit)
        // Broad queries keep room for up to `minItemRows` items; items take whatever commands leave unused.
        let budget = limit - min(itemRows.count, minItemRows, limit)
        var taken = 0
        for g in Group.allCases where g != .items {
            let rows = Array((byGroup[g] ?? []).prefix(max(0, budget - taken)))
            byGroup[g] = rows; taken += rows.count
        }
        byGroup[.items] = Array(itemRows.prefix(limit - taken))
        return Group.allCases.flatMap { byGroup[$0] ?? [] }
    }

    nonisolated static func commandRow(_ c: PaletteCommand) -> PaletteRow {
        PaletteRow(target: .action(c.action), title: c.title, subtitle: c.subtitle, group: c.group)
    }

    nonisolated static func itemRow(_ item: VaultItem) -> PaletteRow {
        PaletteRow(target: .item(item.id), title: item.title.isEmpty ? String(localized: "Untitled") : item.title,
                   subtitle: item.username.isEmpty ? item.kindLabel : item.username, group: .items)
    }
}
