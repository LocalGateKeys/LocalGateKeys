import Foundation
import Observation
import LGKCore

/// A record kind as stored (`web`, `desktop`, `api_key`, …).
typealias ItemKind = String

/// The sidebar's tools, in the Windows order.
enum Tool: CaseIterable, Hashable {
    case securityCentre, generator, reminders, sync, devices, licence, importExport, recoveryCentre, activity, trash, settings

    var title: String {
        switch self {
        case .securityCentre: String(localized: "Security centre")
        case .generator: String(localized: "Generator")
        case .reminders: String(localized: "Reminders")
        case .sync: String(localized: "Sync")
        case .devices: String(localized: "Devices & connections")
        case .licence: String(localized: "Licence")
        case .importExport: String(localized: "Import & export")
        case .recoveryCentre: String(localized: "Recovery centre")
        case .activity: String(localized: "Activity")
        case .trash: String(localized: "Trash")
        case .settings: String(localized: "Settings")
        }
    }
}

enum SidebarSelection: Hashable {
    case all, favourites, recent, kind(ItemKind), collection(String), tool(Tool)

    var isTool: Bool { if case .tool = self { true } else { false } }
}

/// What the sidebar lists and counts, from the vault's live items.
@MainActor @Observable
final class SidebarModel {
    var selection: SidebarSelection = .all
    var items: [VaultItem]
    /// Mac-local collections and memberships (item id → collection ids), kept current by the window.
    var collections: [LocalData.Collection] = []
    var memberships: [String: [String]] = [:]

    /// How many items "Recently used" lists (most recently updated first).
    nonisolated static let recentLimit = 30
    /// Windows `KIND_ORDER` for the first kinds; the rest follow alphabetically by label.
    static let leadingKinds: [ItemKind] = ["web", "desktop", "api_key", "document", "passkey"]

    init(items: [VaultItem] = []) { self.items = items }

    /// The row's number, or nil for rows that show none (Recently used, tools).
    func count(for selection: SidebarSelection) -> Int? {
        switch selection {
        case .all: items.count
        case .favourites: items.count(where: \.favorite)
        case .recent, .tool: nil
        case .kind(let k): items.count(where: { $0.kind == k })
        case .collection: Self.filter(items, by: selection, memberships: memberships).count
        }
    }

    /// Kinds with at least one item, in the Windows order.
    var kindsPresent: [ItemKind] {
        let present = Set(items.map(\.kind))
        let rest = present.subtracting(Self.leadingKinds).sorted {
            (Self.label(forKind: $0).lowercased(), $0) < (Self.label(forKind: $1).lowercased(), $1)
        }
        return Self.leadingKinds.filter(present.contains) + rest
    }

    /// The items the selected row shows, or all of them for a tool.
    func filtered(_ items: [VaultItem]) -> [VaultItem] { Self.filter(items, by: selection, memberships: memberships) }

    /// Collections, by name (case-insensitive), for the sidebar group.
    var sortedCollections: [LocalData.Collection] {
        collections.sorted { (Casefold.fold($0.name), $0.id) < (Casefold.fold($1.name), $1.id) }
    }

    nonisolated static func filter(_ items: [VaultItem], by selection: SidebarSelection,
                                   memberships: [String: [String]] = [:]) -> [VaultItem] {
        switch selection {
        case .collection(let c):
            items.filter { !CollectionsModel.loginKinds.contains($0.kind) && (memberships[$0.id] ?? []).contains(c) }
        case .all, .tool: items
        case .favourites: items.filter(\.favorite)
        case .kind(let k): items.filter { $0.kind == k }
        case .recent: Array(items.sorted { ($0.updatedAt, $1.id) > ($1.updatedAt, $0.id) }.prefix(recentLimit))
        }
    }

    var title: String {
        switch selection {
        case .all: String(localized: "All items")
        case .favourites: String(localized: "Favourites")
        case .recent: String(localized: "Recently used")
        case .kind(let k): Self.label(forKind: k)
        case .collection(let c): collections.first { $0.id == c }?.name ?? String(localized: "Collection")
        case .tool(let t): t.title
        }
    }

    static func label(forKind kind: ItemKind) -> String {
        switch kind {
        case "web": String(localized: "Logins")
        case "desktop": String(localized: "Desktop apps")
        case "api_key": String(localized: "API keys")
        case "ssh_key": String(localized: "SSH keys")
        case "identity": String(localized: "Identities")
        case "license": String(localized: "Software licences")
        case "note": String(localized: "Notes")
        case "card": String(localized: "Payment cards")
        case "bank_account": String(localized: "Bank accounts")
        case "purchase": String(localized: "Purchases")
        case "subscription": String(localized: "Subscriptions")
        case "warranty": String(localized: "Warrantys")
        case "wifi": String(localized: "Wi-Fi networks")
        case "bookmark": String(localized: "Bookmarks")
        case "document": String(localized: "Documents")
        case "passkey": String(localized: "Passkeys")
        default: VaultItem.kindLabel(kind) + "s"
        }
    }
}
