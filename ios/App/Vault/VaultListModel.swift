import Foundation
import Observation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

@MainActor
@Observable
final class VaultListModel {
    var query = ""
    var filter: VaultFilter = .all
    private(set) var items: [VaultItem] = []
    private(set) var loadError: String?
    /// Live synced items, for the free plan's limit.
    private(set) var liveCount = 0
    private(set) var snapshot = StoreSnapshot()
    /// The Vault list's chosen order (per device, never synced). nil: the default grouped list.
    var sort: VaultSortOption? {
        didSet { defaults.set(sort?.rawValue, forKey: Self.sortKey) }
    }
    /// Favorites before the rest in a sorted list.
    var favoritesFirst: Bool {
        didSet { defaults.set(favoritesFirst, forKey: Self.favoritesFirstKey) }
    }

    /// Kept beside the other app settings (the app group's defaults); a per-device choice, not synced.
    static let sortKey = "settings.vaultSort"
    static let favoritesFirstKey = "settings.vaultFavoritesFirst"

    @ObservationIgnored private let store: any ItemStore
    @ObservationIgnored private let defaults: UserDefaults
    init(store: any ItemStore, defaults: UserDefaults = AppSettings.shared.defaults) {
        self.store = store; self.defaults = defaults
        sort = defaults.string(forKey: Self.sortKey).flatMap(VaultSortOption.init)
        favoritesFirst = (defaults.object(forKey: Self.favoritesFirstKey) as? Bool) ?? false
    }

    /// The last few searches, newest first. Memory only: dropped on lock (the model goes) and never written.
    private(set) var recentSearches: [String] = []
    nonisolated static let recentSearchLimit = 5
    nonisolated static let recentItemLimit = 5

    /// Remembers the current query (trimmed, case-insensitive duplicates dropped) as a recent search.
    func noteSearch() {
        recentSearches = Self.remember(query, in: recentSearches)
    }

    nonisolated static func remember(_ query: String, in list: [String]) -> [String] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else { return list }
        let rest = list.filter { $0.compare(q, options: .caseInsensitive) != .orderedSame }
        return Array(([q] + rest).prefix(recentSearchLimit))
    }

    /// The most recently changed items (shown while the search field is empty).
    var recentItems: [VaultItem] {
        Array(items.sorted { ($0.updatedAt, $0.id) > ($1.updatedAt, $1.id) }.prefix(Self.recentItemLimit))
    }

    var visibleItems: [VaultItem] { VaultSearch.apply(items, query: query, filter: filter) }
    var filterOptions: [VaultFilter] { VaultSearch.filterOptions(items) }

    /// The plain list (no search query) in the chosen order, or nil for the default grouped view.
    func sortedItems(filter: VaultFilter) -> [VaultItem]? {
        guard let sort else { return nil }
        return VaultSort.sorted(items.filter(filter.matches), by: sort, favoritesFirst: favoritesFirst)
    }

    func reload() {
        do {
            snapshot = try store.load()
            items = VaultItem.items(from: snapshot); liveCount = ItemLimit.liveCount(snapshot); loadError = nil
            if !filterOptions.contains(filter) { filter = .all }
        } catch {
            loadError = String(localized: "The vault could not be read on this device.")
        }
    }

    /// Marks or unmarks a favorite: sets the record's `favorite`, bumps `updated_at` and commits through
    /// `Normalise.normalForm` and the store like the editor's save, so the change syncs. Never limited by the
    /// free plan (it edits an existing item). `.unchanged` when the record already says so or is gone.
    static func setFavorite(_ favorite: Bool, id: String, store: any ItemStore, clock: any UnixClock,
                            background: (any BackgroundTasking)? = nil) -> SaveResult {
        do {
            var snap = try store.load()
            guard snap.meta[id]?.deleted != true, case .object(let w)? = snap.records[id],
                  case .string(let nsName)? = w["ns"], let ns = Namespace(rawValue: nsName), ns != .license,
                  case .object(var r)? = w["record"] else { return .unchanged }
            if r["favorite"] == .bool(favorite) { return .unchanged }
            r["favorite"] = .bool(favorite)
            r["updated_at"] = .int(clock.now)
            if case .int(let created)? = r["created_at"], created > clock.now { r["created_at"] = .int(clock.now) }
            let record = try Normalise.normalForm(ns: ns, record: .object(r))
            guard case .object(let o) = record, o["id"] == .string(id) else { return .failed }
            snap.records[id] = Wrapper.make(ns: ns, record: record)
            let change = StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync)
            let tasks = background ?? PlatformBackgroundTasks.make()
            try tasks.run("LocalGateKeys save") { try store.commit(change) }
            return .saved
        } catch {
            return .failed
        }
    }
}
