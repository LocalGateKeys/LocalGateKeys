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
    /// The Vault list's Collections filter (sub-plan 07; per device, never synced): a collection id, or nil for
    /// All items (the default). A collection that no longer exists falls back to All items at the next reload.
    var collectionFilter: String? {
        didSet {
            defaults.set(collectionFilter, forKey: Self.collectionKey)
            updateCollectionItems()
        }
    }
    /// The collections, by name (for the filter menu).
    private(set) var collections: [CollectionCatalog.Collection] = []
    /// The live items in the chosen collection; nil with no filter.
    private(set) var collectionItemIDs: Set<String>?

    /// Kept beside the other app settings (the app group's defaults); a per-device choice, not synced.
    static let sortKey = "settings.vaultSort"
    static let favoritesFirstKey = "settings.vaultFavoritesFirst"
    static let collectionKey = "settings.vaultCollection"

    @ObservationIgnored private let store: any ItemStore
    @ObservationIgnored private let defaults: UserDefaults
    /// Items this device hides from the list and search (iPhone travel mode, feature pack §2). Empty by default.
    @ObservationIgnored var hidden: @MainActor (StoreSnapshot) -> Set<String> = { _ in [] }
    /// Collections travel mode hides on this device (feature pack §2): left out of the Collections filter.
    @ObservationIgnored var hiddenCollections: @MainActor () -> Set<String> = {
        let travel = TravelModeBox.shared.current
        return travel.on ? Set(travel.collections.map { $0.lowercased() }) : []
    }
    /// How many live items `hidden` took out at the last reload.
    private(set) var hiddenCount = 0
    init(store: any ItemStore, defaults: UserDefaults = AppSettings.shared.defaults) {
        self.store = store; self.defaults = defaults
        sort = defaults.string(forKey: Self.sortKey).flatMap(VaultSortOption.init)
        favoritesFirst = (defaults.object(forKey: Self.favoritesFirstKey) as? Bool) ?? false
        collectionFilter = defaults.string(forKey: Self.collectionKey)
    }

    /// The Vault list's items: all of them, or those in the chosen collection.
    var listItems: [VaultItem] {
        guard collectionFilter != nil, let ids = collectionItemIDs else { return items }
        return items.filter { ids.contains($0.id) }
    }

    /// The chosen collection's name, nil with no filter.
    var collectionFilterName: String? {
        guard let id = collectionFilter else { return nil }
        return collections.first { $0.id == id }.map { CollectionCatalog.displayName($0.name) }
    }

    private func updateCollectionItems() {
        guard let id = collectionFilter else { collectionItemIDs = nil; return }
        collectionItemIDs = Set(CollectionCatalog.items(in: id, snapshot: snapshot))
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
        return VaultSort.sorted(listItems.filter(filter.matches), by: sort, favoritesFirst: favoritesFirst)
    }

    func reload() {
        do {
            snapshot = try store.load()
            let hide = hidden(snapshot)
            let all = VaultItem.items(from: snapshot)
            items = hide.isEmpty ? all : all.filter { !hide.contains($0.id) }
            hiddenCount = all.count - items.count
            liveCount = ItemLimit.liveCount(snapshot); loadError = nil
            if !filterOptions.contains(filter) { filter = .all }
            let hideCollections = hiddenCollections()
            collections = CollectionCatalog.collections(in: snapshot).filter { !hideCollections.contains($0.id.lowercased()) }
            if let id = collectionFilter, !collections.contains(where: { $0.id == id }) {
                collectionFilter = nil
            } else {
                updateCollectionItems()
            }
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
                  case .string(let nsName)? = w["ns"], let ns = Namespace(rawValue: nsName), ns != .license, ns != .heir,
                  case .object(var r)? = w["record"] else { return .unchanged }
            // A view-only shared item is not changed here, not even its star (sub-plan 07).
            if EditorModel.itemIsReadOnly(id, in: snap) { return .invalid }
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
