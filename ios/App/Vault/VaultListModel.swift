import Foundation
import Observation
import AppShared

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

    @ObservationIgnored private let store: any ItemStore
    init(store: any ItemStore) { self.store = store }

    var visibleItems: [VaultItem] { VaultSearch.apply(items, query: query, filter: filter) }
    var filterOptions: [VaultFilter] { VaultSearch.filterOptions(items) }

    func reload() {
        do {
            snapshot = try store.load()
            items = VaultItem.items(from: snapshot); liveCount = ItemLimit.liveCount(snapshot); loadError = nil
            if !filterOptions.contains(filter) { filter = .all }
        } catch {
            loadError = "The vault could not be read on this device."
        }
    }
}
