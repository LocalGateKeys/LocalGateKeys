import Foundation
import Observation
import os
import LGKCore
import AppSharedMac

/// Tags and collections on the Mac (Windows `collections.py`, `item_schema.py`; sub-plan 07 task 5i).
///
/// Tags live on the synced record (`tags`, every kind). Collections live in the item store as their own states
/// (`col:` catalog rows and `cm:` memberships, `CollectionCatalog`), so they sync with this person's other devices and
/// can be shared: this wraps the iPhone's `CollectionsModel` (list, counts, create, rename, delete, starters,
/// memberships, shared and view-only collections) and adds the Mac's activity events and tag rules. Logins and
/// documents are never added to a collection; an item is in at most 20. Deleting a collection keeps its items; a shared
/// or view-only one is never deleted, and a view-only one is never renamed.
///
/// Before sub-plan 07 the Mac kept collections in its local data (`LocalData.collections`/`memberships`): they move
/// into the store once, at unlock (`unlock`), and again from `reload` if that move could not be committed. Starter
/// collections are only ever added on request (`addStarters`).
@MainActor @Observable
final class MacCollectionsModel {
    nonisolated static let tooManyText = String(localized: "An item cannot belong to more than 20 collections.")

    /// The shared model the Collections sheet reads (rows, counts, badges, starters, the last refusal).
    let shared: CollectionsModel

    @ObservationIgnored private let store: any ItemStore
    @ObservationIgnored private let local: (any LocalDataHosting)?
    @ObservationIgnored private let activity: ActivityRecorder?

    init(store: any ItemStore, local: (any LocalDataHosting)?, activity: ActivityRecorder?,
         clock: any UnixClock = SystemClock(), background: (any BackgroundTasking)? = nil,
         newID: @escaping () -> String = { UUID().uuidString.lowercased() }) {
        self.store = store; self.local = local; self.activity = activity
        shared = CollectionsModel(store: store, localData: { local?.localData },
                                  saveLocal: { data in try local?.commitLocalData(data) },
                                  clock: clock, background: background, newID: newID)
    }

    // MARK: - Rules (pure)

    /// Whether `item` can be put in a collection: typed items only, never logins or documents.
    nonisolated static func canBeMember(_ item: VaultItem) -> Bool { CollectionsModel.offersPicker(kind: item.kind) }

    /// Tags from the editor's text: comma-separated, normalised like `Normalise.normalizeTags`.
    nonisolated static func tags(fromText text: String) throws -> [String] {
        try Normalise.tags(text.split(separator: ",", omittingEmptySubsequences: true).map(String.init))
    }

    nonisolated static func tagText(_ tags: [String]) -> String { tags.joined(separator: ", ") }

    // MARK: - Reading

    /// Collections, by name (case-insensitive), as the last `reload` read them.
    var collections: [CollectionCatalog.Collection] { shared.collections }
    var rows: [CollectionsModel.Row] { shared.rows }
    /// Live item id -> its collection ids.
    var memberships: [String: [String]] { shared.memberships }
    var missingStarters: Bool { shared.missingStarters }
    /// The last refusal or failure.
    var message: String? {
        get { shared.message }
        set { shared.message = newValue }
    }

    /// Reads the store again. Collections an older Mac kept in its local data that are still there (their move into the
    /// store could not be committed at unlock) are moved first, so the sidebar, the picker and the view-only checks,
    /// which all read the store, never miss them.
    func reload() {
        retryMigration()
        shared.reload()
    }

    /// Ids of the known collections `itemID` is in (ids of collections this Mac does not know are not shown).
    func shownMemberships(of itemID: String) -> Set<String> {
        let known = Set(collections.map(\.id))
        return Set((memberships[itemID] ?? []).filter(known.contains))
    }

    /// Live items in the collection.
    func count(of collectionID: String) -> Int { rows.first { $0.id == collectionID }?.count ?? 0 }

    func name(of collectionID: String) -> String? { collections.first { $0.id == collectionID }?.name }

    /// Names of the known collections `itemID` is in, by name.
    func names(of itemID: String) -> [String] {
        let ids = Set(memberships[itemID] ?? [])
        return collections.filter { ids.contains($0.id) }.map(\.name)
    }

    /// The item is in a view-only collection: it is neither edited, moved, starred nor deleted here.
    func isReadOnly(itemID: String) -> Bool { shared.isReadOnly(itemID: itemID) }

    // MARK: - Changes (each records a content-free activity event when it worked)

    /// The new collection's id, or nil (and `message`).
    @discardableResult
    func create(name: String) -> String? {
        guard let id = shared.create(name: name) else { return nil }
        activity?.record(.collectionCreate, count: 1)
        return id
    }

    /// False (and `message`) when refused; a view-only collection is never renamed.
    @discardableResult
    func rename(_ id: String, to name: String) -> Bool {
        let before = self.name(of: id)
        guard shared.rename(id, to: name) else { return false }
        if self.name(of: id) != before { activity?.record(.collectionUpdate, count: 1) }
        return true
    }

    /// Deletes the collection; its items stay. A shared or view-only one is refused (`message`).
    @discardableResult
    func delete(_ id: String) -> Bool {
        let members = count(of: id)
        guard shared.delete(id) else { return false }
        activity?.record(.collectionDelete, result: .deleted, count: members)
        return true
    }

    @discardableResult
    func addStarters() -> Bool { shared.addStarters() }

    /// Sets which known collections the item `itemID` (of `kind`) is in; ids of collections this Mac does not know (from
    /// another device) are kept. False (and `message`) when refused.
    @discardableResult
    func setMemberships(of itemID: String, kind: String, to ids: Set<String>) -> Bool {
        let known = Set(collections.map(\.id))
        let unknown = (memberships[itemID] ?? []).filter { !known.contains($0) }
        return shared.setMemberships(itemID: itemID, kind: kind, to: ids.union(unknown))
    }

    // MARK: - Unlock

    /// At unlock (`MacLockModel`), before anything else reads the local data: the collections an older Mac kept there
    /// move into the store once (`CollectionsModel.migrate`, which writes the store's "done" marker); `data` is the
    /// lock model's in-memory copy and is the cleared one from then on, also when `saveLocal` fails. No starter
    /// collections are added here: they come only from "Add starter collections" (`addStarters`), deduplicated by name
    /// against the catalog as sync has brought it by then, as on every other platform.
    static func unlock(store: any ItemStore, local data: inout LocalData, saveLocal: (LocalData) throws -> Void) {
        CollectionsModel.migrate(store: store, local: &data, saveLocal: saveLocal)
    }

    /// The local data still holds old collections (the move at unlock could not be committed, or a later write saved an
    /// older copy): move them now. The store's "done" marker makes a repeat harmless.
    private func retryMigration() {
        guard let local, var data = local.localData, !data.collections.isEmpty || !data.memberships.isEmpty else { return }
        CollectionsModel.migrate(store: store, local: &data, saveLocal: { try local.commitLocalData($0) })
    }
}
