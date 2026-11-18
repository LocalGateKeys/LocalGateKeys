import Foundation
import Observation
import os
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// The iPhone's collections (sub-plan 07 task 5f), over `CollectionCatalog` and the item store: the list with
/// counts, create, rename, delete (the items stay), the starters and an item's memberships. Collections are free:
/// nothing here checks Pro, and collection states never count toward the free item limit (`ItemLimit` reads
/// `itemRecords`). No UIKit, so the Mac can share it (task 5i): the never-synced local data (Recently deleted rows
/// and the starter ids) comes in through two closures.
@MainActor @Observable
final class CollectionsModel {
    struct Row: Identifiable, Equatable {
        let id: String
        let name: String
        /// Live items in it.
        let count: Int
        /// Shared from one of this person's devices: it cannot be deleted (stop sharing or leave first).
        let isShared: Bool
        /// View only here: it cannot be renamed and its items do not change.
        let isReadOnly: Bool
    }

    nonisolated static let readFailedText = String(localized: "The vault could not be read on this device.")
    nonisolated static let log = Logger(subsystem: "app.localgatekeys", category: "collections")

    private(set) var rows: [Row] = []
    /// The catalog as the last `reload` read it (by name).
    private(set) var collections: [CollectionCatalog.Collection] = []
    /// Live item id -> the collection ids it is in (ids this vault does not know included), as the last `reload` read
    /// them: the Mac's sidebar filter, palette and detail chips.
    private(set) var memberships: [String: [String]] = [:]
    /// Collections that are view only here (`EditorModel.readOnlyCollectionIDs`; a damaged share store fails closed).
    private(set) var readOnlyIDs: Set<String> = []
    /// Some of Personal, Work, Travel and Emergency are missing (by name).
    private(set) var missingStarters = false
    /// The last refusal or failure, shown under the list.
    var message: String?

    @ObservationIgnored private let store: any ItemStore
    @ObservationIgnored private let localData: @MainActor () -> LocalData?
    @ObservationIgnored private let saveLocal: @MainActor (LocalData) throws -> Void
    @ObservationIgnored private let clock: any UnixClock
    @ObservationIgnored private let background: any BackgroundTasking
    @ObservationIgnored private let newID: () -> String
    /// Travel mode on this device (feature pack §2): hidden collections are left out of the list and hidden items out
    /// of the counts. Tests replace it.
    @ObservationIgnored var travel: @MainActor () -> TravelMode = { TravelModeBox.shared.current }

    init(store: any ItemStore, localData: @escaping @MainActor () -> LocalData? = { nil },
         saveLocal: @escaping @MainActor (LocalData) throws -> Void = { _ in }, clock: any UnixClock = SystemClock(),
         background: (any BackgroundTasking)? = nil, newID: @escaping () -> String = { UUID().uuidString.lowercased() }) {
        self.store = store; self.localData = localData; self.saveLocal = saveLocal; self.clock = clock
        self.background = background ?? PlatformBackgroundTasks.make()
        self.newID = newID
    }

    // MARK: - Rules

    /// Whether an item of `kind` gets the collection picker: typed items only, never logins or documents.
    nonisolated static func offersPicker(kind: String) -> Bool { !CollectionCatalog.nonMemberKinds.contains(kind) }

    /// Live items per collection id, in one pass over the store.
    nonisolated static func counts(in snapshot: StoreSnapshot, excluding hidden: Set<String> = []) -> [String: Int] {
        var out: [String: Int] = [:]
        for id in snapshot.itemRecords.keys where snapshot.meta[id]?.deleted != true && !hidden.contains(id) {
            for c in CollectionCatalog.memberships(of: id, in: snapshot) { out[c, default: 0] += 1 }
        }
        return out
    }

    /// Live item id -> its collection ids (items with none are left out).
    nonisolated static func memberships(in snapshot: StoreSnapshot) -> [String: [String]] {
        var out: [String: [String]] = [:]
        for id in snapshot.itemRecords.keys where snapshot.meta[id]?.deleted != true {
            let ids = CollectionCatalog.memberships(of: id, in: snapshot)
            if !ids.isEmpty { out[id] = ids }
        }
        return out
    }

    /// Whether the item `itemID` is in a view-only collection, from the last `reload` (the stores' own checks are
    /// `EditorModel.itemIsReadOnly`).
    func isReadOnly(itemID: String) -> Bool {
        guard !readOnlyIDs.isEmpty else { return false }
        return (memberships[itemID] ?? []).contains { readOnlyIDs.contains($0) }
    }

    // MARK: - Reading

    func reload() {
        let snapshot: StoreSnapshot
        do { snapshot = try store.load() } catch {
            rows = []; collections = []; memberships = [:]; readOnlyIDs = []; message = Self.readFailedText; return
        }
        let mode = travel()
        let hiddenCollections = mode.on ? Set(mode.collections.map { $0.lowercased() }) : []
        let counts = Self.counts(in: snapshot, excluding: mode.hiddenIDs(in: snapshot))
        let readOnly = EditorModel.readOnlyCollectionIDs(in: snapshot)
        let shared = ShareGroups.protectedCollectionIDs(in: snapshot)
        collections = CollectionCatalog.collections(in: snapshot).filter { !hiddenCollections.contains($0.id.lowercased()) }
        memberships = Self.memberships(in: snapshot)
        readOnlyIDs = readOnly
        rows = collections.map { c in
            Row(id: c.id, name: c.name, count: counts[c.id] ?? 0,
                isShared: shared.contains(c.id) || snapshot.records[CollectionStates.linkPrefix + c.id] != nil,
                isReadOnly: readOnly.contains(c.id))
        }
        missingStarters = !((try? CollectionCatalog.starters(in: snapshot, now: 0).ids.isEmpty) ?? true)
    }

    // MARK: - Changes

    /// Creates a collection; its id, or nil (and `message`) when refused.
    @discardableResult
    func create(name: String) -> String? {
        message = nil
        do {
            let (change, id) = try CollectionCatalog.create(name: name, in: try store.load(), now: clock.now, newID: newID)
            try commit(change)
            reload()
            return id
        } catch {
            message = EditorModel.collectionText(for: error); return nil
        }
    }

    /// Renames a collection; false (and `message`) when refused. A view-only collection is never renamed.
    @discardableResult
    func rename(_ id: String, to name: String) -> Bool {
        message = nil
        do {
            let snapshot = try store.load()
            // View only here, from this device's own share records (the catalog itself checks only other devices'
            // `csl:` links); a damaged share store fails closed.
            if EditorModel.readOnlyCollectionIDs(in: snapshot).contains(id) {
                message = EditorModel.readOnlyCollectionText; return false
            }
            if let change = try CollectionCatalog.rename(id, to: name, in: snapshot, now: clock.now) {
                try commit(change)
            }
            reload()
            return true
        } catch CollectionCatalog.Failure.shared {
            message = EditorModel.readOnlyCollectionText; return false
        } catch {
            message = EditorModel.collectionText(for: error); return false
        }
    }

    /// Deletes a collection: its items stay (they leave it), and Recently deleted rows forget it. A shared or
    /// view-only collection is refused. The store goes first; a failed local save afterwards only leaves a stale id in
    /// a trash row, which restore drops (`CollectionCatalog.restored` keeps known collections only).
    @discardableResult
    func delete(_ id: String) -> Bool {
        message = nil
        do {
            let snapshot = try store.load()
            let data = localData()
            let (change, trash) = try CollectionCatalog.delete(id, in: snapshot, trash: data?.trash ?? [],
                                                               protected: ShareGroups.protectedCollectionIDs(in: snapshot))
            try commit(change)
            if var data {
                let wasStarter = data.starterCollectionIDs.contains(id)
                if let trash { data.trash = trash }
                data.starterCollectionIDs.removeAll { $0 == id }
                if trash != nil || wasStarter { try? saveLocal(data) }
            }
            reload()
            return true
        } catch {
            message = EditorModel.collectionText(for: error); return false
        }
    }

    /// Adds the starters that are missing by name; their ids are kept as starters in the local data.
    @discardableResult
    func addStarters() -> Bool {
        message = nil
        do {
            let (change, ids) = try CollectionCatalog.starters(in: try store.load(), now: clock.now, newID: newID)
            if let change {
                try commit(change)
                if var data = localData() {
                    for id in ids where !data.starterCollectionIDs.contains(id) { data.starterCollectionIDs.append(id) }
                    try? saveLocal(data)
                }
            }
            reload()
            return true
        } catch {
            message = EditorModel.collectionText(for: error); return false
        }
    }

    /// Sets the collections of the item `itemID` (of `kind`); false (and `message`) when refused: a login or a
    /// document, more than 20, or an item in a view-only collection (moved neither in nor out).
    @discardableResult
    func setMemberships(itemID: String, kind: String, to ids: Set<String>) -> Bool {
        message = nil
        do {
            let snapshot = try store.load()
            if let change = try CollectionCatalog.setMemberships(itemID: itemID, kind: kind, to: Array(ids), in: snapshot,
                                                                 readOnly: EditorModel.readOnlyCollectionIDs(in: snapshot)) {
                try commit(change)
            }
            reload()
            return true
        } catch {
            message = EditorModel.collectionText(for: error); return false
        }
    }

    // MARK: - Unlock

    /// Moves collections kept in the local data (the Mac's copy from before sub-plan 07; an iPhone never wrote any)
    /// into the store, once: the store commit carries the "done" marker and the cleared copy is saved, so no later
    /// unlock moves anything again. `local` is the host's in-memory copy and is replaced by the cleared one as soon as
    /// the store holds them (`CollectionMigration.run`): the host keeps using it for every later local write, also
    /// when the save failed. A failure is logged; a store that could not take them leaves `local` as it was, so the
    /// next unlock (or the Mac's next reload) tries again. True when something moved.
    @discardableResult
    static func migrate(store: any ItemStore, local: inout LocalData, saveLocal: (LocalData) throws -> Void) -> Bool {
        do {
            return try CollectionMigration.run(store: store, local: &local, saveLocal: saveLocal) != nil
        } catch {
            log.error("Collections could not be moved into the vault: \(String(describing: error), privacy: .public)")
            return false
        }
    }

    private func commit(_ change: StoreChange) throws {
        try background.run("LocalGateKeys save") { try store.commit(change) }
    }
}

#if os(iOS)
extension CollectionsModel {
    /// The iPhone's model over its never-synced local data (nil while it is not open).
    convenience init(store: any ItemStore, local: (any PhoneLocalHosting)?) {
        self.init(store: store, localData: { local?.localData }, saveLocal: { data in try local?.commitLocalData(data) })
    }
}
#endif
