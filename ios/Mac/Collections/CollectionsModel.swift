import Foundation
import Observation
import LGKCore
import AppSharedMac

/// Tags and collections (Windows `collections.py`, `item_schema.py`).
///
/// Tags live on the synced record (`tags`, every kind). Collections and memberships are Mac-local: Windows keeps
/// `collection_ids` on typed records but never syncs it (`vault_bridge.py`), and the synced store's normal form
/// drops the field, so the Mac keeps memberships in `LocalData.memberships` keyed by item id. Only typed items
/// (never logins) can be members; at most 20 per item. Ids of collections this Mac doesn't know are kept on
/// save but never shown. Deleting a collection removes its id from every item and keeps the items.
@MainActor @Observable
final class CollectionsModel {
    nonisolated static let saveFailedText = String(localized: "The collection could not be saved on this Mac.")
    nonisolated static let duplicateNameText = String(localized: "A collection with this name already exists.")
    nonisolated static let emptyNameText = String(localized: "Enter a name for the collection.")
    nonisolated static let longNameText = String(localized: "Collection names can be at most 100 characters.")
    nonisolated static let tooManyText = String(localized: "An item cannot belong to more than 20 collections.")

    enum Failure: Error, Equatable { case locked, invalidName(String), notFound, notTyped, tooMany, save }

    /// The vault's live items (kept current by the window).
    var items: [VaultItem] = []
    /// The last failure line.
    var message: String?

    @ObservationIgnored private let local: any LocalDataHosting
    @ObservationIgnored private let activity: ActivityRecorder?
    @ObservationIgnored private let clock: () -> Date
    @ObservationIgnored private let newID: () -> String

    init(local: any LocalDataHosting, activity: ActivityRecorder?, clock: @escaping () -> Date = Date.init,
         newID: @escaping () -> String = { UUID().uuidString.lowercased() }) {
        self.local = local; self.activity = activity; self.clock = clock; self.newID = newID
    }

    // MARK: - Rules (pure)

    /// Typed catalog items only (Windows: logins have no `collection_ids`).
    nonisolated static func canBeMember(_ item: VaultItem) -> Bool { !loginKinds.contains(item.kind) }
    nonisolated static let loginKinds: Set<String> = ["web", "desktop"]

    /// Tags from the editor's text: comma-separated, normalised like `Normalise.normalizeTags`.
    nonisolated static func tags(fromText text: String) throws -> [String] {
        try Normalise.tags(text.split(separator: ",", omittingEmptySubsequences: true).map(String.init))
    }

    nonisolated static func tagText(_ tags: [String]) -> String { tags.joined(separator: ", ") }

    /// The stripped name, or why it can't be used (case-insensitive unique, 1–100 characters).
    nonisolated static func checkedName(_ raw: String, among existing: [LocalData.Collection], except id: String? = nil) throws -> String {
        let name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { throw Failure.invalidName(emptyNameText) }
        guard name.unicodeScalars.count <= LocalData.maxCollectionName else { throw Failure.invalidName(longNameText) }
        let folded = Casefold.fold(name)
        guard !existing.contains(where: { $0.id != id && Casefold.fold($0.name) == folded }) else {
            throw Failure.invalidName(duplicateNameText)
        }
        return name
    }

    // MARK: - Queries

    /// Collections, by name (case-insensitive).
    var collections: [LocalData.Collection] {
        (local.localData?.collections ?? []).sorted { (Casefold.fold($0.name), $0.id) < (Casefold.fold($1.name), $1.id) }
    }

    private var memberships: [String: [String]] { local.localData?.memberships ?? [:] }

    /// Ids of the known collections `itemID` belongs to (unknown ids are not shown).
    func shownMemberships(of itemID: String) -> Set<String> {
        let known = Set(collections.map(\.id))
        return Set((memberships[itemID] ?? []).filter(known.contains))
    }

    /// Live typed items in the collection.
    func count(of collectionID: String) -> Int {
        let m = memberships
        return items.count { Self.canBeMember($0) && (m[$0.id] ?? []).contains(collectionID) }
    }

    func name(of collectionID: String) -> String? { collections.first { $0.id == collectionID }?.name }

    // MARK: - Changes

    @discardableResult
    func create(name raw: String) throws -> String {
        guard var data = local.localData else { throw Failure.locked }
        let name = try fail(Self.checkedName(raw, among: data.collections))
        let now = Int64(clock().timeIntervalSince1970)
        let id = newID()
        data.collections.append(LocalData.Collection(id: id, name: name, createdAt: now, updatedAt: now))
        try commit(data)
        activity?.record(.collectionCreate, count: 1)
        return id
    }

    func rename(_ id: String, to raw: String) throws {
        guard var data = local.localData else { throw Failure.locked }
        guard let i = data.collections.firstIndex(where: { $0.id == id }) else { throw Failure.notFound }
        let name = try fail(Self.checkedName(raw, among: data.collections, except: id))
        guard name != data.collections[i].name else { return }
        data.collections[i].name = name
        data.collections[i].updatedAt = max(Int64(clock().timeIntervalSince1970), data.collections[i].createdAt)
        data.collections[i].revision += 1
        try commit(data)
        activity?.record(.collectionUpdate, count: 1)
    }

    /// Deletes the collection and strips its id from every item; the items stay.
    func delete(_ id: String) throws {
        guard var data = local.localData else { throw Failure.locked }
        guard data.collections.contains(where: { $0.id == id }) else { throw Failure.notFound }
        data.collections.removeAll { $0.id == id }
        var stripped = 0
        for (item, ids) in data.memberships where ids.contains(id) {
            data.memberships[item] = ids.filter { $0 != id }
            stripped += 1
        }
        try commit(data)
        activity?.record(.collectionDelete, result: .deleted, count: stripped)
    }

    /// What `setMemberships` would store, or `tooMany` (unknown ids count towards the 20).
    func plannedMemberships(of itemID: String, kind: String, to chosen: Set<String>) throws -> [String] {
        guard !Self.loginKinds.contains(kind) else { throw Failure.notTyped }
        let data = local.localData ?? .empty
        let known = Set(data.collections.map(\.id))
        let current = data.memberships[itemID] ?? []
        let unknown = current.filter { !known.contains($0) }
        // Keep the stored order for ids that stay, then add new ones in name order.
        let keptKnown = current.filter { known.contains($0) && chosen.contains($0) }
        let added = collections.map(\.id).filter { chosen.contains($0) && !keptKnown.contains($0) }
        do { return try LocalData.validatedMemberships(unknown + keptKnown + added) } catch {
            message = Self.tooManyText; throw Failure.tooMany
        }
    }

    /// Sets which known collections a typed item (`kind` is never a login) belongs to; unknown ids are kept.
    func setMemberships(of itemID: String, kind: String, to chosen: Set<String>) throws {
        guard var data = local.localData else { throw Failure.locked }
        let next = try plannedMemberships(of: itemID, kind: kind, to: chosen)
        guard next != (data.memberships[itemID] ?? []) else { return }
        data.memberships[itemID] = next.isEmpty ? nil : next
        try commit(data)
    }

    /// Drops memberships of items that are neither live typed items nor in Recently deleted (a restore brings
    /// its collections back; a purge lets them go). Does nothing while the list is empty, so a vault that failed
    /// to load never loses its memberships.
    func prune() {
        guard var data = local.localData, !items.isEmpty, !data.memberships.isEmpty else { return }
        var live = Set(items.filter(Self.canBeMember).map(\.id))
        for row in data.trash {
            if case .object(let r)? = try? row.record(), case .string(let id)? = r["id"] { live.insert(id.lowercased()) }
        }
        let kept = data.memberships.filter { live.contains($0.key) }
        guard kept.count != data.memberships.count else { return }
        data.memberships = kept
        try? local.commitLocalData(data)
    }

    private func fail<T>(_ body: @autoclosure () throws -> T) throws -> T {
        do { return try body() } catch Failure.invalidName(let text) { message = text; throw Failure.invalidName(text) }
    }

    private func commit(_ data: LocalData) throws {
        do { try local.commitLocalData(data); message = nil } catch { message = Self.saveFailedText; throw Failure.save }
    }
}
