import AppIntents
import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// Sub-plan 06: a pinned 2FA code as Shortcuts sees it. Only the vault item's id and the title the person gave it
/// cross into Shortcuts; never the secret or the digits.
struct CodeEntity: AppEntity, Sendable {
    static var typeDisplayRepresentation: TypeDisplayRepresentation { TypeDisplayRepresentation(name: "2FA code") }
    static var defaultQuery: CodeEntityQuery { CodeEntityQuery() }

    /// The vault item's id (the pin), as stored in the pin list.
    let id: String
    /// The code's title, or nil when the codes cannot be read right now (the device or the vault is locked).
    let title: String?

    var displayRepresentation: DisplayRepresentation {
        if let title { return DisplayRepresentation(title: "\(title)") }
        return DisplayRepresentation(title: "Pinned 2FA code")
    }
}

/// Lists only the pinned codes LocalGateKeys shows (`PinnedCodeStore`, at most `maxShown`): never any other vault
/// item. It reads the store the widgets read and writes nothing.
struct CodeEntityQuery: EntityQuery {
    init() {}

    /// The requested ids that are still pinned, titled when their code can be shown now (so a saved shortcut still
    /// resolves while the codes are unreadable, and "Copy code" can say why there is no code).
    @MainActor
    func entities(for identifiers: [CodeEntity.ID]) async throws -> [CodeEntity] {
        let store = CodeIntentEnvironment.makeStore()
        let pinned = store.pinnedIDs
        let titles = Self.titles(store: store)
        return identifiers.filter { pinned.contains($0) }.map { CodeEntity(id: $0, title: titles[$0]) }
    }

    /// The codes that can be shown now, in pin order (none while the device is locked or after Forget on lock).
    @MainActor
    func suggestedEntities() async throws -> [CodeEntity] {
        let store = CodeIntentEnvironment.makeStore()
        return store.codes(at: CodeIntentEnvironment.now()).map { CodeEntity(id: $0.0.id, title: $0.0.title) }
    }

    @MainActor
    private static func titles(store: PinnedCodeStore) -> [String: String] {
        var out: [String: String] = [:]
        for shown in store.codes(at: CodeIntentEnvironment.now()) where out[shown.0.id] == nil {
            out[shown.0.id] = shown.0.title
        }
        return out
    }
}
