#if os(macOS)
import Foundation

/// One Mac profile (Windows `ProfileRecord`, without the photo): shown while locked, so nothing secret.
public struct ProfileRecord: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public var name: String
    public var color: String
    public var createdAt: Int64
    public var lastUsedAt: Int64

    enum CodingKeys: String, CodingKey {
        case id, name, color
        case createdAt = "created_at"
        case lastUsedAt = "last_used_at"
    }

    public init(id: String, name: String, color: String, createdAt: Int64, lastUsedAt: Int64) {
        self.id = id; self.name = name; self.color = color; self.createdAt = createdAt; self.lastUsedAt = lastUsedAt
    }

    /// The profile's initial for its chip.
    public var initial: String { name.first.map { String($0).uppercased() } ?? "?" }
}

public enum ProfileRegistryError: Error, Equatable {
    case invalidName
    case unknown
    case lastProfile
    case corrupt
}

/// The Mac profile list (`Profiles/profiles.json` in the app group container; docs/design/mac-profiles-2026-11-03.md).
/// With no file there is one profile, the default, whose vault is the one from before profiles.
public final class ProfileRegistry: @unchecked Sendable {
    /// Windows `DEFAULT_COLORS`.
    public static let colors = ["#28C7FA", "#7C5CFC", "#34D399", "#F59E0B", "#F472B6", "#60A5FA"]
    public static let nameLimit = 40
    public static let version = 1

    struct Index: Codable, Equatable {
        var version: Int
        var active: String
        var profiles: [ProfileRecord]
    }

    /// The container (or, in tests, any folder): `Vault` is the default profile's directory, `Profiles/` the rest.
    public let root: URL
    private let defaultName: String
    private let now: () -> Int64
    /// Told the active profile after each write: the app keeps the Safari extension's copy of it
    /// (`SafariSaveFiles.recordActiveProfile`), since the extension cannot read this file (audit 2026-11-10).
    private let onWrite: (@Sendable (String) -> Void)?
    private let lock = NSLock()

    public init(root: URL, defaultName: String = String(localized: "Personal"),
                now: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970) },
                onWrite: (@Sendable (String) -> Void)? = nil) {
        self.root = root; self.defaultName = defaultName; self.now = now; self.onWrite = onWrite
    }

    /// The app group container's registry, nil without a container (unsigned builds).
    public static func shared() -> ProfileRegistry? {
        #if DEBUG
        // Debug builds only: a throwaway root for the profile list and every profile's vault (manual checks).
        if let path = ProcessInfo.processInfo.environment["LGK_MAC_PROFILES_ROOT"], !path.isEmpty {
            return ProfileRegistry(root: URL(fileURLWithPath: path, isDirectory: true),
                                   onWrite: { id in SafariSaveFiles.recordActiveProfile(id) })
        }
        #endif
        return AppGroup.containerURL.map { root in
            ProfileRegistry(root: root, onWrite: { id in SafariSaveFiles.recordActiveProfile(id) })
        }
    }

    var fileURL: URL { root.appendingPathComponent("Profiles", isDirectory: true).appendingPathComponent("profiles.json") }

    /// The default profile's vault keeps its old place; the others live in `Profiles/<id>/Vault`.
    public func vaultDirectory(for id: String) -> URL {
        if id == ProfileScope.defaultID { return root.appendingPathComponent("Vault", isDirectory: true) }
        return root.appendingPathComponent("Profiles", isDirectory: true)
            .appendingPathComponent(id, isDirectory: true).appendingPathComponent("Vault", isDirectory: true)
    }

    // MARK: reading

    func read() throws -> Index {
        guard let data = try? Data(contentsOf: fileURL) else { return fallback() }
        guard let index = try? JSONDecoder().decode(Index.self, from: data), !index.profiles.isEmpty,
              Set(index.profiles.map(\.id)).count == index.profiles.count,
              index.profiles.allSatisfy({ Self.isValidID($0.id) }) else { throw ProfileRegistryError.corrupt }
        var fixed = index
        if !fixed.profiles.contains(where: { $0.id == fixed.active }) { fixed.active = fixed.profiles[0].id }
        return fixed
    }

    private func fallback() -> Index {
        Index(version: Self.version, active: ProfileScope.defaultID,
              profiles: [ProfileRecord(id: ProfileScope.defaultID, name: defaultName, color: Self.colors[0], createdAt: 0, lastUsedAt: 0)])
    }

    /// Every profile, oldest first; a damaged file reads as the default profile alone (its vault stays where it was).
    public func profiles() -> [ProfileRecord] { (try? read())?.profiles ?? fallback().profiles }

    public func active() -> ProfileRecord {
        let index = (try? read()) ?? fallback()
        return index.profiles.first { $0.id == index.active } ?? index.profiles[0]
    }

    // MARK: changing

    private func write(_ index: Index) throws {
        let folder = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        try encoder.encode(index).write(to: fileURL, options: .atomic)
    }

    private func change<T>(_ body: (inout Index) throws -> T) throws -> T {
        try lock.withLock {
            var index = try read()
            let out = try body(&index)
            try write(index)
            onWrite?(index.active)
            return out
        }
    }

    /// A new, empty profile (its vault is created at its first unlock screen). It is not made active.
    @discardableResult
    public func create(name: String) throws -> ProfileRecord {
        let clean = try Self.validatedName(name)
        return try change { index in
            let color = Self.colors[index.profiles.count % Self.colors.count]
            let record = ProfileRecord(id: UUID().uuidString.lowercased(), name: clean, color: color, createdAt: now(), lastUsedAt: 0)
            index.profiles.append(record)
            return record
        }
    }

    public func rename(_ id: String, to name: String) throws {
        let clean = try Self.validatedName(name)
        try change { index in
            guard let i = index.profiles.firstIndex(where: { $0.id == id }) else { throw ProfileRegistryError.unknown }
            index.profiles[i].name = clean
        }
    }

    /// Makes `id` the profile the app opens and AutoFill serves.
    public func setActive(_ id: String) throws {
        try change { index in
            guard let i = index.profiles.firstIndex(where: { $0.id == id }) else { throw ProfileRegistryError.unknown }
            index.active = id
            index.profiles[i].lastUsedAt = now()
        }
    }

    /// Drops `id` from the list (its files and Keychain items are removed by the caller). Never the last profile;
    /// the active one passes to the most recently used of the rest.
    public func remove(_ id: String) throws {
        try change { index in
            guard index.profiles.contains(where: { $0.id == id }) else { throw ProfileRegistryError.unknown }
            guard index.profiles.count > 1 else { throw ProfileRegistryError.lastProfile }
            index.profiles.removeAll { $0.id == id }
            if index.active == id {
                index.active = index.profiles.max(by: { $0.lastUsedAt < $1.lastUsedAt })?.id ?? index.profiles[0].id
            }
        }
    }

    // MARK: rules

    public static func validatedName(_ name: String) throws -> String {
        let clean = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty, clean.count <= nameLimit,
              !clean.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw ProfileRegistryError.invalidName
        }
        return clean
    }

    /// The default id or a lowercase UUID: ids become folder names and Keychain account prefixes.
    static func isValidID(_ id: String) -> Bool {
        if id == ProfileScope.defaultID { return true }
        guard let uuid = UUID(uuidString: id) else { return false }
        return uuid.uuidString.lowercased() == id
    }
}
#endif
