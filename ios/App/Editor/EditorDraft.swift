import Foundation
import SwiftUI
import CryptoKit
import AppShared

/// One unsaved editor form (Task 6 of docs/TESTER_FEEDBACK_PLAN_2026-10-29.md): written when the scene leaves
/// `.active` with the editor open, offered after the next unlock. `itemID` nil: a new item. `baseHash` is the
/// SHA-256 of the edited item's record when the editor opened, so a later change (a sync) is noticed.
/// `description` names fields only. Mirrors `android/.../editor/EditorDraft.kt`.
struct EditorDraft: Equatable, Sendable, CustomStringConvertible {
    let kind: EditorKind
    let itemID: String?
    let baseHash: String?
    let values: [String: String]
    let createdAt: Int64

    /// `.sameItem` reopens the item; the others continue as a new item.
    enum Status: Equatable { case newItem, sameItem, itemChanged, itemDeleted }

    func status(in items: [VaultItem]) -> Status {
        guard let id = itemID else { return .newItem }
        guard let item = items.first(where: { $0.id == id }) else { return .itemDeleted }
        return Self.recordHash(item.record) == baseHash ? .sameItem : .itemChanged
    }

    var description: String { "EditorDraft(kind: \(kind), isNew: \(itemID == nil), fields: \(values.keys.sorted()))" }

    /// Hex SHA-256 of the record's canonical JSON (nil when it cannot be encoded).
    static func recordHash(_ record: [String: JSONValue]) -> String? {
        guard let bytes = try? CanonicalJSON.encode(.object(record), dialect: .utf8) else { return nil }
        return SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined()
    }
}

extension EditorModel {
    /// The form as an unsaved draft, stamped `now`.
    func draft(now: Int64) -> EditorDraft {
        EditorDraft(kind: kind, itemID: editingID, baseHash: originalRecord.flatMap(EditorDraft.recordHash),
                    values: values, createdAt: now)
    }
}

/// The one draft file, sealed with a key derived from the vault's local key:
/// HKDF-SHA256(localKey, salt empty, info "localgatekeys|editor-draft|v1", 32 bytes), then AES-256-GCM with a fresh
/// 12-byte nonce and AAD "lgk-editor-draft-v1". File: `nonce || ciphertext+tag`, in the app's own Application Support
/// (not the app group), complete file protection, excluded from backup. Never plaintext, never in UserDefaults,
/// never logged.
///
/// `keychain` returns this unlock's authenticated Keychain (nil once locked): the local key is read at each call, so
/// after a lock nothing is written or read.
@MainActor
final class EditorDraftStore {
    nonisolated static let fileName = "editor-draft.bin"
    nonisolated static let maxAge: Int64 = 7 * 24 * 3600
    nonisolated static let info = Array("localgatekeys|editor-draft|v1".utf8)
    nonisolated static let aad = "lgk-editor-draft-v1"

    let file: URL
    private let keychain: () -> (any KeychainVault)?
    private let random: any RandomSource
    private let clock: any UnixClock

    init(file: URL, keychain: @escaping () -> (any KeychainVault)?, random: any RandomSource = SystemRandomSource(),
         clock: any UnixClock = SystemClock()) {
        self.file = file; self.keychain = keychain; self.random = random; self.clock = clock
    }

    /// `<Application Support>/editor-draft.bin`, in the app's private container. nil: no container.
    nonisolated static func location() -> URL? {
        guard let dir = try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                     appropriateFor: nil, create: true) else { return nil }
        return dir.appendingPathComponent(fileName, isDirectory: false)
    }

    /// Replaces the draft (there is only ever one). False when nothing could be written.
    @discardableResult
    func save(_ draft: EditorDraft) -> Bool {
        guard var key = subkey() else { return false }
        defer { key.resetBytes() }
        do {
            var plain = try Self.encode(draft)
            defer { plain.resetBytes() }
            var blob = try SealedBlob.seal(plain, key: key, aad: Self.aad, random: random)
            defer { blob.resetBytes() }
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(blob).write(to: file, options: [.atomic, .completeFileProtection])
            var url = file
            var values = URLResourceValues(); values.isExcludedFromBackup = true
            try? url.setResourceValues(values)
            return true
        } catch {
            delete()
            return false
        }
    }

    /// The draft, or nil. One that is expired (7 days), unreadable or sealed with another key is deleted.
    func load() -> EditorDraft? {
        guard FileManager.default.fileExists(atPath: file.path) else { return nil }
        guard var key = subkey() else { return nil }   // locked: leave it for the next unlock
        defer { key.resetBytes() }
        do {
            let blob = Array(try Data(contentsOf: file))
            var plain = try SealedBlob.open(blob, key: key, aad: Self.aad)
            defer { plain.resetBytes() }
            let draft = try Self.decode(plain)
            let age = clock.now - draft.createdAt
            guard abs(age) <= Self.maxAge else { delete(); return nil }
            return draft
        } catch {
            delete()
            return nil
        }
    }

    func delete() { Self.deleteFile(file) }

    /// Erase, Leave and Reset use it without a key. True when the file is gone.
    @discardableResult
    nonisolated static func deleteFile(_ url: URL) -> Bool {
        if FileManager.default.fileExists(atPath: url.path) { try? FileManager.default.removeItem(at: url) }
        return !FileManager.default.fileExists(atPath: url.path)
    }

    /// The derived key, or nil when there is no unlocked Keychain or no usable local key. The caller zeroes it.
    private func subkey() -> [UInt8]? {
        guard let vault = keychain(), var local = try? vault.read(.localKey) else { return nil }
        defer { local.resetBytes() }
        guard local.count == 32, local.contains(where: { $0 != 0 }) else { return nil }
        return Self.derive(localKey: local)
    }

    nonisolated static func derive(localKey: [UInt8]) -> [UInt8] {
        CryptoBox.hkdf(ikm: localKey, salt: [], info: info, length: 32)
    }

    nonisolated static func encode(_ d: EditorDraft) throws -> [UInt8] {
        try CanonicalJSON.encode(.object([
            "v": .int(1),
            "kind": .string(d.kind.rawValue),
            "item_id": d.itemID.map { .string($0) } ?? .null,
            "base_hash": d.baseHash.map { .string($0) } ?? .null,
            "values": .object(d.values.mapValues { .string($0) }),
            "created_at": .int(d.createdAt),
        ]), dialect: .utf8)
    }

    struct Malformed: Error {}

    nonisolated static func decode(_ b: [UInt8]) throws -> EditorDraft {
        guard case .object(let o) = try CanonicalJSON.parse(b), case .int(1)? = o["v"],
              case .string(let k)? = o["kind"], let kind = EditorKind(rawValue: k),
              case .object(let vals)? = o["values"], case .int(let created)? = o["created_at"] else { throw Malformed() }
        var values: [String: String] = [:]
        for (key, v) in vals {
            guard case .string(let s) = v else { throw Malformed() }
            values[key] = s
        }
        let itemID: String? = if case .string(let s)? = o["item_id"] { s } else { nil }
        let baseHash: String? = if case .string(let s)? = o["base_hash"] { s } else { nil }
        return EditorDraft(kind: kind, itemID: itemID, baseHash: baseHash, values: values, createdAt: created)
    }
}

/// The prompt after unlock.
enum EditorDraftText {
    static var title: String { String(localized: "Continue your unsaved item?") }
    static var continueLabel: String { String(localized: "Continue") }
    static var discardLabel: String { String(localized: "Discard") }
    static func message(_ status: EditorDraft.Status, kind: EditorKind) -> String {
        switch status {
        case .newItem, .sameItem:
            kind.leftWhileEditingText
        case .itemChanged:
            String(localized: "The item you were editing has changed since. Continue saves your changes as a new item.")
        case .itemDeleted:
            String(localized: "The item you were editing was deleted since. Continue saves your changes as a new item.")
        }
    }
}

private struct EditorDraftsKey: EnvironmentKey {
    static let defaultValue: EditorDraftStore? = nil
}

extension EnvironmentValues {
    /// This unlock's draft file (set by `UnlockedRoot`); nil: the editor keeps no draft.
    var editorDrafts: EditorDraftStore? {
        get { self[EditorDraftsKey.self] }
        set { self[EditorDraftsKey.self] = newValue }
    }
}

private extension Array where Element == UInt8 {
    mutating func resetBytes() { for i in indices { self[i] = 0 } }
}
