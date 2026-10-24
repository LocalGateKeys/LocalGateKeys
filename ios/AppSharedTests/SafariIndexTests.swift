import XCTest
import LGKCore
@testable import AppShared

/// Records every published snapshot.
final class RecordingSafariIndexPublisher: SafariIndexPublishing, @unchecked Sendable {
    private var log: [StoreSnapshot] = []
    private let lock = NSLock()
    var published: [StoreSnapshot] { lock.withLock { log } }
    func publish(_ snapshot: StoreSnapshot) { lock.withLock { log.append(snapshot) } }
}

final class SafariIndexTests: XCTestCase {
    var dir: URL!
    let key = Array(repeating: UInt8(7), count: 32)
    let otherKey = Array(repeating: UInt8(8), count: 32)

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-safari-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    /// A synced wrapper of a record of `kind` in `ns`, with a login's fields.
    func wrapper(_ id: String, ns: Namespace = .entry, kind: String = "web", origin: String = "https://example.com",
                 username: String = "alex", password: String = "pw1") -> JSONValue {
        Wrapper.make(ns: ns, record: .object([
            "id": .string(id), "kind": .string(kind), "label": .string(id), "username": .string(username),
            "password": .string(password), "scope": .object(["origin": .string(origin)]), "updated_at": .int(1),
        ]))
    }

    /// Audit 2026-10-24 M-3 / L-7: the index answers only new / exists, and holds no password fingerprint.
    func test_exists_new() throws {
        let index = SafariIndex.fingerprints(records: ["a": wrapper("a")], key: key)
        XCTAssertEqual(index.entries.count, 1)
        XCTAssertEqual(index.classify(origin: "https://example.com", username: "alex", key: key), .exists)
        XCTAssertEqual(index.classify(origin: "https://example.com", username: "sam", key: key), .new)
        XCTAssertEqual(index.classify(origin: "https://other.example", username: "alex", key: key), .new)
        XCTAssertEqual(index.classify(origin: "https://example.com", username: "Alex", key: key), .new,
                       "usernames are compared exactly")
        XCTAssertEqual(SafariLoginStatus.exists.rawValue, "exists")
        // The password does not change the index at all.
        XCTAssertEqual(SafariIndex.fingerprints(records: ["a": wrapper("a", password: "other")], key: key), index)
        XCTAssertFalse(String(decoding: try index.encoded(), as: UTF8.self).contains("secret"))
    }

    func test_tombstones_and_other_kinds_ignored() throws {
        let records: [String: JSONValue] = [
            "live": wrapper("live"),
            "desk": wrapper("desk", kind: "desktop", username: "desk-user"),
            "note": wrapper("note", ns: .item, kind: "note", username: "note-user"),
            "odd": wrapper("odd", ns: .item, kind: "web", username: "item-ns-user"),
        ]
        let index = SafariIndex.fingerprints(records: records, key: key)
        XCTAssertEqual(index.entries.count, 1, "only the live web login")
        for user in ["desk-user", "note-user", "item-ns-user", "gone-user"] {
            XCTAssertEqual(index.classify(origin: "https://example.com", username: user, key: key), .new, user)
        }

        // End to end: a deleted login is only a tombstone in the sync meta, never in the published index.
        let vault = InMemoryKeychainVault()
        try vault.write(.safariIndexKey, key)
        let out = dir.appendingPathComponent("SafariSave", isDirectory: true)
        let store = try LocalStore(directory: dir.appendingPathComponent("Vault", isDirectory: true), key: Array(repeating: 9, count: 32),
                                   random: FixedRandom())
        store.limitHints = nil
        store.safariIndex = SafariIndexPublisher(keychain: vault, directory: { out })
        var all = records
        all["gone"] = nil
        try store.commit(StoreChange(baseRevision: 0, records: all,
                                     meta: ["gone": .tomb(vv: ["desk": 2], deletedAt: 50)], sync: nil))
        let published = try SafariIndex.decode(Array(try Data(contentsOf: SafariSaveFiles.indexURL(in: out))))
        XCTAssertEqual(published, index)
        XCTAssertEqual(published.classify(origin: "https://example.com", username: "alex", key: key), .exists)
        XCTAssertEqual(published.classify(origin: "https://example.com", username: "gone-user", key: key), .new)
    }

    func test_origin_is_canonicalised() {
        let index = SafariIndex.fingerprints(records: ["a": wrapper("a", origin: "https://Example.COM/")], key: key)
        XCTAssertEqual(index.classify(origin: "https://EXAMPLE.com:443", username: "alex", key: key), .exists)
        XCTAssertEqual(index.classify(origin: "https://example.com:8443", username: "alex", key: key), .new)
        XCTAssertEqual(index.classify(origin: "http://example.com", username: "alex", key: key), .new,
                       "plain HTTP on a public host is not a valid origin")
        XCTAssertEqual(index.classify(origin: "not an origin", username: "alex", key: key), .new)
    }

    func test_json_input_prevents_separator_collisions() {
        // A username holding JSON punctuation stays one field of the MAC input.
        let first = SafariIndex.fingerprints(records: ["a": wrapper("a", origin: "https://example.com", username: "a\",\"b")], key: key)
        let second = SafariIndex.fingerprints(records: ["a": wrapper("a", origin: "https://example.com", username: "a")], key: key)
        XCTAssertEqual(first.entries.count, 1); XCTAssertEqual(second.entries.count, 1)
        XCTAssertNotEqual(first.entries[0].login, second.entries[0].login)
        XCTAssertEqual(first.classify(origin: "https://example.com", username: "a", key: key), .new)
        XCTAssertEqual(second.classify(origin: "https://example.com", username: "a\",\"b", key: key), .new)
    }

    func test_round_trip_encode_decode() throws {
        let index = SafariIndex.fingerprints(records: [
            "a": wrapper("a"), "b": wrapper("b", origin: "https://b.example", username: "sam", password: "pw9"),
            "c": wrapper("c"),   // the same login twice is one entry
        ], key: key)
        XCTAssertEqual(index.entries.count, 2)
        let bytes = try index.encoded()
        let decoded = try SafariIndex.decode(bytes)
        XCTAssertEqual(decoded, index)
        XCTAssertEqual(try decoded.encoded(), bytes)
        XCTAssertEqual(decoded.classify(origin: "https://b.example", username: "sam", key: key), .exists)

        guard case .object(let o) = try CanonicalJSON.parse(bytes), case .array(let rows)? = o["entries"],
              case .object(let row)? = rows.first, case .string(let login)? = row["login"] else { return XCTFail("shape") }
        XCTAssertEqual(o["version"], .int(2))
        XCTAssertEqual(try Base64.decodeStrict(login).count, 32)
        XCTAssertEqual(Set(o.keys), ["version", "entries"]); XCTAssertEqual(Set(row.keys), ["login"])

        XCTAssertEqual(try SafariIndex.decode(try SafariIndex(entries: []).encoded()).entries, [])

        // A version 1 file from an earlier build is read for its logins; its password fingerprints are dropped.
        let mac = Base64.encode(index.entries[0].login), pad = Base64.encode(Array(repeating: UInt8(1), count: 32))
        let v1 = #"{"entries":[{"login":""# + mac + #"","secret":""# + pad + #""}],"version":1}"#
        XCTAssertEqual(try SafariIndex.decode(Array(v1.utf8)).entries, [index.entries[0]])

        for bad in [#"{"version":3,"entries":[]}"#, #"{"version":2}"#, #"{"version":2,"entries":[{"login":"AA=="}]}"#,
                    #"{"version":1,"entries":[{"login":"AA==","secret":"AA=="}]}"#,
                    #"{"entries":[{"login":""# + mac + #"","secret":""# + pad + #""}],"version":2}"#,
                    #"{"version":2,"entries":[],"x":1}"#, "not json"] {
            XCTAssertThrowsError(try SafariIndex.decode(Array(bad.utf8)), bad) { XCTAssertEqual($0 as? SafariIndexError, .malformed) }
        }
    }

    func test_wrong_key_never_matches() {
        let index = SafariIndex.fingerprints(records: ["a": wrapper("a")], key: key)
        XCTAssertEqual(index.classify(origin: "https://example.com", username: "alex", key: otherKey), .new)
        XCTAssertNotEqual(SafariIndex.fingerprints(records: ["a": wrapper("a")], key: otherKey), index)
    }

    func test_commit_publishes_index() throws {
        let recorder = RecordingSafariIndexPublisher()
        let store = try LocalStore(directory: dir, key: Array(repeating: 9, count: 32), random: FixedRandom())
        store.limitHints = nil
        store.safariIndex = recorder
        let change = StoreChange(baseRevision: 0, records: ["a": wrapper("a")], meta: [:], sync: nil)
        try store.commit(change)
        XCTAssertEqual(recorder.published, [try store.load()])
        XCTAssertEqual(recorder.published.first?.revision, 1)
        XCTAssertEqual(recorder.published.first?.records, change.records)

        // A refused commit publishes nothing.
        XCTAssertThrowsError(try store.commit(change))
        XCTAssertEqual(recorder.published.count, 1)
    }

    func test_publisher_is_best_effort() throws {
        let vault = InMemoryKeychainVault()
        let out = dir.appendingPathComponent("SafariSave", isDirectory: true)
        let snap = StoreSnapshot(records: ["a": wrapper("a")], revision: 1)
        let indexFile = SafariSaveFiles.indexURL(in: out)

        // No key yet (the app has not created it): nothing is written.
        SafariIndexPublisher(keychain: vault, directory: { out }).publish(snap)
        XCTAssertFalse(FileManager.default.fileExists(atPath: indexFile.path))

        // No container: swallowed.
        try vault.write(.safariIndexKey, key)
        SafariIndexPublisher(keychain: vault, directory: { throw LocalStoreError.noContainer }).publish(snap)
        XCTAssertFalse(FileManager.default.fileExists(atPath: indexFile.path))

        // A commit whose publisher fails still commits.
        let store = try LocalStore(directory: dir.appendingPathComponent("Vault", isDirectory: true), key: Array(repeating: 9, count: 32),
                                   random: FixedRandom())
        store.limitHints = nil
        store.safariIndex = SafariIndexPublisher(keychain: vault, directory: { throw LocalStoreError.noContainer })
        try store.commit(StoreChange(baseRevision: 0, records: snap.records, meta: [:], sync: nil))
        XCTAssertEqual(try store.load().revision, 1)

        // With the key: written atomically, no temp file left.
        SafariIndexPublisher(keychain: vault, directory: { out }).publish(snap)
        let written = try SafariIndex.decode(Array(try Data(contentsOf: indexFile)))
        XCTAssertEqual(written, SafariIndex.fingerprints(records: snap.records, key: key))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: out.path), [SafariSaveFiles.indexFileName])
    }

    func test_device_unlocked_slots_not_app_only() throws {
        XCTAssertEqual(VaultSlot.safariIndexKey.rawValue, "safari-index-key")
        XCTAssertEqual(VaultSlot.safariInboxKey.rawValue, "safari-inbox-key")
        XCTAssertEqual(VaultSlot.deviceUnlocked, [.safariIndexKey, .safariInboxKey])
        XCTAssertTrue(VaultSlot.deviceUnlocked.isDisjoint(with: VaultSlot.appOnly))
        XCTAssertTrue(VaultSlot.deviceUnlocked.isSubset(of: Set(VaultSlot.allCases)), "erase deletes every case")
        let shared = InMemoryKeychainVault(), app = InMemoryKeychainVault()
        let vault = AppKeychainVault(shared: shared, appOnly: app)
        for slot in VaultSlot.deviceUnlocked { try vault.write(slot, [1]) }
        for slot in VaultSlot.deviceUnlocked {
            XCTAssertEqual(try shared.read(slot), [1], "\(slot) is in the group the Safari extension shares")
            XCTAssertNil(try app.read(slot))
        }
    }
}
