import XCTest
import CryptoKit
import LGKCore
@testable import AppShared

final class FixedRandom: RandomSource, @unchecked Sendable {
    /// Deterministic, non-repeating: SHA-256 of a running counter.
    private var n: UInt64 = 0
    private let lock = NSLock()
    func bytes(count: Int) -> [UInt8] {
        lock.withLock {
            var out: [UInt8] = []
            while out.count < count {
                n += 1
                out += Array(SHA256.hash(data: withUnsafeBytes(of: n.bigEndian) { Data($0) }))
            }
            return Array(out.prefix(count))
        }
    }
}

final class LocalStoreTests: XCTestCase {
    var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    static let secretPassword = "hunter2-very-secret"

    func sampleChange(base: Int64) throws -> StoreChange {
        let w1 = try CanonicalJSON.parse(Array(#"{"ns":"login","record":{"id":"a1","password":"\#(Self.secretPassword)","price":100.0,"big":1e+16,"n":3,"updated_at":7}}"#.utf8))
        let w2 = try CanonicalJSON.parse(Array(#"{"ns":"note","record":{"id":"b2","text":"héllo ☃","updated_at":9}}"#.utf8))
        let identity = try DeviceIdentity.generate(deviceID: "phone-1", random: FixedRandom())
        let sync = SyncGroupState(groupID: "grp", epoch: 2, key: Array(repeating: 7, count: 32), identity: identity,
                                  installID: "inst", hasFolder: true, lastSeen: ["desk": 4], peerDigests: ["desk": "ab"],
                                  membersEpoch: 1, members: ["desk", "phone-1"], keyring: [1, 2, 3], ownCounter: 5,
                                  viewSigners: ["desk": "ZGVzay1zaWduaW5nLWtleQ==", "phone-1": "cGhvbmUta2V5"])
        return StoreChange(baseRevision: base, records: ["a1": w1, "b2": w2],
                           meta: ["a1": try SyncMeta.live(w1, vv: ["phone-1": 1]), "gone": .tomb(vv: ["desk": 2], deletedAt: 50)],
                           sync: sync)
    }

    func test_commit_publishes_plan_full_hint() throws {
        let hints = AppSettings(defaults: UserDefaults(suiteName: "hint-\(UUID().uuidString)")!)
        let store = try LocalStore(directory: dir, key: Array(repeating: 9, count: 32), random: FixedRandom())
        store.limitHints = hints
        func note(_ i: Int) -> JSONValue {
            .object(["ns": .string("item"), "record": .object(["id": .string("n\(i)"), "kind": .string("note")])])
        }
        var records: [String: JSONValue] = [:]
        for i in 0..<3 { records["n\(i)"] = note(i) }
        try store.commit(StoreChange(baseRevision: 0, records: records, meta: [:], sync: nil))
        XCTAssertNil(hints.planFullRevision, "room left")
        records["n3"] = note(3)
        try store.commit(StoreChange(baseRevision: 1, records: records, meta: [:], sync: nil))
        XCTAssertEqual(hints.planFullRevision, 2)
        XCTAssertEqual(LocalStore.committedRevision(directory: dir), 2, "readable before unlock (plain CURRENT)")
        records["n3"] = nil
        try store.commit(StoreChange(baseRevision: 2, records: records, meta: [:], sync: nil))
        XCTAssertNil(hints.planFullRevision)
        XCTAssertNil(LocalStore.committedRevision(directory: dir.appendingPathComponent("missing")))
    }

    func test_store_round_trip() throws {
        let vault = InMemoryKeychainVault()
        let store = try LocalStore.bootstrap(directory: dir, vault: vault, random: FixedRandom())
        XCTAssertEqual(try store.load(), StoreSnapshot())
        let change = try sampleChange(base: 0)
        try store.commit(change)

        let reopened = try LocalStore.open(directory: dir, vault: vault)
        let snap = try reopened.load()
        XCTAssertEqual(snap.revision, 1)
        XCTAssertEqual(snap.records, change.records)
        XCTAssertEqual(snap.meta, change.meta)
        XCTAssertEqual(snap.sync, change.sync)
        // Byte-identical republish: floats stay floats.
        XCTAssertEqual(try CanonicalJSON.encode(snap.records["a1"]!, dialect: .utf8),
                       try CanonicalJSON.encode(change.records["a1"]!, dialect: .utf8))

        // Stale base is refused and leaves the store untouched.
        XCTAssertThrowsError(try store.commit(StoreChange(baseRevision: 0, records: [:], meta: [:], sync: nil)))
        XCTAssertEqual(try store.load(), snap)

        // Next commit replaces everything; only two generations remain on disk.
        try store.commit(StoreChange(baseRevision: 1, records: [:], meta: [:], sync: nil))
        try store.commit(StoreChange(baseRevision: 2, records: ["b2": change.records["b2"]!], meta: [:], sync: nil))
        let last = try store.load()
        XCTAssertEqual(last.revision, 3)
        XCTAssertEqual(Array(last.records.keys), ["b2"])
        XCTAssertNil(last.sync)
        let gens = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasPrefix("g") }.sorted()
        XCTAssertEqual(gens, ["g2", "g3"])
    }

    func test_files_are_encrypted_and_tamper_detected() throws {
        let vault = InMemoryKeychainVault()
        let store = try LocalStore.bootstrap(directory: dir, vault: vault)
        try store.commit(try sampleChange(base: 0))
        let gen = dir.appendingPathComponent("g1")
        for name in try FileManager.default.contentsOfDirectory(atPath: gen.path) {
            let d = try Data(contentsOf: gen.appendingPathComponent(name))
            XCTAssertNil(d.range(of: Data(Self.secretPassword.utf8)), name)
            XCTAssertNil(d.range(of: Data("login".utf8)), name)
        }
        // Swapping item blobs between ids fails authentication.
        let a = try Data(contentsOf: gen.appendingPathComponent("i0.blob"))
        let b = try Data(contentsOf: gen.appendingPathComponent("i1.blob"))
        try b.write(to: gen.appendingPathComponent("i0.blob")); try a.write(to: gen.appendingPathComponent("i1.blob"))
        XCTAssertThrowsError(try store.load())
        // A different local key cannot open the store.
        let other = InMemoryKeychainVault(); try other.write(.localKey, Array(repeating: 9, count: 32))
        XCTAssertThrowsError(try LocalStore.open(directory: dir, vault: other).load())
    }

    func test_uncommitted_generation_is_invisible() throws {
        // Simulates a crash after the new generation was written but before CURRENT moved.
        let vault = InMemoryKeychainVault()
        let store = try LocalStore.bootstrap(directory: dir, vault: vault)
        try store.commit(try sampleChange(base: 0))
        let before = try store.load()
        try FileManager.default.copyItem(at: dir.appendingPathComponent("g1"), to: dir.appendingPathComponent("g2"))
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("tmp-x"), withIntermediateDirectories: false)
        XCTAssertEqual(try store.load(), before)
        try store.commit(StoreChange(baseRevision: 1, records: [:], meta: [:], sync: nil))
        XCTAssertEqual(try store.load().records, [:])
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent("tmp-x").path))
    }

    /// The AutoFill extension opens the store from the Keychain local key alone: `LocalStore.open` takes
    /// no password and no KDF, reads exactly one Keychain slot, and never writes one.
    func test_extension_store_opens_without_kdf() throws {
        let appVault = InMemoryKeychainVault()
        let app = try LocalStore.bootstrap(directory: dir, vault: appVault)
        try app.commit(try sampleChange(base: 0))

        let extVault = InMemoryKeychainVault()
        try extVault.write(.localKey, try XCTUnwrap(appVault.read(.localKey)))
        let start = Date()
        let ext = try LocalStore.open(directory: dir, vault: extVault)
        let snap = try ext.load()
        XCTAssertEqual(snap.records.count, 2)
        XCTAssertEqual(extVault.reads, [.localKey])
        // Argon2id at 128 MiB / 4 iterations takes far longer than this on any device.
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.5)

        let fresh = InMemoryKeychainVault()
        XCTAssertThrowsError(try LocalStore.open(directory: dir, vault: fresh)) {
            XCTAssertEqual($0 as? LocalStoreError, .noLocalKey)
        }
        XCTAssertNil(try fresh.read(.localKey), "open must never create a key")
    }

    func test_nothing_secret_in_user_defaults() throws {
        let vault = InMemoryKeychainVault()
        let store = try LocalStore.bootstrap(directory: dir, vault: vault)
        try store.commit(try sampleChange(base: 0))
        _ = try store.load()
        let counters = VaultCounterStore(vault: vault)
        try counters.persistHelloCounter(64); try counters.setLastAcceptedCounter(9, peer: "desk")
        let identity = try DeviceIdentity.generate(deviceID: "phone-1", random: FixedRandom())
        // Sync secrets live in the sealed store blob (never in defaults).
        try store.commit(StoreChange(baseRevision: try store.load().revision, records: [:], meta: [:],
                                     sync: SyncGroupState(groupID: "grp", epoch: 3, key: Array(repeating: 5, count: 32),
                                                          identity: identity, installID: "inst", hasFolder: false)))
        try vault.write(.folderBookmark, [6, 6])

        let localKey = try XCTUnwrap(vault.read(.localKey))
        let needles: [Data] = [Data(localKey), Data(Base64.encode(localKey).utf8), Data(Self.secretPassword.utf8),
                               Data(identity.signingPrivateKey), Data(Base64.encode(identity.signingPrivateKey).utf8)]
        // Only the app's own persistent domains (the test host's bundle and the app group), not system globals.
        var domains: [[String: Any]] = []
        if let bid = Bundle.main.bundleIdentifier, let d = UserDefaults.standard.persistentDomain(forName: bid) { domains.append(d) }
        if let d = UserDefaults.standard.persistentDomain(forName: AppGroup.identifier) { domains.append(d) }
        if let g = UserDefaults(suiteName: AppGroup.identifier), let d = g.persistentDomain(forName: AppGroup.identifier) { domains.append(d) }
        for domain in domains {
            for (k, v) in domain {
                let lower = k.lowercased()
                for bad in ["localgatekeys", "lgk", "vault", "secret", "password", "localkey", "groupkey", "identity", "keyring", "bookmark", "counter"] {
                    XCTAssertFalse(lower.contains(bad), "UserDefaults key \(k)")
                }
                let blob = (try? PropertyListSerialization.data(fromPropertyList: v, format: .binary, options: 0)) ?? Data("\(v)".utf8)
                for n in needles { XCTAssertNil(blob.range(of: n), "secret under UserDefaults key \(k)") }
            }
        }
    }

    /// Power loss after CURRENT moved but before the new generation reached disk: load falls back to the
    /// newest complete generation, and the next commit based on it succeeds.
    func test_current_pointing_at_missing_generation_falls_back() throws {
        let vault = InMemoryKeychainVault()
        let store = try LocalStore.bootstrap(directory: dir, vault: vault)
        try store.commit(try sampleChange(base: 0))
        try store.commit(StoreChange(baseRevision: 1, records: [:], meta: [:], sync: nil))
        let g1 = try store.load()
        XCTAssertEqual(g1.revision, 2)
        try Data("3\n".utf8).write(to: dir.appendingPathComponent("CURRENT"))
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("g3"), withIntermediateDirectories: false)
        let snap = try store.load()
        XCTAssertEqual(snap, g1)
        try store.commit(StoreChange(baseRevision: snap.revision, records: [:], meta: [:], sync: nil))
        XCTAssertEqual(try store.load().revision, 4)
        // Nothing readable at all: corrupt, never an empty vault.
        for g in ["g3", "g4"] { try FileManager.default.removeItem(at: dir.appendingPathComponent(g)) }
        XCTAssertThrowsError(try store.load())
    }

    /// Tampering with the current generation is reported, never rolled back to an older generation.
    func test_tampered_current_generation_throws_without_rollback() throws {
        let vault = InMemoryKeychainVault()
        let store = try LocalStore.bootstrap(directory: dir, vault: vault)
        try store.commit(try sampleChange(base: 0))
        try store.commit(StoreChange(baseRevision: 1, records: ["b2": try sampleChange(base: 0).records["b2"]!], meta: [:], sync: nil))
        let blob = dir.appendingPathComponent("g2/i0.blob")
        var d = try Data(contentsOf: blob); d[d.count - 1] ^= 0x01; try d.write(to: blob)
        XCTAssertThrowsError(try store.load())
        XCTAssertThrowsError(try store.commit(StoreChange(baseRevision: 1, records: [:], meta: [:], sync: nil)))
        XCTAssertThrowsError(try store.commit(StoreChange(baseRevision: 2, records: [:], meta: [:], sync: nil)))
        let gens = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasPrefix("g") }.sorted()
        XCTAssertEqual(gens, ["g1", "g2"])
        XCTAssertEqual(try String(contentsOf: dir.appendingPathComponent("CURRENT"), encoding: .ascii), "2\n")
    }

    /// A missing CURRENT next to existing generations is corruption, never an empty vault to overwrite.
    func test_read_racing_a_prune_retries_from_current() throws {
        let store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        try store.commit(try sampleChange(base: 0))
        var fired = false
        store.afterStateRead = { rev in
            guard !fired else { return }
            fired = true
            // Two commits land mid-read: CURRENT moves to rev + 2 and generation `rev` is pruned.
            try? store.commit(try! self.sampleChange(base: rev))
            try? store.commit(try! self.sampleChange(base: rev + 1))
        }
        let snap = try store.load()
        XCTAssertTrue(fired)
        XCTAssertEqual(snap.revision, 3)
        XCTAssertEqual(snap.records.count, 2)

        // CURRENT did not move: a missing item blob is damage and still throws.
        store.afterStateRead = nil
        try FileManager.default.removeItem(at: dir.appendingPathComponent("g3/i0.blob"))
        XCTAssertThrowsError(try store.load()) { XCTAssertEqual($0 as? LocalStoreError, .io("missing i0.blob")) }
    }

    func test_missing_current_with_generations_is_corrupt() throws {
        let vault = InMemoryKeychainVault()
        let store = try LocalStore.bootstrap(directory: dir, vault: vault)
        try store.commit(try sampleChange(base: 0))
        try FileManager.default.removeItem(at: dir.appendingPathComponent("CURRENT"))
        XCTAssertThrowsError(try store.load()) { XCTAssertEqual($0 as? LocalStoreError, .corrupt("CURRENT missing but generations exist")) }
        XCTAssertThrowsError(try store.commit(StoreChange(baseRevision: 0, records: [:], meta: [:], sync: nil)))
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.appendingPathComponent("g1/state.blob").path))
    }

    func test_counter_store_and_vault_helpers() throws {
        let vault = InMemoryKeychainVault()
        let counters = VaultCounterStore(vault: vault)
        XCTAssertEqual(try counters.persistedHelloCounter(), 0)
        let source = HelloCounterSource(store: counters, clock: FixedClock())
        let first = try source.nextCounter()
        XCTAssertEqual(try counters.persistedHelloCounter(), first + HelloCounterSource.blockSize - 1)
        try source.acceptInbound(10, peer: "desk")
        XCTAssertThrowsError(try source.acceptInbound(10, peer: "desk"))
        XCTAssertEqual(try VaultCounterStore(vault: vault).lastAcceptedCounter(peer: "desk"), 10)
    }

    // MARK: restored backups

    func excludedFromBackup(_ url: URL) throws -> Bool? {
        try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup
    }

    func test_vault_directory_is_excluded_from_backup_at_creation_and_on_every_bootstrap() throws {
        let vault = InMemoryKeychainVault()
        _ = try LocalStore.bootstrap(directory: dir, vault: vault, random: FixedRandom())
        XCTAssertEqual(try excludedFromBackup(dir), true)
        // An older install created the directory without the flag: the next bootstrap sets it.
        var url = dir!
        var values = URLResourceValues(); values.isExcludedFromBackup = false
        try url.setResourceValues(values)
        XCTAssertEqual(try excludedFromBackup(URL(fileURLWithPath: dir.path)), false)
        _ = try LocalStore.bootstrap(directory: URL(fileURLWithPath: dir.path), vault: vault, random: FixedRandom())
        XCTAssertEqual(try excludedFromBackup(URL(fileURLWithPath: dir.path)), true)
    }

    func test_store_files_without_their_key_are_reported_not_overwritten() throws {
        // A backup restored to a new iPhone: the files came back, the device-only Keychain key did not.
        let original = InMemoryKeychainVault()
        let store = try LocalStore.bootstrap(directory: dir, vault: original, random: FixedRandom())
        try store.commit(try sampleChange(base: 0))
        let restored = InMemoryKeychainVault()
        XCTAssertThrowsError(try LocalStore.bootstrap(directory: dir, vault: restored, random: FixedRandom())) { e in
            XCTAssertEqual(e as? LocalStoreError, .vaultWithoutKey)
        }
        XCTAssertNil(try restored.read(.localKey), "no new key is made over files it cannot read")
        XCTAssertNotNil(LocalStore.committedRevision(directory: dir), "the files are left for Start fresh")
    }

    func test_empty_or_missing_directory_without_a_key_is_a_first_run() throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data().write(to: dir.appendingPathComponent(".lock"))   // a lock file alone holds no vault
        let vault = InMemoryKeychainVault()
        _ = try LocalStore.bootstrap(directory: dir, vault: vault, random: FixedRandom())
        XCTAssertNotNil(try vault.read(.localKey))
    }

    func test_sync_state_lan_peers_round_trip_and_old_states_decode() throws {
        var sync = try XCTUnwrap(try sampleChange(base: 0).sync)
        XCTAssertEqual(try LocalStore.decodeSync(LocalStore.encodeSync(sync)).lanPeers, [])
        sync.lanPeers = [LanPeer(deviceID: "desk", groupID: "grp", name: "Desk PC", endpoint: try LanEndpoint(validating: "192.168.1.4", port: 47821),
                                 signingPublic: Array(repeating: 1, count: 32), exchangePublic: Array(repeating: 2, count: 32), pairedAt: 9),
                         LanPeer(deviceID: "old", groupID: "grp", signingPublic: Array(repeating: 3, count: 32),
                                 exchangePublic: Array(repeating: 4, count: 32), revoked: true)]
        XCTAssertEqual(try LocalStore.decodeSync(LocalStore.encodeSync(sync)), sync)
        // A state stored before the field existed decodes with no LAN peers.
        guard case .object(var o) = LocalStore.encodeSync(sync) else { return XCTFail() }
        o["lan_peers"] = nil
        var old = sync; old.lanPeers = []
        XCTAssertEqual(try LocalStore.decodeSync(.object(o)), old)
        o["lan_peers"] = .array([.string("x")])
        XCTAssertThrowsError(try LocalStore.decodeSync(.object(o))) { XCTAssertEqual($0 as? LocalStoreError, .corrupt("lan_peers")) }
    }

    func test_sync_state_unacked_members_round_trip_and_old_states_decode() throws {
        var sync = try XCTUnwrap(try sampleChange(base: 0).sync)
        sync.unackedMembers = ["c-device"]
        XCTAssertEqual(try LocalStore.decodeSync(LocalStore.encodeSync(sync)), sync)
        guard case .object(var o) = LocalStore.encodeSync(sync) else { return XCTFail() }
        o["unacked_members"] = nil
        XCTAssertEqual(try LocalStore.decodeSync(.object(o)).unackedMembers, [])
        o["unacked_members"] = .string("x")
        XCTAssertThrowsError(try LocalStore.decodeSync(.object(o))) { XCTAssertEqual($0 as? LocalStoreError, .corrupt("unacked_members")) }
    }

    func test_sync_state_witness_fields_round_trip_only_when_set_and_old_states_decode() throws {
        let plain = try XCTUnwrap(try sampleChange(base: 0).sync)
        guard case .object(let p) = LocalStore.encodeSync(plain) else { return XCTFail() }
        for k in ["peer_generations", "rollback_suspected", "witness_peers", "witness_counters", "generation_offset"] {
            XCTAssertNil(p[k], k)   // defaults are not written
        }
        var sync = plain
        sync.peerGenerations = ["b-device": 12]; sync.rollbackSuspected = 40
        sync.witnessPeers = ["b-device"]; sync.witnessCounters = ["b-device": 5]; sync.generationOffset = 7
        XCTAssertEqual(try LocalStore.decodeSync(LocalStore.encodeSync(sync)), sync)
        guard case .object(var o) = LocalStore.encodeSync(sync) else { return XCTFail() }
        o["peer_generations"] = .object(["b-device": .int(-1)])
        XCTAssertThrowsError(try LocalStore.decodeSync(.object(o))) { XCTAssertEqual($0 as? LocalStoreError, .corrupt("peer_generations")) }
        o["peer_generations"] = nil
        o["witness_peers"] = .array([.string("bad id")])
        XCTAssertThrowsError(try LocalStore.decodeSync(.object(o))) { XCTAssertEqual($0 as? LocalStoreError, .corrupt("witness_peers")) }
    }

    func test_sync_state_attachment_peers_round_trip_only_when_set() throws {
        let plain = try XCTUnwrap(try sampleChange(base: 0).sync)
        guard case .object(let p) = LocalStore.encodeSync(plain) else { return XCTFail() }
        XCTAssertNil(p["attachment_peers"])   // default is not written
        var sync = plain
        sync.attachmentPeers = ["b-device", "c-device"]
        guard case .object(var o) = LocalStore.encodeSync(sync) else { return XCTFail() }
        XCTAssertEqual(o["attachment_peers"], .array([.string("b-device"), .string("c-device")]))
        XCTAssertEqual(try LocalStore.decodeSync(.object(o)), sync)
        o["attachment_peers"] = .array([.string("b-device"), .string("b-device")])
        XCTAssertThrowsError(try LocalStore.decodeSync(.object(o))) { XCTAssertEqual($0 as? LocalStoreError, .corrupt("attachment_peers")) }
        o["attachment_peers"] = .string("b-device")
        XCTAssertThrowsError(try LocalStore.decodeSync(.object(o))) { XCTAssertEqual($0 as? LocalStoreError, .corrupt("attachment_peers")) }
    }
}

struct FixedClock: UnixClock { var now: Int64 { 1_700_000_000 } }
