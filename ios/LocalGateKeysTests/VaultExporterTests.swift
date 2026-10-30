import XCTest
import AppShared
@testable import LocalGateKeys

@MainActor
final class VaultExporterTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    static let password = "correct horse battery"
    static let device = "0123456789abcdef0123456789abcdef"

    /// Two logins (one with notes holding a comma and a newline), a passkey and a tombstone.
    func populatedStore() throws -> MemoryStore {
        let store = MemoryStore()
        let der = Data(decodeBase64URL(PasskeyKey.generate().pkcs8B64URL, maxBytes: 1024)!)
        let candidates = [
            ImportCandidate(title: "Alpha, Inc", kind: .login(LoginFields(url: "https://a.example/login", username: "ada",
                                                                         password: "p,w\"1", notes: "one, two\nthree", otpauth: nil))),
            ImportCandidate(title: "Bravo", kind: .login(LoginFields(url: "https://b.example", username: "bob",
                                                                    password: "pw2", notes: "", otpauth: nil))),
            ImportCandidate(title: "example.com", kind: .passkey(PasskeyFields(
                rpID: "example.com", userName: "ada", userDisplayName: "Ada", userHandle: Data([1, 2, 3]),
                credentialID: Data(repeating: 7, count: 16), pkcs8: der))),
        ]
        _ = try VaultImporter(store: store, isPro: { true }, now: { [now] in now }, random: SystemRandomSource())
            .importCandidates(candidates, unsupported: 0)
        store.snapshot.meta["gone-1"] = SyncMeta.tomb(vv: ["peer": 3], deletedAt: 1_799_999_000)
        return store
    }

    func exporter(_ store: MemoryStore) -> VaultExporter {
        VaultExporter(store: store, isPro: { false }, appVersion: "1.2.0", fallbackDeviceID: { Self.device },
                      now: { [now] in now }, random: SystemRandomSource())
    }

    func cleanup(_ url: URL) { addTeardownBlock { try? FileManager.default.removeItem(at: url) } }

    func testBackupOpensWithPassword() async throws {
        let store = try populatedStore()
        let url = try await exporter(store).encryptedBackup(password: Self.password, confirmation: Self.password)
        cleanup(url)
        XCTAssertEqual(url.lastPathComponent, "LocalGateKeys-Backup-2027-01-15.lgkm")
        XCTAssertEqual(url.deletingLastPathComponent().standardizedFileURL.path,
                       FileManager.default.temporaryDirectory.standardizedFileURL.path)
        let payload = try PhoneBackup.open(try Data(contentsOf: url), password: Self.password)
        XCTAssertEqual(payload.platform, "ios")
        XCTAssertEqual(payload.deviceID, try VaultExporter.deviceID(snapshot: StoreSnapshot(), installID: { Self.device }))
        XCTAssertEqual(payload.appVersion, "1.2.0")
        let snap = store.snapshot   // after the export committed its vectors: the view is unchanged
        let expected = try SyncMeta.localView(records: snap.records, meta: snap.meta, device: payload.deviceID,
                                              now: Int64(now.timeIntervalSince1970)).states
        XCTAssertEqual(payload.states.count, 4)
        XCTAssertEqual(Set(payload.states.map(\.id)), Set(expected.keys))
        for s in payload.states {
            let e = try XCTUnwrap(expected[s.id])
            XCTAssertEqual(s, BackupState(id: e.itemID, deleted: e.deleted, deletedAt: e.deletedAt, item: e.item, vv: e.vv))
        }
        XCTAssertTrue(payload.states.contains { $0.id == "gone-1" && $0.deleted })
        if let path = ProcessInfo.processInfo.environment["LGK_EXPORT_BACKUP_TO"] {
            try? FileManager.default.removeItem(atPath: path)
            try FileManager.default.copyItem(at: url, to: URL(fileURLWithPath: path))
        }
    }

    func testShortPasswordRefused() async throws {
        let e = exporter(try populatedStore())
        do { _ = try await e.encryptedBackup(password: "elevenchars", confirmation: "elevenchars"); XCTFail() }
        catch { XCTAssertEqual(error as? VaultExporter.Error, .weakPassword) }
        do { _ = try await e.encryptedBackup(password: Self.password, confirmation: Self.password + "x"); XCTFail() }
        catch { XCTAssertEqual(error as? VaultExporter.Error, .mismatch) }
    }

    func testCSVSkipsPasskeysAndDeleted() throws {
        let store = try populatedStore()
        let url = try exporter(store).csv()
        cleanup(url)
        XCTAssertEqual(url.lastPathComponent, "LocalGateKeys-Export-2027-01-15.csv")
        let text = try String(contentsOf: url, encoding: .utf8)
        XCTAssertTrue(text.hasPrefix("Title,URL,Username,Password,Notes,OTPAuth\r\n"))
        let rows = try CSVLogins.candidates(from: text)
        XCTAssertEqual(rows.map(\.title), ["Alpha, Inc", "Bravo"])
        guard case .login(let a) = rows[0].kind else { return XCTFail() }
        XCTAssertEqual(a.password, "p,w\"1")
        XCTAssertEqual(a.notes, "one, two\nthree")
        XCTAssertEqual(a.url, "https://a.example")
    }

    func testCSVIncludesTOTPAsOtpauth() throws {
        let store = MemoryStore()
        _ = try VaultImporter(store: store, isPro: { true }, now: { [now] in now }, random: SystemRandomSource())
            .importCandidates([ImportCandidate(title: "C", kind: .login(LoginFields(
                url: "https://c.example", username: "c", password: "pw", notes: "",
                otpauth: "otpauth://totp/C?secret=JBSWY3DPEHPK3PXP&digits=8")))], unsupported: 0)
        let url = try exporter(store).csv()
        cleanup(url)
        let rows = try CSVLogins.candidates(from: try String(contentsOf: url, encoding: .utf8))
        guard case .login(let c) = rows.first?.kind, let uri = c.otpauth else { return XCTFail() }
        let config = try TOTP.parseOtpauthURI(uri)
        XCTAssertEqual(config.secret, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(config.digits, 8)
    }

    func testExportCommitsVectorsSoLaterEditsDominate() async throws {
        let store = try populatedStore()
        let url = try await exporter(store).encryptedBackup(password: Self.password, confirmation: Self.password)
        cleanup(url)
        XCTAssertEqual(store.commits, 2)   // the import, then the export's vectors
        let payload = try PhoneBackup.open(try Data(contentsOf: url), password: Self.password)
        let backed = try XCTUnwrap(payload.states.first { !$0.deleted })
        guard case .object(var w) = store.snapshot.records[backed.id]!, case .object(var r)? = w["record"] else { return XCTFail() }
        r["updated_at"] = .int(1_800_000_500)
        r["tags"] = .array([.string("edited")])
        w["record"] = .object(r)
        store.snapshot.records[backed.id] = .object(w)
        let after = try SyncMeta.localView(records: store.snapshot.records, meta: store.snapshot.meta,
                                           device: payload.deviceID, now: 1_800_000_600).states[backed.id]!
        XCTAssertTrue(backed.vv.allSatisfy { after.vv[$0.key, default: 0] >= $0.value })
        XCTAssertTrue(after.vv.contains { $0.value > backed.vv[$0.key, default: 0] })
    }

    func testStaleStoreAbortsExport() async throws {
        let store = try populatedStore()
        let stale = StaleStore(store)
        let e = VaultExporter(store: stale, isPro: { false }, appVersion: "1.2.0", fallbackDeviceID: { Self.device },
                              now: { [now] in now }, random: SystemRandomSource())
        do { _ = try await e.encryptedBackup(password: Self.password, confirmation: Self.password); XCTFail() }
        catch LocalStoreError.stale {} catch { XCTFail("\(error)") }
    }

    func testFallbackDeviceIDIsStableUUID5() throws {
        let a = try VaultExporter.deviceID(snapshot: StoreSnapshot(), installID: { Self.device })
        XCTAssertEqual(a, try VaultExporter.deviceID(snapshot: StoreSnapshot(), installID: { Self.device }))
        XCTAssertNotEqual(a, Self.device)
        XCTAssertNotNil(UUID(uuidString: a))
        XCTAssertNotEqual(a, try VaultExporter.deviceID(snapshot: StoreSnapshot(), installID: { "other" }))
    }

    func testRemoveLeftoverExports() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        for n in ["LocalGateKeys-Export-2026-01-01.csv", "LocalGateKeys-Backup-2026-01-01.lgkm", "keep.csv"] {
            try Data("x".utf8).write(to: dir.appendingPathComponent(n))
        }
        VaultExporter.removeLeftoverExports(in: dir)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path), ["keep.csv"])
    }

    // MARK: format 2 (document files)

    /// A store holding the populated items plus one document whose blob is in a temporary `BlobFolder`.
    func documentStore() throws -> (store: MemoryStore, blobs: BlobFolder, ref: AttachmentRef) {
        let store = try populatedStore()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-blobs-\(UUID().uuidString)")
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let blobs = BlobFolder(root: dir)
        let doc = try AttachmentDocuments.make(data: Array("synthetic passport scan\n".utf8), fileName: "passport.pdf",
                                               mimeType: "application/pdf", title: "", now: Int64(now.timeIntervalSince1970),
                                               random: SystemRandomSource(), blobs: blobs)
        store.snapshot.records[doc.id] = doc.wrapper
        return (store, blobs, doc.ref)
    }

    func testBackupCarriesDocumentFiles() async throws {
        let (store, blobs, ref) = try documentStore()
        var e = exporter(store)
        e.blobs = blobs
        let file = try await e.encryptedBackupFile(password: Self.password, confirmation: Self.password)
        cleanup(file.url)
        XCTAssertEqual(file.filesLeftOut, 0)
        let payload = try PhoneBackup.open(try Data(contentsOf: file.url), password: Self.password)
        XCTAssertEqual(Array(payload.files.keys), [ref.blob])
        XCTAssertEqual(try AttachmentSync.openBlob(try XCTUnwrap(payload.files[ref.blob]), ref: ref),
                       Array("synthetic passport scan\n".utf8))
        XCTAssertTrue(String(decoding: try Data(contentsOf: file.url), as: UTF8.self).contains("\"version\":2"))
    }

    func testBackupWithoutTheFileLeavesItOutAndSaysSo() async throws {
        let (store, _, ref) = try documentStore()
        let file = try await exporter(store).encryptedBackupFile(password: Self.password, confirmation: Self.password)
        cleanup(file.url)
        XCTAssertEqual(file.filesLeftOut, 1)
        let payload = try PhoneBackup.open(try Data(contentsOf: file.url), password: Self.password)
        XCTAssertTrue(payload.files.isEmpty)
        XCTAssertTrue(payload.states.contains { AttachmentDocuments.ref(of: $0.item) == ref }, "the document itself stays")
        XCTAssertTrue(String(decoding: try Data(contentsOf: file.url), as: UTF8.self).contains("\"version\":1"))
        XCTAssertTrue(VaultExporter.filesLeftOutMessage(1).hasPrefix("1 document file was left out"))
    }
}

/// Loads like the wrapped store but refuses every commit as stale.
final class StaleStore: ItemStore, @unchecked Sendable {
    let base: MemoryStore
    init(_ base: MemoryStore) { self.base = base }
    func load() throws -> StoreSnapshot { try base.load() }
    func commit(_ change: StoreChange) throws { throw LocalStoreError.stale(expected: change.baseRevision, actual: -1) }
}
