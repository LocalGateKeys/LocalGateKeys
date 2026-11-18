import XCTest
import Foundation
@testable import LGKCore

// The cross-platform folder check (sub-plan 07 Task 5n), the Swift mirror of the Kotlin `CollectionInteropTest`, against
// `tests/vectors/share/collections/folder.json`: device A's personal sync folder written by the desktop (`folder/a`:
// keyring, signed view with two collections, memberships and a share link, capability files). This core joins it as
// device B with the password (the Argon2id output comes from the vector), runs once more, and must then hold the
// catalog, memberships and link the desktop's B holds (`expected_b`) and publish A's states unchanged.
//
// `LGK_WRITE_FROM_IOS=1` writes B's files (everything this core wrote or changed in the folder) to
// `folder/from_ios/`; the desktop's device A reads them back to the same state in
// `tests/test_share_collection_vectors.py`.
//
// One `DetRand(b_run.rand)` stream feeds the join and both runs, in the order the Kotlin core draws it, so every file
// must equal Kotlin's `folder/from_android/` byte for byte, except what CryptoKit signs with hedged randomness (the
// desktop and Kotlin sign deterministically, RFC 8032): the `.lgksig` files and the keyring's `signing_proof` (and so
// its MAC). Those are compared with Kotlin's signature copied in, and Kotlin's signatures must verify over our bytes
// with our key (the same Ed25519 key: same stream).

private func o(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let x)? = v { return x }; return [:] }
private func a(_ v: JSONValue?) -> [JSONValue] { if case .array(let x)? = v { return x }; return [] }
private func s(_ v: JSONValue?) -> String { if case .string(let x)? = v { return x }; return "" }
private func i(_ v: JSONValue?) -> Int64 { if case .int(let x)? = v { return x }; return -1 }

final class CollectionInteropTests: XCTestCase {
    struct Out {
        let folder: MemoryFolder
        let input: [String: [UInt8]]
        let store: MemoryStore
        let deviceID: String

        /// Every file B wrote or changed, by its path under the sync folder.
        func written(_ syncDir: String) -> [String: [UInt8]] {
            var out: [String: [UInt8]] = [:]
            for (path, data) in folder.files where input[path] != data {
                XCTAssertTrue(path.hasPrefix(syncDir + "/"), path)
                out[String(path.dropFirst(syncDir.count + 1))] = data
            }
            return out
        }
    }

    var doc: [String: JSONValue] = [:]
    var syncDir = ""
    var gk: GroupKey!
    var run: [String: JSONValue] = [:]
    var expected: [String: JSONValue] = [:]

    override func setUpWithError() throws {
        doc = o(try CanonicalJSON.parse(Array(try Data(contentsOf: Vectors.shareCollections("folder.json")))))
        syncDir = s(doc["sync_dir"])
        gk = try GroupKey(groupID: s(doc["group_id"]), epoch: i(doc["epoch"]), key: Vectors.hex(s(doc["group_key_hex"])))
        run = o(doc["b_run"])
        expected = o(doc["expected_b"])
    }

    /// A's folder, then B joins (password key from the vector) and runs once more.
    func flow() throws -> Out {
        let folder = MemoryFolder()
        for rel in a(doc["files"]) {
            folder.files["\(syncDir)/\(s(rel))"] = Array(try Data(contentsOf: Vectors.shareCollections("folder/a/\(s(rel))")))
        }
        let input = folder.files
        let argon = o(doc["argon2"])
        let password = s(doc["password"])
        let rand = DetRand(s(run["rand"]))
        let store = MemoryStore()
        let fs = try FolderSync(access: folder, installID: "ios-interop", collections: true)
        let joined = try fs.join(store: store, deviceName: s(run["device_name"]), random: rand,
                                 clock: FixedClock(now: i(run["join_at"]))) { ring in
            let salt = s(o(o(ring)["kdf"])["salt"])
            guard case .string(let hex)? = argon["\(password)|\(salt)"] else {
                throw FolderSyncError("password", "no Argon2id output for salt \(salt)")
            }
            return Vectors.hex(hex)
        }
        XCTAssertEqual(joined.issues, [], "join")
        XCTAssertTrue(joined.wrote)
        let again = fs.runOnce(store: store, random: rand, clock: FixedClock(now: i(run["run_at"])))
        XCTAssertEqual(again.issues, [], "second run")
        return Out(folder: folder, input: input, store: store, deviceID: try XCTUnwrap(store.snapshot.sync).deviceID)
    }

    func test_b_joins_the_desktop_folder_and_ends_like_the_desktop_b() throws {
        let out = try flow()
        let snap = out.store.snapshot
        var catalog: [String: [String: String]] = [:]
        for c in CollectionCatalog.collections(in: snap) { catalog[c.id] = ["name": c.name, "description": c.description] }
        XCTAssertEqual(catalog, o(expected["catalog"]).mapValues { ["name": s(o($0)["name"]), "description": s(o($0)["description"])] })
        var memberships: [String: [String]] = [:]
        for id in snap.itemRecords.keys {
            let ids = CollectionCatalog.memberships(of: id, in: snap)
            if !ids.isEmpty { memberships[id] = ids }
        }
        XCTAssertEqual(memberships, o(expected["memberships"]).mapValues { a($0).map { s($0) } })
        var links: [String: [String: String]] = [:]
        for (id, w) in snap.records where id.hasPrefix(CollectionStates.linkPrefix) {
            let r = o(o(w)["record"])
            links[s(r["collection_id"])] = ["mode": s(r["mode"]), "role": s(r["role"])]
        }
        XCTAssertEqual(links, o(expected["links"]).mapValues { ["mode": s(o($0)["mode"]), "role": s(o($0)["role"])] })
        XCTAssertEqual(snap.itemRecords.keys.sorted(), a(expected["items"]).map { s($0) })

        // B's view republishes A's states unchanged, signed with the key the keyring lists for B.
        let raw = try XCTUnwrap(out.folder.files[FolderSyncTests.devPath(out.deviceID)])
        let view = try ViewFile.decode(raw, key: gk, expectedDeviceID: out.deviceID)
        XCTAssertEqual(view.states, try a(doc["a_states"]).map(MergeVectors.state))
        let ring = try Keyring.parse(try XCTUnwrap(out.folder.files["\(syncDir)/keyring.lgkkeys"]))
        let identity = try XCTUnwrap(snap.sync).identity
        let key = try XCTUnwrap(Keyring.memberSigningKeys(ring)[out.deviceID])
        XCTAssertEqual(key, Base64.encode(identity.signingPublicKey))
        let sig = try XCTUnwrap(out.folder.files["\(syncDir)/signatures/\(out.deviceID).lgksig"])
        XCTAssertEqual(try ViewSignature.verify(sig, raw: raw, header: view.header), identity.signingPublicKey)
        XCTAssertTrue(FolderBlobs(access: out.folder).capable(gk, deviceID: out.deviceID, signer: key, feature: .collections))
    }

    /// The data file a signature file signs (`signatures/<id>.lgksig` signs `devices/<id>.lgksync`).
    func signedFile(_ sigPath: String) -> String {
        let base = String(sigPath.dropLast(".lgksig".count))
        if base.hasSuffix(".lgkcol") || base.hasSuffix(".lgkcap") || base.hasSuffix(".lgkheircap") { return base }
        if base.hasPrefix("signatures/") { return "devices/" + String(base.dropFirst("signatures/".count)) + ".lgksync" }
        return base + ".lgksync"
    }

    /// `mine` with each member's `signing_proof` from `theirs` and the MAC recomputed (hedged signatures differ).
    func withSignaturesOf(_ theirs: JSONValue, _ mine: JSONValue) throws -> JSONValue {
        var m = o(mine)
        var proofs: [String: JSONValue] = [:]
        for e in a(o(theirs)["members"]) { proofs[s(o(e)["device_id"])] = o(e)["signing_proof"] ?? .null }
        m["members"] = .array(a(m["members"]).map { e in
            var eo = o(e)
            if let p = proofs[s(eo["device_id"])] { eo["signing_proof"] = p }
            return .object(eo)
        })
        return try Keyring.finish(m, key: gk)
    }

    func test_swift_b_writes_the_android_bytes() throws {
        let out = try flow()
        let mine = out.written(syncDir)
        let dir = Vectors.shareCollections("folder/from_android")
        var kotlin: [String: [UInt8]] = [:]
        let files = try XCTUnwrap(FileManager.default.enumerator(at: dir, includingPropertiesForKeys: [.isRegularFileKey]))
        let base = dir.resolvingSymlinksInPath().pathComponents
        for case let url as URL in files {
            guard try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true else { continue }
            let parts = url.resolvingSymlinksInPath().pathComponents
            XCTAssertEqual(Array(parts.prefix(base.count)), base)
            kotlin[parts.dropFirst(base.count).joined(separator: "/")] = Array(try Data(contentsOf: url))
        }
        XCTAssertEqual(mine.keys.sorted(), kotlin.keys.sorted(), "the same files")
        let ownKey = try XCTUnwrap(out.store.snapshot.sync).identity.signingPublicKey
        for (rel, data) in mine.sorted(by: { $0.key < $1.key }) {
            guard let theirs = kotlin[rel] else { continue }
            if rel == "keyring.lgkkeys" {
                let adjusted = try withSignaturesOf(try Keyring.parse(theirs), try Keyring.parse(data))
                XCTAssertEqual(try CanonicalJSON.encode(adjusted, dialect: .utf8), theirs, rel)
            } else if rel.hasSuffix(".lgksig") {
                let signed = try XCTUnwrap(mine[signedFile(rel)], rel)
                let header = try ViewFile.decodeHeader(signed)
                XCTAssertEqual(try ViewSignature.verify(data, raw: signed, header: header), ownKey, rel)
                XCTAssertEqual(try ViewSignature.verify(theirs, raw: signed, header: header), ownKey,
                               "\(rel): Kotlin's deterministic signature verifies over our bytes")
                var a1 = o(try CanonicalJSON.parse(data)), a2 = o(try CanonicalJSON.parse(theirs))
                a1["sig"] = nil
                a2["sig"] = nil
                XCTAssertEqual(a1, a2, rel)
            } else {
                XCTAssertEqual(data, theirs, "\(rel) differs from Kotlin's")
            }
        }
    }

    func test_writes_from_ios_files() throws {
        let out = try flow()
        let again = try flow()
        XCTAssertEqual(out.deviceID, again.deviceID)
        let written = out.written(syncDir), second = again.written(syncDir)
        XCTAssertEqual(written.keys.sorted(), second.keys.sorted())
        for (rel, data) in written where !rel.hasSuffix(".lgksig") && rel != "keyring.lgkkeys" {
            XCTAssertEqual(data, second[rel], "\(rel): the same stream writes the same bytes")
        }
        XCTAssertNotNil(written["devices/\(out.deviceID).lgksync"])
        XCTAssertNotNil(written["keyring.lgkkeys"])
        if ProcessInfo.processInfo.environment["LGK_WRITE_FROM_IOS"] == "1" {
            let dir = Vectors.shareCollections("folder/from_ios")
            try? FileManager.default.removeItem(at: dir)
            for (rel, data) in written {
                let url = dir.appendingPathComponent(rel)
                try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                try Data(data).write(to: url, options: .atomic)
            }
        }
    }
}
