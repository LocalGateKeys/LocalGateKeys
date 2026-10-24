import XCTest
import AuthenticationServices
import CryptoKit
import AppShared

/// tests/vectors/sync/passkeys/assertion.json, read from the repo (tests fail, never skip, when missing).
enum AssertionVectors {
    static func load() throws -> [[String: Any]] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("tests/vectors/sync/passkeys/assertion.json")
        let list = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [[String: Any]] ?? []
        guard !list.isEmpty else { throw CocoaError(.fileReadCorruptFile) }
        return list
    }
    static func hex(_ s: String) -> [UInt8] {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
        return out
    }
}

/// tests/vectors/sync/license_state.json (TEST-ONLY keys; never verifies with production keys).
enum LicenseFixture {
    static func load() throws -> (keys: [String: [UInt8]], id: String, wrapper: JSONValue) {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("tests/vectors/sync/license_state.json")
        guard case .object(let o) = try CanonicalJSON.parse(Array(try Data(contentsOf: url))),
              case .string(let keyID)? = o["key_id"], case .string(let pub)? = o["public_key_b64"],
              case .string(let stateID)? = o["state_id"], let wrapper = o["wrapper"] else { throw CocoaError(.fileReadCorruptFile) }
        return ([keyID: try Base64.decodeStrict(pub)], stateID, wrapper)
    }
}

final class FakeEntitlement: ProEntitlementChecking, @unchecked Sendable {
    let entitled: Bool
    private(set) var calls = 0
    init(_ e: Bool) { entitled = e }
    func isEntitled() async -> Bool { calls += 1; return entitled }
}

final class RecordingRefresher: PasskeyIdentityRefreshing, @unchecked Sendable {
    private(set) var snapshots: [StoreSnapshot] = []
    var onRefresh: (@MainActor () -> Void)?
    func refresh(_ snapshot: StoreSnapshot) async {
        snapshots.append(snapshot)
        if let onRefresh { await onRefresh() }
    }
}

@MainActor
final class PasskeyFlowTests: XCTestCase {
    func freshSettings() -> AppSettings { AppSettings(defaults: UserDefaults(suiteName: "pk-\(UUID().uuidString)")!) }

    func make(_ snapshot: StoreSnapshot, settings: AppSettings? = nil, entitled: Bool = false,
              licenseKeys: [String: [UInt8]] = [:], identities: RecordingRefresher? = nil,
              entitlement: FakeEntitlement? = nil, committedRevision: Int64? = nil)
        -> (PasskeyFlow, FakeAuth, FakeOpener, RecordingStore) {
        let store = RecordingStore(snapshot), opener = FakeOpener(store, revision: committedRevision), auth = FakeAuth(vault: InMemoryKeychainVault())
        let cf = CredentialFlow(auth: auth, opener: opener, matcher: .bundled(Bundle(for: PasskeyFlowTests.self)),
                                clipboard: FakeClipboard(), clock: FixedClock(1_800_000_000), settings: settings ?? freshSettings())
        let f = PasskeyFlow(credentials: cf, pro: entitlement ?? FakeEntitlement(entitled), licenseKeys: licenseKeys,
                            identities: identities, random: SystemRandomSource(), today: { "2026-10-18" })
        return (f, auth, opener, store)
    }

    func test_assertion_signature_verifies() async throws {
        for v in try AssertionVectors.load() {
            let rp = v["rp_id"] as! String
            var s = Fixture.snapshot()
            s.records["pv"] = Fixture.passkey("pv", rp: rp, user: "u", credID: [7, 7, 7], handle: [1, 2],
                                              key: v["private_key_b64u"] as! String)
            let (f, _, _, _) = make(s)
            let hash = Data(AssertionVectors.hex(v["client_data_hash_hex"] as! String))
            let uv = v["user_verified"] as! Bool
            let a = try await f.assert(recordID: "pv", rpID: rp, clientDataHash: hash, userVerified: uv)
            XCTAssertEqual(Array(a.authenticatorData), AssertionVectors.hex(v["authenticator_data_hex"] as! String), rp)
            let pub = try P256.Signing.PublicKey(rawRepresentation: AssertionVectors.hex(v["public_key_x_hex"] as! String)
                                                 + AssertionVectors.hex(v["public_key_y_hex"] as! String))
            let sig = try P256.Signing.ECDSASignature(derRepresentation: a.signature)
            XCTAssertTrue(pub.isValidSignature(sig, for: a.authenticatorData + hash), rp)
            XCTAssertEqual(a.credentialID, Data([7, 7, 7])); XCTAssertEqual(a.userHandle, Data([1, 2]))
            XCTAssertEqual(a.clientDataHash, hash); XCTAssertEqual(a.rpID, rp)
        }
    }

    func test_assertion_auth_data_flags_and_zero_counter() async throws {
        let (f, _, _, _) = make(Fixture.snapshotWithPasskeys(.generate()))
        let hash = Data(repeating: 3, count: 32)
        let uv = try await f.assert(recordID: "p1", rpID: "example.com", clientDataHash: hash, userVerified: true)
        let ad = Array(uv.authenticatorData)
        XCTAssertEqual(ad.count, 37)
        XCTAssertEqual(Array(ad[0..<32]), Array(SHA256.hash(data: Array("example.com".utf8))))
        XCTAssertEqual(ad[32], 0x01 | 0x04 | 0x08 | 0x10, "UP|UV|BE|BS, no AT")
        XCTAssertEqual(Array(ad[33..<37]), [0, 0, 0, 0])
        let noUV = try await f.assert(recordID: "p1", rpID: "example.com", clientDataHash: hash, userVerified: false)
        XCTAssertEqual(Array(noUV.authenticatorData)[32], 0x01 | 0x08 | 0x10)
    }

    func test_empty_allow_list_offers_all_for_rp() async throws {
        let key = PasskeyKey.generate()
        var s = Fixture.snapshotWithPasskeys(key)
        s.records["p4"] = Fixture.passkey("p4", rp: "example.com", user: "bob", credID: [6], handle: [6], key: key.pkcs8B64URL)
        s.records["p5"] = Fixture.passkey("p5", rp: "other.example", user: "eve", credID: [7], handle: [7], key: key.pkcs8B64URL)
        let (f, _, _, _) = make(s)
        let all = try await f.candidates(rpID: "example.com", allowed: [])
        XCTAssertEqual(all.map(\.itemID), ["p1", "p4"])
        let one = try await f.candidates(rpID: "example.com", allowed: [Data([6])])
        XCTAssertEqual(one.map(\.itemID), ["p4"])
        let none = try await f.candidates(rpID: "example.com", allowed: [Data([42])])
        XCTAssertTrue(none.isEmpty)
    }

    func test_rp_match_is_exact_host_casefolded() async throws {
        let (f, _, _, _) = make(Fixture.snapshotWithPasskeys(.generate()))
        let upper = try await f.candidates(rpID: "Example.com", allowed: [])
        XCTAssertEqual(upper.map(\.itemID), ["p1"])
        let sub = try await f.candidates(rpID: "login.example.com", allowed: [])
        XCTAssertTrue(sub.isEmpty)
        let parent = try await f.candidates(rpID: "com", allowed: [])
        XCTAssertTrue(parent.isEmpty)
        let hash = Data(repeating: 1, count: 32)
        _ = try await f.assert(recordID: "p1", rpID: "EXAMPLE.COM", clientDataHash: hash, userVerified: true)
        do { _ = try await f.assert(recordID: "p1", rpID: "login.example.com", clientDataHash: hash, userVerified: true); XCTFail() }
        catch { XCTAssertEqual(error as? PasskeyFlow.Failure, .notFound) }
    }

    func test_unusable_record_rejected() async throws {
        let (f, _, _, _) = make(Fixture.snapshotWithPasskeys(.generate()))
        let rs = try await f.candidates(rpID: "rs.example", allowed: [])
        let bad = try await f.candidates(rpID: "bad.example", allowed: [])
        XCTAssertTrue(rs.isEmpty); XCTAssertTrue(bad.isEmpty)
        for (id, rp) in [("p2", "rs.example"), ("p3", "bad.example"), ("w1", "example.com"), ("missing", "example.com")] {
            do { _ = try await f.assert(recordID: id, rpID: rp, clientDataHash: Data(count: 32), userVerified: true); XCTFail(id) }
            catch { XCTAssertNotNil(error as? PasskeyFlow.Failure, id) }
        }
        do { _ = try await f.assert(recordID: "p1", rpID: "example.com", clientDataHash: Data(count: 31), userVerified: true); XCTFail() }
        catch { XCTAssertEqual(AutoFillErrorMapping.code(for: error), .failed) }
    }

    func test_tombstoned_passkey_not_offered() async throws {
        var s = Fixture.snapshotWithPasskeys(.generate())
        s.meta["p1"] = SyncMeta(digest: nil, body: nil, updatedAt: 1, vv: [:], deleted: true, deletedAt: 1)
        let (f, _, _, _) = make(s)
        let c = try await f.candidates(rpID: "example.com", allowed: [])
        XCTAssertTrue(c.isEmpty)
        do { _ = try await f.assert(recordID: "p1", rpID: "example.com", clientDataHash: Data(count: 32), userVerified: true); XCTFail() }
        catch { XCTAssertEqual(error as? PasskeyFlow.Failure, .notFound) }
    }

    func test_assertion_never_writes_store() async throws {
        let (f, _, _, store) = make(Fixture.snapshotWithPasskeys(.generate()))
        _ = try await f.candidates(rpID: "example.com", allowed: [])
        _ = try await f.assert(recordID: "p1", rpID: "example.com", clientDataHash: Data(count: 32), userVerified: true)
        XCTAssertEqual(store.commits, 0)
    }

    func test_passkeys_off_refuses_before_auth() async {
        for erase in [false, true] {
            let settings = freshSettings()
            if erase { settings.erasePending = true } else { settings.offerPasskeys = false }
            func check(_ error: Error) {
                if erase { XCTAssertEqual(error as? CredentialFlow.Failure, .erasePending) }
                else { XCTAssertEqual(error as? PasskeyFlow.Failure, .passkeysOff) }
            }
            let (f, auth, opener, _) = make(Fixture.snapshotWithPasskeys(.generate()), settings: settings)
            do { _ = try await f.candidates(rpID: "example.com", allowed: []); XCTFail() } catch { check(error) }
            do { _ = try await f.assert(recordID: "p1", rpID: "example.com", clientDataHash: Data(count: 32), userVerified: true); XCTFail() }
            catch { check(error) }
            XCTAssertEqual(auth.calls, 0, "no Face ID prompt"); XCTAssertEqual(opener.opened, 0)
        }
    }

    func test_candidates_carry_no_key_material() async throws {
        let key = PasskeyKey.generate()
        let (f, auth, _, _) = make(Fixture.snapshotWithPasskeys(key))
        let rows = try await f.candidates(rpID: "example.com", allowed: [])
        XCTAssertEqual(rows, [PasskeyCandidate(itemID: "p1", title: "example.com", rpID: "example.com", userName: "alice",
                                               credentialID: Data([1, 2, 3]))])
        XCTAssertFalse("\(rows)".contains(key.pkcs8B64URL))
        XCTAssertEqual(auth.reasons, [PasskeyFlow.signInReason])
        XCTAssertEqual(PasskeyFlow.signInReason, "Sign in with your passkey")
    }

    // MARK: registration

    static let es256 = [-7]

    func register(_ f: PasskeyFlow, algorithms: [Int] = es256, rpID: String = "Shop.Example",
                  hash: Data = Data(repeating: 5, count: 32)) async throws -> (credentialID: Data, attestationObject: Data) {
        try await f.register(rpID: rpID, rpName: "Shop", userName: "ann@example.com", userDisplayName: "Ann",
                             userHandle: Data([0xAA, 0xBB]), clientDataHash: hash, algorithms: algorithms)
    }

    /// Two live items: room for a new one on the free plan.
    func small() -> StoreSnapshot {
        StoreSnapshot(records: ["w1": Fixture.web("w1", user: "alice", password: "pw", origin: "https://example.com")], revision: 3)
    }

    func newItems(_ before: StoreSnapshot, _ after: StoreSnapshot) -> [(String, JSONValue)] {
        after.records.filter { before.records[$0.key] == nil }.map { ($0.key, $0.value) }
    }

    func test_registration_writes_desktop_shaped_item() async throws {
        let before = small(), ids = RecordingRefresher()
        let (f, auth, _, store) = make(before, identities: ids)
        let r = try await register(f)
        XCTAssertEqual(store.commits, 1)
        let added = newItems(before, store.snapshot)
        XCTAssertEqual(added.count, 1)
        let (id, wrapper) = added[0]
        XCTAssertNil(store.snapshot.meta[id], "no meta: the app's next sync stamps it like any phone-created item")
        guard case .object(let w) = wrapper, w["ns"] == .string("item"), case .object(let rec)? = w["record"],
              case .object(let payload)? = rec["payload"], case .string(let keyText)? = payload["private_key"],
              let key = PasskeyKey(pkcs8B64URL: keyText) else { return XCTFail("\(wrapper)") }
        XCTAssertEqual(rec["kind"], .string("passkey")); XCTAssertEqual(rec["id"], .string(id))
        XCTAssertEqual(rec["updated_at"], .int(1_800_000_000)); XCTAssertEqual(rec["created_at"], .int(1_800_000_000))
        let expected = PasskeyRecord.newPayload(rpID: "Shop.Example", rpName: "Shop", userName: "ann@example.com",
                                                userDisplayName: "Ann", userHandle: [0xAA, 0xBB], credentialID: Array(r.credentialID),
                                                key: key, today: "2026-10-18")
        XCTAssertEqual(rec["title"], .string(expected.title)); XCTAssertEqual(expected.title, "Shop (ann@example.com)")
        XCTAssertEqual(rec["payload"], expected.fields)
        XCTAssertEqual(payload["relying_party_id"], .string("shop.example"))
        XCTAssertEqual(r.credentialID.count, 16)
        let normal = try Normalise.normalForm(ns: .item, record: .object(rec))
        XCTAssertEqual(normal, .object(rec), "stored record is its own normal form")
        XCTAssertEqual(try Normalise.normalForm(ns: .item, record: normal), normal)
        XCTAssertEqual(Wrapper.make(ns: .item, record: normal), wrapper)
        XCTAssertEqual(auth.reasons, [PasskeyFlow.createReason]); XCTAssertEqual(PasskeyFlow.createReason, "Create a passkey")
        // QuickType republished from the committed store, the new passkey included, never the key.
        XCTAssertEqual(ids.snapshots.count, 1)
        XCTAssertEqual(ids.snapshots.first?.records[id], wrapper)
        XCTAssertNil(f.credentials.snapshot, "the pre-commit snapshot is dropped")
        // A fresh sign-in finds it.
        let rows = try await f.candidates(rpID: "shop.example", allowed: [r.credentialID])
        XCTAssertEqual(rows.map(\.itemID), [id])
    }

    func test_registration_attestation_parses() async throws {
        let (f, _, _, store) = make(small())
        let r = try await register(f)
        let att = Array(r.attestationObject)
        // {"fmt": "none", "attStmt": {}, "authData": bytes}
        let head: [UInt8] = [0xA3, 0x63] + Array("fmt".utf8) + [0x64] + Array("none".utf8) + [0x67] + Array("attStmt".utf8)
            + [0xA0, 0x68] + Array("authData".utf8)
        XCTAssertEqual(Array(att.prefix(head.count)), head)
        var i = head.count
        XCTAssertEqual(att[i], 0x58); let len = Int(att[i + 1]); i += 2
        let ad = Array(att[i...]); XCTAssertEqual(ad.count, len)
        XCTAssertEqual(Array(ad[0..<32]), Array(SHA256.hash(data: Array("shop.example".utf8))))
        XCTAssertEqual(ad[32], 0x01 | 0x04 | 0x08 | 0x10 | 0x40, "UP|UV|BE|BS|AT")
        XCTAssertEqual(Array(ad[33..<37]), [0, 0, 0, 0])
        XCTAssertEqual(Array(ad[37..<53]), Passkey.aaguid)
        XCTAssertEqual(Array(ad[53..<55]), [0, 16])
        XCTAssertEqual(Array(ad[55..<71]), Array(r.credentialID))
        let stored = newItems(small(), store.snapshot)[0]
        let key = try XCTUnwrap(PasskeyRecord.from(stored.1, id: stored.0)?.key)
        XCTAssertEqual(Array(ad[71...]), coseES256Key(key.publicKey), "COSE key of the stored private key")
        XCTAssertEqual(PasskeyRecord.from(stored.1, id: stored.0)?.credentialID, Array(r.credentialID))
    }

    func test_registration_requires_es256() async throws {
        let (f, auth, _, store) = make(small())
        do { _ = try await register(f, algorithms: [-257]); XCTFail() }
        catch {
            XCTAssertEqual(error as? PasskeyFlow.Failure, .unsupportedAlgorithm)
            XCTAssertEqual(AutoFillErrorMapping.code(for: error), .failed, "iOS falls back to another provider")
        }
        XCTAssertEqual(store.commits, 0); XCTAssertEqual(auth.calls, 0)
        _ = try await register(f, algorithms: [-257, -7])
        XCTAssertEqual(store.commits, 1)
    }

    func test_registration_blocked_over_limit_writes_nothing() async throws {
        let full = Fixture.snapshotWithPasskeys(.generate())   // 6 live items
        XCTAssertGreaterThanOrEqual(ItemLimit.liveCount(full), ItemLimit.freeItems)
        let ids = RecordingRefresher()
        let (f, _, _, store) = make(full, identities: ids)
        do { _ = try await register(f); XCTFail() }
        catch {
            XCTAssertEqual(error as? PasskeyFlow.Failure, .needsPro)
            XCTAssertEqual(AutoFillErrorMapping.code(for: error), .failed)
        }
        XCTAssertEqual(store.commits, 0); XCTAssertTrue(ids.snapshots.isEmpty)
        // Sign-in still works over the limit.
        _ = try await f.assert(recordID: "p1", rpID: "example.com", clientDataHash: Data(count: 32), userVerified: true)
    }

    func test_registration_allowed_with_pro_or_license() async throws {
        let (f, _, _, store) = make(Fixture.snapshotWithPasskeys(.generate()), entitled: true)
        _ = try await register(f)
        XCTAssertEqual(store.commits, 1)

        let v = try LicenseFixture.load()
        var s = Fixture.snapshotWithPasskeys(.generate()); s.records[v.id] = v.wrapper
        let (g, _, _, licensed) = make(s, licenseKeys: v.keys)
        _ = try await register(g)
        XCTAssertEqual(licensed.commits, 1)

        let (h, _, _, unknownKeys) = make(s, licenseKeys: [:])
        do { _ = try await register(h); XCTFail() } catch { XCTAssertEqual(error as? PasskeyFlow.Failure, .needsPro) }
        XCTAssertEqual(unknownKeys.commits, 0)
    }

    func test_registration_retries_once_on_stale_store() async throws {
        let (f, _, _, store) = make(small())
        var raced = false
        store.beforeCommit = { s in
            guard !raced else { return }
            raced = true; s.revision += 1   // the app committed in between
        }
        _ = try await register(f)
        XCTAssertEqual(store.commits, 1)
    }

    func test_erase_pending_refuses_registration() async {
        let settings = freshSettings(); settings.erasePending = true
        let (f, auth, opener, store) = make(small(), settings: settings)
        do { _ = try await register(f); XCTFail() } catch { XCTAssertEqual(error as? CredentialFlow.Failure, .erasePending) }
        XCTAssertEqual(auth.calls, 0); XCTAssertEqual(opener.opened, 0); XCTAssertEqual(store.commits, 0)
    }

    func test_erase_started_during_face_id_commits_nothing() async {
        let settings = freshSettings()
        let (f, auth, _, store) = make(small(), settings: settings)
        auth.onAuthenticate = { settings.erasePending = true }
        do { _ = try await register(f); XCTFail() } catch { XCTAssertEqual(error as? CredentialFlow.Failure, .erasePending) }
        XCTAssertEqual(auth.calls, 1); XCTAssertEqual(store.commits, 0)
        XCTAssertNil(f.credentials.snapshot, "the decrypted vault is forgotten")
    }

    func test_erase_started_before_the_retry_commits_nothing() async {
        let settings = freshSettings()
        let (f, _, _, store) = make(small(), settings: settings)
        store.beforeCommit = { s in
            guard !settings.erasePending else { return }
            settings.erasePending = true; s.revision += 1   // the app committed and began an erase in between
        }
        do { _ = try await register(f); XCTFail() } catch { XCTAssertEqual(error as? CredentialFlow.Failure, .erasePending) }
        XCTAssertEqual(store.commits, 0)
    }

    func test_passkeys_off_refuses_registration() async {
        let settings = freshSettings(); settings.offerPasskeys = false
        let (f, auth, opener, store) = make(small(), settings: settings)
        do { _ = try await register(f); XCTFail() } catch { XCTAssertEqual(error as? PasskeyFlow.Failure, .passkeysOff) }
        XCTAssertEqual(auth.calls, 0); XCTAssertEqual(opener.opened, 0); XCTAssertEqual(store.commits, 0)
    }

    func test_registration_request_completes_once() async throws {
        let (f, _, _, store) = make(small())
        let d = CredentialRequestDriver(passkeys: f), sink = RecordingSink(); d.sink = sink
        d.beginRegistration(PasskeyRegistrationRequest(rpID: "shop.example", rpName: "Shop", userName: "ann", userDisplayName: "Ann",
                                                       userHandle: Data([1]), clientDataHash: Data(repeating: 2, count: 32),
                                                       algorithms: [-7]))
        await d.task?.value
        XCTAssertEqual(sink.registrations.count, 1)
        XCTAssertEqual(sink.registrations.first?.rpID, "shop.example")
        XCTAssertEqual(sink.registrations.first?.clientDataHash, Data(repeating: 2, count: 32))
        XCTAssertEqual(store.commits, 1); XCTAssertNil(f.credentials.snapshot)
        d.cancel(.userCanceled); XCTAssertTrue(sink.cancels.isEmpty)
    }

    func test_second_create_tap_starts_nothing() async throws {
        let (f, auth, _, store) = make(small())
        let d = CredentialRequestDriver(passkeys: f), sink = RecordingSink(); d.sink = sink
        let request = PasskeyRegistrationRequest(rpID: "shop.example", rpName: "Shop", userName: "ann", userDisplayName: "Ann",
                                                 userHandle: Data([1]), clientDataHash: Data(repeating: 2, count: 32),
                                                 algorithms: [-7])
        d.beginRegistration(request)
        let first = d.task
        d.beginRegistration(request)   // Create tapped again while Face ID is up
        XCTAssertEqual(d.task, first, "the first registration keeps running")
        await first?.value
        await d.task?.value
        XCTAssertEqual(auth.calls, 1, "one Face ID prompt")
        XCTAssertEqual(store.commits, 1, "one passkey, never a duplicate")
        XCTAssertEqual(sink.registrations.count, 1)
    }

    func test_registration_refreshes_identities_from_committed_snapshot() async throws {
        let ids = RecordingRefresher()
        let (f, _, _, store) = make(small(), identities: ids)
        _ = try await register(f)
        XCTAssertEqual(store.loads, 1, "the unlock's load is the commit's base; no reload after the commit")
        XCTAssertEqual(ids.snapshots.first?.records, store.snapshot.records)
        XCTAssertEqual(ids.snapshots.first?.revision, store.snapshot.revision)
    }

    func test_storekit_not_consulted_under_limit() async throws {
        let e = FakeEntitlement(true)
        let (f, _, _, store) = make(small(), entitlement: e)
        _ = try await register(f)
        XCTAssertEqual(store.commits, 1); XCTAssertEqual(e.calls, 0)
        // Over the limit with a synced licence: still no StoreKit.
        let v = try LicenseFixture.load()
        var s = Fixture.snapshotWithPasskeys(.generate()); s.records[v.id] = v.wrapper
        let e2 = FakeEntitlement(false)
        let (g, _, _, licensed) = make(s, licenseKeys: v.keys, entitlement: e2)
        _ = try await register(g)
        XCTAssertEqual(licensed.commits, 1); XCTAssertEqual(e2.calls, 0)
        // Over the limit, no licence: asked exactly once.
        let e3 = FakeEntitlement(true)
        let (h, _, _, entitled) = make(Fixture.snapshotWithPasskeys(.generate()), entitlement: e3)
        _ = try await register(h)
        XCTAssertEqual(entitled.commits, 1); XCTAssertEqual(e3.calls, 1)
    }

    func test_over_limit_hint_refuses_before_face_id() async throws {
        let full = Fixture.snapshotWithPasskeys(.generate())
        let settings = freshSettings(); settings.planFullRevision = 42
        let (f, auth, opener, store) = make(full, settings: settings, committedRevision: 42)
        do { _ = try await register(f); XCTFail() } catch { XCTAssertEqual(error as? PasskeyFlow.Failure, .needsPro) }
        XCTAssertEqual(auth.calls, 0, "no Face ID prompt"); XCTAssertEqual(opener.opened, 0); XCTAssertEqual(store.commits, 0)
        // Entitled through StoreKit: the hint does not block, and StoreKit is not asked again in the loop.
        let e = FakeEntitlement(true)
        let (g, gAuth, _, gStore) = make(full, settings: settings, entitlement: e, committedRevision: 42)
        _ = try await register(g)
        XCTAssertEqual(gAuth.calls, 1); XCTAssertEqual(gStore.commits, 1); XCTAssertEqual(e.calls, 1)
        // A stale hint (the store has moved on since) is ignored; the in-loop check still decides.
        let (h, hAuth, _, hStore) = make(small(), settings: settings, committedRevision: 43)
        _ = try await register(h)
        XCTAssertEqual(hAuth.calls, 1); XCTAssertEqual(hStore.commits, 1)
        // No hint at all: Face ID, then the in-loop refusal.
        let (k, kAuth, _, kStore) = make(full, committedRevision: 42)
        do { _ = try await register(k); XCTFail() } catch { XCTAssertEqual(error as? PasskeyFlow.Failure, .needsPro) }
        XCTAssertEqual(kAuth.calls, 1); XCTAssertEqual(kStore.commits, 0)
    }

    func test_registration_cancel_during_auth_commits_nothing() async {
        let auth = GatedAuth(), store = RecordingStore(small()), opener = FakeOpener(store)
        let cf = CredentialFlow(auth: auth, opener: opener, matcher: .bundled(Bundle(for: PasskeyFlowTests.self)),
                                clipboard: FakeClipboard(), clock: FixedClock(1), settings: freshSettings())
        let d = CredentialRequestDriver(passkeys: PasskeyFlow(credentials: cf)), sink = RecordingSink(); d.sink = sink
        d.beginRegistration(PasskeyRegistrationRequest(rpID: "shop.example", rpName: "Shop", userName: "ann", userDisplayName: "Ann",
                                                       userHandle: Data([1]), clientDataHash: Data(repeating: 2, count: 32),
                                                       algorithms: [-7]))
        for _ in 0..<1000 where auth.calls == 0 { await Task.yield() }
        d.cancel(.userCanceled)
        auth.release()
        await d.task?.value
        XCTAssertEqual(opener.opened, 0); XCTAssertEqual(store.commits, 0)
        XCTAssertTrue(sink.registrations.isEmpty)
        XCTAssertEqual(sink.cancels, [.userCanceled])
    }

    func test_post_commit_cancel_completes_nothing() async throws {
        let ids = RecordingRefresher()
        let (f, _, _, store) = make(small(), identities: ids)
        let d = CredentialRequestDriver(passkeys: f), sink = RecordingSink(); d.sink = sink
        ids.onRefresh = { d.cancel(.userCanceled) }   // after the commit, before the request completes
        d.beginRegistration(PasskeyRegistrationRequest(rpID: "shop.example", rpName: "Shop", userName: "ann", userDisplayName: "Ann",
                                                       userHandle: Data([1]), clientDataHash: Data(repeating: 2, count: 32),
                                                       algorithms: [-7]))
        await d.task?.value
        XCTAssertEqual(store.commits, 1, "committed (accepted: like an abandoned desktop create)")
        XCTAssertTrue(sink.registrations.isEmpty)
        XCTAssertEqual(sink.cancels, [.userCanceled])
        XCTAssertNil(f.credentials.snapshot)
    }

    // MARK: request lifecycle

    func test_passkey_identity_request_completes_once_and_forgets_snapshot() async throws {
        let (f, _, _, _) = make(Fixture.snapshotWithPasskeys(.generate()))
        let d = CredentialRequestDriver(passkeys: f), sink = RecordingSink(); d.sink = sink
        d.beginPasskey(recordID: "p1", rpID: "example.com", clientDataHash: Data(count: 32))
        await d.task?.value
        XCTAssertEqual(sink.assertions.map(\.credentialID), [Data([1, 2, 3])])
        XCTAssertNil(f.credentials.snapshot)
        d.cancel(.userCanceled); XCTAssertTrue(sink.cancels.isEmpty)
    }

    func test_passkey_cancel_during_auth_signs_nothing() async {
        let auth = GatedAuth(), opener = FakeOpener(RecordingStore(Fixture.snapshotWithPasskeys(.generate())))
        let cf = CredentialFlow(auth: auth, opener: opener, matcher: .bundled(Bundle(for: PasskeyFlowTests.self)),
                                clipboard: FakeClipboard(), clock: FixedClock(1), settings: freshSettings())
        let d = CredentialRequestDriver(flow: cf), sink = RecordingSink(); d.sink = sink
        d.beginPasskeyList(rpID: "example.com", allowed: [], clientDataHash: Data(count: 32))
        for _ in 0..<1000 where auth.calls == 0 { await Task.yield() }
        d.cancel(.userCanceled)
        auth.release()
        await d.task?.value
        XCTAssertEqual(opener.opened, 0)
        XCTAssertTrue(sink.passkeyLists.isEmpty); XCTAssertTrue(sink.assertions.isEmpty)
        XCTAssertEqual(sink.cancels, [.userCanceled])
    }

    func test_passkey_list_then_select_signs() async throws {
        let (f, _, _, _) = make(Fixture.snapshotWithPasskeys(.generate()))
        let d = CredentialRequestDriver(passkeys: f), sink = RecordingSink(); d.sink = sink
        d.beginPasskeyList(rpID: "example.com", allowed: [], clientDataHash: Data(count: 32))
        await d.task?.value
        XCTAssertEqual(sink.passkeyLists.map { $0.map(\.itemID) }, [["p1"]])
        d.selectPasskey(sink.passkeyLists[0][0])
        await d.task?.value
        XCTAssertEqual(sink.assertions.count, 1)
        XCTAssertNil(f.credentials.snapshot)
    }
}
