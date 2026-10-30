import XCTest
import AppShared
@testable import LocalGateKeys

@MainActor
final class VaultImporterTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    func importer(_ store: any ItemStore, pro: Bool = true) -> VaultImporter {
        VaultImporter(store: store, isPro: { pro }, now: { [now] in now }, random: SystemRandomSource())
    }

    func login(_ host: String, _ user: String = "ada", _ password: String = "pw", otp: String? = nil) -> ImportCandidate {
        ImportCandidate(title: host, kind: .login(LoginFields(url: "https://\(host)/login", username: user, password: password,
                                                              notes: "", otpauth: otp)))
    }

    func passkey(_ rp: String = "example.com", id: UInt8 = 7) -> ImportCandidate {
        let der = Data(decodeBase64URL(PasskeyKey.generate().pkcs8B64URL, maxBytes: 1024)!)
        return ImportCandidate(title: rp, kind: .passkey(PasskeyFields(rpID: rp, userName: "ada", userDisplayName: "Ada",
                                                                      userHandle: Data([1, 2, 3]),
                                                                      credentialID: Data(repeating: id, count: 16), pkcs8: der)))
    }

    func records(_ store: MemoryStore, ns: Namespace) -> [[String: JSONValue]] {
        store.snapshot.records.values.compactMap { w -> [String: JSONValue]? in
            guard case .object(let o) = w, o["ns"] == .string(ns.rawValue) else { return nil }
            return o["record"]?.objectValue
        }
    }

    func testAddsLoginsAndPasskeys() throws {
        let store = MemoryStore()
        let r = try importer(store).importCandidates([login("a.com"), login("b.com"), passkey()], unsupported: 0)
        XCTAssertEqual(r.added, 3)
        XCTAssertEqual(store.commits, 1)
        XCTAssertEqual(records(store, ns: .entry).count, 2)
        let pk = records(store, ns: .item)
        XCTAssertEqual(pk.count, 1)
        XCTAssertEqual(pk[0]["kind"], .string("passkey"))
        XCTAssertEqual(pk[0]["payload"]?.objectValue?["relying_party_id"], .string("example.com"))
    }

    func testSecondImportChangesNothing() throws {
        let store = MemoryStore()
        let batch = [login("a.com"), login("b.com"), passkey(), login("a.com")]
        _ = try importer(store).importCandidates(batch, unsupported: 0)
        XCTAssertEqual(records(store, ns: .entry).count, 2)   // in-batch duplicate deduped
        let r = try importer(store).importCandidates(batch, unsupported: 0)
        XCTAssertEqual(r.unchanged, batch.count)
        XCTAssertEqual(r.added + r.updated, 0)
        XCTAssertEqual(store.commits, 1)
    }

    func testChangedPasswordUpdatesWithHistory() throws {
        let store = MemoryStore()
        _ = try importer(store).importCandidates([login("a.com", "ada", "old")], unsupported: 0)
        let r = try importer(store).importCandidates([login("a.com", "ada", "new")], unsupported: 0)
        XCTAssertEqual(r.updated, 1)
        let rec = records(store, ns: .entry)
        XCTAssertEqual(rec.count, 1)
        XCTAssertEqual(rec[0]["password"], .string("new"))
        XCTAssertEqual(rec[0]["password_history"]?.arrayValue?.first?.objectValue?["password"], .string("old"))
    }

    func testFreeLimit() throws {
        let store = MemoryStore()
        _ = try importer(store).importCandidates([login("x.com"), login("y.com"), login("z.com")], unsupported: 0)
        let batch = (0..<50).map { login("site\($0).com") }
        let r = try importer(store, pro: false).importCandidates(batch, unsupported: 0)
        XCTAssertEqual(r.added, 1)
        XCTAssertEqual(r.needsPro, 49)
    }

    func testPasskeyDuplicateSkipped() throws {
        let store = MemoryStore()
        _ = try importer(store).importCandidates([passkey()], unsupported: 0)
        let before = records(store, ns: .item)
        let r = try importer(store).importCandidates([passkey()], unsupported: 0)
        XCTAssertEqual(r.unchanged, 1)
        XCTAssertEqual(records(store, ns: .item), before)
    }

    func testTotpStoredOnLogin() throws {
        let store = MemoryStore()
        let uri = "otpauth://totp/A:ada?secret=JBSWY3DPEHPK3PXP&issuer=A&digits=8"
        let r = try importer(store).importCandidates([login("a.com", otp: uri), login("b.com", otp: "otpauth://bogus")], unsupported: 0)
        XCTAssertEqual(r.added, 2)
        XCTAssertEqual(r.unsupported, 1)
        let a = records(store, ns: .entry).first { $0["scope"]?.objectValue?["origin"] == .string("https://a.com") }!
        XCTAssertEqual(a["totp"]?.objectValue?["secret"], .string("JBSWY3DPEHPK3PXP"))
        XCTAssertEqual(a["totp"]?.objectValue?["digits"], .int(8))
        let b = records(store, ns: .entry).first { $0["scope"]?.objectValue?["origin"] == .string("https://b.com") }!
        XCTAssertNil(b["totp"])
    }

    func testTotpAddedToLoginWithSamePassword() throws {
        let store = MemoryStore()
        _ = try importer(store).importCandidates([login("a.com")], unsupported: 0)
        let uri = "otpauth://totp/A:ada?secret=JBSWY3DPEHPK3PXP&issuer=A"
        let r = try importer(store).importCandidates([login("a.com", otp: uri)], unsupported: 0)
        XCTAssertEqual(r.updated, 1)
        XCTAssertEqual(records(store, ns: .entry)[0]["totp"]?.objectValue?["secret"], .string("JBSWY3DPEHPK3PXP"))
        XCTAssertNil(records(store, ns: .entry)[0]["password_history"]?.arrayValue?.first)
        XCTAssertEqual(try importer(store).importCandidates([login("a.com", otp: uri)], unsupported: 0).unchanged, 1)
    }

    func testDuplicateInBatchFirstWinsAndReimportChangesNothing() throws {
        let store = MemoryStore()
        let batch = [login("a.com", "ada", "A"), login("a.com", "ada", "B")]
        let first = try importer(store).importCandidates(batch, unsupported: 0)
        XCTAssertEqual(first.added, 1); XCTAssertEqual(first.unchanged, 1)
        let before = store.snapshot.records
        let second = try importer(store).importCandidates(batch, unsupported: 0)
        XCTAssertEqual(second.unchanged, 2)
        XCTAssertEqual(store.commits, 1)
        XCTAssertEqual(store.snapshot.records, before)
        XCTAssertEqual(records(store, ns: .entry)[0]["password"], .string("A"))
    }

    func testAfterCommitRunsOnlyWhenTheVaultChanged() throws {
        let store = MemoryStore()
        var calls = 0
        let make = { VaultImporter(store: store, isPro: { true }, now: { [now = self.now] in now }, random: SystemRandomSource(),
                                   afterCommit: { calls += 1 }) }
        _ = try make().importCandidates([login("a.com")], unsupported: 0)
        XCTAssertEqual(calls, 1)
        _ = try make().importCandidates([login("a.com")], unsupported: 0)
        XCTAssertEqual(calls, 1)
    }

    func testNoticeCopy() {
        XCTAssertEqual(ImportResult(added: 12, updated: 3, unchanged: 2, needsPro: 5, unsupported: 1).notice,
                       "12 added · 3 updated · 2 already saved · 5 waiting: upgrade to Pro, then import again · 1 not supported")
        XCTAssertEqual(ImportResult(added: 1, updated: 0, unchanged: 0, needsPro: 0, unsupported: 0).notice, "1 added")
    }
}
