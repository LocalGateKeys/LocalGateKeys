import XCTest
import AuthenticationServices
import AppShared

/// Desktop-shaped web entries: the `output` of every accepted web case in
/// tests/vectors/sync/normalise/entries.json (what a synced desktop login looks like in the store), wrapped and
/// keyed by its item id as `SyncMeta` stores it. Tests fail, never skip, when the file is missing.
enum DesktopEntries {
    static func load() throws -> [(name: String, id: String, record: [String: JSONValue])] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("tests/vectors/sync/normalise/entries.json")
        guard case .object(let root) = try CanonicalJSON.parse(Array(try Data(contentsOf: url))),
              case .array(let cases)? = root["cases"] else { throw CocoaError(.fileReadCorruptFile) }
        let out: [(String, String, [String: JSONValue])] = cases.compactMap { c in
            guard case .object(let o) = c, o["error"] == .null, o["ns"] == .string("entry"),
                  case .string(let name)? = o["name"], case .object(let r)? = o["output"],
                  r["kind"] == .string("web"), case .string(let id)? = r["id"] else { return nil }
            return (name, id, r)
        }
        guard !out.isEmpty else { throw CocoaError(.fileReadCorruptFile) }
        return out
    }

    static func snapshot(id: String, record: [String: JSONValue]) -> StoreSnapshot {
        StoreSnapshot(records: [id: Wrapper.make(ns: .entry, record: .object(record))], meta: [:], revision: 1)
    }
}

@MainActor
final class RequestEntryTests: XCTestCase {
    let matcher = AutoFillMatcher.bundled(Bundle(for: RequestEntryTests.self))

    func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "<not text>" }

    func driver(_ snapshot: StoreSnapshot) -> (CredentialRequestDriver, RecordingSink, FakeAuth) {
        let auth = FakeAuth(vault: InMemoryKeychainVault())
        let settings = AppSettings(defaults: UserDefaults(suiteName: "re-\(UUID().uuidString)")!)
        let flow = CredentialFlow(auth: auth, opener: FakeOpener(RecordingStore(snapshot)), matcher: matcher,
                                  clipboard: FakeClipboard(), clock: FixedClock(59), settings: settings)
        let d = CredentialRequestDriver(flow: flow), sink = RecordingSink()
        d.sink = sink
        return (d, sink, auth)
    }

    // MARK: Bug 1 — the entry points run on whatever thread AutoFill delivers them on

    /// The no-UI `provideCredentialWithoutUserInteraction` (and any other entry point) can arrive on a
    /// background queue. A Swift 6 main-actor override traps there in its @objc thunk (`_checkExpectedExecutor`)
    /// before its body runs: nothing fills and no Face ID prompt. The entry hop must run the work on main.
    nonisolated func test_entry_from_a_background_thread_runs_on_main() {
        let done = expectation(description: "ran")
        DispatchQueue.global().async {
            MainThreadEntry.run {
                XCTAssertTrue(Thread.isMainThread)
                MainActor.assertIsolated()
                done.fulfill()
            }
        }
        wait(for: [done], timeout: 5)
    }

    /// On the main thread the work runs before `run` returns (ordering with the next system call kept).
    func test_entry_on_main_runs_synchronously() {
        var ran = false
        MainThreadEntry.run { ran = true }
        XCTAssertTrue(ran)
    }

    /// The request is read into a Sendable route before the hop (`ASCredentialRequest` is not Sendable).
    func test_route_of_password_passkey_and_identityless_requests() {
        let pw = ASPasswordCredentialRequest(credentialIdentity: ASPasswordCredentialIdentity(
            serviceIdentifier: ASCredentialServiceIdentifier(identifier: "example.com", type: .domain),
            user: "norm.user", recordIdentifier: "88888888-aaaa-4000-8000-000000000008"))
        XCTAssertEqual(CredentialRequestRoute.of(pw), .password(recordID: "88888888-aaaa-4000-8000-000000000008"))

        let none = ASPasswordCredentialRequest(credentialIdentity: ASPasswordCredentialIdentity(
            serviceIdentifier: ASCredentialServiceIdentifier(identifier: "example.com", type: .domain),
            user: "norm.user", recordIdentifier: nil))
        XCTAssertEqual(CredentialRequestRoute.of(none), .identityNotFound)

        let pkIdentity = ASPasskeyCredentialIdentity(relyingPartyIdentifier: "example.com", userName: "alice",
                                                     credentialID: Data([1, 2, 3]), userHandle: Data([9]), recordIdentifier: "p1")
        let pk = ASPasskeyCredentialRequest(credentialIdentity: pkIdentity, clientDataHash: Data([7, 7]),
                                            userVerificationPreference: .required, supportedAlgorithms: [.ES256])
        XCTAssertEqual(CredentialRequestRoute.of(pk), .passkey(recordID: "p1", rpID: "example.com", clientDataHash: Data([7, 7])))
    }

    /// QuickType end to end with real desktop records: the identity the app publishes (recordIdentifier = the
    /// store's item id) comes back in an `ASPasswordCredentialRequest` and fills that login's user and password.
    func test_published_identity_round_trips_to_a_fill_for_desktop_records() async throws {
        let base = try await roundTripFills(exactSites: false)
        XCTAssertGreaterThan(base, 0, "base_domain desktop vectors publish an identity (exact-origin and host rows do not)")
        let all = try await roundTripFills(exactSites: true)
        XCTAssertGreaterThan(all, 10, "with \"Include exact-site logins\" on, most desktop vectors publish an identity")
        XCTAssertGreaterThan(all, base)
    }

    /// Publishes each desktop vector's identities with "Include exact-site logins" set as given, fills each
    /// one through the QuickType path, and returns how many filled.
    func roundTripFills(exactSites: Bool) async throws -> Int {
        let settings = AppSettings(defaults: UserDefaults(suiteName: "re-\(UUID().uuidString)")!)
        settings.quickTypeExactSites = exactSites
        var filled = 0
        for e in try DesktopEntries.load() {
            let snap = DesktopEntries.snapshot(id: e.id, record: e.record)
            // http, non-default ports and starts_with rows publish no identity (list path only); exact_origin
            // and host rows only with the switch on.
            let identities = IdentityStoreSync(identityStore: FakeIdentityStore(enabled: true), matcher: matcher.matcher,
                                               settings: settings).identities(snap)
            for entry in identities {
                let system = try XCTUnwrap(entry.systemIdentity as? ASPasswordCredentialIdentity, e.name)
                XCTAssertEqual(system.recordIdentifier, e.id, e.name)
                let (d, sink, auth) = driver(snap)
                d.begin(CredentialRequestRoute.of(ASPasswordCredentialRequest(credentialIdentity: system)))
                await d.task?.value
                XCTAssertEqual(auth.calls, 1, e.name)
                XCTAssertEqual(sink.cancels, [], e.name)
                XCTAssertEqual(sink.completed.map(\.0), [str(e.record["username"])], e.name)
                XCTAssertEqual(sink.completed.map(\.1), [str(e.record["password"])], e.name)
                filled += 1
            }
        }
        return filled
    }

    /// An identity with no record id finishes at once (no task, no Face ID), as before.
    func test_identityless_route_finishes_without_prompt() async {
        let (d, sink, auth) = driver(StoreSnapshot(records: [:], meta: [:], revision: 1))
        d.begin(.identityNotFound)
        XCTAssertNil(d.task)
        XCTAssertEqual(auth.calls, 0)
        XCTAssertEqual(sink.cancels, [.credentialIdentityNotFound])
    }

    // MARK: Bug 2 — the list path hands back the username of a desktop record

    func test_list_pick_fills_username_and_password_for_desktop_records() async throws {
        for e in try DesktopEntries.load() {
            guard case .object(let scope)? = e.record["scope"], case .string(let origin)? = scope["origin"] else {
                return XCTFail(e.name)
            }
            // With `scope.urls` rows the rows decide (desktop rules); the first row's URL is a matching page.
            var page = origin + "/login"
            if case .array(let rows)? = scope["urls"], case .object(let row)? = rows.first, case .string(let u)? = row["url"] {
                page = u
            }
            let (d, sink, _) = driver(DesktopEntries.snapshot(id: e.id, record: e.record))
            d.beginList(urls: [page])
            await d.task?.value
            let row = try XCTUnwrap(sink.lists.first?.first, e.name)
            XCTAssertFalse(row.username.isEmpty, "\(e.name): the vector has a username")
            d.select(row)
            XCTAssertEqual(sink.completed.map(\.0), [str(e.record["username"])], e.name)
            XCTAssertEqual(sink.completed.map(\.1), [str(e.record["password"])], e.name)
        }
    }
}
