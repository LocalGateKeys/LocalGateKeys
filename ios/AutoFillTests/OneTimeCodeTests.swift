import XCTest
import AuthenticationServices
import AppShared

/// iPhone "Set Up Codes In" (plan 2026-11-15): the extension lists and fills 2FA codes (iOS 18+ one-time-code
/// requests) with the same unlock, travel mode and access rules as passwords, and the app publishes a one-time-code
/// identity for every login with a 2FA secret.
@MainActor
final class OneTimeCodeTests: XCTestCase {
    let matcher = AutoFillMatcher.bundled(Bundle(for: OneTimeCodeTests.self))
    /// RFC 6238 SHA1 test secret at t = 59, 8 digits (Fixture.rfcTOTP on w1).
    let rfcCode = "94287082"

    var page: [String] {
        AutoFillMatcher.candidateURLs([ASCredentialServiceIdentifier(identifier: "https://example.com/app/login", type: .URL)])
    }

    func settings() -> AppSettings { AppSettings(defaults: UserDefaults(suiteName: "otc-\(UUID().uuidString)")!) }

    func make(_ snapshot: StoreSnapshot = Fixture.snapshot(), travel: TravelMode = .off, copyCode: Bool = true)
        -> (CredentialRequestDriver, RecordingSink, FakeClipboard) {
        let s = settings(); s.copyCodeOnFill = copyCode
        let clip = FakeClipboard()
        let flow = CredentialFlow(auth: FakeAuth(vault: InMemoryKeychainVault()), opener: FakeOpener(RecordingStore(snapshot)),
                                  matcher: matcher, clipboard: clip, clock: FixedClock(59), settings: s)
        flow.travel = { _ in travel }
        let d = CredentialRequestDriver(flow: flow), sink = RecordingSink()
        d.sink = sink
        return (d, sink, clip)
    }

    /// The fixture with w1 (the TOTP login) tagged "Trip".
    func tripSnapshot() -> StoreSnapshot {
        var s = Fixture.snapshot()
        if case .object(var w)? = s.records["w1"], case .object(var r)? = w["record"] {
            r["tags"] = .array([.string("Trip")]); w["record"] = .object(r); s.records["w1"] = .object(w)
        }
        return s
    }

    func test_code_list_offers_only_logins_with_a_2fa_secret() async {
        let (d, sink, _) = make()
        d.beginCodeList(urls: page)
        await d.task?.value
        XCTAssertEqual(sink.lists.map { $0.map(\.id) }, [["w1"]], "w2 matches the page but has no 2FA secret")
        XCTAssertTrue(d.listsCodes)
    }

    func test_picking_a_code_row_fills_the_code_never_the_password_and_copies_nothing() async throws {
        let (d, sink, clip) = make(copyCode: true)
        d.beginCodeList(urls: page)
        await d.task?.value
        let row = try XCTUnwrap(sink.lists.first?.first)
        d.select(row)
        XCTAssertEqual(sink.codes, [rfcCode])
        XCTAssertTrue(sink.completed.isEmpty, "no password leaves the extension")
        XCTAssertTrue(clip.copied.isEmpty, "a code request never copies the code")
        XCTAssertNil(d.flow.snapshot, "the vault is forgotten after the fill")
        d.select(row)
        XCTAssertEqual(sink.codes.count, 1, "finished exactly once")
    }

    func test_code_identity_fills_its_login_code() async {
        let (d, sink, _) = make()
        d.begin(.oneTimeCode(recordID: "w1"))
        await d.task?.value
        XCTAssertEqual(sink.codes, [rfcCode])
        XCTAssertEqual(sink.cancels, [])
    }

    func test_code_identity_of_a_login_without_a_secret_is_not_found() async {
        let (d, sink, _) = make()
        d.begin(.oneTimeCode(recordID: "w2"))
        await d.task?.value
        XCTAssertEqual(sink.codes, [])
        XCTAssertEqual(sink.cancels, [.credentialIdentityNotFound])
    }

    func test_travel_mode_hides_codes_from_the_list_and_the_identity() async {
        let (d, sink, _) = make(tripSnapshot(), travel: TravelMode(on: true, tags: ["trip"]))
        d.beginCodeList(urls: page)
        await d.task?.value
        XCTAssertEqual(sink.lists.map { $0.map(\.id) }, [[]])
        let (d2, sink2, _) = make(tripSnapshot(), travel: TravelMode(on: true, tags: ["trip"]))
        d2.begin(.oneTimeCode(recordID: "w1"))
        await d2.task?.value
        XCTAssertEqual(sink2.codes, [])
        XCTAssertEqual(sink2.cancels, [.credentialIdentityNotFound])
    }

    func test_never_fill_login_gives_no_code() async {
        var s = Fixture.snapshot()
        if case .object(var w)? = s.records["w1"], case .object(var r)? = w["record"] {
            r["policy"] = .object(["fill": .string("never")]); w["record"] = .object(r); s.records["w1"] = .object(w)
        }
        let (d, sink, _) = make(s)
        d.begin(.oneTimeCode(recordID: "w1"))
        await d.task?.value
        XCTAssertEqual(sink.codes, [])
        XCTAssertEqual(sink.cancels, [.credentialIdentityNotFound])
    }

    func test_a_password_list_still_fills_passwords() async throws {
        let (d, sink, _) = make()
        d.beginList(urls: page)
        await d.task?.value
        XCTAssertFalse(d.listsCodes)
        let row = try XCTUnwrap(sink.lists.first?.first { $0.id == "w1" })
        d.select(row)
        XCTAssertEqual(sink.completed.map(\.0), ["alice"])
        XCTAssertEqual(sink.codes, [])
    }

    // MARK: publishing

    func publisher(_ store: FakeIdentityStore) -> IdentityStoreSync {
        let s = settings(); s.quickTypeExactSites = true
        return IdentityStoreSync(identityStore: store, matcher: matcher.matcher, settings: s, oneTimeCodes: true)
    }

    func codeIDs(_ entries: [IdentityEntry]) -> [String] {
        entries.compactMap { if case .oneTimeCode(_, _, let id) = $0 { id } else { nil } }
    }

    func test_iphone_publishes_a_code_identity_for_each_login_with_a_secret() async {
        let ids = FakeIdentityStore(enabled: true)
        await publisher(ids).refresh(Fixture.snapshot())
        let published = ids.replaced.last ?? []
        XCTAssertEqual(Set(codeIDs(published)), ["w1"])
        XCTAssertTrue(published.contains(.oneTimeCode(domain: "example.com", label: "L-w1", recordID: "w1")))
    }

    func test_removed_secret_removes_the_code_identity() async {
        let ids = FakeIdentityStore(enabled: true)
        var s = Fixture.snapshot()
        await publisher(ids).refresh(s)
        if case .object(var w)? = s.records["w1"], case .object(var r)? = w["record"] {
            r["totp"] = nil; w["record"] = .object(r); s.records["w1"] = .object(w)
        }
        await publisher(ids).refresh(s)
        XCTAssertEqual(codeIDs(ids.replaced.last ?? []), [])
    }

    func test_refresh_also_omitting_hides_codes_and_passwords() async {
        let ids = FakeIdentityStore(enabled: true)
        await publisher(ids).refresh(Fixture.snapshot(), alsoOmitting: ["w1"])
        XCTAssertFalse((ids.replaced.last ?? []).contains { $0.recordID == "w1" })
        XCTAssertFalse((ids.replaced.last ?? []).isEmpty, "the other logins are still published")
    }

    func test_platform_flag_matches_the_running_system() {
        if #available(iOS 18.0, *) { XCTAssertTrue(IdentityStoreSync.platformOneTimeCodes) }
        else { XCTAssertFalse(IdentityStoreSync.platformOneTimeCodes) }
    }
}
