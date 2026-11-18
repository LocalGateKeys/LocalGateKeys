import XCTest
import AuthenticationServices
import AppShared

/// The AutoFill side of the Safari "just filled" marker (`SafariFillMarker`): written for every password fill, for the
/// login's saved origin and the page's origin (when the request names one and it differs), each only when the Safari
/// extension saves for it; never for 2FA codes, passkeys or inserted text, and never during a duress session or hold
/// or while an erase is pending.
@MainActor
final class SafariFillMarkerAutoFillTests: XCTestCase {
    let matcher = AutoFillMatcher.bundled(Bundle(for: SafariFillMarkerAutoFillTests.self))
    let pageIDs = [ASCredentialServiceIdentifier(identifier: "https://example.com/app/login", type: .URL)]

    func make(settings: AppSettings? = nil, snapshot: StoreSnapshot = Fixture.snapshot()) -> (CredentialRequestDriver, RecordingSink, Recorder) {
        let s = settings ?? AppSettings(defaults: UserDefaults(suiteName: "fill-\(UUID().uuidString)")!)
        let flow = CredentialFlow(auth: FakeAuth(vault: InMemoryKeychainVault()), opener: FakeOpener(RecordingStore(snapshot)),
                                  matcher: matcher, clipboard: FakeClipboard(), clock: FixedClock(59), settings: s)
        let recorder = Recorder()
        flow.writeFillMarker = { recorder.calls.append(($0, $1)) }
        flow.duressBlocked = { recorder.duress }
        let d = CredentialRequestDriver(flow: flow), sink = RecordingSink()
        d.sink = sink
        return (d, sink, recorder)
    }

    @MainActor final class Recorder {
        var calls: [([String], String)] = []
        var duress = false
    }

    func pickFromList(_ d: CredentialRequestDriver, _ sink: RecordingSink, ids: [ASCredentialServiceIdentifier],
                      id: String = "w1") async throws {
        d.beginList(urls: AutoFillMatcher.candidateURLs(ids), fillOrigin: CredentialRequestDriver.fillOrigin(ids))
        await d.task?.value
        let row = try XCTUnwrap(sink.lists.first?.first { $0.id == id })
        d.select(row)
    }

    func test_a_password_picked_for_a_web_page_writes_the_marker_after_the_fill() async throws {
        let (d, sink, recorder) = make()
        try await pickFromList(d, sink, ids: pageIDs)
        XCTAssertEqual(sink.completed.map(\.0), ["alice"], "the fill itself is unchanged")
        XCTAssertEqual(recorder.calls.map(\.0), [["https://example.com"]], "saved origin and page origin are the same: once")
        XCTAssertEqual(recorder.calls.map(\.1), ["alice"])
        d.select(Fixture.loginW1)
        XCTAssertEqual(recorder.calls.count, 1, "once per request")
    }

    func test_only_web_origins_the_safari_extension_saves_for() {
        XCTAssertEqual(CredentialRequestDriver.fillOrigin(pageIDs), "https://example.com")
        XCTAssertEqual(CredentialRequestDriver.fillOrigin([ASCredentialServiceIdentifier(identifier: "http://localhost:8080/x", type: .URL)]),
                       "http://localhost:8080")
        // A domain identifier (an app's associated domain, or a QuickType identity) names no page origin.
        XCTAssertNil(CredentialRequestDriver.fillOrigin([ASCredentialServiceIdentifier(identifier: "example.com", type: .domain)]))
        XCTAssertNil(CredentialRequestDriver.fillOrigin([ASCredentialServiceIdentifier(identifier: "http://example.com/login", type: .URL)]))
        XCTAssertNil(CredentialRequestDriver.fillOrigin([]))
        // The first usable page URL.
        XCTAssertEqual(CredentialRequestDriver.fillOrigin([
            ASCredentialServiceIdentifier(identifier: "example.org", type: .domain),
            ASCredentialServiceIdentifier(identifier: "ftp://example.org", type: .URL),
            ASCredentialServiceIdentifier(identifier: "https://Login.Example.org/a", type: .URL),
        ]), "https://login.example.org")
    }

    func test_a_list_pick_on_another_page_writes_both_origins() async throws {
        // w2 is saved for https://unused.example and offered on example.com/app through a starts_with row.
        let (d, sink, recorder) = make()
        try await pickFromList(d, sink, ids: pageIDs, id: "w2")
        XCTAssertEqual(sink.completed.map(\.0), ["bob"])
        XCTAssertEqual(recorder.calls.map(\.0), [["https://unused.example", "https://example.com"]])
        XCTAssertEqual(recorder.calls.map(\.1), ["bob"])
    }

    func test_a_list_for_a_domain_identifier_writes_the_saved_origin_only() async throws {
        let (d, sink, recorder) = make()
        try await pickFromList(d, sink, ids: [ASCredentialServiceIdentifier(identifier: "example.com", type: .domain)])
        XCTAssertEqual(sink.completed.count, 1)
        XCTAssertEqual(recorder.calls.map(\.0), [["https://example.com"]])
    }

    /// QuickType: iOS hands over no page URL, so the login's own saved origin is what the marker names.
    func test_a_quicktype_identity_writes_the_saved_origin() async {
        let (d, sink, recorder) = make()
        d.beginIdentity(recordID: "w1")
        await d.task?.value
        XCTAssertEqual(sink.completed.map(\.0), ["alice"])
        XCTAssertEqual(recorder.calls.map(\.0), [["https://example.com"]])
        XCTAssertEqual(recorder.calls.map(\.1), ["alice"])
    }

    func test_a_login_without_a_web_origin_and_no_page_writes_nothing() async {
        var snapshot = Fixture.snapshot()
        snapshot.records["w9"] = Fixture.web("w9", user: "erin", password: "pw-erin", origin: "http://intranet.example")
        snapshot.records["w8"] = Fixture.web("w8", user: "fay", password: "pw-fay", origin: "")
        for id in ["w9", "w8"] {
            let (d, sink, recorder) = make(snapshot: snapshot)
            d.beginIdentity(recordID: id)
            await d.task?.value
            XCTAssertEqual(sink.completed.count, 1, id)
            XCTAssertTrue(recorder.calls.isEmpty, id)
        }
    }

    func test_logins_carry_their_saved_origin() {
        let all = AutoFillMatcher.logins(Fixture.snapshot()).map(\.login)
        XCTAssertEqual(all.first { $0.id == "w1" }?.origin, "https://example.com")
        XCTAssertEqual(all.first { $0.id == "w2" }?.origin, "https://unused.example")
    }

    func test_a_2fa_code_writes_no_marker() async throws {
        let (d, sink, recorder) = make()
        d.beginCodeList(urls: AutoFillMatcher.candidateURLs(pageIDs))
        await d.task?.value
        d.select(try XCTUnwrap(sink.lists.first?.first))
        XCTAssertEqual(sink.codes.count, 1)
        d.beginOneTimeCode(recordID: "w1")
        await d.task?.value
        XCTAssertTrue(recorder.calls.isEmpty)
    }

    func test_text_insertion_writes_no_marker() async throws {
        let (d, sink, recorder) = make()
        d.beginTextInsertion()
        await d.task?.value
        XCTAssertEqual(sink.textLists.count, 1)
        XCTAssertTrue(recorder.calls.isEmpty)
    }

    func test_a_new_request_forgets_the_page_origin() async throws {
        let (d, sink, recorder) = make()
        d.beginList(urls: AutoFillMatcher.candidateURLs(pageIDs), fillOrigin: CredentialRequestDriver.fillOrigin(pageIDs))
        await d.task?.value
        d.beginIdentity(recordID: "w2")   // superseded by a QuickType request
        await d.task?.value
        XCTAssertEqual(sink.completed.count, 1)
        XCTAssertEqual(recorder.calls.map(\.0), [["https://unused.example"]], "the list's page origin is not reused")
    }

    func test_a_cancelled_request_writes_no_marker() async throws {
        let (d, sink, recorder) = make()
        d.beginList(urls: AutoFillMatcher.candidateURLs(pageIDs), fillOrigin: CredentialRequestDriver.fillOrigin(pageIDs))
        await d.task?.value
        d.cancel(.userCanceled)
        d.select(Fixture.loginW1)
        XCTAssertTrue(sink.completed.isEmpty)
        XCTAssertTrue(recorder.calls.isEmpty)
    }

    func test_no_marker_during_a_duress_session_or_hold() async throws {
        let (d, sink, recorder) = make()
        recorder.duress = true
        try await pickFromList(d, sink, ids: pageIDs)
        XCTAssertEqual(sink.completed.count, 1, "the gate is the marker's only: the fill itself is decided elsewhere")
        XCTAssertTrue(recorder.calls.isEmpty)
    }

    func test_no_marker_while_an_erase_is_pending() async throws {
        let settings = AppSettings(defaults: UserDefaults(suiteName: "fill-\(UUID().uuidString)")!)
        let (d, sink, recorder) = make(settings: settings)
        d.beginList(urls: AutoFillMatcher.candidateURLs(pageIDs), fillOrigin: CredentialRequestDriver.fillOrigin(pageIDs))
        await d.task?.value
        settings.erasePending = true   // the app started an erase while the list was up
        d.select(try XCTUnwrap(sink.lists.first?.first { $0.id == "w1" }))
        XCTAssertTrue(recorder.calls.isEmpty)
        // The flow's own gate, called directly.
        d.flow.recordFill(origins: ["https://example.com"], username: "alice")
        XCTAssertTrue(recorder.calls.isEmpty)
    }
}
