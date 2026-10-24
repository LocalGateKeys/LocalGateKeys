import XCTest
import AuthenticationServices
import LocalAuthentication
import AppShared

/// `LAError.notInteractive` (-1004) as LocalAuthentication reports it: a plain NSError in its domain.
let notInteractive = NSError(domain: LAErrorDomain, code: LAError.Code.notInteractive.rawValue)

/// Auth that throws the queued errors first, one per call, then succeeds.
@MainActor
final class ScriptedAuth: AutoFillAuthenticating {
    let vault = InMemoryKeychainVault()
    var errors: [Error]
    private(set) var calls = 0
    init(_ errors: [Error]) { self.errors = errors }
    func authenticate(reason: String) async throws -> any KeychainVault {
        calls += 1
        if !errors.isEmpty { throw errors.removeFirst() }
        return vault
    }
}

/// The QuickType bug: `prepareInterfaceToProvideCredential` arrives before the extension's view has
/// appeared, and `evaluatePolicy` started then fails at once with -1004 (notInteractive).
@MainActor
final class AppearanceGateTests: XCTestCase {

    // MARK: AppearanceGate

    func test_request_before_appear_fires_only_on_appear() {
        let gate = AppearanceGate()
        var fired = 0
        XCTAssertEqual(gate.requestArrived { fired += 1 }, .queued)
        XCTAssertEqual(fired, 0)
        XCTAssertTrue(gate.didAppear())
        XCTAssertEqual(fired, 1)
        XCTAssertFalse(gate.didAppear(), "fires once")
        XCTAssertEqual(fired, 1)
    }

    func test_appear_before_request_fires_at_once() {
        let gate = AppearanceGate()
        XCTAssertFalse(gate.didAppear())
        XCTAssertTrue(gate.appeared)
        var fired = 0
        XCTAssertEqual(gate.requestArrived { fired += 1 }, .fired)
        XCTAssertEqual(fired, 1)
    }

    func test_cancel_before_appear_never_fires() {
        let gate = AppearanceGate()
        var fired = 0
        gate.requestArrived { fired += 1 }
        XCTAssertTrue(gate.cancel())
        XCTAssertFalse(gate.didAppear())
        XCTAssertEqual(gate.requestArrived { fired += 1 }, .dropped)
        XCTAssertEqual(fired, 0)
    }

    func test_one_request_per_instance() {
        let gate = AppearanceGate()
        gate.didAppear()
        var fired = 0
        XCTAssertEqual(gate.requestArrived { fired += 1 }, .fired)
        XCTAssertEqual(gate.requestArrived { fired += 1 }, .dropped)
        XCTAssertEqual(fired, 1)
    }

    // MARK: driver: gating

    func make(_ auth: any AutoFillAuthenticating) -> (CredentialRequestDriver, RecordingSink) {
        let flow = CredentialFlow(auth: auth, opener: FakeOpener(RecordingStore(Fixture.snapshot())),
                                  matcher: .bundled(Bundle(for: AppearanceGateTests.self)),
                                  clipboard: FakeClipboard(), clock: FixedClock(59),
                                  settings: AppSettings(defaults: UserDefaults(suiteName: "ag-\(UUID().uuidString)")!))
        let d = CredentialRequestDriver(flow: flow), sink = RecordingSink()
        d.sink = sink
        return (d, sink)
    }

    func test_gated_identity_prompts_only_after_appear() async {
        let auth = GatedAuth()
        let (d, sink) = make(auth)
        d.whenAppeared("identity") { d.begin(.password(recordID: "w1")) }
        for _ in 0..<50 { await Task.yield() }
        XCTAssertNil(d.task)
        XCTAssertEqual(auth.calls, 0, "no Face ID before the view appeared")
        d.viewDidAppear()
        for _ in 0..<1000 where auth.calls == 0 { await Task.yield() }
        XCTAssertEqual(auth.calls, 1)
        auth.release()
        await d.task?.value
        XCTAssertEqual(sink.completed.map(\.0), ["alice"])
    }

    func test_gated_request_after_appear_starts_at_once() async {
        let auth = ScriptedAuth([])
        let (d, sink) = make(auth)
        d.viewDidAppear()
        d.whenAppeared("list") { d.beginList(urls: ["https://example.com/"]) }
        XCTAssertNotNil(d.task)
        await d.task?.value
        XCTAssertEqual(auth.calls, 1)
        XCTAssertEqual(sink.lists.count, 1)
    }

    func test_cancel_before_appear_prompts_nothing_and_completes_nothing() async {
        let auth = ScriptedAuth([])
        let (d, sink) = make(auth)
        d.whenAppeared("identity") { d.begin(.password(recordID: "w1")) }
        d.cancel(.userCanceled)
        d.viewDidAppear()
        await d.task?.value
        XCTAssertNil(d.task)
        XCTAssertEqual(auth.calls, 0)
        XCTAssertTrue(sink.completed.isEmpty)
        XCTAssertEqual(sink.cancels, [.userCanceled])
    }

    // MARK: driver: retry once on -1004

    func test_not_interactive_once_then_success_fills_after_retry_delay() async {
        let auth = ScriptedAuth([notInteractive])
        let (d, sink) = make(auth)
        d.retryDelay = .milliseconds(1)
        d.viewDidAppear()
        d.beginIdentity(recordID: "w1")
        await d.task?.value
        XCTAssertEqual(auth.calls, 2)
        XCTAssertEqual(sink.cancels, [])
        XCTAssertEqual(sink.completed.map(\.0), ["alice"])
        XCTAssertEqual(sink.completed.map(\.1), ["pw-alice"])
    }

    func test_not_interactive_before_appear_retries_on_next_appear() async {
        let auth = ScriptedAuth([notInteractive])
        let (d, sink) = make(auth)
        d.retryDelay = .seconds(60)   // must not be used: the view has not appeared yet
        d.beginIdentity(recordID: "w1")
        for _ in 0..<1000 where auth.calls == 0 { await Task.yield() }
        for _ in 0..<50 { await Task.yield() }
        XCTAssertEqual(auth.calls, 1, "waits for the view")
        d.viewDidAppear()
        await d.task?.value
        XCTAssertEqual(auth.calls, 2)
        XCTAssertEqual(sink.completed.map(\.0), ["alice"])
    }

    func test_not_interactive_twice_fails() async {
        let auth = ScriptedAuth([notInteractive, notInteractive])
        let (d, sink) = make(auth)
        d.retryDelay = .milliseconds(1)
        d.viewDidAppear()
        d.beginIdentity(recordID: "w1")
        await d.task?.value
        XCTAssertEqual(auth.calls, 2)
        XCTAssertTrue(sink.completed.isEmpty)
        XCTAssertEqual(sink.cancels, [.failed])
    }

    func test_cancel_while_waiting_for_appear_prompts_nothing() async {
        let auth = ScriptedAuth([notInteractive])
        let (d, sink) = make(auth)
        d.beginIdentity(recordID: "w1")
        for _ in 0..<1000 where auth.calls == 0 { await Task.yield() }
        d.cancel(.userCanceled)
        d.viewDidAppear()
        await d.task?.value
        XCTAssertEqual(auth.calls, 1, "no second prompt after cancel")
        XCTAssertTrue(sink.completed.isEmpty)
        XCTAssertNil(d.flow.snapshot)
        XCTAssertEqual(sink.cancels, [.userCanceled])
    }

    func test_cancel_during_retry_delay_prompts_nothing() async {
        let auth = ScriptedAuth([notInteractive])
        let (d, sink) = make(auth)
        d.retryDelay = .seconds(60)
        d.viewDidAppear()
        d.beginIdentity(recordID: "w1")
        for _ in 0..<1000 where auth.calls == 0 { await Task.yield() }
        d.cancel(.userCanceled)
        await d.task?.value
        XCTAssertEqual(auth.calls, 1)
        XCTAssertTrue(sink.completed.isEmpty)
        XCTAssertEqual(sink.cancels, [.userCanceled])
    }

    func test_passkey_assertion_retries_on_not_interactive() async {
        let key = PasskeyKey.generate()
        let auth = ScriptedAuth([notInteractive])
        let flow = CredentialFlow(auth: auth, opener: FakeOpener(RecordingStore(Fixture.snapshotWithPasskeys(key))),
                                  matcher: .bundled(Bundle(for: AppearanceGateTests.self)),
                                  clipboard: FakeClipboard(), clock: FixedClock(59),
                                  settings: AppSettings(defaults: UserDefaults(suiteName: "ag-\(UUID().uuidString)")!))
        let d = CredentialRequestDriver(flow: flow), sink = RecordingSink()
        d.sink = sink
        d.retryDelay = .milliseconds(1)
        d.viewDidAppear()
        d.begin(.passkey(recordID: "p1", rpID: "example.com", clientDataHash: Data(repeating: 7, count: 32)))
        await d.task?.value
        XCTAssertEqual(auth.calls, 2)
        XCTAssertEqual(sink.cancels, [])
        XCTAssertEqual(sink.assertions.count, 1)
    }

    // MARK: error mapping

    func test_not_interactive_is_retryable_never_user_canceled() {
        XCTAssertTrue(AutoFillErrorMapping.isRetryable(notInteractive))
        XCTAssertTrue(AutoFillErrorMapping.isRetryable(LAError(.notInteractive)))
        XCTAssertNotEqual(AutoFillErrorMapping.code(for: notInteractive), .userCanceled)
        XCTAssertEqual(AutoFillErrorMapping.code(for: notInteractive), .failed, "after the one retry")
        for e: Error in [LAError(.userCancel), LAError(.authenticationFailed), LAErrorStub.cancelled] {
            XCTAssertFalse(AutoFillErrorMapping.isRetryable(e), "\(e)")
        }
    }
}
