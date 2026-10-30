import XCTest
@testable import LGKCore

final class FakeTransport: BreachTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var _requests: [(URL, [String: String])] = []
    let response: @Sendable (URL) throws -> Data
    init(_ response: @escaping @Sendable (URL) throws -> Data) { self.response = response }
    var requests: [(URL, [String: String])] { lock.lock(); defer { lock.unlock() }; return _requests }
    func get(_ url: URL, headers: [String: String]) async throws -> Data {
        lock.withLock { _requests.append((url, headers)) }
        return try response(url)
    }
}

final class BreachCheckTests: XCTestCase {
    // SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
    let body = Data("""
    0018A45C4D1DEF81644B54AB7F969B88D65:1\r
    1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r
    011053FD0102E94D6AE2F8B83D76FAF94F6:0
    """.utf8)

    func checker(_ t: FakeTransport, offline: Bool = false, enabled: Bool = true) -> BreachChecker {
        BreachChecker(transport: t, appVersion: "1.2.3", strictOffline: { offline }, enabled: { enabled },
                      pause: .zero)
    }

    func testPrefixAndHeaders() async throws {
        let t = FakeTransport { [body] _ in body }
        _ = try await checker(t).check("password")
        XCTAssertEqual(t.requests.count, 1)
        XCTAssertEqual(t.requests[0].0.absoluteString, "https://api.pwnedpasswords.com/range/5BAA6")
        XCTAssertEqual(t.requests[0].1, ["Add-Padding": "true", "User-Agent": "LocalGateKeys/1.2.3"])
    }

    func testCountFromSuffix() async throws {
        let t = FakeTransport { [body] _ in body }
        let count = try await checker(t).check("password")
        XCTAssertEqual(count, 9_545_824)
        let other = try await checker(t).check("not-in-list-xyz")
        XCTAssertEqual(other, 0)
    }

    func testStrictOfflineSendsNothing() async {
        let t = FakeTransport { [body] _ in body }
        do { _ = try await checker(t, offline: true).check("password"); XCTFail() } catch {
            XCTAssertEqual(error as? BreachCheckError, .strictOffline)
            XCTAssertEqual(error.localizedDescription,
                "Strict offline mode is on. Turn it off in Privacy settings to run an explicit external check.")
        }
        let r = await checker(t, offline: true).scan([HealthLogin(id: "a", title: "", password: "p", hasTOTP: false, updatedAt: Date())]) { _, _ in }
        XCTAssertTrue(r.cancelled)
        XCTAssertTrue(t.requests.isEmpty)
    }

    func testDisabledSendsNothing() async {
        let t = FakeTransport { [body] _ in body }
        do { _ = try await checker(t, enabled: false).check("password"); XCTFail() } catch {
            XCTAssertEqual(error as? BreachCheckError, .disabled)
            XCTAssertEqual(error.localizedDescription,
                "Breach checks are off. Turning them on lets a check button send a 5-character hash prefix to HIBP. Nothing is checked automatically.")
        }
        XCTAssertTrue(t.requests.isEmpty)
    }

    func testInvalidResponseIsError() async {
        for bad in [Data(), Data("<html>hello</html>".utf8), Data([0xFF, 0xFE])] {
            let t = FakeTransport { _ in bad }
            do { _ = try await checker(t).check("password"); XCTFail() } catch {
                XCTAssertEqual(error as? BreachCheckError, .failed)
                XCTAssertEqual(error.localizedDescription, "Breach check could not complete; no result is available.")
            }
        }
        let failing = FakeTransport { _ in throw URLError(.notConnectedToInternet) }
        do { _ = try await checker(failing).check("password"); XCTFail() } catch {
            XCTAssertEqual(error as? BreachCheckError, .failed)
        }
    }

    func testOversizeResponseIsError() async {
        var big = body
        big.append(Data(repeating: 0x41, count: 200_001))
        let t = FakeTransport { [big] _ in big }
        do { _ = try await checker(t).check("password"); XCTFail() } catch {
            XCTAssertEqual(error as? BreachCheckError, .failed)
        }
    }

    func testDuplicatesRequestedOnce() async {
        let t = FakeTransport { [body] _ in body }
        let d = Date()
        let logins = [HealthLogin(id: "a", title: "", password: "password", hasTOTP: false, updatedAt: d),
                      HealthLogin(id: "b", title: "", password: "password", hasTOTP: false, updatedAt: d),
                      HealthLogin(id: "c", title: "", password: "other", hasTOTP: false, updatedAt: d),
                      HealthLogin(id: "e", title: "", password: "", hasTOTP: false, updatedAt: d)]
        let r = await checker(t).scan(logins) { _, _ in }
        XCTAssertEqual(t.requests.count, 2)
        XCTAssertEqual(r.breached, ["a", "b"])
        XCTAssertEqual(r.counts["c"], 0)
        XCTAssertFalse(r.cancelled)
    }
}

final class CancellingTransport: BreachTransport, @unchecked Sendable {
    func get(_ url: URL, headers: [String: String]) async throws -> Data {
        withUnsafeCurrentTask { $0?.cancel() }
        throw URLError(.cancelled)
    }
}

final class BreachScanCancelTests: XCTestCase {
    func testCancelledMidRequestIsNotFailed() async {
        let c = BreachChecker(transport: CancellingTransport(), appVersion: "1", strictOffline: { false },
                              enabled: { true }, pause: .zero)
        let logins = [HealthLogin(id: "a", title: "", password: "p", hasTOTP: false, updatedAt: nil),
                      HealthLogin(id: "b", title: "", password: "q", hasTOTP: false, updatedAt: nil)]
        let r = await Task { await c.scan(logins) { _, _ in } }.value
        XCTAssertTrue(r.cancelled)
        XCTAssertTrue(r.failed.isEmpty)
        XCTAssertTrue(r.counts.isEmpty)
    }
}

final class StubProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var handler: ((URLRequest) -> (status: Int, headers: [String: String], body: Data))?
    nonisolated(unsafe) static var seen: [URL] = []
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.seen.append(request.url!)
        let (status, headers, body) = Self.handler!(request)
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1",
                                       headerFields: headers)!
        if (300..<400).contains(status), let loc = headers["Location"], let target = URL(string: loc) {
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self)
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class URLSessionTransportTests: XCTestCase {
    let url = URL(string: "https://api.pwnedpasswords.com/range/5BAA6")!

    func transport() -> URLSessionBreachTransport {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubProtocol.self]
        return URLSessionBreachTransport(configuration: config)
    }

    func run(_ status: Int, _ headers: [String: String] = [:], _ body: Data) async -> Result<Data, Error> {
        StubProtocol.seen = []
        StubProtocol.handler = { _ in (status, headers, body) }
        do { return .success(try await transport().get(url, headers: ["Add-Padding": "true"])) }
        catch { return .failure(error) }
    }

    func testStubbedResponses() async {
        let ok = Data("1E4C9B93F3F0682250B6CF8331B7EE68FD8:1\r\n".utf8)
        guard case .success(let data) = await run(200, [:], ok) else { return XCTFail("200 failed") }
        XCTAssertEqual(data, ok)

        guard case .failure = await run(302, ["Location": "https://evil.example/x"], Data()) else {
            return XCTFail("redirect followed")
        }
        XCTAssertEqual(StubProtocol.seen, [url])

        guard case .failure = await run(503, [:], ok) else { return XCTFail("503 accepted") }
        guard case .failure = await run(200, [:], Data(repeating: 0x41, count: 200_001)) else {
            return XCTFail("oversize accepted")
        }
        guard case .success = await run(200, [:], Data(repeating: 0x41, count: 200_000)) else {
            return XCTFail("exact cap rejected")
        }
    }
}
