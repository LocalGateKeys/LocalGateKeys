import Foundation
import Network
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

// LAN sync runs only in the main app (this target). The AutoFill extension never links this file.

/// A refused, failed or timed-out socket step. `kind` says why, so pairing can explain it; a sync run
/// reports any of them as the desktop's `unreachable`.
struct LanSocketError: Error, Equatable, CustomStringConvertible {
    let message: String
    let kind: LanFailure
    init(_ message: String, kind: LanFailure = .other) { self.message = message; self.kind = kind }
    var description: String { message }
}

/// One TCP connection to a LAN endpoint. `receiveFrame` returns one whole frame, length prefix included.
protocol LanSocket: Sendable {
    func send(_ bytes: [UInt8]) async throws
    func receiveFrame() async throws -> [UInt8]
    func close()
}

/// Opens TCP connections. Production: `NWLanDialer`; tests: a fake.
protocol LanDialer: Sendable {
    /// `waitForNetwork`: tolerate a waiting connection (Local Network permission prompt) until the deadline.
    func dial(_ endpoint: LanEndpoint, waitForNetwork: Bool) async throws -> any LanSocket
}

extension LanDialer {
    func dial(_ endpoint: LanEndpoint) async throws -> any LanSocket { try await dial(endpoint, waitForNetwork: false) }
}

/// The `LanConnector` the app gives `LanClient.sync`. Only the paired peer is contacted, and only at an
/// address where `LanAddress.isLAN` is true. A connect or hello that fails surfaces as
/// `LanPeerNotAnswering` (nothing of the request was sent), which `LanClient` retries once after 50 ms
/// with a newly minted hello (desktop `CHUNK_RETRY_DELAY`; never for the first request of a run).
struct PairedLanConnector: LanConnector {
    let paired: PinnedPeer
    let dialer: any LanDialer

    func connect(to peer: PinnedPeer) async throws -> any LanConnection {
        guard peer == paired else { throw LanSocketError("not the paired device") }
        guard let endpoint = peer.endpoint, LanAddress.isLAN(endpoint.host) else {
            throw LanSocketError("the paired device has no LAN address")
        }
        return SocketLanConnection(endpoint: endpoint, dialer: dialer)
    }
}

/// One request on one connection: the first `exchange` dials and sends the hello, the second sends the
/// sealed request and closes.
actor SocketLanConnection: LanConnection {
    let endpoint: LanEndpoint
    let dialer: any LanDialer
    private var socket: (any LanSocket)?
    private var exchanges = 0

    init(endpoint: LanEndpoint, dialer: any LanDialer) { self.endpoint = endpoint; self.dialer = dialer }

    func exchange(_ frame: [UInt8]) async throws -> [UInt8] {
        exchanges += 1
        if exchanges == 1 {
            let s: any LanSocket
            do { s = try await dialer.dial(endpoint) } catch { throw LanPeerNotAnswering("\(error)") }
            do {
                try await s.send(frame)
                let reply = try await s.receiveFrame()
                socket = s
                return reply
            } catch {
                s.close()
                throw LanPeerNotAnswering("\(error)")
            }
        }
        guard let socket else { throw LanSocketError("connection is closed") }
        defer { socket.close(); self.socket = nil }
        try await socket.send(frame)
        return try await socket.receiveFrame()
    }
}

/// Sends the one enrollment request of a scanned offer and returns the one-frame reply (desktop
/// `SyncTransport.enroll`). Not retried, like the desktop. The reply comes only after the user chose
/// Accept on the inviting device, so the read waits up to `Enrollment.replySeconds` (75 s).
protocol EnrollmentSending: Sendable {
    /// `onConnected`: called once the connection is up, before the request is sent.
    func enroll(endpoint: LanEndpoint, request: [UInt8], onConnected: @escaping @Sendable () -> Void) async throws -> [UInt8]
}

struct SocketEnroller: EnrollmentSending {
    let dialer: any LanDialer

    func enroll(endpoint: LanEndpoint, request: [UInt8],
                onConnected: @escaping @Sendable () -> Void = {}) async throws -> [UInt8] {
        guard LanAddress.isLAN(endpoint.host) else { throw LanSocketError("not a LAN address") }
        guard request.starts(with: Enrollment.requestMagic), request.count <= Enrollment.maxBytes else {
            throw LanSocketError("enrollment request is malformed")
        }
        // The first connection can sit in `.waiting` while iOS shows the Local Network prompt.
        let s = try await dialer.dial(endpoint, waitForNetwork: true)
        defer { s.close() }
        onConnected()
        try await s.send(try LanTransport.encodeFrame(request))
        let reply = try LanTransport.decodeFrame(try await s.receiveFrame())
        guard reply.count <= Enrollment.maxBytes else { throw LanSocketError("enrollment reply exceeds the bound") }
        return reply
    }
}

// MARK: Network.framework

/// TCP over `NWConnection` to a literal LAN address: the one from the scanned QR offer pinned with the
/// peer, or one found by `HostFinder` (Bonjour) after the pinned one stopped answering. No DNS lookup.
struct NWLanDialer: LanDialer {
    /// Desktop `DEFAULT_SOCKET_TIMEOUT = 5.0`, per sync connection.
    var timeout: TimeInterval = 5
    /// Enrollment: how long a connection may wait in `.waiting` for the Local Network prompt to be
    /// answered. Refused and unroutable connects fail at once instead.
    var promptTimeout: TimeInterval = 20
    /// Enrollment: once connected, the time the request and the reply get (desktop `ENROLL_REPLY_SECONDS`
    /// = 75): the inviting device answers only after its user chose Accept (up to 60 s).
    var enrollReplyTimeout: TimeInterval = TimeInterval(Enrollment.replySeconds)
    /// Enrollment: browse for `_lgksync._tcp` while dialling, so iOS asks for (and lists the app under)
    /// Local Network even when the dialled address is off-link and would not trigger the prompt itself.
    var browseForPrompt = true

    func dial(_ endpoint: LanEndpoint, waitForNetwork: Bool) async throws -> any LanSocket {
        guard LanAddress.isLAN(endpoint.host), let port = NWEndpoint.Port(rawValue: UInt16(clamping: endpoint.port)),
              endpoint.port > 0 else { throw LanSocketError("not a LAN address") }
        if Task.isCancelled { throw LanSocketError("connect cancelled", kind: .cancelled) }
        let nudge = waitForNetwork && browseForPrompt ? LocalNetworkNudge.start() : nil
        defer { nudge?.cancel() }
        let params = NWParameters.tcp
        params.prohibitedInterfaceTypes = [.cellular]
        let conn = NWConnection(host: NWEndpoint.Host(endpoint.host), port: port, using: params)
        let socket = NWLanSocket(conn, deadline: Date().addingTimeInterval(waitForNetwork ? promptTimeout : timeout),
                                 ioTimeout: waitForNetwork ? enrollReplyTimeout : timeout)
        try await socket.start(waitForNetwork: waitForNetwork)
        return socket
    }
}

/// A short Bonjour browse for the sync service type (declared in `NSBonjourServices`). Nothing it finds
/// is used; it only makes iOS show the Local Network prompt. Cancelled once the dial has finished.
final class LocalNetworkNudge: @unchecked Sendable {
    static let serviceType = "_lgksync._tcp"
    let browser: NWBrowser

    private init(_ browser: NWBrowser) { self.browser = browser }

    static func start() -> LocalNetworkNudge {
        let browser = NWBrowser(for: .bonjour(type: serviceType, domain: nil), using: .tcp)
        browser.stateUpdateHandler = { _ in }
        browser.browseResultsChangedHandler = { _, _ in }
        browser.start(queue: DispatchQueue(label: "lgk.lan.nudge"))
        return LocalNetworkNudge(browser)
    }

    func cancel() { browser.cancel() }
}

/// Resumes a continuation once (state handlers and timeouts race).
private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func run(_ body: () -> Void) { if lock.withLock({ defer { done = true }; return !done }) { body() } }
}

/// The connect's `ConnectWait`, updated on the connection's queue and read by its timeout.
private final class WaitBox: @unchecked Sendable {
    private let lock = NSLock()
    private var wait = ConnectWait()
    func observe(_ state: NWConnection.State, _ unsatisfied: NWPath.UnsatisfiedReason?) {
        lock.withLock { wait.observe(state, unsatisfied: unsatisfied) }
    }
    var deadlineFailure: LanFailure { lock.withLock { wait.deadlineFailure } }
}

final class NWLanSocket: LanSocket, @unchecked Sendable {
    let conn: NWConnection
    let ioTimeout: TimeInterval
    let queue = DispatchQueue(label: "lgk.lan.socket")
    private let lock = NSLock()
    private var _deadline: Date

    init(_ conn: NWConnection, deadline: Date, ioTimeout: TimeInterval = 5) {
        self.conn = conn; self._deadline = deadline; self.ioTimeout = ioTimeout
    }

    var deadline: Date { lock.withLock { _deadline } }
    private var remaining: TimeInterval { max(0.001, deadline.timeIntervalSinceNow) }

    /// Connects. `waitForNetwork` (enrollment): a `.waiting` connection is given until the deadline only
    /// while waiting can help (Local Network permission pending, path not yet up); a refused or unroutable
    /// connect fails at once either way.
    func start(waitForNetwork: Bool) async throws {
        let conn = self.conn, queue = self.queue
        let once = Once(), wait = WaitBox()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                @Sendable func fail(_ kind: LanFailure, _ message: String) {
                    once.run { conn.cancel(); cont.resume(throwing: LanSocketError(message, kind: kind)) }
                }
                conn.stateUpdateHandler = { state in
                    let unsatisfied = conn.currentPath?.unsatisfiedReason
                    wait.observe(state, unsatisfied)
                    switch state {
                    case .ready: once.run { cont.resume() }
                    case .waiting(let e):
                        switch LanFailure.verdict(waiting: e, unsatisfied: unsatisfied) {
                        case .fail(let kind): fail(kind, "connect failed: \(e)")
                        case .wait(let isDenied):
                            if !waitForNetwork {
                                fail(isDenied ? .localNetworkDenied : .unreachable, "connect failed: \(e)")
                            }
                        }
                    case .failed(let e): fail(LanFailure.classify(e), "connect failed: \(e)")
                    case .cancelled: once.run { cont.resume(throwing: LanSocketError("connect cancelled", kind: .cancelled)) }
                    default: break
                    }
                }
                // Cancelled before the connection started: never start it.
                if Task.isCancelled {
                    once.run { cont.resume(throwing: LanSocketError("connect cancelled", kind: .cancelled)) }
                    return
                }
                conn.start(queue: queue)
                queue.asyncAfter(deadline: .now() + remaining) {
                    let failure = wait.deadlineFailure
                    fail(failure, failure == .localNetworkDenied ? "local network access was not granted" : "connect timed out")
                }
            }
        } onCancel: { conn.cancel() }
        // Enrollment: from the moment it connected, the exchange gets `ioTimeout` (the dialer's
        // `enrollReplyTimeout`, 75 s: the reply waits for Accept on the inviting device), also when the
        // Local Network prompt was answered near the connect deadline. A sync dial keeps its 5 s in total.
        if waitForNetwork { lock.withLock { _deadline = max(_deadline, Date().addingTimeInterval(ioTimeout)) } }
    }

    func send(_ bytes: [UInt8]) async throws {
        let conn = self.conn
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                let once = Once()
                conn.send(content: Data(bytes), completion: .contentProcessed { error in
                    once.run {
                        if let error { cont.resume(throwing: LanSocketError("write failed: \(error)", kind: LanFailure.classify(error))) }
                        else { cont.resume() }
                    }
                })
                queue.asyncAfter(deadline: .now() + remaining) {
                    once.run { conn.cancel(); cont.resume(throwing: LanSocketError("write timed out", kind: .timedOut)) }
                }
            }
        } onCancel: { conn.cancel() }
    }

    private func receive(exactly n: Int) async throws -> [UInt8] {
        var out: [UInt8] = []
        while out.count < n {
            let want = n - out.count
            let conn = self.conn
            let chunk: [UInt8] = try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { cont in
                    let once = Once()
                    conn.receive(minimumIncompleteLength: 1, maximumLength: want) { data, _, isComplete, error in
                        once.run {
                            if let data, !data.isEmpty { cont.resume(returning: Array(data)); return }
                            if let error {
                                cont.resume(throwing: LanSocketError("read failed: \(error)", kind: LanFailure.classify(error))); return
                            }
                            cont.resume(throwing: isComplete ? LanSocketError("peer closed the connection", kind: .closedByPeer)
                                                             : LanSocketError("read failed"))
                        }
                    }
                    queue.asyncAfter(deadline: .now() + remaining) {
                        once.run { conn.cancel(); cont.resume(throwing: LanSocketError("read timed out", kind: .timedOut)) }
                    }
                }
            } onCancel: { conn.cancel() }
            out += chunk
        }
        return out
    }

    func receiveFrame() async throws -> [UInt8] {
        let header = try await receive(exactly: 4)
        let n = Int(header[0]) << 24 | Int(header[1]) << 16 | Int(header[2]) << 8 | Int(header[3])
        guard (1...LanTransport.maxFramePayload).contains(n) else { throw LanSocketError("frame length is outside the bound") }
        return header + (try await receive(exactly: n))
    }

    func close() { conn.cancel() }
}
