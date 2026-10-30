import Foundation
import Network
import Observation
import LGKCore
import AppSharedMac

// The Mac's Wi-Fi sync host (desktop `transport.SyncTransport` listener). The pure parts — connection
// limits (`InboundLimits`) and the per-connection protocol (`LanHostSession`) — are unit-tested; the
// Network.framework adapter below only moves bytes.

/// Desktop `transport.py` listener constants.
enum LanListenLimits {
    static let maxConnections = 4
    static let maxPerAddress = 2
    static let maxPreAuthPerAddress = 1
    static let maxPreAuthPerPrefix = 3
    static let reservedForVerified = 1
    static let verifiedSeconds: Double = 15 * 60
    static let maxVerifiedAddresses = 64
    /// `CONNECT_SECONDS` (outbound dials).
    static let connectSeconds: TimeInterval = 3
    /// `FIRST_FRAME_SECONDS`.
    static let firstFrameSeconds: TimeInterval = 2
    /// `DEFAULT_SOCKET_TIMEOUT`: the whole inbound connection.
    static let socketSeconds: TimeInterval = 5
    /// `MAX_FIRST_FRAME_BYTES`.
    static let maxFirstFrameBytes = 64 * 1024
    /// `LISTEN_BACKLOG`.
    static let backlog = 8
}

/// Inbound connection bookkeeping (desktop `_reserve_inbound`, `_inbound_authenticated`, `_release_inbound`).
/// Every address: at most 4 connections in total and 2 from it. An address without a verified hello in the
/// last 15 minutes also leaves 1 slot free and holds at most 1 unauthenticated connection itself and 3
/// together with its /24 (IPv4) or /64 (IPv6) network. Not thread-safe: the server guards it with a lock.
struct InboundLimits {
    private var inbound: [Int: String] = [:]   // connection id -> source address
    private var preAuth: [Int: String] = [:]   // not yet authenticated -> source network
    private var verified: [(address: String, at: Double)] = []   // oldest first

    var count: Int { inbound.count }
    var preAuthCount: Int { preAuth.count }

    /// The /24 or /64 network of `address` (a zone id is dropped, an IPv4-mapped IPv6 address counts as IPv4);
    /// the address itself when it does not parse.
    static func prefix(_ address: String) -> String {
        let bare = address.split(separator: "%", maxSplits: 1).first.map(String.init) ?? address
        switch LanAddress.parse(bare) {
        case .v4(let b)?: return "\(b[0]).\(b[1]).\(b[2]).0/24"
        case .v6(let b)?:
            if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xFF && b[11] == 0xFF { return "\(b[12]).\(b[13]).\(b[14]).0/24" }
            return b[0..<8].map { String(format: "%02x", $0) }.joined() + "::/64"
        case nil: return bare
        }
    }

    private mutating func recentlyVerified(_ address: String, now: Double) -> Bool {
        verified.removeAll { now - $0.at > LanListenLimits.verifiedSeconds }
        return verified.contains { $0.address == address }
    }

    /// Takes a slot for connection `id` from `address`; false when a cap is reached (close it unread).
    mutating func reserve(_ id: Int, address: String, now: Double) -> Bool {
        let prefix = Self.prefix(address)
        guard inbound.count < LanListenLimits.maxConnections else { return false }
        guard inbound.values.filter({ $0 == address }).count < LanListenLimits.maxPerAddress else { return false }
        if !recentlyVerified(address, now: now) {
            guard inbound.count < LanListenLimits.maxConnections - LanListenLimits.reservedForVerified else { return false }
            guard preAuth.keys.filter({ inbound[$0] == address }).count < LanListenLimits.maxPreAuthPerAddress else { return false }
            guard preAuth.values.filter({ $0 == prefix }).count < LanListenLimits.maxPreAuthPerPrefix else { return false }
        }
        inbound[id] = address
        preAuth[id] = prefix
        return true
    }

    /// Connection `id` sent a verified session hello: it leaves the pre-authentication caps and its address may
    /// use the reserved slot for 15 minutes.
    mutating func authenticated(_ id: Int, now: Double) {
        preAuth[id] = nil
        guard let address = inbound[id] else { return }
        verified.removeAll { $0.address == address }
        verified.append((address, now))
        if verified.count > LanListenLimits.maxVerifiedAddresses { verified.removeFirst(verified.count - LanListenLimits.maxVerifiedAddresses) }
    }

    mutating func release(_ id: Int) {
        inbound[id] = nil
        preAuth[id] = nil
    }

    /// The listener stopped: every connection is gone (verified addresses are kept, like the desktop).
    mutating func removeAll() {
        inbound.removeAll()
        preAuth.removeAll()
    }
}

// MARK: one connection

/// One accepted TCP connection as the host protocol uses it. `receiveFrame` returns one whole frame, length
/// prefix included, of at most `limit` payload bytes, by `deadline`.
protocol HostSocket: Sendable {
    func receiveFrame(limit: Int, deadline: Date) async throws -> [UInt8]
    func send(_ bytes: [UInt8], deadline: Date) async throws
    func close()
}

/// Answers one enrollment request (`LGKENROLL1`): the reply payload to send, or nil to close without one.
/// It may wait for the user's Accept (up to 60 s).
protocol EnrollmentHandling: Sendable {
    func enroll(_ raw: [UInt8]) async -> [UInt8]?
}

/// The host side of one inbound connection (desktop `transport._handle_inbound`): the first frame (at most
/// 64 KiB, within 2 s) is either an enrollment request — answered only while an offer is shown — or a signed
/// session hello, which `LanResponder` checks against the pinned peers; then one sealed request and its
/// sealed answer, all within 5 s. Any failure closes the connection without an unauthenticated answer.
struct LanHostSession: Sendable {
    let responder: LanResponder
    /// The armed offer's handler; nil while no pairing code is shown (an enrollment request is then dropped).
    let enrollment: (any EnrollmentHandling)?
    var socketSeconds: TimeInterval = LanListenLimits.socketSeconds
    var firstFrameSeconds: TimeInterval = LanListenLimits.firstFrameSeconds

    enum Outcome: Equatable, Sendable {
        case closed, enrollmentAnswered, versionRefused, served
    }

    /// Runs the connection to its end and closes the socket. `authenticated` is called once a session hello
    /// verified (the connection then leaves the pre-authentication limits).
    @discardableResult
    func handle(_ socket: any HostSocket, authenticated: @Sendable () -> Void = {}) async -> Outcome {
        defer { socket.close() }
        let deadline = Date().addingTimeInterval(socketSeconds)
        do {
            let first = try await socket.receiveFrame(limit: LanListenLimits.maxFirstFrameBytes,
                                                      deadline: min(deadline, Date().addingTimeInterval(firstFrameSeconds)))
            let payload = try LanTransport.decodeFrame(first)
            if payload.starts(with: Enrollment.requestMagic) {
                guard let enrollment, payload.count <= Enrollment.maxBytes else { return .closed }
                guard let reply = await enrollment.enroll(payload), (1...Enrollment.maxBytes).contains(reply.count) else { return .closed }
                // The reply comes after the user's Accept: it gets a fresh socket timeout.
                try await socket.send(try LanTransport.encodeFrame(reply), deadline: Date().addingTimeInterval(socketSeconds))
                return .enrollmentAnswered
            }
            switch try responder.accept(helloFrame: first) {
            case .refuse(let frame):
                try await socket.send(frame, deadline: deadline)
                return .versionRefused
            case .accepted(var connection):
                authenticated()
                try await socket.send(connection.helloFrame, deadline: deadline)
                let request = try await socket.receiveFrame(limit: LanTransport.maxFramePayload, deadline: deadline)
                let answer = try responder.respond(&connection, requestFrame: request)
                try await socket.send(answer, deadline: deadline)
                return .served
            }
        } catch {
            return .closed
        }
    }
}

// MARK: the server

/// The listener's shared state: limits, open connections, the responder and the armed offer handler.
/// Thread-safe (one lock); Network.framework callbacks arrive on `queue`.
final class LanHostServer: @unchecked Sendable {
    let responder: LanResponder
    let monotonic: any MonotonicClock
    let queue = DispatchQueue(label: "lgk.lan.host")
    private let lock = NSLock()
    private var limits = InboundLimits()
    private var connections: [Int: NWConnection] = [:]
    private var nextID = 0
    private var listener: NWListener?
    private var enrollmentHandler: (any EnrollmentHandling)?
    private var stopped = false
    /// Called (on the server's queue) when the listener fails after it was listening.
    var onFailed: (@Sendable () -> Void)?

    init(responder: LanResponder, monotonic: any MonotonicClock = SystemMonotonicClock()) {
        self.responder = responder; self.monotonic = monotonic
    }

    var enrollment: (any EnrollmentHandling)? {
        get { lock.withLock { enrollmentHandler } }
        set { lock.withLock { enrollmentHandler = newValue } }
    }

    var openConnections: Int { lock.withLock { limits.count } }

    /// Binds `host:port` (port 0: any free port) and waits until it listens; returns the bound port.
    /// `service`: the Bonjour announcement (`_lgksync._tcp`, neutral name, TXT v/t), nil for none.
    /// `interface`: the adapter that owns `host`; the listener (and so its announcement) is limited to it.
    func start(host: String, port: Int, service: NWListener.Service? = nil, interface: NWInterface? = nil) async throws -> Int {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)), (0...65535).contains(port) else {
            throw LanListenError.badAddress
        }
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(host), port: nwPort)
        params.prohibitedInterfaceTypes = [.cellular]
        if let interface { params.requiredInterface = interface }
        let listener: NWListener
        do { listener = try NWListener(using: params) } catch { throw LanListenError.cannotListen("\(error)") }
        listener.service = service
        listener.newConnectionHandler = { [weak self] conn in self?.accept(conn) ?? conn.cancel() }
        let started: Int = try await withCheckedThrowingContinuation { cont in
            let once = OnceFlag()
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: once.run { cont.resume(returning: Int(listener.port?.rawValue ?? 0)) }
                case .failed(let e): once.run { listener.cancel(); cont.resume(throwing: LanListenError.cannotListen("\(e)")) }
                case .waiting(let e): once.run { listener.cancel(); cont.resume(throwing: LanListenError.cannotListen("\(e)")) }
                case .cancelled: once.run { cont.resume(throwing: LanListenError.cannotListen("cancelled")) }
                default: break
                }
            }
            lock.withLock { self.listener = listener; stopped = false }
            listener.start(queue: queue)
        }
        listener.stateUpdateHandler = { [weak self] state in
            if case .failed = state, let self {
                let wasListening = self.isListening
                self.stop()
                if wasListening { self.onFailed?() }
            }
        }
        return started
    }

    /// Stops listening and closes every connection; the armed offer handler is dropped.
    func stop() {
        let (l, open): (NWListener?, [NWConnection]) = lock.withLock {
            stopped = true
            defer { listener = nil; connections.removeAll(); limits.removeAll(); enrollmentHandler = nil }
            return (listener, Array(connections.values))
        }
        l?.cancel()
        open.forEach { $0.cancel() }
    }

    /// Replaces (or with nil withdraws) the Bonjour announcement of the running listener.
    func announce(_ service: NWListener.Service?) {
        guard let l = lock.withLock({ stopped ? nil : listener }) else { return }
        queue.async { l.service = service }
    }

    /// The `NWInterface` named `name` (for example `en0`), from one path snapshot; nil within 1 s.
    static func interface(named name: String) async -> NWInterface? {
        await withCheckedContinuation { (cont: CheckedContinuation<NWInterface?, Never>) in
            let monitor = NWPathMonitor()
            let queue = DispatchQueue(label: "lgk.lan.interfaces")
            let once = OnceFlag()
            monitor.pathUpdateHandler = { path in
                once.run { monitor.cancel(); cont.resume(returning: path.availableInterfaces.first { $0.name == name }) }
            }
            monitor.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 1) { once.run { monitor.cancel(); cont.resume(returning: nil) } }
        }
    }

    var isListening: Bool { lock.withLock { listener != nil && !stopped } }
    /// The port the listener bound (nil until ready).
    var boundPort: Int? { lock.withLock { listener?.port.map { Int($0.rawValue) } } }

    private func accept(_ conn: NWConnection) {
        let address: String
        if case .hostPort(let host, _) = conn.endpoint { address = Self.text(host) } else { address = "" }
        let admitted: (Int, LanHostSession)? = lock.withLock {
            guard !stopped else { return nil }
            let id = nextID; nextID += 1
            guard limits.reserve(id, address: address, now: monotonic.seconds) else { return nil }
            connections[id] = conn
            return (id, LanHostSession(responder: responder, enrollment: enrollmentHandler))
        }
        guard let (id, session) = admitted else { conn.cancel(); return }   // cheap: nothing was read
        let socket = NWHostSocket(conn, queue: queue)
        conn.start(queue: queue)
        Task.detached { [weak self] in
            await session.handle(socket, authenticated: { [weak self] in self?.authenticated(id) })
            self?.release(id)
        }
    }

    private func authenticated(_ id: Int) { lock.withLock { limits.authenticated(id, now: monotonic.seconds) } }
    private func release(_ id: Int) { lock.withLock { limits.release(id); connections[id] = nil } }

    static func text(_ host: NWEndpoint.Host) -> String {
        switch host {
        case .ipv4(let a): return "\(a)".split(separator: "%").first.map(String.init) ?? "\(a)"
        case .ipv6(let a): return "\(a)".split(separator: "%").first.map(String.init) ?? "\(a)"
        case .name(let n, _): return n
        @unknown default: return "\(host)"
        }
    }
}

enum LanListenError: Error, Equatable {
    case badAddress
    case cannotListen(String)
}

private final class OnceFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func run(_ body: () -> Void) { if lock.withLock({ defer { done = true }; return !done }) { body() } }
}

/// `HostSocket` over an accepted `NWConnection`.
final class NWHostSocket: HostSocket, @unchecked Sendable {
    let conn: NWConnection
    let queue: DispatchQueue

    init(_ conn: NWConnection, queue: DispatchQueue) { self.conn = conn; self.queue = queue }

    private func remaining(_ deadline: Date) -> TimeInterval { max(0.001, deadline.timeIntervalSinceNow) }

    func send(_ bytes: [UInt8], deadline: Date) async throws {
        let conn = self.conn
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            let once = OnceFlag()
            conn.send(content: Data(bytes), completion: .contentProcessed { error in
                once.run { if let error { cont.resume(throwing: error) } else { cont.resume() } }
            })
            queue.asyncAfter(deadline: .now() + remaining(deadline)) {
                once.run { conn.cancel(); cont.resume(throwing: LanListenError.cannotListen("write timed out")) }
            }
        }
    }

    private func receive(exactly n: Int, deadline: Date) async throws -> [UInt8] {
        var out: [UInt8] = []
        while out.count < n {
            let want = n - out.count, conn = self.conn
            let chunk: [UInt8] = try await withCheckedThrowingContinuation { cont in
                let once = OnceFlag()
                conn.receive(minimumIncompleteLength: 1, maximumLength: want) { data, _, isComplete, error in
                    once.run {
                        if let data, !data.isEmpty { cont.resume(returning: Array(data)); return }
                        cont.resume(throwing: error ?? LanListenError.cannotListen(isComplete ? "peer closed" : "read failed"))
                    }
                }
                queue.asyncAfter(deadline: .now() + remaining(deadline)) {
                    once.run { conn.cancel(); cont.resume(throwing: LanListenError.cannotListen("read timed out")) }
                }
            }
            out += chunk
        }
        return out
    }

    func receiveFrame(limit: Int, deadline: Date) async throws -> [UInt8] {
        let header = try await receive(exactly: 4, deadline: deadline)
        let n = Int(header[0]) << 24 | Int(header[1]) << 16 | Int(header[2]) << 8 | Int(header[3])
        guard (1...min(limit, LanTransport.maxFramePayload)).contains(n) else { throw LanListenError.cannotListen("frame length is outside the bound") }
        return header + (try await receive(exactly: n, deadline: deadline))
    }

    func close() { conn.cancel() }
}

// MARK: the host

/// The host's licence-only switch, read by the responder off the main actor.
final class LicenceOnlyFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var on = false
    var value: Bool {
        get { lock.withLock { on } }
        set { lock.withLock { on = newValue } }
    }
}

/// Wi-Fi sync hosting on the Mac (desktop `service.LanAdapter`): listens on the chosen private address only
/// while the vault is unlocked and Wi-Fi sync is on, serves pinned peers through `LanResponder`, answers
/// enrollment while a pairing code is shown (`HostPairingModel`), and dials every pinned peer that listens
/// itself (a PC) on each sync run. Locking (`shutdown`) stops the listener and refuses every later commit.
@MainActor
@Observable
final class LanHost {
    enum ShowResult: Equatable { case shown, notListening, failed(String) }

    static let lanNotListening = "lan-not-listening"

    private(set) var isListening = false
    private(set) var endpoint: LanEndpoint?
    /// Why the listener could not start (shown on the Wi-Fi card).
    private(set) var listenError: String?
    /// True when the last start followed this Mac's address to a new one (the Sync page says so).
    private(set) var addressChanged = false
    let pairing: HostPairingModel

    /// Licence-only mode while this Mac is free (plan 2026-10-29-appstore-licence Task 8, desktop licence-only
    /// sync): pairing works, served peers' views are merged for licence states only, this Mac answers with no
    /// states and dials no peer. A licence received this way makes the Mac Pro, and full hosting follows.
    @ObservationIgnored let licenceOnlyFlag = LicenceOnlyFlag()
    var licenceOnly: Bool {
        get { licenceOnlyFlag.value }
        set { licenceOnlyFlag.value = newValue }
    }
    /// False once the vault locked; nothing listens or commits then.
    @ObservationIgnored var isUnlocked: () -> Bool
    #if DEBUG
    /// Tests only: allow 127.0.0.1 (production listens on private LAN addresses only).
    @ObservationIgnored var allowsLoopbackForTests = false
    /// Tests only: runs after the bind finished, before the result is kept.
    @ObservationIgnored var afterBindForTests: (() async -> Void)?
    #endif
    static let stoppedText = String(localized: "Wi-Fi sync stopped. Check the network and turn it on again.")
    /// Bumped by every start and stop: a bind that finishes after another start or a stop is dropped.
    @ObservationIgnored private var generation = 0
    /// The Bonjour instance name, `LocalGateKeys-xxxx`, new for every start.
    @ObservationIgnored private var instanceName = ""
    /// What the running announcement was made from (UTC day, group, epoch); nil: nothing announced.
    @ObservationIgnored private var announcedFor: String?
    @ObservationIgnored private var lastAnnounceCheck: Double?
    /// How often `refreshAnnouncement` re-reads the group state (the UTC day and the key epoch).
    static let announceCheckSeconds: Double = 60

    @ObservationIgnored let store: GatedStore
    @ObservationIgnored let gate = SessionGate()
    @ObservationIgnored let deps: SyncDependencies
    @ObservationIgnored let counters: HelloCounterSource
    @ObservationIgnored let monotonic: any MonotonicClock
    @ObservationIgnored private(set) var server: LanHostServer?

    /// `counters` must be the same source the coordinator's Wi-Fi client uses, so hello counters keep increasing.
    init(store: any ItemStore, deps: SyncDependencies, counters: HelloCounterSource,
         monotonic: any MonotonicClock = SystemMonotonicClock(), isUnlocked: @escaping () -> Bool = { true }) {
        let gated = GatedStore(store, gate: gate)
        self.store = gated; self.deps = deps; self.counters = counters; self.monotonic = monotonic
        self.isUnlocked = isUnlocked
        pairing = HostPairingModel(store: gated, random: deps.random, clock: deps.clock, monotonic: monotonic)
    }

    /// A host over the unlocked vault's publishing store, stopped by every lock; nil while locked.
    static func make(lock: MacLockModel, deps: SyncDependencies, counters: HelloCounterSource) -> LanHost? {
        guard lock.state == .unlocked, let store = lock.store as? PublishingItemStore else { return nil }
        let host = LanHost(store: SyncSourceStore(base: store, local: lock), deps: deps, counters: counters,
                           isUnlocked: { [weak lock] in lock?.state == .unlocked })
        lock.onLock.append { [weak host] in host?.shutdown() }
        return host
    }

    private var allowLoopback: Bool {
        #if DEBUG
        allowsLoopbackForTests
        #else
        false
        #endif
    }

    /// Starts listening on `endpoint` (a private address of this Mac; port 0 only in tests). False, with
    /// `listenError`, when the vault is locked, the address is not private or the port is taken.
    @discardableResult
    func start(_ endpoint: LanEndpoint, followed: Bool = false) async -> Bool {
        await start(host: endpoint.host, port: endpoint.port, followed: followed)
    }

    @discardableResult
    func start(host: String, port: Int, followed: Bool = false) async -> Bool {
        stop()
        generation += 1
        let mine = generation
        guard gate.isOpen, isUnlocked() else { listenError = nil; return false }
        guard LanAddressPicker.isHostable(host, allowLoopback: allowLoopback) else {
            listenError = LanAddressPicker.privateText
            return false
        }
        guard LanAddressPicker.portRange.contains(port) || (allowLoopback && port == 0) else {
            listenError = LanAddressPicker.portText
            return false
        }
        let shown = host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
        let installID: String
        do { installID = try deps.keychain.installID(random: deps.random) } catch {
            listenError = SyncWording.stepFailedCopy
            return false
        }
        let responder = LanResponder(store: store, installID: installID, counters: counters, random: deps.random,
                                     clock: deps.clock, licenseKeys: deps.licenseKeys, witnessMemory: deps.witnessMemory,
                                     blobs: deps.attachmentBlobs, attachmentPeers: deps.attachmentPeers,
                                     licenceOnly: { [flag = licenceOnlyFlag] in flag.value })
        let server = LanHostServer(responder: responder, monotonic: monotonic)
        // Announced only on the adapter that owns the address (desktop `announce.py`), under a new neutral name.
        let name = Discovery.instanceName(random: deps.random)
        // Loopback (tests only) is never announced.
        let (service, announced): (NWListener.Service?, String?) = host.hasPrefix("127.") ? (nil, nil) : announcement(name: name)
        var interface: NWInterface?
        if let owner = LanAddressPicker.interfaceAddresses().first(where: { $0.address == host })?.interface {
            interface = await LanHostServer.interface(named: owner)
        }
        let bound: Int
        do { bound = try await server.start(host: host, port: port, service: service, interface: interface) } catch {
            listenError = String(localized: "Wi-Fi sync could not listen on \(shown). Another app may be using that port.")
            return false
        }
        #if DEBUG
        await afterBindForTests?()
        #endif
        // Locked, stopped or started again while binding: never keep this listener.
        guard generation == mine, gate.isOpen, isUnlocked(),
              let endpoint = try? LanEndpoint(validating: host, port: bound) else { server.stop(); return false }
        self.server?.stop()
        self.server = server
        server.onFailed = { [weak self, weak server] in
            Task { @MainActor in
                guard let self, let server, self.server === server else { return }
                self.stop()
                self.listenError = Self.stoppedText
            }
        }
        self.endpoint = endpoint
        instanceName = name
        announcedFor = announced
        lastAnnounceCheck = monotonic.seconds
        isListening = true
        listenError = nil
        addressChanged = followed
        return true
    }

    /// The Bonjour service for this host's group at the current UTC day, and what it was made from; none while
    /// this Mac is in no group (nothing to tag).
    private func announcement(name: String) -> (NWListener.Service?, String?) {
        guard let state = (try? store.load())?.sync,
              let groupKey = try? GroupKey(groupID: state.groupID, epoch: state.epoch, key: state.key) else { return (nil, nil) }
        let now = deps.clock.now
        let txt = Discovery.txtRecord(groupKey, hostDeviceID: state.deviceID, now: now)
        let service = NWListener.Service(name: name, type: Discovery.serviceType, domain: nil, txtRecord: NWTXTRecord(txt))
        return (service, "\(Discovery.utcDay(now))|\(state.groupID)|\(state.epoch)")
    }

    /// Renews the announcement when the UTC day, the group or its key epoch changed (every second from the
    /// scheduler; the group state is read at most once a minute unless `force`). Only while listening.
    func refreshAnnouncement(force: Bool = false) {
        guard gate.isOpen, isUnlocked(), isListening, let server, let endpoint, !endpoint.host.hasPrefix("127.") else { return }
        let t = monotonic.seconds
        if !force, let last = lastAnnounceCheck, t - last < Self.announceCheckSeconds { return }
        lastAnnounceCheck = t
        let (service, made) = announcement(name: instanceName)
        guard made != announcedFor else { return }
        announcedFor = made
        server.announce(service)
    }

    /// Wi-Fi sync turned off: stop listening and close the pairing code.
    func stop() {
        generation += 1
        pairing.close()
        server?.stop()
        server = nil
        isListening = false
        endpoint = nil
        addressChanged = false
        announcedFor = nil
        lastAnnounceCheck = nil
    }

    /// The listening address left this Mac (an interface change): stop, with the Task 5 message.
    func stopAddressLost() {
        stop()
        listenError = Self.stoppedText
    }

    /// The vault locked: stop, and refuse every later read and commit of this host.
    func shutdown() {
        gate.close()
        stop()
    }

    /// "Show QR code": a new offer at the listening address (a Wi-Fi group is created when there is none).
    func showQR() -> ShowResult {
        guard gate.isOpen, isUnlocked(), let server, server.isListening, let endpoint else { return .notListening }
        do {
            let installID = try deps.keychain.installID(random: deps.random)
            server.enrollment = try pairing.begin(endpoint: endpoint, installID: installID)
            return .shown
        } catch let e as SyncActionError {
            return .failed(SyncWording.errorCopy(e.reason, here: true) ?? SyncWording.stepFailedCopy)
        } catch {
            return .failed(SyncWording.stepFailedCopy)
        }
    }

    /// One sync run of the host (desktop `LanAdapter.run`): every pinned, unrevoked peer with an endpoint is
    /// dialled (a phone has none and connects to this Mac instead), then the issues seen while serving peers.
    func syncPeers() async -> [SyncIssue] {
        guard gate.isOpen, isUnlocked() else { return [] }
        guard isListening, let server else { return [SyncIssue(Self.lanNotListening)] }
        guard let state = (try? store.load())?.sync else { return [SyncIssue("not-joined")] }
        let installID: String
        do { installID = try deps.keychain.installID(random: deps.random) } catch { return [SyncIssue("state-corrupt", "\(error)")] }
        var issues: [SyncIssue] = []
        let store = self.store, deps = self.deps
        // Licence-only: this Mac publishes nothing, so it dials no peer (peers that connect are still served).
        for peer in state.lanPeers where !licenceOnly && !peer.revoked && peer.endpoint != nil {
            guard gate.isOpen else { break }
            let report = await SyncCoordinator.lanRun(store: store, deps: deps, installID: installID, peer: peer.pinned)
            issues += report.issues
        }
        if let served = server.responder.takeReport() { issues += served.issues }   // reported once
        // Rises the responder's save throttle held back (rollback witnesses) are saved once per run.
        if gate.isOpen { Witness.flush(store: store, memory: deps.witnessMemory) }
        refreshAnnouncement(force: true)   // a sync may have rotated the group key (new epoch, new tag)
        return issues
    }
}
