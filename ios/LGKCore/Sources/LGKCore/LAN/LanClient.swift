import Foundation
/// The only I/O seam of LAN sync: one TCP connection to the peer. A `LanConnector` opens a new
/// connection for every request; the client calls `exchange` exactly twice on it (its hello, then
/// the sealed request) and drops it. Frames carry their 4-byte length prefix both ways.
public protocol LanConnection: Sendable {
    func exchange(_ frame: [UInt8]) async throws -> [UInt8]
}

/// Thrown by a connector or connection when the peer did not answer before anything of the request
/// was sent: the connect failed, or the hello exchange failed (desktop `transport.PeerNotAnswering`).
/// `LanClient` retries such a request once, with a NEW hello (new session id, higher counter).
public struct LanPeerNotAnswering: Error, Equatable, Sendable, CustomStringConvertible {
    public let detail: String
    public init(_ detail: String) { self.detail = detail }
    public var description: String { "peer did not answer: \(detail)" }
}

public protocol LanConnector: Sendable {
    func connect(to peer: PinnedPeer) async throws -> any LanConnection
}

/// Persistent hello-counter state, implemented by the app (encrypted store); tests use memory.
///
/// Contract: reserving a block (`persistHelloCounter`) must be atomic and durable before any counter
/// of the block is used, so a crash can never lead to a reused counter. Only the main app performs LAN
/// sync and writes this store; the AutoFill extension never does.
public protocol CounterStore: AnyObject, Sendable {
    /// The last hello counter reserved and saved (0 when none).
    func persistedHelloCounter() throws -> Int64
    /// Saves the last counter of a newly reserved block; must be durable before it returns.
    func persistHelloCounter(_ last: Int64) throws
    /// The last hello counter accepted from `peer` (0 when none).
    func lastAcceptedCounter(peer: String) throws -> Int64
    /// Saves the last hello counter accepted from `peer`.
    func setLastAcceptedCounter(_ counter: Int64, peer: String) throws
}

/// Hello counters handed out from blocks persisted before use (desktop `lan_sync.transport_state`):
/// a block of `blockSize` starts at `max(persisted + 1, clock in microseconds, previous block end + 1)`
/// and its last value is saved before any of it is used, so a counter is never reused, also across
/// restarts and a clock set backwards. Thread-safe: block state and store access are serialized by a lock.
public final class HelloCounterSource: @unchecked Sendable {
    public static let blockSize: Int64 = 64
    let store: any CounterStore
    let clock: any UnixClock
    private var next: Int64 = 1
    private var last: Int64 = 0
    private let lock = NSLock()

    public init(store: any CounterStore, clock: any UnixClock) { self.store = store; self.clock = clock }

    public func nextCounter() throws -> Int64 {
        lock.lock(); defer { lock.unlock() }
        if next > last {
            let persisted = try store.persistedHelloCounter()
            let (micro, overflow) = clock.now.multipliedReportingOverflow(by: 1_000_000)
            let start = max(persisted &+ 1, overflow ? Int64.max : micro, last &+ 1)
            guard persisted < Int64.max, start <= Int64.max - Self.blockSize else {
                throw LanTransportError.replay("Outbound sync counter is exhausted")
            }
            let end = start + Self.blockSize - 1
            try store.persistHelloCounter(end)
            next = start; last = end
        }
        defer { next += 1 }
        return next
    }

    /// Accepts `counter` from `peer` only when it is above the last accepted one, and saves it.
    public func acceptInbound(_ counter: Int64, peer: String) throws {
        lock.lock(); defer { lock.unlock() }
        guard counter > (try store.lastAcceptedCounter(peer: peer)) else {
            throw LanTransportError.replay("Session hello counter did not increase")
        }
        try store.setLastAcceptedCounter(counter, peer: peer)
    }
}

/// The initiator of LAN sync (desktop `lan_sync.sync_with` and `SyncTransport.request`).
/// Immutable after init and `Sendable`; counter state lives in the lock-protected `HelloCounterSource`.
public final class LanClient: Sendable {
    public let identity: DeviceIdentity
    public let groupKey: GroupKey
    let counters: HelloCounterSource
    let random: any RandomSource
    let clock: any UnixClock
    let retryDelayNanos: UInt64
    let sleep: @Sendable (UInt64) async -> Void

    /// Desktop `lan_sync.CHUNK_RETRY_DELAY = 0.05` s.
    public static let defaultRetryDelayNanos: UInt64 = 50_000_000

    public init(identity: DeviceIdentity, groupKey: GroupKey, counters: HelloCounterSource,
                random: any RandomSource, clock: any UnixClock, retryDelayNanos: UInt64 = LanClient.defaultRetryDelayNanos,
                sleep: @escaping @Sendable (UInt64) async -> Void = { try? await Task.sleep(nanoseconds: $0) }) {
        self.identity = identity; self.groupKey = groupKey; self.counters = counters
        self.random = random; self.clock = clock; self.retryDelayNanos = retryDelayNanos; self.sleep = sleep
    }

    /// One connection: send a hello (fresh 16-byte session id, then a 32-byte hello nonce from
    /// `random`), check the responder's hello (pinned keys, same session id, increasing counter),
    /// send one sealed request and open the one sealed response.
    public func request(_ plaintext: [UInt8], peer: PinnedPeer, connection: any LanConnection) async throws -> [UInt8] {
        let sessionID = random.bytes(count: LanTransport.sessionIDBytes)
        let localHello = try SessionHello.make(identity: identity, groupID: groupKey.groupID, sessionID: sessionID,
                                               counter: try counters.nextCounter(), random: AnyRandom(random))
        let helloFrame = try await connection.exchange(try LanTransport.encodeFrame(try localHello.toBytes()))
        let remoteHello = try SessionHello.parse(try LanTransport.decodeFrame(helloFrame))
        guard remoteHello.deviceID == peer.deviceID else {
            throw LanTransportError.authentication("Session peer is not the expected paired device")
        }
        try SessionHello.verify(remoteHello, pinned: peer, groupID: groupKey.groupID)
        try counters.acceptInbound(remoteHello.counter, peer: peer.deviceID)
        guard remoteHello.sessionID == sessionID else { throw LanTransportError.authentication("Session hello is bound to another session") }
        var channel = try SecureChannel(local: identity, remote: peer, groupID: groupKey.groupID, sessionID: sessionID,
                                        role: .initiator, localHello: localHello, remoteHello: remoteHello)
        let response = try await connection.exchange(try channel.seal(plaintext))
        return try channel.open(response)
    }

    /// One request on a new connection (desktop `sync_with.call`). With `retry`, a request the peer did
    /// not answer (`LanPeerNotAnswering`: nothing was sent) is made again once after `retryDelayNanos`,
    /// on a new connection with a newly minted hello.
    private func call(_ m: LanMessage, peer: PinnedPeer, connector: any LanConnector, retry: Bool = true) async throws -> LanMessage {
        let plain = try LanMessages.encode(m)
        let raw: [UInt8]
        do {
            raw = try await request(plain, peer: peer, connection: try await connector.connect(to: peer))
        } catch is LanPeerNotAnswering where retry {
            await sleep(retryDelayNanos)
            raw = try await request(plain, peer: peer, connection: try await connector.connect(to: peer))
        }
        do { return try LanMessages.parse(raw) } catch let e as LanSyncError {
            throw LanSyncError(e.reason == "bad-message" ? "bad-reply" : e.reason)
        }
    }

    /// `_reply_issue`: a responder error or an unexpected message.
    static func replyIssue(_ m: LanMessage) -> LanSyncError {
        if case .error(let reason) = m {
            let mapped = ["epoch-behind": "epoch-behind", "peer-epoch-behind": "peer-epoch-behind",
                          "rejoin-required": "peer-rejoin-required", "not-joined": "peer-not-joined"]
            if let kind = mapped[reason] { return LanSyncError(kind) }
            return LanSyncError("peer-refused", reason)
        }
        return LanSyncError("bad-reply", "\(m)")
    }

    /// One LAN sync with `peer`: send this device's view in chunks (each acknowledged but the
    /// last), receive the peer's view (first chunk as the answer to the last one, the rest with
    /// `next`) and return the peer's decoded states for the caller to merge. Refusals throw
    /// `LanSyncError` with the desktop's issue codes. `ownCounter` is the stored view header counter
    /// (informational on LAN, never reserved).
    public func sync(peer: PinnedPeer, localStates: [ItemState], ownCounter: Int64,
                     connector: any LanConnector) async throws -> [ItemState] {
        let raw: [UInt8]
        do {
            raw = try ViewFile.encode(key: groupKey, deviceID: identity.deviceID, counter: ownCounter,
                                      states: localStates, now: AnyClock(clock), random: AnyRandom(random))
        } catch let e as SyncFormatError { throw LanSyncError("too-large", e.reason) }
        let parts = LanMessages.splitView(raw)
        guard raw.count <= LanMessages.maxViewBytes, Int64(parts.count) <= LanMessages.maxChunks else {
            throw LanSyncError("too-large", "view exceeds the LAN bound")
        }
        let transfer = lowerHex(random.bytes(count: 16))
        func chunk(_ seq: Int) -> LanMessage {
            .view(groupID: groupKey.groupID, epoch: groupKey.epoch, transfer: transfer, seq: Int64(seq),
                  total: Int64(parts.count), size: Int64(raw.count), view: Base64.encode(parts[seq]))
        }
        var reply = try await call(chunk(0), peer: peer, connector: connector, retry: false)  // unreachable: reported at once
        for seq in 1..<max(parts.count, 1) {
            guard reply == .ack(transfer: transfer, seq: Int64(seq - 1)) else { throw Self.replyIssue(reply) }
            reply = try await call(chunk(seq), peer: peer, connector: connector)
        }
        return try await receiveView(reply, peer: peer, connector: connector)
    }

    private func receiveView(_ first: LanMessage, peer: PinnedPeer, connector: any LanConnector) async throws -> [ItemState] {
        guard case let .view(group, epoch, transfer, _, total, size, _) = first else { throw Self.replyIssue(first) }
        guard group == groupKey.groupID else { throw LanSyncError("group-mismatch", peer.deviceID) }
        guard epoch == groupKey.epoch else {
            throw LanSyncError(epoch > groupKey.epoch ? "epoch-behind" : "peer-epoch-behind", peer.deviceID)
        }
        var parts: [[UInt8]] = []
        var received = 0
        var message = first
        while true {
            guard case let .view(g, e, t, seq, tot, sz, text) = message else { throw Self.replyIssue(message) }
            guard t == transfer, seq == Int64(parts.count) else { throw LanSyncError("bad-reply", "chunk order") }
            guard g == groupKey.groupID, e == groupKey.epoch else { throw LanSyncError("bad-reply", "chunk group") }
            guard tot == total, sz == size else { throw LanSyncError("bad-chunk") }
            guard let data = try? Base64.decodeStrict(text) else { throw LanSyncError("bad-reply") }
            if data.isEmpty { throw LanSyncError("bad-chunk") }
            if data.count > LanMessages.chunkLimit { throw LanSyncError("too-large") }
            parts.append(data)
            received += data.count
            if received > size { throw LanSyncError("bad-chunk") }
            if seq == total - 1 { break }
            message = try await call(.next(transfer: transfer, seq: Int64(parts.count)), peer: peer, connector: connector)
        }
        guard received == size else { throw LanSyncError("bad-chunk") }
        do {
            return try ViewFile.decode(parts.flatMap { $0 }, key: groupKey, expectedDeviceID: peer.deviceID).states
        } catch let e as SyncFormatError {
            throw LanSyncError(e.reason == "device-mismatch" ? "device-mismatch" : "bad-peer-data", "\(peer.deviceID): \(e.reason)")
        }
    }
}

private struct AnyClock: UnixClock {
    let now: Int64
    init(_ c: any UnixClock) { now = c.now }
}

private struct AnyRandom: RandomSource {
    let base: any RandomSource
    init(_ b: any RandomSource) { base = b }
    func bytes(count: Int) -> [UInt8] { base.bytes(count: count) }
}
