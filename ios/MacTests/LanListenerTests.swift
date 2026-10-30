import XCTest
import CryptoKit
import LGKCore
@testable import AppSharedMac

// MARK: helpers

private let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

private func vectorData(_ name: String) throws -> [UInt8] {
    Array(try Data(contentsOf: repo.appendingPathComponent("tests/vectors/sync/" + name)))
}
private func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
private func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { return a }; return [] }
private func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }
private func vec(_ name: String) throws -> [String: JSONValue] { obj(try CanonicalJSON.parse(try vectorData(name))) }
private func hex(_ s: String) -> [UInt8] {
    var out: [UInt8] = []; var i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return out
}

private let groupID = "5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64"
private let install = "mac-install-0001"

private func identity(_ who: String) throws -> DeviceIdentity {
    let p = obj(obj(obj(try vec("identities.json")["devices"])[who])["private"])
    return try DeviceIdentity(deviceID: str(p["device_id"]), signingPrivate: try Base64.decodeStrict(str(p["signing_private"])),
                              exchangePrivate: try Base64.decodeStrict(str(p["exchange_private"])))
}
private func vectorKey() throws -> [UInt8] { hex(str(obj(try vec("lan/expected_lan.json")["reply"])["key_hex"])) }

private final class TestStore: ItemStore, @unchecked Sendable {
    private let lock = NSLock()
    private var snap: StoreSnapshot
    private(set) var commits = 0
    init(_ s: StoreSnapshot = StoreSnapshot()) { snap = s }
    var snapshot: StoreSnapshot { lock.withLock { snap } }
    func load() throws -> StoreSnapshot { lock.withLock { snap } }
    func commit(_ change: StoreChange) throws {
        try lock.withLock {
            guard change.baseRevision == snap.revision else { throw LocalStoreError.stale(expected: change.baseRevision, actual: snap.revision) }
            snap = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: snap.revision + 1)
            commits += 1
        }
    }
}

private final class TestCounters: CounterStore, @unchecked Sendable {
    private let lock = NSLock()
    private var out: Int64 = 0
    var inbound: [String: Int64] = [:]
    func persistedHelloCounter() throws -> Int64 { lock.withLock { out } }
    func persistHelloCounter(_ last: Int64) throws { lock.withLock { out = last } }
    func lastAcceptedCounter(peer: String) throws -> Int64 { lock.withLock { inbound[peer] ?? 0 } }
    func setLastAcceptedCounter(_ counter: Int64, peer: String) throws { lock.withLock { inbound[peer] = counter } }
    func reset() { lock.withLock { inbound = [:] } }
}

private struct Clock: UnixClock { let now: Int64 }
private final class Mono: MonotonicClock, @unchecked Sendable {
    private let lock = NSLock()
    private var s: Double
    init(_ s: Double = 1000) { self.s = s }
    var seconds: Double { lock.withLock { s } }
    func advance(_ d: Double) { lock.withLock { s += d } }
}

private final class QueueRandom: RandomSource, @unchecked Sendable {
    private let lock = NSLock()
    private var queue: [[UInt8]]
    init(_ q: [[UInt8]]) { queue = q }
    func bytes(count: Int) -> [UInt8] {
        lock.withLock { queue.isEmpty ? SystemRandomSource().bytes(count: count) : queue.removeFirst() }
    }
}

/// A scripted connection: frames to hand out, and a hook that turns what the host sent into the next frame.
private final class ScriptSocket: HostSocket, @unchecked Sendable {
    private let lock = NSLock()
    private var incoming: [[UInt8]]
    private(set) var sent: [[UInt8]] = []
    private(set) var closed = false
    let onSend: @Sendable ([UInt8]) -> [UInt8]?
    init(_ frames: [[UInt8]], onSend: @escaping @Sendable ([UInt8]) -> [UInt8]? = { _ in nil }) { incoming = frames; self.onSend = onSend }
    func receiveFrame(limit: Int, deadline: Date) async throws -> [UInt8] {
        let f: [UInt8]? = lock.withLock { incoming.isEmpty ? nil : incoming.removeFirst() }
        guard let f, f.count - 4 <= limit else { throw LanListenError.cannotListen("no frame") }
        return f
    }
    func send(_ bytes: [UInt8], deadline: Date) async throws {
        lock.withLock { sent.append(bytes) }
        if let next = onSend(bytes) { lock.withLock { incoming.append(next) } }
    }
    func close() { lock.withLock { closed = true } }
}

private func noteRecord(_ i: Int, title: String) -> (String, JSONValue) {
    let id = String(format: "00000000-0000-4000-8000-%012d", i)
    let r: JSONValue = .object(["id": .string(id), "kind": .string("note"), "title": .string("\(title) \(i)"), "created_at": .int(1_700_000_000),
                                "updated_at": .int(1_700_000_000 + Int64(i)), "favorite": .bool(false), "tags": .array([]),
                                "payload": .object(["body": .string("body \(i)"), "fields": .array([]), "template_id": .null])])
    let normal = try! Normalise.normalForm(ns: .item, record: r)
    return (id, Wrapper.make(ns: .item, record: normal))
}

private struct RecordingLan: LanTransporting {
    final class Log: @unchecked Sendable {
        private let lock = NSLock()
        private var peers: [String] = []
        func add(_ p: String) { lock.withLock { peers.append(p) } }
        var dialled: [String] { lock.withLock { peers } }
    }
    let log = Log()
    func exchangeViews(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                       ownCounter: Int64) async throws -> [ItemState] {
        log.add(peer.deviceID)
        return []
    }
    func enroll(endpoint: LanEndpoint, request: [UInt8], onConnected: @escaping @Sendable () -> Void) async throws -> [UInt8] {
        throw LanSocketError("not used")
    }
}

@MainActor
private func waitUntil(_ timeout: TimeInterval = 20, _ condition: () -> Bool) async throws {
    let end = Date().addingTimeInterval(timeout)
    while !condition() {
        guard Date() < end else { throw LanListenError.cannotListen("condition not met in time") }
        try await Task.sleep(nanoseconds: 10_000_000)
    }
}

// MARK: tests

/// Phase 4 Task 5: the Mac hosts Wi-Fi sync (listener, limits, pairing, serving, outbound dialling).
@MainActor
final class LanListenerTests: XCTestCase {
    private func liveDeps(_ keychain: InMemoryKeychainVault, lan: (any LanTransporting)? = nil) -> (SyncDependencies, HelloCounterSource) {
        var deps = SyncDependencies.live(keychain: keychain)
        let counters = HelloCounterSource(store: VaultCounterStore(vault: keychain), clock: SystemClock())
        deps.lan = lan ?? LiveLanTransport(dialer: NWLanDialer(browseForPrompt: false), counters: counters,
                                           random: SystemRandomSource(), clock: SystemClock())
        deps.autoFill = NoAutoFillRefresh()
        deps.localSubnet = { nil }
        return (deps, counters)
    }

    // MARK: pairing and sync over loopback

    func testLoopbackPairAndSync() async throws {
        let (macID, macNote) = noteRecord(1, title: "From Mac")
        let (phoneID, phoneNote) = noteRecord(2, title: "From iPhone")
        let macStore = TestStore(StoreSnapshot(records: [macID: macNote], meta: [:], sync: nil, revision: 1))
        let (macDeps, macCounters) = liveDeps(InMemoryKeychainVault())
        let host = LanHost(store: macStore, deps: macDeps, counters: macCounters)
        host.allowsLoopbackForTests = true
        let started = await host.start(host: "127.0.0.1", port: 0)
        XCTAssertTrue(started, host.listenError ?? "")
        defer { host.shutdown() }
        let endpoint = try XCTUnwrap(host.endpoint)
        XCTAssertEqual(endpoint.host, "127.0.0.1")
        XCTAssertNotEqual(endpoint.port, 0)

        XCTAssertEqual(host.showQR(), .shown)
        let qr = try XCTUnwrap(host.pairing.qrText)
        XCTAssertTrue(qr.hasPrefix("lgk-pair:"))
        XCTAssertEqual(try PairingOffer.parseQR(qr).endpoint, endpoint)
        XCTAssertEqual(host.pairing.copyCodeText(), qr)
        XCTAssertEqual(host.pairing.message, "Code text copied.")
        let group = try XCTUnwrap(macStore.snapshot.sync)   // a Wi-Fi group was created for the offer
        XCTAssertFalse(group.hasFolder)

        // The iPhone's sync client joins with the code text.
        let phoneStore = TestStore(StoreSnapshot(records: [phoneID: phoneNote], meta: [:], sync: nil, revision: 1))
        let (phoneDeps, _) = liveDeps(InMemoryKeychainVault())
        let phone = SyncCoordinator(store: phoneStore, deps: phoneDeps)
        let join = Task { await phone.joinByQR(qr) }
        try await waitUntil { host.pairing.stage == .confirm && phone.verificationCode != nil }
        let request = try XCTUnwrap(host.pairing.request)
        XCTAssertEqual(request.name, SyncWording.deviceName)
        XCTAssertEqual(request.code, HostPairingModel.formatCode(try XCTUnwrap(phone.verificationCode)))
        XCTAssertEqual(request.fingerprint.count, 19)
        XCTAssertEqual(macStore.snapshot.sync?.lanPeers, [])   // nothing pinned before Accept
        XCTAssertTrue(host.pairing.decide(true, deviceID: request.deviceID))
        let joined = await join.value
        XCTAssertTrue(joined, phone.actionError ?? "")

        // Pinned once, with no endpoint (a phone always connects to the Mac).
        let peers = try XCTUnwrap(macStore.snapshot.sync?.lanPeers)
        XCTAssertEqual(peers.count, 1)
        XCTAssertNil(peers[0].endpoint)
        XCTAssertEqual(host.pairing.stage, .paired)
        XCTAssertEqual(host.pairing.paired?.message.hasSuffix("If you don't recognise it, choose Undo."), true)
        XCTAssertEqual(host.pairing.paired?.name, SyncWording.shortID(peers[0].deviceID))
        XCTAssertTrue(host.pairing.paired?.message.hasPrefix("Paired: Device ") == true)
        // The first sync ran over loopback both ways: each side has the other's item.
        XCTAssertEqual(phoneStore.snapshot.sync?.groupID, group.groupID)
        XCTAssertNotNil(phoneStore.snapshot.records[macID])
        XCTAssertNotNil(macStore.snapshot.records[phoneID])
        XCTAssertEqual(host.server?.responder.lastReport?.wrote, true)
        XCTAssertTrue(phone.issues.isEmpty, "\(phone.issues)")

        // A second run still works (hello counters increase), and the replayed code is used up.
        await phone.sync(.manual)
        XCTAssertTrue(phone.issues.isEmpty, "\(phone.issues)")
        let reply = try await SocketEnroller(dialer: NWLanDialer(browseForPrompt: false))
            .enroll(endpoint: endpoint, request: try Enrollment.buildRequest(offer: try PairingOffer.parseQR(qr), identity: try identity("C"),
                                                                            random: SystemRandomSource(), now: SystemClock()))
        XCTAssertEqual(reply, try Enrollment.refusal("used-or-expired"))

        // Undo removes the device again (revoked, kept listed): its next sync is refused.
        XCTAssertTrue(host.pairing.undo())
        XCTAssertEqual(macStore.snapshot.sync?.lanPeers.first?.revoked, true)
        await phone.sync(.manual)
        XCTAssertFalse(phone.issues.isEmpty)
    }

    // MARK: limits

    func testInboundLimits() {
        var l = InboundLimits()
        let a = "192.168.1.5", now = 100.0
        // One unauthenticated connection per address.
        XCTAssertTrue(l.reserve(1, address: a, now: now))
        XCTAssertFalse(l.reserve(2, address: a, now: now))
        // Once it sent a verified hello, the address may hold a second (2 per address), not a third.
        l.authenticated(1, now: now)
        XCTAssertTrue(l.reserve(2, address: a, now: now))
        l.authenticated(2, now: now)
        XCTAssertFalse(l.reserve(3, address: a, now: now))
        l.release(1); l.release(2)
        XCTAssertEqual(l.count, 0)

        // Three unauthenticated connections per /24, and one slot kept for verified addresses.
        XCTAssertTrue(l.reserve(10, address: "192.168.1.6", now: now))
        XCTAssertTrue(l.reserve(11, address: "192.168.1.7", now: now))
        XCTAssertTrue(l.reserve(12, address: "192.168.1.8", now: now))
        XCTAssertFalse(l.reserve(13, address: "10.0.0.9", now: now))     // the 4th slot is reserved
        XCTAssertTrue(l.reserve(14, address: a, now: now))                // a verified address may take it
        XCTAssertEqual(l.count, 4)
        XCTAssertFalse(l.reserve(15, address: a, now: now))               // 4 in total
        l.release(14); l.release(12)
        XCTAssertTrue(l.reserve(16, address: "10.0.0.9", now: now))       // other network
        XCTAssertFalse(l.reserve(17, address: "192.168.1.9", now: now))   // reserved slot again
        l.release(16)
        XCTAssertTrue(l.reserve(18, address: "192.168.1.9", now: now))
        XCTAssertFalse(l.reserve(19, address: "192.168.1.10", now: now))  // reserved slot (and /24 full)

        // A verified address loses its privilege after 15 minutes.
        var v = InboundLimits()
        XCTAssertTrue(v.reserve(1, address: a, now: 0)); v.authenticated(1, now: 0); v.release(1)
        XCTAssertTrue(v.reserve(2, address: "192.168.2.1", now: 1))
        XCTAssertTrue(v.reserve(3, address: "192.168.3.1", now: 1))
        XCTAssertTrue(v.reserve(4, address: "192.168.4.1", now: 1))
        XCTAssertTrue(v.reserve(5, address: a, now: 899))
        v.release(5)
        XCTAssertFalse(v.reserve(6, address: a, now: 901))

        // Prefixes: /24, /64, IPv4-mapped as IPv4, zone ids dropped.
        XCTAssertEqual(InboundLimits.prefix("192.168.1.77"), "192.168.1.0/24")
        XCTAssertEqual(InboundLimits.prefix("::ffff:192.168.1.77"), "192.168.1.0/24")
        XCTAssertEqual(InboundLimits.prefix("fe80::1%en0"), InboundLimits.prefix("fe80::2"))
        XCTAssertNotEqual(InboundLimits.prefix("fd00:0:0:1::1"), InboundLimits.prefix("fd00:0:0:2::1"))
        XCTAssertEqual(LanListenLimits.maxFirstFrameBytes, 64 * 1024)
        XCTAssertEqual(LanListenLimits.socketSeconds, 5)
        XCTAssertEqual(LanListenLimits.firstFrameSeconds, 2)
        XCTAssertEqual(LanListenLimits.connectSeconds, 3)
    }

    func testOversizedOrSilentFirstFrameClosed() async throws {
        let store = TestStore()
        let responder = LanResponder(store: store, installID: install, counters: HelloCounterSource(store: TestCounters(), clock: Clock(now: 0)),
                                     random: SystemRandomSource(), clock: Clock(now: 1))
        let session = LanHostSession(responder: responder, enrollment: nil)
        // An enrollment request while no code is shown: dropped without an answer.
        let enrollSocket = ScriptSocket([try LanTransport.encodeFrame(try vectorData("lan/enroll_request.bin"))])
        let outcome1 = await session.handle(enrollSocket)
        XCTAssertEqual(outcome1, .closed)
        XCTAssertTrue(enrollSocket.sent.isEmpty); XCTAssertTrue(enrollSocket.closed)
        // A first frame over 64 KiB, or none: closed unanswered.
        let big = ScriptSocket([try LanTransport.encodeFrame([UInt8](repeating: 0x7B, count: 64 * 1024 + 1))])
        let outcome2 = await session.handle(big)
        XCTAssertEqual(outcome2, .closed)
        XCTAssertTrue(big.sent.isEmpty)
        let silent = ScriptSocket([])
        let outcome3 = await session.handle(silent)
        XCTAssertEqual(outcome3, .closed)
        // A hello of a device that is not paired: closed unanswered.
        let hello = ScriptSocket([try vectorData("lan/hello_initiator.bin")])
        let outcome4 = await session.handle(hello)
        XCTAssertEqual(outcome4, .closed)
        XCTAssertTrue(hello.sent.isEmpty)
    }

    // MARK: locking and addresses

    func testNotListeningWhileLocked() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-lanhost-\(UUID().uuidString)", isDirectory: true)
        let suite = "lgk-lanhost-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(at: dir); UserDefaults().removePersistentDomain(forName: suite) }
        let settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(),
                             kdfParams: .init(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1))
        let lock = MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), startTimer: false)
        let (deps, counters) = liveDeps(InMemoryKeychainVault())
        XCTAssertNil(LanHost.make(lock: lock, deps: deps, counters: counters))   // locked: no host
        await lock.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertEqual(lock.state, .unlocked)
        let host = try XCTUnwrap(LanHost.make(lock: lock, deps: deps, counters: counters))
        // The host's merges commit through the Recently deleted hook too.
        let hostSource = try XCTUnwrap(host.store.base as? SyncSourceStore)
        XCTAssertTrue((hostSource.local as AnyObject?) === lock)
        host.allowsLoopbackForTests = true
        let started = await host.start(host: "127.0.0.1", port: 0)
        XCTAssertTrue(started)
        XCTAssertTrue(host.isListening)
        XCTAssertEqual(host.showQR(), .shown)
        let port = try XCTUnwrap(host.endpoint?.port)

        lock.lock()
        XCTAssertFalse(host.isListening)
        XCTAssertNil(host.server)
        XCTAssertEqual(host.pairing.stage, .idle)
        XCTAssertEqual(host.showQR(), .notListening)
        let restarted = await host.start(host: "127.0.0.1", port: 0)
        XCTAssertFalse(restarted)
        // Nothing accepts connections on the old port any more.
        do {
            let s = try await NWLanDialer(timeout: 1, browseForPrompt: false).dial(try LanEndpoint(validating: "127.0.0.1", port: port))
            try await s.send(try LanTransport.encodeFrame(try vectorData("lan/hello_initiator.bin")))
            _ = try await s.receiveFrame()
            XCTFail("the listener must be stopped")
        } catch {}
        let issues = await host.syncPeers()
        XCTAssertEqual(issues, [])
    }

    func testPublicAddressRefused() async throws {
        for text in ["8.8.8.8:47821", "127.0.0.1:47821", "0.0.0.0:47821", "[2001:db8::1]:47821"] {
            XCTAssertEqual(LanAddressPicker.validate(text), .failure(LanAddressError(LanAddressPicker.privateText)), text)
        }
        XCTAssertEqual(LanAddressPicker.validate("192.168.1.20:80"), .failure(LanAddressError(LanAddressPicker.portText)))
        XCTAssertEqual(LanAddressPicker.validate("mac.local:47821"), .failure(LanAddressError(LanAddressPicker.nameText)))
        XCTAssertEqual(LanAddressPicker.validate("fe80::1:47821"), .failure(LanAddressError(LanAddressPicker.bracketText)))
        XCTAssertEqual(LanAddressPicker.validate(""), .failure(LanAddressError(LanAddressPicker.emptyText)))
        XCTAssertEqual(try LanAddressPicker.validate(" 192.168.1.20:47822 ").get(), try LanEndpoint(validating: "192.168.1.20", port: 47822))
        XCTAssertEqual(try LanAddressPicker.validate("[fe80::1]:47821").get().host, "fe80::1")

        // Candidates: private IPv4 on en* only (no VPN/utun, bridge or public), link-local last.
        let found = LanAddressPicker.candidates([
            LanInterfaceAddress(interface: "utun3", address: "10.8.0.2"),
            LanInterfaceAddress(interface: "en1", address: "169.254.10.2"),
            LanInterfaceAddress(interface: "en0", address: "192.168.1.20"),
            LanInterfaceAddress(interface: "en0", address: "8.8.4.4"),
            LanInterfaceAddress(interface: "bridge0", address: "192.168.2.1"),
            LanInterfaceAddress(interface: "lo0", address: "127.0.0.1"),
            LanInterfaceAddress(interface: "en5", address: "10.0.0.7"),
        ])
        XCTAssertEqual(found.map(\.address), ["192.168.1.20", "10.0.0.7", "169.254.10.2"])
        XCTAssertEqual(LanAddressPicker.suggestion(current: nil, candidates: found), try LanEndpoint(validating: "192.168.1.20", port: 47821))
        let chosen = try LanEndpoint(validating: "10.0.0.7", port: 50000)
        XCTAssertEqual(LanAddressPicker.suggestion(current: chosen, candidates: found), chosen)   // the user's choice stays
        XCTAssertEqual(LanAddressPicker.defaultPort, 47821)

        // The host never listens on a public or (outside tests) loopback address.
        let (deps, counters) = liveDeps(InMemoryKeychainVault())
        let host = LanHost(store: TestStore(), deps: deps, counters: counters)
        let publicStart = await host.start(host: "127.0.0.1", port: 0)
        XCTAssertFalse(publicStart)
        XCTAssertFalse(host.isListening)
        XCTAssertEqual(host.listenError, LanAddressPicker.privateText)
        XCTAssertFalse(LanAddressPicker.isHostable("8.8.8.8", allowLoopback: true))
        XCTAssertFalse(LanAddressPicker.isHostable("127.0.0.1"))
        XCTAssertEqual(host.showQR(), .notListening)
        host.licenceOnly = true   // a free Mac pairs too (licence-only, inside its listen window); here nothing listens
        XCTAssertEqual(host.showQR(), .notListening)
    }

    // MARK: outbound dialling

    func testOutboundDialsPeersWithEndpoints() async throws {
        let gk = try vectorKey()
        func peer(_ who: String, endpoint: LanEndpoint?, revoked: Bool = false) throws -> LanPeer {
            let i = try identity(who)
            return LanPeer(deviceID: i.deviceID, groupID: groupID, name: who, endpoint: endpoint, signingPublic: i.signingPublicKey,
                           exchangePublic: i.exchangePublicKey, pairedAt: 1, revoked: revoked)
        }
        let pc = try peer("B", endpoint: try LanEndpoint(validating: "192.168.1.31", port: 48202))
        let phone = try peer("C", endpoint: nil)
        let gone = LanPeer(deviceID: "d4444444-0000-4000-8000-00000000000d", groupID: groupID, name: "Old PC",
                           endpoint: try LanEndpoint(validating: "192.168.1.32", port: 47821),
                           signingPublic: [UInt8](repeating: 4, count: 32), exchangePublic: [UInt8](repeating: 5, count: 32), revoked: true)
        let keychain = InMemoryKeychainVault()
        try keychain.writeSlot(.installID, Array(install.utf8))
        let store = TestStore(StoreSnapshot(sync: SyncGroupState(groupID: groupID, epoch: 1, key: gk, identity: try identity("A"),
                                                                 installID: install, hasFolder: false, lanPeers: [pc, phone, gone])))
        let lan = RecordingLan()
        let (deps, counters) = liveDeps(keychain, lan: lan)
        let host = LanHost(store: store, deps: deps, counters: counters)
        let notListening = await host.syncPeers()
        XCTAssertEqual(notListening, [SyncIssue("lan-not-listening")])
        host.allowsLoopbackForTests = true
        let started = await host.start(host: "127.0.0.1", port: 0)
        XCTAssertTrue(started)
        defer { host.shutdown() }
        _ = await host.syncPeers()
        XCTAssertEqual(lan.log.dialled, [pc.deviceID])   // only the listening, unrevoked peer
    }

    // MARK: Windows interop (Python-generated initiator frames)

    func testWindowsEnrollmentRequestsInterop() async throws {
        let lanVec = try vec("lan/expected_lan.json")
        let offer = try PairingOffer.parseQR(str(lanVec["qr_payload"]))
        let a = try identity("A"), b = try identity("B")
        let store = TestStore(StoreSnapshot(sync: SyncGroupState(groupID: groupID, epoch: 1, key: try vectorKey(), identity: a,
                                                                 installID: install, hasFolder: false)))
        let mono = Mono()
        let clock = Clock(now: 1790000030)
        let model = HostPairingModel(store: store, random: SystemRandomSource(), clock: clock, monotonic: mono)
        let responder = LanResponder(store: store, installID: install, counters: HelloCounterSource(store: TestCounters(), clock: clock),
                                     random: SystemRandomSource(), clock: clock)

        // Request with an endpoint (a Windows PC): shown with its name and code, accepted, pinned.
        let handler = try model.arm(try OfferSession(offer: offer, inviter: a, wall: clock, monotonic: mono))
        let session = LanHostSession(responder: responder, enrollment: handler)
        let raw = try vectorData("lan/enroll_request.bin")
        let socket = ScriptSocket([try LanTransport.encodeFrame(raw)])
        let run = Task { await session.handle(socket) }
        try await waitUntil { model.stage == .confirm }
        let req = obj(lanVec["request"])
        XCTAssertEqual(model.request?.name, str(req["name"]))
        XCTAssertEqual(model.request?.code, HostPairingModel.formatCode(str(req["verification_code"])))
        XCTAssertEqual(model.request?.fingerprint, HostPairingModel.fingerprintText(b.fingerprint))
        XCTAssertEqual(model.secondsLeft, 60)
        XCTAssertFalse(model.decide(true, deviceID: "someone-else"))
        XCTAssertTrue(model.decide(true, deviceID: b.deviceID))
        let outcome = await run.value
        XCTAssertEqual(outcome, .enrollmentAnswered)
        let reply = try LanTransport.decodeFrame(try XCTUnwrap(socket.sent.first))
        let endpoint = try LanEndpoint(validating: "192.168.1.31", port: 48202)
        let opened = try Enrollment.openReply(offer: offer, identity: b, raw: reply, endpoint: endpoint, name: str(req["name"]))
        XCTAssertEqual(opened.key, try vectorKey())
        XCTAssertEqual(opened.groupID, groupID)
        XCTAssertEqual(store.snapshot.sync?.lanPeers.map(\.deviceID), [b.deviceID])
        XCTAssertEqual(store.snapshot.sync?.lanPeers.first?.endpoint, endpoint)
        XCTAssertEqual(model.stage, .paired)

        // The same request again: used up, with the Windows refusal bytes.
        let replay = ScriptSocket([try LanTransport.encodeFrame(raw)])
        _ = await session.handle(replay)
        let refusals = obj(obj(lanVec["framing"])["refusals_hex"])
        XCTAssertEqual(try LanTransport.decodeFrame(try XCTUnwrap(replay.sent.first)), hex(str(refusals["used-or-expired"])))

        // A request without an endpoint (an iPhone), declined: the Windows "declined" refusal, nothing pinned.
        let store2 = TestStore(StoreSnapshot(sync: SyncGroupState(groupID: groupID, epoch: 1, key: try vectorKey(), identity: a,
                                                                  installID: install, hasFolder: false)))
        let model2 = HostPairingModel(store: store2, random: SystemRandomSource(), clock: clock, monotonic: mono)
        let handler2 = try model2.arm(try OfferSession(offer: offer, inviter: a, wall: clock, monotonic: mono))
        let declineSocket = ScriptSocket([try LanTransport.encodeFrame(try vectorData("lan/enroll_request_no_endpoint.bin"))])
        let run2 = Task { await LanHostSession(responder: responder, enrollment: handler2).handle(declineSocket) }
        try await waitUntil { model2.stage == .confirm }
        XCTAssertEqual(model2.request?.code, HostPairingModel.formatCode(str(obj(lanVec["request_no_endpoint"])["verification_code"])))
        XCTAssertTrue(model2.decide(false, deviceID: b.deviceID))
        _ = await run2.value
        XCTAssertEqual(try LanTransport.decodeFrame(try XCTUnwrap(declineSocket.sent.first)), hex(str(refusals["declined"])))
        XCTAssertEqual(store2.snapshot.sync?.lanPeers, [])
        XCTAssertEqual(model2.message, HostPairingModel.declinedText)
        XCTAssertFalse(model2.decide(true, deviceID: b.deviceID))
    }

    func testUnansweredRequestDeclinesItself() async throws {
        let offer = try PairingOffer.parseQR(str(try vec("lan/expected_lan.json")["qr_payload"]))
        let a = try identity("A")
        let store = TestStore(StoreSnapshot(sync: SyncGroupState(groupID: groupID, epoch: 1, key: try vectorKey(), identity: a,
                                                                 installID: install, hasFolder: false)))
        let mono = Mono(), clock = Clock(now: 1790000030)
        let model = HostPairingModel(store: store, random: SystemRandomSource(), clock: clock, monotonic: mono)
        model.acceptSeconds = 0.05
        XCTAssertEqual(Enrollment.acceptTimeoutSeconds, 60)
        let handler = try model.arm(try OfferSession(offer: offer, inviter: a, wall: clock, monotonic: mono))
        let reply = await handler.enroll(try vectorData("lan/enroll_request.bin"))
        XCTAssertEqual(reply, try Enrollment.refusal("declined"))
        XCTAssertEqual(model.stage, .declined)
        XCTAssertEqual(store.snapshot.sync?.lanPeers, [])
        // Closing disarms the offer: later requests get no answer.
        model.close()
        let late = await handler.enroll(try vectorData("lan/enroll_request.bin"))
        XCTAssertNil(late)
    }

    func testSecondRequestWhileWaitingDeclined() async throws {
        let lanVec = try vec("lan/expected_lan.json")
        let offer = try PairingOffer.parseQR(str(lanVec["qr_payload"]))
        let a = try identity("A")
        let store = TestStore(StoreSnapshot(sync: SyncGroupState(groupID: groupID, epoch: 1, key: try vectorKey(), identity: a,
                                                                 installID: install, hasFolder: false)))
        let mono = Mono(), clock = Clock(now: 1790000030)
        let model = HostPairingModel(store: store, random: SystemRandomSource(), clock: clock, monotonic: mono)
        let session = try OfferSession(offer: offer, inviter: a, wall: clock, monotonic: mono)
        _ = try model.arm(session)
        let first = try XCTUnwrap(try { () -> Enrollment.Request? in
            if case .verified(let r) = session.handle(try vectorData("lan/enroll_request.bin")) { return r }; return nil }())
        let waiting = Task { await model.ask(first, session: session) }
        try await waitUntil { model.stage == .confirm }
        let shown = try XCTUnwrap(model.request)
        // A second request while the first waits: declined at once; the first stays on screen.
        let second = await model.ask(first, session: session)
        XCTAssertFalse(second)
        XCTAssertEqual(model.stage, .confirm)
        XCTAssertEqual(model.request, shown)
        XCTAssertFalse(model.decide(true, deviceID: "c3333333-0000-4000-8000-00000000000c"))
        XCTAssertTrue(model.decide(true, deviceID: shown.deviceID))
        let accepted = await waiting.value
        XCTAssertTrue(accepted)
    }

    func testStopOrRestartDuringBind() async throws {
        let (deps, counters) = liveDeps(InMemoryKeychainVault())
        let host = LanHost(store: TestStore(), deps: deps, counters: counters)
        host.allowsLoopbackForTests = true
        // Wi-Fi sync turned off while the first bind is in flight: nothing keeps listening.
        host.afterBindForTests = { [weak host] in host?.afterBindForTests = nil; host?.stop() }
        let first = await host.start(host: "127.0.0.1", port: 0)
        XCTAssertFalse(first)
        XCTAssertFalse(host.isListening)
        XCTAssertNil(host.server)
        // Two overlapping starts: only the later one is kept, exactly one server.
        var inner = false
        host.afterBindForTests = { [weak host] in
            guard let host, !inner else { return }
            inner = true
            let ok = await host.start(host: "127.0.0.1", port: 0)
            XCTAssertTrue(ok)
        }
        let outer = await host.start(host: "127.0.0.1", port: 0)
        XCTAssertFalse(outer)
        XCTAssertTrue(host.isListening)
        let server = try XCTUnwrap(host.server)
        XCTAssertTrue(server.isListening)
        XCTAssertEqual(host.endpoint.map { $0.port }, server.boundPort)
        host.shutdown()
        XCTAssertFalse(server.isListening)
    }

    func testListenerFailureStopsHost() async throws {
        let (deps, counters) = liveDeps(InMemoryKeychainVault())
        let host = LanHost(store: TestStore(), deps: deps, counters: counters)
        host.allowsLoopbackForTests = true
        let ok = await host.start(host: "127.0.0.1", port: 0)
        XCTAssertTrue(ok)
        host.server?.onFailed?()
        try await waitUntil { !host.isListening }
        XCTAssertNil(host.endpoint)
        XCTAssertEqual(host.listenError, "Wi-Fi sync stopped. Check the network and turn it on again.")
    }

    func testEndpointValidationRefusesPublicAddresses() throws {
        for h in ["8.8.8.8", "1.1.1.1", "2001:4860::8888", "::ffff:192.168.1.2", "fe80::1%en0"] {
            XCTAssertThrowsError(try LanEndpoint(validating: h, port: 47821), h)
            XCTAssertFalse(LanAddressPicker.isHostable(h, allowLoopback: true), h)
        }
        XCTAssertThrowsError(try LanEndpoint(validating: "192.168.1.2", port: 0))
        // Loopback parses as a LAN endpoint, but the Mac only listens there in DEBUG tests.
        XCTAssertFalse(LanAddressPicker.isHostable("127.0.0.1"))
        XCTAssertFalse(LanAddressPicker.isHostable("::1"))
        XCTAssertTrue(LanAddressPicker.isHostable("192.168.1.2"))
    }

    func testWindowsSessionFramesInterop() async throws {
        let m = try vec("lan/messages.json")
        let conns = arr(m["connections"]).map(obj)
        let a = try identity("A"), b = try identity("B")
        let pinnedB = PinnedPeer(deviceID: b.deviceID, groupID: groupID, signingPublic: b.signingPublicKey,
                                 exchangePublic: b.exchangePublicKey, endpoint: nil)
        let peerA = LanPeer(deviceID: a.deviceID, groupID: groupID, name: "A", signingPublic: a.signingPublicKey,
                            exchangePublic: a.exchangePublicKey, pairedAt: 1)
        let store = TestStore(StoreSnapshot(sync: SyncGroupState(groupID: groupID, epoch: 1, key: try vectorKey(), identity: b,
                                                                 installID: install, hasFolder: false, ownCounter: 4, lanPeers: [peerA])))
        let counters = TestCounters()
        let responder = LanResponder(store: store, installID: install, counters: HelloCounterSource(store: counters, clock: Clock(now: 0)),
                                     random: SystemRandomSource(), clock: Clock(now: 1790000900))
        let session = LanHostSession(responder: responder, enrollment: nil)
        var answers: [[UInt8]] = []
        func connect(_ c: [String: JSONValue]) async throws -> [UInt8] {
            counters.reset()   // every recorded connection uses hello counter 1
            let ini = obj(obj(c["hello"])["initiator"])
            let helloText = Array(str(ini["text"]).utf8)
            let sid = hex(str(c["session_id"]))
            // The request plaintext Python sealed for this connection (opened with the vector key).
            var recorded = try SecureChannel(key: hex(str(c["key"])), sessionID: sid, role: .responder)
            let plain = try recorded.open(try vectorData("lan/" + str(obj(c["request"])["file"])))
            let ephPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: hex(str(ini["ephemeral_private_hex"])))
            let staticShared = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: a.exchangePrivateKey)
                .sharedSecretFromKeyAgreement(with: try Curve25519.KeyAgreement.PublicKey(rawRepresentation: b.exchangePublicKey))
                .withUnsafeBytes { Array($0) }
            let channelBox = ChannelBox()
            let socket = ScriptSocket([try LanTransport.encodeFrame(helloText)]) { sent in
                // The Mac's hello: verify it, derive A's channel from Python's hello text, seal the recorded request.
                guard channelBox.channel == nil, let payload = try? LanTransport.decodeFrame(sent),
                      let hostHello = try? SessionHello.parse(payload), (try? SessionHello.verify(hostHello, pinned: pinnedB, groupID: groupID)) != nil,
                      let pub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: hostHello.ephemeralPublic),
                      let eph = try? ephPriv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes({ Array($0) }),
                      let transcript = try? SecureChannel.transcript(helloText, payload),
                      let key = try? SecureChannel.deriveKey(ephemeralShared: eph, staticShared: staticShared, sessionID: sid, transcript: transcript),
                      var ch = try? SecureChannel(key: key, sessionID: sid, role: .initiator),
                      let frame = try? ch.seal(plain) else { return nil }
                channelBox.channel = ch
                return frame
            }
            let outcome = await session.handle(socket)
            XCTAssertEqual(outcome, .served)
            XCTAssertEqual(socket.sent.count, 2)
            var ch = try XCTUnwrap(channelBox.channel)
            return try ch.open(socket.sent[1])
        }
        for c in conns.prefix(2) { answers.append(try await connect(c)) }
        // Connection 1: the ack Python recorded, byte for byte.
        XCTAssertEqual(answers[0], Array(str(obj(conns[0]["response"])["plaintext"]).utf8))
        // Connection 2: A's view merged (20 items committed) and the Mac's own view sent back in chunks.
        XCTAssertEqual(store.commits, 1)
        XCTAssertEqual(store.snapshot.records.count, 20)
        guard case let .view(g, e, transfer, 0, total, size, first) = try LanMessages.parse(answers[1]) else { return XCTFail("no view") }
        XCTAssertEqual(g, groupID); XCTAssertEqual(e, 1)
        XCTAssertGreaterThanOrEqual(total, 2)
        // The Mac's view opens with the group key and comes from this device.
        var parts = [try Base64.decodeStrict(first)]
        for seq in 1..<total {
            let plain = responder.serve(peer: peerA, request: try LanMessages.encode(.next(transfer: transfer, seq: seq)))
            guard case let .view(_, _, _, s, _, _, v) = try LanMessages.parse(plain), s == seq else { return XCTFail("chunk \(seq)") }
            parts.append(try Base64.decodeStrict(v))
        }
        let whole = Array(parts.joined())
        XCTAssertEqual(Int64(whole.count), size)
        let view = try ViewFile.decode(whole, key: try GroupKey(groupID: groupID, epoch: 1, key: try vectorKey()), expectedDeviceID: b.deviceID)
        XCTAssertEqual(view.states.count, 20)
        // Connection 3 asks for chunk 1 of Python's recorded transfer, which this Mac never sent: refused.
        let third = try await connect(conns[2])
        XCTAssertEqual(try LanMessages.parse(third), .error(reason: "bad-chunk"))
    }
}

private final class ChannelBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: SecureChannel?
    var channel: SecureChannel? {
        get { lock.withLock { value } }
        set { lock.withLock { value = newValue } }
    }
}
