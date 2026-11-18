import Crypto
import Foundation

/// One LAN peer this device lists in its group state (desktop `SyncGroupState.lan_peers` entry:
/// `PairedDevice` + `endpoint` + `name`). A removed peer stays listed with `revoked` so its id can never
/// come back; its keys stay pinned so a hello of it is recognised and refused.
public struct LanPeer: Equatable, Sendable {
    public var deviceID: String
    public var groupID: String
    /// The name the device gave when it enrolled (display only, not authenticated by a key).
    public var name: String?
    /// Where the peer listens; nil when it always initiates (an iPhone).
    public var endpoint: LanEndpoint?
    public var signingPublic: [UInt8]
    public var exchangePublic: [UInt8]
    public var pairedAt: Int64
    public var revoked: Bool
    /// The downgrade pin of LAN protocol version 3 (stored `"hello":3`, desktop `peer_to_entry(sealed=)`): the
    /// peer has used the sealed hello, so its clear-text hello is refused. nil: not pinned. Removed only with
    /// the entry.
    public var hello: Int64?
    /// Stored fields this version does not know, kept as they are (a newer app's entry survives a save here).
    public var extras: [String: JSONValue]

    static let knownFields: Set<String> = ["device_id", "group_id", "name", "endpoint", "signing_public", "exchange_public",
                                           "paired_at", "revoked", "hello"]

    public init(deviceID: String, groupID: String, name: String? = nil, endpoint: LanEndpoint? = nil,
                signingPublic: [UInt8], exchangePublic: [UInt8], pairedAt: Int64 = 0, revoked: Bool = false,
                hello: Int64? = nil, extras: [String: JSONValue] = [:]) {
        self.deviceID = deviceID; self.groupID = groupID; self.name = name; self.endpoint = endpoint
        self.signingPublic = signingPublic; self.exchangePublic = exchangePublic
        self.pairedAt = pairedAt; self.revoked = revoked
        self.hello = hello; self.extras = extras.filter { !Self.knownFields.contains($0.key) }
    }

    /// Pinned to the sealed hello (`hello` is at least 3, desktop `_entry_sealed`).
    public var sealed: Bool { (hello ?? 0) >= LanTransport.version }

    /// Lowercase hex SHA-256 of the signing key.
    public var fingerprint: String { lowerHex(Array(SHA256.hash(data: signingPublic))) }

    public var pinned: PinnedPeer {
        PinnedPeer(deviceID: deviceID, groupID: groupID, signingPublic: signingPublic, exchangePublic: exchangePublic, endpoint: endpoint)
    }

    /// The stored form (the app's encrypted store; never sent).
    public var json: JSONValue {
        var o: [String: JSONValue] = extras
        let known: [String: JSONValue] = [
            "device_id": .string(deviceID), "group_id": .string(groupID), "name": name.map { .string($0) } ?? .null,
            "endpoint": endpoint?.json ?? .null, "signing_public": .string(Base64.encode(signingPublic)),
            "exchange_public": .string(Base64.encode(exchangePublic)), "paired_at": .int(pairedAt),
            "revoked": .bool(revoked)]
        o.merge(known) { _, mine in mine }
        if let hello { o["hello"] = .int(hello) }
        return .object(o)
    }

    public init(json: JSONValue) throws {
        guard case .object(let o) = json, case .string(let device)? = o["device_id"], case .string(let group)? = o["group_id"],
              case .int(let paired)? = o["paired_at"], case .bool(let revoked)? = o["revoked"] else {
            throw LanSyncError("bad-peer", "stored LAN peer is malformed")
        }
        let name: String?
        switch o["name"] {
        case .string(let s)?: name = s
        case .null?, nil: name = nil
        default: throw LanSyncError("bad-peer", "stored LAN peer name is malformed")
        }
        let endpoint: LanEndpoint?
        switch o["endpoint"] {
        case .object(let e)?:
            guard let ep = try? Pairing.endpoint(host: e["host"], port: e["port"]) else { throw LanSyncError("bad-peer", "stored LAN peer endpoint is malformed") }
            endpoint = ep
        case .null?, nil: endpoint = nil
        default: throw LanSyncError("bad-peer", "stored LAN peer endpoint is malformed")
        }
        guard let signing = try? LanTransport.b64(o["signing_public"], length: 32, "signing"),
              let exchange = try? LanTransport.b64(o["exchange_public"], length: 32, "exchange") else {
            throw LanSyncError("bad-peer", "stored LAN peer keys are malformed")
        }
        // `hello`: an integer is the pin; any other value is not one and is kept as it is (desktop `_entry_sealed`).
        var extras = o.filter { !Self.knownFields.contains($0.key) }
        var hello: Int64?
        switch o["hello"] {
        case .int(let h)?: hello = h
        case let other?: extras["hello"] = other
        case nil: break
        }
        self.init(deviceID: device, groupID: group, name: name, endpoint: endpoint, signingPublic: signing,
                  exchangePublic: exchange, pairedAt: paired, revoked: revoked, hello: hello)
        self.extras = extras
    }
}

/// Peers this device pinned to the sealed hello in this unlock session (desktop `SyncState.sealed_peers`); the
/// stored pin is `LanPeer.hello`. Thread-safe.
public final class SealedPeerMemory: @unchecked Sendable {
    private let lock = NSLock()
    private var peers: Set<String> = []
    public init() {}
    public func contains(_ peer: String) -> Bool { lock.withLock { peers.contains(peer) } }
    public func insert(_ peer: String) { lock.withLock { _ = peers.insert(peer) } }
}

/// The LAN peer list of a group state and the host side of accepting an enrollment
/// (desktop `lan_sync._with_peer`, `LanResponder.enroll_verify` / `enroll_finish`, `MAX_LAN_PEERS`).
public enum LanPeers {
    /// Desktop `vault_bridge.MAX_LAN_PEERS`; revoked entries count.
    public static let maxPeers = 16

    public static func entry(_ state: SyncGroupState, _ deviceID: String) -> LanPeer? {
        state.lanPeers.first { $0.deviceID == deviceID }
    }

    /// `state` with `peer` listed (replacing an entry of the same id); `too-many-peers` past `maxPeers`.
    public static func adding(_ peer: LanPeer, to state: SyncGroupState) throws -> SyncGroupState {
        let others = state.lanPeers.filter { $0.deviceID != peer.deviceID }
        guard others.count < maxPeers else { throw LanSyncError("too-many-peers", "at most \(maxPeers) LAN peers") }
        var s = state
        s.lanPeers = others + [peer]
        return s
    }

    /// `state` with `deviceID` marked revoked (kept listed); false when it was not listed.
    public static func revoking(_ deviceID: String, in state: SyncGroupState) -> (SyncGroupState, Bool) {
        var s = state
        guard let i = s.lanPeers.firstIndex(where: { $0.deviceID == deviceID }) else { return (s, false) }
        s.lanPeers[i].revoked = true
        return (s, true)
    }

    /// `state` with the listed peer `deviceID` pinned to the sealed hello (`"hello":3`, desktop `save_sealed`); nil
    /// when it is not listed or already pinned (nothing to save).
    public static func pinningSealed(_ deviceID: String, in state: SyncGroupState) -> SyncGroupState? {
        guard let i = state.lanPeers.firstIndex(where: { $0.deviceID == deviceID }), !state.lanPeers[i].sealed else { return nil }
        var s = state
        s.lanPeers[i].hello = LanTransport.version
        return s
    }

    /// Saves the pin of `deviceID` (`pinningSealed`) in one commit; false when nothing was saved (not listed,
    /// already pinned, or the commit failed).
    @discardableResult
    public static func pinSealed(_ deviceID: String, store: any ItemStore) -> Bool {
        guard let snap = try? store.load(), let state = snap.sync, let next = pinningSealed(deviceID, in: state) else { return false }
        return (try? store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta,
                                              sync: next))) != nil
    }

    /// Device ids a new device may not take (`_reserved_ids`): listed peers (revoked ones too), keyring
    /// members and this device.
    public static func reservedIDs(_ state: SyncGroupState) -> Set<String> {
        Set(state.lanPeers.map(\.deviceID)).union(state.members).union([state.deviceID])
    }

    /// `enroll_verify`: one enrollment request for the armed `session`. An offer that is not of `state`'s
    /// group or not made by this device stops the session and gets the generic refusal; a full peer list
    /// answers `full` before anything is consumed; then `OfferSession.handle` with the reserved ids.
    public static func verifyEnrollment(_ raw: [UInt8], session: OfferSession, state: SyncGroupState?) -> OfferSession.Outcome {
        guard let state, matches(session.offer, state) else {
            let wasListening = session.isListening
            session.stop()
            return wasListening ? OfferSession.refusal("refused") : .close
        }
        return session.handle(raw, reservedIDs: reservedIDs(state), peerCount: state.lanPeers.count, maxPeers: maxPeers) {
            rejoining($0, in: state)
        }
    }

    /// A paired device pairing again under its kept identity (design 2026-11-17, rule 4): `request`'s id is a Wi-Fi
    /// peer of this host that is not revoked, and its signing and exchange keys both equal the ones pinned for it.
    /// Never this host's own id, a revoked id, an id with other keys or an id known only from the folder's member
    /// list (its keys are not compared here): those stay reserved.
    public static func rejoining(_ request: Enrollment.Request, in state: SyncGroupState) -> Bool {
        guard request.deviceID != state.deviceID, let peer = entry(state, request.deviceID), !peer.revoked else { return false }
        return Keyring.constantTimeEqual(peer.signingPublic, request.signingPublic)
            && Keyring.constantTimeEqual(peer.exchangePublic, request.exchangePublic)
    }

    static func matches(_ offer: PairingOffer, _ state: SyncGroupState) -> Bool {
        offer.groupID == state.groupID && offer.inviterDeviceID == state.deviceID
            && offer.inviterSigningPublic == state.identity.signingPublicKey
            && offer.inviterExchangePublic == state.identity.exchangePublicKey
    }

    /// `enroll_finish` after Accept: re-checks the offer against the current `state` (group, inviter),
    /// the peer limit and the reserved ids (taken while the prompt was open), then pins the new device and
    /// seals the group key to it. Returns the reply frame payload and the state to commit; a refusal
    /// throws `PairingError.refused` with the reason to answer (`refused` or `full`). Pin nothing on throw. A rejoin
    /// (`rejoining`) replaces the device's entry instead of adding one.
    /// A device that paired through a version-2 offer (commit-then-reveal) is pinned to the sealed hello at once.
    public static func acceptEnrollment(_ request: Enrollment.Request, offer: PairingOffer, state: SyncGroupState,
                                        now: Int64, random: some RandomSource) throws -> (reply: [UInt8], state: SyncGroupState) {
        guard matches(offer, state) else { throw PairingError.refused("refused") }
        // A rejoin replaces the device's own entry: it is not refused as known and does not count against the limit.
        let again = rejoining(request, in: state)
        guard again || state.lanPeers.count < maxPeers else { throw PairingError.refused("full") }
        guard again || !reservedIDs(state).contains(request.deviceID) else { throw PairingError.refused("refused") }
        var peer = LanPeer(deviceID: request.deviceID, groupID: state.groupID, name: request.name, endpoint: request.endpoint,
                           signingPublic: request.signingPublic, exchangePublic: request.exchangePublic, pairedAt: now,
                           hello: request.reveal != nil ? LanTransport.version : nil)
        if again, let old = entry(state, request.deviceID) {
            // Name, address and pairing time are the new pairing's; the sealed-hello pin is never lowered, and fields
            // of a newer app stay. The host's counters and rollback memory for this id are untouched.
            peer.hello = peer.hello ?? old.hello
            peer.extras = old.extras
        }
        let newState: SyncGroupState
        do { newState = try adding(peer, to: state) } catch { throw PairingError.refused("full") }
        let reply = try Enrollment.sealReply(inviter: state.identity, offer: offer, request: request,
                                             groupKey: try state.groupKey(), random: random)
        return (reply, newState)
    }
}
