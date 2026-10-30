import Crypto

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

    public init(deviceID: String, groupID: String, name: String? = nil, endpoint: LanEndpoint? = nil,
                signingPublic: [UInt8], exchangePublic: [UInt8], pairedAt: Int64 = 0, revoked: Bool = false) {
        self.deviceID = deviceID; self.groupID = groupID; self.name = name; self.endpoint = endpoint
        self.signingPublic = signingPublic; self.exchangePublic = exchangePublic
        self.pairedAt = pairedAt; self.revoked = revoked
    }

    /// Lowercase hex SHA-256 of the signing key.
    public var fingerprint: String { lowerHex(Array(SHA256.hash(data: signingPublic))) }

    public var pinned: PinnedPeer {
        PinnedPeer(deviceID: deviceID, groupID: groupID, signingPublic: signingPublic, exchangePublic: exchangePublic, endpoint: endpoint)
    }

    /// The stored form (the app's encrypted store; never sent).
    public var json: JSONValue {
        .object(["device_id": .string(deviceID), "group_id": .string(groupID), "name": name.map { .string($0) } ?? .null,
                 "endpoint": endpoint?.json ?? .null, "signing_public": .string(Base64.encode(signingPublic)),
                 "exchange_public": .string(Base64.encode(exchangePublic)), "paired_at": .int(pairedAt),
                 "revoked": .bool(revoked)])
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
        self.init(deviceID: device, groupID: group, name: name, endpoint: endpoint, signingPublic: signing,
                  exchangePublic: exchange, pairedAt: paired, revoked: revoked)
    }
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
        return session.handle(raw, reservedIDs: reservedIDs(state), peerCount: state.lanPeers.count, maxPeers: maxPeers)
    }

    static func matches(_ offer: PairingOffer, _ state: SyncGroupState) -> Bool {
        offer.groupID == state.groupID && offer.inviterDeviceID == state.deviceID
            && offer.inviterSigningPublic == state.identity.signingPublicKey
            && offer.inviterExchangePublic == state.identity.exchangePublicKey
    }

    /// `enroll_finish` after Accept: re-checks the offer against the current `state` (group, inviter),
    /// the peer limit and the reserved ids (taken while the prompt was open), then pins the new device and
    /// seals the group key to it. Returns the reply frame payload and the state to commit; a refusal
    /// throws `PairingError.refused` with the reason to answer (`refused` or `full`). Pin nothing on throw.
    public static func acceptEnrollment(_ request: Enrollment.Request, offer: PairingOffer, state: SyncGroupState,
                                        now: Int64, random: some RandomSource) throws -> (reply: [UInt8], state: SyncGroupState) {
        guard matches(offer, state) else { throw PairingError.refused("refused") }
        guard state.lanPeers.count < maxPeers else { throw PairingError.refused("full") }
        guard !reservedIDs(state).contains(request.deviceID) else { throw PairingError.refused("refused") }
        let peer = LanPeer(deviceID: request.deviceID, groupID: state.groupID, name: request.name, endpoint: request.endpoint,
                           signingPublic: request.signingPublic, exchangePublic: request.exchangePublic, pairedAt: now)
        let newState: SyncGroupState
        do { newState = try adding(peer, to: state) } catch { throw PairingError.refused("full") }
        let reply = try Enrollment.sealReply(inviter: state.identity, offer: offer, request: request,
                                             groupKey: try state.groupKey(), random: random)
        return (reply, newState)
    }
}
