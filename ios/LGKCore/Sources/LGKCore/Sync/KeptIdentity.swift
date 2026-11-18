/// This device's identity in a sync group it left (design 2026-11-17 "Keep the device id when a device leaves and
/// rejoins"). Leave sync keeps it; joining the same group again reuses it, so the other devices see the same device
/// under the same id instead of a second row.
///
/// Besides the id and the private keys it holds every counter a peer uses to refuse a replay or rollback from this
/// device id, so a rejoin continues them and never starts lower:
/// * `ownCounter`: the counter of this device's view file. Folder peers keep the last counter they accepted from it
///   (`lastSeen`) and refuse a lower one (`rollback`) or the same one with other bytes (`suspicious-rewrite`).
/// * `generationOffset`: added to the store revision to give the vault generation peers witnessed
///   (`peerGenerations`); a lower generation from this id is reported as a rollback. The revision itself only grows.
/// * `epoch`: the group key epoch it last held; a folder join at a lower epoch does not reuse it.
/// The LAN hello counter is the device's own and survives Leave on its own (`SyncCoordinator.clear`).
///
/// Device-only: stored sealed with the vault next to the group state (`StoreSnapshot.keptIdentity`), never in a
/// record, so never synced, in a view, a backup or an export. At most one per vault.
public struct KeptIdentity: Equatable, Sendable {
    public var identity: DeviceIdentity
    public var groupID: String
    public var epoch: Int64
    public var ownCounter: Int64
    public var generationOffset: Int64

    public init(identity: DeviceIdentity, groupID: String, epoch: Int64, ownCounter: Int64, generationOffset: Int64) {
        self.identity = identity; self.groupID = groupID; self.epoch = epoch
        self.ownCounter = ownCounter; self.generationOffset = generationOffset
    }

    /// What Leave keeps of `state`.
    public init(leaving state: SyncGroupState) {
        self.init(identity: state.identity, groupID: state.groupID, epoch: state.epoch, ownCounter: state.ownCounter,
                  generationOffset: state.generationOffset)
    }

    public var deviceID: String { identity.deviceID }

    /// True when a join of `groupID` uses it (rule 3: the same group only).
    public func fits(groupID: String) -> Bool { RemovalNotice.same(self.groupID, groupID) }

    /// The group state of a join that used it: the joined group's key, this identity and its counters.
    public func joinedState(_ gk: GroupKey, installID: String, hasFolder: Bool) -> SyncGroupState {
        SyncGroupState(groupID: gk.groupID, epoch: gk.epoch, key: gk.key, identity: identity, installID: installID,
                       hasFolder: hasFolder, membersEpoch: gk.epoch, ownCounter: ownCounter,
                       generationOffset: generationOffset)
    }

    static let fields: Set<String> = ["device_id", "signing", "exchange", "group_id", "epoch", "own_counter",
                                      "generation_offset"]

    /// The stored form (inside the vault's sealed state; never sent or written to a folder).
    public var json: JSONValue {
        .object(["device_id": .string(identity.deviceID), "signing": .string(Base64.encode(identity.signingPrivateKey)),
                 "exchange": .string(Base64.encode(identity.exchangePrivateKey)), "group_id": .string(groupID),
                 "epoch": .int(epoch), "own_counter": .int(ownCounter), "generation_offset": .int(generationOffset)])
    }

    /// Throws for anything but the exact stored form.
    public init(json: JSONValue) throws {
        struct Malformed: Error {}
        guard case .object(let o) = json, Set(o.keys) == Self.fields,
              case .string(let device)? = o["device_id"], case .string(let signing)? = o["signing"],
              case .string(let exchange)? = o["exchange"], case .string(let group)? = o["group_id"], Identifier.isValid(group),
              case .int(let epoch)? = o["epoch"], epoch >= 0,
              case .int(let counter)? = o["own_counter"], counter >= 0,
              case .int(let offset)? = o["generation_offset"], offset >= 0,
              let s = try? Base64.decodeStrict(signing), let x = try? Base64.decodeStrict(exchange) else { throw Malformed() }
        self.init(identity: try DeviceIdentity(deviceID: device, signingPrivate: s, exchangePrivate: x), groupID: group,
                  epoch: epoch, ownCounter: counter, generationOffset: offset)
    }
}
