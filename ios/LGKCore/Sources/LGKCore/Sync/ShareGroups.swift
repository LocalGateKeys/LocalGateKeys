/// Share groups: a collection shared with other people through its own sync group (sub-plan 07; desktop
/// `share_group.py`, the Windows behaviour is the spec).
///
/// A shared collection is a second sync group next to the vault's personal one, with its own keyring
/// (`ShareKeyring`), its own device identity and its own removal notices. The keyring carries the share metadata
/// (collection id, sealed name, mode, owner device and Ed25519 key) and the owner's signature over the approved
/// members. The personal group (`StoreSnapshot.sync`) is read only for a clash check and is never changed here.
///
/// - Owner authority is cryptographic: every device pins the owner (device id and key), the collection id and the mode
///   when it creates or joins (`ShareKeyring.Pin`); `adopt` refuses a keyring that changes any of them; at one epoch a
///   keyring may only grow. Members the owner has not approved yet are pending: no removal-notice authority, and they
///   are dropped when the owner removes someone. Losing the owner's device freezes the group (no owner recovery yet).
/// - Pro (`ShareAccess`): creating, joining and syncing need Pro, checked before any key derivation. Approving,
///   removing a member (a security action) and leaving work without it; a lapsed device keeps what it has.
/// - Stored only in the item store's sealed state (`StoreSnapshot.shares`, `ShareRecord`): keys, keyring and the
///   owner's signing key never become records, so they never reach personal sync, a view, a backup or an export.
/// - A collection is shared on this device when one of its share records names it. Its catalog row (`col:`) stays an
///   ordinary personal collection state; another of this person's devices learns the share only as a `csl:` link
///   (mode and role, `shareLinks`).
///
/// Every operation loads the store once and commits once (`StoreChange.shares`); nothing here logs, and no key,
/// password or keyring appears in a description.
public enum ShareGroups {
    /// One member of a share as the owner's screens show it (desktop `Member`).
    public struct Member: Equatable, Sendable, CustomStringConvertible {
        public let deviceID: String
        /// Nil: the name cannot be read ("Unnamed device").
        public let name: String?
        public let addedAt: Int64
        /// The owner signed this member (false: joined, waiting for the owner).
        public let approved: Bool
        public init(deviceID: String, name: String?, addedAt: Int64, approved: Bool) {
            self.deviceID = deviceID; self.name = name; self.addedAt = addedAt; self.approved = approved
        }
        public var description: String { "Member(\(deviceID), approved=\(approved))" }
    }

    /// One share group of this vault (desktop `ShareGroup`).
    public struct Group: Equatable, Sendable, CustomStringConvertible {
        public let groupID: String
        public let collectionID: String
        /// The collection name sealed in the keyring.
        public let name: String
        public let sharedMode: String
        /// The owner's device id in this group.
        public let owner: String
        public let role: ShareRecord.Role
        public let members: [Member]
        /// 1: items sealed with the group key (the share password opens them); 2: with the content key that the owner
        /// wraps only to approved devices (share v2, keyring format 3).
        public let version: Int
        public var description: String {
            "ShareGroup(\(groupID), collection=\(collectionID), mode=\(sharedMode), role=\(role.rawValue), members=\(members.count), version=\(version))"
        }
    }

    static func same(_ a: String, _ b: String) -> Bool { Array(a.utf8) == Array(b.utf8) }

    // MARK: - reading

    /// Every share group of this vault, each checked (`bad-state` for a damaged one).
    public static func records(in snapshot: StoreSnapshot) throws -> [String: ShareRecord] {
        try ShareRecord.decodeAll(snapshot.shares)
    }

    static func record(_ snapshot: StoreSnapshot, _ groupID: String) throws -> (all: [String: ShareRecord], record: ShareRecord) {
        let all = try records(in: snapshot)
        guard let record = all[groupID] else { throw ShareGroupError("not-joined", "this vault is not in that share group") }
        return (all, record)
    }

    /// Every share group, by group id (works without Pro: read access stays).
    public static func list(in snapshot: StoreSnapshot) throws -> [Group] {
        try records(in: snapshot).sorted { scalarOrder($0.key, $1.key) }.map { try group(of: $0.value) }
    }

    /// The group view of one record: its name, mode and members with their names (desktop `_group`).
    public static func group(of record: ShareRecord) throws -> Group {
        guard let bytes = record.state.keyring else { throw ShareRecord.bad("keyring") }
        let ring = try ShareKeyring.parse(bytes)
        let gk = try record.state.groupKey()
        let names = Keyring.memberNames(ring, key: gk)
        let approved = Set((ShareKeyring.approvedMembers(ring) ?? []).map { Array($0.utf8) })
        var members: [Member] = []
        for m in Keyring.arr(Keyring.obj(ring)["members"]) {
            let mo = Keyring.obj(m)
            guard let id = Keyring.str(mo["device_id"]) else { continue }
            let name: String? = names[id] ?? nil
            members.append(Member(deviceID: id, name: name, addedAt: Keyring.int(mo["added_at"]) ?? 0,
                                  approved: approved.contains(Array(id.utf8))))
        }
        return Group(groupID: record.groupID, collectionID: record.collectionID, name: try ShareKeyring.shareName(ring, key: gk),
                     sharedMode: record.pin.sharedMode, owner: record.pin.owner, role: record.role, members: members,
                     version: ShareKeyring.shareVersion(ring) ?? 1)
    }

    /// The key the share's item views are sealed with on this device (desktop `view_key`); nil while it waits for
    /// approval. Share v1: the group key G of an approved member (the owner always). Share v2: the content key C from
    /// this device's content wrap (`ShareKeyring.openContentKey`; `content-key` when the wrap does not open to the
    /// committed key).
    public static func viewKey(of record: ShareRecord) throws -> GroupKey? {
        let ring = try storedRing(record)
        if ShareKeyring.shareVersion(ring) == 2 {
            return try ShareKeyring.openContentKey(ring, identity: record.state.identity)
        }
        let approved = (ShareKeyring.approvedMembers(ring) ?? []).union([record.pin.owner])
        guard approved.contains(where: { same($0, record.state.deviceID) }) else { return nil }
        return try record.state.groupKey()
    }

    /// `viewKey(of:)` of `groupID` (`not-joined` when this vault is not in it).
    public static func viewKey(in snapshot: StoreSnapshot, groupID: String) throws -> GroupKey? {
        try viewKey(of: try record(snapshot, groupID).record)
    }

    /// Whether this device owns share v1 `groupID` (desktop `needs_upgrade`): the share page offers the upgrade to share
    /// v2. False for anything that cannot be read.
    public static func needsUpgrade(in snapshot: StoreSnapshot, groupID: String) -> Bool {
        guard let rec = try? record(snapshot, groupID).record, rec.role == .owner, same(rec.state.deviceID, rec.pin.owner),
              let ring = try? storedRing(rec) else { return false }
        return ShareKeyring.shareVersion(ring) == 1
    }

    /// Members waiting for the owner's approval, with their names: what the owner is shown before approving.
    public static func pendingMembers(in snapshot: StoreSnapshot, groupID: String) throws -> [Member] {
        try group(of: try record(snapshot, groupID).record).members.filter { !$0.approved }
    }

    /// The members the owner removed on this device (oldest first).
    public static func removedMembers(in snapshot: StoreSnapshot, groupID: String) throws -> [ShareRecord.Removed] {
        try record(snapshot, groupID).record.removed
    }

    /// The collection ids the stored share groups name, read as leniently as possible: a damaged store must still
    /// fail closed (every collection it might name, else every collection, counts as shared).
    static func looseCollectionIDs(_ snapshot: StoreSnapshot) -> Set<String> {
        guard let raw = snapshot.shares else { return [] }
        if case .object(let groups) = raw {
            var out = Set<String>()
            var whole = true
            for value in groups.values {
                if case .object(let o) = value, case .string(let c)? = o["collection_id"] { out.insert(c) } else { whole = false }
            }
            if whole { return out }
        }
        return Set(CollectionCatalog.collections(in: snapshot).map(\.id))
    }

    /// Collections this vault holds as a member of a read-only share: local edits there are refused
    /// (`ShareAccess.checkWritable`). Fails closed: if the share groups cannot be read, every collection they might
    /// name is read-only (desktop `read_only_collection_ids`).
    public static func readOnlyCollectionIDs(in snapshot: StoreSnapshot) -> Set<String> {
        guard let all = try? records(in: snapshot) else {
            return ShareAccess.readOnlyCollectionIDs(nil, sharedCollectionIDs: looseCollectionIDs(snapshot))
        }
        let memberships = all.values.map {
            ShareAccess.Membership(collectionID: $0.collectionID, role: $0.role.rawValue, sharedMode: $0.pin.sharedMode)
        }
        return ShareAccess.readOnlyCollectionIDs(memberships, sharedCollectionIDs: [])
    }

    /// `{collection id: link}` of the collections shared on this device, which personal collection sync publishes as
    /// `csl:` links to this person's other devices; nil when the share groups cannot be read (desktop `share_links`).
    /// Only the mode and this device's role ever leave the device.
    public static func shareLinks(in snapshot: StoreSnapshot) -> [String: CollectionShares.Link]? {
        guard let all = try? records(in: snapshot) else { return nil }
        let rows = Set(CollectionCatalog.collections(in: snapshot).map { Array($0.id.utf8) })
        var out: [String: CollectionShares.Link] = [:]
        for record in all.values where rows.contains(Array(record.collectionID.utf8)) {
            out[record.collectionID] = CollectionShares.Link(mode: record.pin.sharedMode, role: record.role.rawValue)
        }
        return out
    }

    /// Collections another of this person's devices holds as a member of a read-only share (a `csl:` link), not shared
    /// on this device itself: edits are refused here too (desktop `linked_read_only_collection_ids`).
    public static func linkedReadOnlyCollectionIDs(in snapshot: StoreSnapshot) -> Set<String> {
        let linked = CollectionCatalog.linkedReadOnlyIDs(in: snapshot)
        guard let all = try? records(in: snapshot) else { return linked }   // unreadable: refuse more, never less
        let here = Set(all.values.map { Array($0.collectionID.utf8) })
        return linked.filter { !here.contains(Array($0.utf8)) }
    }

    /// What personal sync needs from the share groups (`CollectionShares`, 5g passes it on every personal run).
    public static func collectionShares(in snapshot: StoreSnapshot) -> CollectionShares {
        CollectionShares(links: shareLinks(in: snapshot), readOnly: readOnlyCollectionIDs(in: snapshot))
    }

    /// The collections `CollectionCatalog.delete` must refuse: those shared on this device and the read-only ones.
    public static func protectedCollectionIDs(in snapshot: StoreSnapshot) -> Set<String> {
        let here: Set<String>
        if let all = try? records(in: snapshot) { here = Set(all.values.map(\.collectionID)) } else { here = looseCollectionIDs(snapshot) }
        return here.union(readOnlyCollectionIDs(in: snapshot)).union(CollectionCatalog.linkedReadOnlyIDs(in: snapshot))
    }

    // MARK: - writing

    static func commit(_ store: any ItemStore, _ snapshot: StoreSnapshot, records: [String: JSONValue]? = nil,
                       shares: [String: ShareRecord]) throws {
        try store.commit(StoreChange(baseRevision: snapshot.revision, records: records ?? snapshot.records,
                                     meta: snapshot.meta, sync: snapshot.sync, shares: .set(ShareRecord.encode(shares))))
    }

    static func checkInstallID(_ installID: String) throws {
        guard !installID.isEmpty, installID.unicodeScalars.count <= FolderSync.maxInstallID, !installID.contains("\u{0}") else {
            throw ShareGroupError("bad-install-id", "install id must be a non-empty bounded string")
        }
    }

    static func canonical(_ ring: JSONValue) throws -> [UInt8] { try CanonicalJSON.encode(ring, dialect: .utf8) }

    /// A folder reference the stored record can hold (at most `ShareRecord.maxFolderBytes`, as lgk-core
    /// `checkFolder`): a larger one would make every stored share unreadable (`bad-state`), so it is refused before
    /// anything is written.
    static func checkFolder(_ folder: [UInt8]?) throws {
        if let folder, folder.count > ShareRecord.maxFolderBytes {
            throw ShareGroupError("bad-folder", "folder reference too large")
        }
    }

    static func requireOwner(_ record: ShareRecord) throws {
        guard record.role == .owner, same(record.state.deviceID, record.pin.owner) else {
            throw ShareGroupError("not-owner", "only the person who shared the collection does this")
        }
    }

    static func storedRing(_ record: ShareRecord) throws -> JSONValue {
        guard let bytes = record.state.keyring else { throw ShareRecord.bad("keyring") }
        return try ShareKeyring.parse(bytes)
    }

    /// Keyring bytes as the folder holds them (desktop `parse_keyring`): size, strict JSON, an object. Nothing is
    /// authenticated here; `adopt` and the owner and join checks do that.
    static func parseLoose(_ raw: [UInt8]) throws -> JSONValue {
        guard raw.count <= Keyring.maxKeyringBytes else { throw KeyringError("too-large", "\(raw.count) > \(Keyring.maxKeyringBytes)") }
        let value: JSONValue
        do { value = try CanonicalJSON.parse(raw) } catch { throw KeyringError("bad-json", "keyring is not valid JSON") }
        guard case .object = value else { throw KeyringError("bad-keyring", "keyring must be an object") }
        return value
    }

    /// Share `collectionID` (desktop `create_share_group`): a new share group with this device, named `deviceName`, as
    /// its owner. `password` is what the other people type to join (the sync password strength rule). The mode
    /// (`read` / `edit`) is fixed for the life of the group. Refused: `pro-required` (before any key derivation),
    /// `no-collection`, `already-shared` (shared here, or a `csl:` link says another of this person's devices shares
    /// it), `bad-metadata`, then the keyring reasons. `folder`: the host's opaque folder reference, kept with the
    /// record. The host writes the keyring to the folder (`FolderSync.writeShareKeyring`) and undoes with `leave` if
    /// that fails.
    public static func create(store: any ItemStore, collectionID: String, password: String, deviceName: String,
                              sharedMode: String, installID: String, isPro: Bool, folder: [UInt8]? = nil,
                              random: RandomSource, clock: UnixClock) throws -> Group {
        try create(store: store, collectionID: collectionID, password: password, deviceName: deviceName,
                   sharedMode: sharedMode, installID: installID, isPro: isPro, folder: folder, random: random,
                   clock: clock, derive: nil)
    }

    static func create(store: any ItemStore, collectionID: String, password: String, deviceName: String,
                       sharedMode: String, installID: String, isPro: Bool, folder: [UInt8]?, random: RandomSource,
                       clock: UnixClock, derive: Keyring.KeyDerivation?,
                       shareFormat: Int64 = Keyring.shareFormat) throws -> Group {
        try ShareAccess.requirePro(.create, isPro: isPro)
        try checkInstallID(installID)
        try checkFolder(folder)
        let snapshot = try store.load()
        var all = try records(in: snapshot)
        guard let row = CollectionCatalog.collections(in: snapshot).first(where: { same($0.id, collectionID) }) else {
            throw ShareGroupError("no-collection", "that collection does not exist")
        }
        // A link: another of this person's devices shares it (as owner or member); sharing it again from here would
        // hand someone else's items to new people.
        if all.values.contains(where: { same($0.collectionID, collectionID) })
            || snapshot.records[CollectionStates.linkPrefix + collectionID] != nil {
            throw ShareGroupError("already-shared", "that collection is already shared")
        }
        let spec = ShareKeyring.Spec(collectionID: collectionID, name: row.name, sharedMode: sharedMode)
        try spec.check()
        let identity = try DeviceIdentity.generate(random: random)
        // Share v2 (`shareFormat` 3); 2 (share v1) only for the migration tests.
        let (ring, gk) = try ShareKeyring.create(password: password, identity: identity, name: deviceName, spec: spec,
                                                 random: random, now: clock, derive: derive ?? Keyring.productionKDF,
                                                 shareFormat: shareFormat)
        let state = SyncGroupState(groupID: gk.groupID, epoch: gk.epoch, key: gk.key, identity: identity,
                                   installID: installID, hasFolder: true, membersEpoch: gk.epoch,
                                   members: [identity.deviceID], keyring: try canonical(ring))
        let record = ShareRecord(role: .owner, pin: try ShareKeyring.Pin.of(ring), state: state, folder: folder)
        all[gk.groupID] = record
        try commit(store, snapshot, shares: all)
        return try group(of: record)
    }

    /// Join the share group of `keyring` (the folder's bytes) with its share password, as `deviceName` (desktop
    /// `join_share_group`). Refused: `pro-required` (before any key derivation), the keyring structure reasons,
    /// `not-share` (a device-sync keyring), `personal-group` (this vault's own device sync), `already-joined`,
    /// `own-share` (shared by another of this person's devices: it already syncs here), `collection-exists` (this vault
    /// already has that collection: marking it shared would publish items nobody chose to share), `collection-limit`,
    /// then the join reasons (`password`...). The owner, collection and mode are pinned from this keyring (trust on
    /// first use, authenticated by the password). The collection is added, named like the owner's (with a number on a
    /// clash). This device stays pending until the owner approves it; the share run writes the grown keyring.
    ///
    /// Joining again: a member whose join was lost to someone else's at the same moment (`superseded`) joins the same
    /// group again with a new device identity; its collection, items, folder and share bookkeeping stay, and the
    /// pinned facts must not change (`tampered`).
    public static func join(store: any ItemStore, keyring: [UInt8], password: String, deviceName: String,
                            installID: String, isPro: Bool, folder: [UInt8]? = nil, random: RandomSource,
                            clock: UnixClock) throws -> Group {
        try join(store: store, keyring: keyring, password: password, deviceName: deviceName, installID: installID,
                 isPro: isPro, folder: folder, random: random, clock: clock, derive: nil)
    }

    static func join(store: any ItemStore, keyring: [UInt8], password: String, deviceName: String, installID: String,
                     isPro: Bool, folder: [UInt8]?, random: RandomSource, clock: UnixClock,
                     derive: Keyring.KeyDerivation?) throws -> Group {
        try ShareAccess.requirePro(.join, isPro: isPro)
        try checkInstallID(installID)
        try checkFolder(folder)
        let ring = try ShareKeyring.parse(keyring)
        // Not authenticated yet (the password join below does that): the metadata only chooses a refusal here.
        guard let meta = try ShareKeyring.metadata(ring) else {
            throw ShareGroupError("not-share", "that keyring is device sync, not a shared collection")
        }
        let groupID = Keyring.str(Keyring.obj(ring)["group_id"]) ?? ""
        let collectionID = Keyring.str(meta["collection_id"]) ?? ""
        let snapshot = try store.load()
        if let personal = snapshot.sync, same(personal.groupID, groupID) {
            throw ShareGroupError("personal-group", "that is this vault's own device sync group")
        }
        var all = try records(in: snapshot)
        let previous = all[groupID]
        if let previous, !supersededJoin(previous, folder: ring) {
            throw ShareGroupError("already-joined", "this vault is already in that share group")
        }
        let catalog = CollectionCatalog.collections(in: snapshot)
        let existing = catalog.contains { same($0.id, collectionID) }
        let link = existing ? storedLink(snapshot, collectionID) : nil
        let sharedHere = all.values.contains { same($0.collectionID, collectionID) }
        if let link, same(link.role, "owner"), !sharedHere {
            throw ShareGroupError("own-share", "you shared this collection from another of your devices")
        }
        // Never two share groups for one collection on a device.
        if all.contains(where: { !same($0.key, groupID) && same($0.value.collectionID, collectionID) }) {
            throw ShareGroupError("collection-exists", "this vault already has that collection")
        }
        if existing && previous == nil && link == nil {
            throw ShareGroupError("collection-exists", "this vault already has that collection")
        }
        if !existing && catalog.count >= CollectionCatalog.maxCollections { throw CollectionCatalog.Failure.limit }
        let identity = try DeviceIdentity.generate(random: random)
        let joined: (JSONValue, GroupKey)
        if let derive {
            let salt = try Keyring.b64(Keyring.obj(Keyring.obj(ring)["kdf"])["salt"], Keyring.kdfSaltLen, "kdf salt")
            let key = try derive(password, salt)
            joined = try ShareKeyring.join(ring, passwordKey: key, identity: identity, name: deviceName, random: random,
                                           now: clock)
        } else {
            joined = try ShareKeyring.join(ring, password: password, identity: identity, name: deviceName, random: random,
                                           now: clock)
        }
        let (newRing, gk) = joined
        let name = try ShareKeyring.shareName(newRing, key: gk)
        let pin = try ShareKeyring.Pin.of(newRing)
        if let previous, !previous.pin.matches(pin) {
            throw KeyringError("tampered", "the keyring changes the share's owner, collection or mode")
        }
        let state = SyncGroupState(groupID: gk.groupID, epoch: gk.epoch, key: gk.key, identity: identity,
                                   installID: installID, hasFolder: true, membersEpoch: gk.epoch,
                                   members: ShareKeyring.memberIDs(newRing), keyring: try canonical(newRing),
                                   unackedMembers: ShareKeyring.pending(newRing, own: identity.deviceID))
        let record = ShareRecord(role: .member, pin: pin, state: state, meta: previous?.meta ?? [:],
                                 folder: folder ?? previous?.folder)
        all[groupID] = record
        var recs = snapshot.records
        if existing {
            recs[CollectionStates.linkPrefix + collectionID] = nil   // now shared here: this device speaks for it
        } else {
            let unique = CollectionCatalog.uniqueName(name, taken: catalog.map(\.name))
            recs[CollectionStates.catalogPrefix + collectionID] = try CollectionCatalog.catalogWrapper(
                id: collectionID, name: unique, description: "", createdAt: clock.now, updatedAt: clock.now)
        }
        try commit(store, snapshot, records: recs, shares: all)
        return try group(of: record)
    }

    /// Join `groupID` again after someone else's join at the same moment won (`superseded`), from the same folder's
    /// keyring (desktop `rejoin`): `not-joined` unless this vault is in that group, `folder-has-other-group` for a
    /// keyring of another group, else `join`.
    public static func rejoin(store: any ItemStore, groupID: String, keyring: [UInt8], password: String,
                              deviceName: String, installID: String, isPro: Bool, random: RandomSource,
                              clock: UnixClock) throws -> Group {
        try rejoin(store: store, groupID: groupID, keyring: keyring, password: password, deviceName: deviceName,
                   installID: installID, isPro: isPro, random: random, clock: clock, derive: nil)
    }

    static func rejoin(store: any ItemStore, groupID: String, keyring: [UInt8], password: String, deviceName: String,
                       installID: String, isPro: Bool, random: RandomSource, clock: UnixClock,
                       derive: Keyring.KeyDerivation?) throws -> Group {
        try ShareAccess.requirePro(.join, isPro: isPro)
        _ = try record(try store.load(), groupID)
        let folderRing = try parseLoose(keyring)
        guard same(Keyring.str(Keyring.obj(folderRing)["group_id"]) ?? "", groupID) else {
            throw ShareGroupError("folder-has-other-group", "that folder holds another share group")
        }
        return try join(store: store, keyring: keyring, password: password, deviceName: deviceName, installID: installID,
                        isPro: isPro, folder: nil, random: random, clock: clock, derive: derive)
    }

    /// The checked `csl:` link of `collectionID` stored here (learned from another of this person's devices).
    static func storedLink(_ snapshot: StoreSnapshot, _ collectionID: String) -> CollectionShares.Link? {
        let id = CollectionStates.linkPrefix + collectionID
        guard let w = snapshot.records[id], let r = CollectionCatalog.checked(id, w),
              case .string(let mode)? = r["mode"], case .string(let role)? = r["role"] else { return nil }
        return CollectionShares.Link(mode: mode, role: role)
    }

    /// The owner approves `deviceIDs`, each of which the screen showed by name (`pendingMembers`; desktop
    /// `approve_members`): `not-owner` on another device, `not-pending` for an empty choice or an id that is not
    /// waiting. Works without Pro. Returns the members just approved. The host writes the new keyring
    /// (`FolderSync.writeShareKeyring`); the share run does too.
    @discardableResult
    public static func approve(store: any ItemStore, groupID: String, deviceIDs: [String]) throws -> [Member] {
        let snapshot = try store.load()
        var (all, rec) = try record(snapshot, groupID)
        try requireOwner(rec)
        let waiting = try group(of: rec).members.filter { !$0.approved }
        let waitingIDs = Set(waiting.map { Array($0.deviceID.utf8) })
        let chosen = Set(deviceIDs.map { Array($0.utf8) })
        guard !chosen.isEmpty, chosen.isSubset(of: waitingIDs) else {
            throw ShareGroupError("not-pending", "approve only members that are waiting")
        }
        let ids = ShareKeyring.sortedIDs(deviceIDs)
        let ring = try ShareKeyring.approvePending(try storedRing(rec), trusted: try rec.state.groupKey(),
                                                   identity: rec.state.identity, deviceIDs: ids)
        rec.state.keyring = try canonical(ring)
        rec.state.unackedMembers = ShareKeyring.pending(ring, own: rec.state.deviceID)
        all[groupID] = rec
        try commit(store, snapshot, shares: all)
        return waiting.filter { chosen.contains(Array($0.deviceID.utf8)) }
            .map { Member(deviceID: $0.deviceID, name: $0.name, addedAt: $0.addedAt, approved: true) }
            .sorted { scalarOrder($0.deviceID, $1.deviceID) }
    }

    /// The owner removes `deviceID` (desktop `remove_member`; works without Pro): a rotation with a NEW share password
    /// (the removed person knows the old one) that also drops every member the owner never approved, the owner signing
    /// the rest. Returns the owner-signed removal notice, naming this share group only: the host writes it first
    /// (`FolderSync.publishShareNotice`), then the rotated keyring. The names go to the removed list.
    public static func removeMember(store: any ItemStore, groupID: String, deviceID: String, newPassword: String,
                                    random: RandomSource, clock: UnixClock) throws -> [UInt8] {
        try removeMember(store: store, groupID: groupID, deviceID: deviceID, newPassword: newPassword, random: random,
                         clock: clock, derive: Keyring.productionKDF)
    }

    static func removeMember(store: any ItemStore, groupID: String, deviceID: String, newPassword: String,
                             random: RandomSource, clock: UnixClock, derive: Keyring.KeyDerivation) throws -> [UInt8] {
        let snapshot = try store.load()
        var (all, rec) = try record(snapshot, groupID)
        try requireOwner(rec)
        guard Identifier.isValid(deviceID), !same(deviceID, rec.state.deviceID) else {
            throw ShareGroupError("not-member", "invalid device id")
        }
        let ring = try storedRing(rec)
        let trusted = try rec.state.groupKey()
        let names = Keyring.memberNames(ring, key: trusted)
        let now = clock.now
        // A share v1 group is upgraded to share v2 in the same rotation (`ShareKeyring.removeMember`).
        let removed = try ShareKeyring.removeMember(ring, trusted: trusted, identity: rec.state.identity, deviceID: deviceID,
                                                    newPassword: newPassword, random: random, issuedAt: now,
                                                    derive: derive)
        var state = FolderSync.epochReset(rec.state)
        state.epoch = removed.key.epoch; state.key = removed.key.key; state.membersEpoch = removed.key.epoch
        state.members = ShareKeyring.memberIDs(removed.keyring); state.keyring = try canonical(removed.keyring)
        state.unackedMembers = []
        rec.state = state
        var rows = rec.removed
        for d in removed.dropped {
            if let entry = names[d] { rows.append(ShareRecord.Removed(name: entry, at: max(0, now))) }
        }
        rec.removed = Array(rows.suffix(ShareRecord.maxRemoved))
        all[groupID] = rec
        try commit(store, snapshot, shares: all)
        return removed.notice
    }

    /// The owner upgrades share v1 `groupID` to share v2 (desktop `upgrade_share`; works without Pro: a security action).
    /// A rotation to epoch + 1 that removes nobody: approved members get the new content key, pending members stay
    /// pending, and `password` (the share password for the new epoch, which must pass the share password rules) may
    /// be the current one: it no longer opens any item. The new keyring is kept for the share run (or
    /// `FolderSync.writeShareKeyring`) to write. Refused: `not-owner`, `already-upgraded`, then the keyring reasons
    /// (`weak-password`...).
    @discardableResult
    public static func upgrade(store: any ItemStore, groupID: String, password: String, random: RandomSource) throws -> Group {
        try upgrade(store: store, groupID: groupID, password: password, random: random, derive: Keyring.productionKDF)
    }

    @discardableResult
    static func upgrade(store: any ItemStore, groupID: String, password: String, random: RandomSource,
                        derive: Keyring.KeyDerivation) throws -> Group {
        let snapshot = try store.load()
        var (all, rec) = try record(snapshot, groupID)
        try requireOwner(rec)
        let ring = try storedRing(rec)
        guard ShareKeyring.shareVersion(ring) == 1 else {
            throw ShareGroupError("already-upgraded", "this share is already upgraded")
        }
        let (newRing, gk) = try ShareKeyring.upgrade(ring, trusted: try rec.state.groupKey(), identity: rec.state.identity,
                                                     password: password, random: random, derive: derive)
        var state = FolderSync.epochReset(rec.state)
        state.epoch = gk.epoch; state.key = gk.key; state.membersEpoch = gk.epoch
        state.members = ShareKeyring.memberIDs(newRing); state.keyring = try canonical(newRing)
        state.unackedMembers = ShareKeyring.pending(newRing, own: state.deviceID)
        rec.state = state
        all[groupID] = rec
        try commit(store, snapshot, shares: all)
        return try group(of: rec)
    }

    /// The share link of `collectionID` received from another of this person's devices (it holds the share, this
    /// device does not), nil when there is none or the collection is shared here (desktop `received_share_link`). A
    /// share store that cannot be read counts as shared here (fails closed).
    public static func receivedLink(in snapshot: StoreSnapshot, collectionID: String) -> CollectionShares.Link? {
        sharedHere(snapshot, collectionID) ? nil : storedLink(snapshot, collectionID)
    }

    static func sharedHere(_ snapshot: StoreSnapshot, _ collectionID: String) -> Bool {
        guard let all = try? records(in: snapshot) else { return true }
        return all.values.contains { same($0.collectionID, collectionID) }
    }

    /// Forget the share link of `collectionID` received from another of this person's devices (final review finding 4;
    /// desktop `forget_share_link`, lgk-core `ShareGroups.forgetLink`). A received link goes away only through a
    /// tombstone its holder publishes, so the link of a device that was lost, reset or left device sync stays for ever:
    /// it blocks sharing the collection again (the owner-loss recovery), deleting it, and (read-only) every edit on this
    /// person's devices. The `csl:` record is removed here; the next personal collections run publishes its tombstone
    /// (the link is no longer relayed), so the person's other devices drop it too. A holder that still exists
    /// republishes its own link above the tombstone (`CollectionSync`), so forgetting never takes a live share away.
    /// Works without Pro.
    ///
    /// Refused: `shared-here` when this device holds the share itself (leave instead; also for a share store that
    /// cannot be read), `no-link` when there is no link record.
    public static func forgetLink(store: any ItemStore, collectionID: String) throws {
        let snapshot = try store.load()
        if sharedHere(snapshot, collectionID) {
            throw ShareGroupError("shared-here", "that collection is shared on this device")
        }
        let id = CollectionStates.linkPrefix + collectionID
        guard snapshot.records[id] != nil else { throw ShareGroupError("no-link", "that collection has no share link") }
        var records = snapshot.records
        records[id] = nil
        try store.commit(StoreChange(baseRevision: snapshot.revision, records: records, meta: snapshot.meta,
                                     sync: snapshot.sync))
    }

    /// Forget `groupID` on this vault (desktop `leave_share_group`; works without Pro). The collection stops being
    /// shared here and keeps its items; the group's keys and its share bookkeeping go. The other members still list
    /// this device until the owner removes it.
    public static func leave(store: any ItemStore, groupID: String) throws {
        let snapshot = try store.load()
        let found = try record(snapshot, groupID)
        var all = found.all
        all[groupID] = nil
        // A link of the same collection from another of this person's devices that also shares it (re-review wave B,
        // B1) goes too: this device's next personal run tombstones it, and a device that still shares republishes it.
        var records = snapshot.records
        records[CollectionStates.linkPrefix + found.record.collectionID] = nil
        try commit(store, snapshot, records: records, shares: all)
    }

    /// Whether `collectionID` is shared on this device and another of this person's devices also shares it (its link
    /// is stored here; re-review wave B, B1): the share page warns, and one share should be stopped or left.
    public static func sharedTwice(in snapshot: StoreSnapshot, collectionID: String) -> Bool {
        guard let all = try? records(in: snapshot), all.values.contains(where: { same($0.collectionID, collectionID) })
        else { return false }
        return snapshot.records[CollectionStates.linkPrefix + collectionID] != nil
    }

    /// Keep `folder` (the host's opaque folder reference; nil for none) with `groupID`.
    public static func setFolder(store: any ItemStore, groupID: String, folder: [UInt8]?) throws {
        try checkFolder(folder)
        let snapshot = try store.load()
        var (all, rec) = try record(snapshot, groupID)
        rec.folder = folder
        all[groupID] = rec
        try commit(store, snapshot, shares: all)
    }

    // MARK: - keyring changes found in the folder (the share run)

    /// Accept a newer keyring of `groupID` from the folder (desktop `adopt_keyring`): authenticated against the stored
    /// trusted key and the owner's signature; `tampered` if it changes a pinned fact or, at the stored epoch, does not
    /// only grow; `removed` when an owner-signed rotation left this device out. Members the owner has not approved are
    /// stored as pending (`unackedMembers`).
    @discardableResult
    static func adopt(store: any ItemStore, groupID: String, keyring raw: [UInt8]) throws -> ShareRecord {
        let snapshot = try store.load()
        var (all, rec) = try record(snapshot, groupID)
        let candidate = try parseLoose(raw)
        let gk = try ShareKeyring.adopt(stored: try storedRing(rec), candidate: candidate, trusted: try rec.state.groupKey(),
                                        identity: rec.state.identity, pin: rec.pin)
        var state = gk.epoch != rec.state.epoch ? FolderSync.epochReset(rec.state) : rec.state
        state.epoch = gk.epoch; state.key = gk.key; state.membersEpoch = gk.epoch
        state.members = ShareKeyring.memberIDs(candidate); state.keyring = try canonical(candidate)
        state.unackedMembers = ShareKeyring.pending(candidate, own: state.deviceID)
        rec.state = state
        all[groupID] = rec
        try commit(store, snapshot, shares: all)
        return rec
    }

    /// Owner only (desktop `reconcile_owner_keyring`): this device's approvals re-signed onto a same-epoch folder
    /// keyring that someone else grew meanwhile (a join between the owner's approval and its next run), when the
    /// result only grows from the stored one; the new joiners stay pending. False, with nothing changed, otherwise.
    static func reconcileOwner(store: any ItemStore, groupID: String, keyring raw: [UInt8]) throws -> Bool {
        let snapshot = try store.load()
        var (all, rec) = try record(snapshot, groupID)
        guard rec.role == .owner, same(rec.state.deviceID, rec.pin.owner), let folder = try? parseLoose(raw),
              let stored = try? storedRing(rec), let trusted = try? rec.state.groupKey(),
              let ring = ShareKeyring.reconcileOwner(stored: stored, folder: folder, trusted: trusted,
                                                     identity: rec.state.identity, pin: rec.pin) else { return false }
        rec.state.membersEpoch = rec.state.epoch
        rec.state.members = ShareKeyring.memberIDs(ring)
        rec.state.keyring = try canonical(ring)
        rec.state.unackedMembers = ShareKeyring.pending(ring, own: rec.state.deviceID)
        all[groupID] = rec
        try commit(store, snapshot, shares: all)
        return true
    }

    /// Whether this member's pending join of the group was lost to another join at the same moment (desktop
    /// `superseded_join`): the user joins again; anything else stays a refusal. Never on the owner's device.
    static func supersededJoin(_ rec: ShareRecord, folder: JSONValue) -> Bool {
        guard rec.role == .member, !same(rec.state.deviceID, rec.pin.owner), let stored = try? storedRing(rec),
              let trusted = try? rec.state.groupKey() else { return false }
        return ShareKeyring.supersededJoin(stored: stored, folder: folder, trusted: trusted, identity: rec.state.identity,
                                           pin: rec.pin)
    }

    /// Whether this device writes its trusted keyring over a folder keyring it could not take (desktop
    /// `restores_over`), asked only after adopting, reconciling and the superseded-join check failed, or for bytes that
    /// do not parse (`folder` nil) or name another group. Without it anyone who can write to the share folder could
    /// stop the share on every device. The owner's device: always (the only authority), except over a later epoch
    /// signed by the pinned owner key, which only this owner made. A member's device: only over a keyring of its
    /// trusted epoch that does not authenticate (MAC or the pinned owner's signature); an authenticated one that does
    /// not grow is a concurrent join and still stops the run.
    static func restoresOver(_ rec: ShareRecord, folder: JSONValue?) -> Bool {
        guard let trusted = try? rec.state.groupKey() else { return false }
        if rec.role == .owner, same(rec.state.deviceID, rec.pin.owner) {
            guard let folder else { return true }
            return !ShareKeyring.ownerSignedAhead(folder: folder, trusted: trusted, pin: rec.pin)
        }
        guard let folder, case .object(let f) = folder, ShareKeyring.sameJSON(f["group_id"], .string(trusted.groupID)),
              f["epoch"] == .int(trusted.epoch) else { return false }
        return !ShareKeyring.authenticatesAtEpoch(folder: folder, trusted: trusted, identity: rec.state.identity,
                                                  pin: rec.pin)
    }

    // MARK: - removal

    /// The pinned owner removed this device from `groupID` (desktop `apply_share_removal`; works without Pro): `notice`
    /// must verify as the owner's notice for this device (`RemovalError` otherwise, `owner` on the owner's own device,
    /// whatever it says). Every live item in the shared collection leaves the store, documents last; a document still
    /// linked from an item outside the collection stays. Nothing else is touched (personal items, other collections,
    /// the personal group), and the group is forgotten, in one commit. The host's store moves what leaves to Recently
    /// deleted (`trash`: `trash-full` is checked first, `item-error` when Recently deleted is unknown or the commit
    /// fails; nothing changes then and the next run tries again). Returns how many items left.
    @discardableResult
    public static func applyShareRemoval(store: any ItemStore, groupID: String, notice: [UInt8], folderKeyring: [UInt8],
                                         trash: ShareTrash) throws -> Int {
        let snapshot = try store.load()
        let found = try record(snapshot, groupID)
        var all = found.all
        let rec = found.record
        guard rec.role == .member,
              let watch = ShareAccess.removalWatch(groupID: rec.state.groupID, deviceID: rec.state.deviceID,
                                                   epoch: rec.state.epoch, installID: rec.state.installID, folder: "",
                                                   pin: rec.pin) else { throw RemovalError("owner") }
        _ = try RemovalNotice.verify(notice, watch: watch, folderKeyring: folderKeyring)
        let cid = rec.collectionID
        var rows: [(id: String, document: Bool)] = []
        for (id, w) in snapshot.itemRecords where SyncMeta.nsName(w) == Namespace.item.rawValue {
            guard CollectionCatalog.memberships(of: id, records: snapshot.records).contains(where: { same($0, cid) }) else {
                continue
            }
            var document = false
            if case .object(let wo) = w, case .object(let r)? = wo["record"], r["kind"] == .string("document") { document = true }
            rows.append((id, document))
        }
        // Linking items first, then documents (desktop order); by id within each, so the result never depends on
        // dictionary order.
        rows.sort { a, b in a.document != b.document ? !a.document : scalarOrder(a.id, b.id) }
        if !rows.isEmpty {
            guard let count = trash.count else { throw ShareGroupError("item-error", "Recently deleted is not available") }
            guard count + rows.count <= LocalData.maxTrash else {
                throw ShareGroupError("trash-full", "the trash cannot hold this collection's items")
            }
        }
        var records = snapshot.records
        var moved = 0
        for row in rows {
            if row.document && linkedDocument(row.id, records) { continue }
            records[row.id] = nil
            records[CollectionStates.membershipPrefix + row.id] = nil
            moved += 1
        }
        all[groupID] = nil
        records[CollectionStates.linkPrefix + cid] = nil   // as `leave` (B1)
        do {
            try commit(store, snapshot, records: records, shares: all)
        } catch {
            // Not the trash limit (checked above): the store refused the change, reported as it is.
            throw ShareGroupError("item-error", "\(error)")
        }
        return moved
    }

    /// Whether a live item in `records` still links `documentID` (`payload.document_ids`).
    static func linkedDocument(_ documentID: String, _ records: [String: JSONValue]) -> Bool {
        for (id, w) in records where !CollectionStates.isReserved(id, w) {
            guard case .object(let wo) = w, case .object(let r)? = wo["record"], case .object(let p)? = r["payload"],
                  case .array(let docs)? = p["document_ids"] else { continue }
            if docs.contains(where: { if case .string(let s) = $0 { return same(s, documentID) }; return false }) { return true }
        }
        return false
    }
}
