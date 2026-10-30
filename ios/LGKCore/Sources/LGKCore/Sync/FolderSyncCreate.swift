/// Creating a folder group, giving a Wi-Fi group a folder and rotating (desktop `create_folder_group`,
/// `add_folder_to_group` and `rotate_folder_group`). Each writes the keyring only if the folder still holds
/// what was read (`keyring-changed`), commits the group state once, takes the keyring back if that commit
/// fails, and then runs once.
extension FolderSync {
    /// Start a new group in this folder with this vault as its first member (fresh identity), then run once.
    /// Refuses a vault already in a group (`already-joined`) and a folder that holds one (`folder-in-use`);
    /// `weak-password` and `bad-name` as for the keyring.
    public func create(store: any ItemStore, password: String, deviceName: String, random: some RandomSource,
                       clock: some UnixClock) throws -> RunReport {
        try create(store: store, password: password, deviceName: deviceName, random: random, clock: clock,
                   derive: Keyring.productionKDF)
    }

    func create(store: any ItemStore, password: String, deviceName: String, random: some RandomSource,
                clock: some UnixClock, derive: Keyring.KeyDerivation) throws -> RunReport {
        try Self.translate {
            let snapshot = try store.load()
            guard snapshot.sync == nil else { throw FolderSyncError("already-joined", "leave the current sync group first") }
            guard !access.exists(FolderLayout.keyringPath) else {
                throw FolderSyncError("folder-in-use", "this folder already holds a sync group; join it instead")
            }
            let identity = try DeviceIdentity.generate(random: random)
            let (ring, gk) = try Keyring.create(password: password, identity: identity, name: deviceName, groupID: nil,
                                                random: random, now: clock, derive: derive)
            let written = try CanonicalJSON.encode(ring, dialect: .utf8)
            try writeKeyring(written, expected: nil)
            let state = SyncGroupState(groupID: gk.groupID, epoch: gk.epoch, key: gk.key, identity: identity,
                                       installID: installID, hasFolder: true, membersEpoch: gk.epoch,
                                       members: [identity.deviceID], keyring: written)
            try commitOrUndo(store, snapshot, state, written: written, previous: nil)
        }
        return runOnce(store: store, random: random, clock: clock)
    }

    /// Give this vault's Wi-Fi-only group this folder with a new sync password, then run once. The keyring is
    /// made for the stored group key (`Keyring.createForExistingGroup`), so the paired devices attach with the
    /// password; a folder that already holds this group is attached to instead (`attach`).
    ///
    /// Audit M9: a removed (revoked) Wi-Fi peer still holds the stored key, so without `freshKey` the call is
    /// refused (`lan-peer-removed`). With `freshKey` the keyring is made for a NEW random key at epoch + 1 (same
    /// group id, `prev_mac` null) and this device moves to it; the other Wi-Fi peers pair again or attach.
    public func addFolder(toGroup store: any ItemStore, password: String, deviceName: String, freshKey: Bool = false,
                          random: some RandomSource, clock: some UnixClock) throws -> RunReport {
        try addFolder(toGroup: store, password: password, deviceName: deviceName, freshKey: freshKey, random: random,
                      clock: clock, derive: Keyring.productionKDF)
    }

    func addFolder(toGroup store: any ItemStore, password: String, deviceName: String, freshKey: Bool,
                   random: some RandomSource, clock: some UnixClock, derive: Keyring.KeyDerivation) throws -> RunReport {
        let existing: Bool = try Self.translate {
            let snapshot = try store.load()
            guard let state = snapshot.sync else { throw FolderSyncError("not-joined") }
            guard state.installID == installID else {
                throw FolderSyncError("rejoin-required", "this vault was joined on another installation")
            }
            guard !state.hasFolder else { throw FolderSyncError("already-has-folder", "this sync group already uses a cloud folder") }
            if access.exists(FolderLayout.keyringPath) {
                let ring = try Keyring.parse(try readKeyringBytes())
                guard Keyring.str(Keyring.obj(ring)["group_id"]) == state.groupID else {
                    throw FolderSyncError("folder-has-other-group", "this folder holds another sync group")
                }
                return true
            }
            if state.lanPeers.contains(where: \.revoked) && !freshKey {
                throw FolderSyncError("lan-peer-removed", "a removed Wi-Fi device still holds this group's key")
            }
            var gk = try state.groupKey()
            if freshKey { gk = try Keyring.groupKey(state.groupID, state.epoch + 1, try Keyring.draw(random, Keyring.keyLen)) }
            let ring = try Keyring.createForExistingGroup(gk, password: password, identity: state.identity, name: deviceName,
                                                          random: random, now: clock, derive: derive)
            let written = try CanonicalJSON.encode(ring, dialect: .utf8)
            try writeKeyring(written, expected: nil)
            var newState = gk.epoch != state.epoch ? Self.epochReset(state) : state
            newState.epoch = gk.epoch; newState.key = gk.key; newState.hasFolder = true
            newState.membersEpoch = gk.epoch; newState.members = [state.deviceID]; newState.keyring = written
            try commitOrUndo(store, snapshot, newState, written: written, previous: nil)
            return false
        }
        if existing {
            return try attach(store: store, deviceName: deviceName, random: random, clock: clock) { ring in
                try derive(password, try Keyring.b64(Keyring.obj(Keyring.obj(ring)["kdf"])["salt"], Keyring.kdfSaltLen, "kdf salt"))
            }
        }
        return runOnce(store: store, random: random, clock: clock)
    }

    /// New group key and sync password (epoch + 1), dropping `remove`, and deletes their files; then runs once.
    ///
    /// The new key is wrapped only to this device and the members in `keep` (the members the user saw and
    /// confirmed, audit M10); every other keyring member is dropped like `remove`. `keep` nil means the members
    /// this device knows at its epoch. A LAN-only peer in `remove` leaves the LAN list only. Use it with no
    /// `remove` to change the sync password.
    public func rotate(store: any ItemStore, newPassword: String, remove: [String] = [], keep: [String]? = nil,
                       random: some RandomSource, clock: some UnixClock) throws -> RunReport {
        try rotate(store: store, newPassword: newPassword, remove: remove, keep: keep, random: random, clock: clock,
                   derive: Keyring.productionKDF)
    }

    func rotate(store: any ItemStore, newPassword: String, remove: [String], keep: [String]?, random: some RandomSource,
                clock: some UnixClock, derive: Keyring.KeyDerivation) throws -> RunReport {
        try Self.translate {
            let snapshot = try store.load()
            guard let state = snapshot.sync else { throw FolderSyncError("not-joined") }
            guard state.installID == installID else {
                throw FolderSyncError("rejoin-required", "this vault was joined on another installation")
            }
            guard remove.allSatisfy(Identifier.isValid) else { throw FolderSyncError("not-member", "invalid device id") }
            let kept: Set<String>
            if let keep {
                guard keep.allSatisfy(Identifier.isValid) else { throw FolderSyncError("not-member", "invalid device id") }
                kept = Set(keep)
            } else {
                // Members added elsewhere and not yet confirmed never receive the new key (audit M10).
                kept = (state.membersEpoch == state.epoch ? Set(state.members) : []).subtracting(state.unackedMembers)
            }
            let raw = try readKeyringBytes()
            let ring = try Keyring.parse(raw)
            let ringIDs = Self.memberIDs(ring)
            let lanIDs = Set(state.lanPeers.map(\.deviceID))
            var drop = remove
            var ringDrop = remove.filter { ringIDs.contains($0) || !lanIDs.contains($0) }
            let unconfirmed = ringIDs.subtracting(kept).subtracting(remove).subtracting([state.deviceID]).sorted()
            ringDrop += unconfirmed; drop += unconfirmed
            let (newRing, gk) = try Keyring.rotate(ring, trusted: try state.groupKey(), identity: state.identity,
                                                   newPassword: newPassword, remove: ringDrop, random: random, derive: derive)
            let written = try CanonicalJSON.encode(newRing, dialect: .utf8)
            try writeKeyring(written, expected: raw)
            let gone = Set(drop)
            var newState = Self.epochReset(state)
            newState.epoch = gk.epoch; newState.key = gk.key; newState.membersEpoch = gk.epoch
            newState.members = Self.memberIDs(newRing).sorted(); newState.keyring = written
            newState.lanPeers = state.lanPeers.filter { !gone.contains($0.deviceID) }
            newState.unackedMembers = []  // every member kept was confirmed
            try commitOrUndo(store, snapshot, newState, written: written, previous: raw)
            for dev in gone.sorted() {
                if let path = FolderLayout.deviceFile(dev) { try? access.remove(path) }
                if let path = FolderLayout.signatureFile(dev) { try? access.remove(path) }
                if let path = FolderLayout.witnessFile(dev) { try? access.remove(path) }
                if let path = FolderLayout.witnessSignatureFile(dev) { try? access.remove(path) }
            }
        }
        return runOnce(store: store, random: random, clock: clock)
    }

    /// Members to confirm (desktop `_unacked_members`): unconfirmed ones still listed, plus members of `current`
    /// (the accepted keyring) this device did not know at its last run, other than itself. This device never
    /// adds another member itself, so each arrival was added elsewhere. A state without a recorded member list
    /// (`membersEpoch` 0) reports nothing new. At most `maxMembersSeen`.
    static func unackedMembers(_ state: SyncGroupState, current: Set<String>) -> [String] {
        var out = Set(state.unackedMembers).intersection(current)
        if state.membersEpoch != 0 { out.formUnion(current.subtracting(state.members).subtracting([state.deviceID])) }
        return Array(out.sorted().prefix(maxMembersSeen))
    }

    /// The user confirmed `deviceIDs` (desktop `acknowledge_members`); only those ids stop being unconfirmed,
    /// so one that appeared after the user looked stays. Returns how many were confirmed.
    @discardableResult
    public func acknowledgeMembers(store: any ItemStore, _ deviceIDs: [String]) throws -> Int {
        try Self.translate {
            let snapshot = try store.load()
            guard var state = snapshot.sync else { throw FolderSyncError("not-joined") }
            guard state.installID == installID else {
                throw FolderSyncError("rejoin-required", "this vault was joined on another installation")
            }
            let chosen = Set(deviceIDs)
            let left = state.unackedMembers.filter { !chosen.contains($0) }
            let count = state.unackedMembers.count - left.count
            guard count > 0 else { return 0 }
            state.unackedMembers = left
            try store.commit(StoreChange(baseRevision: snapshot.revision, records: snapshot.records, meta: snapshot.meta,
                                         sync: state))
            return count
        }
    }

    /// Commit `state`; on failure put the folder's keyring back to `previous` (nil: remove it) if it still holds
    /// `written`, and rethrow.
    func commitOrUndo(_ store: any ItemStore, _ snapshot: StoreSnapshot, _ state: SyncGroupState, written: [UInt8],
                      previous: [UInt8]?) throws {
        do {
            try store.commit(StoreChange(baseRevision: snapshot.revision, records: snapshot.records, meta: snapshot.meta,
                                         sync: state))
        } catch {
            if let previous { undoKeyringWrite(written: written, previous: previous) }
            else if (try? readKeyringBytes()) == written { try? access.remove(FolderLayout.keyringPath) }
            throw error
        }
    }
}
