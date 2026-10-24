import Crypto

/// A folder group operation (join/attach) was refused; `reason` is a stable code (desktop `FolderSyncError`).
public struct FolderSyncError: Error, Equatable, Sendable, CustomStringConvertible {
    public let reason: String
    public let detail: String
    public init(_ reason: String, _ detail: String = "") { self.reason = reason; self.detail = detail }
    public var description: String { detail.isEmpty ? reason : "\(reason): \(detail)" }
}

/// Peer views accepted in one read, plus the counters and sha256 of every file accepted (or recognised as stale).
struct PeerRead {
    var views: [PeerView] = []
    var issues: [SyncIssue] = []
    var seen: [String: Int64] = [:]
    var digests: [String: String] = [:]
    /// Device id -> base64 signing key of every accepted view that carried a valid signature.
    var signers: [String: String] = [:]
}

/// The cloud-folder transport (desktop `folder_transport.FolderSync`); see that module's docstring for every rule.
///
/// Review rule: the store is committed only after every read and check of a run has succeeded, in ONE
/// `ItemStore.commit`, and only when something changed. A wrong sync password, a keyring that is not
/// trusted or a corrupt peer file therefore never modifies the store. The reserved own-file counter is part
/// of that commit, which happens before the own file is written, so a counter is never reused.
public struct FolderSync {
    public static let staleAfterSeconds: Int64 = SyncMeta.tombstoneMaxAgeDays * 86400
    public static let ownRefreshSeconds: Int64 = 30 * 86400
    public static let maxIgnoredNames = 20
    public static let maxPeersSeen = 64
    public static let maxMembersSeen = 64
    public static let maxInstallID = 128
    /// Highest counter accepted from a device's file without a last-seen counter (desktop `MAX_FILE_COUNTER`).
    public static let maxFileCounter: Int64 = 1 << 40
    /// Largest step above the last accepted counter of a device (desktop `MAX_COUNTER_JUMP`).
    public static let maxCounterJump: Int64 = 1 << 24

    /// `rollback` or `implausible-counter` for a peer file's `counter`, nil to accept it (desktop
    /// `counter_verdict`); `last` is the last counter accepted from that device (nil: none at this epoch).
    public static func counterVerdict(_ counter: Int64, last: Int64?) -> String? {
        guard let last else { return counter > maxFileCounter ? "implausible-counter" : nil }
        if counter < last { return "rollback" }
        return counter - last > maxCounterJump ? "implausible-counter" : nil
    }

    /// Fields cleared on moving to a new epoch: peer counters, digests and signing keys (own key kept).
    static func epochReset(_ state: SyncGroupState) -> SyncGroupState {
        var out = state
        out.lastSeen = [:]; out.peerDigests = [:]
        out.viewSigners = state.viewSigners.filter { $0.key == state.deviceID }
        return out
    }

    static let restoreKinds: Set<String> = ["tampered", "rollback"]
    static let nextEpochStopReasons: Set<String> = ["tampered", "device-wrap", "key-mismatch"]
    static let rejoinReasons: Set<String> = ["missed-rotation", "not-member"]
    static let tamperReasons: Set<String> = ["device-wrap", "key-mismatch"]
    static let removedOrConflict = SyncIssue(
        "removed-or-conflict", "This device may have been removed from sync. Re-join if that isn't expected.")
    static let rotationConflict = SyncIssue(
        "rotation-conflict", "another device rotated at the same time; re-join with the newest sync password")

    public let access: any FolderAccess
    public let installID: String
    /// Licence keys this build knows (key id -> raw Ed25519 public key).
    public let licenseKeys: [String: [UInt8]]
    /// Device id -> base64 signing key of every LAN-paired peer (desktop `_paired_keys`): the only key that
    /// peer's view signature may carry, ahead of the signer pinned on first use.
    public let pairedKeys: [String: String]

    public init(access: any FolderAccess, installID: String, licenseKeys: [String: [UInt8]] = [:],
                pairedKeys: [String: String] = [:]) throws {
        guard !installID.isEmpty, installID.unicodeScalars.count <= Self.maxInstallID, !installID.contains("\u{0}") else {
            throw FolderSyncError("bad-install-id", "install id must be a non-empty bounded string")
        }
        self.access = access; self.installID = installID; self.licenseKeys = licenseKeys; self.pairedKeys = pairedKeys
    }

    // MARK: keyring

    func readKeyringBytes() throws -> [UInt8] {
        try access.read(FolderLayout.keyringPath, limit: Keyring.maxKeyringBytes + 1)
    }

    /// Writes `data` if the folder still holds `expected` (nil: no keyring), else `keyring-changed`.
    func writeKeyring(_ data: [UInt8], expected: [UInt8]?) throws {
        let current: [UInt8]?
        do { current = try readKeyringBytes() } catch FolderAccessError.notFound { current = nil }
        guard current == expected else { throw FolderSyncError("keyring-changed", "another device changed the keyring; try again") }
        try access.writeAtomic(FolderLayout.keyringPath, data)
    }

    static func keyringKind(_ reason: String) -> String {
        if reason == "group-mismatch" { return "folder-has-other-group" }
        if restoreKinds.contains(reason) { return reason }
        if rejoinReasons.contains(reason) { return "rejoin-required" }
        if tamperReasons.contains(reason) { return "tampered" }
        return "keyring-corrupt"
    }

    /// (issues, key, ring, ring bytes); key nil means the run must stop.
    func trustedKeyring(_ state: SyncGroupState) -> ([SyncIssue], GroupKey?, JSONValue?, [UInt8]?) {
        let raw: [UInt8]
        do { raw = try readKeyringBytes() } catch FolderAccessError.notFound {
            return ([SyncIssue("keyring-missing", FolderLayout.keyringName)], nil, nil, nil)
        } catch {
            return ([SyncIssue("keyring-unreadable", "\(error)")], nil, nil, nil)
        }
        let trusted: GroupKey
        do { trusted = try state.groupKey() } catch { return ([SyncIssue("local-data", "\(error)")], nil, nil, nil) }
        let ring: JSONValue
        do { ring = try Keyring.parse(raw) } catch {
            return ([SyncIssue("keyring-corrupt", "\(error)")], nil, nil, nil)
        }
        do {
            let gk = try Keyring.accept(ring, trusted: trusted, identity: state.identity)
            return ([], gk, ring, raw)
        } catch {
            let reason = (error as? KeyringError)?.reason ?? "keyring-corrupt"
            let kind = Self.keyringKind(reason)
            let detail = reason == kind ? "\(error)" : "\(kind): \(error)"
            let o = Keyring.obj(ring)
            let sameGroup = Keyring.str(o["group_id"]) == trusted.groupID
            let epoch = Keyring.int(o["epoch"])
            if sameGroup && epoch == trusted.epoch + 1 && Self.nextEpochStopReasons.contains(reason) {
                return ([Self.unlisted(ring, state) ? Self.removedOrConflict : Self.rotationConflict], nil, nil, nil)
            }
            if sameGroup && epoch == trusted.epoch && reason == "tampered" && Self.unlisted(ring, state) {
                return ([Self.removedOrConflict], nil, nil, nil)
            }
            if reason == "tampered" && Self.competingRotation(ring, trusted: trusted, state: state) {
                return ([Self.rotationConflict], nil, nil, nil)
            }
            if Self.restoreKinds.contains(kind) && !(epoch.map { $0 > trusted.epoch } ?? false),
               let (gk, restored) = restoreKeyring(state, trusted: trusted) {
                return ([SyncIssue("keyring-restored", detail)], gk, restored, state.keyring)
            }
            return ([SyncIssue(kind, detail)], nil, nil, nil)
        }
    }

    /// Re-verify the stored keyring and write it back; nil if that is impossible.
    func restoreKeyring(_ state: SyncGroupState, trusted: GroupKey) -> (GroupKey, JSONValue)? {
        guard let bytes = state.keyring,
              let ring = try? Keyring.parse(bytes),
              let gk = try? Keyring.accept(ring, trusted: trusted, identity: state.identity),
              gk.epoch == trusted.epoch,
              (try? access.writeAtomic(FolderLayout.keyringPath, bytes)) != nil else { return nil }
        return (gk, ring)
    }

    /// True if `ring` does not list this device or lacks its wrap.
    static func unlisted(_ ring: JSONValue, _ state: SyncGroupState) -> Bool {
        let o = Keyring.obj(ring)
        var listed = false, wrapped = false
        if case .array(let members)? = o["members"] {
            listed = members.contains { Keyring.str(Keyring.obj($0)["device_id"]) == state.deviceID }
        }
        if case .object(let wraps)? = o["device_wraps"] { wrapped = wraps[state.deviceID] != nil }
        return !(listed && wrapped)
    }

    /// True if `ring` is at the trusted epoch and our own wrap opens a different key (two rotations from one epoch).
    static func competingRotation(_ ring: JSONValue, trusted: GroupKey, state: SyncGroupState) -> Bool {
        let o = Keyring.obj(ring)
        guard Keyring.str(o["group_id"]) == trusted.groupID, Keyring.int(o["epoch"]) == trusted.epoch,
              (try? Keyring.verifyStructure(ring)) != nil,
              let other = try? Keyring.unwrapDevice(ring, identity: state.identity),
              Keyring.macOK(ring, key: other) else { return false }
        return other.key != trusted.key
    }

    static func memberIDs(_ ring: JSONValue) -> Set<String> {
        guard case .array(let members)? = Keyring.obj(ring)["members"] else { return [] }
        return Set(members.compactMap { Keyring.str(Keyring.obj($0)["device_id"]) })
    }

    // MARK: device files

    static func ignoredIssue(_ names: [String]) -> SyncIssue {
        let shown = names.prefix(maxIgnoredNames).joined(separator: ", ")
        let more = names.count > maxIgnoredNames ? ", +\(names.count - maxIgnoredNames) more" : ""
        return SyncIssue("ignored-file", "\(names.count) \(names.count == 1 ? "file" : "files"): \(shown)\(more)")
    }

    static func sha256Hex(_ data: [UInt8]) -> String {
        lowerHex(SHA256.hash(data: data))
    }

    /// Reads every peer file; never throws for a single bad file.
    func readPeers(_ gk: GroupKey, ownID: String, members: Set<String>, lastSeen: [String: Int64],
                   digests: [String: String], now: Int64, signers: [String: String] = [:],
                   pairedKeys: [String: String] = [:]) -> PeerRead {
        var out = PeerRead()
        var allowed = Set<String>()
        for m in members.subtracting([ownID]).sorted() {
            if Identifier.isSafeDeviceFile(m) { allowed.insert(m) } else { out.issues.append(SyncIssue("unsafe-member", m)) }
        }
        let names: [String]
        do { names = try access.list(FolderLayout.devicesDir).sorted() } catch FolderAccessError.notFound {
            return out
        } catch {
            out.issues.append(SyncIssue("folder-unreadable", "\(error)"))
            return out
        }
        var ignored: [String] = []
        let suffix = FolderLayout.deviceSuffix
        for name in names {
            if name.hasPrefix(".") && name.hasSuffix(".tmp") { continue }  // an in-flight atomic write
            let dev = name.hasSuffix(suffix) ? String(name.dropLast(suffix.count)) : ""
            if dev == ownID { continue }
            guard allowed.contains(dev), let path = FolderLayout.deviceFile(dev) else { ignored.append(name); continue }
            let raw: [UInt8]
            do { raw = try access.read(path, limit: ViewFile.maxBytes + 1) } catch {
                out.issues.append(SyncIssue("unreadable", "\(name): \(error)"))
                continue
            }
            let view: (header: ViewHeader, states: [ItemState])
            do { view = try ViewFile.decode(raw, key: gk, expectedDeviceID: dev) } catch {
                let reason = (error as? SyncFormatError)?.reason ?? "corrupt"
                let kind = ["epoch-mismatch", "device-mismatch"].contains(reason) ? reason : "corrupt"
                out.issues.append(SyncIssue(kind, "\(name): \(reason)"))
                continue
            }
            let counter = view.header.counter
            let digest = Self.sha256Hex(raw)
            let last = lastSeen[dev]
            if let last, counter < last {
                out.issues.append(SyncIssue("rollback", "\(name): counter \(counter) < \(last)"))
                continue
            }
            if last == counter && (digests[dev] ?? digest) != digest {
                out.issues.append(SyncIssue("suspicious-rewrite", "\(name): counter \(counter) reused"))
                continue
            }
            let signer: String?
            switch checkSignature(dev, name: name, raw: raw, header: view.header, signers: signers, pairedKeys: pairedKeys) {
            case .refused(let issue): out.issues.append(issue); continue
            case .signed(let key): signer = key
            case .unsigned: signer = nil
            }
            if Self.counterVerdict(counter, last: last) != nil {
                out.issues.append(SyncIssue("implausible-counter", "\(name): counter \(counter)"))
                continue
            }
            out.seen[dev] = counter; out.digests[dev] = digest
            if let signer { out.signers[dev] = signer }
            if view.header.writtenAt < now - Self.staleAfterSeconds {
                out.issues.append(SyncIssue("stale-device", name))
                continue
            }
            out.views.append(PeerView(deviceID: dev, states: view.states))
        }
        if !ignored.isEmpty { out.issues.append(Self.ignoredIssue(ignored)) }
        return out
    }

    enum SignatureCheck { case signed(String), unsigned, refused(SyncIssue) }

    func readSignature(_ deviceID: String) -> [UInt8]? {
        guard let path = FolderLayout.signatureFile(deviceID) else { return nil }
        return try? access.read(path, limit: ViewSignature.maxBytes + 1)
    }

    /// A validly signed view (its base64 key), an accepted unsigned one, or a refusal with its issue.
    func checkSignature(_ dev: String, name: String, raw: [UInt8], header: ViewHeader,
                        signers: [String: String], pairedKeys: [String: String] = [:]) -> SignatureCheck {
        let expected = pairedKeys[dev] ?? signers[dev]
        var why = "no signature file"
        if let sig = readSignature(dev) {
            do {
                let key = Base64.encode(try ViewSignature.verify(sig, raw: raw, header: header))
                if let expected, key != expected {
                    return .refused(SyncIssue("view-forged", "\(name): signed by another key"))
                }
                return .signed(key)
            } catch {
                why = (error as? SyncFormatError)?.reason ?? "sig-malformed"
            }
        }
        guard signers[dev] != nil else { return .unsigned }  // a device that never signed (older app): accepted as before
        return .refused(SyncIssue(why == "sig-mismatch" ? "view-forged" : "view-unsigned", "\(name): \(why)"))
    }

    /// Deletes this device's leftover temp files (a crash between write and replace).
    func sweepOwnTempFiles(_ deviceID: String) {
        let prefix = ".\(deviceID)\(FolderLayout.deviceSuffix)."
        guard let names = try? access.list(FolderLayout.devicesDir) else { return }
        for name in names where name.hasPrefix(prefix) && name.hasSuffix(".tmp") {
            try? access.remove("\(FolderLayout.devicesDir)/\(name)")
        }
    }

    struct OwnStatus {
        var needsWrite: Bool
        var counter: Int64 = 0
        var stale = false
        var present = false
        /// The file carries a valid signature by this device's own key.
        var selfSigned = false
    }

    /// What the own file holds; a file without a valid own signature always needs a write.
    func ownFileStatus(_ gk: GroupKey, _ state: SyncGroupState, ownStates: [ItemState]?, now: Int64) -> OwnStatus {
        guard let path = FolderLayout.deviceFile(state.deviceID),
              let raw = try? access.read(path, limit: ViewFile.maxBytes + 1),
              let view = try? ViewFile.decode(raw, key: gk, expectedDeviceID: state.deviceID) else {
            return OwnStatus(needsWrite: ownStates != nil)
        }
        let (counter, writtenAt) = (view.header.counter, view.header.writtenAt)
        let stale = writtenAt < now - Self.staleAfterSeconds
        var selfSigned = false
        if let sig = readSignature(state.deviceID),
           let key = try? ViewSignature.verify(sig, raw: raw, header: view.header) {
            selfSigned = key == state.identity.signingPublicKey
        }
        guard let ownStates else {
            return OwnStatus(needsWrite: false, counter: counter, stale: stale, present: true, selfSigned: selfSigned)
        }
        let needs = view.states != ownStates || counter != state.ownCounter || !selfSigned
            || writtenAt < now - Self.ownRefreshSeconds
        return OwnStatus(needsWrite: needs, counter: counter, stale: stale, present: true, selfSigned: selfSigned)
    }

    // MARK: one run

    /// One full folder sync (desktop `run_once`). Never throws: every problem is an issue in the report.
    public func runOnce(store: any ItemStore, random: some RandomSource, clock: some UnixClock) -> RunReport {
        let now = clock.now
        var fail = RunReport()
        let snapshot: StoreSnapshot
        do { snapshot = try store.load() } catch {
            fail.issues = [SyncIssue("local-data", "\(error)")]
            return fail
        }
        guard var state = snapshot.sync else { fail.issues = [SyncIssue("not-joined")]; return fail }
        guard state.installID == installID else { fail.issues = [SyncIssue("rejoin-required", "install-mismatch")]; return fail }
        guard state.hasFolder, access.exists(FolderLayout.syncDir) else {
            fail.issues = [SyncIssue("folder-missing", FolderLayout.syncDir)]
            return fail
        }
        var (issues, gkOpt, ringOpt, ringBytesOpt) = trustedKeyring(state)
        guard let gk = gkOpt, let ring = ringOpt, let ringBytes = ringBytesOpt else {
            fail.issues = issues.isEmpty ? [SyncIssue("keyring-corrupt")] : issues
            return fail
        }
        let original = state
        let current = Self.memberIDs(ring)
        if gk.epoch != state.epoch {
            state = Self.epochReset(state)
            state.epoch = gk.epoch; state.key = gk.key; state.membersEpoch = gk.epoch
            state.members = current.sorted(); state.keyring = ringBytes
        }
        let known: Set<String> = state.membersEpoch == gk.epoch ? Set(state.members) : []
        for dropped in known.subtracting(current).sorted() { issues.append(SyncIssue("member-dropped", dropped)) }
        if !current.contains(state.deviceID) && !known.contains(state.deviceID) {
            issues.append(SyncIssue("member-dropped", state.deviceID))
        }
        for (device, name) in Keyring.memberNames(ring, key: gk).sorted(by: { $0.key < $1.key }) where name == nil {
            issues.append(SyncIssue("bad-name", device))
        }
        var members = known.union(current)
        if members.count > Self.maxMembersSeen { members = current }

        if Identifier.isSafeDeviceFile(state.deviceID) { sweepOwnTempFiles(state.deviceID) }
        let peers = readPeers(gk, ownID: state.deviceID, members: members, lastSeen: state.lastSeen,
                              digests: state.peerDigests, now: now,
                              signers: state.viewSigners.filter { $0.key != state.deviceID },
                              pairedKeys: pairedKeys.filter { $0.key != state.deviceID })
        issues += peers.issues
        let knownDevices = members.union(state.lastSeen.keys).union([state.deviceID])
        var report = SyncRunner.run(store: snapshot, views: peers.views, device: state.deviceID, now: now,
                                    licenseKeys: licenseKeys, known: knownDevices)
        issues += report.issues

        let ownKey = Base64.encode(state.identity.signingPublicKey)
        var lastSeen = state.lastSeen.merging(peers.seen) { $1 }
        var digests = state.peerDigests.merging(peers.digests) { $1 }
        var signers = state.viewSigners.merging(peers.signers) { $1 }
        if lastSeen.count > Self.maxPeersSeen || digests.count > Self.maxPeersSeen || signers.count > Self.maxPeersSeen {
            lastSeen = lastSeen.filter { members.contains($0.key) }
            digests = digests.filter { members.contains($0.key) }
            signers = signers.filter { members.contains($0.key) }
        }
        var newState = state
        newState.lastSeen = lastSeen; newState.peerDigests = digests; newState.viewSigners = signers
        newState.membersEpoch = gk.epoch; newState.members = members.sorted(); newState.keyring = ringBytes
        let status = ownFileStatus(gk, state, ownStates: report.ownStates, now: now)
        if status.stale { issues.append(SyncIssue("stale-self", "this device had not synced for over a year")) }
        var fileCounter = status.counter
        let signedBefore = state.viewSigners[state.deviceID] == ownKey
        if status.present && !status.selfSigned
            && (fileCounter > state.ownCounter || (signedBefore && fileCounter == state.ownCounter)) {
            // Not written by this device: someone holding the group key wrote our file.
            issues.append(SyncIssue("own-file-rewritten", "\(state.deviceID)\(FolderLayout.deviceSuffix): counter "
                                    + "\(fileCounter), reserved \(state.ownCounter)"))
            if fileCounter - state.ownCounter > Self.maxCounterJump { fileCounter = state.ownCounter }
        } else if fileCounter > state.ownCounter {
            issues.append(SyncIssue("counter-resynced", "own file counter \(fileCounter) > reserved \(state.ownCounter)"))
        }
        let base = max(state.ownCounter, fileCounter)
        var needsWrite = status.needsWrite
        if base >= VersionVector.maxCounter {
            // Only a counter stored before the bounds existed can get here; never fail the whole run.
            issues.append(SyncIssue("counter-exhausted", "own counter \(base)"))
            needsWrite = false
        }
        let counter = base + 1
        if needsWrite { newState.ownCounter = counter; newState.viewSigners[state.deviceID] = ownKey }

        // Every read and check is done: commit once (records, meta, group state, reserved counter).
        let records = report.records ?? snapshot.records
        let meta = report.meta ?? snapshot.meta
        if records != snapshot.records || meta != snapshot.meta || newState != original {
            do {
                try store.commit(StoreChange(baseRevision: snapshot.revision, records: records, meta: meta, sync: newState))
            } catch {
                issues.append(SyncIssue("busy", "\(error)"))
                report.issues = issues
                report.wrote = false
                return report
            }
        }

        if needsWrite, let own = report.ownStates, let path = FolderLayout.deviceFile(state.deviceID),
           let sigPath = FolderLayout.signatureFile(state.deviceID) {
            do {
                let raw = try ViewFile.encode(key: gk, deviceID: state.deviceID, counter: counter, states: own,
                                              now: clock, random: random)
                let sig = try ViewSignature.sign(raw, header: try ViewFile.decodeHeader(raw), identity: state.identity)
                try access.writeAtomic(path, raw)
                try access.writeAtomic(sigPath, sig)
                report.wrote = true
            } catch let e as SyncFormatError {
                issues.append(SyncIssue("too-large", "\(e)"))
            } catch {
                issues.append(SyncIssue("write-failed", "\(error)"))
            }
        } else if needsWrite, report.ownStates != nil {
            issues.append(SyncIssue("write-failed", "device id is not a safe file name"))
        }
        report.issues = issues
        return report
    }

    // MARK: join and attach

    static func translate<T>(_ body: () throws -> T) throws -> T {
        do { return try body() } catch let e as FolderSyncError { throw e } catch let e as KeyringError {
            throw FolderSyncError(e.reason, e.detail)
        } catch let e as FolderAccessError {
            throw FolderSyncError("folder-error", "\(e)")
        } catch {
            throw FolderSyncError("folder-error", "\(error)")
        }
    }

    /// Join the group in the folder with the sync password and a fresh device identity, then run once.
    ///
    /// Refuses another group than the one this store is in (`different-group`) and a healthy membership of the
    /// same group (`already-joined`). A wrong password (`password`) or any refusal leaves store and folder untouched.
    public func join(store: any ItemStore, password: String, deviceName: String, random: some RandomSource,
                     clock: some UnixClock) throws -> RunReport {
        try join(store: store, deviceName: deviceName, random: random, clock: clock) {
            try Keyring.passwordKey($0, password: password)
        }
    }

    /// `join` with the Argon2id step injectable (tests pass a known key).
    func join(store: any ItemStore, deviceName: String, random: some RandomSource, clock: some UnixClock,
              passwordKey: (JSONValue) throws -> [UInt8]) throws -> RunReport {
        try Self.translate {
            let snapshot = try store.load()
            let raw: [UInt8]
            do { raw = try readKeyringBytes() } catch FolderAccessError.notFound {
                throw FolderSyncError("no-group", "no sync group in this folder")
            }
            let ring = try Keyring.parse(raw)
            if let state = snapshot.sync {
                if state.groupID != Keyring.str(Keyring.obj(ring)["group_id"]) {
                    throw FolderSyncError("different-group", "this vault already syncs with another group")
                }
                if state.installID == installID, state.hasFolder, healthyMember(ring, state) {
                    throw FolderSyncError("already-joined", "this vault is already a member")
                }
            }
            let identity = try DeviceIdentity.generate(random: random)
            let (newRing, gk) = try Keyring.join(ring, identity: identity, name: deviceName, random: random, now: clock) {
                try passwordKey(ring)
            }
            let written = try CanonicalJSON.encode(newRing, dialect: .utf8)
            try writeKeyring(written, expected: raw)
            let old = snapshot.sync
            // Counters seen at another epoch are dropped (see `epochReset`); the new identity signs afresh.
            let same = old != nil && old!.epoch == gk.epoch
            let newState = SyncGroupState(
                groupID: gk.groupID, epoch: gk.epoch, key: gk.key, identity: identity, installID: installID,
                hasFolder: true, lastSeen: same ? old!.lastSeen : [:], peerDigests: same ? old!.peerDigests : [:],
                membersEpoch: gk.epoch, members: Self.memberIDs(newRing).sorted(), keyring: written, ownCounter: 0)
            do {
                try store.commit(StoreChange(baseRevision: snapshot.revision, records: snapshot.records,
                                             meta: snapshot.meta, sync: newState))
            } catch {
                undoKeyringWrite(written: written, previous: raw)
                throw error
            }
            if let old, old.installID == installID, let path = FolderLayout.deviceFile(old.deviceID) {
                try? access.remove(path)  // our previous identity's file is obsolete
                if let sigPath = FolderLayout.signatureFile(old.deviceID) { try? access.remove(sigPath) }
            }
        }
        return runOnce(store: store, random: random, clock: clock)
    }

    /// Use the folder another device added to this store's Wi-Fi-only group (desktop `attach_folder`), then run once.
    public func attach(store: any ItemStore, password: String, deviceName: String, random: some RandomSource,
                       clock: some UnixClock) throws -> RunReport {
        try attach(store: store, deviceName: deviceName, random: random, clock: clock) {
            try Keyring.passwordKey($0, password: password)
        }
    }

    func attach(store: any ItemStore, deviceName: String, random: some RandomSource, clock: some UnixClock,
                passwordKey: (JSONValue) throws -> [UInt8]) throws -> RunReport {
        try Self.translate {
            let snapshot = try store.load()
            guard let state = snapshot.sync else { throw FolderSyncError("not-joined") }
            guard state.installID == installID else {
                throw FolderSyncError("rejoin-required", "this vault was joined on another installation")
            }
            guard !state.hasFolder else { throw FolderSyncError("already-has-folder", "this sync group already uses a cloud folder") }
            let raw: [UInt8]
            do { raw = try readKeyringBytes() } catch FolderAccessError.notFound {
                throw FolderSyncError("no-group", "no sync group in this folder")
            }
            let ring = try Keyring.parse(raw)
            guard Keyring.str(Keyring.obj(ring)["group_id"]) == state.groupID else {
                throw FolderSyncError("folder-has-other-group", "this folder holds another sync group")
            }
            let newRing = try Keyring.attach(ring, passwordKey: try passwordKey(ring), identity: state.identity,
                                             name: deviceName, stored: try state.groupKey(), random: random, now: clock)
            let written: [UInt8]
            if newRing == ring { written = raw } else {
                written = try CanonicalJSON.encode(newRing, dialect: .utf8)
                try writeKeyring(written, expected: raw)
            }
            var newState = state
            newState.hasFolder = true; newState.membersEpoch = state.epoch
            newState.members = Self.memberIDs(newRing).sorted(); newState.keyring = written
            do {
                try store.commit(StoreChange(baseRevision: snapshot.revision, records: snapshot.records,
                                             meta: snapshot.meta, sync: newState))
            } catch {
                if written != raw { undoKeyringWrite(written: written, previous: raw) }
                throw error
            }
        }
        return runOnce(store: store, random: random, clock: clock)
    }

    func healthyMember(_ ring: JSONValue, _ state: SyncGroupState) -> Bool {
        guard let trusted = try? state.groupKey(),
              (try? Keyring.accept(ring, trusted: trusted, identity: state.identity)) != nil else { return false }
        return Self.memberIDs(ring).contains(state.deviceID)
    }

    /// Best effort: put `previous` back if the folder still holds exactly `written`.
    func undoKeyringWrite(written: [UInt8], previous: [UInt8]) {
        guard (try? readKeyringBytes()) == written else { return }
        try? access.writeAtomic(FolderLayout.keyringPath, previous)
    }
}
