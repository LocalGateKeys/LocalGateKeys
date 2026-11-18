/// A share group syncing through its own cloud folder (sub-plan 07; desktop `FolderSync(share=)`, `_share_run`,
/// `_share_keyring`, `_share_removed`). Same folder layout as the personal group.
///
/// - Pro only. Without Pro only the keyring step runs (a repair, an adoption, the owner's removal of this device:
///   security actions, like removing a member), then the run stops with `pro-required`: no view is read or written.
///   Never a licence, a document, an attachment, a witness, a heartbeat or a collection state: only the shared
///   collection's items (`ShareItemStore`).
/// - Keyring: the folder's keyring is adopted (`ShareGroups.adopt`: owner signature, pinned owner/collection/mode,
///   growth only within an epoch). On the owner's device, a folder keyring that others grew while the owner's own
///   approvals waited to be written is merged (approvals re-signed over the grown roster, the new joiners pending) and
///   written (`keyring-merged`). A missing keyring, or one this device's trusted keyring grows from (an older epoch,
///   fewer members or approvals: a member's tampering included), is replaced by the trusted one (`keyring-restored`).
///   So that nobody with write access to the folder can stop the share (`ShareGroups.restoresOver`): the owner's
///   device writes its trusted keyring back over any folder keyring it cannot adopt or reconcile, bytes that do not
///   parse and another group's keyring included (only a later epoch signed by the pinned owner key is left alone;
///   another group's keyring is reported as `other-group-replaced`, so two owners writing over each other show up); a
///   member's device writes back over a keyring of its trusted epoch that does not authenticate (MAC or owner
///   signature). An authenticated keyring of that epoch that does not grow (a concurrent join) still stops a member's
///   run, and a member never writes over another group's keyring (`folder-has-other-group`). A rotation that dropped
///   this device: the owner's removal notice for it (`removed/`) is verified with the pinned owner key only, the
///   collection's items leave (to Recently deleted, through the host's store) and the group is forgotten
///   (`share-removed`, detail: the collection id); without a valid notice the run stops with `rejoin-required`. A
///   member whose pending join was lost to another join at the same moment stops with `superseded` (join again).
/// - Approval: a device the owner has not approved adopts the keyring and stops (`awaiting-approval`): no peer view is
///   merged and no own view written. This holds honest clients back only; the share password itself opens the folder.
/// - Peers: only members the owner approved (and the owner), each view signed with its keyring key (the owner's with
///   its pinned key). Read-only shares: a member merges only the owner's view and the owner merges none, so only the
///   owner's edits flow, whatever a member's file holds.
/// - One commit for the merge and the share's state (the reserved counter included), then the own view (format 1,
///   signed).
extension FolderSync {
    /// Which share group a `FolderSync` runs, and what the host knows at the start of the run.
    public struct Share: Sendable {
        public let groupID: String
        /// Pro on this device: a free device's run does the keyring step only (a repair), then stops with
        /// `pro-required`.
        public let isPro: Bool
        /// Recently deleted as it is now (`ShareTrash.of(localData.trash)`).
        public let trash: ShareTrash

        public init(groupID: String, isPro: Bool, trash: ShareTrash) {
            self.groupID = groupID; self.isPro = isPro; self.trash = trash
        }
    }

    /// Whether a parsed folder keyring has an integer `format` above the newest this version reads (`update-required`).
    static func newerFormat(_ ring: JSONValue) -> Bool {
        guard let f = Keyring.int(Keyring.obj(ring)["format"]) else { return false }
        return f > Keyring.newestFormat
    }

    static func stop(_ kind: String, _ detail: String = "") -> RunReport {
        var r = RunReport()
        r.issues = [SyncIssue(kind, detail)]
        return r
    }

    /// One run of a share group's folder. Never throws: every problem is an issue in the report. The report's
    /// `records`/`meta` stay nil (the share view is not the store).
    func runShare(store: any ItemStore, share: Share, random: some RandomSource, clock: some UnixClock) -> RunReport {
        let now = clock.now
        let groupID = share.groupID
        let main: StoreSnapshot
        do { main = try store.load() } catch { return Self.stop("local-data", "\(error)") }
        let record: ShareRecord
        do {
            guard let found = try ShareGroups.records(in: main)[groupID] else { return Self.stop("not-joined", groupID) }
            record = found
        } catch {
            return Self.stop("state-corrupt", groupID)
        }
        guard ShareKeyring.same(record.state.installID, installID) else { return Self.stop("rejoin-required", "install-mismatch") }
        var issues: [SyncIssue] = []
        let stopped = shareKeyring(store: store, record: record, share: share, issues: &issues)
        guard share.isPro else {
            // Pro ended: the keyring step above still ran (a repair is a security action, like removing a member;
            // final review A2); no view is read or written.
            var report = RunReport()
            report.issues = (stopped?.issues ?? issues) + [SyncIssue("pro-required", groupID)]
            return report
        }
        if let stopped { return stopped }

        let shareStore = ShareItemStore(base: store, groupID: groupID, trash: share.trash)
        let view: ShareProjection
        do { view = try shareStore.projection() } catch let e as ShareGroupError where e.reason == "bad-state" {
            return Self.stop("state-corrupt", groupID)
        } catch {
            return Self.stop("local-data", "\(error)")
        }
        let info = view.record
        let state = info.state
        guard let ringBytes = state.keyring, let ring = try? ShareKeyring.parse(ringBytes), (try? state.groupKey()) != nil else {
            return Self.stop("keyring-corrupt", "no trusted keyring")
        }
        let own = state.deviceID, owner = info.pin.owner
        let approved = (ShareKeyring.approvedMembers(ring) ?? []).union([owner])
        // The key the views are sealed with: share v2, the content key only approved devices hold; share v1, the group
        // key.
        var viewKey: GroupKey? = nil
        if approved.contains(where: { ShareKeyring.same($0, own) }) {
            do { viewKey = try ShareGroups.viewKey(of: info) } catch {
                var tampered = RunReport()
                tampered.issues = issues + [SyncIssue("tampered", "\(error)")]
                return tampered
            }
        }
        guard let gk = viewKey else {
            // Not approved yet: the keyring was adopted above, but no peer view is merged and no own view is written
            // until the owner lets this device in (share v2: it cannot open them either).
            var pending = RunReport()
            pending.issues = issues + [SyncIssue("awaiting-approval", groupID)]
            return pending
        }
        // Read-only: only the owner's edits flow; the owner reads nobody.
        var members = info.pin.sharedMode == "read" ? Set([owner]) : approved
        members = members.filter { !ShareKeyring.same($0, own) && Identifier.isSafeDeviceFile($0) }
        var ringKeys = Keyring.memberSigningKeys(ring).filter { members.contains($0.key) }
        if members.contains(owner) { ringKeys[owner] = info.pin.ownerKey }
        let peers = readPeers(gk, ownID: own, members: members, lastSeen: state.lastSeen, digests: state.peerDigests,
                              now: now, signers: state.viewSigners.filter { members.contains($0.key) },
                              keyringKeys: ringKeys)
        issues += peers.issues
        let filtered = view.filter(peers.views)
        issues += filtered.issues
        var report = SyncRunner.run(store: view.snapshot, views: filtered.views, device: own, now: now,
                                    known: approved.union(state.lastSeen.keys))
        issues += report.issues

        let ownKey = Base64.encode(state.identity.signingPublicKey)
        let keep = approved.union([own])
        var newState = state
        newState.lastSeen = state.lastSeen.merging(peers.seen) { $1 }.filter { keep.contains($0.key) }
        newState.peerDigests = state.peerDigests.merging(peers.digests) { $1 }.filter { keep.contains($0.key) }
        newState.viewSigners = state.viewSigners.merging(peers.signers) { $1 }.merging(ringKeys) { $1 }
            .filter { keep.contains($0.key) }
        let accepted = peers.seen.filter { $0.value > (state.lastSeen[$0.key] ?? -1) }.keys
        newState = newState.synced(with: accepted.sorted(), now: now)
        let status = ownFileStatus(gk, state, ownStates: report.ownStates, now: now)
        var fileCounter = status.counter
        if status.present && !status.selfSigned && fileCounter > state.ownCounter {
            issues.append(SyncIssue("own-file-rewritten", "\(own)\(FolderLayout.deviceSuffix)"))
            if fileCounter - state.ownCounter > Self.maxCounterJump { fileCounter = state.ownCounter }
        }
        let counter = max(state.ownCounter, fileCounter) + 1
        var needsWrite = status.needsWrite && report.ownStates != nil
        if needsWrite && counter > VersionVector.maxCounter {
            issues.append(SyncIssue("counter-exhausted", "own counter \(counter - 1)"))
            needsWrite = false
        }
        if needsWrite {
            newState.ownCounter = counter
            newState.viewSigners[own] = ownKey
        }
        // Every read and check is done: one commit (the share's items, memberships, meta and state, the counter
        // reserved before the file carrying it is written).
        let records = report.records ?? view.snapshot.records
        let meta = report.meta ?? view.snapshot.meta
        report.records = nil
        report.meta = nil
        if records != view.snapshot.records || meta != view.snapshot.meta || newState != state {
            do {
                try shareStore.commit(StoreChange(baseRevision: view.snapshot.revision, records: records, meta: meta,
                                                  sync: newState))
            } catch {
                issues.append(SyncIssue("busy", "\(error)"))
                report.issues = issues
                report.wrote = false
                return report
            }
        }
        report.wrote = false
        if needsWrite, let ownStates = report.ownStates, let path = FolderLayout.deviceFile(own),
           let sigPath = FolderLayout.signatureFile(own) {
            do {
                let raw = try ViewFile.encode(key: gk, deviceID: own, counter: counter, states: ownStates, now: clock,
                                              random: random)
                let sig = try ViewSignature.sign(raw, header: try ViewFile.decodeHeader(raw), identity: state.identity)
                try access.writeAtomic(path, raw)
                try access.writeAtomic(sigPath, sig)
                report.wrote = true
            } catch let e as SyncFormatError {
                issues.append(SyncIssue("too-large", "\(e)"))
            } catch {
                issues.append(SyncIssue("write-failed", "\(error)"))
            }
        } else if needsWrite {
            issues.append(SyncIssue("write-failed", "device id is not a safe file name"))
        }
        report.issues = issues
        return report
    }

    /// Bring the folder keyring and the trusted one together (desktop `_share_keyring`); a report means the run stops.
    func shareKeyring(store: any ItemStore, record: ShareRecord, share: Share, issues: inout [SyncIssue]) -> RunReport? {
        let state = record.state
        guard var stored = state.keyring else { return Self.stop("keyring-corrupt", "no trusted keyring") }
        let raw: [UInt8]?
        do { raw = try readKeyringBytes() } catch FolderAccessError.notFound { raw = nil } catch {
            return Self.stop("keyring-unreadable", "\(error)")
        }
        if raw == stored { return nil }
        var merged = false
        var otherGroup = false
        var parsed: JSONValue?
        if let raw {
            do { parsed = try ShareGroups.parseLoose(raw) } catch {
                // Bytes that do not parse: the owner writes its keyring back; a member waits for it.
                guard ShareGroups.restoresOver(record, folder: nil) else { return Self.stop("keyring-corrupt", "\(error)") }
            }
            if let ring = parsed, Self.newerFormat(ring) {
                // A later app version wrote it: never write an older keyring over it.
                return Self.stop("update-required", FolderLayout.keyringName)
            }
            if let ring = parsed, !ShareKeyring.same(Keyring.str(Keyring.obj(ring)["group_id"]) ?? "", state.groupID) {
                guard ShareGroups.restoresOver(record, folder: ring) else {
                    return Self.stop("folder-has-other-group", FolderLayout.keyringName)
                }
                otherGroup = Keyring.str(Keyring.obj(ring)["group_id"]) != nil
                parsed = nil
            }
        }
        if let raw, let folderRing = parsed {
            do {
                try ShareGroups.adopt(store: store, groupID: state.groupID, keyring: raw)
                return nil
            } catch let e as ShareGroupError {
                return Self.stop(e.reason, e.detail)
            } catch let e as KeyringError {
                if e.reason == "removed" { return shareRemoved(store: store, record: record, folderRaw: raw, reason: e.reason, share: share) }
                let reconciled: Bool
                do { reconciled = try ShareGroups.reconcileOwner(store: store, groupID: state.groupID, keyring: raw) } catch {
                    return Self.stop("busy", "\(error)")
                }
                if reconciled {
                    // The owner's approvals, re-signed over the folder's grown roster: write that.
                    guard let fresh = try? ShareGroups.records(in: store.load())[state.groupID]?.state.keyring else {
                        return Self.stop("local-data", "the merged keyring cannot be read back")
                    }
                    stored = fresh
                    merged = true
                    issues.append(SyncIssue("keyring-merged", FolderLayout.keyringName))
                } else if let storedRing = try? ShareKeyring.parse(stored), ShareKeyring.growsFrom(old: folderRing, new: storedRing) {
                    // The folder is behind this device: the trusted keyring is written back below.
                } else if ShareGroups.supersededJoin(record, folder: folderRing) {
                    // Someone joined at the same moment and this device's join was lost: join again.
                    return Self.stop("superseded", state.groupID)
                } else if ShareGroups.restoresOver(record, folder: folderRing) {
                    // The owner's keyring over anything else; a member's over a copy that fails to authenticate.
                } else {
                    if Self.rejoinReasons.contains(e.reason) {
                        return shareRemoved(store: store, record: record, folderRaw: raw, reason: e.reason, share: share)
                    }
                    return Self.stop(Self.keyringKind(e.reason), "\(e)")
                }
            } catch {
                return Self.stop("busy", "\(error)")
            }
        }
        do {
            try writeKeyring(stored, expected: raw)
        } catch let e as FolderSyncError {
            return Self.stop(e.reason, e.detail)
        } catch {
            return Self.stop("write-failed", "keyring: \(error)")
        }
        // Another share's keyring that the owner replaced is said apart (final review A1): two owners of different
        // groups in one folder would otherwise overwrite each other without a word.
        if raw != nil && !merged {
            issues.append(SyncIssue(otherGroup ? "other-group-replaced" : "keyring-restored", FolderLayout.keyringName))
        }
        return nil
    }

    /// The folder's keyring no longer lets this device in: act on the owner's notice, if there is one (desktop
    /// `_share_removed`).
    func shareRemoved(store: any ItemStore, record: ShareRecord, folderRaw: [UInt8], reason: String, share: Share) -> RunReport {
        guard let notice = readShareNotice(record.state.deviceID) else { return Self.stop("rejoin-required", reason) }
        do {
            try ShareGroups.applyShareRemoval(store: store, groupID: record.groupID, notice: notice,
                                              folderKeyring: folderRaw, trash: share.trash)
        } catch let e as RemovalError {
            return Self.stop("rejoin-required", "\(reason); notice refused (\(e.reason))")
        } catch let e as ShareGroupError {
            // Recently deleted full, or the store refused: nothing changed, the next run tries again.
            return Self.stop(e.reason, e.detail)
        } catch {
            return Self.stop("item-error", "\(error)")
        }
        return Self.stop("share-removed", record.collectionID)
    }

    /// The removal notice for `deviceID` in the folder; nil when missing, too large or unreadable.
    func readShareNotice(_ deviceID: String) -> [UInt8]? {
        guard let path = RemovalNotice.path(deviceID),
              let raw = try? access.read(path, limit: RemovalNotice.maxBytes + 1), raw.count <= RemovalNotice.maxBytes else {
            return nil
        }
        return raw
    }

    /// Writes the owner's removal `notice` for `deviceID` (`ShareGroups.removeMember`) before the rotated keyring;
    /// false when it could not be written.
    public func publishShareNotice(deviceID: String, notice: [UInt8]) -> Bool {
        guard let path = RemovalNotice.path(deviceID), (try? access.writeAtomic(path, notice)) != nil else { return false }
        return true
    }

    /// Puts this device's trusted keyring of the share group into the folder now (after create, join, approve or
    /// remove; the share run also does it). False when the folder holds something else it may not replace or cannot
    /// be written.
    public func writeShareKeyring(store: any ItemStore, groupID: String) -> Bool {
        guard let snapshot = try? store.load(), let all = try? ShareGroups.records(in: snapshot),
              let ring = all[groupID]?.state.keyring else { return false }
        let current: [UInt8]?
        do { current = try readKeyringBytes() } catch FolderAccessError.notFound { current = nil } catch { return false }
        if current == ring { return true }
        if let current {
            // A later app version's keyring is never replaced by this one.
            if let folder = try? ShareGroups.parseLoose(current), Self.newerFormat(folder) { return false }
            // Only over an older state of the same group (never another group's keyring). Bytes that do not even parse
            // are not replaced here either (fails closed: false); the next share run reports `keyring-corrupt` and the
            // user clears the folder. Desktop `_write_keyring` would overwrite them.
            guard let folder = try? ShareGroups.parseLoose(current), let mine = try? ShareKeyring.parse(ring),
                  ShareKeyring.growsFrom(old: folder, new: mine) else { return false }
        }
        return (try? writeKeyring(ring, expected: current)) != nil
    }

    /// Whether the folder already holds a sync group's keyring (a new share refuses it: `folder-in-use`).
    public func holdsKeyring() -> Bool { access.exists(FolderLayout.keyringPath) }
}
