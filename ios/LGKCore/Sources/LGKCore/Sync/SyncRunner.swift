/// One sync run shared by every transport: local view -> fold peer views -> one apply (desktop `runner.run_merge`).
///
/// Pure: it never touches the store. The returned report carries the new `records` and `meta`, which the
/// transport commits only once every read and check has succeeded.
public enum SyncRunner {
    /// Folds `views` into the local view of `store` and applies the outcome.
    ///
    /// * A peer state whose version vector is implausible next to the local state of that id
    ///   (`Plausibility.implausibleVV`; audit M-6) is quarantined before the fold (`implausible-vv`, detail
    ///   `<device>:<item>`). Known devices: `device`, the views' devices and `known`.
    /// * A view the engine rejects as a whole is dropped (`bad-peer-data`).
    /// * A single peer record that cannot be stored is quarantined (`bad-peer-record`, or `update-needed`
    ///   for a newer wrapper schema; detail `<device>:<item>`); the rest of that view merges.
    /// * An apply that still fails gives `apply-failed`; nothing is applied but `ownStates` carries the local view.
    /// * A store that cannot be read for sync gives `local-data` and no `ownStates` (publish nothing).
    /// * A received document (attachment sync) whose blob is not in `blobs` yet is quarantined as
    ///   `attachment-missing`: it is never applied without its file, and the next run retries.
    public static func run(store: StoreSnapshot, views: [PeerView], device: String, now: Int64,
                           licenseKeys: [String: [UInt8]] = [:], known: Set<String> = [],
                           blobs: (any AttachmentBlobStore)? = nil) -> RunReport {
        var report = RunReport()
        let local: (states: [String: ItemState], meta: [String: SyncMeta], skipped: [String: String])
        do {
            local = try SyncMeta.localView(records: store.records, meta: store.meta, device: device, now: now)
        } catch {
            report.issues.append(SyncIssue("local-data", "\(error)"))
            return report
        }
        let localSkipped = local.skipped.sorted { scalarOrder($0.key, $1.key) }.map { ($0.key, $0.value) }
        report.skipped = localSkipped
        let knownAll = known.union([device]).union(views.map(\.deviceID))
        let plausible = views.map { view -> PeerView in
            let kept = view.states.filter { s in
                let why = Plausibility.implausibleVV(s.vv, local: local.states[s.itemID]?.vv, known: knownAll)
                if why != nil { report.issues.append(SyncIssue("implausible-vv", "\(view.deviceID):\(s.itemID)")) }
                return why == nil
            }
            return kept.count == view.states.count ? view : PeerView(deviceID: view.deviceID, states: kept)
        }
        let fold = Engine.fold(local: local.states, views: plausible, ownDeviceID: device) { state in
            check(state, licenseKeys: licenseKeys, blobs: blobs)
        }
        for dev in fold.badViews { report.issues.append(SyncIssue("bad-peer-data", dev)) }
        for q in fold.quarantined {
            let kind = ["update-needed", "attachment-missing"].contains(q.reason) ? q.reason : "bad-peer-record"
            report.issues.append(SyncIssue(kind, "\(q.device):\(q.item)"))
        }
        let applied: SyncMeta.ApplyResult
        do {
            applied = try SyncMeta.applyRemote(fold.outcome, records: store.records, meta: local.meta, device: device,
                                               now: now, licenseKeys: licenseKeys)
        } catch {
            report.issues.append(SyncIssue("apply-failed", "\(error)"))
            report.ownStates = sorted(local.states)
            report.records = store.records
            report.meta = local.meta
            return report
        }
        let final: (states: [String: ItemState], meta: [String: SyncMeta], skipped: [String: String])
        do {
            final = try SyncMeta.localView(records: applied.records, meta: applied.meta, device: device, now: now)
        } catch {
            report.issues.append(SyncIssue("local-data", "\(error)"))
            return report
        }
        report.applied = applied.applied
        report.deleted = applied.deleted
        report.conflicts = applied.conflicts
        report.licenses = applied.licenses
        let skipped = Set(localSkipped.map { [$0.0, $0.1] }).union(final.skipped.map { [$0.key, $0.value] })
        report.skipped = skipped.sorted { $0.lexicographicallyPrecedes($1) }.map { ($0[0], $0[1]) }
        report.ownStates = sorted(final.states)
        report.records = applied.records
        report.meta = final.meta
        return report
    }

    static func sorted(_ states: [String: ItemState]) -> [ItemState] {
        states.values.sorted { $0.itemID < $1.itemID }
    }

    /// The bridge's refusal for a state the fold wants to store, or nil (plays desktop `apply`'s per-record check).
    static func check(_ state: ItemState, licenseKeys: [String: [UInt8]], blobs: (any AttachmentBlobStore)? = nil) -> String? {
        guard !state.deleted, let item = state.item else { return nil }
        let isCopy: Bool
        if case .object(let o) = item {
            // applyRemote drops these without a word: a licence this build cannot verify, or a licence conflict copy.
            // (a copy never carries a `lic:` id; a `lic:` state with a top-level id is refused below).
            isCopy = o["id"] != nil && !Wrapper.isLicenseID(state.itemID)
            if o["ns"] == .string(Namespace.license.rawValue) && (licenseKeys.isEmpty || isCopy) { return nil }
        } else {
            isCopy = false
        }
        do {
            _ = try Wrapper.unwrap(state, isCopy: isCopy, licenseKeys: licenseKeys)
            if let ref = AttachmentDocuments.ref(of: item), blobs?.has(ref.blob) != true { return "attachment-missing" }
            return nil
        } catch let e as RecordError {
            return e.reason ?? "bad-remote"
        } catch {
            return "bad-remote"
        }
    }
}
