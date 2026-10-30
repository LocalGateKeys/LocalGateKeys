/// Attachment sync over the cloud folder (desktop `attachment_flow` folder part and `BlobFolder` on the folder).
///
/// * Blobs: `LocalGateKeys Sync/attachments/<blob_id>.lgkblob`, content addressed, written before the view
///   that references them, kept alive by `keep`, swept 7 days after no view references them.
/// * Capability: `attachments/<device_id>.lgkcap` is a zero-record format-1 view of the current epoch (counter
///   0), signed like a view in `attachments/<device_id>.lgkcap.lgksig`. It counts only when it decodes under the
///   group key, names that device and its signature verifies with the key this device trusts for it.
public struct FolderBlobs: Sendable {
    public let access: any FolderAccess

    public static let capSuffix = ".lgkcap"
    public static let capSigSuffix = ".lgkcap.lgksig"
    public static let maxCapBytes = 4096
    public static var dir: String { "\(FolderLayout.syncDir)/\(AttachmentSync.blobsDirName)" }

    public init(access: any FolderAccess) { self.access = access }

    public static func path(_ blobID: String) throws -> String {
        "\(dir)/\(try AttachmentSync.checkBlobID(blobID))\(AttachmentSync.blobSuffix)"
    }

    static func capPaths(_ deviceID: String) -> (cap: String, sig: String)? {
        guard Identifier.isSafeDeviceFile(deviceID) else { return nil }
        return ("\(dir)/\(deviceID)\(capSuffix)", "\(dir)/\(deviceID)\(capSigSuffix)")
    }

    // MARK: blobs

    public func ids() -> Set<String> {
        guard let names = try? access.list(Self.dir) else { return [] }
        var out = Set<String>()
        for name in names where name.hasSuffix(AttachmentSync.blobSuffix) {
            let stem = String(name.dropLast(AttachmentSync.blobSuffix.count))
            if AttachmentSync.isBlobID(stem) { out.insert(stem) }
        }
        return out
    }

    /// The verified blob (size, magic, content address), or nil.
    public func read(_ blobID: String) -> [UInt8]? {
        guard let path = try? Self.path(blobID),
              let raw = try? access.read(path, limit: AttachmentSync.maxBlobBytes + 1) else { return nil }
        return (try? AttachmentSync.checkBlobShape(raw, expectedID: blobID)) == nil ? nil : raw
    }

    /// Stores a blob; an existing one is kept unless `replace` (a wrong-length copy).
    public func write(_ blob: [UInt8], replace: Bool = false) throws {
        try AttachmentSync.checkBlobShape(blob)
        let path = try Self.path(AttachmentSync.blobID(blob))
        if !replace && access.exists(path) { return }
        try access.writeAtomic(path, blob)
    }

    /// Desktop `BlobFolder.keep`: the blob is there with the expected length; its time is refreshed once it is
    /// half the sweep age old. False when missing, of the wrong length or when the refresh failed.
    public func keep(_ blobID: String, size: Int, now: Int64) -> Bool {
        guard let path = try? Self.path(blobID), access.exists(path) else { return false }
        guard let attrs = access.fileAttributes(path) else {
            // No attributes on this folder: check the length by reading (no refresh is possible).
            return (try? access.read(path, limit: size + 1))?.count == size
        }
        guard attrs.size == size else { return false }
        if now - attrs.modified >= AttachmentSync.sweepMinAgeSeconds / 2 {
            do { try access.touch(path, modified: now) } catch { return false }
        }
        return true
    }

    /// Removes blobs no view references once older than the sweep age; a blob of unknown age is kept.
    @discardableResult
    public func sweep(referenced: Set<String>, now: Int64) -> [String] {
        var removed: [String] = []
        for id in ids().subtracting(referenced).sorted() {
            guard let path = try? Self.path(id), let attrs = access.fileAttributes(path),
                  now - attrs.modified >= AttachmentSync.sweepMinAgeSeconds else { continue }
            if (try? access.remove(path)) != nil { removed.append(id) }
        }
        return removed
    }

    // MARK: capability

    /// Whether `deviceID` published a valid capability file signed with `signer` (base64 Ed25519 key).
    public func capable(_ gk: GroupKey, deviceID: String, signer: String?) -> Bool {
        guard let signer, let paths = Self.capPaths(deviceID),
              let raw = try? access.read(paths.cap, limit: Self.maxCapBytes + 1), raw.count <= Self.maxCapBytes,
              let sig = try? access.read(paths.sig, limit: ViewSignature.maxBytes + 1), sig.count <= ViewSignature.maxBytes,
              let view = try? ViewFile.decode(raw, key: gk, expectedDeviceID: deviceID, maxBytes: Self.maxCapBytes, maxRecords: 0),
              let key = try? ViewSignature.verify(sig, raw: raw, header: view.header) else { return false }
        return Base64.encode(key) == signer
    }

    /// Writes this device's capability file unless a valid one is there; whether it wrote.
    @discardableResult
    public func writeCapability(_ gk: GroupKey, identity: DeviceIdentity, clock: some UnixClock,
                                random: some RandomSource) throws -> Bool {
        let own = Base64.encode(identity.signingPublicKey)
        if capable(gk, deviceID: identity.deviceID, signer: own) { return false }
        guard let paths = Self.capPaths(identity.deviceID) else { throw FolderSyncError("write-failed", "device id is not a safe file name") }
        let raw = try ViewFile.encode(key: gk, deviceID: identity.deviceID, counter: 0, states: [], now: clock, random: random)
        let sig = try ViewSignature.sign(raw, header: try ViewFile.decodeHeader(raw), identity: identity)
        try access.writeAtomic(paths.cap, raw)
        try access.writeAtomic(paths.sig, sig)
        return true
    }

    // MARK: run steps

    /// `import_missing` over the folder: every live document of the peer views whose blob this device lacks is
    /// read from the folder, verified against its reference and stored in `local`.
    public func importMissing(_ states: [ItemState], into local: any AttachmentBlobStore) -> [SyncIssue] {
        let (refs, issues) = Self.uniqueRefs(AttachmentDocuments.refs(states))
        var out = issues
        let have = local.ids()
        for ref in refs.sorted(by: { $0.blob < $1.blob }) where !have.contains(ref.blob) {
            guard let blob = read(ref.blob) else { continue }   // apply reports attachment-missing
            do {
                _ = try AttachmentSync.openBlob(blob, ref: ref)
                try local.write(blob)
            } catch let e as AttachmentSyncError {
                out.append(SyncIssue("attachment-refused", "\(ref.attachmentID): \(e.reason)"))
            } catch {
                out.append(SyncIssue("attachment-refused", "\(ref.attachmentID): \(error)"))
            }
        }
        return out
    }

    /// `publish_folder_blobs`: before the own view is written, every own document's blob is in the folder with
    /// the right length (kept, written, or rewritten when its copy has the wrong length).
    public func publishOwn(_ ownStates: [ItemState], from local: any AttachmentBlobStore, now: Int64) -> [SyncIssue] {
        var issues: [SyncIssue] = []
        let present = ids()
        var done = Set<String>()
        for ref in AttachmentDocuments.refs(ownStates) where !done.contains(ref.blob) {
            let exists = present.contains(ref.blob)
            if exists && keep(ref.blob, size: ref.blobSize, now: now) { done.insert(ref.blob); continue }
            guard let blob = local.read(ref.blob) else {
                issues.append(SyncIssue("attachment-missing", "own:\(ref.attachmentID)"))
                continue
            }
            do { try write(blob, replace: exists) } catch {
                issues.append(SyncIssue("write-failed", "attachment: \(error)"))
                continue
            }
            done.insert(ref.blob)
        }
        return issues
    }

    /// Desktop `unique_refs`: one reference per attachment id, at most `maxAttachments`.
    static func uniqueRefs(_ refs: [AttachmentRef]) -> ([AttachmentRef], [SyncIssue]) {
        var seen: [String: AttachmentRef] = [:]
        var order: [AttachmentRef] = []
        var issues: [SyncIssue] = []
        for ref in refs {
            if let known = seen[ref.attachmentID] {
                if known != ref { issues.append(SyncIssue("attachment-refused", "\(ref.attachmentID): two different files")) }
                continue
            }
            if seen.count >= AttachmentSync.maxAttachments {
                issues.append(SyncIssue("too-many-attachments", "\(AttachmentSync.maxAttachments)"))
                break
            }
            seen[ref.attachmentID] = ref
            order.append(ref)
        }
        return (order, issues)
    }
}
