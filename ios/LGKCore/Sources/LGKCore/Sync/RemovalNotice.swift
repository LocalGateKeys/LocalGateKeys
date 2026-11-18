import Foundation
import Crypto

/// Signed removal notices (desktop `localvault.sync.removal`; design `docs/design/security-2026-10-30/wp-a-design.md`).
///
/// The existing "maybe removed" issues (`removed-or-conflict`, `rejoin-required`...) are inferences anyone with the
/// group key or folder access can cause, so nothing ever erases on them. A notice is signed by the member that
/// removed the device, with the member signing key the removed device already trusted (`signing_public` in the
/// keyring it accepted before the removal); only a verified notice may lead to an erase.
///
/// Notice (`LocalGateKeys Sync/removed/<device id>.lgkremoved`, canonical JSON, at most 4 KiB):
///
///     {"format":1,"group_id","device_id","epoch","signer","issued_at","sig"}
///
/// `sig` is standard base64 of the Ed25519 signature over `label + canonical_json(body)` (the notice without
/// `sig`). The layout need not be canonical: the signed message is rebuilt from the parsed values. `epoch` is the
/// epoch the removal created. Check order and reason codes are the desktop `verify_notice`'s, case for case
/// (`tests/vectors/sync/removal/SCHEMA.md`).
public struct RemovalError: Error, Equatable, Sendable, CustomStringConvertible {
    public let reason: String
    public init(_ reason: String) { self.reason = reason }
    public var description: String { reason }
}

/// The fields of a notice other than its signature.
public struct RemovalNoticeBody: Equatable, Sendable {
    public let groupID: String
    public let deviceID: String
    public let epoch: Int64
    public let signer: String
    public let issuedAt: Int64

    public init(groupID: String, deviceID: String, epoch: Int64, signer: String, issuedAt: Int64) {
        self.groupID = groupID; self.deviceID = deviceID; self.epoch = epoch; self.signer = signer; self.issuedAt = issuedAt
    }
}

public enum RemovalNotice {
    public static let format: Int64 = 1
    public static let label = Array("localgatekeys|sync|removal-notice|v1|".utf8)
    public static let removedDirName = "removed"
    public static let suffix = ".lgkremoved"
    public static let maxBytes = 4096
    /// The issue a folder run reports when a notice for this device verified (detail: the signer's device id).
    public static let issueKind = "removal-notice"
    static let maxInt: Int64 = (1 << 53) - 1
    static let fields: Set<String> = ["format", "group_id", "device_id", "epoch", "signer", "issued_at", "sig"]

    public static var removedDir: String { "\(FolderLayout.syncDir)/\(removedDirName)" }

    /// Path of the notice for `deviceID`; nil unless the id is a safe file name.
    public static func path(_ deviceID: String) -> String? {
        Identifier.isSafeDeviceFile(deviceID) ? "\(removedDir)/\(deviceID)\(suffix)" : nil
    }

    static func isInt(_ v: Int64) -> Bool { v >= 0 && v <= maxInt }

    /// Code-point (byte) equality: Swift `==` is canonical equivalence, the desktop compares code points.
    static func same(_ a: String, _ b: String) -> Bool { Array(a.utf8) == Array(b.utf8) }

    static func body(_ n: RemovalNoticeBody) -> [String: JSONValue] {
        ["format": .int(format), "group_id": .string(n.groupID), "device_id": .string(n.deviceID), "epoch": .int(n.epoch),
         "signer": .string(n.signer), "issued_at": .int(n.issuedAt)]
    }

    /// What the signature covers: the label, then the canonical JSON of the six body fields.
    public static func message(_ n: RemovalNoticeBody) throws -> [UInt8] {
        label + (try CanonicalJSON.encode(.object(body(n)), dialect: .utf8))
    }

    /// The notice bytes (canonical JSON, no newline) that `n.signer` removed `n.deviceID`; `sign` returns the
    /// 64-byte Ed25519 signature of its argument. `bad-notice` for an invalid id, an epoch or `issued_at` outside
    /// 0...2^53-1, or a signer that is the removed device (desktop `make_notice`).
    public static func make(_ n: RemovalNoticeBody, sign: ([UInt8]) throws -> [UInt8]) throws -> [UInt8] {
        guard Identifier.isValid(n.groupID), Identifier.isValid(n.deviceID), Identifier.isValid(n.signer),
              isInt(n.epoch), isInt(n.issuedAt), !same(n.signer, n.deviceID) else { throw RemovalError("bad-notice") }
        let sig: [UInt8]
        do { sig = try sign(try message(n)) } catch { throw RemovalError("bad-notice") }
        guard sig.count == 64 else { throw RemovalError("bad-notice") }
        var o = body(n)
        o["sig"] = .string(Base64.encode(sig))
        return try CanonicalJSON.encode(.object(o), dialect: .utf8)
    }

    /// The notice `identity` signs that it removed `deviceID` from `groupID` at `epoch`.
    public static func make(identity: DeviceIdentity, groupID: String, deviceID: String, epoch: Int64,
                            issuedAt: Int64) throws -> [UInt8] {
        try make(RemovalNoticeBody(groupID: groupID, deviceID: deviceID, epoch: epoch, signer: identity.deviceID,
                                   issuedAt: issuedAt)) { try identity.sign($0) }
    }

    /// (notice, signed message, signature); throws `RemovalError("bad-notice")` (desktop `parse_notice`).
    public static func parse(_ raw: [UInt8]) throws -> (notice: RemovalNoticeBody, message: [UInt8], signature: [UInt8]) {
        guard raw.count <= maxBytes, case .object(let o)? = try? CanonicalJSON.parse(raw), Set(o.keys) == fields,
              o["format"] == .int(format),
              case .string(let group)? = o["group_id"], Identifier.isValid(group),
              case .string(let device)? = o["device_id"], Identifier.isValid(device),
              case .string(let signer)? = o["signer"], Identifier.isValid(signer),
              case .int(let epoch)? = o["epoch"], isInt(epoch),
              case .int(let issued)? = o["issued_at"], isInt(issued),
              case .string(let sigText)? = o["sig"],
              let sig = try? Base64.decodeStrict(sigText), sig.count == 64 else { throw RemovalError("bad-notice") }
        let notice = RemovalNoticeBody(groupID: group, deviceID: device, epoch: epoch, signer: signer, issuedAt: issued)
        guard let signed = try? message(notice) else { throw RemovalError("bad-notice") }
        return (notice, signed, sig)
    }

    /// The notice `raw` if it proves that `watch`'s device was removed; else `RemovalError` with the desktop
    /// `verify_notice` reason (`bad-notice`, `not-for-this-device`, `stale`, `unknown-signer`, `bad-key`,
    /// `bad-signature`, `keyring`), checked in that order. `folderKeyring`: the bytes of the folder's current
    /// keyring, corroboration only (never authenticated, as on the desktop).
    public static func verify(_ raw: [UInt8], watch: RemovalWatch, folderKeyring: [UInt8]) throws -> RemovalNoticeBody {
        let (notice, signed, sig) = try parse(raw)
        guard same(notice.groupID, watch.groupID), same(notice.deviceID, watch.deviceID) else {
            throw RemovalError("not-for-this-device")
        }
        guard !same(notice.signer, watch.deviceID), notice.epoch > watch.epoch else { throw RemovalError("stale") }
        guard let keyText = watch.signers.first(where: { same($0.key, notice.signer) })?.value else {
            throw RemovalError("unknown-signer")
        }
        guard let key = try? Base64.decodeStrict(keyText), key.count == 32 else { throw RemovalError("bad-key") }
        guard DeviceIdentity.verify(signature: sig, message: signed, publicKey: key) else {
            throw RemovalError("bad-signature")
        }
        guard folderKeyring.count <= Keyring.maxKeyringBytes,
              case .object(let ring)? = try? CanonicalJSON.parse(folderKeyring),
              case .string(let group)? = ring["group_id"], Identifier.isValid(group),
              case .int(let epoch)? = ring["epoch"], isInt(epoch),
              case .array(let members)? = ring["members"] else { throw RemovalError("keyring") }
        // Entries that are not objects with a text device id are ignored.
        let listed = members.contains { m in
            if case .object(let mo) = m, case .string(let id)? = mo["device_id"] { return same(id, watch.deviceID) }
            return false
        }
        guard same(group, watch.groupID), epoch >= notice.epoch, !listed else { throw RemovalError("keyring") }
        return notice
    }

    /// The verified notice for `watch`'s device in `access`, or nil (desktop `check`; never throws). Nothing is
    /// accepted for another installation than the one that joined.
    public static func check(_ watch: RemovalWatch, access: any FolderAccess, installID: String) -> RemovalNoticeBody? {
        guard same(watch.installID, installID), let path = path(watch.deviceID),
              let raw = try? access.read(path, limit: maxBytes + 1), raw.count <= maxBytes,
              let ring = try? access.read(FolderLayout.keyringPath, limit: Keyring.maxKeyringBytes + 1),
              ring.count <= Keyring.maxKeyringBytes else { return nil }
        return try? verify(raw, watch: watch, folderKeyring: ring)
    }
}

/// The removal watch file (desktop `Watch`, `<vault stem>.sync-watch.json` next to the vault, plain canonical JSON):
/// the trusted group id, device id, epoch, install id, folder and the member signing keys of the trusted keyring,
/// so the app can check for a notice while the vault is locked. Written from the trusted sync state on every folder
/// run and deleted when the vault leaves or resets sync. Someone who can edit it could only stop an erase.
public struct RemovalWatch: Equatable, Sendable {
    public static let version: Int64 = 1
    public static let suffix = ".sync-watch.json"
    public static let maxBytes = 16 * 1024
    static let fields: Set<String> = ["version", "group_id", "device_id", "epoch", "install_id", "folder", "signers"]

    public var groupID: String
    public var deviceID: String
    public var epoch: Int64
    public var installID: String
    public var folder: String
    /// Device id -> base64 Ed25519 signing key of every confirmed member that may sign a notice.
    public var signers: [String: String]

    public init(groupID: String, deviceID: String, epoch: Int64, installID: String, folder: String,
                signers: [String: String]) {
        self.groupID = groupID; self.deviceID = deviceID; self.epoch = epoch; self.installID = installID
        self.folder = folder; self.signers = signers
    }

    /// The watch file name for a vault file name (desktop `watch_path`: the stem, then the suffix).
    public static func fileName(forVault name: String) -> String {
        var stem = Substring(name)
        if let dot = name.lastIndex(of: "."), dot != name.startIndex, name.index(after: dot) != name.endIndex {
            stem = name[..<dot]
        }
        return String(stem) + suffix
    }

    /// The file content (canonical JSON, UTF-8, no newline; desktop `canonical_json(watch.to_dict())`).
    public func encoded() -> [UInt8] {
        let o: [String: JSONValue] = [
            "version": .int(Self.version), "group_id": .string(groupID), "device_id": .string(deviceID),
            "epoch": .int(epoch), "install_id": .string(installID), "folder": .string(folder),
            "signers": .object(signers.mapValues { .string($0) }),
        ]
        return (try? CanonicalJSON.encode(.object(o), dialect: .utf8)) ?? []
    }

    /// The watch in `raw`, or nil when it is not valid (desktop `load_watch`). Signer keys are not checked as
    /// base64 here; `RemovalNotice.verify` reports `bad-key` later.
    public static func parse(_ raw: [UInt8]) -> RemovalWatch? {
        guard raw.count <= maxBytes, case .object(let o)? = try? CanonicalJSON.parse(raw), Set(o.keys) == fields,
              o["version"] == .int(version),
              case .string(let group)? = o["group_id"], Identifier.isValid(group),
              case .string(let device)? = o["device_id"], Identifier.isValid(device),
              case .int(let epoch)? = o["epoch"], RemovalNotice.isInt(epoch),
              case .string(let install)? = o["install_id"], !install.isEmpty,
              case .string(let folder)? = o["folder"], !folder.isEmpty,
              case .object(let s)? = o["signers"] else { return nil }
        var signers: [String: String] = [:]
        for (id, value) in s {
            guard Identifier.isValid(id), case .string(let key) = value else { return nil }
            signers[id] = key
        }
        return RemovalWatch(groupID: group, deviceID: device, epoch: epoch, installID: install, folder: folder,
                            signers: signers)
    }

    /// The watch for a trusted state (desktop `watch_from_state`); nil without a readable keyring. Signers are the
    /// members of the trusted keyring with a signing key, except this device, the members the user has not
    /// confirmed yet (`unacked`: anyone with the sync password can add one, with a key of their choosing) and
    /// invalid ids. The keyring is only parsed, not verified again (it was accepted when it was stored).
    public static func derive(groupID: String, deviceID: String, epoch: Int64, installID: String, keyring: [UInt8]?,
                              unacked: [String], folder: String) -> RemovalWatch? {
        guard let keyring, keyring.count <= Keyring.maxKeyringBytes,
              let ring = try? CanonicalJSON.parse(keyring), case .object = ring else { return nil }
        let unconfirmed = Set(unacked.map { Array($0.utf8) })
        var signers: [String: String] = [:]
        for (id, key) in Keyring.memberSigningKeys(ring)
        where Identifier.isValid(id) && !RemovalNotice.same(id, deviceID) && !unconfirmed.contains(Array(id.utf8)) {
            signers[id] = key
        }
        return RemovalWatch(groupID: groupID, deviceID: deviceID, epoch: epoch, installID: installID, folder: folder,
                            signers: signers)
    }

    /// `derive` for a stored group state.
    public static func derive(_ state: SyncGroupState, folder: String) -> RemovalWatch? {
        derive(groupID: state.groupID, deviceID: state.deviceID, epoch: state.epoch, installID: state.installID,
               keyring: state.keyring, unacked: state.unackedMembers, folder: folder)
    }

    /// `fresh` with each signer's key pinned to the one `old` (the stored watch) already had (desktop `pinned`).
    ///
    /// Anyone with the group key can rewrite the keyring at the same epoch, including a member's `signing_public`
    /// (the proof is signed by the new key itself). A device never changes its key (re-joining makes a new device
    /// id), so the first key seen for a member stays the one a notice must carry; members gone from the trusted
    /// keyring are dropped. Another group or device id: `fresh` as it is.
    public static func pinned(_ fresh: RemovalWatch, old: RemovalWatch?) -> RemovalWatch {
        guard let old, RemovalNotice.same(old.groupID, fresh.groupID), RemovalNotice.same(old.deviceID, fresh.deviceID) else {
            return fresh
        }
        var out = fresh
        out.signers = [:]
        for (id, key) in fresh.signers { out.signers[id] = old.signers[id] ?? key }
        return out
    }

    /// Stores `fresh` pinned against the stored watch and returns what was stored (desktop `refresh_watch`; nil
    /// store: `fresh`, nothing written). Never throws; the file is written only when its content changes.
    @discardableResult
    public static func refresh(_ store: (any RemovalWatchStore)?, _ fresh: RemovalWatch) -> RemovalWatch {
        guard let store else { return fresh }
        let stored = store.load()
        let watch = pinned(fresh, old: stored.flatMap(parse))
        let data = watch.encoded()
        if stored != data { store.save(data) }
        return watch
    }
}

/// Where the watch file lives (next to the vault). Every method is best effort and never throws.
public protocol RemovalWatchStore: Sendable {
    /// The folder text the watch records (the cloud folder's path; information for the locked check).
    var folder: String { get }
    func load() -> [UInt8]?
    func save(_ data: [UInt8])
    func forget()
}

/// The watch file at `url` (atomic writes; a missing or oversized file reads as nil).
public struct FileRemovalWatchStore: RemovalWatchStore {
    public let url: URL
    public let folder: String

    public init(url: URL, folder: String) { self.url = url; self.folder = folder }

    public func load() -> [UInt8]? {
        guard let h = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? h.close() }
        guard let data = try? h.read(upToCount: RemovalWatch.maxBytes + 1), data.count <= RemovalWatch.maxBytes else {
            return nil
        }
        return Array(data)
    }

    public func save(_ data: [UInt8]) {
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? Data(data).write(to: url, options: .atomic)
    }

    public func forget() { try? FileManager.default.removeItem(at: url) }
}
