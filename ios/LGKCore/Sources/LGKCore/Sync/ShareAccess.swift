/// An edit in a collection this device holds as a member of a read-only share (desktop `ReadOnlyCollection`).
public struct ReadOnlyCollectionError: Error, Equatable, Sendable, CustomStringConvertible {
    public init() {}
    public var description: String { "read-only-collection" }
}

/// Sharing a collection needs Pro (desktop `share_group.ProRequired`, feature `sharing`).
public struct ShareProRequiredError: Error, Equatable, Sendable, CustomStringConvertible {
    public init() {}
    public var description: String { "pro-required" }
}

/// Who may do what with a shared collection (desktop `share_group` gating and `item_service.check_writable`; Kotlin
/// `ShareAccess`).
///
/// - Pro: creating, joining and syncing a share need Pro. Removing a member (a security action), approving and leaving
///   work without it; a device whose Pro lapsed keeps reading what it has.
/// - Read-only: a member of a `read` share never changes that collection's items (edit, move in or out, delete,
///   restore); a damaged share store fails closed (every shared collection read-only).
/// - Removal notices: only the pinned owner's key signs one, and the owner's own device never acts on one.
public enum ShareAccess {
    public enum Action: Sendable, CaseIterable {
        case create, join, sync, approve, remove, leave

        public var needsPro: Bool {
            switch self {
            case .create, .join, .sync: true
            case .approve, .remove, .leave: false
            }
        }
    }

    /// `ShareProRequiredError` when `action` needs Pro and `isPro` is false. Call before any key derivation.
    public static func requirePro(_ action: Action, isPro: Bool) throws {
        if action.needsPro && !isPro { throw ShareProRequiredError() }
    }

    /// One share this vault is in: the collection, this device's role (`owner` / `member`) and the fixed mode.
    public struct Membership: Equatable, Sendable {
        public let collectionID: String
        public let role: String
        public let sharedMode: String
        public init(collectionID: String, role: String, sharedMode: String) {
            self.collectionID = collectionID; self.role = role; self.sharedMode = sharedMode
        }
    }

    /// Collections this vault holds as a member of a read-only share. `memberships` nil means the share store could
    /// not be read: then every collection in `sharedCollectionIDs` is read-only (fail closed).
    public static func readOnlyCollectionIDs(_ memberships: [Membership]?, sharedCollectionIDs: Set<String>) -> Set<String> {
        guard let memberships else { return sharedCollectionIDs }
        return Set(memberships.filter { $0.role == "member" && $0.sharedMode == "read" }.map(\.collectionID))
    }

    /// `ReadOnlyCollectionError` if any of `records` (the item before and after a change; nil for none) is in a
    /// `readOnly` collection, so a move into or out of such a collection is refused too.
    public static func checkWritable(_ readOnly: Set<String>, _ records: JSONValue?...) throws {
        if readOnly.isEmpty { return }
        // Swift string equality is canonical equivalence: it can only match more ids, which refuses more (fail closed).
        for record in records {
            guard case .object(let o)? = record, case .array(let ids)? = o["collection_ids"] else { continue }
            for v in ids {
                if case .string(let s) = v, readOnly.contains(s) { throw ReadOnlyCollectionError() }
            }
        }
    }

    /// The removal watch of a member device in a share (desktop `share_watch`): the pinned owner is the only signer.
    /// Nil on the owner's own device. Verify a notice with `RemovalNotice.verify`.
    public static func removalWatch(groupID: String, deviceID: String, epoch: Int64, installID: String, folder: String,
                                    pin: ShareKeyring.Pin) -> RemovalWatch? {
        if Array(pin.owner.utf8) == Array(deviceID.utf8) { return nil }
        return RemovalWatch(groupID: groupID, deviceID: deviceID, epoch: epoch, installID: installID, folder: folder,
                            signers: [pin.owner: pin.ownerKey])
    }
}
