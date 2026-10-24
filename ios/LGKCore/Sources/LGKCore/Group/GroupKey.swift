/// A sealed-view format error; `reason` is the desktop `SyncFormatError.reason` string.
public struct SyncFormatError: Error, Equatable, Sendable, CustomStringConvertible {
    public let reason: String
    public let detail: String
    public init(_ reason: String, _ detail: String = "") { self.reason = reason; self.detail = detail }
    public var description: String { detail.isEmpty ? reason : "\(reason): \(detail)" }
}

/// Epoch group key (desktop `sync.group.GroupKey`).
public struct GroupKey: Equatable, Sendable {
    public static let recordInfo = Array("localgatekeys|sync|folder-record|v1|".utf8)
    public static let fileInfo = Array("localgatekeys|sync|folder-file|v1|".utf8)

    public let groupID: String
    public let epoch: Int64
    public let key: [UInt8]

    public init(groupID: String, epoch: Int64, key: [UInt8]) throws {
        guard Identifier.isValid(groupID) else { throw SyncFormatError("bad-group-key", "group_id") }
        guard (1...VersionVector.maxCounter).contains(epoch) else { throw SyncFormatError("bad-group-key", "epoch") }
        guard key.count == 32 else { throw SyncFormatError("bad-group-key", "key must be 32 bytes") }
        self.groupID = groupID; self.epoch = epoch; self.key = key
    }

    private func derive(_ label: [UInt8]) -> [UInt8] {
        CryptoBox.hkdf(ikm: key, salt: Array(groupID.utf8), info: label + Array(String(epoch).utf8), length: 32)
    }

    public var recordKey: [UInt8] { derive(Self.recordInfo) }
    public var fileKey: [UInt8] { derive(Self.fileInfo) }
}
