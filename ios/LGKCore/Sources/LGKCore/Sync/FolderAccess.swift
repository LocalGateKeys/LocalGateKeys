/// File access inside the folder the user picked (iCloud Drive, OneDrive, Dropbox...).
///
/// Paths are relative to that folder, `/`-separated. Layout:
/// `LocalGateKeys Sync/keyring.lgkkeys`, `LocalGateKeys Sync/devices/<device_id>.lgksync` and
/// `LocalGateKeys Sync/signatures/<device_id>.lgksig`.
public protocol FolderAccess: Sendable {
    /// Names (not paths) of the entries of `dir`; throws `FolderAccessError.notFound` when it is missing.
    func list(_ dir: String) throws -> [String]
    /// At most `limit` bytes of `path`; throws `FolderAccessError.notFound` when it is missing.
    func read(_ path: String, limit: Int) throws -> [UInt8]
    /// Writes through a temp file in the same directory and an atomic replace; creates parent directories.
    func writeAtomic(_ path: String, _ data: [UInt8]) throws
    func remove(_ path: String) throws
    /// True for an existing file or directory.
    func exists(_ path: String) -> Bool
    /// Size in bytes and modification time (Unix seconds) of a regular file; nil when unknown. Attachment
    /// sync uses it to keep blobs alive and to sweep old ones (an unknown time is never swept).
    func fileAttributes(_ path: String) -> (size: Int, modified: Int64)?
    /// Sets the modification time of an existing file (attachment `keep`).
    func touch(_ path: String, modified: Int64) throws
}

extension FolderAccess {
    public func fileAttributes(_ path: String) -> (size: Int, modified: Int64)? { nil }
    public func touch(_ path: String, modified: Int64) throws {}
}

public enum FolderAccessError: Error, Equatable, Sendable {
    case notFound(String)
    case io(String)
}

/// Folder layout (desktop `folder_transport` constants).
public enum FolderLayout {
    public static let syncDir = "LocalGateKeys Sync"
    public static let keyringName = "keyring.lgkkeys"
    public static let devicesDirName = "devices"
    public static let deviceSuffix = ".lgksync"
    public static var keyringPath: String { "\(syncDir)/\(keyringName)" }
    public static var devicesDir: String { "\(syncDir)/\(devicesDirName)" }
    public static let signaturesDirName = "signatures"
    public static let signatureSuffix = ".lgksig"
    public static var signaturesDir: String { "\(syncDir)/\(signaturesDirName)" }

    /// Path of `deviceID`'s file; nil unless the id is a safe file name.
    public static func deviceFile(_ deviceID: String) -> String? {
        Identifier.isSafeDeviceFile(deviceID) ? "\(devicesDir)/\(deviceID)\(deviceSuffix)" : nil
    }

    /// Path of `deviceID`'s view signature (desktop `signature_file`); nil unless the id is a safe file name.
    public static func signatureFile(_ deviceID: String) -> String? {
        Identifier.isSafeDeviceFile(deviceID) ? "\(signaturesDir)/\(deviceID)\(signatureSuffix)" : nil
    }

    /// Witness files (2026-10-29): `witness/<id>.lgksync` (a format-2 view with zero records) next to a
    /// format-1 view, and `witness/<id>.lgksig`, its signature by the same key.
    public static let witnessDirName = "witness"
    public static var witnessDir: String { "\(syncDir)/\(witnessDirName)" }

    /// Path of `deviceID`'s witness file; nil unless the id is a safe file name.
    public static func witnessFile(_ deviceID: String) -> String? {
        Identifier.isSafeDeviceFile(deviceID) ? "\(witnessDir)/\(deviceID)\(deviceSuffix)" : nil
    }

    /// Path of the signature of `deviceID`'s witness file; nil unless the id is a safe file name.
    public static func witnessSignatureFile(_ deviceID: String) -> String? {
        Identifier.isSafeDeviceFile(deviceID) ? "\(witnessDir)/\(deviceID)\(signatureSuffix)" : nil
    }
}
