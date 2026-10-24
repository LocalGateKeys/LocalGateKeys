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
}
