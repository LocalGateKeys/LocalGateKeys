package app.localgatekeys.core.sync

import app.localgatekeys.core.primitives.Identifier

/** [kind] NOT_FOUND: the path is missing; IO: anything else. */
class FolderAccessException(val kind: Kind, val detail: String) : Exception("${kind.name.lowercase()}: $detail") {
    enum class Kind { NOT_FOUND, IO }
}

/**
 * File access inside the folder the user picked (Drive, OneDrive, Dropbox...).
 *
 * Paths are relative to that folder, `/`-separated. Layout:
 * `LocalGateKeys Sync/keyring.lgkkeys`, `LocalGateKeys Sync/devices/<device_id>.lgksync` and
 * `LocalGateKeys Sync/signatures/<device_id>.lgksig`, plus `LocalGateKeys Sync/witness/<device_id>.lgksync` and
 * `.lgksig` (rollback witnesses, 2026-10-29).
 */
interface FolderAccess {
    /** Names (not paths) of the entries of [dir]; throws [FolderAccessException] NOT_FOUND when it is missing. */
    fun list(dir: String): List<String>

    /** At most [limit] bytes of [path]; throws [FolderAccessException] NOT_FOUND when it is missing. */
    fun read(path: String, limit: Int): ByteArray

    /**
     * Writes through a temp file in the same directory and an atomic replace; creates parent directories.
     *
     * The temp file MUST be named `.<final name>.<anything>.tmp` (a leading dot and a `.tmp` suffix), e.g.
     * `.<device_id>.lgksync.<random>.tmp` for a device file: [FolderSync] skips every `.*.tmp` entry when it
     * reads peer files (an in-flight write), and removes this device's own leftovers named
     * `.<device_id>.lgksync.*.tmp` at the start of a run. A Storage Access Framework implementation that
     * cannot rename must still use this naming for any temporary document it creates.
     */
    fun writeAtomic(path: String, data: ByteArray)

    fun remove(path: String)

    /**
     * True for an existing file or directory. Implementations should not throw: answer false when the
     * path cannot be checked (revoked permission, provider error). [FolderSync.runOnce] still treats a
     * throw as false, reporting `folder-missing`.
     */
    fun exists(path: String): Boolean

    /**
     * Last modification time of the file at [path] in Unix seconds, or null when unknown (attachment sync,
     * 2026-10-29: unreferenced blobs are swept only when older than 7 days, and never when this is unknown).
     */
    fun modifiedAt(path: String): Long? = null

    /** Size in bytes of the file at [path], or null when unknown (the caller then reads it to check). */
    fun size(path: String): Long? = null
}

/** Folder layout (desktop `folder_transport` constants). */
object FolderLayout {
    const val SYNC_DIR = "LocalGateKeys Sync"
    const val KEYRING_NAME = "keyring.lgkkeys"
    const val DEVICES_DIR_NAME = "devices"
    const val DEVICE_SUFFIX = ".lgksync"
    const val KEYRING_PATH = "$SYNC_DIR/$KEYRING_NAME"
    const val DEVICES_DIR = "$SYNC_DIR/$DEVICES_DIR_NAME"
    const val SIGNATURES_DIR_NAME = "signatures"
    const val SIGNATURE_SUFFIX = ".lgksig"
    const val SIGNATURES_DIR = "$SYNC_DIR/$SIGNATURES_DIR_NAME"

    /** Path of [deviceId]'s file; null unless the id is a safe file name. */
    fun deviceFile(deviceId: String): String? =
        if (Identifier.isSafeDeviceFile(deviceId)) "$DEVICES_DIR/$deviceId$DEVICE_SUFFIX" else null

    /** Path of [deviceId]'s view signature (desktop `signature_file`); null unless the id is a safe file name. */
    fun signatureFile(deviceId: String): String? =
        if (Identifier.isSafeDeviceFile(deviceId)) "$SIGNATURES_DIR/$deviceId$SIGNATURE_SUFFIX" else null

    /** Witness files (2026-10-29): a format-2 view with no records next to a format-1 view, and its signature. */
    const val WITNESS_DIR_NAME = "witness"
    const val WITNESS_DIR = "$SYNC_DIR/$WITNESS_DIR_NAME"

    /** Path of [deviceId]'s witness file; null unless the id is a safe file name. */
    fun witnessFile(deviceId: String): String? =
        if (Identifier.isSafeDeviceFile(deviceId)) "$WITNESS_DIR/$deviceId$DEVICE_SUFFIX" else null

    /** Attachment blobs and capability files (2026-10-29): `attachments/<blob_id>.lgkblob`, `<device_id>.lgkcap[.lgksig]`. */
    const val ATTACHMENTS_DIR = "$SYNC_DIR/attachments"

    /** Path of one attachment blob; null unless [blobId] is 64 lowercase hex characters. */
    fun blobFile(blobId: String): String? =
        if (AttachmentSync.isBlobId(blobId)) "$ATTACHMENTS_DIR/$blobId${AttachmentSync.BLOB_SUFFIX}" else null

    /** Path of [deviceId]'s attachment capability file; null unless the id is a safe file name. */
    fun capabilityFile(deviceId: String): String? =
        if (Identifier.isSafeDeviceFile(deviceId)) "$ATTACHMENTS_DIR/$deviceId${AttachmentSync.CAP_SUFFIX}" else null

    /** Path of the signature of [deviceId]'s capability file; null unless the id is a safe file name. */
    fun capabilitySignatureFile(deviceId: String): String? =
        if (Identifier.isSafeDeviceFile(deviceId)) "$ATTACHMENTS_DIR/$deviceId${AttachmentSync.CAP_SIG_SUFFIX}" else null

    /** Path of the signature of [deviceId]'s witness file; null unless the id is a safe file name. */
    fun witnessSignatureFile(deviceId: String): String? =
        if (Identifier.isSafeDeviceFile(deviceId)) "$WITNESS_DIR/$deviceId$SIGNATURE_SUFFIX" else null
}
