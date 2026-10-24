package app.localgatekeys.core.group

import app.localgatekeys.core.engine.VersionVector
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.Identifier

/** Epoch group key (desktop `sync.group.GroupKey`). */
class GroupKey(val groupId: String, val epoch: Long, key: ByteArray) {
    private val keyBytes: ByteArray

    init {
        if (!Identifier.isValid(groupId)) throw SyncFormatException("bad-group-key", "group_id")
        if (epoch < 1 || epoch > VersionVector.MAX_COUNTER) throw SyncFormatException("bad-group-key", "epoch")
        if (key.size != 32) throw SyncFormatException("bad-group-key", "key must be 32 bytes")
        keyBytes = key.copyOf()
    }

    /** A copy of the 32 key bytes. */
    val key: ByteArray get() = keyBytes.copyOf()

    private fun derive(label: ByteArray): ByteArray =
        CryptoBox.hkdf(keyBytes, groupId.toByteArray(Charsets.UTF_8), label + epoch.toString().toByteArray(Charsets.UTF_8), 32)

    val recordKey: ByteArray get() = derive(RECORD_INFO_BYTES)
    val fileKey: ByteArray get() = derive(FILE_INFO_BYTES)

    override fun equals(other: Any?): Boolean =
        other is GroupKey && groupId == other.groupId && epoch == other.epoch && keyBytes.contentEquals(other.keyBytes)

    override fun hashCode(): Int = (groupId.hashCode() * 31 + epoch.hashCode()) * 31 + keyBytes.contentHashCode()

    companion object {
        private val RECORD_INFO_BYTES = "localgatekeys|sync|folder-record|v1|".toByteArray(Charsets.UTF_8)
        private val FILE_INFO_BYTES = "localgatekeys|sync|folder-file|v1|".toByteArray(Charsets.UTF_8)

        /** A copy of the record-key HKDF info prefix. */
        val RECORD_INFO: ByteArray get() = RECORD_INFO_BYTES.copyOf()

        /** A copy of the file-key HKDF info prefix. */
        val FILE_INFO: ByteArray get() = FILE_INFO_BYTES.copyOf()
    }
}
