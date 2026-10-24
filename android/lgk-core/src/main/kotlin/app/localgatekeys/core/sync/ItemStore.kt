package app.localgatekeys.core.sync

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.records.SyncMeta

/**
 * This device's membership of a sync group (desktop `vault_bridge.SyncGroupState`, without the LAN fields).
 * [key] and [keyring] are copied in and handed out as copies, so no caller can change the state's bytes.
 * Not a `data class` (its properties would hand out the arrays), but [copy], [equals] and [hashCode] work by content.
 */
class SyncGroupState(
    val groupId: String,
    val epoch: Long,
    key: ByteArray,
    val identity: DeviceIdentity,
    val installId: String,
    /** True once the group uses the cloud folder (joined or attached there). */
    val hasFolder: Boolean = true,
    /** Last counter and sha256 hex of the last file accepted per peer. */
    val lastSeen: Map<String, Long> = emptyMap(),
    val peerDigests: Map<String, String> = emptyMap(),
    val membersEpoch: Long = 0,
    val members: List<String> = emptyList(),
    /** Bytes of the last accepted keyring (restored over a rolled-back or tampered one). */
    keyring: ByteArray? = null,
    /** The last own-file counter reserved; saved before the file carrying it is written. */
    val ownCounter: Long = 0,
    /**
     * Device id -> base64 Ed25519 key its view files are signed with (desktop `view_signers`, audit M-7): this
     * device's own key once it wrote a signed view, and each peer's once a signed view of it verified. A pinned
     * peer's views must carry a valid signature by that key. Adopting a new epoch keeps only the own entry.
     * The app's store must persist it (an empty map just means no peer is pinned yet).
     */
    val viewSigners: Map<String, String> = emptyMap(),
) {
    private val keyBytes: ByteArray = key.copyOf()
    private val keyringBytes: ByteArray? = keyring?.copyOf()

    /** A copy of the 32-byte group key. */
    val key: ByteArray get() = keyBytes.copyOf()

    /** A copy of the last accepted keyring's bytes, or null. */
    val keyring: ByteArray? get() = keyringBytes?.copyOf()

    val deviceId: String get() = identity.deviceId

    internal fun groupKey(): GroupKey = GroupKey(groupId, epoch, keyBytes)

    fun copy(
        groupId: String = this.groupId,
        epoch: Long = this.epoch,
        key: ByteArray = this.keyBytes,
        identity: DeviceIdentity = this.identity,
        installId: String = this.installId,
        hasFolder: Boolean = this.hasFolder,
        lastSeen: Map<String, Long> = this.lastSeen,
        peerDigests: Map<String, String> = this.peerDigests,
        membersEpoch: Long = this.membersEpoch,
        members: List<String> = this.members,
        keyring: ByteArray? = this.keyringBytes,
        ownCounter: Long = this.ownCounter,
        viewSigners: Map<String, String> = this.viewSigners,
    ): SyncGroupState = SyncGroupState(
        groupId, epoch, key, identity, installId, hasFolder, lastSeen, peerDigests, membersEpoch, members, keyring, ownCounter,
        viewSigners,
    )

    override fun equals(other: Any?): Boolean =
        other is SyncGroupState && groupId == other.groupId && epoch == other.epoch && keyBytes.contentEquals(other.keyBytes) &&
            identity == other.identity && installId == other.installId && hasFolder == other.hasFolder &&
            lastSeen == other.lastSeen && peerDigests == other.peerDigests && membersEpoch == other.membersEpoch &&
            members == other.members && keyringBytes.contentEquals(other.keyringBytes) && ownCounter == other.ownCounter &&
            viewSigners == other.viewSigners

    override fun hashCode(): Int {
        var h = groupId.hashCode()
        h = 31 * h + epoch.hashCode()
        h = 31 * h + keyBytes.contentHashCode()
        h = 31 * h + identity.hashCode()
        h = 31 * h + installId.hashCode()
        h = 31 * h + lastSeen.hashCode()
        h = 31 * h + keyringBytes.contentHashCode()
        return h
    }

    /** Never shows key material. */
    override fun toString(): String = "SyncGroupState(groupId=$groupId, epoch=$epoch, device=$deviceId, installId=$installId)"
}

/** What the store holds for sync: every record as its synced wrapper, the per-id sync meta and the group state. */
data class StoreSnapshot(
    val records: Map<String, JsonValue> = emptyMap(),
    val meta: Map<String, SyncMeta> = emptyMap(),
    val sync: SyncGroupState? = null,
    /** Changes on every commit; a commit against an older revision is refused. */
    val revision: Long = 0,
) {
    /** Counts only: records hold plaintext secrets. */
    override fun toString(): String =
        "StoreSnapshot(records=${records.size}, meta=${meta.size}, sync=${if (sync == null) "none" else "set"}, revision=$revision)"
}

/** One atomic store write: the full new records, meta and group state, based on [baseRevision]. */
data class StoreChange(
    val baseRevision: Long,
    val records: Map<String, JsonValue>,
    val meta: Map<String, SyncMeta>,
    val sync: SyncGroupState?,
) {
    /** Counts only: records hold plaintext secrets. */
    override fun toString(): String =
        "StoreChange(baseRevision=$baseRevision, records=${records.size}, meta=${meta.size}, sync=${if (sync == null) "none" else "set"})"
}

/**
 * The local vault as sync sees it. [commit] is atomic and durable before it returns, and throws when the
 * store changed since `baseRevision` (the caller syncs again).
 */
interface ItemStore {
    fun load(): StoreSnapshot

    fun commit(change: StoreChange)
}
