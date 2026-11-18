package app.localgatekeys.core.sync

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.LanPeer
import app.localgatekeys.core.records.SyncMeta

/**
 * This device's membership of a sync group (desktop `vault_bridge.SyncGroupState`).
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
    /** Rollback witnesses (2026-10-29, [Witness]): the highest vault generation each peer published; never lowered. */
    val peerGenerations: Map<String, Long> = emptyMap(),
    /** The highest generation of THIS vault a peer has seen above our own; 0 = none. Sticky until acknowledged. */
    val rollbackSuspected: Long = 0,
    /** Sorted peer ids that showed support for view format 2 (a format-2 view, a witness file or a LAN witness). */
    val witnessPeers: List<String> = emptyList(),
    /** Folder peer -> view counter of its last view that published a generation (`witness-missing`). */
    val witnessCounters: Map<String, Long> = emptyMap(),
    /** Added to the store's committed revision to give this vault's generation (raised only by the acknowledgement). */
    val generationOffset: Long = 0,
    /**
     * Peer device id -> wall-clock time (Unix seconds) this device last accepted that peer's changes (UX plan
     * workstream 6, `lastSyncedAt[deviceID]`). Local only: never written to the folder or sent over Wi-Fi.
     */
    val peerSyncedAt: Map<String, Long> = emptyMap(),
    /**
     * Sorted Wi-Fi peer ids that answered a `blob-get` (attachment sync, 2026-10-29, desktop `attachment_peers`): only
     * they receive `document` items over Wi-Fi.
     */
    val attachmentPeers: List<String> = emptyList(),
    /**
     * Sorted keyring member ids that appeared without this device adding or confirming them (desktop
     * `unacked_members`, audit M10): anyone with the sync password can add a member. They get no new key at the next
     * rotation and cannot sign a removal notice this device accepts, until the user confirms them.
     */
    val unackedMembers: List<String> = emptyList(),
    /**
     * Sorted Wi-Fi peer ids that answered a `features` message listing `collections` (desktop `collection_peers`,
     * sub-plan 07): personal collection states go into views (and are merged) only with them. The app's store persists
     * it when not empty.
     */
    val collectionPeers: List<String> = emptyList(),
    /**
     * Sorted Wi-Fi peer ids that answered `heir-hello` (sub-plan 08, desktop `heir_peers`): only they receive the
     * emergency access plan over Wi-Fi.
     */
    val heirPeers: List<String> = emptyList(),
    /**
     * The Wi-Fi peers this device accepted as a host (desktop `lan_peers`, [app.localgatekeys.core.lan.LanPeers]):
     * revoked ones stay listed. The app's store persists it when not empty.
     */
    val lanPeers: List<LanPeer> = emptyList(),
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
        peerGenerations: Map<String, Long> = this.peerGenerations,
        rollbackSuspected: Long = this.rollbackSuspected,
        witnessPeers: List<String> = this.witnessPeers,
        witnessCounters: Map<String, Long> = this.witnessCounters,
        generationOffset: Long = this.generationOffset,
        peerSyncedAt: Map<String, Long> = this.peerSyncedAt,
        attachmentPeers: List<String> = this.attachmentPeers,
        unackedMembers: List<String> = this.unackedMembers,
        collectionPeers: List<String> = this.collectionPeers,
        heirPeers: List<String> = this.heirPeers,
        lanPeers: List<LanPeer> = this.lanPeers,
    ): SyncGroupState = SyncGroupState(
        groupId, epoch, key, identity, installId, hasFolder, lastSeen, peerDigests, membersEpoch, members, keyring, ownCounter,
        viewSigners, peerGenerations, rollbackSuspected, witnessPeers, witnessCounters, generationOffset, peerSyncedAt,
        attachmentPeers, unackedMembers, collectionPeers, heirPeers, lanPeers,
    )

    /** [peerSyncedAt] with [peers] accepted at [now] (at most [limit] peers kept, the most recent ones). */
    fun syncedWith(peers: Collection<String>, now: Long, limit: Int = 64): SyncGroupState {
        if (peers.isEmpty()) return this
        var times = peerSyncedAt + peers.associateWith { now }
        if (times.size > limit) times = times.entries.sortedByDescending { it.value }.take(limit).associate { it.key to it.value }
        return copy(peerSyncedAt = times)
    }

    override fun equals(other: Any?): Boolean =
        other is SyncGroupState && groupId == other.groupId && epoch == other.epoch && keyBytes.contentEquals(other.keyBytes) &&
            identity == other.identity && installId == other.installId && hasFolder == other.hasFolder &&
            lastSeen == other.lastSeen && peerDigests == other.peerDigests && membersEpoch == other.membersEpoch &&
            members == other.members && keyringBytes.contentEquals(other.keyringBytes) && ownCounter == other.ownCounter &&
            viewSigners == other.viewSigners && peerGenerations == other.peerGenerations &&
            rollbackSuspected == other.rollbackSuspected && witnessPeers == other.witnessPeers &&
            witnessCounters == other.witnessCounters && generationOffset == other.generationOffset &&
            peerSyncedAt == other.peerSyncedAt && attachmentPeers == other.attachmentPeers &&
            unackedMembers == other.unackedMembers && collectionPeers == other.collectionPeers && heirPeers == other.heirPeers &&
            lanPeers == other.lanPeers

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
    /**
     * The share groups of this vault (sub-plan 07, [ShareRecord.encode]), exactly as stored: null when there is none.
     * Kept raw so a damaged entry never stops the store from loading ([ShareGroups.records] decodes it strictly and the
     * share readers fail closed). Device-only secrets: never a record, so never in a view, a backup or an export.
     */
    val shares: JsonValue? = null,
    /**
     * Older local collections were moved into this store ([CollectionCatalog.migrate], sub-plan 07): the migration
     * commit sets it, every other commit keeps it, so a later run never merges an old local copy into the store again.
     */
    val collectionsMigrated: Boolean = false,
) {
    /** Counts only: records hold plaintext secrets, shares hold keys. */
    override fun toString(): String =
        "StoreSnapshot(records=${records.size}, meta=${meta.size}, sync=${if (sync == null) "none" else "set"}, revision=$revision" +
            (if (shares == null) ")" else ", shares=set)")
}

/** One atomic store write: the full new records, meta and group state, based on [baseRevision]. */
data class StoreChange(
    val baseRevision: Long,
    val records: Map<String, JsonValue>,
    val meta: Map<String, SyncMeta>,
    val sync: SyncGroupState?,
    /** What this commit does with the stored share groups: [Shares.Keep] for every write that is not about a share. */
    val shares: Shares = Shares.Keep,
    /** Sets [StoreSnapshot.collectionsMigrated]; null keeps it as stored (every write but the migration's). */
    val collectionsMigrated: Boolean? = null,
) {
    /** The stored share groups after a commit: kept as they are, or replaced ([Replace.value] null: none left). */
    sealed interface Shares {
        object Keep : Shares {
            override fun toString(): String = "Keep"
        }

        data class Replace(val value: JsonValue?) : Shares {
            /** Never shows the groups (they hold keys). */
            override fun toString(): String = "Replace(${if (value == null) "none" else "set"})"
        }
    }

    /** Counts only: records hold plaintext secrets, shares hold keys. */
    override fun toString(): String =
        "StoreChange(baseRevision=$baseRevision, records=${records.size}, meta=${meta.size}, sync=${if (sync == null) "none" else "set"}" +
            (if (shares == Shares.Keep) ")" else ", shares=$shares)")
}

/**
 * The local vault as sync sees it. [commit] is atomic and durable before it returns, and throws when the
 * store changed since `baseRevision` (the caller syncs again).
 */
interface ItemStore {
    fun load(): StoreSnapshot

    fun commit(change: StoreChange)
}
