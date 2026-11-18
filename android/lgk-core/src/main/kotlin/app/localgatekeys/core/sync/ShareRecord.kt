package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.VersionVector
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.SyncMeta

/**
 * A share-group operation that is refused; [reason] is a stable code (desktop `share_group.ShareGroupError`):
 * `bad-state`, `not-joined`, `not-share`, `personal-group`, `already-joined`, `own-share`, `collection-exists`,
 * `no-collection`, `already-shared`, `not-owner`, `not-pending`, `not-member`, `trash-full`, `item-error`, `bad-remote`,
 * `store-changed`, `bad-install-id`, `bad-folder`, `folder-has-other-group`. Never carries a key, a password or a keyring.
 */
class ShareGroupException(val reason: String, val detail: String = "") :
    Exception(if (detail.isEmpty()) reason else "$reason: $detail")

/**
 * What Recently deleted holds when a share runs (the app's trash rows, read before the run): how many rows (a removal
 * checks `trash-full` first; null: unknown, so a removal is refused) and the collections of each deleted record (an
 * incoming share item may bring back only a deleted item of its own collection, never a personal one).
 */
class ShareTrash(
    val count: Int?,
    /** Deleted record id -> its `collection_ids` (empty for none). */
    val collections: Map<String, List<String>> = emptyMap(),
    /**
     * Deleted record id -> the record as deleted (the newest row of that id): an item a share brings back keeps this
     * device's own tags, favourite, other collections and `document_ids` from it (desktop `_Applier.store`).
     */
    val records: Map<String, Map<String, JsonValue>> = emptyMap(),
) {
    /** Counts only: the records hold plaintext. */
    override fun toString(): String = "ShareTrash(count=$count, records=${records.size})"

    companion object {
        /** The most rows Recently deleted holds (the app's `LocalData.MAX_TRASH`, LGKCore `LocalData.maxTrash`). */
        const val MAX_TRASH = 20_000

        /** From the app's Recently deleted rows: each row's record ([CollectionCatalog.trashRecord]), oldest first. */
        fun of(rows: List<JsonValue>): ShareTrash {
            val out = LinkedHashMap<String, List<String>>()
            val records = LinkedHashMap<String, Map<String, JsonValue>>()
            for (row in rows) {
                val r = (row as? JsonValue.Obj)?.fields ?: continue
                val id = (r["id"] as? JsonValue.Str)?.v ?: continue
                out[id] = (out[id] ?: emptyList()) + CollectionCatalog.strings(r["collection_ids"])
                records[id] = r
            }
            return ShareTrash(rows.size, out, records)
        }
    }
}

/**
 * One share group of this vault as stored in the item store's sealed state ([StoreSnapshot.shares], desktop
 * `payload["share_groups"]`): the role, the pinned facts (collection, owner device and key, mode), the group's own sync
 * state (keys, keyring, counters), its own per-record sync meta (desktop `share_sync_meta`), the members the owner
 * removed and an opaque folder reference (the app's folder tree URI, as bytes).
 *
 * Everything here stays on the device: it is never a record, so never in a sync view (personal or share), a backup or
 * an export. [toString] names no key, password, keyring or member. [folder] is copied in and handed out as a copy.
 */
class ShareRecord(
    val role: Role,
    val pin: ShareKeyring.Pin,
    val state: SyncGroupState,
    val meta: Map<String, SyncMeta> = emptyMap(),
    val removed: List<Removed> = emptyList(),
    folder: ByteArray? = null,
) {
    enum class Role(val wire: String) {
        OWNER("owner"),
        MEMBER("member"),
        ;

        companion object {
            fun of(wire: String): Role? = entries.firstOrNull { it.wire == wire }
        }
    }

    /** One member the owner removed (desktop `removed` rows): the name when it could be read, and when. */
    data class Removed(val name: String?, val at: Long) {
        override fun toString(): String = "Removed(at=$at)"
    }

    private val folderBytes: ByteArray? = folder?.copyOf()

    /** A copy of the folder reference, or null. */
    val folder: ByteArray? get() = folderBytes?.copyOf()

    val groupId: String get() = state.groupId
    val collectionId: String get() = pin.collectionId

    /** This device may not publish local changes: a member of a `read` share. */
    val isReadOnly: Boolean get() = role == Role.MEMBER && pin.sharedMode == "read"

    fun copy(
        role: Role = this.role,
        pin: ShareKeyring.Pin = this.pin,
        state: SyncGroupState = this.state,
        meta: Map<String, SyncMeta> = this.meta,
        removed: List<Removed> = this.removed,
        folder: ByteArray? = this.folderBytes,
    ): ShareRecord = ShareRecord(role, pin, state, meta, removed, folder)

    override fun equals(other: Any?): Boolean =
        other is ShareRecord && role == other.role && pin == other.pin && state == other.state && meta == other.meta &&
            removed == other.removed && folderBytes.contentEquals(other.folderBytes)

    override fun hashCode(): Int = (state.hashCode() * 31 + pin.hashCode()) * 31 + role.hashCode()

    override fun toString(): String =
        "ShareRecord(group=${state.groupId}, collection=${pin.collectionId}, role=${role.wire}, mode=${pin.sharedMode})"

    /** The stored JSON of this record. */
    internal fun json(): JsonValue {
        val o = LinkedHashMap<String, JsonValue>()
        o["version"] = JsonValue.Int(VERSION)
        o["role"] = JsonValue.Str(role.wire)
        o["collection_id"] = JsonValue.Str(pin.collectionId)
        o["owner"] = JsonValue.Str(pin.owner)
        o["owner_key"] = JsonValue.Str(pin.ownerKey)
        o["shared_mode"] = JsonValue.Str(pin.sharedMode)
        o["state"] = encodeState(state)
        o["meta"] = JsonValue.Obj(meta.mapValues { encodeMeta(it.value) })
        if (removed.isNotEmpty()) {
            o["removed"] = JsonValue.Arr(removed.map { JsonValue.Obj(mapOf("name" to optText(it.name), "at" to JsonValue.Int(it.at))) })
        }
        val f = folderBytes
        if (f != null) o["folder"] = JsonValue.Str(Base64Std.encode(f))
        return JsonValue.Obj(o)
    }

    /** The pinned facts against the stored keyring (desktop `_check_record`). */
    internal fun check(groupId: String) {
        if (state.groupId != groupId) throw bad("group id")
        val got = try {
            val bytes = state.keyring ?: throw bad("keyring")
            val ring = ShareKeyring.parse(bytes)
            if (Keyring.str(Keyring.obj(ring)["group_id"]) != groupId) throw bad("keyring")
            ShareKeyring.Pin.of(ring)
        } catch (e: ShareGroupException) {
            throw e
        } catch (e: Exception) {
            throw bad("keyring")
        }
        if (got != pin) throw bad("keyring")
        if ((role == Role.OWNER) != (state.deviceId == pin.owner)) throw bad("role")
    }

    companion object {
        const val VERSION: Long = 1
        const val MAX_REMOVED = 50
        internal const val MAX_NAME = 100
        internal const val MAX_FOLDER_BYTES = 64 * 1024

        private val FIELDS = setOf("version", "role", "collection_id", "owner", "owner_key", "shared_mode", "state", "meta")
        private val OPTIONAL_FIELDS = setOf("removed", "folder")
        private val STATE_FIELDS = setOf(
            "group_id", "epoch", "key", "device_id", "signing", "exchange", "install_id", "last_seen", "peer_digests",
            "members_epoch", "members", "keyring", "own_counter", "view_signers", "unacked_members", "peer_synced_at",
        )
        private val META_FIELDS = setOf("digest", "body", "updated_at", "vv", "deleted", "deleted_at")

        internal fun bad(what: String) = ShareGroupException("bad-state", "stored share group is malformed: $what")

        /** The stored JSON of every group: `{group id: record}`; null for none (the key is then left out of the store). */
        fun encode(records: Map<String, ShareRecord>): JsonValue? {
            if (records.isEmpty()) return null
            return JsonValue.Obj(records.mapValues { it.value.json() })
        }

        private fun optText(s: String?): JsonValue = if (s == null) JsonValue.Null else JsonValue.Str(s)

        private fun optInt(n: Long?): JsonValue = if (n == null) JsonValue.Null else JsonValue.Int(n)

        private fun ints(d: Map<String, Long>): JsonValue = JsonValue.Obj(d.mapValues { JsonValue.Int(it.value) })

        private fun texts(d: Map<String, String>): JsonValue = JsonValue.Obj(d.mapValues { JsonValue.Str(it.value) })

        private fun strings(a: List<String>): JsonValue = JsonValue.Arr(a.map { JsonValue.Str(it) })

        private fun b64(b: ByteArray): JsonValue = JsonValue.Str(Base64Std.encode(b))

        internal fun encodeState(s: SyncGroupState): JsonValue = JsonValue.Obj(
            linkedMapOf(
                "group_id" to JsonValue.Str(s.groupId),
                "epoch" to JsonValue.Int(s.epoch),
                "key" to b64(s.key),
                "device_id" to JsonValue.Str(s.identity.deviceId),
                "signing" to b64(s.identity.signingPrivateKey),
                "exchange" to b64(s.identity.exchangePrivateKey),
                "install_id" to JsonValue.Str(s.installId),
                "last_seen" to ints(s.lastSeen),
                "peer_digests" to texts(s.peerDigests),
                "members_epoch" to JsonValue.Int(s.membersEpoch),
                "members" to strings(s.members),
                "keyring" to (s.keyring?.let { b64(it) } ?: JsonValue.Null),
                "own_counter" to JsonValue.Int(s.ownCounter),
                "view_signers" to texts(s.viewSigners),
                "unacked_members" to strings(s.unackedMembers),
                "peer_synced_at" to ints(s.peerSyncedAt),
            ),
        )

        internal fun encodeMeta(m: SyncMeta): JsonValue = JsonValue.Obj(
            mapOf(
                "digest" to optText(m.digest), "body" to optText(m.body), "updated_at" to optInt(m.updatedAt),
                "vv" to ints(m.vv), "deleted" to JsonValue.Bool(m.deleted), "deleted_at" to optInt(m.deletedAt),
            ),
        )

        // ---- strict decode ----

        /** Every stored group, each checked (desktop `_records` / `_check_record`); `bad-state` for anything off. */
        fun decodeAll(raw: JsonValue?): Map<String, ShareRecord> {
            if (raw == null) return emptyMap()
            val groups = (raw as? JsonValue.Obj)?.fields ?: throw bad("groups")
            val out = LinkedHashMap<String, ShareRecord>()
            for ((groupId, value) in groups) out[groupId] = decode(groupId, value)
            return out
        }

        /**
         * One stored group: exact fields and types, the stored keyring re-verified (structure and owner signature), and
         * the pinned facts equal to its metadata; the owner role only on the owner's device.
         */
        fun decode(groupId: String, value: JsonValue): ShareRecord {
            val o = (value as? JsonValue.Obj)?.fields
            if (!Identifier.isValid(groupId) || o == null) throw bad("group id")
            val keys = o.keys
            if (!keys.containsAll(FIELDS) || !OPTIONAL_FIELDS.containsAll(keys - FIELDS)) throw bad("fields")
            if (o["version"] != JsonValue.Int(VERSION)) throw bad("version")
            val role = (o["role"] as? JsonValue.Str)?.v?.let { Role.of(it) } ?: throw bad("role")
            val pin = ShareKeyring.Pin(
                text(o["collection_id"], "collection_id"), text(o["owner"], "owner"), text(o["owner_key"], "owner_key"),
                text(o["shared_mode"], "shared_mode"),
            )
            val state = decodeState(o["state"])
            val metaObject = (o["meta"] as? JsonValue.Obj)?.fields
            if (metaObject == null || metaObject.size > SyncMeta.MAX_RECORDS) throw bad("meta")
            val meta = LinkedHashMap<String, SyncMeta>()
            for ((id, m) in metaObject) meta[id] = decodeMeta(m)
            val removed = ArrayList<Removed>()
            val rows = o["removed"]
            if (rows != null) {
                val list = (rows as? JsonValue.Arr)?.items
                if (list == null || list.size > MAX_REMOVED) throw bad("removed")
                for (row in list) {
                    val r = (row as? JsonValue.Obj)?.fields
                    val at = (r?.get("at") as? JsonValue.Int)?.v
                    if (r == null || r.keys != setOf("name", "at") || at == null || at < 0) throw bad("removed")
                    when (val n = r["name"]) {
                        JsonValue.Null -> removed.add(Removed(null, at))
                        is JsonValue.Str -> if (Scalars.count(n.v) <= MAX_NAME) removed.add(Removed(n.v, at)) else throw bad("removed")
                        else -> throw bad("removed")
                    }
                }
            }
            var folder: ByteArray? = null
            val f = o["folder"]
            if (f != null) {
                val bytes = try {
                    Base64Std.decodeStrict((f as? JsonValue.Str)?.v ?: throw bad("folder"))
                } catch (e: ShareGroupException) {
                    throw e
                } catch (e: Exception) {
                    throw bad("folder")
                }
                if (bytes.size > MAX_FOLDER_BYTES) throw bad("folder")
                folder = bytes
            }
            val record = ShareRecord(role, pin, state, meta, removed, folder)
            record.check(groupId)
            return record
        }

        private fun text(v: JsonValue?, what: String): String = (v as? JsonValue.Str)?.v ?: throw bad(what)

        private fun intMap(v: JsonValue?, what: String): Map<String, Long> {
            val d = (v as? JsonValue.Obj)?.fields ?: throw bad(what)
            return d.mapValues { (_, x) -> (x as? JsonValue.Int)?.v?.takeIf { it >= 0 } ?: throw bad(what) }
        }

        private fun textMap(v: JsonValue?, what: String): Map<String, String> {
            val d = (v as? JsonValue.Obj)?.fields ?: throw bad(what)
            return d.mapValues { (_, x) -> (x as? JsonValue.Str)?.v ?: throw bad(what) }
        }

        private fun ids(v: JsonValue?, what: String): List<String> {
            val a = (v as? JsonValue.Arr)?.items ?: throw bad(what)
            return a.map { x -> (x as? JsonValue.Str)?.v?.takeIf { Identifier.isValid(it) } ?: throw bad(what) }
        }

        private fun bytes(v: JsonValue?, what: String): ByteArray {
            val t = (v as? JsonValue.Str)?.v ?: throw bad(what)
            return try {
                Base64Std.decodeStrict(t)
            } catch (e: Exception) {
                throw bad(what)
            }
        }

        private fun decodeState(v: JsonValue?): SyncGroupState {
            val o = (v as? JsonValue.Obj)?.fields
            if (o == null || o.keys != STATE_FIELDS) throw bad("state")
            val deviceId = (o["device_id"] as? JsonValue.Str)?.v ?: throw bad("identity")
            val signing = bytes(o["signing"], "identity")
            val exchange = bytes(o["exchange"], "identity")
            val identity = try {
                DeviceIdentity(deviceId, signing, exchange)
            } catch (e: Exception) {
                throw bad("identity")
            }
            val epoch = (o["epoch"] as? JsonValue.Int)?.v
            val membersEpoch = (o["members_epoch"] as? JsonValue.Int)?.v
            val ownCounter = (o["own_counter"] as? JsonValue.Int)?.v
            if (epoch == null || membersEpoch == null || ownCounter == null || ownCounter < 0) throw bad("counters")
            val key = bytes(o["key"], "key")
            val groupId = text(o["group_id"], "group_id")
            // A share always holds the keyring it last accepted or wrote, and a usable key for it.
            try {
                GroupKey(groupId, epoch, key)
            } catch (e: Exception) {
                throw bad("key")
            }
            val keyring = bytes(o["keyring"], "keyring")
            val installId = text(o["install_id"], "install_id")
            if (installId.isEmpty() || Scalars.count(installId) > FolderSync.MAX_INSTALL_ID) throw bad("install_id")
            return SyncGroupState(
                groupId = groupId, epoch = epoch, key = key, identity = identity, installId = installId, hasFolder = true,
                lastSeen = intMap(o["last_seen"], "last_seen"), peerDigests = textMap(o["peer_digests"], "peer_digests"),
                membersEpoch = membersEpoch, members = ids(o["members"], "members"), keyring = keyring,
                ownCounter = ownCounter, viewSigners = textMap(o["view_signers"], "view_signers"),
                unackedMembers = ids(o["unacked_members"], "unacked_members"),
                peerSyncedAt = intMap(o["peer_synced_at"], "peer_synced_at"),
            )
        }

        internal fun decodeMeta(v: JsonValue): SyncMeta {
            val o = (v as? JsonValue.Obj)?.fields
            val deleted = (o?.get("deleted") as? JsonValue.Bool)?.v
            val vvObject = (o?.get("vv") as? JsonValue.Obj)?.fields
            if (o == null || o.keys != META_FIELDS || deleted == null || vvObject == null) throw bad("meta")
            fun textField(k: String): String? = when (val x = o[k]) {
                JsonValue.Null -> null
                is JsonValue.Str -> x.v
                else -> throw bad("meta")
            }
            fun intField(k: String): Long? = when (val x = o[k]) {
                JsonValue.Null -> null
                is JsonValue.Int -> x.v
                else -> throw bad("meta")
            }
            val vv = vvObject.mapValues { (_, x) ->
                (x as? JsonValue.Int)?.v?.takeIf { it in 0..VersionVector.MAX_COUNTER } ?: throw bad("meta")
            }
            return SyncMeta(textField("digest"), textField("body"), intField("updated_at"), vv, deleted, intField("deleted_at"))
        }
    }
}
