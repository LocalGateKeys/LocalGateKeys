package app.localgatekeys.core.sync

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.keyring.KeyringException
import app.localgatekeys.core.keyring.KeyringRotate
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.SyncMeta

/**
 * Share groups: a collection shared with other people through its own sync group (sub-plan 07 Task 5k; the Kotlin port
 * of LGKCore `ShareGroups`, desktop `share_group.py`; the Windows behaviour is the spec).
 *
 * A shared collection is a second sync group next to the vault's personal one, with its own keyring ([ShareKeyring]),
 * its own device identity and its own removal notices. The keyring carries the share metadata (collection id, sealed
 * name, mode, owner device and Ed25519 key) and the owner's signature over the approved members. The personal group
 * ([StoreSnapshot.sync]) is read only for a clash check and is never changed here.
 *
 * - Owner authority is cryptographic: every device pins the owner (device id and key), the collection id and the mode
 *   when it creates or joins ([ShareKeyring.Pin]); [adopt] refuses a keyring that changes any of them; at one epoch a
 *   keyring may only grow. Members the owner has not approved yet are pending: no removal-notice authority, and they are
 *   dropped when the owner removes someone. Losing the owner's device freezes the group (no owner recovery yet).
 * - Pro ([ShareAccess]): creating, joining and syncing need Pro, checked before any key derivation. Approving, removing a
 *   member (a security action) and leaving work without it; a lapsed device keeps what it has.
 * - Stored only in the item store's sealed state ([StoreSnapshot.shares], [ShareRecord]): keys, keyring and the owner's
 *   signing key never become records, so they never reach personal sync, a view, a backup or an export.
 * - A collection is shared on this device when one of its share records names it. Its catalog row (`col:`) stays an
 *   ordinary personal collection state; another of this person's devices learns the share only as a `csl:` link (mode
 *   and role, [shareLinks]).
 *
 * Every operation loads the store once and commits once ([StoreChange.shares]); nothing here logs, and no key, password
 * or keyring appears in a [toString].
 */
object ShareGroups {
    /** One member of a share as the owner's screens show it (desktop `Member`). [name] null: "Unnamed device". */
    data class Member(val deviceId: String, val name: String?, val addedAt: Long, val approved: Boolean) {
        override fun toString(): String = "Member($deviceId, approved=$approved)"
    }

    /** One share group of this vault (desktop `ShareGroup`). [name]: the collection name sealed in the keyring. */
    data class Group(
        val groupId: String,
        val collectionId: String,
        val name: String,
        val sharedMode: String,
        /** The owner's device id in this group. */
        val owner: String,
        val role: ShareRecord.Role,
        val members: List<Member>,
        /**
         * 1: items sealed with the group key (the share password opens them); 2: with the content key that only approved
         * members hold (`docs/superpowers/specs/2026-11-12-collections-crypto-gating.md`).
         */
        val version: Int = 2,
    ) {
        override fun toString(): String =
            "ShareGroup($groupId, collection=$collectionId, mode=$sharedMode, role=${role.wire}, members=${members.size}, v$version)"
    }

    private inline fun <T> orNull(body: () -> T): T? = try {
        body()
    } catch (e: Exception) {
        null
    }

    private fun byScalars(a: String, b: String): Int = Scalars.compare(a, b)

    // ---- reading ----

    /** Every share group of this vault, each checked (`bad-state` for a damaged one). */
    fun records(snapshot: StoreSnapshot): Map<String, ShareRecord> = ShareRecord.decodeAll(snapshot.shares)

    private fun record(snapshot: StoreSnapshot, groupId: String): Pair<MutableMap<String, ShareRecord>, ShareRecord> {
        val all = LinkedHashMap(records(snapshot))
        val record = all[groupId] ?: throw ShareGroupException("not-joined", "this vault is not in that share group")
        return all to record
    }

    /** Every share group, by group id (works without Pro: read access stays). */
    fun list(snapshot: StoreSnapshot): List<Group> =
        records(snapshot).entries.sortedWith { a, b -> byScalars(a.key, b.key) }.map { group(it.value) }

    /** The group view of one record: its name, mode and members with their names (desktop `_group`). */
    fun group(record: ShareRecord): Group {
        val bytes = record.state.keyring ?: throw ShareRecord.bad("keyring")
        val ring = ShareKeyring.parse(bytes)
        val gk = record.state.groupKey()
        val names = Keyring.memberNames(ring, gk)
        val approved = ShareKeyring.approvedMembers(ring) ?: emptySet()
        val members = ArrayList<Member>()
        for (m in Keyring.arr(Keyring.obj(ring)["members"])) {
            val mo = Keyring.obj(m)
            val id = Keyring.str(mo["device_id"]) ?: continue
            members.add(Member(id, names[id], Keyring.int(mo["added_at"]) ?: 0, id in approved))
        }
        return Group(
            record.groupId, record.collectionId, ShareKeyring.shareName(ring, gk), record.pin.sharedMode, record.pin.owner,
            record.role, members, ShareKeyring.shareVersion(ring) ?: 1,
        )
    }

    /**
     * The key the share's item views are sealed with on this device (desktop `view_key`); null while it waits for
     * approval. Share v1: the group key G of an approved member (the owner always). Share v2: the content key C from this
     * device's content wrap ([ShareKeyring.openContentKey]); [KeyringException] `content-key` when the wrap does not open
     * to the committed key.
     */
    fun viewKey(record: ShareRecord): app.localgatekeys.core.group.GroupKey? {
        val ring = storedRing(record)
        if (ShareKeyring.shareVersion(ring) == 2) return ShareKeyring.openContentKey(ring, record.state.identity)
        val approved = (ShareKeyring.approvedMembers(ring) ?: emptySet()) + record.pin.owner
        return if (record.state.deviceId in approved) record.state.groupKey() else null
    }

    /** [viewKey] of [groupId] (`not-joined` when this vault is not in it). */
    fun viewKey(snapshot: StoreSnapshot, groupId: String): app.localgatekeys.core.group.GroupKey? = viewKey(record(snapshot, groupId).second)

    /** Whether this device owns share v1 [groupId]: the share sheet offers the upgrade to share v2 (desktop `needs_upgrade`). */
    fun needsUpgrade(snapshot: StoreSnapshot, groupId: String): Boolean {
        val rec = record(snapshot, groupId).second
        return rec.role == ShareRecord.Role.OWNER && rec.state.deviceId == rec.pin.owner && ShareKeyring.shareVersion(storedRing(rec)) == 1
    }

    /** Members waiting for the owner's approval, with their names: what the owner is shown before approving. */
    fun pendingMembers(snapshot: StoreSnapshot, groupId: String): List<Member> =
        group(record(snapshot, groupId).second).members.filter { !it.approved }

    /** The members the owner removed on this device (oldest first). */
    fun removedMembers(snapshot: StoreSnapshot, groupId: String): List<ShareRecord.Removed> = record(snapshot, groupId).second.removed

    /**
     * The collection ids the stored share groups name, read as leniently as possible: a damaged store must still fail
     * closed (every collection it might name, else every collection, counts as shared).
     */
    internal fun looseCollectionIds(snapshot: StoreSnapshot): Set<String> {
        val raw = snapshot.shares ?: return emptySet()
        val groups = (raw as? JsonValue.Obj)?.fields
        if (groups != null) {
            val out = HashSet<String>()
            var whole = true
            for (value in groups.values) {
                val c = ((value as? JsonValue.Obj)?.fields?.get("collection_id") as? JsonValue.Str)?.v
                if (c != null) out.add(c) else whole = false
            }
            if (whole) return out
        }
        return CollectionCatalog.collections(snapshot).map { it.id }.toSet()
    }

    /**
     * Collections this vault holds as a member of a read-only share: local edits there are refused
     * ([ShareAccess.checkWritable]). Fails closed: if the share groups cannot be read, every collection they might name
     * is read-only (desktop `read_only_collection_ids`).
     */
    fun readOnlyCollectionIds(snapshot: StoreSnapshot): Set<String> {
        val all = orNull { records(snapshot) }
            ?: return ShareAccess.readOnlyCollectionIds(null, looseCollectionIds(snapshot))
        val memberships = all.values.map { ShareAccess.Membership(it.collectionId, it.role.wire, it.pin.sharedMode) }
        return ShareAccess.readOnlyCollectionIds(memberships, emptySet())
    }

    /**
     * `{collection id: link}` of the collections shared on this device, which personal collection sync publishes as
     * `csl:` links to this person's other devices; null when the share groups cannot be read (desktop `share_links`).
     * Only the mode and this device's role ever leave the device.
     */
    fun shareLinks(snapshot: StoreSnapshot): Map<String, CollectionShares.Link>? {
        val all = orNull { records(snapshot) } ?: return null
        val rows = CollectionCatalog.collections(snapshot).map { it.id }.toSet()
        val out = LinkedHashMap<String, CollectionShares.Link>()
        for (record in all.values) {
            if (record.collectionId in rows) out[record.collectionId] = CollectionShares.Link(record.pin.sharedMode, record.role.wire)
        }
        return out
    }

    /**
     * Collections another of this person's devices holds as a member of a read-only share (a `csl:` link), not shared on
     * this device itself: edits are refused here too (desktop `linked_read_only_collection_ids`).
     */
    fun linkedReadOnlyCollectionIds(snapshot: StoreSnapshot): Set<String> {
        val linked = CollectionCatalog.linkedReadOnlyIds(snapshot)
        val all = orNull { records(snapshot) } ?: return linked // unreadable: refuse more, never less
        val here = all.values.map { it.collectionId }.toSet()
        return linked.filter { it !in here }.toSet()
    }

    /** What personal sync needs from the share groups ([CollectionShares]; the app passes it on every personal run). */
    fun collectionShares(snapshot: StoreSnapshot): CollectionShares =
        CollectionShares(shareLinks(snapshot), readOnlyCollectionIds(snapshot))

    /** The collections [CollectionCatalog.delete] must refuse: those shared on this device and the read-only ones. */
    fun protectedCollectionIds(snapshot: StoreSnapshot): Set<String> {
        val here = orNull { records(snapshot) }?.values?.map { it.collectionId }?.toSet() ?: looseCollectionIds(snapshot)
        return here + readOnlyCollectionIds(snapshot) + CollectionCatalog.linkedReadOnlyIds(snapshot)
    }

    // ---- writing ----

    private fun commit(store: ItemStore, snapshot: StoreSnapshot, shares: Map<String, ShareRecord>, records: Map<String, JsonValue>? = null) {
        store.commit(
            StoreChange(
                snapshot.revision, records ?: snapshot.records, snapshot.meta, snapshot.sync,
                StoreChange.Shares.Replace(ShareRecord.encode(shares)),
            ),
        )
    }

    private fun checkInstallId(installId: String) {
        if (installId.isEmpty() || Scalars.count(installId) > FolderSync.MAX_INSTALL_ID || installId.contains('\u0000')) {
            throw ShareGroupException("bad-install-id", "install id must be a non-empty bounded string")
        }
    }

    /**
     * A folder reference the stored record can hold (at most [ShareRecord.MAX_FOLDER_BYTES]): a larger one would make
     * every stored share unreadable (`bad-state`), so it is refused before anything is written.
     */
    private fun checkFolder(folder: ByteArray?) {
        if (folder != null && folder.size > ShareRecord.MAX_FOLDER_BYTES) throw ShareGroupException("bad-folder", "folder reference too large")
    }

    private fun canonical(ring: JsonValue): ByteArray = CanonicalJson.encode(ring, Dialect.UTF8)

    private fun requireOwner(record: ShareRecord) {
        if (record.role != ShareRecord.Role.OWNER || record.state.deviceId != record.pin.owner) {
            throw ShareGroupException("not-owner", "only the person who shared the collection does this")
        }
    }

    private fun storedRing(record: ShareRecord): JsonValue {
        val bytes = record.state.keyring ?: throw ShareRecord.bad("keyring")
        return ShareKeyring.parse(bytes)
    }

    /**
     * Keyring bytes as the folder holds them (desktop `parse_keyring`): size, strict JSON, an object. Nothing is
     * authenticated here; [adopt] and the owner and join checks do that.
     */
    internal fun parseLoose(raw: ByteArray): JsonValue {
        if (raw.size > Keyring.MAX_KEYRING_BYTES) throw KeyringException("too-large", "${raw.size} > ${Keyring.MAX_KEYRING_BYTES}")
        val value = try {
            CanonicalJson.parse(raw)
        } catch (e: Exception) {
            throw KeyringException("bad-json", "keyring is not valid JSON")
        }
        if (value !is JsonValue.Obj) throw KeyringException("bad-keyring", "keyring must be an object")
        return value
    }

    /**
     * Share [collectionId] (desktop `create_share_group`): a new share group with this device, named [deviceName], as its
     * owner. [password] is what the other people type to join; [strong]: the sync password rule
     * ([ShareKeyring.isStrongPassword]). The mode (`read` / `edit`) is fixed for the life of the group. Refused:
     * [ShareProRequiredException] (before any key derivation), `bad-install-id`, `no-collection`, `already-shared`
     * (shared here, or a `csl:` link says another of this person's devices shares it), `bad-metadata`, then the keyring
     * reasons. [folder]: the app's opaque folder reference, kept with the record. The app writes the keyring to the
     * folder ([FolderSync.writeShareKeyring], after checking [FolderSync.holdsKeyring]) and undoes with [leave] if that
     * fails.
     */
    fun create(
        store: ItemStore,
        collectionId: String,
        password: String,
        deviceName: String,
        sharedMode: String,
        installId: String,
        isPro: Boolean,
        random: RandomSource,
        clock: UnixClock,
        strong: (String) -> Boolean,
        folder: ByteArray? = null,
        /** [ShareKeyring.LEGACY_SHARE_FORMAT] makes a share v1 group (tests of the upgrade only; desktop `_NEW_SHARE_FORMAT`). */
        shareFormat: Long = ShareKeyring.SHARE_FORMAT,
    ): Group = create(
        store, collectionId, password, deviceName, sharedMode, installId, isPro, random, clock, strong, folder, KeyringRotate.productionKdf,
        shareFormat,
    )

    internal fun create(
        store: ItemStore,
        collectionId: String,
        password: String,
        deviceName: String,
        sharedMode: String,
        installId: String,
        isPro: Boolean,
        random: RandomSource,
        clock: UnixClock,
        strong: (String) -> Boolean,
        folder: ByteArray?,
        derive: KeyringRotate.KeyDerivation,
        shareFormat: Long = ShareKeyring.SHARE_FORMAT, // tests pass the legacy format to make a share v1
    ): Group {
        ShareAccess.requirePro(ShareAccess.Action.CREATE, isPro)
        checkInstallId(installId)
        checkFolder(folder)
        val snapshot = store.load()
        val all = LinkedHashMap(records(snapshot))
        val row = CollectionCatalog.collections(snapshot).firstOrNull { it.id == collectionId }
            ?: throw ShareGroupException("no-collection", "that collection does not exist")
        // A link: another of this person's devices shares it (as owner or member); sharing it again from here would hand
        // someone else's items to new people.
        if (all.values.any { it.collectionId == collectionId } || snapshot.records[CollectionStates.LINK_PREFIX + collectionId] != null) {
            throw ShareGroupException("already-shared", "that collection is already shared")
        }
        val spec = ShareKeyring.Spec(collectionId, row.name, sharedMode)
        spec.check()
        val identity = DeviceIdentity.generate(random = random)
        val (ring, gk) = ShareKeyring.create(password, identity, deviceName, spec, random, clock.now, strong, derive, shareFormat)
        val state = SyncGroupState(
            groupId = gk.groupId, epoch = gk.epoch, key = gk.key, identity = identity, installId = installId, hasFolder = true,
            membersEpoch = gk.epoch, members = listOf(identity.deviceId), keyring = canonical(ring),
        )
        val record = ShareRecord(ShareRecord.Role.OWNER, ShareKeyring.Pin.of(ring), state, folder = folder)
        all[gk.groupId] = record
        commit(store, snapshot, all)
        return group(record)
    }

    /**
     * Join the share group of [keyring] (the folder's bytes) with its share password, as [deviceName] (desktop
     * `join_share_group`). Refused: [ShareProRequiredException] (before any key derivation), `bad-install-id`, the
     * keyring structure reasons, `not-share` (a device-sync keyring), `personal-group` (this vault's own device sync),
     * `already-joined`, `own-share` (shared by another of this person's devices: it already syncs here),
     * `collection-exists` (this vault already has that collection: marking it shared would publish items nobody chose to
     * share), `collection-limit`, then the join reasons (`password`...). The owner, collection and mode are pinned from
     * this keyring (trust on first use, authenticated by the password). The collection is added, named like the owner's
     * (with a number on a clash). This device stays pending until the owner approves it; the share run writes the grown
     * keyring.
     *
     * Joining again: a member whose join was lost to someone else's at the same moment (`superseded`) joins the same
     * group again with a new device identity; its collection, items, folder and share bookkeeping stay, and the pinned
     * facts must not change (`tampered`).
     */
    fun join(
        store: ItemStore,
        keyring: ByteArray,
        password: String,
        deviceName: String,
        installId: String,
        isPro: Boolean,
        random: RandomSource,
        clock: UnixClock,
        folder: ByteArray? = null,
    ): Group = join(store, keyring, password, deviceName, installId, isPro, random, clock, folder, null)

    internal fun join(
        store: ItemStore,
        keyring: ByteArray,
        password: String,
        deviceName: String,
        installId: String,
        isPro: Boolean,
        random: RandomSource,
        clock: UnixClock,
        folder: ByteArray?,
        derive: KeyringRotate.KeyDerivation?,
    ): Group {
        ShareAccess.requirePro(ShareAccess.Action.JOIN, isPro)
        checkInstallId(installId)
        checkFolder(folder)
        val ring = ShareKeyring.parse(keyring)
        // Not authenticated yet (the password join below does that): the metadata only chooses a refusal here.
        val meta = ShareKeyring.metadata(ring) ?: throw ShareGroupException("not-share", "that keyring is device sync, not a shared collection")
        val groupId = Keyring.str(Keyring.obj(ring)["group_id"]) ?: ""
        val collectionId = Keyring.str(meta["collection_id"]) ?: ""
        val snapshot = store.load()
        val personal = snapshot.sync
        if (personal != null && personal.groupId == groupId) {
            throw ShareGroupException("personal-group", "that is this vault's own device sync group")
        }
        val all = LinkedHashMap(records(snapshot))
        val previous = all[groupId]
        if (previous != null && !supersededJoin(previous, ring)) {
            throw ShareGroupException("already-joined", "this vault is already in that share group")
        }
        val catalog = CollectionCatalog.collections(snapshot)
        val existing = catalog.any { it.id == collectionId }
        val link = if (existing) storedLink(snapshot, collectionId) else null
        val sharedHere = all.values.any { it.collectionId == collectionId }
        if (link != null && link.role == "owner" && !sharedHere) {
            throw ShareGroupException("own-share", "you shared this collection from another of your devices")
        }
        // Never two share groups for one collection on a device.
        if (all.any { it.key != groupId && it.value.collectionId == collectionId }) {
            throw ShareGroupException("collection-exists", "this vault already has that collection")
        }
        if (existing && previous == null && link == null) {
            throw ShareGroupException("collection-exists", "this vault already has that collection")
        }
        if (!existing && catalog.size >= CollectionCatalog.MAX_COLLECTIONS) {
            throw CollectionCatalogException(CollectionCatalog.Failure.LIMIT)
        }
        val identity = DeviceIdentity.generate(random = random)
        val (newRing, gk) = if (derive != null) {
            val salt = Keyring.b64(Keyring.obj(Keyring.obj(ring)["kdf"])["salt"], Keyring.KDF_SALT_LEN, "kdf salt")
            ShareKeyring.join(ring, derive.derive(password, salt), identity, deviceName, random, clock)
        } else {
            ShareKeyring.join(ring, password, identity, deviceName, random, clock)
        }
        val name = ShareKeyring.shareName(newRing, gk)
        val pin = ShareKeyring.Pin.of(newRing)
        if (previous != null && previous.pin != pin) {
            throw KeyringException("tampered", "the keyring changes the share's owner, collection or mode")
        }
        val state = SyncGroupState(
            groupId = gk.groupId, epoch = gk.epoch, key = gk.key, identity = identity, installId = installId, hasFolder = true,
            membersEpoch = gk.epoch, members = ShareKeyring.memberIds(newRing), keyring = canonical(newRing),
            unackedMembers = ShareKeyring.pending(newRing, identity.deviceId),
        )
        val record = ShareRecord(
            ShareRecord.Role.MEMBER, pin, state, meta = previous?.meta ?: emptyMap(), folder = folder ?: previous?.folder,
        )
        all[groupId] = record
        val recs = LinkedHashMap(snapshot.records)
        if (existing) {
            recs.remove(CollectionStates.LINK_PREFIX + collectionId) // now shared here: this device speaks for it
        } else {
            val unique = CollectionCatalog.uniqueName(name, catalog.map { it.name })
            recs[CollectionStates.CATALOG_PREFIX + collectionId] =
                CollectionCatalog.catalogWrapper(collectionId, unique, "", clock.now, clock.now)
        }
        commit(store, snapshot, all, recs)
        return group(record)
    }

    /**
     * Join [groupId] again after someone else's join at the same moment won (`superseded`), from the same folder's
     * keyring (desktop `rejoin`): `not-joined` unless this vault is in that group, `folder-has-other-group` for a keyring
     * of another group, else [join].
     */
    fun rejoin(
        store: ItemStore,
        groupId: String,
        keyring: ByteArray,
        password: String,
        deviceName: String,
        installId: String,
        isPro: Boolean,
        random: RandomSource,
        clock: UnixClock,
    ): Group = rejoin(store, groupId, keyring, password, deviceName, installId, isPro, random, clock, null)

    internal fun rejoin(
        store: ItemStore,
        groupId: String,
        keyring: ByteArray,
        password: String,
        deviceName: String,
        installId: String,
        isPro: Boolean,
        random: RandomSource,
        clock: UnixClock,
        derive: KeyringRotate.KeyDerivation?,
    ): Group {
        ShareAccess.requirePro(ShareAccess.Action.JOIN, isPro)
        record(store.load(), groupId)
        val folderRing = parseLoose(keyring)
        if ((Keyring.str(Keyring.obj(folderRing)["group_id"]) ?: "") != groupId) {
            throw ShareGroupException("folder-has-other-group", "that folder holds another share group")
        }
        return join(store, keyring, password, deviceName, installId, isPro, random, clock, null, derive)
    }

    /** The checked `csl:` link of [collectionId] stored here (learned from another of this person's devices). */
    private fun storedLink(snapshot: StoreSnapshot, collectionId: String): CollectionShares.Link? {
        val id = CollectionStates.LINK_PREFIX + collectionId
        val r = CollectionCatalog.checked(id, snapshot.records[id] ?: return null) ?: return null
        val mode = CollectionCatalog.str(r["mode"]) ?: return null
        val role = CollectionCatalog.str(r["role"]) ?: return null
        return CollectionShares.Link(mode, role)
    }

    /**
     * The owner approves [deviceIds], each of which the screen showed by name ([pendingMembers]; desktop
     * `approve_members`): `not-owner` on another device, `not-pending` for an empty choice or an id that is not waiting.
     * Works without Pro. Returns the members just approved. The app writes the new keyring
     * ([FolderSync.writeShareKeyring]); the share run does too.
     */
    fun approve(store: ItemStore, groupId: String, deviceIds: List<String>, random: RandomSource = SystemRandomSource()): List<Member> {
        val snapshot = store.load()
        val (all, rec) = record(snapshot, groupId)
        requireOwner(rec)
        val waiting = group(rec).members.filter { !it.approved }
        val waitingIds = waiting.map { it.deviceId }.toSet()
        val chosen = deviceIds.toSet()
        if (chosen.isEmpty() || !waitingIds.containsAll(chosen)) {
            throw ShareGroupException("not-pending", "approve only members that are waiting")
        }
        val ids = CollectionCatalog.sortedIds(deviceIds)
        val ring = ShareKeyring.approvePending(storedRing(rec), rec.state.groupKey(), rec.state.identity, ids, random)
        all[groupId] = rec.copy(
            state = rec.state.copy(keyring = canonical(ring), unackedMembers = ShareKeyring.pending(ring, rec.state.deviceId)),
        )
        commit(store, snapshot, all)
        return waiting.filter { it.deviceId in chosen }.map { it.copy(approved = true) }.sortedWith { a, b -> byScalars(a.deviceId, b.deviceId) }
    }

    /**
     * The owner upgrades share v1 [groupId] to share v2 (desktop `upgrade_share`; works without Pro: a security action).
     * A rotation to epoch + 1 that removes nobody: approved members get the new content key, pending members stay
     * pending, the share password may stay the same (it no longer opens any item; [strong] is the password rule). The new
     * keyring is kept in the vault; the app writes it ([FolderSync.writeShareKeyring]) and the share run does too.
     * Refused: `not-owner`, `already-upgraded`, then the keyring reasons (`weak-password`...).
     */
    fun upgrade(
        store: ItemStore,
        groupId: String,
        password: String,
        random: RandomSource,
        strong: (String) -> Boolean,
    ): Group = upgrade(store, groupId, password, random, strong, KeyringRotate.productionKdf)

    internal fun upgrade(
        store: ItemStore,
        groupId: String,
        password: String,
        random: RandomSource,
        strong: (String) -> Boolean,
        derive: KeyringRotate.KeyDerivation,
    ): Group {
        val snapshot = store.load()
        val (all, rec) = record(snapshot, groupId)
        requireOwner(rec)
        val ring = storedRing(rec)
        if (ShareKeyring.shareVersion(ring) != 1) throw ShareGroupException("already-upgraded", "this share is already upgraded")
        val (newRing, gk) = ShareKeyring.upgrade(ring, rec.state.groupKey(), rec.state.identity, password, random, strong, derive)
        val state = FolderSync.epochReset(rec.state, gk.epoch, gk.key).copy(
            membersEpoch = gk.epoch, members = ShareKeyring.memberIds(newRing), keyring = canonical(newRing),
            unackedMembers = ShareKeyring.pending(newRing, rec.state.deviceId),
        )
        val updated = rec.copy(state = state)
        all[groupId] = updated
        commit(store, snapshot, all)
        return group(updated)
    }

    /**
     * The owner removes [deviceId] (desktop `remove_member`; works without Pro): a rotation with a NEW share password
     * (the removed person knows the old one; [strong] is the password rule) that also drops every member the owner never
     * approved, the owner signing the rest. A share v1 group is upgraded to share v2 in the same rotation. Returns the
     * owner-signed removal notice, naming this share group only: the app writes it first ([FolderSync.publishShareNotice]),
     * then the rotated keyring. The names go to the removed list.
     */
    fun removeMember(
        store: ItemStore,
        groupId: String,
        deviceId: String,
        newPassword: String,
        random: RandomSource,
        clock: UnixClock,
        strong: (String) -> Boolean,
    ): ByteArray = removeMember(store, groupId, deviceId, newPassword, random, clock, strong, KeyringRotate.productionKdf)

    internal fun removeMember(
        store: ItemStore,
        groupId: String,
        deviceId: String,
        newPassword: String,
        random: RandomSource,
        clock: UnixClock,
        strong: (String) -> Boolean,
        derive: KeyringRotate.KeyDerivation,
    ): ByteArray {
        val snapshot = store.load()
        val (all, rec) = record(snapshot, groupId)
        requireOwner(rec)
        if (!Identifier.isValid(deviceId) || deviceId == rec.state.deviceId) {
            throw ShareGroupException("not-member", "invalid device id")
        }
        val ring = storedRing(rec)
        val trusted = rec.state.groupKey()
        val names = Keyring.memberNames(ring, trusted)
        val now = clock.now
        val removed = ShareKeyring.removeMember(ring, trusted, rec.state.identity, deviceId, newPassword, random, strong, now, derive)
        val state = FolderSync.epochReset(rec.state, removed.key.epoch, removed.key.key).copy(
            membersEpoch = removed.key.epoch, members = ShareKeyring.memberIds(removed.keyring),
            keyring = canonical(removed.keyring), unackedMembers = emptyList(),
        )
        val rows = ArrayList(rec.removed)
        for (d in removed.dropped) {
            if (names.containsKey(d)) rows.add(ShareRecord.Removed(names[d], maxOf(0L, now)))
        }
        all[groupId] = rec.copy(state = state, removed = rows.takeLast(ShareRecord.MAX_REMOVED))
        commit(store, snapshot, all)
        return removed.notice
    }

    /**
     * The share link of [collectionId] received from another of this person's devices (it holds the share, this device
     * does not), null when there is none or the collection is shared here (desktop `received_share_link`). A share store
     * that cannot be read counts as shared here (fails closed).
     */
    fun receivedLink(snapshot: StoreSnapshot, collectionId: String): CollectionShares.Link? =
        if (sharedHere(snapshot, collectionId)) null else storedLink(snapshot, collectionId)

    private fun sharedHere(snapshot: StoreSnapshot, collectionId: String): Boolean = try {
        records(snapshot).values.any { it.collectionId == collectionId }
    } catch (e: Exception) {
        true
    }

    /**
     * Forget the share link of [collectionId] received from another of this person's devices (final review finding 4;
     * desktop `forget_share_link`, LGKCore `ShareGroups.forgetLink`). A received link goes away only through a tombstone
     * its holder publishes, so the link of a device that was lost, reset or left device sync stays for ever: it blocks
     * sharing the collection again (the owner-loss recovery), deleting it, and (read-only) every edit on this person's
     * devices. The `csl:` record is removed here; the next personal collections run publishes its tombstone (the link is
     * no longer relayed), so the person's other devices drop it too. A holder that still exists republishes its own link
     * above the tombstone ([CollectionSync]), so forgetting never takes a live share away. Works without Pro.
     *
     * Refused: `shared-here` when this device holds the share itself (leave instead; also for a share store that cannot
     * be read), `no-link` when there is no link record.
     */
    fun forgetLink(store: ItemStore, collectionId: String) {
        val snapshot = store.load()
        if (sharedHere(snapshot, collectionId)) throw ShareGroupException("shared-here", "that collection is shared on this device")
        val id = CollectionStates.LINK_PREFIX + collectionId
        if (snapshot.records[id] == null) throw ShareGroupException("no-link", "that collection has no share link")
        val recs = LinkedHashMap(snapshot.records)
        recs.remove(id)
        store.commit(StoreChange(snapshot.revision, recs, snapshot.meta, snapshot.sync))
    }

    /**
     * Forget [groupId] on this vault (desktop `leave_share_group`; works without Pro). The collection stops being shared
     * here and keeps its items; the group's keys and its share bookkeeping go. The other members still list this device
     * until the owner removes it.
     */
    fun leave(store: ItemStore, groupId: String) {
        val snapshot = store.load()
        val (all, rec) = record(snapshot, groupId)
        all.remove(groupId)
        // A link of the same collection from another of this person's devices that also shares it (re-review wave B,
        // B1) goes too: this device's next personal run tombstones it, and a device that still shares republishes it.
        val recs = LinkedHashMap(snapshot.records)
        recs.remove(CollectionStates.LINK_PREFIX + rec.collectionId)
        commit(store, snapshot, all, recs)
    }

    /**
     * Whether [collectionId] is shared on this device and another of this person's devices also shares it (its link is
     * stored here; re-review wave B, B1): the share sheet warns, and one share should be stopped or left.
     */
    fun sharedTwice(snapshot: StoreSnapshot, collectionId: String): Boolean {
        val here = try {
            records(snapshot).values.any { it.collectionId == collectionId }
        } catch (e: Exception) {
            false
        }
        return here && snapshot.records[CollectionStates.LINK_PREFIX + collectionId] != null
    }

    /** Keep [folder] (the app's opaque folder reference; null for none) with [groupId]. */
    fun setFolder(store: ItemStore, groupId: String, folder: ByteArray?) {
        checkFolder(folder)
        val snapshot = store.load()
        val (all, rec) = record(snapshot, groupId)
        all[groupId] = rec.copy(folder = folder)
        commit(store, snapshot, all)
    }

    // ---- keyring changes found in the folder (the share run) ----

    /**
     * Accept a newer keyring of [groupId] from the folder (desktop `adopt_keyring`): authenticated against the stored
     * trusted key and the owner's signature; `tampered` if it changes a pinned fact or, at the stored epoch, does not
     * only grow; `removed` when an owner-signed rotation left this device out. Members the owner has not approved are
     * stored as pending (`unackedMembers`).
     */
    internal fun adopt(store: ItemStore, groupId: String, raw: ByteArray): ShareRecord {
        val snapshot = store.load()
        val (all, rec) = record(snapshot, groupId)
        val candidate = parseLoose(raw)
        val gk = ShareKeyring.adopt(storedRing(rec), candidate, rec.state.groupKey(), rec.state.identity, rec.pin)
        val base = if (gk.epoch != rec.state.epoch) FolderSync.epochReset(rec.state, gk.epoch, gk.key) else rec.state
        val state = base.copy(
            epoch = gk.epoch, key = gk.key, membersEpoch = gk.epoch, members = ShareKeyring.memberIds(candidate),
            keyring = canonical(candidate), unackedMembers = ShareKeyring.pending(candidate, base.deviceId),
        )
        val updated = rec.copy(state = state)
        all[groupId] = updated
        commit(store, snapshot, all)
        return updated
    }

    /**
     * Owner only (desktop `reconcile_owner_keyring`): this device's approvals re-signed onto a same-epoch folder keyring
     * that someone else grew meanwhile (a join between the owner's approval and its next run), when the result only grows
     * from the stored one; the new joiners stay pending. False, with nothing changed, otherwise.
     */
    internal fun reconcileOwner(store: ItemStore, groupId: String, raw: ByteArray): Boolean {
        val snapshot = store.load()
        val (all, rec) = record(snapshot, groupId)
        if (rec.role != ShareRecord.Role.OWNER || rec.state.deviceId != rec.pin.owner) return false
        val folder = orNull { parseLoose(raw) } ?: return false
        val stored = orNull { storedRing(rec) } ?: return false
        val trusted = orNull { rec.state.groupKey() } ?: return false
        val ring = ShareKeyring.reconcileOwner(stored, folder, trusted, rec.state.identity, rec.pin) ?: return false
        all[groupId] = rec.copy(
            state = rec.state.copy(
                membersEpoch = rec.state.epoch, members = ShareKeyring.memberIds(ring), keyring = canonical(ring),
                unackedMembers = ShareKeyring.pending(ring, rec.state.deviceId),
            ),
        )
        commit(store, snapshot, all)
        return true
    }

    /**
     * Whether this member's pending join of the group was lost to another join at the same moment (desktop
     * `superseded_join`): the user joins again; anything else stays a refusal. Never on the owner's device.
     */
    internal fun supersededJoin(rec: ShareRecord, folder: JsonValue): Boolean {
        if (rec.role != ShareRecord.Role.MEMBER || rec.state.deviceId == rec.pin.owner) return false
        val stored = orNull { storedRing(rec) } ?: return false
        val trusted = orNull { rec.state.groupKey() } ?: return false
        return ShareKeyring.supersededJoin(stored, folder, trusted, rec.state.identity, rec.pin)
    }

    /**
     * Whether this device writes its trusted keyring over a folder keyring it could not take (desktop `restores_over`),
     * asked only after adopting, reconciling and the superseded-join check failed, or for bytes that do not parse
     * ([folder] null) or name another group. Without it anyone who can write to the share folder could stop the share on
     * every device. The owner's device: always (the only authority), except over a later epoch signed by the pinned owner
     * key, which only this owner made. A member's device: only over a keyring of its trusted epoch that does not
     * authenticate (MAC or the pinned owner's signature); an authenticated one that does not grow is a concurrent join
     * and still stops the run.
     */
    internal fun restoresOver(rec: ShareRecord, folder: JsonValue?): Boolean {
        val trusted = orNull { rec.state.groupKey() } ?: return false
        if (rec.role == ShareRecord.Role.OWNER && rec.state.deviceId == rec.pin.owner) {
            return folder == null || !ShareKeyring.ownerSignedAhead(folder, trusted, rec.pin)
        }
        if (folder == null) return false
        val f = (folder as? JsonValue.Obj)?.fields ?: return false
        if (f["group_id"] != JsonValue.Str(trusted.groupId) || f["epoch"] != JsonValue.Int(trusted.epoch)) return false
        return !ShareKeyring.authenticatesAtEpoch(folder, trusted, rec.state.identity, rec.pin)
    }

    // ---- removal ----

    /**
     * The pinned owner removed this device from [groupId] (desktop `apply_share_removal`; works without Pro): [notice]
     * must verify as the owner's notice for this device ([RemovalException] otherwise, `owner` on the owner's own device,
     * whatever it says). Every live item in the shared collection leaves the store, documents last; a document still
     * linked from an item outside the collection stays. Nothing else is touched (personal items, other collections, the
     * personal group), and the group is forgotten, in one commit. The app's store moves what leaves to Recently deleted
     * ([trash]: `trash-full` is checked first, `item-error` when Recently deleted is unknown or the commit fails; nothing
     * changes then and the next run tries again). Returns how many items left.
     */
    fun applyShareRemoval(store: ItemStore, groupId: String, notice: ByteArray, folderKeyring: ByteArray, trash: ShareTrash): Int {
        val snapshot = store.load()
        val (all, rec) = record(snapshot, groupId)
        val watch = if (rec.role == ShareRecord.Role.MEMBER) {
            ShareAccess.removalWatch(rec.state.groupId, rec.state.deviceId, rec.state.epoch, rec.state.installId, "", rec.pin)
        } else {
            null
        }
        if (watch == null) throw RemovalException("owner")
        Removal.verifyNotice(notice, watch, folderKeyring)
        val cid = rec.collectionId
        val rows = ArrayList<Pair<String, Boolean>>()
        for ((id, w) in snapshot.itemRecords) {
            if (SyncMeta.nsName(w) != Namespace.ITEM.wire) continue
            if (cid !in CollectionCatalog.memberships(id, snapshot.records)) continue
            val r = ((w as? JsonValue.Obj)?.fields?.get("record") as? JsonValue.Obj)?.fields
            rows.add(id to (r?.get("kind") == JsonValue.Str("document")))
        }
        // Linking items first, then documents (desktop order); by id within each, so the result never depends on map order.
        rows.sortWith { a, b -> if (a.second != b.second) (if (a.second) 1 else -1) else byScalars(a.first, b.first) }
        if (rows.isNotEmpty()) {
            val count = trash.count ?: throw ShareGroupException("item-error", "Recently deleted is not available")
            if (count + rows.size > ShareTrash.MAX_TRASH) {
                throw ShareGroupException("trash-full", "the trash cannot hold this collection's items")
            }
        }
        val records = LinkedHashMap(snapshot.records)
        var moved = 0
        for ((id, document) in rows) {
            if (document && linkedDocument(id, records)) continue
            records.remove(id)
            records.remove(CollectionStates.MEMBERSHIP_PREFIX + id)
            moved++
        }
        all.remove(groupId)
        records.remove(CollectionStates.LINK_PREFIX + rec.collectionId) // as `leave` (B1)
        try {
            commit(store, snapshot, all, records)
        } catch (e: Exception) {
            // Not the trash limit (checked above): the store refused the change, reported as it is.
            throw ShareGroupException("item-error", e.message ?: e.javaClass.simpleName)
        }
        return moved
    }

    /** Whether a live item in [records] still links [documentId] (`payload.document_ids`). */
    private fun linkedDocument(documentId: String, records: Map<String, JsonValue>): Boolean {
        for ((id, w) in records) {
            if (CollectionStates.isReserved(id, w)) continue
            val r = ((w as? JsonValue.Obj)?.fields?.get("record") as? JsonValue.Obj)?.fields ?: continue
            val docs = ((r["payload"] as? JsonValue.Obj)?.fields?.get("document_ids") as? JsonValue.Arr)?.items ?: continue
            if (docs.any { (it as? JsonValue.Str)?.v == documentId }) return true
        }
        return false
    }
}
