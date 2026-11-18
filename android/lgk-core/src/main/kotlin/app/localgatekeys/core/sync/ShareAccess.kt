package app.localgatekeys.core.sync

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.ShareKeyring

/** An edit in a collection this device holds as a member of a read-only share (desktop `ReadOnlyCollection`). */
class ReadOnlyCollectionException : Exception("read-only-collection")

/** Sharing a collection needs Pro (desktop `share_group.ProRequired`, feature `sharing`). */
class ShareProRequiredException : Exception("pro-required")

/**
 * Who may do what with a shared collection (desktop `share_group` gating and `item_service.check_writable`).
 *
 * - Pro: creating, joining and syncing a share need Pro. Removing a member (a security action), approving and leaving
 *   work without it; a device whose Pro lapsed keeps reading what it has.
 * - Read-only: a member of a `read` share never changes that collection's items (edit, move in or out, delete,
 *   restore); a damaged share store fails closed (every shared collection read-only).
 * - Removal notices: only the pinned owner's key signs one, and the owner's own device never acts on one.
 */
object ShareAccess {
    enum class Action(val needsPro: Boolean) {
        CREATE(true),
        JOIN(true),
        SYNC(true),
        APPROVE(false),
        REMOVE(false),
        LEAVE(false),
    }

    /** [ShareProRequiredException] when [action] needs Pro and [isPro] is false. Call before any key derivation. */
    fun requirePro(action: Action, isPro: Boolean) {
        if (action.needsPro && !isPro) throw ShareProRequiredException()
    }

    /** One share this vault is in: the collection, this device's role (`owner` / `member`) and the fixed mode. */
    data class Membership(val collectionId: String, val role: String, val sharedMode: String)

    /**
     * Collections this vault holds as a member of a read-only share. [memberships] null means the share store could
     * not be read: then every collection in [sharedCollectionIds] is read-only (fail closed).
     */
    fun readOnlyCollectionIds(memberships: List<Membership>?, sharedCollectionIds: Set<String>): Set<String> =
        memberships?.filter { it.role == "member" && it.sharedMode == "read" }?.map { it.collectionId }?.toSet()
            ?: sharedCollectionIds

    /**
     * [ReadOnlyCollectionException] if any of [records] (the item before and after a change; null for none) is in a
     * [readOnly] collection, so a move into or out of such a collection is refused too.
     */
    fun checkWritable(readOnly: Set<String>, vararg records: JsonValue?) {
        if (readOnly.isEmpty()) return
        for (record in records) {
            val ids = ((record as? JsonValue.Obj)?.fields?.get("collection_ids") as? JsonValue.Arr)?.items ?: continue
            if (ids.any { (it as? JsonValue.Str)?.v in readOnly }) throw ReadOnlyCollectionException()
        }
    }

    /**
     * The removal watch of a member device in a share (desktop `share_watch`): the pinned owner is the only signer.
     * Null on the owner's own device. Verify a notice with [Removal.verifyNotice].
     */
    fun removalWatch(groupId: String, deviceId: String, epoch: Long, installId: String, folder: String, pin: ShareKeyring.Pin): RemovalWatch? {
        if (pin.owner == deviceId) return null
        return RemovalWatch(groupId, deviceId, epoch, installId, folder, mapOf(pin.owner to pin.ownerKey))
    }
}
