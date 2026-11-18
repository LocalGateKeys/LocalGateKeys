package app.localgatekeys.core.keyring

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring.arr
import app.localgatekeys.core.keyring.Keyring.int
import app.localgatekeys.core.keyring.Keyring.obj
import app.localgatekeys.core.keyring.Keyring.str
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.password.StrengthEstimator
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.RandomSource

/**
 * The keyring rotation writer (desktop `keyring.rotate`, Swift `Keyring.rotate`): a new group key, epoch + 1, a new
 * salt and a NEW sync password; the [remove] devices are dropped. Byte-identical to both for the same random stream
 * (`tests/vectors/sync/mac/keyring_write.json`).
 *
 * Draw order: the new group key (32), the salt (16), the password-wrap nonce (12), then for each remaining member in
 * keyring order its device wrap (eph 32, nonce 12) and its name nonce (12).
 */
internal object KeyringRotate {
    const val MIN_PASSWORD_LEN = 12
    const val MIN_PASSWORD_SCORE = 3
    const val UNNAMED_DEVICE = "Unnamed device"

    /** The Argon2id key for a password and a salt (production cost; tests inject the vector's outputs). */
    fun interface KeyDerivation {
        fun derive(password: String, salt: ByteArray): ByteArray
    }

    val productionKdf = KeyDerivation { password, salt ->
        Keyring.argon2(
            password, salt,
            mapOf(
                "memory_kib" to JsonValue.Int(Keyring.KDF_MEMORY_KIB),
                "iterations" to JsonValue.Int(Keyring.KDF_ITERATIONS),
                "parallelism" to JsonValue.Int(Keyring.KDF_PARALLELISM),
            ),
        )
    }

    /** Desktop `_check_password`: at least 12 code points and a strength score of 3 or more. */
    fun isStrong(password: String, strength: StrengthEstimator): Boolean =
        password.codePointCount(0, password.length) >= MIN_PASSWORD_LEN && strength.estimate(password).score >= MIN_PASSWORD_SCORE

    private class Member(
        val deviceId: String,
        val name: String,
        val exchangePublic: String,
        val signingPublic: JsonValue,
        val signingProof: JsonValue,
        val addedAt: Long,
    )

    /**
     * Reasons in order: `weak-password`, the `accept` reasons, `stale-trust`, `not-member` / `key-mismatch` (this
     * device), `cannot-remove-self`, `not-member` (a device to remove), `password-reused`.
     */
    fun rotate(
        ring: JsonValue,
        trusted: GroupKey,
        identity: DeviceIdentity,
        newPassword: String,
        remove: Collection<String>,
        random: RandomSource,
        strong: (String) -> Boolean,
        derive: KeyDerivation,
        share: Boolean = false,
        upgrade: Boolean = false,
        allowSamePassword: Boolean = false,
    ): Pair<JsonValue, GroupKey> {
        if (!strong(newPassword)) throw KeyringException("weak-password", "sync password is too short or too easy to guess")
        val gk = KeyringAccept.accept(ring, trusted, identity, share)
        if (gk.epoch != trusted.epoch) throw KeyringException("stale-trust", "adopt the current keyring before rotating")
        if (upgrade && obj(ring)["metadata"] == null) throw KeyringException("not-share", "a personal keyring has no share version")
        Keyring.member(ring, identity)
        val members = arr(obj(ring)["members"]).map { obj(it) }
        val drop = remove.toSet()
        val have = members.mapNotNull { str(it["device_id"]) }.toSet()
        if (identity.deviceId in drop) throw KeyringException("cannot-remove-self", "a device cannot remove itself")
        if (!have.containsAll(drop)) throw KeyringException("not-member", "device to remove is not a member")
        if (!allowSamePassword) {
            // An upgrade (share v1 to v2) may keep the share password: it no longer opens any item.
            val oldSalt = Keyring.b64(obj(obj(ring)["kdf"])["salt"], Keyring.KDF_SALT_LEN, "kdf salt")
            val reused = try {
                Keyring.unwrap(ring, derive.derive(newPassword, oldSalt))
                true
            } catch (e: KeyringException) {
                false
            }
            if (reused) throw KeyringException("password-reused", "choose a sync password different from the current one")
        }
        val newKey = Keyring.groupKey(gk.groupId, gk.epoch + 1, Keyring.draw(random, Keyring.KEY_LEN))
        val names = Keyring.memberNames(ring, gk)
        val remaining = members.mapNotNull { m ->
            val id = str(m["device_id"]) ?: return@mapNotNull null
            if (id in drop) return@mapNotNull null
            Member(
                id, names[id] ?: UNNAMED_DEVICE, str(m["exchange_public"]) ?: "",
                m["signing_public"] ?: JsonValue.Null, m["signing_proof"] ?: JsonValue.Null, int(m["added_at"]) ?: 0,
            )
        }
        var body = freshBody(newKey, newPassword, remaining, random, derive)
        val meta = obj(ring)["metadata"]
        if (meta != null) {
            // A share group (desktop `rotate`): only the owner rotates; the name is re-sealed for the new epoch (one
            // more nonce, drawn last) and the owner approves every remaining member.
            val old = obj(meta)
            val cid = str(old["collection_id"]) ?: throw KeyringException("bad-metadata", "collection_id")
            val sealed = ShareKeyring.sealName(newKey, cid, ShareKeyring.shareName(ring, gk), random)
            body["metadata"] = JsonValue.Obj(LinkedHashMap(old).also { it["name_ct"] = JsonValue.Str(sealed) })
            body = if (upgrade || int(obj(ring)["format"]) == ShareKeyring.SHARE_FORMAT) {
                // Share v2 (or an upgrade to it): a new content key C (32), then one content wrap per approved member in
                // id order; the approved members are the previous ones minus the removed (the owner always).
                body["format"] = JsonValue.Int(ShareKeyring.SHARE_FORMAT)
                body["prev_mac"] = JsonValue.Str(Base64Std.encode(Keyring.chainMac(gk, newKey))) // owner-signed (share v2)
                val content = Keyring.groupKey(newKey.groupId, newKey.epoch, Keyring.draw(random, Keyring.KEY_LEN))
                val keep = (ShareKeyring.approvedMembers(ring) ?: emptySet()) - drop
                ShareKeyring.signOwner(body, identity, keep, content, random)
            } else {
                ShareKeyring.signOwner(body, identity, null)
            }
        }
        body["prev_mac"] = JsonValue.Str(Base64Std.encode(Keyring.chainMac(gk, newKey)))
        return Pair(Keyring.finish(body, newKey), newKey)
    }

    /** A uuid4 group id from 16 random bytes (desktop `uuid.uuid4()`, Swift `SyncGroup.uuid4`). */
    fun uuid4(random: RandomSource): String {
        val u = Keyring.draw(random, 16)
        u[6] = ((u[6].toInt() and 0x0F) or 0x40).toByte()
        u[8] = ((u[8].toInt() and 0x3F) or 0x80).toByte()
        val h = u.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        return "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20, 32)}"
    }

    /**
     * The first keyring of an existing group ([gk] from Wi-Fi enrollment) with [identity] as its only member; `prev_mac`
     * null at any epoch (desktop `create_for_existing_group`, Swift `Keyring.createForExistingGroup`). Draw order: salt
     * (16), password-wrap nonce (12), the device wrap (eph 32, nonce 12), the name nonce (12). Reasons as [create].
     */
    fun createForExistingGroup(
        gk: GroupKey,
        password: String,
        identity: DeviceIdentity,
        name: String,
        random: RandomSource,
        addedAt: Long,
        strong: (String) -> Boolean,
        derive: KeyDerivation,
    ): JsonValue {
        if (!strong(password)) throw KeyringException("weak-password", "sync password is too short or too easy to guess")
        if (!app.localgatekeys.core.primitives.Identifier.isValid(identity.deviceId)) {
            throw KeyringException("bad-device-id", "device id must be ASCII [A-Za-z0-9._:-], 1..128 chars")
        }
        MemberNames.checkName(name)
        if (addedAt < 0 || addedAt > Keyring.MAX_INT) throw KeyringException("bad-fields", "added_at")
        val exchange = Base64Std.encode(identity.exchangePublicKey)
        val signing = Base64Std.encode(identity.signingPublicKey)
        val proof = identity.sign(Keyring.proofMessage(gk.groupId, identity.deviceId, exchange, signing))
        val member = Member(
            identity.deviceId, name, exchange, JsonValue.Str(signing), JsonValue.Str(Base64Std.encode(proof)), addedAt,
        )
        val body = freshBody(gk, password, listOf(member), random, derive)
        body["prev_mac"] = JsonValue.Null
        return Keyring.finish(body, gk)
    }

    /**
     * A new group (epoch 1, uuid4 group id, `prev_mac` null) with [identity] as its only member (desktop
     * `create_group`, Swift `Keyring.create`). Draw order: the group id (16), G (32), salt (16), password-wrap nonce
     * (12), the device wrap (eph 32, nonce 12), the name nonce (12). Reasons: `weak-password`, `bad-device-id`,
     * `bad-name`, `bad-fields`. [share]: a share group (`bad-metadata` first when the description is malformed).
     */
    fun create(
        password: String,
        identity: DeviceIdentity,
        name: String,
        random: RandomSource,
        addedAt: Long,
        strong: (String) -> Boolean,
        derive: KeyDerivation,
        share: ShareKeyring.Spec? = null,
        shareFormat: Long = ShareKeyring.SHARE_FORMAT,
    ): Pair<JsonValue, GroupKey> {
        if (shareFormat != ShareKeyring.SHARE_FORMAT && shareFormat != ShareKeyring.LEGACY_SHARE_FORMAT) {
            throw KeyringException("bad-format", "unsupported share format")
        }
        share?.check()
        if (!strong(password)) throw KeyringException("weak-password", "sync password is too short or too easy to guess")
        if (!app.localgatekeys.core.primitives.Identifier.isValid(identity.deviceId)) {
            throw KeyringException("bad-device-id", "device id must be ASCII [A-Za-z0-9._:-], 1..128 chars")
        }
        MemberNames.checkName(name)
        if (addedAt < 0 || addedAt > Keyring.MAX_INT) throw KeyringException("bad-fields", "added_at")
        val gid = uuid4(random)
        val gk = Keyring.groupKey(gid, 1, Keyring.draw(random, Keyring.KEY_LEN))
        val exchange = Base64Std.encode(identity.exchangePublicKey)
        val signing = Base64Std.encode(identity.signingPublicKey)
        val proof = identity.sign(Keyring.proofMessage(gid, identity.deviceId, exchange, signing))
        val member = Member(
            identity.deviceId, name, exchange, JsonValue.Str(signing), JsonValue.Str(Base64Std.encode(proof)), addedAt,
        )
        var body = freshBody(gk, password, listOf(member), random, derive)
        if (share != null) {
            // A share group owned by [identity] (desktop `create_group(metadata=)`): the collection name is sealed under
            // G (one more nonce, drawn last) and the owner signs the roster.
            body["metadata"] = JsonValue.Obj(
                mapOf(
                    "kind" to JsonValue.Str(ShareKeyring.KIND),
                    "collection_id" to JsonValue.Str(share.collectionId),
                    "name_ct" to JsonValue.Str(ShareKeyring.sealName(gk, share.collectionId, share.name, random)),
                    "shared_mode" to JsonValue.Str(share.sharedMode),
                    "owner" to JsonValue.Str(identity.deviceId),
                    "owner_key" to JsonValue.Str(signing),
                ),
            )
            // Share v2 (the default): C (32) and the owner's content wrap (eph 32, nonce 12) after the name nonce.
            var content: GroupKey? = null
            if (shareFormat == ShareKeyring.SHARE_FORMAT) {
                body["format"] = JsonValue.Int(ShareKeyring.SHARE_FORMAT)
                body["prev_mac"] = JsonValue.Null // owner-signed (share v2)
                content = Keyring.groupKey(gk.groupId, gk.epoch, Keyring.draw(random, Keyring.KEY_LEN))
            }
            body = ShareKeyring.signOwner(body, identity, null, content, random)
        }
        body["prev_mac"] = JsonValue.Null
        return Pair(Keyring.finish(body, gk), gk)
    }

    /** A new epoch's body (desktop `_fresh_body`): salt, password wrap, then each member (wrap, then name). */
    private fun freshBody(
        gk: GroupKey,
        password: String,
        members: List<Member>,
        random: RandomSource,
        derive: KeyDerivation,
    ): LinkedHashMap<String, JsonValue> {
        val salt = Keyring.draw(random, Keyring.KDF_SALT_LEN)
        val nonce = Keyring.draw(random, Keyring.NONCE_LEN)
        val ct = try {
            CryptoBox.sealGcm(derive.derive(password, salt), nonce, gk.key, Keyring.passwordAad(gk.groupId, gk.epoch))
        } catch (e: KeyringException) {
            throw e
        } catch (e: Exception) {
            throw KeyringException("bad-kdf", e.toString())
        }
        val entries = ArrayList<JsonValue>()
        val wraps = LinkedHashMap<String, JsonValue>()
        for (m in members) {
            val exchange = Keyring.b64(JsonValue.Str(m.exchangePublic), 32, "exchange_public")
            val wrap = Keyring.wrapDevice(gk, m.deviceId, exchange, random)
            entries.add(
                JsonValue.Obj(
                    mapOf(
                        "device_id" to JsonValue.Str(m.deviceId),
                        "name_ct" to JsonValue.Str(MemberNames.sealName(gk, m.deviceId, m.name, random)),
                        "exchange_public" to JsonValue.Str(m.exchangePublic),
                        "signing_public" to m.signingPublic,
                        "signing_proof" to m.signingProof,
                        "added_at" to JsonValue.Int(m.addedAt),
                    ),
                ),
            )
            wraps[m.deviceId] = wrap
        }
        return linkedMapOf(
            "format" to JsonValue.Int(Keyring.FORMAT),
            "group_id" to JsonValue.Str(gk.groupId),
            "epoch" to JsonValue.Int(gk.epoch),
            "kdf" to JsonValue.Obj(
                mapOf(
                    "name" to JsonValue.Str(Keyring.KDF_NAME),
                    "salt" to JsonValue.Str(Base64Std.encode(salt)),
                    "memory_kib" to JsonValue.Int(Keyring.KDF_MEMORY_KIB),
                    "iterations" to JsonValue.Int(Keyring.KDF_ITERATIONS),
                    "parallelism" to JsonValue.Int(Keyring.KDF_PARALLELISM),
                ),
            ),
            "password_wrap" to JsonValue.Obj(
                mapOf("nonce" to JsonValue.Str(Base64Std.encode(nonce)), "ct" to JsonValue.Str(Base64Std.encode(ct))),
            ),
            "device_wraps" to JsonValue.Obj(wraps),
            "members" to JsonValue.Arr(entries),
        )
    }
}
