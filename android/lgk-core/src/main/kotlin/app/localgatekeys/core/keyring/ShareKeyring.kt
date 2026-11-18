package app.localgatekeys.core.keyring

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring.arr
import app.localgatekeys.core.keyring.Keyring.int
import app.localgatekeys.core.keyring.Keyring.obj
import app.localgatekeys.core.keyring.Keyring.str
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.PyStrip
import app.localgatekeys.core.password.StrengthEstimator

/**
 * Shared-collection keyrings (sub-plan 07; desktop `keyring.py` share fields and `share_group.py`). Byte for byte with
 * `tests/vectors/share/collections/keyring.json`.
 *
 * A share keyring is a format-2 keyring with two more top-level fields:
 *
 * - `metadata`: `{"kind":"share","collection_id","name_ct","shared_mode","owner","owner_key"}`. The collection name is
 *   sealed under the group key (`name_ct`, HKDF info `localgatekeys|sync|share-name|v1|<epoch>`, salt the group id, AAD
 *   `lgk-keyring-share-name-v1|<group>|<epoch>|<collection>`); `owner` and `owner_key` are the owner device id and its
 *   raw Ed25519 view-signing key, listed as that member's `signing_public`.
 * - `owner_sig`: `{"members":[approved ids, sorted],"sig"}`, the owner's Ed25519 signature over
 *   `localgatekeys|sync|share-owner|v1|` + canonical JSON of `{group_id, epoch, metadata, members:[{device_id,
 *   exchange_public, signing_public}] of the approved ids}`.
 *
 * Every member holds G and can re-MAC a keyring, so the owner's signature is what gives the owner authority: only the
 * owner approves members, rotates and removes. Within one epoch a share keyring may only grow ([checkSameEpochGrowth]);
 * the owner id and key, collection id and mode are pinned at join ([Pin]) and never change.
 *
 * Share v2 (format 3, `docs/superpowers/specs/2026-11-12-collections-crypto-gating.md`, byte for byte with
 * `tests/vectors/share/collections/gating.json`): one more top-level field `content` = `{"commit","wraps":{device_id:
 * {"eph","nonce","ct"}}}`. The share's item views are sealed with a content key C (32 random bytes per epoch,
 * [openContentKey]) that the owner wraps only to the members it approved, so the share password (which opens G) opens no
 * item. `commit` = SHA-256(`localgatekeys|sync|share-content|v1|` + group | epoch | C); a content wrap is a device wrap
 * of C with the labels `localgatekeys|sync|content-wrap|v1|` (HKDF info) and `lgk-keyring-content-wrap-v1|` (AAD). The
 * wrap ids equal `owner_sig.members` (`bad-content`) and the owner signs `localgatekeys|sync|share-owner|v2|` + canonical
 * JSON of `{group_id, epoch, metadata, members, content, kdf, password_wrap, device_wraps (approved members only),
 * prev_mac}`, so the signature binds G; writers set `prev_mac` before signing (null at create, the chain MAC at a
 * rotation, carried at an approval). Joining keeps format 3 and adds no content wrap; [approve]
 * wraps C to each newly approved member (id order); a rotation of a format-3 keyring (or [upgrade] of a format-2 one)
 * draws a new C after the share-name nonce, then one content wrap per approved member. A format above 3 is
 * `newer-format`.
 */
object ShareKeyring {
    const val KIND = "share"

    /** The keyring format of a share v2 keyring (item views sealed with the content key). */
    const val SHARE_FORMAT: Long = 3

    /** The format of a share v1 keyring (item views sealed with G; legacy vectors and migration tests create it). */
    const val LEGACY_SHARE_FORMAT: Long = 2
    val SHARED_MODES: Set<String> = setOf("read", "edit")
    const val MAX_NAME_LEN = 100
    const val NAME_CT_MIN = 12 + 1 + 16
    const val NAME_CT_MAX = 12 + 4 * MAX_NAME_LEN + 16

    private fun utf8(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

    private val NAME_AAD = utf8("lgk-keyring-share-name-v1|")
    private val NAME_INFO = utf8("localgatekeys|sync|share-name|v1|")
    private val OWNER_SIG_LABEL = utf8("localgatekeys|sync|share-owner|v1|")
    private val OWNER_SIG_LABEL_V2 = utf8("localgatekeys|sync|share-owner|v2|")
    private val CONTENT_AAD = utf8("lgk-keyring-content-wrap-v1|")
    private val CONTENT_INFO = utf8("localgatekeys|sync|content-wrap|v1|")
    private val CONTENT_COMMIT_LABEL = utf8("localgatekeys|sync|share-content|v1|")
    private val metadataFields = setOf("kind", "collection_id", "name_ct", "shared_mode", "owner", "owner_key")
    private val ownerSigFields = setOf("members", "sig")
    private val sameEpochFixed = listOf("format", "group_id", "epoch", "kdf", "password_wrap", "metadata", "prev_mac")
    private val uuidRe = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    /** Canonical lowercase 8-4-4-4-12 (Python `str(uuid.UUID(v)) == v`). */
    fun isCanonicalUuid(v: String?): Boolean = v != null && uuidRe.matches(v)

    /** The plaintext share description given at creation (desktop `check_share_spec`). */
    class Spec(val collectionId: String, val name: String, val sharedMode: String) {
        /** `bad-metadata` unless well formed. */
        fun check() {
            if (!isCanonicalUuid(collectionId)) throw KeyringException("bad-metadata", "collection_id must be a canonical UUID")
            checkShareName(name)
            if (sharedMode !in SHARED_MODES) throw KeyringException("bad-metadata", "shared_mode must be read or edit")
        }

        override fun toString(): String = "ShareKeyring.Spec(collection=$collectionId, mode=$sharedMode)"
    }

    /**
     * What a device pins when it creates or joins a share (desktop `_PINNED`): no later keyring may change it.
     * [ownerKey] is base64 text as stored in the metadata.
     */
    data class Pin(val collectionId: String, val owner: String, val ownerKey: String, val sharedMode: String) {
        companion object {
            /** From a structurally verified share keyring. */
            fun of(ring: JsonValue): Pin {
                val m = metadata(ring) ?: throw KeyringException("not-share", "a personal keyring has no owner")
                return Pin(str(m["collection_id"])!!, str(m["owner"])!!, str(m["owner_key"])!!, str(m["shared_mode"])!!)
            }
        }
    }

    private fun checkShareName(name: String): String {
        if (MemberNames.strictEncode(name) == null) throw KeyringException("bad-metadata", "name is not encodable")
        if (Scalars.count(name) !in 1..MAX_NAME_LEN || PyStrip.strip(name) != name) {
            throw KeyringException("bad-metadata", "name must be 1..100 characters without outer spaces")
        }
        return name
    }

    // ---- structure ----

    /** Desktop `check_metadata`: the stored metadata block's exact shape (no authentication). */
    internal fun checkMetadata(v: JsonValue?): Map<String, JsonValue> {
        val m = (v as? JsonValue.Obj)?.fields
        if (m == null || m.keys != metadataFields) throw KeyringException("bad-fields", "metadata fields")
        if (str(m["kind"]) != KIND) throw KeyringException("bad-metadata", "unsupported metadata kind")
        if (!isCanonicalUuid(str(m["collection_id"]))) throw KeyringException("bad-metadata", "collection_id must be a canonical UUID")
        if (Keyring.b64any(m["name_ct"], "metadata name_ct").size !in NAME_CT_MIN..NAME_CT_MAX) {
            throw KeyringException("bad-metadata", "name_ct must be 29..428 bytes")
        }
        if (str(m["shared_mode"]) !in SHARED_MODES) throw KeyringException("bad-metadata", "shared_mode must be read or edit")
        val owner = str(m["owner"])
        if (owner == null || !Identifier.isValid(owner)) throw KeyringException("bad-metadata", "owner")
        Keyring.b64(m["owner_key"], 32, "metadata owner_key")
        return m
    }

    /** The share metadata of a structurally verified keyring, or null for a personal (device sync) keyring. */
    fun metadata(ring: JsonValue): Map<String, JsonValue>? = obj(ring)["metadata"]?.let { checkMetadata(it) }

    /** `owner_sig` of a structurally valid share keyring: the approved member ids (desktop `_check_owner_sig`). */
    internal fun checkOwnerSig(ring: JsonValue): Set<String> {
        val o = obj(ring)
        val meta = obj(o["metadata"])
        val sig = (o["owner_sig"] as? JsonValue.Obj)?.fields
        if (sig == null || sig.keys != ownerSigFields) throw KeyringException("bad-fields", "owner_sig fields")
        val listed = (sig["members"] as? JsonValue.Arr)?.items
        val approved = listed?.map { str(it) }
        if (approved == null || approved.any { it == null } ||
            approved.filterNotNull() != approved.filterNotNull().toSortedSet { a, b -> Scalars.compare(a, b) }.toList()
        ) {
            throw KeyringException("bad-owner", "owner_sig members must be sorted, unique ids")
        }
        val ids = approved.filterNotNull()
        val byId = arr(o["members"]).associate { str(obj(it)["device_id"]) to obj(it) }
        val owner = byId[str(meta["owner"])]
        if (owner == null || owner["signing_public"] != meta["owner_key"]) {
            throw KeyringException("bad-owner", "the owner is not listed with its key")
        }
        if (str(meta["owner"]) !in ids || ids.any { d -> byId[d].let { it == null || it["signing_public"] == JsonValue.Null } }) {
            throw KeyringException("bad-owner", "owner_sig lists a member that is not in the keyring")
        }
        if (int(o["format"]) == SHARE_FORMAT && obj(obj(o["content"])["wraps"]).keys != ids.toSet()) {
            throw KeyringException("bad-content", "content wraps must match the approved members exactly")
        }
        val rawSig = Keyring.b64(sig["sig"], Keyring.PROOF_LEN, "owner_sig sig")
        val key = Keyring.b64(meta["owner_key"], 32, "owner_key")
        if (!DeviceIdentity.verify(rawSig, ownerMessage(o, ids), key)) {
            throw KeyringException("bad-owner-sig", "the owner's signature does not verify")
        }
        return ids.toSet()
    }

    /** Member ids the owner approved; null for a personal keyring. Call only on a verified keyring. */
    fun approvedMembers(ring: JsonValue): Set<String>? {
        val sig = obj(ring)["owner_sig"] ?: return null
        return arr(obj(sig)["members"]).mapNotNull { str(it) }.toSet()
    }

    /** What the owner signs (desktop `_owner_message`). */
    internal fun ownerMessage(ring: Map<String, JsonValue>, approved: List<String>): ByteArray {
        val byId = arr(ring["members"]).associate { str(obj(it)["device_id"]) to obj(it) }
        val roster = approved.sortedWith { a, b -> Scalars.compare(a, b) }.map { d ->
            val m = byId.getValue(d)
            JsonValue.Obj(
                mapOf(
                    "device_id" to JsonValue.Str(d),
                    "exchange_public" to (m["exchange_public"] ?: JsonValue.Null),
                    "signing_public" to (m["signing_public"] ?: JsonValue.Null),
                ),
            )
        }
        val fields = linkedMapOf(
            "group_id" to (ring["group_id"] ?: JsonValue.Null),
            "epoch" to (ring["epoch"] ?: JsonValue.Null),
            "metadata" to (ring["metadata"] ?: JsonValue.Null),
            "members" to JsonValue.Arr(roster),
        )
        if (int(ring["format"]) == SHARE_FORMAT) {
            // Share v2 also binds G (audit 2026-11-12 F-01): the content block, the KDF and password wrap, the approved
            // members' device wraps and the chain MAC, so a removed member holding the old G cannot reuse the signature.
            val dw = obj(ring["device_wraps"])
            val sortedIds = approved.sortedWith { a, b -> Scalars.compare(a, b) }
            fields["content"] = ring["content"] ?: JsonValue.Null
            fields["kdf"] = ring["kdf"] ?: JsonValue.Null
            fields["password_wrap"] = ring["password_wrap"] ?: JsonValue.Null
            fields["device_wraps"] = JsonValue.Obj(LinkedHashMap<String, JsonValue>().also { m -> for (d in sortedIds) m[d] = dw[d] ?: JsonValue.Null })
            fields["prev_mac"] = ring["prev_mac"] ?: JsonValue.Null
            return OWNER_SIG_LABEL_V2 + CanonicalJson.encode(JsonValue.Obj(fields), Dialect.UTF8)
        }
        return OWNER_SIG_LABEL + CanonicalJson.encode(JsonValue.Obj(fields), Dialect.UTF8)
    }

    // ---- the content key (share v2) ----

    /** `content.commit` of [ck]: SHA-256 over the label, group id | epoch | C. */
    internal fun contentCommit(ck: GroupKey): ByteArray = java.security.MessageDigest.getInstance("SHA-256").digest(
        CONTENT_COMMIT_LABEL + utf8(ck.groupId) + Keyring.BAR + Keyring.epochBytes(ck.epoch) + Keyring.BAR + ck.key,
    )

    /** The content wrap of [ck] for [deviceId] (its exchange key as base64 text). Draws eph (32), then nonce (12). */
    internal fun wrapContent(ck: GroupKey, deviceId: String, exchangePublic: String, random: RandomSource): JsonValue =
        Keyring.wrapDevice(
            ck, deviceId, Keyring.b64(JsonValue.Str(exchangePublic), 32, "exchange_public"), random,
            info = CONTENT_INFO, aadLabel = CONTENT_AAD,
        )

    /**
     * 1 for a share v1 keyring (items sealed with G), 2 for share v2 (format 3), null for a personal one (desktop
     * `share_version`). Call it only on a structurally verified keyring.
     */
    fun shareVersion(ring: JsonValue): Int? {
        val o = obj(ring)
        if ("metadata" !in o) return null
        return if (int(o["format"]) == SHARE_FORMAT) 2 else 1
    }

    /**
     * `GroupKey(group_id, epoch, C)` of share v2 [ring] from this device's content wrap (desktop `open_content_key`);
     * null when the owner has not wrapped C for this device (not approved yet). Reasons: `not-share-v2` for any other
     * keyring, `not-member` / `key-mismatch` (this device), `content-key` when the wrap does not open or opens a key other
     * than the committed one. Call it only on an accepted keyring.
     */
    fun openContentKey(ring: JsonValue, identity: DeviceIdentity): GroupKey? {
        val o = obj(ring)
        if (int(o["format"]) != SHARE_FORMAT || "content" !in o) throw KeyringException("not-share-v2", "this keyring has no content key")
        Keyring.member(ring, identity)
        val content = obj(o["content"])
        val wrap = obj(content["wraps"])[identity.deviceId] ?: return null
        val gid = str(o["group_id"]) ?: throw KeyringException("bad-fields", "keyring")
        val epoch = int(o["epoch"]) ?: throw KeyringException("bad-fields", "keyring")
        val w = obj(wrap)
        val plain = try {
            val shared = identity.exchange(Keyring.b64(w["eph"], 32, "eph"))
            val key = CryptoBox.hkdf(shared, utf8(gid), CONTENT_INFO + utf8(identity.deviceId), Keyring.KEY_LEN)
            val aad = CONTENT_AAD + utf8(gid) + Keyring.BAR + Keyring.epochBytes(epoch) + Keyring.BAR + utf8(identity.deviceId)
            CryptoBox.openGcm(key, Keyring.b64(w["nonce"], Keyring.NONCE_LEN, "nonce"), Keyring.b64(w["ct"], Keyring.WRAP_CT_LEN, "ct"), aad)
        } catch (e: Exception) {
            throw KeyringException("content-key", "the content wrap cannot be opened")
        }
        val ck = try {
            Keyring.groupKey(gid, epoch, plain)
        } catch (e: KeyringException) {
            throw KeyringException("content-key", "the content wrap cannot be opened")
        }
        val committed = try {
            Keyring.b64(content["commit"], 32, "content commit")
        } catch (e: KeyringException) {
            throw KeyringException("content-key", "the content commitment cannot be read")
        }
        if (!Keyring.constantTimeEqual(contentCommit(ck), committed)) {
            throw KeyringException("content-key", "the content key differs from the committed one")
        }
        return ck
    }

    /**
     * [body] without `mac`, with `owner_sig` by [identity] (the owner) approving [approve] (null: every listed member)
     * plus the owner itself. `not-owner` unless [identity] is the metadata's owner; `not-member` for an id not listed.
     *
     * A format-3 [body] also gets its `content` block for the content key [content] (`content-key` when missing): the
     * wraps it already holds for that C are kept, then [reuse] (the owner's own earlier wraps of this epoch), and every
     * other approved member gets a new wrap from [random], drawn in member id order (desktop `_sign_owner`).
     */
    internal fun signOwner(
        body: Map<String, JsonValue>,
        identity: DeviceIdentity,
        approve: Collection<String>?,
        content: GroupKey? = null,
        random: RandomSource? = null,
        reuse: Map<String, JsonValue>? = null,
    ): LinkedHashMap<String, JsonValue> {
        val meta = obj(body["metadata"])
        if (str(meta["owner"]) != identity.deviceId || str(meta["owner_key"]) != Base64Std.encode(identity.signingPublicKey)) {
            throw KeyringException("not-owner", "only the owner changes a share group")
        }
        val out = LinkedHashMap(body)
        out.remove("mac")
        out.remove("owner_sig")
        val listed = arr(out["members"]).mapNotNull { str(obj(it)["device_id"]) }.toSet()
        val chosen = if (approve == null) listed else approve.toSet() + identity.deviceId
        if (!listed.containsAll(chosen)) throw KeyringException("not-member", "an approved device is not a member")
        val approved = chosen.sortedWith { a, b -> Scalars.compare(a, b) }
        if (int(out["format"]) == SHARE_FORMAT) {
            if ("prev_mac" !in out) throw KeyringException("bad-fields", "set prev_mac before the owner signs a share v2 keyring")
            if (content == null) throw KeyringException("content-key", "a share v2 keyring needs its content key")
            val commit = JsonValue.Str(Base64Std.encode(contentCommit(content)))
            val old = out["content"] as? JsonValue.Obj
            val have = if (old != null && old.fields["commit"] == commit) obj(old.fields["wraps"]) else emptyMap()
            val byId = arr(out["members"]).associate { str(obj(it)["device_id"]) to obj(it) }
            val wraps = LinkedHashMap<String, JsonValue>()
            for (d in approved) {
                wraps[d] = have[d] ?: reuse?.get(d) ?: run {
                    val rnd = random ?: throw KeyringException("bad-random", "a new content wrap needs a random source")
                    wrapContent(content, d, str(byId[d]?.get("exchange_public")) ?: "", rnd)
                }
            }
            out["content"] = JsonValue.Obj(mapOf("commit" to commit, "wraps" to JsonValue.Obj(wraps)))
        }
        val sig = identity.sign(ownerMessage(out, approved))
        out["owner_sig"] = JsonValue.Obj(
            mapOf(
                "members" to JsonValue.Arr(approved.map { JsonValue.Str(it) }),
                "sig" to JsonValue.Str(Base64Std.encode(sig)),
            ),
        )
        return out
    }

    // ---- the collection name ----

    private fun nameKey(gk: GroupKey): ByteArray =
        CryptoBox.hkdf(gk.key, utf8(gk.groupId), NAME_INFO + Keyring.epochBytes(gk.epoch), Keyring.KEY_LEN)

    private fun nameAad(gk: GroupKey, collectionId: String): ByteArray =
        NAME_AAD + utf8(gk.groupId) + Keyring.BAR + Keyring.epochBytes(gk.epoch) + Keyring.BAR + utf8(collectionId)

    /** `name_ct` of [name] for [collectionId] under [gk]. Draws the 12-byte nonce. */
    internal fun sealName(gk: GroupKey, collectionId: String, name: String, random: RandomSource): String {
        val plain = MemberNames.strictEncode(checkShareName(name))!!
        val nonce = Keyring.draw(random, Keyring.NONCE_LEN)
        return Base64Std.encode(nonce + CryptoBox.sealGcm(nameKey(gk), nonce, plain, nameAad(gk, collectionId)))
    }

    /** The collection name of an accepted share keyring at [gk]'s epoch; `bad-metadata` when it cannot be read. */
    fun shareName(ring: JsonValue, gk: GroupKey): String {
        val meta = checkMetadata(obj(ring)["metadata"])
        val raw = Keyring.b64any(meta["name_ct"], "metadata name_ct")
        val plain = try {
            CryptoBox.openGcm(nameKey(gk), raw.copyOfRange(0, Keyring.NONCE_LEN), raw.copyOfRange(Keyring.NONCE_LEN, raw.size),
                nameAad(gk, str(meta["collection_id"])!!))
        } catch (e: Exception) {
            throw KeyringException("bad-metadata", "the collection name cannot be read")
        }
        val name = MemberNames.strictUtf8(plain) ?: throw KeyringException("bad-metadata", "the collection name cannot be read")
        if (Scalars.count(name) !in 1..MAX_NAME_LEN || PyStrip.strip(name) != name) {
            throw KeyringException("bad-metadata", "the collection name is malformed")
        }
        return name
    }

    // ---- reading ----

    /**
     * Parse a keyring a share flow reads (strict, structure and owner signature verified). A personal keyring parses
     * too: [requireShare] refuses it.
     */
    fun parse(data: ByteArray): JsonValue = KeyringParse.parse(data, share = true)

    /** `not-share` for a device-sync keyring (desktop `join_share_group`). */
    fun requireShare(ring: JsonValue): Map<String, JsonValue> =
        metadata(ring) ?: throw KeyringException("not-share", "that keyring is device sync, not a shared collection")

    /** Sorted member ids. */
    fun memberIds(ring: JsonValue): List<String> =
        arr(obj(ring)["members"]).mapNotNull { str(obj(it)["device_id"]) }.sortedWith { a, b -> Scalars.compare(a, b) }

    /** Members the owner has not approved, never [own] (desktop `_pending`). */
    fun pending(ring: JsonValue, own: String): List<String> {
        val approved = approvedMembers(ring) ?: emptySet()
        return memberIds(ring).filter { it !in approved && it != own }
    }

    // ---- writers ----

    /**
     * A new share group (epoch 1) owned by [identity] (desktop `create_group(metadata=)`): share v2 (format 3). Draw
     * order as [KeyringRotate.create], then the name nonce (12), then C (32) and the owner's content wrap (eph 32, nonce
     * 12). Reasons: `bad-metadata`, `weak-password`, `bad-device-id`, `bad-name`, `bad-fields`.
     */
    fun create(
        password: String,
        identity: DeviceIdentity,
        name: String,
        spec: Spec,
        random: RandomSource,
        addedAt: Long,
        strong: (String) -> Boolean,
    ): Pair<JsonValue, GroupKey> =
        KeyringRotate.create(password, identity, name, random, addedAt, strong, KeyringRotate.productionKdf, spec, SHARE_FORMAT)

    /** [create] with the Argon2id step injected; [shareFormat] [LEGACY_SHARE_FORMAT] writes share v1 (legacy vectors only). */
    internal fun create(
        password: String,
        identity: DeviceIdentity,
        name: String,
        spec: Spec,
        random: RandomSource,
        addedAt: Long,
        strong: (String) -> Boolean,
        derive: KeyringRotate.KeyDerivation,
        shareFormat: Long = SHARE_FORMAT,
    ): Pair<JsonValue, GroupKey> = KeyringRotate.create(password, identity, name, random, addedAt, strong, derive, spec, shareFormat)

    /**
     * Join a share by its password: `not-share` for a device-sync keyring, then the [Keyring.join] reasons. The new
     * member is pending until the owner approves it. Pin the result with [Pin.of].
     */
    fun join(
        ring: JsonValue,
        password: String,
        identity: DeviceIdentity,
        name: String,
        random: RandomSource,
        now: UnixClock,
    ): Pair<JsonValue, GroupKey> {
        KeyringParse.verifyStructure(ring, share = true)
        requireShare(ring)
        return KeyringJoin.join(ring, identity, name, random, now, share = true) { Keyring.passwordKey(ring, password) }
    }

    internal fun join(
        ring: JsonValue,
        passwordKey: ByteArray,
        identity: DeviceIdentity,
        name: String,
        random: RandomSource,
        now: UnixClock,
    ): Pair<JsonValue, GroupKey> {
        KeyringParse.verifyStructure(ring, share = true)
        requireShare(ring)
        return KeyringJoin.join(ring, identity, name, random, now, share = true) { passwordKey }
    }

    /** Authenticate a share keyring against the trusted key (structure, owner signature, MAC, chain). */
    fun accept(ring: JsonValue, trusted: GroupKey, identity: DeviceIdentity): GroupKey =
        KeyringAccept.accept(ring, trusted, identity, share = true)

    /**
     * The owner approves [approve] (null: every member) at the trusted epoch (desktop `owner_approve_members`). Same
     * epoch, key, metadata and device wraps; only `owner_sig` and `mac` change (and, share v2, `content`: the owner opens
     * C from its own content wrap and wraps it to each newly approved member in id order from [random]; [reuseWraps], the
     * `content` block of the owner's own stored keyring of this epoch, gives the wraps it already made, so a merge grows
     * from that keyring). Reasons: the [accept] ones, `stale-trust`, `not-share`, `not-member` / `key-mismatch` (this
     * device), `not-owner`, `content-key`, `not-member` (an approved id).
     */
    fun approve(
        ring: JsonValue,
        trusted: GroupKey,
        identity: DeviceIdentity,
        approve: Collection<String>?,
        random: RandomSource = SystemRandomSource(),
        reuseWraps: JsonValue? = null,
    ): JsonValue {
        val gk = accept(ring, trusted, identity)
        if (gk.epoch != trusted.epoch) throw KeyringException("stale-trust", "adopt the current keyring first")
        val meta = requireShare(ring)
        Keyring.member(ring, identity)
        if (str(meta["owner"]) != identity.deviceId || str(meta["owner_key"]) != Base64Std.encode(identity.signingPublicKey)) {
            throw KeyringException("not-owner", "only the owner changes a share group")
        }
        val chosen = approve?.let { (approvedMembers(ring) ?: emptySet()) + it }
        var content: GroupKey? = null
        var reuse: Map<String, JsonValue>? = null
        if (int(obj(ring)["format"]) == SHARE_FORMAT) {
            content = openContentKey(ring, identity) ?: throw KeyringException("content-key", "the owner has no content wrap")
            val r = (reuseWraps as? JsonValue.Obj)?.fields
            if (r != null && r["commit"] == obj(obj(ring)["content"])["commit"]) reuse = (r["wraps"] as? JsonValue.Obj)?.fields
        }
        return Keyring.finish(signOwner(obj(ring), identity, chosen, content, random, reuse), gk)
    }

    /**
     * The owner approves pending members it showed by name (desktop `approve_members`): `not-pending` for an empty
     * choice or an id that is not pending in [ring], else [approve].
     */
    fun approvePending(
        ring: JsonValue,
        trusted: GroupKey,
        identity: DeviceIdentity,
        deviceIds: Collection<String>,
        random: RandomSource = SystemRandomSource(),
    ): JsonValue {
        val pending = pending(ring, identity.deviceId).toSet()
        if (deviceIds.isEmpty() || !pending.containsAll(deviceIds)) {
            throw KeyringException("not-pending", "approve only members that are waiting")
        }
        return approve(ring, trusted, identity, deviceIds, random)
    }

    /**
     * The owner rotates (new key, epoch + 1, a NEW share password), dropping [remove] (desktop `rotate` +
     * `remove_member`: pass the removed member and every unapproved one). The name is re-sealed. A share v1 keyring
     * approves every remaining member; a share v2 one (or [upgrade] of a share v1 one) keeps the previous approvals minus
     * the removed devices and draws a new content key. Reasons: as [Keyring.rotate], then `not-owner`.
     */
    fun rotate(
        ring: JsonValue,
        trusted: GroupKey,
        identity: DeviceIdentity,
        newPassword: String,
        remove: Collection<String>,
        random: RandomSource,
        strong: (String) -> Boolean,
        upgrade: Boolean = false,
    ): Pair<JsonValue, GroupKey> =
        KeyringRotate.rotate(ring, trusted, identity, newPassword, remove, random, strong, KeyringRotate.productionKdf, share = true, upgrade = upgrade)

    internal fun rotate(
        ring: JsonValue,
        trusted: GroupKey,
        identity: DeviceIdentity,
        newPassword: String,
        remove: Collection<String>,
        random: RandomSource,
        strong: (String) -> Boolean,
        derive: KeyringRotate.KeyDerivation,
        upgrade: Boolean = false,
    ): Pair<JsonValue, GroupKey> =
        KeyringRotate.rotate(ring, trusted, identity, newPassword, remove, random, strong, derive, share = true, upgrade = upgrade)

    /**
     * The owner upgrades share v1 [ring] to share v2 (desktop `upgrade_share_keyring`): a rotation to epoch + 1 that
     * removes nobody; a new G and a content key C wrapped to the members already approved (pending ones stay pending).
     * [password] is the share password of the new epoch: the current one may be kept (it no longer opens any item); it
     * must pass [strong]. Reasons: `not-share`, `already-v2`, then the [rotate] ones (`not-owner`...).
     */
    fun upgrade(
        ring: JsonValue,
        trusted: GroupKey,
        identity: DeviceIdentity,
        password: String,
        random: RandomSource,
        strong: (String) -> Boolean,
    ): Pair<JsonValue, GroupKey> = upgrade(ring, trusted, identity, password, random, strong, KeyringRotate.productionKdf)

    internal fun upgrade(
        ring: JsonValue,
        trusted: GroupKey,
        identity: DeviceIdentity,
        password: String,
        random: RandomSource,
        strong: (String) -> Boolean,
        derive: KeyringRotate.KeyDerivation,
    ): Pair<JsonValue, GroupKey> {
        val o = obj(ring)
        if ("metadata" !in o) throw KeyringException("not-share", "a personal keyring has no share version")
        if (int(o["format"]) == SHARE_FORMAT) throw KeyringException("already-v2", "this share is already share v2")
        return KeyringRotate.rotate(
            ring, trusted, identity, password, emptyList(), random, strong, derive, share = true, upgrade = true, allowSamePassword = true,
        )
    }

    /** What [removeMember] returns: the rotated keyring and key, and the owner's signed notice to write to `removed/`. */
    class Removed(val keyring: JsonValue, val key: GroupKey, val notice: ByteArray, val dropped: List<String>) {
        override fun toString(): String = "ShareKeyring.Removed(epoch=${key.epoch}, dropped=${dropped.size})"
    }

    /**
     * The owner removes [deviceId] (desktop `share_group.remove_member`; works without Pro): a rotation with a NEW share
     * password (the removed person knows the old one) that also drops every member the owner never approved (they get no
     * notice), and the owner-signed notice naming this share group only. A share v1 group is upgraded to share v2 in the
     * same rotation (a new content key for the others; [upgrade] false only for the legacy share v1 vectors). `not-owner`
     * on any other device, `not-member` for a bad id, then the [rotate] reasons.
     */
    fun removeMember(
        ring: JsonValue,
        trusted: GroupKey,
        identity: DeviceIdentity,
        deviceId: String,
        newPassword: String,
        random: RandomSource,
        strong: (String) -> Boolean,
        issuedAt: Long,
    ): Removed = removeMember(ring, trusted, identity, deviceId, newPassword, random, strong, issuedAt, KeyringRotate.productionKdf)

    internal fun removeMember(
        ring: JsonValue,
        trusted: GroupKey,
        identity: DeviceIdentity,
        deviceId: String,
        newPassword: String,
        random: RandomSource,
        strong: (String) -> Boolean,
        issuedAt: Long,
        derive: KeyringRotate.KeyDerivation,
        upgrade: Boolean = true,
    ): Removed {
        val pin = Pin.of(ring)
        if (pin.owner != identity.deviceId) throw KeyringException("not-owner", "only the person who shared the collection does this")
        if (!Identifier.isValid(deviceId)) throw KeyringException("not-member", "invalid device id")
        val drop = listOf(deviceId) + pending(ring, identity.deviceId).filter { it != deviceId }
        val (rotated, key) = KeyringRotate.rotate(ring, trusted, identity, newPassword, drop, random, strong, derive, share = true, upgrade = upgrade)
        val notice = app.localgatekeys.core.sync.Removal.makeNotice(identity, trusted.groupId, deviceId, key.epoch, issuedAt)
        return Removed(rotated, key, notice, drop)
    }

    /** The share password rule (the sync password rule: 12+ characters, strength 3+). */
    fun isStrongPassword(password: String, strength: StrengthEstimator): Boolean = KeyringRotate.isStrong(password, strength)

    // ---- adopting ----

    /**
     * At one epoch a share keyring may only grow (desktop `_check_same_epoch_growth`): `tampered` for anything else.
     * Fixed: format, group, epoch, kdf, password wrap, metadata, prev_mac; the old members an unchanged prefix; every
     * old device wrap unchanged; the approved roster a superset.
     */
    fun checkSameEpochGrowth(old: JsonValue, new: JsonValue) {
        val o = obj(old)
        val n = obj(new)
        if (sameEpochFixed.any { o[it] != n[it] }) throw KeyringException("tampered", "a share keyring changed within its epoch")
        val om = arr(o["members"])
        val nm = arr(n["members"])
        if (nm.size < om.size || nm.subList(0, om.size) != om) {
            throw KeyringException("tampered", "a share keyring dropped or changed a member within its epoch")
        }
        val nw = obj(n["device_wraps"])
        if (obj(o["device_wraps"]).any { (d, w) -> nw[d] != w }) {
            throw KeyringException("tampered", "a share keyring changed a device wrap within its epoch")
        }
        if (!(approvedMembers(new) ?: emptySet()).containsAll(approvedMembers(old) ?: emptySet())) {
            throw KeyringException("tampered", "a share keyring un-approved a member within its epoch")
        }
        // Share v2: the content commitment is fixed and no content wrap changes or disappears.
        val oc = o["content"]
        val nc = n["content"]
        if ((oc == null) != (nc == null)) throw KeyringException("tampered", "a share keyring changed its version within its epoch")
        if (oc != null && nc != null) {
            val nWraps = obj(obj(nc)["wraps"])
            if (obj(oc)["commit"] != obj(nc)["commit"] || obj(obj(oc)["wraps"]).any { (d, w) -> nWraps[d] != w }) {
                throw KeyringException("tampered", "a share keyring changed its content key or a content wrap within its epoch")
            }
        }
    }

    /** Whether [new] is a later state of [old] (a later epoch, or growth within one); desktop `grows_from`. */
    fun growsFrom(old: JsonValue, new: JsonValue): Boolean {
        val o = obj(old)
        val n = obj(new)
        if (o["group_id"] == null || o["group_id"] != n["group_id"]) return false
        val oe = int(o["epoch"])
        val ne = int(n["epoch"])
        if (oe != null && ne != null && oe < ne) return true
        if (o["epoch"] != n["epoch"] || old == new) return false
        return try {
            checkSameEpochGrowth(old, new)
            true
        } catch (e: KeyringException) {
            false
        }
    }

    private fun checkPinned(ring: JsonValue, pin: Pin) {
        val m = metadata(ring)
        if (m == null || Pin.of(ring) != pin) {
            throw KeyringException("tampered", "the keyring changes the share's owner, collection or mode")
        }
    }

    /**
     * Accept a newer keyring of a share this device is in (desktop `adopt_keyring`): [stored] is the last accepted
     * keyring at [trusted]'s epoch, [pin] what this device pinned. Returns the key to keep (same or next epoch).
     * Reasons in order: the [accept] ones, `tampered` (pinned facts), `tampered` (same-epoch growth), `removed`.
     */
    fun adopt(stored: JsonValue, candidate: JsonValue, trusted: GroupKey, identity: DeviceIdentity, pin: Pin): GroupKey {
        val gk = accept(candidate, trusted, identity)
        checkPinned(candidate, pin)
        if (gk.epoch == trusted.epoch) checkSameEpochGrowth(stored, candidate)
        if (identity.deviceId !in memberIds(candidate)) throw KeyringException("removed", "this device is no longer in the share group")
        return gk
    }

    /**
     * Owner only (desktop `reconcile_owner_keyring`): the owner's stored approvals re-signed onto a same-epoch folder
     * keyring that someone else grew meanwhile, when the result grows from [stored]; null for anything else.
     */
    fun reconcileOwner(
        stored: JsonValue,
        folder: JsonValue,
        trusted: GroupKey,
        identity: DeviceIdentity,
        pin: Pin,
        random: RandomSource = SystemRandomSource(),
    ): JsonValue? {
        if (pin.owner != identity.deviceId) return null
        return try {
            val f = obj(folder)
            if (f["group_id"] != JsonValue.Str(trusted.groupId) || f["epoch"] != JsonValue.Int(trusted.epoch)) return null
            // Share v2: the owner's stored content wraps are reused, so the result still grows from the stored keyring.
            val ring = approve(folder, trusted, identity, approvedMembers(stored) ?: emptySet(), random, obj(stored)["content"])
            checkPinned(ring, pin)
            checkSameEpochGrowth(stored, ring)
            ring
        } catch (e: KeyringException) {
            null
        }
    }

    /**
     * A member's join lost to someone else's join at the same moment (desktop `superseded_join`): the folder keyring
     * authenticates at the stored epoch, no longer lists this device, and grows from [stored] minus this device's own
     * last entry and wrap. The user joins again; anything else stays `tampered`.
     */
    fun supersededJoin(stored: JsonValue, folder: JsonValue, trusted: GroupKey, identity: DeviceIdentity, pin: Pin): Boolean {
        if (pin.owner == identity.deviceId) return false
        return try {
            val f = obj(folder)
            if (f["group_id"] != JsonValue.Str(trusted.groupId) || f["epoch"] != JsonValue.Int(trusted.epoch)) return false
            accept(folder, trusted, identity)
            val own = identity.deviceId
            if (own in memberIds(folder)) return false
            val s = obj(stored)
            val members = arr(s["members"])
            if (members.isEmpty() || str(obj(members.last())["device_id"]) != own) return false
            val base = LinkedHashMap(s)
            base["members"] = JsonValue.Arr(members.dropLast(1))
            base["device_wraps"] = JsonValue.Obj(obj(s["device_wraps"]).filterKeys { it != own })
            checkSameEpochGrowth(JsonValue.Obj(base), folder)
            true
        } catch (e: KeyringException) {
            false
        }
    }

    /**
     * Whether [folder] is a later epoch of this share signed by the pinned owner key (desktop `_owner_signed_ahead`). Only
     * the owner's own device can make one, so an owner's device that trusts an older epoch (its vault went back) never
     * writes that older keyring over it.
     */
    fun ownerSignedAhead(folder: JsonValue, trusted: GroupKey, pin: Pin): Boolean = try {
        val f = obj(folder)
        val epoch = int(f["epoch"])
        if (f["group_id"] != JsonValue.Str(trusted.groupId) || epoch == null || epoch <= trusted.epoch) {
            false
        } else {
            KeyringParse.verifyStructure(folder, share = true) // the owner signature included
            metadata(folder) != null && Pin.of(folder) == pin
        }
    } catch (e: Exception) {
        false
    }

    /**
     * Whether [folder] (at the trusted epoch) has a valid MAC under the trusted key and the pinned owner's signature
     * (desktop `_authenticates_at_epoch`).
     */
    fun authenticatesAtEpoch(folder: JsonValue, trusted: GroupKey, identity: DeviceIdentity, pin: Pin): Boolean = try {
        accept(folder, trusted, identity)
        val m = metadata(folder)
        m != null && str(m["owner"]) == pin.owner && str(m["owner_key"]) == pin.ownerKey
    } catch (e: Exception) {
        false
    }
}
