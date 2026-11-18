package app.localgatekeys.core.keyring

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring.b64
import app.localgatekeys.core.keyring.Keyring.b64any
import app.localgatekeys.core.keyring.Keyring.int
import app.localgatekeys.core.keyring.Keyring.str
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Identifier

internal object KeyringParse {
    private val topFields = setOf("format", "group_id", "epoch", "kdf", "password_wrap", "device_wraps", "members", "prev_mac", "mac")
    private val kdfFields = setOf("name", "salt", "memory_kib", "iterations", "parallelism")
    private val pwWrapFields = setOf("nonce", "ct")
    private val devWrapFields = setOf("eph", "nonce", "ct")
    private val memberFieldsV1 = setOf("device_id", "name_ct", "exchange_public", "added_at")
    private val memberFields = memberFieldsV1 + setOf("signing_public", "signing_proof")

    /** The top-level fields only a share keyring has (sub-plan 07, desktop `_SHARE_TOP_FIELDS`). */
    val shareTopFields = setOf("metadata", "owner_sig")

    /**
     * Parse strictly (size, UTF-8, duplicate keys, non-finite numbers), then verify the structure. [share]: a share
     * keyring (metadata and owner signature) is accepted; without it one is refused as `share-group` (a device-sync
     * flow must never adopt a shared collection's keyring, desktop `join_folder_group`).
     */
    fun parse(data: ByteArray, share: Boolean = false): JsonValue {
        if (data.size > Keyring.MAX_KEYRING_BYTES) {
            throw KeyringException("too-large", "${data.size} > ${Keyring.MAX_KEYRING_BYTES}")
        }
        val value = try {
            CanonicalJson.parse(data)
        } catch (e: Exception) {
            throw KeyringException("bad-json", "keyring is not valid JSON")
        }
        if (value !is JsonValue.Obj) throw KeyringException("bad-keyring", "keyring must be an object")
        verifyStructure(value, share)
        return value
    }

    private fun fields(v: JsonValue?, expected: Set<String>, what: String): Map<String, JsonValue> {
        if (v !is JsonValue.Obj || v.fields.keys != expected) throw KeyringException("bad-fields", what)
        return v.fields
    }

    private fun isInt(v: JsonValue?, min: Long = 0): Boolean {
        val i = int(v) ?: return false
        return i >= min && i <= Keyring.MAX_INT
    }

    /** Whether [keyring] carries a share field (desktop: `_SHARE_TOP_FIELDS & set(keyring)`). */
    fun isShare(keyring: JsonValue): Boolean = (keyring as? JsonValue.Obj)?.fields?.keys?.any { it in shareTopFields } == true

    /**
     * Shape, bounds, KDF parameters and wrap/member sets; no authentication. Same check order as the desktop. A share
     * keyring ([share] true) also has its `metadata` checked and its `owner_sig` verified (the last step); with [share]
     * false it is refused as `share-group` before anything else.
     */
    fun verifyStructure(keyring: JsonValue, share: Boolean = false) {
        if (isNewerFormat(keyring)) throw KeyringException("newer-format", "this keyring needs a newer version of the app")
        val isShare = isShare(keyring)
        if (isShare && !share) throw KeyringException("share-group", "this keyring belongs to a shared collection")
        // Share v2 (format 3): a share keyring with the `content` block (desktop `verify_keyring_structure`).
        val v2 = int((keyring as? JsonValue.Obj)?.fields?.get("format")) == ShareKeyring.SHARE_FORMAT
        val expected = if (isShare) topFields + shareTopFields else topFields
        val ring = fields(keyring, if (v2) expected + CONTENT else expected, "keyring fields")
        val format = int(ring["format"])
        if (format == null || format !in Keyring.READ_FORMATS) throw KeyringException("bad-format", "unsupported keyring format")
        if (v2 && !isShare) throw KeyringException("bad-fields", "a format-3 keyring is a share keyring")
        if (isShare) {
            if (format < 2) throw KeyringException("bad-fields", "a format-1 keyring has no share fields")
            ShareKeyring.checkMetadata(ring["metadata"])
        }
        val wantMember = if (format >= 2) memberFields else memberFieldsV1
        val gid = str(ring["group_id"])
        if (gid == null || !Identifier.isValid(gid)) throw KeyringException("bad-group-id", "group_id")
        if (!isInt(ring["epoch"], 1)) throw KeyringException("bad-epoch", "epoch")
        val epoch = int(ring["epoch"])!!

        val kdf = fields(ring["kdf"], kdfFields, "kdf fields")
        if (str(kdf["name"]) != Keyring.KDF_NAME) throw KeyringException("bad-kdf", "unsupported kdf")
        for ((name, want) in listOf(
            "memory_kib" to Keyring.KDF_MEMORY_KIB,
            "iterations" to Keyring.KDF_ITERATIONS,
            "parallelism" to Keyring.KDF_PARALLELISM,
        )) {
            if (int(kdf[name]) != want) throw KeyringException("bad-kdf", "$name differs from the format parameters")
        }
        b64(kdf["salt"], Keyring.KDF_SALT_LEN, "kdf salt")

        val pw = fields(ring["password_wrap"], pwWrapFields, "password_wrap fields")
        b64(pw["nonce"], Keyring.NONCE_LEN, "password_wrap nonce")
        b64(pw["ct"], Keyring.WRAP_CT_LEN, "password_wrap ct")

        val members = (ring["members"] as? JsonValue.Arr)?.items
        if (members == null || members.isEmpty()) throw KeyringException("bad-members", "members must be a non-empty list")
        if (members.size > Keyring.MAX_MEMBERS) throw KeyringException("too-many-members", "members must have at most 16 entries")
        val ids = HashSet<String>()
        for (m in members) {
            val mo = fields(m, wantMember, "member fields")
            val id = str(mo["device_id"])
            if (id == null || !Identifier.isValid(id)) throw KeyringException("bad-device-id", "member device_id")
            if (!ids.add(id)) throw KeyringException("duplicate-member", "member device ids must be unique")
            if (b64any(mo["name_ct"], "member name_ct").size !in Keyring.NAME_CT_MIN..Keyring.NAME_CT_MAX) {
                throw KeyringException("bad-name", "member name_ct must be 29..92 bytes")
            }
            if (!isInt(mo["added_at"])) throw KeyringException("bad-fields", "member added_at")
            b64(mo["exchange_public"], 32, "member exchange_public")
            if (format >= 2) checkMemberProof(gid, mo)
        }

        val wraps = (ring["device_wraps"] as? JsonValue.Obj)?.fields
        if (wraps == null || wraps.keys != ids) throw KeyringException("wrap-mismatch", "device_wraps must match members exactly")
        for (key in wraps.keys.sorted()) {
            val w = fields(wraps[key], devWrapFields, "device wrap fields")
            b64(w["eph"], 32, "device wrap eph")
            b64(w["nonce"], Keyring.NONCE_LEN, "device wrap nonce")
            b64(w["ct"], Keyring.WRAP_CT_LEN, "device wrap ct")
        }

        if (epoch == 1L) {
            if (ring["prev_mac"] != JsonValue.Null) throw KeyringException("bad-fields", "prev_mac must be null at epoch 1")
        } else if (ring["prev_mac"] != JsonValue.Null) {
            b64(ring["prev_mac"], Keyring.MAC_LEN, "prev_mac")
        }
        b64(ring["mac"], Keyring.MAC_LEN, "mac")
        if (v2) checkContentShape(ring[CONTENT])
        if (isShare) ShareKeyring.checkOwnerSig(keyring)
    }

    private const val CONTENT = "content"
    private val contentFields = setOf("commit", "wraps")

    /** Whether [keyring]'s `format` is an integer above every format this version reads (desktop `newer-format`). */
    fun isNewerFormat(keyring: JsonValue): Boolean {
        val format = int((keyring as? JsonValue.Obj)?.fields?.get("format")) ?: return false
        return format > Keyring.READ_FORMATS.max()
    }

    /** Desktop `_check_content_shape`: `{commit, wraps:{device_id:{eph, nonce, ct}}}` with the wrap lengths. */
    private fun checkContentShape(content: JsonValue?) {
        val c = fields(content, contentFields, "content fields")
        b64(c["commit"], 32, "content commit")
        val wraps = (c["wraps"] as? JsonValue.Obj)?.fields ?: throw KeyringException("bad-content", "content wraps must be an object")
        for ((deviceId, wrap) in wraps) {
            if (!Identifier.isValid(deviceId)) throw KeyringException("bad-content", "content wrap device id")
            val w = fields(wrap, devWrapFields, "content wrap fields")
            b64(w["eph"], 32, "content wrap eph")
            b64(w["nonce"], Keyring.NONCE_LEN, "content wrap nonce")
            b64(w["ct"], Keyring.WRAP_CT_LEN, "content wrap ct")
        }
    }

    /** `_check_member_proof`: `signing_public` and `signing_proof` both null, or a key with its member's valid proof. */
    private fun checkMemberProof(groupId: String, m: Map<String, JsonValue>) {
        val key = m["signing_public"]
        val proof = m["signing_proof"]
        if (key == JsonValue.Null && proof == JsonValue.Null) return
        if (key == JsonValue.Null || proof == JsonValue.Null) {
            throw KeyringException("bad-member-proof", "signing_public and signing_proof must both be set or both null")
        }
        val rawKey = b64(key, 32, "member signing_public")
        val rawProof = b64(proof, Keyring.PROOF_LEN, "member signing_proof")
        val message = Keyring.proofMessage(groupId, str(m["device_id"])!!, str(m["exchange_public"])!!, str(key)!!)
        if (!DeviceIdentity.verify(rawProof, message, rawKey)) {
            throw KeyringException("bad-member-proof", "member ${str(m["device_id"])}: signing proof does not verify")
        }
    }
}
