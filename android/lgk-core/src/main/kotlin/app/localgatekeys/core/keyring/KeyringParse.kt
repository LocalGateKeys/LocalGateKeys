package app.localgatekeys.core.keyring

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring.b64
import app.localgatekeys.core.keyring.Keyring.b64any
import app.localgatekeys.core.keyring.Keyring.int
import app.localgatekeys.core.keyring.Keyring.str
import app.localgatekeys.core.primitives.Identifier

internal object KeyringParse {
    private val topFields = setOf("format", "group_id", "epoch", "kdf", "password_wrap", "device_wraps", "members", "prev_mac", "mac")
    private val kdfFields = setOf("name", "salt", "memory_kib", "iterations", "parallelism")
    private val pwWrapFields = setOf("nonce", "ct")
    private val devWrapFields = setOf("eph", "nonce", "ct")
    private val memberFields = setOf("device_id", "name_ct", "exchange_public", "added_at")

    /** Parse strictly (size, UTF-8, duplicate keys, non-finite numbers), then verify the structure. */
    fun parse(data: ByteArray): JsonValue {
        if (data.size > Keyring.MAX_KEYRING_BYTES) {
            throw KeyringException("too-large", "${data.size} > ${Keyring.MAX_KEYRING_BYTES}")
        }
        val value = try {
            CanonicalJson.parse(data)
        } catch (e: Exception) {
            throw KeyringException("bad-json", "keyring is not valid JSON")
        }
        if (value !is JsonValue.Obj) throw KeyringException("bad-keyring", "keyring must be an object")
        verifyStructure(value)
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

    /** Shape, bounds, KDF parameters and wrap/member sets; no authentication. Same check order as the desktop. */
    fun verifyStructure(keyring: JsonValue) {
        val ring = fields(keyring, topFields, "keyring fields")
        if (int(ring["format"]) != Keyring.FORMAT) throw KeyringException("bad-format", "unsupported keyring format")
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
            val mo = fields(m, memberFields, "member fields")
            val id = str(mo["device_id"])
            if (id == null || !Identifier.isValid(id)) throw KeyringException("bad-device-id", "member device_id")
            if (!ids.add(id)) throw KeyringException("duplicate-member", "member device ids must be unique")
            if (b64any(mo["name_ct"], "member name_ct").size !in Keyring.NAME_CT_MIN..Keyring.NAME_CT_MAX) {
                throw KeyringException("bad-name", "member name_ct must be 29..92 bytes")
            }
            if (!isInt(mo["added_at"])) throw KeyringException("bad-fields", "member added_at")
            b64(mo["exchange_public"], 32, "member exchange_public")
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
    }
}
