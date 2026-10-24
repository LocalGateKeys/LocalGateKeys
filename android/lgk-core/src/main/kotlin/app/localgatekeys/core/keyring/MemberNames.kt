package app.localgatekeys.core.keyring

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring.arr
import app.localgatekeys.core.keyring.Keyring.obj
import app.localgatekeys.core.keyring.Keyring.str
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.RandomSource
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

internal object MemberNames {
    private fun nameAad(groupId: String, epoch: Long, deviceId: String): ByteArray =
        Keyring.NAME_AAD + groupId.toByteArray(Charsets.UTF_8) + Keyring.BAR + Keyring.epochBytes(epoch) +
            Keyring.BAR + deviceId.toByteArray(Charsets.UTF_8)

    /**
     * Strict UTF-8 encode: a lone UTF-16 surrogate is refused (null) instead of silently becoming `?`,
     * like Python's `str.encode("utf-8")` (Swift strings cannot hold one).
     */
    private fun strictEncode(name: String): ByteArray? = try {
        val buf = Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .encode(CharBuffer.wrap(name))
        ByteArray(buf.remaining()).also { buf.get(it) }
    } catch (e: CharacterCodingException) {
        null
    }

    /** 1..64 UTF-8 bytes, strictly encodable (no lone surrogate). */
    fun checkName(name: String): String {
        val bytes = strictEncode(name) ?: throw KeyringException("bad-name", "device name is not valid Unicode text")
        if (bytes.size !in 1..Keyring.MAX_NAME_LEN) {
            throw KeyringException("bad-name", "device name must be 1..64 UTF-8 bytes")
        }
        return name
    }

    /** Strict UTF-8 decode (rejects overlongs, surrogates, truncation), like Python's `bytes.decode("utf-8")`. */
    fun strictUtf8(bytes: ByteArray): String? = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
    } catch (e: CharacterCodingException) {
        null
    }

    /** `name_ct` for [deviceId] at [gk]'s epoch. Draws the 12-byte nonce. */
    fun sealName(gk: GroupKey, deviceId: String, name: String, random: RandomSource): String {
        val plain = strictEncode(checkName(name))!!
        val nonce = Keyring.draw(random, Keyring.NONCE_LEN)
        val ct = CryptoBox.sealGcm(
            Keyring.nameKey(gk), nonce, plain, nameAad(gk.groupId, gk.epoch, deviceId),
        )
        return Base64Std.encode(nonce + ct)
    }

    private fun openName(key: ByteArray, gk: GroupKey, deviceId: JsonValue?, value: JsonValue?): String? {
        val id = str(deviceId)
        if (id == null || !Identifier.isValid(id)) return null
        return try {
            val raw = Keyring.b64any(value, "member name_ct")
            if (raw.size !in Keyring.NAME_CT_MIN..Keyring.NAME_CT_MAX) return null
            val plain = CryptoBox.openGcm(
                key, raw.copyOfRange(0, Keyring.NONCE_LEN), raw.copyOfRange(Keyring.NONCE_LEN, raw.size),
                nameAad(gk.groupId, gk.epoch, id),
            )
            val name = strictUtf8(plain) ?: return null
            checkName(name)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Decrypt every member's name: `[device_id: name]`, null for a name that cannot be read.
     * Call ONLY on a keyring already accepted under `key`; it does not authenticate the keyring.
     */
    fun memberNames(ring: JsonValue, key: GroupKey): Map<String, String?> {
        val k = Keyring.nameKey(key)
        val out = LinkedHashMap<String, String?>()
        for (m in arr(obj(ring)["members"])) {
            val mo = obj(m)
            val id = str(mo["device_id"]) ?: continue
            out[id] = openName(k, key, mo["device_id"], mo["name_ct"])
        }
        return out
    }
}
