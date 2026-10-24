package app.localgatekeys.core.keyring

import app.localgatekeys.core.crypto.Argon2
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.SyncFormatException
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.primitives.X25519
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Password- and device-wrapped group keyring (desktop `localvault.sync.keyring`). Format 2 adds each
 * member's Ed25519 view-signing key (`signing_public`) and its `signing_proof`; format 1 is still
 * read, every write is format 2. Keyrings are handled as [JsonValue] so an untouched keyring
 * re-encodes byte-identically.
 */
object Keyring {
    /** The format every write produces. */
    const val FORMAT: Long = 2

    /** The formats a keyring may have to be read (1: members without signing keys). */
    val READ_FORMATS: Set<Long> = setOf(1L, 2L)
    const val KDF_NAME = "argon2id"
    const val KDF_MEMORY_KIB: Long = 131072
    const val KDF_ITERATIONS: Long = 4
    const val KDF_PARALLELISM: Long = 4
    const val KDF_SALT_LEN = 16
    const val MAX_MEMBERS = 16
    const val MAX_KEYRING_BYTES = 256 * 1024
    const val MAX_NAME_LEN = 64
    const val NONCE_LEN = 12
    const val KEY_LEN = 32
    const val WRAP_CT_LEN = 48
    const val MAC_LEN = 32
    const val PROOF_LEN = 64
    const val NAME_CT_MIN = 12 + 1 + 16
    const val NAME_CT_MAX = 12 + 64 + 16
    const val MAX_INT: Long = (1L shl 53) - 1

    private fun ascii(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

    private val PASSWORD_AAD = ascii("lgk-keyring-password-wrap-v1|")
    private val DEVICE_AAD = ascii("lgk-keyring-device-wrap-v1|")
    private val DEVICE_INFO = ascii("localgatekeys|sync|device-wrap|v1|")
    private val MAC_INFO = ascii("localgatekeys|sync|keyring-mac|v1|")
    internal val NAME_AAD = ascii("lgk-keyring-member-name-v1|")
    internal val NAME_INFO = ascii("localgatekeys|sync|member-name|v1|")
    internal val BAR = byteArrayOf(0x7C)
    private val MEMBER_PROOF_LABEL = ascii("localgatekeys|sync|keyring-member|v2|")

    // ---- JSON access (only on structurally verified keyrings unless noted) ----

    internal fun obj(v: JsonValue?): Map<String, JsonValue> = (v as? JsonValue.Obj)?.fields ?: emptyMap()
    internal fun arr(v: JsonValue?): List<JsonValue> = (v as? JsonValue.Arr)?.items ?: emptyList()
    internal fun str(v: JsonValue?): String? = (v as? JsonValue.Str)?.v
    internal fun int(v: JsonValue?): Long? = (v as? JsonValue.Int)?.v

    // ---- base64 ----

    internal fun b64any(v: JsonValue?, what: String): ByteArray {
        val s = str(v) ?: throw KeyringException("bad-base64", what)
        return try {
            Base64Std.decodeStrict(s)
        } catch (e: Exception) {
            throw KeyringException("bad-base64", what)
        }
    }

    internal fun b64(v: JsonValue?, length: Int, what: String): ByteArray {
        val raw = b64any(v, what)
        if (raw.size != length) throw KeyringException("bad-length", what)
        return raw
    }

    // ---- derivations ----

    internal fun epochBytes(e: Long): ByteArray = ascii(e.toString())

    internal fun passwordAad(groupId: String, epoch: Long): ByteArray =
        PASSWORD_AAD + ascii(groupId) + BAR + epochBytes(epoch)

    internal fun deviceAad(groupId: String, epoch: Long, deviceId: String): ByteArray =
        DEVICE_AAD + ascii(groupId) + BAR + epochBytes(epoch) + BAR + ascii(deviceId)

    internal fun deviceKey(shared: ByteArray, groupId: String, deviceId: String): ByteArray =
        CryptoBox.hkdf(shared, ascii(groupId), DEVICE_INFO + ascii(deviceId), KEY_LEN)

    internal fun macKey(gk: GroupKey): ByteArray =
        CryptoBox.hkdf(gk.key, ascii(gk.groupId), MAC_INFO + epochBytes(gk.epoch), KEY_LEN)

    internal fun nameKey(gk: GroupKey): ByteArray =
        CryptoBox.hkdf(gk.key, ascii(gk.groupId), NAME_INFO + epochBytes(gk.epoch), KEY_LEN)

    internal fun hmac(key: ByteArray, message: ByteArray): ByteArray {
        val m = Mac.getInstance("HmacSHA256")
        m.init(SecretKeySpec(key, "HmacSHA256"))
        return m.doFinal(message)
    }

    internal fun constantTimeEqual(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var d = 0
        for (i in a.indices) d = d or (a[i].toInt() xor b[i].toInt())
        return d == 0
    }

    /** HMAC over canonical JSON of the keyring without `mac`. */
    internal fun mac(ring: Map<String, JsonValue>, gk: GroupKey): ByteArray {
        val body = LinkedHashMap(ring)
        body.remove("mac")
        return hmac(macKey(gk), CanonicalJson.encode(JsonValue.Obj(body), Dialect.UTF8))
    }

    /** `prev_mac`: the old epoch's key commits to the new epoch's MAC key. */
    internal fun chainMac(old: GroupKey, new: GroupKey): ByteArray {
        val commitment = Hex.lower(MessageDigest.getInstance("SHA-256").digest(macKey(new)))
        val message = ascii("rotate|") + ascii(new.groupId) + BAR + epochBytes(new.epoch) + BAR + ascii(commitment)
        return hmac(macKey(old), message)
    }

    internal fun macOk(ring: JsonValue, gk: GroupKey): Boolean {
        val o = obj(ring)
        return try {
            val given = b64(o["mac"], MAC_LEN, "mac")
            val want = mac(o, gk)
            constantTimeEqual(given, want)
        } catch (e: Exception) {
            false
        }
    }

    internal fun chainOk(value: JsonValue?, old: GroupKey, new: GroupKey): Boolean {
        val given = try {
            b64(value, MAC_LEN, "prev_mac")
        } catch (e: KeyringException) {
            return false
        }
        return constantTimeEqual(given, chainMac(old, new))
    }

    /** Body with `prev_mac` carried over and `mac` recomputed under [gk]. */
    internal fun finish(body: Map<String, JsonValue>, gk: GroupKey): JsonValue {
        val out = LinkedHashMap(body)
        out.remove("mac")
        out["mac"] = JsonValue.Str(Base64Std.encode(mac(out, gk)))
        return JsonValue.Obj(out)
    }

    internal fun groupKey(groupId: String, epoch: Long, key: ByteArray): GroupKey = try {
        GroupKey(groupId, epoch, key)
    } catch (e: SyncFormatException) {
        throw KeyringException("bad-group-key", e.toString())
    }

    // ---- member signing keys (format 2) ----

    /** What `signing_proof` signs: label + group id | device id | exchange_public | signing_public (both base64 text). */
    internal fun proofMessage(groupId: String, deviceId: String, exchangePublic: String, signingPublic: String): ByteArray =
        MEMBER_PROOF_LABEL + ascii(groupId) + BAR + ascii(deviceId) + BAR + ascii(exchangePublic) + BAR + ascii(signingPublic)

    /**
     * `member_signing_keys`: `{device_id: base64 Ed25519 key}` of every member whose entry lists its
     * view-signing key. Call it only on an accepted keyring (the structure check verified each
     * listed key's proof). Members without a key (format 1, or carried over from it) are absent.
     */
    fun memberSigningKeys(ring: JsonValue): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (m in arr(obj(ring)["members"])) {
            val mo = obj(m)
            val id = str(mo["device_id"]) ?: continue
            val key = str(mo["signing_public"]) ?: continue
            out[id] = key
        }
        return out
    }

    // ---- password wrap ----

    internal fun argon2(password: String, salt: ByteArray, kdf: Map<String, JsonValue>): ByteArray {
        val mem = int(kdf["memory_kib"])
        val its = int(kdf["iterations"])
        val par = int(kdf["parallelism"])
        val max = Int.MAX_VALUE.toLong()
        if (mem == null || its == null || par == null || mem !in 0..max || its !in 0..max || par !in 0..max) {
            throw KeyringException("bad-kdf", "kdf parameters")
        }
        // A lone UTF-16 surrogate has no UTF-8 form: reject it before any KDF work.
        val pwBytes = try {
            val b = Charsets.UTF_8.newEncoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .encode(java.nio.CharBuffer.wrap(password))
            ByteArray(b.remaining()).also { b.get(it) }
        } catch (e: java.nio.charset.CharacterCodingException) {
            throw KeyringException("password", "password is not valid text")
        }
        return try {
            Argon2.default.derive(pwBytes, salt, mem.toInt(), its.toInt(), par.toInt(), KEY_LEN)
        } catch (e: Exception) {
            throw KeyringException("bad-kdf", "argon2id failed")
        }
    }

    /** The Argon2id key for [password] with the keyring's salt and kdf parameters. */
    internal fun passwordKey(ring: JsonValue, password: String): ByteArray {
        val kdf = obj(obj(ring)["kdf"])
        return argon2(password, b64(kdf["salt"], KDF_SALT_LEN, "kdf salt"), kdf)
    }

    /** Open the password wrap with an already derived Argon2id key (structure must be verified). */
    internal fun unwrap(ring: JsonValue, passwordKey: ByteArray): GroupKey {
        val o = obj(ring)
        val pw = obj(o["password_wrap"])
        val gid = str(o["group_id"])
        val epoch = int(o["epoch"])
        if (gid == null || epoch == null) throw KeyringException("bad-fields", "keyring")
        val plain = try {
            CryptoBox.openGcm(
                passwordKey, b64(pw["nonce"], NONCE_LEN, "nonce"), b64(pw["ct"], WRAP_CT_LEN, "ct"),
                passwordAad(gid, epoch),
            )
        } catch (e: KeyringException) {
            throw e
        } catch (e: Exception) {
            throw KeyringException("password", "wrong sync password or damaged keyring")
        }
        return groupKey(gid, epoch, plain)
    }

    /** Open the password wrap (Argon2id with the keyring's kdf block). Verifies structure first. */
    fun unwrapWithPassword(ring: JsonValue, password: String): GroupKey {
        KeyringParse.verifyStructure(ring)
        return unwrap(ring, passwordKey(ring, password))
    }

    // ---- device wrap ----

    internal fun member(ring: JsonValue, identity: DeviceIdentity): Map<String, JsonValue> {
        for (m in arr(obj(ring)["members"])) {
            val mo = obj(m)
            if (str(mo["device_id"]) == identity.deviceId) {
                if (str(mo["exchange_public"]) != Base64Std.encode(identity.exchangePublicKey)) {
                    throw KeyringException("key-mismatch", "device key differs from the registered member")
                }
                val signing = mo["signing_public"]
                if (signing != null && signing != JsonValue.Null && str(signing) != Base64Std.encode(identity.signingPublicKey)) {
                    throw KeyringException("key-mismatch", "signing key differs from the registered member")
                }
                return mo
            }
        }
        throw KeyringException("not-member", "device is not a member of this keyring")
    }

    /** Open this device's wrap (structure must be verified): `not-member`, `key-mismatch`, `device-wrap`. */
    internal fun unwrapDevice(ring: JsonValue, identity: DeviceIdentity): GroupKey {
        member(ring, identity)
        val o = obj(ring)
        val wrap = obj(obj(o["device_wraps"])[identity.deviceId])
        val gid = str(o["group_id"])
        val epoch = int(o["epoch"])
        if (gid == null || epoch == null) throw KeyringException("bad-fields", "keyring")
        val plain = try {
            val shared = identity.exchange(b64(wrap["eph"], 32, "eph"))
            CryptoBox.openGcm(
                deviceKey(shared, gid, identity.deviceId),
                b64(wrap["nonce"], NONCE_LEN, "nonce"), b64(wrap["ct"], WRAP_CT_LEN, "ct"),
                deviceAad(gid, epoch, identity.deviceId),
            )
        } catch (e: KeyringException) {
            throw e
        } catch (e: Exception) {
            throw KeyringException("device-wrap", "device wrap cannot be opened")
        }
        return groupKey(gid, epoch, plain)
    }

    /** (eph, nonce, ct) wrap of [gk] to [exchangePublic]. Draws eph (32) then nonce (12). */
    internal fun wrapDevice(gk: GroupKey, deviceId: String, exchangePublic: ByteArray, random: RandomSource): JsonValue {
        val ephRaw = draw(random, 32)
        val ephPublic: ByteArray
        val shared: ByteArray
        try {
            shared = X25519.agree(ephRaw, exchangePublic)
            ephPublic = X25519.publicKey(ephRaw)
        } catch (e: RuntimeException) {
            throw KeyringException("bad-member-key", "exchange key unusable")
        }
        if (shared.none { it.toInt() != 0 }) throw KeyringException("bad-member-key", "exchange key unusable")
        val nonce = draw(random, NONCE_LEN)
        val ct = CryptoBox.sealGcm(deviceKey(shared, gk.groupId, deviceId), nonce, gk.key, deviceAad(gk.groupId, gk.epoch, deviceId))
        return JsonValue.Obj(
            mapOf(
                "eph" to JsonValue.Str(Base64Std.encode(ephPublic)),
                "nonce" to JsonValue.Str(Base64Std.encode(nonce)),
                "ct" to JsonValue.Str(Base64Std.encode(ct)),
            ),
        )
    }

    internal fun draw(random: RandomSource, n: Int): ByteArray {
        val raw = random.bytes(n)
        if (raw.size != n) throw KeyringException("bad-random", "random source must return exactly $n bytes")
        return raw
    }

    // ---- public API (implemented in the sibling files) ----

    /** Parse keyring bytes strictly and verify the structure. */
    fun parse(data: ByteArray): JsonValue = KeyringParse.parse(data)

    /** Authenticate [ring] against the device's trusted `(group_id, epoch, G)` (desktop `accept_keyring`). */
    fun accept(ring: JsonValue, trusted: GroupKey, identity: DeviceIdentity): GroupKey =
        KeyringAccept.accept(ring, trusted, identity)

    /** Join by sync password: open G, require the MAC, add this device, recompute the MAC. */
    fun join(
        ring: JsonValue,
        password: String,
        identity: DeviceIdentity,
        name: String,
        random: RandomSource,
        now: UnixClock,
    ): Pair<JsonValue, GroupKey> = KeyringJoin.join(ring, identity, name, random, now) { passwordKey(ring, password) }

    /** `join` with a pre-derived Argon2id key (tests). The key is used only after the cheap checks. */
    internal fun join(
        ring: JsonValue,
        passwordKey: ByteArray,
        identity: DeviceIdentity,
        name: String,
        random: RandomSource,
        now: UnixClock,
    ): Pair<JsonValue, GroupKey> = KeyringJoin.join(ring, identity, name, random, now) { passwordKey }

    /** Add a device that already holds [stored] to [ring]; idempotent when already listed with its own key and wrap. */
    fun attach(
        ring: JsonValue,
        password: String,
        identity: DeviceIdentity,
        name: String,
        stored: GroupKey,
        random: RandomSource,
        now: UnixClock,
    ): JsonValue = KeyringJoin.attach(ring, identity, name, stored, random, now) { passwordKey(ring, password) }

    internal fun attach(
        ring: JsonValue,
        passwordKey: ByteArray,
        identity: DeviceIdentity,
        name: String,
        stored: GroupKey,
        random: RandomSource,
        now: UnixClock,
    ): JsonValue = KeyringJoin.attach(ring, identity, name, stored, random, now) { passwordKey }

    /** Decrypt every member's name; null for a name that cannot be read. Call only on an already accepted keyring. */
    fun memberNames(ring: JsonValue, key: GroupKey): Map<String, String?> = MemberNames.memberNames(ring, key)
}
