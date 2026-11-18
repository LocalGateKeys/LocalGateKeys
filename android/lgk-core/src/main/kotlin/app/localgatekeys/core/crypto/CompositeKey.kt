package app.localgatekeys.core.crypto

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.RandomSource
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** The two factor kinds, in the only order a factor list may hold them (docs/formats/COMPOSITE_KEY_V1.md §2). */
enum class FactorKind(val id: String) {
    KEYFILE("keyfile"),
    YUBIKEY_HMAC("yubikey-hmac"),
}

/**
 * The public description of one factor, stored next to the password wrapper (never a secret). A key file has only
 * [check]; a YubiKey also its [slot] (1 or 2) and its 32-byte [challenge] as 64 lower-case hex digits.
 */
data class FactorSpec(val kind: FactorKind, val check: String, val slot: Int? = null, val challenge: String? = null) {
    init {
        require(CHECK.matches(check)) { "Factor check must be 16 lower-case hex digits" }
        if (kind == FactorKind.KEYFILE) {
            require(slot == null && challenge == null) { "A key-file factor has no slot or challenge" }
        } else {
            require(slot == 1 || slot == 2) { "YubiKey slot must be 1 or 2" }
            require(challenge != null && CHALLENGE.matches(challenge)) { "YubiKey challenge must be 64 lower-case hex digits" }
        }
    }

    /** The 64 bytes sent to the YubiKey ([FactorKind.YUBIKEY_HMAC] only). */
    val paddedChallenge: ByteArray
        get() = CompositeKey.padChallenge(Hex.decode(challenge ?: throw IllegalStateException("Only a YubiKey factor has a challenge")))

    /** Canonical JSON (§2): keys in byte order, no whitespace; every value is ASCII letters, digits or `-`. */
    internal fun canonical(): String =
        if (kind == FactorKind.KEYFILE) "{\"check\":\"$check\",\"kind\":\"${kind.id}\"}"
        else "{\"challenge\":\"$challenge\",\"check\":\"$check\",\"kind\":\"${kind.id}\",\"slot\":$slot}"

    companion object {
        private val CHECK = Regex("[0-9a-f]{16}")
        private val CHALLENGE = Regex("[0-9a-f]{64}")

        fun keyFile(check: String) = FactorSpec(FactorKind.KEYFILE, check)

        fun yubiKey(check: String, slot: Int, challenge: ByteArray): FactorSpec {
            require(challenge.size == CompositeKey.CHALLENGE_SIZE) { "YubiKey challenge must be 32 bytes" }
            return FactorSpec(FactorKind.YUBIKEY_HMAC, check, slot, Hex.lower(challenge))
        }

        /** Strict parse of a stored factor object: any unknown, missing or mistyped field is refused. */
        fun fromJson(value: JsonValue): FactorSpec {
            val f = (value as? JsonValue.Obj)?.fields ?: throw IllegalArgumentException("Factor must be an object")
            val kind = FactorKind.entries.firstOrNull { it.id == (f["kind"] as? JsonValue.Str)?.v }
                ?: throw IllegalArgumentException("Unknown factor kind")
            val allowed = if (kind == FactorKind.KEYFILE) setOf("kind", "check") else setOf("kind", "check", "slot", "challenge")
            require(f.keys == allowed) { "Factor fields are malformed" }
            val check = (f["check"] as? JsonValue.Str)?.v ?: throw IllegalArgumentException("Factor check must be a string")
            if (kind == FactorKind.KEYFILE) return keyFile(check)
            val slot = (f["slot"] as? JsonValue.Int)?.v ?: throw IllegalArgumentException("YubiKey slot must be an integer")
            val challenge = (f["challenge"] as? JsonValue.Str)?.v ?: throw IllegalArgumentException("YubiKey challenge must be a string")
            require(slot == 1L || slot == 2L) { "YubiKey slot must be 1 or 2" }
            return FactorSpec(kind, check, slot.toInt(), challenge)
        }
    }
}

/** The supplied key file or YubiKey is not the one these factors were set up with (raised before any Argon2id). */
class FactorMismatchException(val kind: FactorKind) : Exception("The ${kind.id} factor does not match")

/** The factors are set but not all were supplied: offer them, or the recovery phrase. */
class FactorRequiredException(val kinds: List<FactorKind>) : Exception("factor required: ${kinds.joinToString { it.id }}")

/**
 * Composite key v1 (docs/formats/COMPOSITE_KEY_V1.md, vectors tests/vectors/composite_key, Python
 * `src/localvault/composite_key.py`): key-file and YubiKey secrets mixed into the Argon2id output,
 *
 *     HKDF-SHA256(ikm = argon_out || secret_1 [|| secret_2], salt = "localgatekeys|composite|v1",
 *                 info = canonical JSON of the factor list, L = 32)
 *
 * and the Argon2id output itself when there are no factors, so formats without factors are unchanged.
 */
object CompositeKey {
    const val SECRET_SIZE = 32
    const val CHALLENGE_SIZE = 32
    const val PADDED_CHALLENGE_SIZE = 64
    const val YUBIKEY_RESPONSE_SIZE = 20
    /** The largest factor list the formats store (Android `app-password.bin` v2: `L` in 1-1024). */
    const val MAX_LIST_BYTES = 1024
    private val SALT = "localgatekeys|composite|v1".toByteArray(Charsets.US_ASCII)
    private val CHECK_INFO = "localgatekeys|factor-check|v1".toByteArray(Charsets.US_ASCII)

    /** At most one key file, then at most one YubiKey. */
    fun validate(specs: List<FactorSpec>) {
        val kinds = specs.map { it.kind }
        require(kinds == FactorKind.entries.filter { it in kinds }) { "Factor list must hold at most one key file then at most one YubiKey" }
    }

    /** Canonical JSON of the factor list (§2), ASCII. */
    fun info(specs: List<FactorSpec>): ByteArray {
        validate(specs)
        return specs.joinToString(",", "[", "]") { it.canonical() }.toByteArray(Charsets.US_ASCII)
    }

    /** A stored factor list: 1-2 valid objects, and the bytes must be exactly their canonical JSON. */
    fun parseList(bytes: ByteArray): List<FactorSpec> {
        require(bytes.size in 1..MAX_LIST_BYTES) { "Factor list size is out of range" }
        val parsed = try {
            CanonicalJson.parse(bytes)
        } catch (e: JsonException) {
            throw IllegalArgumentException("Factor list is not JSON")
        }
        val items = (parsed as? JsonValue.Arr)?.items ?: throw IllegalArgumentException("Factor list must be an array")
        require(items.size in 1..2) { "Factor list must hold one or two factors" }
        val specs = items.map { FactorSpec.fromJson(it) }
        require(info(specs).contentEquals(bytes)) { "Factor list is not canonical" }
        return specs
    }

    /** Hex of the first 8 bytes of HMAC-SHA256(secret, "localgatekeys|factor-check|v1"). */
    fun check(secret: ByteArray): String {
        require(secret.size == SECRET_SIZE) { "Factor secret must be 32 bytes" }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret, "HmacSHA256"))
        return Hex.lower(mac.doFinal(CHECK_INFO).copyOf(8))
    }

    /** The factor secret of a YubiKey: SHA-256 of its 20-byte HMAC-SHA1 response. */
    fun yubikeySecret(response: ByteArray): ByteArray {
        require(response.size == YUBIKEY_RESPONSE_SIZE) { "YubiKey response must be 20 bytes" }
        return MessageDigest.getInstance("SHA-256").digest(response)
    }

    /**
     * The 32-byte challenge padded to 64 bytes as KeePassXC pads it (32 bytes of 0x20). These 64 bytes go to the
     * YubiKey exactly: never hand a YubiKey library the bare 32 bytes and let it pad.
     */
    fun padChallenge(challenge: ByteArray): ByteArray {
        require(challenge.size == CHALLENGE_SIZE) { "YubiKey challenge must be 32 bytes" }
        val pad = PADDED_CHALLENGE_SIZE - CHALLENGE_SIZE
        return challenge + ByteArray(pad) { pad.toByte() }
    }

    /** 32 random bytes for a YubiKey factor, never ending in 0x00 or 0x20 (a variable-mode slot would drop them). */
    fun newChallenge(random: RandomSource): ByteArray {
        while (true) {
            val c = random.bytes(CHALLENGE_SIZE)
            val last = c[CHALLENGE_SIZE - 1].toInt() and 0xff
            if (last != 0x00 && last != 0x20) return c
        }
    }

    /** [FactorMismatchException] for the first secret whose check differs (constant-time compare); runs no KDF. */
    fun verify(specs: List<FactorSpec>, secrets: List<ByteArray>) {
        validate(specs)
        require(specs.size == secrets.size) { "One secret per factor is required" }
        for ((spec, secret) in specs.zip(secrets)) {
            val ok = MessageDigest.isEqual(check(secret).toByteArray(Charsets.US_ASCII), spec.check.toByteArray(Charsets.US_ASCII))
            if (!ok) throw FactorMismatchException(spec.kind)
        }
    }

    /**
     * The wrapping key: [argonOut] itself (the same array) when there are no factors, otherwise a new array the caller
     * zeroes. The caller still owns [argonOut].
     */
    fun combine(argonOut: ByteArray, specs: List<FactorSpec>, secrets: List<ByteArray>): ByteArray {
        validate(specs)
        require(specs.size == secrets.size) { "One secret per factor is required" }
        if (specs.isEmpty()) return argonOut
        require(argonOut.size == SECRET_SIZE && secrets.all { it.size == SECRET_SIZE }) { "Composite key inputs must be 32 bytes each" }
        val ikm = ByteArray(SECRET_SIZE * (1 + secrets.size))
        try {
            argonOut.copyInto(ikm)
            secrets.forEachIndexed { i, s -> s.copyInto(ikm, SECRET_SIZE * (i + 1)) }
            return CryptoBox.hkdf(ikm, SALT, info(specs), 32)
        } finally {
            ikm.fill(0)
        }
    }
}
