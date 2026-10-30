package app.localgatekeys.core.crypto

import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.CryptoBoxException
import app.localgatekeys.core.primitives.RandomSource
import java.nio.ByteBuffer
import java.text.Normalizer

/** Argon2id cost. [DESKTOP] is `vault.py` `DEFAULT_KDF` (t=3, 64 MiB, p=4, 32-byte output). */
data class AppPasswordParams(val memoryKiB: Int, val iterations: Int, val parallelism: Int) {
    init {
        require(iterations in 1..10 && parallelism in 1..16 && memoryKiB in MIN_MEMORY_KIB..MAX_MEMORY_KIB) {
            "Argon2id parameters are outside the accepted range"
        }
    }

    companion object {
        const val MIN_MEMORY_KIB = 8 * 1024
        const val MAX_MEMORY_KIB = 1024 * 1024
        val DESKTOP = AppPasswordParams(memoryKiB = 65536, iterations = 3, parallelism = 4)
    }
}

/** Why the app password file could not be used. */
class AppPasswordException(val kind: Kind, message: String = kind.name) : Exception(message) {
    enum class Kind { WRONG_PASSWORD, WRONG_PHRASE, MALFORMED }
}

/**
 * `app-password.bin`: the 32-byte local key wrapped twice,
 * by Argon2id(app password) and by the recovery phrase. Immutable; [encode] gives the 165 bytes.
 */
class AppPasswordRecord private constructor(
    val params: AppPasswordParams,
    private val pwSalt: ByteArray,
    private val pwNonce: ByteArray,
    private val pwSealed: ByteArray,
    private val recSalt: ByteArray,
    private val recNonce: ByteArray,
    private val recSealed: ByteArray,
) {
    fun encode(): ByteArray = ByteBuffer.allocate(SIZE).apply {
        put(header(params)); put(pwSalt); put(pwNonce); put(pwSealed); put(recSalt); put(recNonce); put(recSealed)
    }.array()

    /** The local key (caller zeroes it). [password] is UTF-8 bytes from [passwordBytes]; it is not modified. */
    fun unwrapWithPassword(password: ByteArray, argon: Argon2id = Argon2.default): ByteArray {
        val key = derive(argon, password, pwSalt, params)
        try {
            return CryptoBox.openGcm(key, pwNonce, pwSealed, aad(params, PASSWORD))
        } catch (e: CryptoBoxException) {
            throw AppPasswordException(AppPasswordException.Kind.WRONG_PASSWORD, "That app password is not right")
        } finally {
            key.fill(0)
        }
    }

    /** The local key from the 24-word phrase (caller zeroes it). */
    fun unwrapWithPhrase(phrase: String): ByteArray {
        val entropy = Bip39.entropy(phrase)
        val key = recoveryKey(entropy, recSalt)
        entropy.fill(0)
        try {
            return CryptoBox.openGcm(key, recNonce, recSealed, aad(params, RECOVERY))
        } catch (e: CryptoBoxException) {
            throw AppPasswordException(AppPasswordException.Kind.WRONG_PHRASE, "This recovery phrase does not belong to this vault")
        } finally {
            key.fill(0)
        }
    }

    /** Same recovery wrapper, a new password wrapper for [newPassword] (fresh salt and nonce). */
    fun withNewPassword(localKey: ByteArray, newPassword: ByteArray, random: RandomSource, argon: Argon2id = Argon2.default): AppPasswordRecord {
        val salt = random.bytes(SALT)
        val nonce = random.bytes(NONCE)
        val key = derive(argon, newPassword, salt, params)
        try {
            return AppPasswordRecord(params, salt, nonce, CryptoBox.sealGcm(key, nonce, localKey, aad(params, PASSWORD)), recSalt, recNonce, recSealed)
        } finally {
            key.fill(0)
        }
    }

    override fun toString(): String = "AppPasswordRecord($params)"

    /** A new record and the recovery phrase to show once. */
    class Created(val record: AppPasswordRecord, val phrase: String) {
        override fun toString(): String = "Created(${record.params})"
    }

    companion object {
        private val MAGIC = "LGKAPW".toByteArray(Charsets.US_ASCII)
        private const val VERSION: Byte = 1
        const val HEADER = 13
        private const val SALT = 16
        private const val NONCE = 12
        private const val SEALED = 48
        const val SIZE = HEADER + 2 * (SALT + NONCE + SEALED)
        private val PASSWORD = "|password".toByteArray(Charsets.US_ASCII)
        private val RECOVERY = "|recovery".toByteArray(Charsets.US_ASCII)
        private val RECOVERY_KEY_INFO = "localgatekeys|recovery-key|v1".toByteArray(Charsets.US_ASCII)

        /** The typed password as NFC UTF-8 bytes; the caller zeroes them. */
        fun passwordBytes(chars: CharSequence): ByteArray = Normalizer.normalize(chars, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)

        fun create(
            localKey: ByteArray,
            password: ByteArray,
            random: RandomSource,
            params: AppPasswordParams = AppPasswordParams.DESKTOP,
            argon: Argon2id = Argon2.default,
        ): Created {
            require(localKey.size == 32) { "local key must be 32 bytes" }
            val entropy = random.bytes(32)
            try {
                val phrase = Bip39.phrase(entropy)
                val recSalt = random.bytes(SALT)
                val recNonce = random.bytes(NONCE)
                val rk = recoveryKey(entropy, recSalt)
                val recSealed = try { CryptoBox.sealGcm(rk, recNonce, localKey, aad(params, RECOVERY)) } finally { rk.fill(0) }
                val base = AppPasswordRecord(params, ByteArray(SALT), ByteArray(NONCE), ByteArray(SEALED), recSalt, recNonce, recSealed)
                return Created(base.withNewPassword(localKey, password, random, argon), phrase)
            } finally {
                entropy.fill(0)
            }
        }

        fun decode(bytes: ByteArray): AppPasswordRecord {
            fun bad(): Nothing = throw AppPasswordException(AppPasswordException.Kind.MALFORMED, "The app password file is damaged")
            if (bytes.size != SIZE || !bytes.copyOf(MAGIC.size).contentEquals(MAGIC) || bytes[6] != VERSION) bad()
            val b = ByteBuffer.wrap(bytes, 7, SIZE - 7)
            val mem = b.int
            val t = b.get().toInt() and 0xff
            val p = b.get().toInt() and 0xff
            val params = try { AppPasswordParams(mem, t, p) } catch (e: IllegalArgumentException) { bad() }
            fun take(n: Int) = ByteArray(n).also { b.get(it) }
            return AppPasswordRecord(params, take(SALT), take(NONCE), take(SEALED), take(SALT), take(NONCE), take(SEALED))
        }

        private fun header(params: AppPasswordParams): ByteArray = ByteBuffer.allocate(HEADER).apply {
            put(MAGIC); put(VERSION); putInt(params.memoryKiB); put(params.iterations.toByte()); put(params.parallelism.toByte())
        }.array()

        private fun aad(params: AppPasswordParams, label: ByteArray) = header(params) + label

        private fun derive(argon: Argon2id, password: ByteArray, salt: ByteArray, params: AppPasswordParams): ByteArray =
            argon.derive(password, salt, params.memoryKiB, params.iterations, params.parallelism, 32)

        private fun recoveryKey(entropy: ByteArray, salt: ByteArray): ByteArray = CryptoBox.hkdf(entropy, salt, RECOVERY_KEY_INFO, 32)
    }
}

/**
 * Wrong-try delay: from the 5th consecutive wrong try, 30 s, doubling per further wrong try, at most 15 min.
 * Seconds to wait after [failures] wrong tries.
 */
object AppPasswordDelay {
    const val FREE_TRIES = 4
    const val FIRST_DELAY = 30L
    const val MAX_DELAY = 15 * 60L

    fun seconds(failures: Int): Long {
        if (failures <= FREE_TRIES) return 0
        val steps = (failures - FREE_TRIES - 1).coerceAtMost(10)
        return (FIRST_DELAY shl steps).coerceAtMost(MAX_DELAY)
    }

    /** Seconds still to wait at [now] after [failures] wrong tries, the last at [lastFailureAt] (Unix seconds). */
    fun remaining(failures: Int, lastFailureAt: Long, now: Long): Long {
        val wait = seconds(failures)
        if (wait == 0L) return 0
        // A clock moved backwards does not shorten the wait below the full delay.
        val elapsed = (now - lastFailureAt).let { if (it < 0) 0 else it }
        return (wait - elapsed).coerceAtLeast(0)
    }

    /**
     * As [remaining], but a wall clock moved forward does not count as time passed: while the device has not restarted
     * ([sameBoot], and the monotonic clock did not go backwards), the elapsed time is the monotonic clock's
     * ([elapsed] - [lastFailureElapsed], seconds since boot). After a restart (or with no monotonic stamp, [lastFailureElapsed]
     * < 0) the wall clock decides, as before.
     */
    fun remaining(
        failures: Int,
        lastFailureAt: Long,
        now: Long,
        lastFailureElapsed: Long,
        elapsed: Long,
        sameBoot: Boolean,
    ): Long {
        if (!sameBoot || lastFailureElapsed < 0 || elapsed < lastFailureElapsed) return remaining(failures, lastFailureAt, now)
        val wait = seconds(failures)
        if (wait == 0L) return 0
        return (wait - (elapsed - lastFailureElapsed)).coerceAtLeast(0)
    }
}
