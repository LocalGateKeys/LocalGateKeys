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
 * by Argon2id(app password) and by the recovery phrase. Immutable; [encode] gives the 165 bytes of v1.
 *
 * With [factors] (a key file and/or a YubiKey, docs/formats/COMPOSITE_KEY_V1.md §7) the file is v2: the factor list
 * follows the parameters, the password wrapper's key mixes in the factor secrets ([CompositeKey.combine]) and its AAD
 * is the v2 header. The recovery wrapper keeps its v1 AAD, so its bytes never change when factors come or go.
 */
class AppPasswordRecord private constructor(
    val params: AppPasswordParams,
    /** The key file / YubiKey this password needs (empty: v1, unchanged). Public: nothing in it is secret. */
    val factors: List<FactorSpec>,
    private val pwSalt: ByteArray,
    private val pwNonce: ByteArray,
    private val pwSealed: ByteArray,
    private val recSalt: ByteArray,
    private val recNonce: ByteArray,
    private val recSealed: ByteArray,
) {
    fun encode(): ByteArray {
        val head = passwordHeader(params, factors)
        return ByteBuffer.allocate(head.size + 2 * (SALT + NONCE + SEALED)).apply {
            put(head); put(pwSalt); put(pwNonce); put(pwSealed); put(recSalt); put(recNonce); put(recSealed)
        }.array()
    }

    /**
     * The local key (caller zeroes it). [password] is UTF-8 bytes from [passwordBytes]; it is not modified. With
     * [factors], [secrets] holds one 32-byte secret per factor in list order: a missing one is
     * [FactorRequiredException] and a wrong one [FactorMismatchException], both before any Argon2id run.
     */
    fun unwrapWithPassword(password: ByteArray, argon: Argon2id = Argon2.default, secrets: List<ByteArray> = emptyList()): ByteArray {
        if (secrets.size != factors.size) throw FactorRequiredException(factors.map { it.kind })
        CompositeKey.verify(factors, secrets)
        val key = wrappingKey(argon, password, pwSalt, params, factors, secrets)
        try {
            return CryptoBox.openGcm(key, pwNonce, pwSealed, passwordHeader(params, factors) + PASSWORD)
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
            return CryptoBox.openGcm(key, recNonce, recSealed, header(params) + RECOVERY)
        } catch (e: CryptoBoxException) {
            throw AppPasswordException(AppPasswordException.Kind.WRONG_PHRASE, "This recovery phrase does not belong to this vault")
        } finally {
            key.fill(0)
        }
    }

    /**
     * Same recovery wrapper, a new password wrapper for [newPassword] (fresh salt and nonce) that needs [factors]
     * ([secrets]: one per factor, list order). No factors (the default) writes v1: callers that keep the factors pass
     * them. The new wrapper is opened once with the same key before it is returned.
     */
    fun withNewPassword(
        localKey: ByteArray,
        newPassword: ByteArray,
        random: RandomSource,
        argon: Argon2id = Argon2.default,
        factors: List<FactorSpec> = emptyList(),
        secrets: List<ByteArray> = emptyList(),
    ): AppPasswordRecord {
        CompositeKey.verify(factors, secrets)
        val aad = passwordHeader(params, factors) + PASSWORD
        val salt = random.bytes(SALT)
        val nonce = random.bytes(NONCE)
        val key = wrappingKey(argon, newPassword, salt, params, factors, secrets)
        try {
            val sealed = CryptoBox.sealGcm(key, nonce, localKey, aad)
            CryptoBox.openGcm(key, nonce, sealed, aad).fill(0)
            return AppPasswordRecord(params, factors.toList(), salt, nonce, sealed, recSalt, recNonce, recSealed)
        } finally {
            key.fill(0)
        }
    }

    override fun toString(): String = "AppPasswordRecord($params, factors=${factors.map { it.kind.id }})"

    /** A new record and the recovery phrase to show once. */
    class Created(val record: AppPasswordRecord, val phrase: String) {
        override fun toString(): String = "Created(${record.params})"
    }

    companion object {
        private val MAGIC = "LGKAPW".toByteArray(Charsets.US_ASCII)
        private const val VERSION: Byte = 1
        private const val VERSION_FACTORS: Byte = 2
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
                val recSealed = try { CryptoBox.sealGcm(rk, recNonce, localKey, header(params) + RECOVERY) } finally { rk.fill(0) }
                val base = AppPasswordRecord(params, emptyList(), ByteArray(SALT), ByteArray(NONCE), ByteArray(SEALED), recSalt, recNonce, recSealed)
                return Created(base.withNewPassword(localKey, password, random, argon), phrase)
            } finally {
                entropy.fill(0)
            }
        }

        /** v1 (165 bytes) or v2 (`167 + L` bytes, a canonical factor list of 1-1024 bytes); anything else is MALFORMED. */
        fun decode(bytes: ByteArray): AppPasswordRecord {
            fun bad(): Nothing = throw AppPasswordException(AppPasswordException.Kind.MALFORMED, "The app password file is damaged")
            if (bytes.size < SIZE || !bytes.copyOf(MAGIC.size).contentEquals(MAGIC)) bad()
            val b = ByteBuffer.wrap(bytes, 7, bytes.size - 7)
            val mem = b.int
            val t = b.get().toInt() and 0xff
            val p = b.get().toInt() and 0xff
            val params = try { AppPasswordParams(mem, t, p) } catch (e: IllegalArgumentException) { bad() }
            val factors = when (bytes[6]) {
                VERSION -> if (bytes.size == SIZE) emptyList() else bad()
                VERSION_FACTORS -> {
                    val l = b.short.toInt() and 0xffff
                    if (l !in 1..CompositeKey.MAX_LIST_BYTES || bytes.size != SIZE + 2 + l) bad()
                    val list = ByteArray(l).also { b.get(it) }
                    try { CompositeKey.parseList(list) } catch (e: IllegalArgumentException) { bad() }
                }
                else -> bad()
            }
            fun take(n: Int) = ByteArray(n).also { b.get(it) }
            return AppPasswordRecord(params, factors, take(SALT), take(NONCE), take(SEALED), take(SALT), take(NONCE), take(SEALED))
        }

        /** The v1 header: also the start of the recovery wrapper's AAD in v2. */
        private fun header(params: AppPasswordParams): ByteArray = ByteBuffer.allocate(HEADER).apply {
            put(MAGIC); put(VERSION); putInt(params.memoryKiB); put(params.iterations.toByte()); put(params.parallelism.toByte())
        }.array()

        /** The header the file starts with and the password wrapper's AAD: v1 without factors, else v2 (`L` and the list). */
        private fun passwordHeader(params: AppPasswordParams, factors: List<FactorSpec>): ByteArray {
            if (factors.isEmpty()) return header(params)
            val list = CompositeKey.info(factors)
            require(list.size <= CompositeKey.MAX_LIST_BYTES) { "factor list too long" }
            return ByteBuffer.allocate(HEADER + 2 + list.size).apply {
                put(MAGIC); put(VERSION_FACTORS); putInt(params.memoryKiB); put(params.iterations.toByte()); put(params.parallelism.toByte())
                putShort(list.size.toShort()); put(list)
            }.array()
        }

        /** Argon2id(password), then the composite key when there are factors (the caller zeroes the result). */
        private fun wrappingKey(
            argon: Argon2id,
            password: ByteArray,
            salt: ByteArray,
            params: AppPasswordParams,
            factors: List<FactorSpec>,
            secrets: List<ByteArray>,
        ): ByteArray {
            val out = argon.derive(password, salt, params.memoryKiB, params.iterations, params.parallelism, 32)
            if (factors.isEmpty()) return out
            try {
                return CompositeKey.combine(out, factors, secrets)
            } finally {
                out.fill(0)
            }
        }

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
