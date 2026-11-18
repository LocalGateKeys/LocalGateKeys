package app.localgatekeys.android.unlock

import app.localgatekeys.core.crypto.CompositeKey
import app.localgatekeys.core.crypto.FactorKind
import app.localgatekeys.core.crypto.FactorMismatchException
import app.localgatekeys.core.crypto.FactorRequiredException
import app.localgatekeys.core.crypto.FactorSpec
import app.localgatekeys.core.crypto.KeyFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** A key file for the app password: its content URI and display name. The file itself is never copied. */
data class KeyFileRef(val uri: String, val name: String)

/** The key file could not be read (moved, deleted, permission gone) or is larger than any key file. */
class KeyFileUnreadableException(val name: String, val tooLarge: Boolean = false) : Exception("key file unreadable")

/**
 * The YubiKey did not answer. None of these is a password failure: the wrong-try delay never counts them.
 * [Code.REMOVED]: the key left the reader (NFC tag lost, USB unplugged) during the exchange.
 */
class YubiKeyException(val code: Code, val slot: Int = DEFAULT_SLOT) : Exception("YubiKey: $code") {
    enum class Code { REMOVED, TIMEOUT, SLOT_NOT_CONFIGURED, BAD_ANSWER, NO_TRANSPORT, CANCELLED }

    companion object {
        const val DEFAULT_SLOT = 2
    }
}

/**
 * Where the app password's factors come from on this phone: the key file (picked with the system file picker, its
 * persisted URI permission remembered unless "Don't remember") and a YubiKey over NFC or USB ([YubiKeyReader]).
 */
interface FactorSource {
    /** The remembered key file, or null (none, or "Don't remember"). */
    fun rememberedKeyFile(): KeyFileRef?

    /** The file's bytes, at most [KeyFile.MAX_BYTES] (the caller zeroes them); [KeyFileUnreadableException] otherwise. */
    suspend fun readKeyFile(ref: KeyFileRef): ByteArray

    /** False with "Don't remember": no key file location is kept (the unlock screen offers no Remember box). */
    fun remembers(): Boolean

    /**
     * Keep [ref] for the next unlock (its read grant persisted now, after it worked), unless "Don't remember" is set;
     * the grant of the file it replaces is given back.
     */
    fun rememberKeyFile(ref: KeyFileRef)

    /** A picked file that will not be remembered (a failed or replaced pick): any grant it holds is given back. */
    fun releaseKeyFile(ref: KeyFileRef)

    /**
     * Waits for a YubiKey (NFC tap or USB) and returns its 20-byte HMAC-SHA1 response from [slot] to [challenge], which
     * is always the full 64-byte padded challenge, sent as given. Throws [YubiKeyException].
     */
    suspend fun yubiKey(slot: Int, challenge: ByteArray): ByteArray

    /** Stops a [yubiKey] wait (it throws [YubiKeyException.Code.CANCELLED]); nothing when none is running. */
    fun cancelYubiKey()
}

/** The factors for one password check: the key file's bytes (null: none chosen) and the YubiKey's answer. */
class FactorInput(
    val keyFile: suspend () -> ByteArray?,
    val yubiKey: suspend (slot: Int, challenge: ByteArray) -> ByteArray,
) {
    override fun toString() = "FactorInput"
}

/** Turns a [FactorInput] into the composite key's secrets (docs/formats/COMPOSITE_KEY_V1.md §1, §3). */
object FactorSecrets {
    /**
     * One 32-byte secret per spec, in list order (the caller zeroes them). Each secret's `check` is compared as soon as
     * it is known, so a wrong key file is reported before the YubiKey is asked and before any Argon2id run:
     * [FactorRequiredException] (none supplied), [FactorMismatchException], [app.localgatekeys.core.crypto.KeyFileException]
     * (not a usable key file), [YubiKeyException], [KeyFileUnreadableException].
     */
    suspend fun collect(specs: List<FactorSpec>, input: FactorInput?): List<ByteArray> {
        if (specs.isEmpty()) return emptyList()
        if (input == null) throw FactorRequiredException(specs.map { it.kind })
        val out = ArrayList<ByteArray>(specs.size)
        try {
            for (spec in specs) {
                val secret = when (spec.kind) {
                    FactorKind.KEYFILE -> {
                        val bytes = input.keyFile() ?: throw FactorRequiredException(listOf(FactorKind.KEYFILE))
                        // Up to 64 MiB hashed: off the main thread.
                        try { withContext(Dispatchers.Default) { KeyFile.keyFromBytes(bytes) } } finally { bytes.fill(0) }
                    }
                    FactorKind.YUBIKEY_HMAC -> {
                        val slot = spec.slot ?: YubiKeyException.DEFAULT_SLOT
                        val response = input.yubiKey(slot, spec.paddedChallenge)
                        try {
                            if (response.size != CompositeKey.YUBIKEY_RESPONSE_SIZE) throw YubiKeyException(YubiKeyException.Code.BAD_ANSWER, slot)
                            CompositeKey.yubikeySecret(response)
                        } finally {
                            response.fill(0)
                        }
                    }
                }
                out += secret
                CompositeKey.verify(listOf(spec), listOf(secret))
            }
            return out
        } catch (e: Throwable) {
            out.forEach { it.fill(0) }
            throw e
        }
    }

    /** A YubiKey factor for a new [challenge] (32 bytes): asks the key and builds the spec and its secret. */
    suspend fun newYubiKey(slot: Int, challenge: ByteArray, input: FactorInput): Pair<FactorSpec, ByteArray> {
        val response = input.yubiKey(slot, CompositeKey.padChallenge(challenge))
        try {
            if (response.size != CompositeKey.YUBIKEY_RESPONSE_SIZE) throw YubiKeyException(YubiKeyException.Code.BAD_ANSWER, slot)
            val secret = CompositeKey.yubikeySecret(response)
            return FactorSpec.yubiKey(CompositeKey.check(secret), slot, challenge) to secret
        } finally {
            response.fill(0)
        }
    }
}

/**
 * A YubiKey's answer through [ask]; a key that leaves the reader mid-answer ([YubiKeyException.Code.REMOVED]) is asked
 * again, up to [tries] times in all. [prompt] runs before each try (again = after a removal: "Touch your YubiKey again").
 */
suspend fun askYubiKeyWithRetries(tries: Int, prompt: (again: Boolean) -> Unit, ask: suspend () -> ByteArray): ByteArray {
    var n = 1
    while (true) {
        prompt(n > 1)
        try {
            return ask()
        } catch (e: YubiKeyException) {
            if (e.code != YubiKeyException.Code.REMOVED || n >= tries) throw e
        }
        n++
    }
}
