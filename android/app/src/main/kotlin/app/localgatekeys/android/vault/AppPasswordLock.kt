package app.localgatekeys.android.vault

import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.core.crypto.AppPasswordDelay
import app.localgatekeys.core.crypto.AppPasswordException
import app.localgatekeys.core.crypto.AppPasswordRecord
import app.localgatekeys.core.crypto.Argon2
import app.localgatekeys.core.crypto.Argon2id
import app.localgatekeys.core.crypto.FactorSpec
import app.localgatekeys.core.crypto.RecoveryPhraseException
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import javax.crypto.Cipher

/** Where the app password lives: `filesDir/app-password.bin` and the biometric wrap `filesDir/vault-key-bio.bin`. */
data class AppPasswordFiles(val record: File, val bioWrapped: File) {
    companion object {
        fun under(filesDir: File) = AppPasswordFiles(File(filesDir, "app-password.bin"), File(filesDir, "vault-key-bio.bin"))
    }
}

/** The wrong-try delay is running: [seconds] left. */
class AppPasswordWaitException(val seconds: Long) : Exception("wait $seconds s")

/** The app password is on and no biometric shortcut is set up (or it was cancelled): type the password. */
class AppPasswordRequiredException : Exception("app password required")

/** The fingerprints or faces changed: the biometric shortcut was removed. Type the app password. */
class BiometricChangedException : Exception("biometric enrolment changed")

/** The persisted wrong-try count (AppSettings in the app). */
interface AppPasswordAttempts {
    var failures: Int
    var lastFailureAt: Long
    /** Monotonic seconds since boot at the last wrong try (-1: none) and that boot ([BootClock.boot]). */
    var lastFailureElapsed: Long
        get() = -1L
        set(@Suppress("UNUSED_PARAMETER") v) {}
    var lastFailureBoot: Long
        get() = -1L
        set(@Suppress("UNUSED_PARAMETER") v) {}

    companion object {
        fun of(settings: AppSettings) = object : AppPasswordAttempts {
            override var failures: Int
                get() = settings.appPasswordFailures
                set(v) { settings.appPasswordFailures = v }
            override var lastFailureAt: Long
                get() = settings.appPasswordLastFailureAt
                set(v) { settings.appPasswordLastFailureAt = v }
            override var lastFailureElapsed: Long
                get() = settings.appPasswordLastFailureElapsed
                set(v) { settings.appPasswordLastFailureElapsed = v }
            override var lastFailureBoot: Long
                get() = settings.appPasswordLastFailureBoot
                set(v) { settings.appPasswordLastFailureBoot = v }
        }
    }
}

/**
 * A clock a wall-clock change does not move: seconds since boot ([elapsed], `SystemClock.elapsedRealtime`) and which
 * boot it is ([boot], `Settings.Global.BOOT_COUNT`; -1 when unknown). Keeps the wrong-try delay from being skipped by
 * setting the date forward.
 */
interface BootClock {
    val elapsed: Long
    val boot: Long

    companion object {
        /** No monotonic clock: the wall clock alone decides (tests that do not care). */
        val NONE = object : BootClock {
            override val elapsed = -1L
            override val boot = -1L
        }
    }
}

/**
 * The optional app password (`app-password.bin`, the local key wrapped by Argon2id(password) and by the recovery phrase)
 * and the optional biometric-only shortcut [bioKey] + `vault-key-bio.bin`. Blocking: call off the main thread. Never logs or stores a password or phrase.
 */
class AppPasswordLock(
    val files: AppPasswordFiles,
    val bioKey: VaultKey,
    private val random: RandomSource,
    private val attempts: AppPasswordAttempts,
    private val clock: UnixClock,
    private val argon: () -> Argon2id = { Argon2.default },
    private val bootClock: BootClock = BootClock.NONE,
) {
    fun isOn(): Boolean = files.record.exists()

    fun biometricOn(): Boolean = files.bioWrapped.exists() && safeExists()

    private fun safeExists(): Boolean = try { bioKey.exists() } catch (e: VaultKeyException) { false }

    fun record(): AppPasswordRecord = try {
        AppPasswordRecord.decode(files.record.readBytes())
    } catch (e: IOException) {
        throw LocalStoreException(LocalStoreException.Kind.IO, "app password file")
    }

    /** Seconds the wrong-try delay still runs (0: a try is allowed). */
    fun waitSeconds(): Long {
        val elapsed = bootClock.elapsed
        val boot = bootClock.boot
        val sameBoot = elapsed >= 0 && boot >= 0 && boot == attempts.lastFailureBoot
        return AppPasswordDelay.remaining(
            attempts.failures, attempts.lastFailureAt, clock.now, attempts.lastFailureElapsed, elapsed, sameBoot,
        )
    }

    /**
     * The key file / YubiKey the app password needs (empty: none, or no readable password file). Public data: read for
     * the unlock screen and Settings.
     */
    fun factors(): List<FactorSpec> {
        val file = files.record
        if (!file.exists()) return emptyList()
        // Asked on the main thread (the unlock screen, the sheets): decoded once per change of the file.
        val stamp = file.lastModified() to file.length()
        factorCache?.let { (s, list) -> if (s == stamp) return list }
        val list = try { record().factors } catch (e: Exception) { emptyList() }
        factorCache = stamp to list
        return list
    }

    /** [factors] for the file stamp (modified time, length) it was read at; cleared by every write here. */
    @Volatile private var factorCache: Pair<Pair<Long, Long>, List<FactorSpec>>? = null

    /**
     * The local key (caller zeroes it). Counts a wrong password; refuses during the delay. With factors, [secrets] holds
     * their secrets in list order; a missing or wrong factor is thrown before Argon2id and never counted.
     */
    fun unwrapPassword(password: ByteArray, secrets: List<ByteArray> = emptyList()): ByteArray =
        counted { record().unwrapWithPassword(password, argon(), secrets) }

    /** The local key from the recovery phrase (caller zeroes it); a wrong phrase counts like a wrong password. */
    fun unwrapPhrase(phrase: String): ByteArray = counted { record().unwrapWithPhrase(phrase) }

    private inline fun counted(block: () -> ByteArray): ByteArray {
        val wait = waitSeconds()
        if (wait > 0) throw AppPasswordWaitException(wait)
        try {
            val key = block()
            if (attempts.failures != 0) attempts.failures = 0
            return key
        } catch (e: AppPasswordException) {
            if (e.kind != AppPasswordException.Kind.MALFORMED) noteFailure()
            throw e
        } catch (e: RecoveryPhraseException) {
            noteFailure()
            throw e
        }
    }

    /**
     * Duress password (sub-plan 08): a wrong try that did not go through [unwrapPassword] or [unwrapPhrase] (the real
     * vault is held, so a right password is refused as wrong and counted).
     */
    fun noteWrongTry() = noteFailure()

    /** The wrong-try count now (read before a counted try whose success must not reset it: the held vault). */
    fun failureCount(): Int = attempts.failures

    /**
     * Held vault (sub-plan 08, iPhone review I1): a right password or phrase was refused as wrong after its counted try
     * reset the count; the count goes back to [previous] and this try is added, so the delay grows exactly as for a
     * wrong guess.
     */
    fun noteWrongTryAfter(previous: Int) {
        attempts.failures = previous
        noteFailure()
    }

    /** Duress password: an unlock of the second vault resets the count like any success (no tell-tale back-off). */
    fun clearFailures() {
        if (attempts.failures != 0) attempts.failures = 0
    }

    private fun noteFailure() {
        attempts.lastFailureAt = clock.now
        attempts.lastFailureElapsed = bootClock.elapsed
        attempts.lastFailureBoot = bootClock.boot
        attempts.failures = attempts.failures + 1
    }

    fun write(record: AppPasswordRecord) {
        factorCache = null
        writeFileAtomically(files.record, record.encode(), random)
        factorCache = null
    }

    /** Biometric shortcut, step 1: a fresh biometric-only key and the cipher the prompt must authorise. */
    fun prepareBiometric(): Cipher {
        removeBiometric()
        bioKey.create()
        return bioKey.cipherForWrap()
    }

    /** Step 2, with the authorised cipher. */
    fun finishBiometric(localKey: ByteArray, cipher: Cipher) {
        writeFileAtomically(files.bioWrapped, bioKey.wrap(localKey, cipher), random)
    }

    fun bioCipherForUnwrap(): Pair<ByteArray, Cipher> {
        val wrapped = try { files.bioWrapped.readBytes() } catch (e: IOException) {
            throw LocalStoreException(LocalStoreException.Kind.IO, "biometric key file")
        }
        return wrapped to bioKey.cipherForUnwrap(wrapped)
    }

    /** Removes the shortcut; a missing one is not an error. */
    fun removeBiometric() {
        files.bioWrapped.delete()
        bioKey.delete()
    }

    /** Erase and turn-off: the shortcut, then the record. True when everything is gone. */
    fun deleteAll(): Boolean {
        factorCache = null
        var ok = true
        try { removeBiometric() } catch (e: Exception) { ok = false }
        if (files.bioWrapped.exists()) ok = false
        if (files.record.exists() && !files.record.delete()) ok = false
        return ok
    }
}

/** Temp file `.<name>.<random>.tmp`, fsync, atomic rename, directory fsync; [LocalStoreException] (IO) on failure. */
internal fun writeFileAtomically(file: File, bytes: ByteArray, random: RandomSource) {
    val dir = file.absoluteFile.parentFile ?: throw LocalStoreException(LocalStoreException.Kind.IO, file.name)
    val tmp = File(dir, ".${file.name}.${Hex.lower(random.bytes(8))}.tmp")
    try {
        dir.mkdirs()
        FileOutputStream(tmp).use { out ->
            out.write(bytes)
            out.flush()
            out.fd.sync()
        }
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (e: AtomicMoveNotSupportedException) {
            throw IOException("atomic rename not supported", e)
        }
        syncDirectory(dir)
    } catch (e: IOException) {
        tmp.delete()
        throw LocalStoreException(LocalStoreException.Kind.IO, file.name)
    }
}
