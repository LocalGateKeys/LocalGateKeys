package app.localgatekeys.android.duress

import app.localgatekeys.android.unlock.VaultDirs
import app.localgatekeys.android.vault.AppPasswordLock
import app.localgatekeys.android.vault.AppPasswordWaitException
import app.localgatekeys.android.vault.BootClock
import app.localgatekeys.android.vault.LocalStore
import app.localgatekeys.android.vault.writeFileAtomically
import app.localgatekeys.core.crypto.AppPasswordException
import app.localgatekeys.core.crypto.AppPasswordParams
import app.localgatekeys.core.crypto.AppPasswordRecord
import app.localgatekeys.core.crypto.Argon2
import app.localgatekeys.core.crypto.Argon2id
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import java.io.File
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Why a duress-password change was refused (desktop `duress.DuressError`): `same` / `close` (equal to or one edit from
 * the app password), `near_duress` (a new app password too near the duress password), `hours`, `exists`, `missing`,
 * `needs_password` (the app password is off) or `generic` (the plain "couldn't save" every refusal inside a duress
 * session ends with).
 */
class DuressException(val code: String) : Exception(code)

/**
 * Where the second vault lives: its own folder `filesDir/.lgk-d` with its own app-password file, store, secret slots,
 * documents and settings, so nothing it writes touches the real vault's files. [hold] (until when the real vault is
 * held) and [real] (the real vault's sealed duress record) sit beside the real vault.
 */
class DuressFiles(val dir: File, val hold: File, val real: File) {
    val record: File get() = File(dir, "app-password.bin")
    val vault: File get() = File(dir, "Vault")
    val secrets: File get() = File(dir, "secrets.bin")
    val config: File get() = File(dir, "config.bin")
    val draft: File get() = File(dir, "draft.bin")
    val attachments: File get() = File(vault, "attachments")

    /** The second vault's own folders, in the shape the opener uses (no wrapped key: only the password opens it). */
    val vaultDirs: VaultDirs get() = VaultDirs(vault, File(dir, "vault-key.bin"), secrets)

    companion object {
        const val DIR = ".lgk-d"
        fun under(filesDir: File) = DuressFiles(File(filesDir, DIR), File(filesDir, "vault.hold.json"), File(filesDir, "duress.bin"))
    }
}

/**
 * The duress password on phones (sub-plan 08, Task 5a; desktop `duress.py`): a second app password that opens a
 * separate, plausible vault ([DuressFiles]) and holds the real one for the chosen hours. It needs the app password
 * (the unlock screen's password field is what a coercer sees). The unlock tries the real vault first and this one
 * second; when this file exists both Argon2id derivations run on every app-password unlock, so the time taken does not
 * tell which one opened. While held, the real app password, the fingerprint shortcut and the recovery phrase are all
 * refused as if wrong. A session opened here gets no sync and no autofill or passkey service, and nothing on screen
 * names it. Blocking: call off the main thread. Never logs or stores a password.
 */
class DuressVault(
    val files: DuressFiles,
    private val random: RandomSource,
    private val clock: UnixClock,
    private val argon: () -> Argon2id = { Argon2.default },
    private val params: AppPasswordParams = AppPasswordParams.DESKTOP,
    private val bootClock: BootClock = BootClock.NONE,
) {
    /** Set while the second vault is the open session (process-wide; the services read it). */
    @Volatile var sessionOpen: Boolean = false

    fun configured(): Boolean = files.record.isFile

    /** The second vault's local key for [password] (the caller zeroes it), else null; one Argon2id run when configured. */
    fun tryOpen(password: ByteArray): ByteArray? {
        if (!configured()) return null
        return try {
            AppPasswordRecord.decode(files.record.readBytes()).unwrapWithPassword(password, argon())
        } catch (e: AppPasswordException) {
            null
        } catch (e: Exception) {
            null
        }
    }

    // ---- the hold -------------------------------------------------------------------------

    /**
     * Until when (Unix seconds) the real vault is held, else null. An unreadable hold file fails closed.
     * Audit 2026-11-10 (as the iPhone): setting the date forward does not end the hold. A hold written with its
     * monotonic anchor (`mono`, `boot`, from [bootClock]) ends only once the wall clock has passed `until` and the
     * monotonic clock has also counted the hold's length (`until - since`). A restart sets that clock back to zero, so
     * after one only the time since the restart counts: a restart can make the hold longer, never shorter. A hold
     * without an anchor (an earlier build, or no monotonic clock) keeps the wall-clock rule.
     */
    fun heldUntil(now: Long = clock.now): Long? {
        val f = files.hold
        return try {
            if (!f.exists()) return null
            val until = try {
                val o = (CanonicalJson.parse(f.readBytes().copyOf(minOf(f.length(), 4096L).toInt())) as JsonValue.Obj).fields
                val u = (o["until"] as JsonValue.Int).v
                val since = (o["since"] as? JsonValue.Int)?.v
                val mono = (o["mono"] as? JsonValue.Int)?.v
                if (since != null && mono != null && u > since) {
                    val boot = (o["boot"] as? JsonValue.Int)?.v
                    val remaining = monotonicRemaining(u - since, mono, boot, bootClock.elapsed, bootClock.boot)
                    if (remaining > 0) maxOf(u, now + remaining) else u
                } else {
                    u
                }
            } catch (e: Exception) {
                f.lastModified() / 1000 + MAX_HOURS * 3600L
            }
            if (until > now) until else null
        } catch (e: Exception) {
            now + 60 // cannot even look: fail closed for a minute
        }
    }

    fun held(): Boolean = heldUntil() != null

    /** A duress session is open or the real vault is held: the autofill and passkey services offer nothing. */
    fun servicesBlocked(): Boolean = sessionOpen || held()

    /** Holds the real vault after a duress unlock; returns until when. Never shortens an earlier hold. */
    fun trip(decoyKey: ByteArray): Long {
        val now = clock.now
        var until = now + hours(decoyKey) * 3600L
        heldUntil(now)?.let { until = maxOf(until, it) }
        val o = linkedMapOf<String, JsonValue>("version" to JsonValue.Int(1), "since" to JsonValue.Int(now), "until" to JsonValue.Int(until))
        // The monotonic anchor (audit 2026-11-10); an earlier build reads only `since` and `until`.
        val elapsed = bootClock.elapsed
        if (elapsed >= 0) {
            o["mono"] = JsonValue.Int(elapsed)
            bootClock.boot.takeIf { it >= 0 }?.let { o["boot"] = JsonValue.Int(it) }
        }
        writeFileAtomically(files.hold, CanonicalJson.encode(JsonValue.Obj(o), Dialect.UTF8), random)
        return until
    }

    /** After a real unlock: removes a finished hold; returns when the duress password was used (else null). */
    fun release(): Long? {
        val f = files.hold
        if (!f.exists() || heldUntil() != null) return null
        val since = try {
            ((CanonicalJson.parse(f.readBytes()) as JsonValue.Obj).fields["since"] as? JsonValue.Int)?.v
        } catch (e: Exception) {
            null
        }
        f.delete()
        return since ?: 0
    }

    // ---- sealed records ---------------------------------------------------------------------

    private fun seal(key: ByteArray, info: String, value: JsonValue.Obj): ByteArray {
        val k = CryptoBox.hkdf(key, ByteArray(0), info.toByteArray(Charsets.US_ASCII), 32)
        try {
            val nonce = random.bytes(12)
            return nonce + CryptoBox.sealGcm(k, nonce, CanonicalJson.encode(value, Dialect.UTF8), info.toByteArray(Charsets.US_ASCII))
        } finally {
            k.fill(0)
        }
    }

    private fun open(key: ByteArray, info: String, file: File): Map<String, JsonValue>? {
        val k = CryptoBox.hkdf(key, ByteArray(0), info.toByteArray(Charsets.US_ASCII), 32)
        return try {
            val data = file.readBytes()
            val plain = CryptoBox.openGcm(k, data.copyOf(12), data.copyOfRange(12, data.size), info.toByteArray(Charsets.US_ASCII))
            (CanonicalJson.parse(plain) as? JsonValue.Obj)?.fields
        } catch (e: Exception) {
            null
        } finally {
            k.fill(0)
        }
    }

    /** The hours this second vault holds the real one for (from its own sealed settings). */
    fun hours(decoyKey: ByteArray): Int {
        val h = (open(decoyKey, CONFIG_INFO, files.config)?.get("hours") as? JsonValue.Int)?.v
        return if (h != null && h in MIN_HOURS..MAX_HOURS) h.toInt() else DEFAULT_HOURS
    }

    // ---- setup, removal and the real password's distance ----------------------------------

    /**
     * Creates the second vault for the real session ([realKey]). [appPassword] is the real app password, already checked
     * by the caller; a duress password equal to it or one edit away is refused. [seed] fills the new vault's store
     * (sample or copied items). Inside a duress session ([decoySession]) every check runs and then `generic` is thrown
     * with nothing written.
     */
    fun setup(
        realKey: ByteArray,
        appPassword: ByteArray,
        duressPassword: ByteArray,
        hours: Int,
        decoySession: Boolean,
        seed: (LocalStore) -> Unit,
    ) {
        if (hours !in MIN_HOURS..MAX_HOURS) throw DuressException("hours")
        if (withinOneEdit(appPassword, duressPassword)) {
            throw DuressException(if (MessageDigest.isEqual(appPassword, duressPassword)) "same" else "close")
        }
        if (decoySession) throw DuressException("generic")
        if (configured()) throw DuressException("exists")
        files.dir.deleteRecursively() // leftovers of an earlier second vault
        val key = random.bytes(32)
        try {
            files.dir.mkdirs()
            val created = AppPasswordRecord.create(key, duressPassword, random, params, argon())
            LocalStore.open(files.vault, key, random, null).use { seed(it) }
            writeFileAtomically(files.config, seal(key, CONFIG_INFO, JsonValue.Obj(mapOf("hours" to JsonValue.Int(hours.toLong())))), random)
            val real = linkedMapOf<String, JsonValue>("hours" to JsonValue.Int(hours.toLong()), "created" to JsonValue.Int(clock.now))
            nearRecord(duressPassword)?.let { real["near"] = it }
            writeFileAtomically(files.real, seal(realKey, REAL_INFO, JsonValue.Obj(real)), random)
            // Last: the record is what makes the second vault exist.
            writeFileAtomically(files.record, created.record.encode(), random)
        } catch (e: Exception) {
            files.dir.deleteRecursively()
            files.real.delete()
            throw e
        } finally {
            key.fill(0)
        }
    }

    /** Removes the second vault, its hold and the real vault's record. False when there was none. */
    fun remove(decoySession: Boolean): Boolean {
        if (decoySession) throw DuressException("generic")
        val existed = configured()
        files.dir.deleteRecursively()
        files.hold.delete()
        files.real.delete()
        return existed
    }

    /**
     * "Change app password" inside a duress session (Ruling T5a-b): changes the second vault's password only, with no
     * visible refusal. [current] must open the second vault's record to the open session's key ([decoyKey]); nothing
     * is tried against the real vault (no oracle there). Throttled like the real change through [throttle] (the app
     * password's one wrong-try count): refused during the delay, a wrong current password counted, a right one resets the
     * count. The caller zeroes the arrays.
     */
    fun changeSecondPassword(decoyKey: ByteArray, current: ByteArray, newPassword: ByteArray, throttle: AppPasswordLock) {
        val wait = throttle.waitSeconds()
        if (wait > 0) throw AppPasswordWaitException(wait)
        val opened = tryOpen(current)
        val right = try {
            opened != null && MessageDigest.isEqual(opened, decoyKey)
        } finally {
            opened?.fill(0)
        }
        if (!right) {
            throttle.noteWrongTry()
            throw AppPasswordException(AppPasswordException.Kind.WRONG_PASSWORD)
        }
        throttle.clearFailures()
        val created = AppPasswordRecord.create(decoyKey, newPassword, random, params, argon())
        writeFileAtomically(files.record, created.record.encode(), random)
    }

    /**
     * "Erase this phone's vault" inside a duress session (Ruling T5a-b): only the second vault's data goes (its items,
     * documents, slots, draft, received shares and local extras); the real vault, the hold and the second vault's
     * password stay, so the duress password then opens an empty vault. True when that data is gone.
     */
    fun eraseSecondVault(): Boolean {
        val keep = setOf(files.record.name, files.config.name)
        var ok = true
        for (f in files.dir.listFiles().orEmpty()) {
            if (f.name in keep) continue
            if (!f.deleteRecursively() && f.exists()) ok = false
        }
        return ok
    }

    /** Erase: everything of the second vault goes (true when nothing is left). */
    fun eraseAll(): Boolean {
        files.dir.deleteRecursively()
        files.hold.delete()
        files.real.delete()
        return !files.dir.exists() && !files.hold.exists() && !files.real.exists()
    }

    /** The real vault's duress hours, for Settings (null: not set up or unreadable). */
    fun realHours(realKey: ByteArray): Int? {
        if (!configured()) return null
        return (open(realKey, REAL_INFO, files.real)?.get("hours") as? JsonValue.Int)?.v?.toInt()
    }

    /**
     * Before the real app password changes (or is reset with the recovery phrase): refuses the duress password and
     * anything one edit from it (`near_duress`), from the fingerprint kept at setup and an exact try of the second vault.
     * A duress session checks nothing (desktop review R2: no oracle against the real vault from there).
     */
    fun checkNewPassword(realKey: ByteArray, newPassword: ByteArray, decoySession: Boolean) {
        if (decoySession || !configured()) return
        val near = open(realKey, REAL_INFO, files.real)?.get("near")
        if (near != null && isNear(near, newPassword)) throw DuressException("near_duress")
        tryOpen(newPassword)?.let {
            it.fill(0)
            throw DuressException("near_duress")
        }
    }

    private fun mac(key: ByteArray, tag: String, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }
            .doFinal(tag.toByteArray(Charsets.US_ASCII) + data).copyOf(16)

    private class NearHashes(val whole: ByteArray, val deletions: Set<String>, val positional: Set<String>)

    /** Keyed hashes of the password, of each one-character deletion and of each deletion with its position. */
    private fun nearHashes(key: ByteArray, password: ByteArray): NearHashes {
        val points = codePoints(password)
        val whole = mac(key, "U|", utf8(points))
        val deletions = HashSet<String>()
        val positional = HashSet<String>()
        for (i in points.indices) {
            val rest = utf8(points.filterIndexed { j, _ -> j != i }.toIntArray())
            deletions += Base64Std.encode(mac(key, "U|", rest))
            positional += Base64Std.encode(mac(key, "P$i|", rest))
            rest.fill(0)
        }
        points.fill(0)
        return NearHashes(whole, deletions, positional)
    }

    private fun nearRecord(password: ByteArray): JsonValue.Obj? {
        if (codePoints(password).size > NEAR_LIMIT) return null
        val key = random.bytes(32)
        val h = nearHashes(key, password)
        return JsonValue.Obj(
            mapOf(
                "key" to JsonValue.Str(Base64Std.encode(key)),
                "whole" to JsonValue.Str(Base64Std.encode(h.whole)),
                "deletions" to JsonValue.Arr(h.deletions.sorted().map { JsonValue.Str(it) }),
                "positional" to JsonValue.Arr(h.positional.sorted().map { JsonValue.Str(it) }),
            ),
        ).also { key.fill(0) }
    }

    private fun isNear(record: JsonValue, password: ByteArray): Boolean {
        val r = (record as? JsonValue.Obj)?.fields ?: return false
        return try {
            val key = Base64Std.decodeStrict(r.getValue("key").str())
            val whole = Base64Std.encode(Base64Std.decodeStrict(r.getValue("whole").str()))
            val deletions = r.getValue("deletions").arr().map { it.str() }.toSet()
            val positional = r.getValue("positional").arr().map { it.str() }.toSet()
            if (codePoints(password).size > NEAR_LIMIT + 1) return false
            val mine = nearHashes(key, password)
            val m = Base64Std.encode(mine.whole)
            m == whole || m in deletions || whole in mine.deletions || positional.any { it in mine.positional }
        } catch (e: Exception) {
            false
        }
    }

    companion object {
        const val MIN_HOURS = 1
        const val MAX_HOURS = 168
        const val DEFAULT_HOURS = 24
        /** Passwords longer than this keep only the exact checks. */
        const val NEAR_LIMIT = 256
        private const val CONFIG_INFO = "LocalGateKeys duress config v1"
        private const val REAL_INFO = "LocalGateKeys duress real v1"

        /**
         * The seconds of a hold of [length] still to run on the monotonic clock, anchored at [mono] in boot [boot] (-1 or
         * null: unknown). After a restart (another boot, or the clock below the anchor) only the seconds since that
         * restart count, so the count never exceeds the time really passed.
         */
        internal fun monotonicRemaining(length: Long, mono: Long, boot: Long?, nowElapsed: Long, nowBoot: Long): Long {
            if (nowElapsed < 0) return length // no monotonic clock now: nothing counted
            val restarted = (boot != null && boot >= 0 && nowBoot >= 0 && boot != nowBoot) || nowElapsed < mono
            val counted = if (restarted) nowElapsed else nowElapsed - mono
            return length - maxOf(counted, 0)
        }

        /** The code points of UTF-8 [bytes] (no String is made, so nothing unwipeable is left behind). */
        internal fun codePoints(bytes: ByteArray): IntArray {
            val out = ArrayList<Int>()
            var i = 0
            while (i < bytes.size) {
                val lead = bytes[i].toInt() and 0xFF
                val size = when {
                    lead < 0x80 -> 1
                    lead < 0xE0 -> 2
                    lead < 0xF0 -> 3
                    else -> 4
                }
                var value = if (size == 1) lead else lead and (0x3F shr (size - 1))
                for (j in i + 1 until minOf(i + size, bytes.size)) value = (value shl 6) or (bytes[j].toInt() and 0x3F)
                out += value
                i += size
            }
            return out.toIntArray()
        }

        private fun utf8(points: IntArray): ByteArray {
            val sb = StringBuilder()
            for (p in points) sb.appendCodePoint(p)
            return sb.toString().toByteArray(Charsets.UTF_8)
        }

        /** Whether two passwords (UTF-8) are equal or one insertion, deletion or substitution apart. */
        fun withinOneEdit(first: ByteArray, second: ByteArray): Boolean {
            var a = codePoints(first)
            var b = codePoints(second)
            try {
                if (a.size < b.size) a = b.also { b = a }
                if (a.size - b.size > 1) return false
                var i = 0
                while (i < b.size && a[i] == b[i]) i++
                return if (a.size == b.size) {
                    a.copyOfRange(minOf(i + 1, a.size), a.size).contentEquals(b.copyOfRange(minOf(i + 1, b.size), b.size))
                } else {
                    a.copyOfRange(minOf(i + 1, a.size), a.size).contentEquals(b.copyOfRange(i, b.size))
                }
            } finally {
                a.fill(0)
                b.fill(0)
            }
        }
    }
}
