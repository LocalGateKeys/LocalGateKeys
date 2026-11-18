package app.localgatekeys.android.trash

import app.localgatekeys.android.vault.syncDirectory
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.RandomSource
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID

/**
 * Where this phone's never-synced data lives (Recently deleted). Tests use [InMemoryLocalData]. A port of the iPhone's
 * `PhoneLocalHosting` (`ios/App/Local/PhoneLocalData.swift`).
 */
interface LocalDataHosting {
    /** The current data, null while it is not open (the vault locked). */
    val localData: LocalData?

    /** Validates and saves [data], then makes it current. Throws (and changes nothing) when it cannot be saved. */
    fun commitLocalData(data: LocalData)

    /** Set when the stored file could not be read and was reset (shown once on the Recently deleted page). */
    val wasReset: Boolean get() = false
}

/**
 * `local-data.bin` in the vault directory (`filesDir/Vault`, as on the iPhone), sealed with AES-256-GCM under a key
 * derived from the vault's local key: HKDF-SHA256(localKey, salt empty, info "localgatekeys|android-local-data|v1", 32)
 * (a different label from the iPhone's and the editor draft's). File: `version(1) || nonce(12) || ciphertext+tag`.
 *
 * - It never syncs (nothing in sync reads it) and is in no backup: the phone backup is built from the store snapshot,
 *   and the manifest keeps every app file out of Android's cloud backup and device transfer.
 * - Erase vault, Start fresh and the device-removal erase delete the whole vault directory ([VaultEraser]), and it with it.
 * - A file that cannot be read (another key after Start fresh, damage) is set aside as `local-data.bin.bad.<seconds>` and
 *   starts empty, so it can never block unlock; if it cannot be moved aside, saves are refused rather than overwrite it.
 *
 * [localKey] is the open vault's own array (`UnlockedVault.localKey`): read at each call, so after a lock (which zeroes
 * it) nothing is written. Blocking: call off the main thread. Never logs content or key material.
 */
class PhoneLocalData(
    directory: File,
    private val localKey: ByteArray,
    private val random: RandomSource,
    private val now: () -> Long = { System.currentTimeMillis() / 1000 },
    private val dirSync: (File) -> Unit = ::syncDirectory,
) : LocalDataHosting {
    val file: File = File(directory, FILE_NAME)

    @Volatile override var localData: LocalData? = null
        private set

    @Volatile override var wasReset: Boolean = false
        private set

    @Volatile private var blocked = false

    init {
        load()
    }

    private fun load() {
        if (!file.exists()) {
            localData = LocalData.EMPTY
            return
        }
        val key = subkey()
        if (key == null) {
            localData = null // locked already: leave the file for the next unlock
            return
        }
        try {
            localData = decode(file.readBytes(), key)
        } catch (e: Exception) {
            val dir = file.absoluteFile.parentFile
            val t = now()
            var bad = File(dir, "$BAD_PREFIX$t")
            var n = 1
            while (bad.exists()) {
                bad = File(dir, "$BAD_PREFIX$t-$n"); n++
            }
            if (!file.renameTo(bad)) blocked = true
            localData = LocalData.EMPTY
            wasReset = true
        } finally {
            key.fill(0)
        }
    }

    @Synchronized
    override fun commitLocalData(data: LocalData) {
        if (blocked) throw IOException("unreadable local data in place")
        val valid = data.validated()
        val key = subkey() ?: throw IOException("locked")
        val plain = LocalData.encode(valid)
        try {
            val nonce = random.bytes(NONCE_BYTES)
            val sealed = byteArrayOf(FORMAT_VERSION) + nonce + CryptoBox.sealGcm(key, nonce, plain, AAD)
            writeAtomically(sealed)
            localData = valid
        } finally {
            plain.fill(0)
            key.fill(0)
        }
    }

    private fun writeAtomically(bytes: ByteArray) {
        val dir = file.absoluteFile.parentFile ?: throw IOException("no directory")
        if (!dir.isDirectory && !dir.mkdirs() && !dir.isDirectory) throw IOException("create directory")
        val tmp = File(dir, ".${file.name}.${UUID.randomUUID()}.tmp")
        try {
            FileOutputStream(tmp).use { out ->
                out.write(bytes)
                out.flush()
                out.fd.sync()
            }
            try {
                Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: AtomicMoveNotSupportedException) {
                throw IOException("atomic rename not supported")
            }
            dirSync(dir)
        } finally {
            tmp.delete()
        }
    }

    /** The derived key, or null when the vault's key is gone (zeroed by a lock). The caller zeroes it. */
    private fun subkey(): ByteArray? {
        if (localKey.size != 32 || localKey.all { it.toInt() == 0 }) return null
        return CryptoBox.hkdf(localKey, ByteArray(0), INFO, 32)
    }

    override fun toString(): String = "PhoneLocalData"

    companion object {
        const val FILE_NAME = "local-data.bin"
        const val BAD_PREFIX = "local-data.bin.bad."
        private const val FORMAT_VERSION: Byte = 1
        private const val NONCE_BYTES = 12
        private val INFO = "localgatekeys|android-local-data|v1".toByteArray(Charsets.UTF_8)
        private val AAD = "localgatekeys|android-local-data|v1".toByteArray(Charsets.UTF_8)

        /**
         * This phone's travel mode read straight from the file in [directory], with no side effect (an unreadable file
         * is left where it is): OFF when there is no file yet (travel mode was never set), null when it cannot be read.
         * Callers treat null as "everything hidden" (scan A-M4: fail closed). Blocking.
         */
        fun readTravelMode(directory: File, localKey: ByteArray): app.localgatekeys.core.sync.TravelMode.Setting? {
            val f = File(directory, FILE_NAME)
            if (!f.exists()) return app.localgatekeys.core.sync.TravelMode.Setting.OFF
            if (localKey.size != 32 || localKey.all { it.toInt() == 0 }) return null
            val key = CryptoBox.hkdf(localKey, ByteArray(0), INFO, 32)
            return try {
                decode(f.readBytes(), key).travelMode
            } catch (e: Exception) {
                null
            } finally {
                key.fill(0)
            }
        }

        private fun decode(bytes: ByteArray, key: ByteArray): LocalData {
            if (bytes.size <= 1 + NONCE_BYTES + 16 || bytes[0] != FORMAT_VERSION) throw LocalDataException("format")
            val plain = CryptoBox.openGcm(key, bytes.copyOfRange(1, 1 + NONCE_BYTES), bytes.copyOfRange(1 + NONCE_BYTES, bytes.size), AAD)
            try {
                return LocalData.decode(plain)
            } finally {
                plain.fill(0)
            }
        }
    }
}

/** Local data in memory only (tests and previews). */
class InMemoryLocalData(data: LocalData = LocalData.EMPTY) : LocalDataHosting {
    override var localData: LocalData? = data
        private set
    var failSaves = false

    override fun commitLocalData(data: LocalData) {
        if (failSaves) throw IOException("save failed")
        localData = data.validated()
    }
}
