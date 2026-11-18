package app.localgatekeys.android.sync

import app.localgatekeys.core.sync.Removal
import app.localgatekeys.core.sync.RemovalWatch
import app.localgatekeys.core.sync.RemovalWatchStore
import java.io.File
import java.io.FileOutputStream

/**
 * This phone's removal watch file (desktop `<vault>.sync-watch.json`, core [Removal]): `filesDir/Vault.sync-watch.json`,
 * next to the vault directory, plain JSON. It holds only ids, the trusted epoch, the install id, the folder's tree URI
 * and the members' public signing keys, so a removal notice can be checked while the vault is locked. Written by every
 * folder run, deleted by Leave / Reset sync and by an erase. Someone who can change it could only stop an erase (and
 * could already delete the vault). App-private storage, excluded from every Android backup and device transfer.
 */
class RemovalWatchFile(val file: File) {
    /** The store a folder run refreshes; [folderUri] is what the file records as the folder. */
    fun store(folderUri: String): RemovalWatchStore = object : RemovalWatchStore {
        override val folder: String = folderUri
        override fun read(): ByteArray? = readBytes()
        override fun write(data: ByteArray) = writeAtomic(data)
        override fun delete() {
            this@RemovalWatchFile.delete()
        }
    }

    /** The stored file (at most [Removal.MAX_WATCH_BYTES] + 1 bytes), or null when there is none or it cannot be read. */
    fun readBytes(): ByteArray? = try {
        if (!file.isFile) {
            null
        } else {
            file.inputStream().use { input ->
                val buf = ByteArray(Removal.MAX_WATCH_BYTES + 1)
                var n = 0
                while (n < buf.size) {
                    val r = input.read(buf, n, buf.size - n)
                    if (r < 0) break
                    n += r
                }
                buf.copyOf(n)
            }
        }
    } catch (e: Exception) {
        null
    }

    /** The parsed watch, or null (missing or not valid). */
    fun load(): RemovalWatch? = Removal.parseWatch(readBytes())

    /** Temp file in the same directory, fsync, atomic rename. */
    fun writeAtomic(data: ByteArray) {
        val dir = file.absoluteFile.parentFile ?: throw java.io.IOException("no parent directory")
        dir.mkdirs()
        val tmp = File(dir, ".${file.name}.${System.nanoTime()}.tmp")
        try {
            FileOutputStream(tmp).use { out ->
                out.write(data)
                out.fd.sync()
            }
            if (!tmp.renameTo(file)) {
                java.nio.file.Files.move(
                    tmp.toPath(), file.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                )
            }
        } finally {
            if (tmp.exists()) tmp.delete()
        }
    }

    /** True when the file is gone afterwards. Never throws. */
    fun delete(): Boolean = try {
        !file.exists() || file.delete() || !file.exists()
    } catch (e: SecurityException) {
        false
    }

    override fun toString(): String = "RemovalWatchFile(${file.name})"

    companion object {
        /** `Vault` (the vault directory) -> `Vault.sync-watch.json` beside it. */
        fun beside(vaultDir: File): RemovalWatchFile = RemovalWatchFile(File(vaultDir.absoluteFile.parentFile, Removal.watchFileName(vaultDir.name)))
    }
}
