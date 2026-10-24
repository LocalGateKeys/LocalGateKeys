package app.localgatekeys.android.vault

import android.util.Log
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.pro.LicenseKeys
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.DeviceIdentityException
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.CryptoBoxException
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * The encrypted item store in `filesDir/Vault` (core [ItemStore]); a port of `ios/AppShared/LocalStore.swift`.
 *
 * Layout of the directory:
 * - `CURRENT`: the committed revision as ASCII decimal plus a newline. It is the only commit point.
 * - `g<rev>/state.blob`: sealed state (revision, item index id -> file, sync meta, sync group state).
 * - `g<rev>/i<n>.blob`: one sealed blob per record (its synced wrapper), records in id order.
 * - `.lock`: the `FileChannel.lock()` target serializing writers across processes.
 *
 * Every blob is `nonce(12) || AES-256-GCM(ciphertext || tag)` under the 32-byte local key; the AAD binds a
 * blob to its revision (and item id), so blobs cannot be swapped between generations or items.
 *
 * Commit: write a full new generation into `tmp-<uuid>/` (each file fsynced, then the directory), rename it to
 * `g<rev+1>`, fsync the vault directory, then write `CURRENT` through a temp file, fsync, atomic rename and a
 * directory fsync. A crash at any point before the last rename leaves the previous revision current and
 * readable; stray `tmp-*` and newer `g*` entries are removed by the next commit. The previous generation is
 * kept one commit longer so a reader racing a commit still finds its files; a reader that loses that race
 * retries from `CURRENT`, up to three reads in all (see [load]).
 *
 * Locking: an in-process lock (per canonical directory, so two instances in one process serialize too) and
 * then a file lock. The file lock is held only while the generation is written; the settings hint, which is
 * app code, runs after both locks are released.
 *
 * Android notes: there are no per-file protection classes here, and no per-file backup exclusion API: the
 * manifest sets `allowBackup="false"` and excludes every domain from cloud backup and device transfer, which
 * keeps the vault out of any backup (the iPhone's `excludeFromBackup` has no counterpart). File modes come
 * from the app's private data directory.
 *
 * The local key is copied in, kept only for the life of the instance ([close] zeroes it) and never logged.
 */
class LocalStore private constructor(
    val directory: File,
    localKey: ByteArray,
    private val random: RandomSource,
    private val settings: AppSettings?,
    private val dirSync: (File) -> Unit,
) : ItemStore, AutoCloseable {
    private val key: ByteArray = localKey.copyOf()
    private val lock: Any = locks.computeIfAbsent(lockKey(directory)) { Any() }

    @Volatile private var closed = false

    /** Set by [beginClose] without the lock: every later read and write (and a running commit, before CURRENT) refuses. */
    @Volatile private var closing = false

    /** Test seam: called after a generation's state blob was read, before its item blobs are. */
    internal var afterStateRead: ((Long) -> Unit)? = null

    /** Test seam: the reads and stats that decide absence versus failure. */
    internal var fs: StoreFs = NioStoreFs

    /** Test seam: called with the synced `CURRENT` temp file just before it is renamed over `CURRENT`. */
    internal var beforeCurrentRename: ((File) -> Unit)? = null

    /** Test seam: called after the new generation is renamed into place, before `CURRENT` is written. */
    internal var beforeCurrentWrite: (() -> Unit)? = null

    init {
        try {
            if (!directory.isDirectory && !directory.mkdirs() && !directory.isDirectory) {
                throw LocalStoreException(LocalStoreException.Kind.IO, "create directory")
            }
        } catch (e: SecurityException) {
            throw LocalStoreException(LocalStoreException.Kind.IO, "create directory")
        }
    }

    /**
     * Zeroes the key copy; the store is unusable afterwards. Takes the same lock as [load] and [commit], so it
     * waits for a running one to finish: no blob is ever sealed or opened with a zeroed key.
     */
    override fun close() {
        // Called from inside a load or commit on this thread (a callback): zeroing the key now would corrupt it.
        check(!Thread.holdsLock(lock)) { "close() inside a store operation" }
        synchronized(lock) {
            closed = true
            key.fill(0)
        }
    }

    /**
     * Shuts the write gate at once without waiting for the store lock (the app locked): a commit not yet started
     * refuses, and one in flight stops at its next seal or before writing `CURRENT`, so its generation never becomes
     * visible (the stray `g<rev>` is removed by the next commit). Call [close] afterwards, off the main thread.
     */
    fun beginClose() {
        closing = true
    }

    private fun checkOpen() {
        if (closed || closing) throw LocalStoreException(LocalStoreException.Kind.BAD_LOCAL_KEY, "closed")
    }

    // MARK: ItemStore

    /**
     * Reads the generation CURRENT names. A commit racing this read may move CURRENT and prune the generation
     * being read (a missing `state.blob` or `i<n>.blob`, or no generation left). Only in that case, when CURRENT
     * has moved past the revision being read, the read re-resolves CURRENT and retries (at most
     * [MAX_READ_ATTEMPTS] reads). If CURRENT has not moved the error is thrown as is: a file missing from the
     * current generation is damage or tampering, never retried away.
     */
    override fun load(): StoreSnapshot = synchronized(lock) { loadLocked() }

    private fun loadLocked(): StoreSnapshot {
        checkOpen()
        var attempt = 1
        while (true) {
            val current = currentRevision()
            if (current == 0L) return StoreSnapshot()
            try {
                return visibleSnapshot(current)
            } catch (e: LocalStoreException) {
                if (attempt >= MAX_READ_ATTEMPTS || !isMissingFile(e) || currentRevision() == current) throw e
                attempt++
            }
        }
    }

    private fun isMissingFile(e: LocalStoreException): Boolean = when (e.kind) {
        LocalStoreException.Kind.IO -> e.detail.startsWith("missing ")
        LocalStoreException.Kind.CORRUPT -> e.detail.startsWith("no generation")
        else -> false
    }

    /**
     * The generation CURRENT names. Only when that generation (or its state blob) is absent from disk, i.e. it
     * never got there before a power loss, does this fall back to the newest older generation. Any other failure
     * (I/O, authentication, corrupt data) throws: tampering or damage is reported, never silently rolled back,
     * and [commit] refuses to run on top of it.
     */
    private fun visibleSnapshot(current: Long): StoreSnapshot {
        if (stateExists(current)) return read(current)
        for (rev in generations().filter { it < current }.sortedDescending()) {
            if (stateExists(rev)) return read(rev)
        }
        throw LocalStoreException(LocalStoreException.Kind.CORRUPT, "no generation at or below $current")
    }

    /** Absent only when the file system says so; any other stat failure counts as present so [read] reports it. */
    private fun stateExists(rev: Long): Boolean = !fs.notExists(File(generationDir(rev), "state.blob").toPath())

    /**
     * Atomic and durable before it returns. The in-process lock and the file lock are held only while the
     * generation is written; the plan hint in [AppSettings] is published after both are released.
     */
    override fun commit(change: StoreChange) {
        val committed = synchronized(lock) {
            checkOpen()
            withFileLock { write(change) }
        }
        publishLimitHint(committed)
    }

    private fun write(change: StoreChange): StoreSnapshot {
        val current = currentRevision()
        // The revision readers actually see (CURRENT, or the fallback generation if it is missing).
        val visible = if (current == 0L) 0L else visibleSnapshot(current).revision
        if (change.baseRevision != visible) {
            throw LocalStoreException(LocalStoreException.Kind.STALE, "expected ${change.baseRevision}, actual $visible")
        }
        val rev = current + 1
        val tmp = File(directory, "tmp-${UUID.randomUUID()}")
        val gen = generationDir(rev)
        var step = "create tmp"
        // The new generation is renamed into place before CURRENT names it. If the commit fails (or the app locks)
        // in between, that generation is removed again: CURRENT never named it, and a stray g1 next to a missing
        // CURRENT would read as damage.
        var generationRenamed = false
        var currentPublished = false
        fun abandon() {
            tmp.deleteRecursively()
            if (generationRenamed && !currentPublished) {
                gen.deleteRecursively()
                try {
                    dirSync(directory)
                } catch (e: IOException) {
                    // best effort: the next commit prunes newer generations as well
                }
            }
        }
        try {
            if (!tmp.mkdir()) throw IOException("mkdir")
            val index = ArrayList<JsonValue>()
            for ((n, id) in change.records.keys.sortedWith { a, b -> Scalars.compare(a, b) }.withIndex()) {
                val file = "i$n.blob"
                step = "write $file"
                val plain = CanonicalJson.encode(change.records.getValue(id), Dialect.UTF8)
                writeFileSynced(File(tmp, file), seal(plain, ITEM_AAD + "$rev|" + id))
                index.add(JsonValue.Obj(mapOf("id" to JsonValue.Str(id), "file" to JsonValue.Str(file))))
            }
            val state = JsonValue.Obj(
                mapOf(
                    "v" to JsonValue.Int(1),
                    "revision" to JsonValue.Int(rev),
                    "items" to JsonValue.Arr(index),
                    "meta" to JsonValue.Obj(change.meta.mapValues { encodeMeta(it.value) }),
                    "sync" to (change.sync?.let { encodeSync(it) } ?: JsonValue.Null),
                ),
            )
            step = "write state.blob"
            writeFileSynced(File(tmp, "state.blob"), seal(CanonicalJson.encode(state, Dialect.UTF8), STATE_AAD + "$rev"))
            step = "sync tmp"
            dirSync(tmp)
            step = "rename generation"
            if (gen.exists()) gen.deleteRecursively() // leftover of a crashed commit
            moveAtomically(tmp, gen)
            generationRenamed = true
            step = "sync directory"
            dirSync(directory)
            step = "write CURRENT"
            beforeCurrentWrite?.invoke()
            checkOpen()
            writeDurably("$rev\n".toByteArray(Charsets.US_ASCII), File(directory, "CURRENT")) { currentPublished = true }
        } catch (e: LocalStoreException) {
            abandon()
            throw e
        } catch (e: JsonException) {
            abandon()
            throw LocalStoreException(LocalStoreException.Kind.IO, "encode")
        } catch (e: IOException) {
            abandon()
            throw LocalStoreException(LocalStoreException.Kind.IO, step)
        } catch (e: RuntimeException) {
            abandon()
            throw LocalStoreException(LocalStoreException.Kind.IO, step)
        }
        prune(rev - 1, rev)
        return StoreSnapshot(change.records, change.meta, change.sync, rev)
    }

    /**
     * Best effort: a failed settings write never fails a commit that is already durable. The hint is only an
     * optimization for screens that check the free plan before the store is opened.
     */
    private fun publishLimitHint(snap: StoreSnapshot) {
        val hints = settings ?: return
        try {
            val full = !ItemLimit.allows(ItemLimit.Action.CREATE, snap, false) &&
                ItemLimit.validLicense(snap, LicenseKeys.production) == null
            hints.planFullRevision = if (full) snap.revision else null
        } catch (e: RuntimeException) {
            // Computing or writing the hint failed after a durable commit: the commit still succeeded. The hint
            // stays as it was and the next commit publishes again. Log the class only, never content.
            Log.w("LocalStore", "plan hint not published: " + e.javaClass.simpleName)
        }
    }

    // MARK: files

    private fun generationDir(rev: Long) = File(directory, "g$rev")

    private fun generations(): List<Long> =
        (directory.list() ?: emptyArray()).mapNotNull { generationNumber(it) }

    /**
     * 0 only when CURRENT does not exist and no generation exists. Any other read error, or a missing CURRENT
     * next to existing generations, throws, so a failed read is never taken for an empty vault (which the next
     * commit would overwrite).
     */
    private fun currentRevision(): Long {
        val file = File(directory, "CURRENT")
        val buf = ByteArray(32)
        val n = try {
            fs.newInputStream(file.toPath()).use { it.read(buf) }
        } catch (e: NoSuchFileException) {
            // Exactly "does not exist" (ENOENT); every other failure below is an I/O error, never an empty vault.
            if (generations().isNotEmpty()) {
                throw LocalStoreException(LocalStoreException.Kind.CORRUPT, "CURRENT missing but generations exist")
            }
            return 0L
        } catch (e: IOException) {
            throw LocalStoreException(LocalStoreException.Kind.IO, "CURRENT")
        }
        val rev = if (n > 0) String(buf, 0, n, Charsets.US_ASCII).trim().toLongOrNull() else null
        if (rev == null || rev <= 0) throw LocalStoreException(LocalStoreException.Kind.CORRUPT, "CURRENT")
        return rev
    }

    private fun readFile(f: File): ByteArray = try {
        fs.readAllBytes(f.toPath())
    } catch (e: NoSuchFileException) {
        throw LocalStoreException(LocalStoreException.Kind.IO, "missing ${f.name}")
    } catch (e: IOException) {
        throw LocalStoreException(LocalStoreException.Kind.IO, "read ${f.name}")
    }

    private fun read(rev: Long): StoreSnapshot {
        val gen = generationDir(rev)
        try {
            val state = CanonicalJson.parse(open(readFile(File(gen, "state.blob")), STATE_AAD + "$rev"))
            val o = (state as? JsonValue.Obj)?.fields ?: throw corrupt("state")
            val items = (o["items"] as? JsonValue.Arr)?.items
            val meta = (o["meta"] as? JsonValue.Obj)?.fields
            val sync = o["sync"]
            if (o["revision"] != JsonValue.Int(rev) || items == null || meta == null || sync == null) throw corrupt("state")
            afterStateRead?.invoke(rev)
            val records = LinkedHashMap<String, JsonValue>()
            for (entry in items) {
                val e = (entry as? JsonValue.Obj)?.fields ?: throw corrupt("index")
                val id = (e["id"] as? JsonValue.Str)?.v
                val file = (e["file"] as? JsonValue.Str)?.v
                if (id == null || file == null || file.contains('/') || file.contains('\\') || file == ".." || file == "." ||
                    file.contains('\u0000')
                ) {
                    throw corrupt("index")
                }
                val plain = open(readFile(File(gen, file)), ITEM_AAD + "$rev|" + id)
                records[id] = CanonicalJson.parse(plain)
            }
            return StoreSnapshot(
                records, meta.mapValues { decodeMeta(it.value) },
                if (sync == JsonValue.Null) null else decodeSync(sync), rev,
            )
        } catch (e: JsonException) {
            throw corrupt("json")
        }
    }

    /** Writes a new file and flushes it to stable storage. */
    private fun writeFileSynced(f: File, bytes: ByteArray) {
        if (f.exists()) throw IOException("exists")
        FileOutputStream(f).use { out ->
            out.write(bytes)
            out.flush()
            out.fd.sync()
        }
    }

    private fun moveAtomically(from: File, to: File) {
        try {
            Files.move(from.toPath(), to.toPath(), StandardCopyOption.ATOMIC_MOVE)
        } catch (e: AtomicMoveNotSupportedException) {
            throw IOException("atomic rename not supported")
        }
    }

    /** Temp file `.<name>.<uuid>.tmp` in the same directory, fsync, atomic rename over the target, directory fsync. */
    private fun writeDurably(bytes: ByteArray, target: File, renamed: () -> Unit = {}) {
        val dir = target.absoluteFile.parentFile
        val tmp = File(dir, ".${target.name}.${UUID.randomUUID()}.tmp")
        try {
            writeFileSynced(tmp, bytes)
            beforeCurrentRename?.invoke(tmp)
            checkOpen() // the app locked during the temp file's fsync: never publish
            try {
                Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: AtomicMoveNotSupportedException) {
                throw IOException("atomic rename not supported")
            }
            renamed()
            dirSync(dir)
        } catch (e: Throwable) {
            tmp.delete()
            throw e
        }
    }

    /** Keeps [oldest]..[current]; drops `tmp-*`, newer generations and stray `CURRENT` temp files. */
    private fun prune(oldest: Long, current: Long) {
        for (name in directory.list() ?: return) {
            var drop = name.startsWith("tmp-") || (name.startsWith(".CURRENT.") && name.endsWith(".tmp"))
            val n = generationNumber(name)
            if (n != null) drop = n < oldest || n > current
            if (drop) File(directory, name).deleteRecursively()
        }
    }

    /** The in-process lock is already held; this takes the cross-process lock and releases it on return. */
    private fun <T> withFileLock(body: () -> T): T {
        val channel = try {
            FileChannel.open(File(directory, ".lock").toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        } catch (e: IOException) {
            throw LocalStoreException(LocalStoreException.Kind.IO, "lock")
        }
        channel.use {
            val fileLock = try {
                it.lock()
            } catch (e: IOException) {
                throw LocalStoreException(LocalStoreException.Kind.IO, "lock")
            } catch (e: java.nio.channels.OverlappingFileLockException) {
                throw LocalStoreException(LocalStoreException.Kind.IO, "lock")
            }
            try {
                return body()
            } finally {
                try {
                    fileLock.release()
                } catch (e: IOException) {
                    // closing the channel releases it
                }
            }
        }
    }

    // MARK: crypto

    private fun seal(plain: ByteArray, aad: String): ByteArray {
        checkOpen()
        val nonce = random.bytes(NONCE_BYTES)
        return nonce + CryptoBox.sealGcm(key, nonce, plain, aad.toByteArray(Charsets.UTF_8))
    }

    private fun open(blob: ByteArray, aad: String): ByteArray {
        if (blob.size < MIN_BLOB) throw corrupt("blob")
        return try {
            CryptoBox.openGcm(key, blob.copyOfRange(0, NONCE_BYTES), blob.copyOfRange(NONCE_BYTES, blob.size), aad.toByteArray(Charsets.UTF_8))
        } catch (e: CryptoBoxException) {
            throw corrupt("authentication")
        }
    }

    companion object {
        private val locks = ConcurrentHashMap<String, Any>()
        private const val STATE_AAD = "localgatekeys|local-state|v1|"
        private const val ITEM_AAD = "localgatekeys|local-item|v1|"
        private const val NONCE_BYTES = 12
        private const val MIN_BLOB = 28
        internal const val MAX_READ_ATTEMPTS = 3
        private const val SET_ASIDE_MARKER = "-unreadable-"

        private fun lockKey(dir: File): String = try {
            dir.canonicalPath
        } catch (e: IOException) {
            dir.absoluteFile.normalize().path
        }

        private fun corrupt(what: String) = LocalStoreException(LocalStoreException.Kind.CORRUPT, what)

        /**
         * Opens (creating the directory if needed) the store at [dir] with the 32-byte local key, which the caller
         * obtains from the unlock layer. [settings] receives the plan hint after each commit (null: none).
         * Throws [LocalStoreException] `BAD_LOCAL_KEY` when the key is not 32 bytes.
         */
        fun open(dir: File, localKey: ByteArray?, random: RandomSource, settings: AppSettings?): LocalStore =
            openForTest(dir, localKey, random, settings, ::syncDirectory)

        internal fun openForTest(
            dir: File,
            localKey: ByteArray?,
            random: RandomSource,
            settings: AppSettings?,
            dirSync: (File) -> Unit,
        ): LocalStore {
            // Never creates a key and never touches the directory when there is none (the extension rule).
            if (localKey == null) throw LocalStoreException(LocalStoreException.Kind.NO_LOCAL_KEY)
            if (localKey.size != 32) throw LocalStoreException(LocalStoreException.Kind.BAD_LOCAL_KEY, "key length")
            return LocalStore(dir, localKey, random, settings, dirSync)
        }

        /** What the first-run / unlock layer does next; see [bootstrap]. */
        enum class BootstrapAction { FIRST_RUN, OPEN, VAULT_WITHOUT_KEY }

        /**
         * Pure decision for the unlock layer; it creates and overwrites nothing. Deletes set-aside copies of
         * [dir] first (best effort). [OPEN]: the wrapped key exists. [VAULT_WITHOUT_KEY]: store files exist but
         * the key does not (a restored copy; offer Start fresh, never make a new key over them). [FIRST_RUN]:
         * neither; a directory holding only `.lock` counts as empty.
         */
        fun bootstrap(dir: File, wrappedKeyExists: Boolean): BootstrapAction {
            removeSetAside(dir)
            return when {
                wrappedKeyExists -> BootstrapAction.OPEN
                hasStoreFiles(dir) -> BootstrapAction.VAULT_WITHOUT_KEY
                else -> BootstrapAction.FIRST_RUN
            }
        }

        /**
         * The committed revision from the plain `CURRENT` file, readable without the key (screens check it
         * against `AppSettings.planFullRevision` before unlocking). Null when absent or unreadable.
         */
        fun committedRevision(dir: File): Long? = try {
            String(File(dir, "CURRENT").readBytes(), Charsets.US_ASCII).trim().toLongOrNull()
        } catch (e: IOException) {
            null
        } catch (e: SecurityException) {
            null
        }

        /** True when [dir] holds a committed store: `CURRENT` or a `g<rev>` generation. */
        fun hasStoreFiles(dir: File): Boolean =
            (dir.list() ?: return false).any { it == "CURRENT" || generationNumber(it) != null }

        /**
         * Renames [dir] to `<name>-unreadable-<now>` (or `-<now>-<n>`) next to it (Start fresh, when it cannot be
         * deleted). Nothing reads it again; [removeSetAside] deletes it later.
         */
        fun setAside(dir: File, now: Long) {
            val parent = dir.absoluteFile.parentFile ?: throw LocalStoreException(LocalStoreException.Kind.IO, "set aside")
            var target = File(parent, dir.name + SET_ASIDE_MARKER + now)
            var n = 1
            while (target.exists()) {
                target = File(parent, dir.name + SET_ASIDE_MARKER + now + "-" + n)
                n++
            }
            try {
                Files.move(dir.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE)
            } catch (e: IOException) {
                throw LocalStoreException(LocalStoreException.Kind.IO, "set aside")
            }
        }

        /** Best effort: deletes the set-aside copies of [nextTo] (`<name>-unreadable-*`). Errors are ignored. */
        fun removeSetAside(nextTo: File) {
            val parent = nextTo.absoluteFile.parentFile ?: return
            val prefix = nextTo.name + SET_ASIDE_MARKER
            for (name in parent.list() ?: return) {
                if (name.startsWith(prefix)) File(parent, name).deleteRecursively()
            }
        }

        /** `g<digits>` to its number; anything else (`gx`, `g`, `tmp-*`) is not a generation. */
        private fun generationNumber(name: String): Long? =
            if (name.length > 1 && name[0] == 'g' && name.drop(1).all { it in '0'..'9' }) name.drop(1).toLongOrNull() else null

        // MARK: state encoding (CanonicalJson, never another JSON library)

        private fun optStr(s: String?): JsonValue = if (s == null) JsonValue.Null else JsonValue.Str(s)
        private fun optInt(n: Long?): JsonValue = if (n == null) JsonValue.Null else JsonValue.Int(n)
        private fun ints(d: Map<String, Long>): JsonValue = JsonValue.Obj(d.mapValues { JsonValue.Int(it.value) })
        private fun b64(b: ByteArray): JsonValue = JsonValue.Str(Base64Std.encode(b))

        internal fun encodeMeta(m: SyncMeta): JsonValue = JsonValue.Obj(
            mapOf(
                "digest" to optStr(m.digest), "body" to optStr(m.body), "updated_at" to optInt(m.updatedAt),
                "vv" to ints(m.vv), "deleted" to JsonValue.Bool(m.deleted), "deleted_at" to optInt(m.deletedAt),
            ),
        )

        internal fun encodeSync(s: SyncGroupState): JsonValue = JsonValue.Obj(
            mapOf(
                "group_id" to JsonValue.Str(s.groupId), "epoch" to JsonValue.Int(s.epoch), "key" to b64(s.key),
                "device_id" to JsonValue.Str(s.identity.deviceId), "signing" to b64(s.identity.signingPrivateKey),
                "exchange" to b64(s.identity.exchangePrivateKey), "install_id" to JsonValue.Str(s.installId),
                "has_folder" to JsonValue.Bool(s.hasFolder), "last_seen" to ints(s.lastSeen),
                "peer_digests" to JsonValue.Obj(s.peerDigests.mapValues { JsonValue.Str(it.value) }),
                "members_epoch" to JsonValue.Int(s.membersEpoch),
                "members" to JsonValue.Arr(s.members.map { JsonValue.Str(it) }),
                "keyring" to (s.keyring?.let { b64(it) } ?: JsonValue.Null), "own_counter" to JsonValue.Int(s.ownCounter),
                // Pinned view signing keys (audit M-7), the iPhone's LocalStore JSON.
                "view_signers" to JsonValue.Obj(s.viewSigners.mapValues { JsonValue.Str(it.value) }),
            ),
        )

        private class Fields(v: JsonValue) {
            val o: Map<String, JsonValue> = (v as? JsonValue.Obj)?.fields ?: throw corrupt("state")

            fun str(k: String): String = (o[k] as? JsonValue.Str)?.v ?: throw corrupt(k)
            fun optStr(k: String): String? = if (o[k] == JsonValue.Null) null else str(k)
            fun int(k: String): Long = (o[k] as? JsonValue.Int)?.v ?: throw corrupt(k)
            fun optInt(k: String): Long? = if (o[k] == JsonValue.Null) null else int(k)
            fun bool(k: String): Boolean = (o[k] as? JsonValue.Bool)?.v ?: throw corrupt(k)
            fun bytes(k: String): ByteArray = try {
                Base64Std.decodeStrict(str(k))
            } catch (e: Base64Exception) {
                throw corrupt(k)
            }
            fun dict(k: String): Map<String, JsonValue> = (o[k] as? JsonValue.Obj)?.fields ?: throw corrupt(k)
            fun ints(k: String): Map<String, Long> = dict(k).mapValues { (it.value as? JsonValue.Int)?.v ?: throw corrupt(k) }
        }

        internal fun decodeMeta(v: JsonValue): SyncMeta {
            val f = Fields(v)
            return SyncMeta(f.optStr("digest"), f.optStr("body"), f.optInt("updated_at"), f.ints("vv"), f.bool("deleted"), f.optInt("deleted_at"))
        }

        internal fun decodeSync(v: JsonValue): SyncGroupState {
            val f = Fields(v)
            val identity = try {
                DeviceIdentity(f.str("device_id"), f.bytes("signing"), f.bytes("exchange"))
            } catch (e: DeviceIdentityException) {
                throw corrupt("identity")
            }
            val members = (f.o["members"] as? JsonValue.Arr)?.items ?: throw corrupt("members")
            // Pinned view signing keys (audit M-7); absent in states stored before the pins existed.
            val signers = if (!f.o.containsKey("view_signers")) emptyMap() else f.dict("view_signers").mapValues {
                (it.value as? JsonValue.Str)?.v ?: throw corrupt("view_signers")
            }
            return SyncGroupState(
                groupId = f.str("group_id"), epoch = f.int("epoch"), key = f.bytes("key"), identity = identity,
                installId = f.str("install_id"), hasFolder = f.bool("has_folder"), lastSeen = f.ints("last_seen"),
                peerDigests = f.dict("peer_digests").mapValues { (it.value as? JsonValue.Str)?.v ?: throw corrupt("peer_digests") },
                membersEpoch = f.int("members_epoch"),
                members = members.map { (it as? JsonValue.Str)?.v ?: throw corrupt("members") },
                keyring = if (f.o["keyring"] == JsonValue.Null) null else f.bytes("keyring"),
                ownCounter = f.int("own_counter"),
                viewSigners = signers,
            )
        }
    }
}

/** The file-system reads whose failures must never be mistaken for "absent"; tests substitute failing versions. */
internal interface StoreFs {
    /** True only when the file system definitely says the path does not exist. */
    fun notExists(p: java.nio.file.Path): Boolean
    fun readAllBytes(p: java.nio.file.Path): ByteArray
    fun newInputStream(p: java.nio.file.Path): java.io.InputStream
}

internal object NioStoreFs : StoreFs {
    override fun notExists(p: java.nio.file.Path): Boolean = Files.notExists(p)
    override fun readAllBytes(p: java.nio.file.Path): ByteArray = Files.readAllBytes(p)
    override fun newInputStream(p: java.nio.file.Path): java.io.InputStream = Files.newInputStream(p)
}
