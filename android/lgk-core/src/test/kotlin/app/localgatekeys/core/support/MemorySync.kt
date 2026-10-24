package app.localgatekeys.core.support

import app.localgatekeys.core.sync.FolderAccess
import app.localgatekeys.core.sync.FolderAccessException
import app.localgatekeys.core.sync.FolderSyncException
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot

/** In-memory folder: path -> bytes; directories exist when a file lies under them. */
class MemoryFolder : FolderAccess {
    val files = LinkedHashMap<String, ByteArray>()
    val writes = ArrayList<String>()

    /** When set, writeAtomic to a path containing this text throws an IO error (nothing is stored). */
    @Volatile var failWritesContaining: String? = null

    /** Contents as comparable values (ByteArray has no structural equality). */
    fun image(): Map<String, List<Byte>> = files.mapValues { it.value.toList() }

    @Synchronized
    override fun list(dir: String): List<String> {
        val prefix = "$dir/"
        val names = files.keys.filter { it.startsWith(prefix) }.map { it.substring(prefix.length) }.filter { !it.contains("/") }
        if (names.isEmpty() && !exists(dir)) throw FolderAccessException(FolderAccessException.Kind.NOT_FOUND, dir)
        return names
    }

    @Synchronized
    override fun read(path: String, limit: Int): ByteArray {
        val d = files[path] ?: throw FolderAccessException(FolderAccessException.Kind.NOT_FOUND, path)
        return d.copyOf(minOf(limit, d.size))
    }

    @Synchronized
    override fun writeAtomic(path: String, data: ByteArray) {
        val bad = failWritesContaining
        if (bad != null && path.contains(bad)) throw FolderAccessException(FolderAccessException.Kind.IO, "disk full: $path")
        files[path] = data.copyOf()
        writes.add(path)
    }

    @Synchronized
    override fun remove(path: String) {
        files.remove(path) ?: throw FolderAccessException(FolderAccessException.Kind.NOT_FOUND, path)
    }

    @Synchronized
    override fun exists(path: String): Boolean = files.containsKey(path) || files.keys.any { it.startsWith("$path/") }
}

/** In-memory store that counts commits. */
class MemoryStore(snapshot: StoreSnapshot = StoreSnapshot()) : ItemStore {
    @Volatile var snapshot: StoreSnapshot = snapshot
    var commits = 0
        private set
    private val lock = Any()

    /** When true, commit throws before changing anything. */
    @Volatile var failCommits = false

    override fun load(): StoreSnapshot = synchronized(lock) { snapshot }

    override fun commit(change: StoreChange) = synchronized(lock) {
        if (failCommits) throw FolderSyncException("store-offline")
        if (change.baseRevision != snapshot.revision) throw FolderSyncException("vault-changed")
        commits += 1
        snapshot = StoreSnapshot(change.records, change.meta, change.sync, snapshot.revision + 1)
    }
}
