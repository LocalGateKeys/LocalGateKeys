package app.localgatekeys.android.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.PairingOffer
import app.localgatekeys.core.lan.PinnedPeer
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.FolderAccess
import app.localgatekeys.core.sync.FolderAccessException
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import java.io.File
import kotlinx.coroutines.CompletableDeferred

// Ports of the fakes in ios/LocalGateKeysTests/SyncCoordinatorTests.swift and TestDoubles.swift.

/** The desktop's tests/vectors/sync (tests fail, never skip, when missing). */
object SyncVectors {
    val root: File = File(checkNotNull(System.getProperty("lgk.repoRoot")) { "lgk.repoRoot not set" }, "tests/vectors/sync")
        .also { check(it.isDirectory) { "vectors missing: $it" } }

    fun data(name: String): ByteArray = File(root, name).also { check(it.isFile) { "vector missing: $it" } }.readBytes()

    fun json(name: String): Map<String, JsonValue> = (CanonicalJson.parse(data(name)) as JsonValue.Obj).fields

    fun obj(v: JsonValue?): Map<String, JsonValue> = (v as? JsonValue.Obj)?.fields ?: emptyMap()

    fun str(v: JsonValue?): String = (v as? JsonValue.Str)?.v ?: ""

    fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    fun identity(who: String): DeviceIdentity {
        val p = obj(obj(obj(json("identities.json")["devices"])[who])["private"])
        return DeviceIdentity(str(p["device_id"]), Base64Std.decodeStrict(str(p["signing_private"])), Base64Std.decodeStrict(str(p["exchange_private"])))
    }

    fun qrText(): String = String(data("lan/qr_payload.txt"), Charsets.UTF_8)

    fun lanNow(): Long = (json("lan/expected_lan.json")["now"] as JsonValue.Int).v

    fun lanGroupKey(): GroupKey {
        val lan = json("lan/expected_lan.json")
        val offer = PairingOffer.parseQr(qrText())
        return GroupKey(offer.groupId, 1, hex(str(obj(lan["reply_no_endpoint"])["key_hex"])))
    }

    const val PASSWORD = "correct horse battery staple 42"

    /**
     * The name B announces in the vector enrollment: `lan/enroll_reply_no_endpoint.bin` is bound to it, so a QR join
     * with any other name fails to open the reply (scripts/make_sync_vectors.py; Swift `vectorDeviceName`).
     */
    const val DEVICE_NAME = "Ilias’s iPhone é"
}

/** In-memory folder: path -> bytes; directories exist when a file lies under them. [onRead] runs before each read. */
class MemoryFolder : FolderAccess {
    val files = LinkedHashMap<String, ByteArray>()
    @Volatile var onRead: ((String) -> Unit)? = null

    @Synchronized fun snapshot(): Map<String, List<Byte>> = files.mapValues { it.value.toList() }

    @Synchronized fun put(path: String, data: ByteArray) { files[path] = data }

    @Synchronized fun get(path: String): ByteArray? = files[path]

    override fun list(dir: String): List<String> = synchronized(this) {
        val prefix = "$dir/"
        val names = files.keys.filter { it.startsWith(prefix) }.map { it.substring(prefix.length) }.filter { !it.contains("/") }
        if (names.isEmpty() && !exists(dir)) throw FolderAccessException(FolderAccessException.Kind.NOT_FOUND, dir)
        names
    }

    override fun read(path: String, limit: Int): ByteArray {
        onRead?.invoke(path)
        synchronized(this) {
            val d = files[path] ?: throw FolderAccessException(FolderAccessException.Kind.NOT_FOUND, path)
            return d.copyOf(minOf(limit, d.size))
        }
    }

    @Synchronized override fun writeAtomic(path: String, data: ByteArray) { files[path] = data.copyOf() }

    @Synchronized override fun remove(path: String) {
        files.remove(path) ?: throw FolderAccessException(FolderAccessException.Kind.NOT_FOUND, path)
    }

    @Synchronized override fun exists(path: String): Boolean = files.containsKey(path) || files.keys.any { it.startsWith("$path/") }
}

/**
 * Every folder URI opens [folder]; [opened] records the URIs. A URI in [revoked] has lost its permission: it is not
 * available and does not open. [kept] records every [keepOnly] call (the permission that stays; null: none).
 */
class FakeFolders(val folder: MemoryFolder) : FolderOpening {
    val opened: MutableList<String> = java.util.Collections.synchronizedList(ArrayList())
    val revoked: MutableSet<String> = java.util.Collections.synchronizedSet(HashSet())
    val kept: MutableList<String?> = java.util.Collections.synchronizedList(ArrayList())
    override fun open(uri: String): FolderAccess {
        opened.add(uri)
        if (uri in revoked) throw FolderAccessException(FolderAccessException.Kind.IO, "the chosen folder is no longer available")
        return folder
    }

    override fun isAvailable(uri: String): Boolean = uri !in revoked

    override fun keepOnly(uri: String?) {
        kept.add(uri)
    }
}

/**
 * Fake Wi-Fi transport. [exchange] answers view exchanges; while [gated] each exchange blocks (interruptibly) until
 * [release], so overlapping runs would show in [maxConcurrent].
 */
class FakeLan : LanTransporting {
    private val lock = Object()
    @Volatile var exchange: (List<ItemState>) -> List<ItemState> = { emptyList() }
    @Volatile var enrollReply: (ByteArray) -> ByteArray = { throw LanSocketException("refused") }
    /** Runs before [enrollReply] (a dial still in flight). */
    @Volatile var enrollHold: (() -> Unit)? = null
    /** Reports the dial as connected before [enrollHold]. */
    @Volatile var connectsBeforeHold = false
    var exchanges = 0; private set
    var enrolls = 0; private set
    var maxConcurrent = 0; private set
    private var active = 0
    private var waiters = 0
    val sent = ArrayList<List<ItemState>>()
    var gated = false
        set(v) = synchronized(lock) { field = v }

    override fun exchangeViews(
        peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: List<ItemState>, ownCounter: Long,
    ): List<ItemState> {
        synchronized(lock) {
            exchanges++; active++; maxConcurrent = maxOf(maxConcurrent, active); sent.add(localStates)
        }
        try {
            synchronized(lock) {
                if (gated) {
                    waiters++
                    try {
                        while (gated) lock.wait()
                    } finally {
                        waiters--
                    }
                }
            }
            return exchange(localStates)
        } finally {
            synchronized(lock) { active-- }
        }
    }

    override fun enroll(endpoint: LanEndpoint, request: ByteArray, onConnected: () -> Unit): ByteArray {
        synchronized(lock) { enrolls++ }
        if (connectsBeforeHold) onConnected()
        enrollHold?.invoke()
        return enrollReply(request)
    }

    val waiting: Int get() = synchronized(lock) { waiters }

    fun release() = synchronized(lock) {
        gated = false
        lock.notifyAll()
    }
}

class CountingAutoFill : AutoFillIdentityRefreshing {
    @Volatile var calls = 0; private set
    override suspend fun syncDidFinish(store: ItemStore) { synchronized(this) { calls++ } }
}

/** Holds every publish until [release], and records overlapping publishes. */
class GatedAutoFill : AutoFillIdentityRefreshing {
    private val released = CompletableDeferred<Unit>()
    var calls = 0; private set
    var maxConcurrent = 0; private set
    var waiting = 0; private set
    private var active = 0

    override suspend fun syncDidFinish(store: ItemStore) {
        synchronized(this) { calls++; active++; maxConcurrent = maxOf(maxConcurrent, active); waiting++ }
        try {
            released.await()
        } finally {
            synchronized(this) { active--; waiting-- }
        }
    }

    fun release() { released.complete(Unit) }
}

/** An [ItemStore] safe to touch from the coordinator's background work; counts loads and commits. */
class LockedStore(s: StoreSnapshot = StoreSnapshot()) : ItemStore {
    private var snap = s
    var commits = 0; private set
    var loads = 0; private set
    val snapshot: StoreSnapshot get() = synchronized(this) { snap }

    /** Runs inside each load (tests use it to lock at a chosen moment). */
    @Volatile var onLoad: (() -> Unit)? = null

    /**
     * [onLoad] runs after the snapshot is taken (a held load returns what it read before it was held) and outside the
     * store's monitor, so a held load never blocks other readers or commits.
     */
    override fun load(): StoreSnapshot {
        val s = synchronized(this) { loads++; snap }
        onLoad?.invoke()
        return s
    }

    @Synchronized override fun commit(change: StoreChange) {
        check(change.baseRevision == snap.revision) { "stale: ${change.baseRevision} != ${snap.revision}" }
        snap = StoreSnapshot(change.records, change.meta, change.sync, snap.revision + 1)
        commits++
    }
}

/** Records sleeps; returns at once (no real waiting). */
class NoSleep {
    val slept: MutableList<Long> = java.util.Collections.synchronizedList(ArrayList())
    val fn: suspend (Long) -> Unit = { slept.add(it) }
}

/** A gate a blocking fake waits on until the test opens it. Uninterruptible: cancelling the caller does not open it. */
class AsyncGate {
    private val lock = Object()
    private var open = false
    var waiting = 0; private set

    fun await() {
        var interrupted = false
        synchronized(lock) {
            waiting++
            while (!open) {
                try { lock.wait() } catch (_: InterruptedException) { interrupted = true }
            }
            waiting--
        }
        if (interrupted) Thread.currentThread().interrupt()
    }

    fun open() = synchronized(lock) { open = true; lock.notifyAll() }
}

fun noteRecord(i: Int, title: String = "Note"): Pair<String, JsonValue> {
    val id = "00000000-0000-4000-8000-%012d".format(i)
    val r = JsonValue.Obj(
        mapOf(
            "id" to JsonValue.Str(id), "kind" to JsonValue.Str("note"), "title" to JsonValue.Str("$title $i"),
            "created_at" to JsonValue.Int(1_700_000_000), "updated_at" to JsonValue.Int(1_700_000_000L + i),
            "favorite" to JsonValue.Bool(false), "tags" to JsonValue.Arr(emptyList()),
            "payload" to JsonValue.Obj(
                mapOf("body" to JsonValue.Str("body $i"), "fields" to JsonValue.Arr(emptyList()), "template_id" to JsonValue.Null),
            ),
        ),
    )
    return id to Wrapper.make(Namespace.ITEM, Normalise.normalForm(Namespace.ITEM, r))
}

/** The states device [device] would publish for [records]. */
fun peerStates(records: Map<String, JsonValue>, device: String, now: Long): List<ItemState> =
    SyncMeta.localView(records, emptyMap(), device, now).states.values.sortedBy { it.itemId }
