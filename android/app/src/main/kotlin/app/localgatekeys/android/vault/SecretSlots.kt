package app.localgatekeys.android.vault

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.PairingException
import app.localgatekeys.core.lan.PinnedPeer
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.CryptoBoxException
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.sync.KeptIdentity
import java.io.File
import java.io.FileOutputStream
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/** The secrets kept in `secrets.bin`. [key] is the entry name inside the sealed JSON object. */
enum class Slot(val key: String) {
    PAIRED_PEER("paired-peer"),
    INSTALL_ID("install-id"),
    HELLO_COUNTER("hello-counter"),
    PEER_COUNTERS("peer-counters"),
    FOLDER_URI("folder-uri"),
    /** Emergency access (sub-plan 08): this vault's heir folder tree URI, the requester keys and the shards held. */
    HEIR_FOLDER_URI("heir-folder-uri"),
    HEIR_IDENTITY("heir-identity"),
    HEIR_SHARDS("heir-shards"),
    /**
     * What Leave sync kept of this device's membership ([KeptIdentity], design 2026-11-17): its id, keys, group and
     * counters, reused when it joins the same group again. Sealed here like the other sync secrets, so it never leaves
     * this device (no sync, no backup, no export); erasing the vault deletes it with this file.
     */
    KEPT_IDENTITY("kept-identity"),
}

/** [CORRUPT]: the file does not open (wrong key, tampering, damage). [MALFORMED]: a slot's content is invalid. */
class SecretSlotsException(val kind: Kind, message: String = kind.name) : Exception(message) {
    enum class Kind { CORRUPT, MALFORMED }
}

/**
 * Named secret slots in one file, sealed with the 32-byte local key (AES-256-GCM, a fresh random nonce per
 * write, AAD `localgatekeys|android-secrets|v1`; file = nonce(12) || ciphertext+tag). The plaintext is one
 * canonical JSON object of slot name to standard base64 value. A missing file is an empty store.
 *
 * Every write replaces the whole file through a temp file (`.<name>.<random>.tmp`), fsync and an atomic
 * rename, so a crash or failure leaves the previous file intact. The instance keeps its own copy of the key;
 * [close] zeroes it. Thread-safe, and every read-modify-write on one file is serialized by a process-wide lock
 * keyed by the file's canonical path, so two instances over the same file never lose each other's updates.
 *
 * After the rename the directory is fsynced ([syncDirectory]) so the new name survives power loss; a failure
 * there is reported to the caller (the data file is already replaced) rather than hidden.
 *
 * The internal constructor's [beforeRename] and [dirSync] are test seams.
 */
class SecretSlots internal constructor(
    private val file: File,
    localKey: ByteArray,
    private val random: RandomSource,
    private val beforeRename: (File) -> Unit,
    private val dirSync: (File) -> Unit,
) : AutoCloseable {
    constructor(file: File, localKey: ByteArray, random: RandomSource) :
        this(file, localKey, random, {}, ::syncDirectory)

    private val key: ByteArray
    private val lock: Any = locks.computeIfAbsent(file.canonicalPath) { Any() }
    private var closed = false

    /** Set by [beginClose] without the lock: later reads and writes refuse; a write in flight stops before its file is replaced. */
    @Volatile private var closing = false

    init {
        require(localKey.size == 32) { "local key must be 32 bytes" }
        key = localKey.copyOf()
    }

    /** Shuts the slots at once without waiting for the lock (the app locked). Call [close] afterwards, off the main thread. */
    fun beginClose() {
        closing = true
    }

    override fun close() {
        synchronized(lock) {
            key.fill(0)
            closed = true
        }
    }

    fun read(s: Slot): ByteArray? = synchronized(lock) {
        val m = load()
        try {
            m[s.key]?.copyOf()
        } finally {
            m.values.forEach { it.fill(0) }
        }
    }

    fun write(s: Slot, v: ByteArray) {
        update(s) { v }
    }

    /**
     * Atomically replaces the slot with [f] of its current value (null when empty), under the file lock.
     * [f]'s result is copied, not zeroed; the caller owns it.
     */
    fun update(s: Slot, f: (ByteArray?) -> ByteArray) {
        synchronized(lock) {
            val m = load()
            try {
                val next = f(m[s.key]?.copyOf())
                m.remove(s.key)?.fill(0)
                m[s.key] = next.copyOf()
                store(m)
            } finally {
                m.values.forEach { it.fill(0) }
            }
        }
    }

    fun delete(s: Slot) {
        synchronized(lock) {
            val m = load()
            try {
                val removed = m.remove(s.key)
                if (s == Slot.PAIRED_PEER) sealedPeer = null // the pin goes with its peer
                if (removed != null) {
                    removed.fill(0)
                    store(m)
                }
            } finally {
                m.values.forEach { it.fill(0) }
            }
        }
    }

    /** The paired LAN peer, or null. A stored peer whose endpoint is not a LAN address is refused (MALFORMED). */
    fun pairedPeer(): PinnedPeer? {
        val bytes = read(Slot.PAIRED_PEER) ?: return null
        try {
            val o = (CanonicalJson.parse(bytes) as? JsonValue.Obj ?: throw malformed("paired peer")).fields
            fun str(k: String) = (o[k] as? JsonValue.Str ?: throw malformed("paired peer $k")).v
            val signing = Base64Std.decodeStrict(str("signing_public"))
            val exchange = Base64Std.decodeStrict(str("exchange_public"))
            var endpoint: LanEndpoint? = null
            val e = o["endpoint"]
            if (e is JsonValue.Obj) {
                val host = e.fields["host"] as? JsonValue.Str ?: throw malformed("paired peer host")
                val port = e.fields["port"] as? JsonValue.Int ?: throw malformed("paired peer port")
                if (port.v !in 0..65535) throw malformed("paired peer port")
                endpoint = LanEndpoint(host.v, port.v.toInt())
            }
            return PinnedPeer(str("device_id"), str("group_id"), signing, exchange, endpoint)
        } catch (e: JsonException) {
            throw malformed("paired peer")
        } catch (e: Base64Exception) {
            throw malformed("paired peer")
        } catch (e: PairingException) {
            throw malformed("paired peer endpoint")
        } finally {
            bytes.fill(0)
        }
    }

    /**
     * Stores [p] as the paired peer. Rewriting the same peer (same device and group id) keeps the fields this version
     * does not know and the sealed-hello pin (`"hello":3`, `LAN_SYNC_V3.md` 2.5); [fresh] (a new pairing) drops them, so
     * a pin goes only with its peer. [sealed] pins the peer (a pairing through a version-2 offer).
     */
    fun setPairedPeer(p: PinnedPeer, sealed: Boolean = false, fresh: Boolean = false) {
        synchronized(lock) {
            var written: ByteArray? = null
            update(Slot.PAIRED_PEER) { old ->
                val kept = if (fresh || old == null) emptyMap() else sameEntry(old, p.deviceId, p.groupId)
                val o = kept.toMutableMap()
                o["device_id"] = JsonValue.Str(p.deviceId)
                o["group_id"] = JsonValue.Str(p.groupId)
                o["signing_public"] = JsonValue.Str(Base64Std.encode(p.signingPublic))
                o["exchange_public"] = JsonValue.Str(Base64Std.encode(p.exchangePublic))
                o["endpoint"] = p.endpoint?.let {
                    JsonValue.Obj(mapOf("host" to JsonValue.Str(it.host), "port" to JsonValue.Int(it.port.toLong())))
                } ?: JsonValue.Null
                if (sealed) o[HELLO] = JsonValue.Int(SEALED_HELLO)
                old?.fill(0)
                CanonicalJson.encode(JsonValue.Obj(o), Dialect.UTF8).also { written = it }
            }
            written?.fill(0)
            sealedPeer = if (sealed) p.deviceId else if (fresh || sealedPeer != p.deviceId) null else sealedPeer
        }
    }

    /** The stored entry's fields when it is [deviceId]'s in [groupId], else nothing (an unreadable entry: nothing). */
    private fun sameEntry(old: ByteArray, deviceId: String, groupId: String): Map<String, JsonValue> {
        val o = try {
            (CanonicalJson.parse(old) as? JsonValue.Obj)?.fields
        } catch (e: JsonException) {
            null
        } ?: return emptyMap()
        return if (o["device_id"] == JsonValue.Str(deviceId) && o["group_id"] == JsonValue.Str(groupId)) o else emptyMap()
    }

    /** True when the paired peer [deviceId] is pinned to the sealed hello (`"hello":3` in its entry). */
    fun pairedPeerSealed(deviceId: String): Boolean = synchronized(lock) {
        if (sealedPeer == deviceId) return true
        val bytes = read(Slot.PAIRED_PEER) ?: return false
        try {
            val o = (CanonicalJson.parse(bytes) as? JsonValue.Obj)?.fields ?: return false
            val pinned = o["device_id"] == JsonValue.Str(deviceId) && o[HELLO] == JsonValue.Int(SEALED_HELLO)
            if (pinned) sealedPeer = deviceId
            pinned
        } catch (e: JsonException) {
            false
        } finally {
            bytes.fill(0)
        }
    }

    /**
     * Pins the paired peer [deviceId] to the sealed hello after a sealed session (spec 2.5): writes `"hello":3` into its
     * entry once, keeping every other field. Returns false when [deviceId] is not the paired peer. Kept in memory too.
     */
    fun markPairedPeerSealed(deviceId: String): Boolean = synchronized(lock) {
        if (pairedPeerSealed(deviceId)) return true
        val bytes = read(Slot.PAIRED_PEER) ?: return false
        val o = try {
            (CanonicalJson.parse(bytes) as? JsonValue.Obj)?.fields
        } catch (e: JsonException) {
            null
        } finally {
            bytes.fill(0)
        }
        if (o == null || o["device_id"] != JsonValue.Str(deviceId)) return false
        val next = CanonicalJson.encode(JsonValue.Obj(o + (HELLO to JsonValue.Int(SEALED_HELLO))), Dialect.UTF8)
        try {
            write(Slot.PAIRED_PEER, next)
        } finally {
            next.fill(0)
        }
        sealedPeer = deviceId
        true
    }

    /** The paired peer pinned to the sealed hello, as last read or written (the in-memory pin). */
    @Volatile private var sealedPeer: String? = null

    /**
     * The identity Leave sync kept ([Slot.KEPT_IDENTITY]), or null. One that cannot be read is treated as none (a join
     * then makes a new identity, as before) and is deleted, best effort.
     */
    fun keptIdentity(): KeptIdentity? {
        val bytes = read(Slot.KEPT_IDENTITY) ?: return null
        return try {
            KeptIdentity.decode(bytes)
        } catch (e: IllegalArgumentException) {
            try {
                delete(Slot.KEPT_IDENTITY)
            } catch (_: Exception) {
            }
            null
        } finally {
            bytes.fill(0)
        }
    }

    /** Stores [kept], replacing the one kept before (at most one per vault). */
    fun setKeptIdentity(kept: KeptIdentity) {
        val bytes = kept.encode()
        try {
            write(Slot.KEPT_IDENTITY, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    /** This installation's install id: 32 lowercase hex characters (16 random bytes), created once on first use. */
    fun installId(): String = synchronized(lock) {
        val existing = read(Slot.INSTALL_ID)
        if (existing != null) {
            val s = try {
                Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(existing)).toString()
            } catch (e: java.nio.charset.CharacterCodingException) {
                existing.fill(0)
                throw malformed("install id")
            }
            existing.fill(0)
            if (s.isEmpty()) throw malformed("install id")
            return s
        }
        val id = Hex.lower(random.bytes(16))
        write(Slot.INSTALL_ID, id.toByteArray(Charsets.UTF_8))
        id
    }

    private fun malformed(what: String) = SecretSlotsException(SecretSlotsException.Kind.MALFORMED, "malformed $what")

    // --- sealed file

    private fun load(): MutableMap<String, ByteArray> {
        check(!closed && !closing) { "SecretSlots is closed" }
        if (!file.exists()) return mutableMapOf()
        val raw = file.readBytes()
        if (raw.size < MIN_FILE) throw SecretSlotsException(SecretSlotsException.Kind.CORRUPT, "secrets file too short")
        var plain: ByteArray? = null
        try {
            plain = CryptoBox.openGcm(key, raw.copyOfRange(0, 12), raw.copyOfRange(12, raw.size), AAD)
            val o = (CanonicalJson.parse(plain) as? JsonValue.Obj ?: throw corrupt()).fields
            val out = mutableMapOf<String, ByteArray>()
            for ((k, v) in o) out[k] = Base64Std.decodeStrict((v as? JsonValue.Str ?: throw corrupt()).v)
            return out
        } catch (e: CryptoBoxException) {
            throw corrupt()
        } catch (e: JsonException) {
            throw corrupt()
        } catch (e: Base64Exception) {
            throw corrupt()
        } finally {
            plain?.fill(0)
        }
    }

    private fun corrupt() = SecretSlotsException(SecretSlotsException.Kind.CORRUPT, "secrets file is damaged")

    private fun store(m: Map<String, ByteArray>) {
        check(!closed && !closing) { "SecretSlots is closed" }
        val o = JsonValue.Obj(m.mapValues { JsonValue.Str(Base64Std.encode(it.value)) })
        val plain = CanonicalJson.encode(o, Dialect.UTF8)
        try {
            val nonce = random.bytes(12)
            val blob = nonce + CryptoBox.sealGcm(key, nonce, plain, AAD)
            writeAtomically(blob)
        } finally {
            plain.fill(0)
            m.values.forEach { it.fill(0) }
        }
    }

    private fun writeAtomically(blob: ByteArray) {
        val dir = file.absoluteFile.parentFile ?: throw IOException("no parent directory")
        dir.mkdirs()
        val tmp = File(dir, ".${file.name}.${Hex.lower(random.bytes(8))}.tmp")
        try {
            FileOutputStream(tmp).use { out ->
                out.write(blob)
                out.flush()
                out.fd.sync()
            }
            beforeRename(tmp)
            check(!closing) { "SecretSlots is closed" }
            try {
                Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: AtomicMoveNotSupportedException) {
                throw IOException("atomic rename not supported", e)
            }
            dirSync(dir)
        } catch (e: Throwable) {
            tmp.delete()
            throw e
        }
    }

    companion object {
        private val locks = java.util.concurrent.ConcurrentHashMap<String, Any>()
        private val AAD = "localgatekeys|android-secrets|v1".toByteArray(Charsets.UTF_8)
        private const val MIN_FILE = 12 + 16

        /** The paired-peer entry's sealed-hello pin (desktop `lan_peers` entry field `"hello":3`). */
        private const val HELLO = "hello"
        private const val SEALED_HELLO: Long = 3
    }
}

/**
 * fsyncs a directory so a rename inside it is durable. Android (Linux) can open directories read-only, so a
 * failure here is a real I/O fault and is reported, never swallowed.
 */
internal fun syncDirectory(dir: File) {
    try {
        val fd = Os.open(dir.path, OsConstants.O_RDONLY, 0)
        try {
            Os.fsync(fd)
        } finally {
            Os.close(fd)
        }
    } catch (e: ErrnoException) {
        throw IOException("cannot fsync directory ${dir.path}: ${e.message}", e)
    }
}
