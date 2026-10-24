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

    fun setPairedPeer(p: PinnedPeer) {
        val o = mutableMapOf<String, JsonValue>(
            "device_id" to JsonValue.Str(p.deviceId),
            "group_id" to JsonValue.Str(p.groupId),
            "signing_public" to JsonValue.Str(Base64Std.encode(p.signingPublic)),
            "exchange_public" to JsonValue.Str(Base64Std.encode(p.exchangePublic)),
            "endpoint" to JsonValue.Null,
        )
        p.endpoint?.let {
            o["endpoint"] = JsonValue.Obj(mapOf("host" to JsonValue.Str(it.host), "port" to JsonValue.Int(it.port.toLong())))
        }
        val bytes = CanonicalJson.encode(JsonValue.Obj(o), Dialect.UTF8)
        try {
            write(Slot.PAIRED_PEER, bytes)
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
