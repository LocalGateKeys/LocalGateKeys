package app.localgatekeys.core.backup

import app.localgatekeys.core.crypto.Argon2
import app.localgatekeys.core.engine.EngineException
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.VersionVector
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.CryptoBoxException
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.sync.AttachmentRef
import app.localgatekeys.core.sync.AttachmentSync
import app.localgatekeys.core.sync.AttachmentSyncException
import app.localgatekeys.core.sync.Documents

/** A failed phone backup read or write. [reason] is one of the format's reason strings. */
class PhoneBackupException(val reason: String) : Exception(messageFor(reason)) {
    private companion object {
        fun messageFor(reason: String): String = when (reason) {
            "not-a-backup" -> "This is not a LocalGateKeys phone backup."
            "unsupported-version" -> "This backup was made by a newer version of LocalGateKeys. Update the app and try again."
            "bad-kdf" -> "This backup uses unsupported password-protection settings."
            "wrong-password-or-damaged" -> "Wrong password, or the file is damaged."
            "bad-payload" -> "The backup was opened but its contents are not valid."
            "too-large" -> "This file is too large to be a phone backup."
            else -> reason
        }
    }
}

/**
 * The plain header of a backup. [kdf] holds `name` (String) and the three integer costs (Long).
 * [salt] and [nonce] are copied in and handed out as copies; [copy], [equals] and [hashCode] work by content.
 */
class BackupHeader(
    val createdAt: Long,
    val platform: String,
    val kdf: Map<String, Any>,
    salt: ByteArray,
    nonce: ByteArray,
    /** 1, or 2 when the backup carries document files. */
    val version: Int = PhoneBackupFormat.VERSION,
) {
    private val saltBytes: ByteArray = salt.copyOf()
    private val nonceBytes: ByteArray = nonce.copyOf()

    /** A copy of the 16-byte Argon2id salt. */
    val salt: ByteArray get() = saltBytes.copyOf()

    /** A copy of the 12-byte AES-GCM nonce. */
    val nonce: ByteArray get() = nonceBytes.copyOf()

    fun copy(
        createdAt: Long = this.createdAt,
        platform: String = this.platform,
        kdf: Map<String, Any> = this.kdf,
        salt: ByteArray = this.saltBytes,
        nonce: ByteArray = this.nonceBytes,
        version: Int = this.version,
    ): BackupHeader = BackupHeader(createdAt, platform, kdf, salt, nonce, version)

    override fun equals(other: Any?): Boolean =
        other is BackupHeader && createdAt == other.createdAt && platform == other.platform && kdf == other.kdf && version == other.version &&
            saltBytes.contentEquals(other.saltBytes) && nonceBytes.contentEquals(other.nonceBytes)

    override fun hashCode(): Int {
        var h = createdAt.hashCode()
        h = 31 * h + platform.hashCode()
        h = 31 * h + kdf.hashCode()
        h = 31 * h + saltBytes.contentHashCode()
        h = 31 * h + nonceBytes.contentHashCode()
        h = 31 * h + version
        return h
    }

    override fun toString(): String = "BackupHeader(createdAt=$createdAt, platform=$platform, kdf=$kdf, version=$version)"
}

data class PhoneBackup(
    val header: BackupHeader,
    val deviceId: String,
    val appVersion: String,
    val proHint: Boolean,
    val states: List<ItemState>,
    /** Format 2: blob id -> sealed sync blob of a live document's file (shape-checked against [states], not opened). */
    val files: Map<String, ByteArray> = emptyMap(),
) {
    /** Counts only: the states hold plaintext secrets. */
    override fun toString(): String =
        "PhoneBackup(header=$header, deviceId=$deviceId, appVersion=$appVersion, proHint=$proHint, states=${states.size}, files=${files.size})"
}

/** The files a writer includes (blob id -> blob) and the attachment ids of documents left without their file. */
class SelectedFiles(val files: Map<String, ByteArray>, val leftOut: List<String>)

/**
 * The `LGKMBAK1` phone backup file (tests/vectors/backup/README.md; Python reference `phone_backup.py`).
 * Every check before the AES-GCM step runs without any Argon2 work.
 */
object PhoneBackupFormat {
    const val FORMAT = "LGKMBAK1"
    const val VERSION = 1
    const val FILES_VERSION = 2
    const val MAX_FILE_BYTES = 256 shl 20
    const val MAX_STATES = 20000
    const val MAX_FILES = 500

    /** Writers include document files until their sealed blobs add up to this; the rest are left out. */
    const val MAX_BACKUP_FILES_BYTES: Long = 160L * 1024 * 1024

    private const val MAX_INT = (1L shl 53) - 1
    private const val SALT_LEN = 16
    private const val NONCE_LEN = 12
    private const val KEY_LEN = 32
    private val PLATFORMS = setOf("android", "ios")
    private val ENVELOPE_KEYS = setOf("ciphertext", "header")
    private val HEADER_KEYS = setOf("created_at", "format", "kdf", "nonce", "platform", "salt", "version")
    private val KDF_KEYS = setOf("name", "time_cost", "memory_cost_kib", "parallelism")
    private val PAYLOAD_KEYS = setOf("app_version", "device_id", "pro_hint", "states", "version")
    private val PAYLOAD_KEYS_V2 = PAYLOAD_KEYS + "files"
    private val FILE_KEYS = setOf("blob", "data")
    private val STATE_KEYS = setOf("deleted", "deleted_at", "id", "item", "vv")

    private val PRODUCTION_KDF: Map<String, Long> =
        mapOf("time_cost" to 4L, "memory_cost_kib" to 131072L, "parallelism" to 4L)

    private class Envelope(val rawHeader: JsonValue.Obj, val header: BackupHeader, val ciphertext: ByteArray)

    private fun fail(reason: String): Nothing = throw PhoneBackupException(reason)

    fun inspect(data: ByteArray): BackupHeader = parseEnvelope(data).header

    fun read(data: ByteArray, password: String): PhoneBackup {
        val env = parseEnvelope(data)
        val kdf = env.header.kdf
        val key = derive(password, env.header.salt, kdf["time_cost"] as Long, kdf["memory_cost_kib"] as Long, kdf["parallelism"] as Long)
        val plain = try {
            CryptoBox.openGcm(key, env.header.nonce, env.ciphertext, CanonicalJson.encode(env.rawHeader, Dialect.UTF8))
        } catch (e: CryptoBoxException) {
            fail("wrong-password-or-damaged")
        }
        val p = parsePayload(plain, env.header.version)
        return PhoneBackup(env.header, p.deviceId, p.appVersion, p.proHint, p.states, p.files)
    }

    fun write(
        states: List<ItemState>,
        password: String,
        deviceId: String,
        platform: String,
        appVersion: String,
        createdAt: Long,
        proHint: Boolean,
        random: RandomSource,
        kdf: Map<String, Int>? = null,
        files: Map<String, ByteArray> = emptyMap(),
    ): ByteArray {
        val costs: Map<String, Long> = if (kdf == null) {
            PRODUCTION_KDF
        } else {
            if (kdf.keys != setOf("time_cost", "memory_cost_kib", "parallelism")) fail("bad-kdf")
            kdf.mapValues { it.value.toLong() }
        }
        if (!kdfInBounds(costs["time_cost"]!!, costs["memory_cost_kib"]!!, costs["parallelism"]!!)) fail("bad-kdf")
        val ordered = states.sortedBy { it.itemId }
        if (ordered.map { it.itemId }.toSet().size != ordered.size || ordered.size > MAX_STATES ||
            !Identifier.isValid(deviceId) || !validAppVersion(appVersion) || platform !in PLATFORMS ||
            createdAt !in 0..MAX_INT
        ) {
            fail("bad-payload")
        }
        val version = if (files.isEmpty()) VERSION else FILES_VERSION
        if (files.isNotEmpty()) checkFiles(files, ordered)
        val salt = random.bytes(SALT_LEN)
        val nonce = random.bytes(NONCE_LEN)
        require(salt.size == SALT_LEN && nonce.size == NONCE_LEN) { "salt must be 16 bytes and nonce 12 bytes" }
        val header = JsonValue.Obj(
            mapOf(
                "created_at" to JsonValue.Int(createdAt),
                "format" to JsonValue.Str(FORMAT),
                "kdf" to JsonValue.Obj(
                    mapOf(
                        "name" to JsonValue.Str("argon2id"),
                        "time_cost" to JsonValue.Int(costs["time_cost"]!!),
                        "memory_cost_kib" to JsonValue.Int(costs["memory_cost_kib"]!!),
                        "parallelism" to JsonValue.Int(costs["parallelism"]!!),
                    ),
                ),
                "nonce" to JsonValue.Str(Base64Std.encode(nonce)),
                "platform" to JsonValue.Str(platform),
                "salt" to JsonValue.Str(Base64Std.encode(salt)),
                "version" to JsonValue.Int(version.toLong()),
            ),
        )
        val fields = linkedMapOf(
            "app_version" to JsonValue.Str(appVersion),
            "device_id" to JsonValue.Str(deviceId),
            "pro_hint" to JsonValue.Bool(proHint),
            "states" to JsonValue.Arr(ordered.map(::stateJson)),
            "version" to JsonValue.Int(version.toLong()),
        )
        if (files.isNotEmpty()) {
            fields["files"] = JsonValue.Arr(
                files.keys.sorted().map { b ->
                    JsonValue.Obj(mapOf("blob" to JsonValue.Str(b), "data" to JsonValue.Str(Base64Std.encode(files.getValue(b)))))
                },
            )
        }
        val payload = JsonValue.Obj(fields)
        val key = derive(password, salt, costs["time_cost"]!!, costs["memory_cost_kib"]!!, costs["parallelism"]!!, forWrite = true)
        val ct = CryptoBox.sealGcm(
            key, nonce, CanonicalJson.encode(payload, Dialect.UTF8), CanonicalJson.encode(header, Dialect.UTF8),
        )
        val file = JsonValue.Obj(mapOf("ciphertext" to JsonValue.Str(Base64Std.encode(ct)), "header" to header))
        return CanonicalJson.encode(file, Dialect.UTF8)
    }

    // ---- envelope ---------------------------------------------------------------------------

    private fun parseEnvelope(data: ByteArray): Envelope {
        if (data.size > MAX_FILE_BYTES) fail("too-large")
        val env = try {
            CanonicalJson.parse(data)
        } catch (e: JsonException) {
            fail("not-a-backup")
        }
        if (env !is JsonValue.Obj || env.fields.keys != ENVELOPE_KEYS) fail("not-a-backup")
        val header = env.fields["header"]
        if (header !is JsonValue.Obj || header.fields.keys != HEADER_KEYS || header.fields["format"] != JsonValue.Str(FORMAT)) {
            fail("not-a-backup")
        }
        val h = header.fields
        val salt = b64(h["salt"], SALT_LEN)
        val nonce = b64(h["nonce"], NONCE_LEN)
        val ct = b64(env.fields["ciphertext"], null)
        val created = h["created_at"]
        val platform = h["platform"]
        if (platform !is JsonValue.Str || platform.v !in PLATFORMS || created !is JsonValue.Int || created.v !in 0..MAX_INT) {
            fail("not-a-backup")
        }
        val version = h["version"]
        if (version !is JsonValue.Int) fail("not-a-backup")
        if (version.v > FILES_VERSION) fail("unsupported-version")
        if (version.v != VERSION.toLong() && version.v != FILES_VERSION.toLong()) fail("not-a-backup")
        val costs = kdfCosts(h["kdf"]) ?: fail("bad-kdf")
        val kdf = mapOf<String, Any>(
            "name" to "argon2id",
            "time_cost" to costs[0],
            "memory_cost_kib" to costs[1],
            "parallelism" to costs[2],
        )
        return Envelope(header, BackupHeader(created.v, platform.v, kdf, salt, nonce, version.v.toInt()), ct)
    }

    private fun b64(v: JsonValue?, length: Int?): ByteArray {
        if (v !is JsonValue.Str) fail("not-a-backup")
        val raw = try {
            Base64Std.decodeStrict(v.v)
        } catch (e: Base64Exception) {
            fail("not-a-backup")
        }
        if (length != null && raw.size != length) fail("not-a-backup")
        return raw
    }

    /** [time, memory, parallelism] when the kdf object is exactly well formed and in bounds. */
    private fun kdfCosts(v: JsonValue?): List<Long>? {
        if (v !is JsonValue.Obj || v.fields.keys != KDF_KEYS || v.fields["name"] != JsonValue.Str("argon2id")) return null
        val t = v.fields["time_cost"]
        val m = v.fields["memory_cost_kib"]
        val p = v.fields["parallelism"]
        if (t !is JsonValue.Int || m !is JsonValue.Int || p !is JsonValue.Int) return null
        return if (kdfInBounds(t.v, m.v, p.v)) listOf(t.v, m.v, p.v) else null
    }

    private fun kdfInBounds(t: Long, m: Long, p: Long): Boolean =
        t in 1..10 && m in 8192..524288 && p in 1..16

    private fun derive(password: String, salt: ByteArray, t: Long, m: Long, p: Long, forWrite: Boolean = false): ByteArray {
        // A password with a lone surrogate has no UTF-8 form (Python raises); it cannot match any key.
        val hasLoneSurrogate = try {
            Charsets.UTF_8.newEncoder().encode(java.nio.CharBuffer.wrap(password))
            false
        } catch (e: java.nio.charset.CharacterCodingException) {
            true
        }
        if (hasLoneSurrogate) {
            if (forWrite) throw IllegalArgumentException("password is not valid text")
            fail("wrong-password-or-damaged")
        }
        return Argon2.default.derive(password.toByteArray(Charsets.UTF_8), salt, m.toInt(), t.toInt(), p.toInt(), KEY_LEN)
    }

    private fun validAppVersion(s: String): Boolean = s.length in 1..32 && s.all { it.code in 0x20..0x7E }

    // ---- payload ----------------------------------------------------------------------------

    private class Payload(
        val deviceId: String,
        val appVersion: String,
        val proHint: Boolean,
        val states: List<ItemState>,
        val files: Map<String, ByteArray>,
    )

    /** The format-2 rules for [files] against [states] (`bad-payload` on any failure). */
    fun checkFiles(files: Map<String, ByteArray>, states: Iterable<ItemState>) {
        if (files.isEmpty() || files.size > MAX_FILES) fail("bad-payload")
        val sizes = HashMap<String, Long>()
        for (ref in Documents.refs(states)) sizes[ref.blob] = ref.blobSize
        for ((blob, data) in files) {
            try {
                AttachmentSync.checkBlobShape(data, blob)
            } catch (e: AttachmentSyncException) {
                fail("bad-payload")
            }
            if (sizes[blob] != data.size.toLong()) fail("bad-payload") // not named by a live document, or another size
        }
    }

    /**
     * The files a writer includes: live documents in state-id order, each blob ([fetch] returns it or null) while
     * the total stays within [budget] and [MAX_FILES]. A missing blob, or one that does not fit, is left out and its
     * document stays in the backup without its file.
     */
    fun selectFiles(
        states: Iterable<ItemState>,
        fetch: (AttachmentRef) -> ByteArray?,
        budget: Long = MAX_BACKUP_FILES_BYTES,
    ): SelectedFiles {
        val files = LinkedHashMap<String, ByteArray>()
        val leftOut = ArrayList<String>()
        var total = 0L
        for (ref in Documents.refs(states.sortedBy { it.itemId })) {
            if (ref.blob in files) continue
            val blob = fetch(ref)
            if (blob == null || blob.size.toLong() != ref.blobSize || files.size >= MAX_FILES || total + blob.size > budget) {
                leftOut.add(ref.attachmentId)
                continue
            }
            files[ref.blob] = blob
            total += blob.size
        }
        return SelectedFiles(files, leftOut)
    }

    private fun parseFiles(raw: JsonValue?): Map<String, ByteArray> {
        if (raw !is JsonValue.Arr || raw.items.isEmpty() || raw.items.size > MAX_FILES) fail("bad-payload") // count first
        val out = LinkedHashMap<String, ByteArray>()
        var previous: String? = null
        for (entry in raw.items) {
            if (entry !is JsonValue.Obj || entry.fields.keys != FILE_KEYS) fail("bad-payload")
            val blob = entry.fields["blob"]
            val data = entry.fields["data"]
            if (blob !is JsonValue.Str || data !is JsonValue.Str) fail("bad-payload")
            if (previous != null && blob.v <= previous) fail("bad-payload") // unsorted or duplicate
            previous = blob.v
            out[blob.v] = try {
                Base64Std.decodeStrict(data.v)
            } catch (e: Base64Exception) {
                fail("bad-payload")
            }
        }
        return out
    }

    private fun parsePayload(plain: ByteArray, version: Int): Payload {
        val payload = try {
            CanonicalJson.parse(plain)
        } catch (e: JsonException) {
            fail("bad-payload")
        }
        val keys = if (version == FILES_VERSION) PAYLOAD_KEYS_V2 else PAYLOAD_KEYS
        if (payload !is JsonValue.Obj || payload.fields.keys != keys) fail("bad-payload")
        val f = payload.fields
        val appVersion = f["app_version"]
        val deviceId = f["device_id"]
        val proHint = f["pro_hint"]
        val list = f["states"]
        if (f["version"] != JsonValue.Int(version.toLong()) ||
            appVersion !is JsonValue.Str || !validAppVersion(appVersion.v) ||
            deviceId !is JsonValue.Str || !Identifier.isValid(deviceId.v) ||
            proHint !is JsonValue.Bool || list !is JsonValue.Arr || list.items.size > MAX_STATES
        ) {
            fail("bad-payload")
        }
        val states = ArrayList<ItemState>(list.items.size)
        var previous: String? = null
        for (raw in list.items) {
            val state = parseState(raw)
            if (previous != null && state.itemId <= previous) fail("bad-payload")
            previous = state.itemId
            states.add(state)
        }
        var files: Map<String, ByteArray> = emptyMap()
        if (version == FILES_VERSION) {
            files = parseFiles(f["files"])
            checkFiles(files, states)
        }
        return Payload(deviceId.v, appVersion.v, proHint.v, states, files)
    }

    private fun parseState(raw: JsonValue): ItemState {
        if (raw !is JsonValue.Obj || raw.fields.keys != STATE_KEYS) fail("bad-payload")
        val f = raw.fields
        val id = f["id"]
        val deleted = f["deleted"]
        val deletedAt = f["deleted_at"]
        val item = f["item"]
        val vvJson = f["vv"]
        if (id !is JsonValue.Str || deleted !is JsonValue.Bool || vvJson !is JsonValue.Obj) fail("bad-payload")
        val deletedAtValue: Long? = when (deletedAt) {
            JsonValue.Null -> null
            is JsonValue.Int -> deletedAt.v
            else -> fail("bad-payload")
        }
        val itemValue: JsonValue? = when (item) {
            JsonValue.Null -> null
            is JsonValue.Obj -> item
            else -> fail("bad-payload")
        }
        val vv = HashMap<String, Long>()
        for ((device, counter) in vvJson.fields) {
            if (counter !is JsonValue.Int || counter.v < 1 || counter.v > VersionVector.MAX_COUNTER) fail("bad-payload")
            vv[device] = counter.v
        }
        return try {
            ItemState(id.v, vv, deleted.v, deletedAtValue, itemValue)
        } catch (e: EngineException) {
            fail("bad-payload")
        }
    }

    private fun stateJson(s: ItemState): JsonValue = JsonValue.Obj(
        mapOf(
            "deleted" to JsonValue.Bool(s.deleted),
            "deleted_at" to (s.deletedAt?.let { JsonValue.Int(it) } ?: JsonValue.Null),
            "id" to JsonValue.Str(s.itemId),
            "item" to (s.item ?: JsonValue.Null),
            "vv" to JsonValue.Obj(s.vv.mapValues { JsonValue.Int(it.value) }),
        ),
    )
}
