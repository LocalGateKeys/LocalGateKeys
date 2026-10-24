package app.localgatekeys.core.group

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.CryptoBoxException
import app.localgatekeys.core.primitives.Ed25519
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import java.security.MessageDigest

/** Parsed `LGKSYNC1` header line. */
data class ViewHeader(
    val format: Long,
    val groupId: String,
    val deviceId: String,
    val epoch: Long,
    val counter: Long,
    val writtenAt: Long,
) {
    internal fun json(): JsonValue = JsonValue.Obj(
        mapOf(
            "format" to JsonValue.Int(format), "group_id" to JsonValue.Str(groupId), "device_id" to JsonValue.Str(deviceId),
            "epoch" to JsonValue.Int(epoch), "counter" to JsonValue.Int(counter), "written_at" to JsonValue.Int(writtenAt),
        ),
    )
}

/** Device view files (desktop `sync.group.encode_view` / `decode_view`). */
object ViewFile {
    private val MAGIC_BYTES = "LGKSYNC1\n".toByteArray(Charsets.UTF_8)

    /** A copy of the file magic. */
    val MAGIC: ByteArray get() = MAGIC_BYTES.copyOf()
    const val FORMAT: Long = 1
    const val MAX_BYTES: Int = 64 shl 20
    const val MAX_RECORDS: Int = 20_000
    private val HEADER_FIELDS = setOf("format", "group_id", "device_id", "epoch", "counter", "written_at")

    private fun checkHeaderValues(device: JsonValue?, epoch: JsonValue?, counter: JsonValue?, writtenAt: JsonValue?) {
        val validDevice = device is JsonValue.Str && Identifier.isValid(device.v)
        if (!validDevice || !SealedItem.isInt(counter) || !SealedItem.isInt(writtenAt)) {
            throw SyncFormatException("bad-header", "invalid device_id/counter/written_at")
        }
        if (!SealedItem.isInt(epoch)) throw SyncFormatException("bad-header", "invalid epoch")
    }

    /** Serialises [states] (sorted by id) into one view file. Nonces: one per item in id order, then the file nonce. */
    fun encode(
        key: GroupKey,
        deviceId: String,
        counter: Long,
        states: List<ItemState>,
        now: UnixClock,
        random: RandomSource,
        maxRecords: Int = MAX_RECORDS,
    ): ByteArray {
        val writtenAt = now.now
        checkHeaderValues(JsonValue.Str(deviceId), JsonValue.Int(key.epoch), JsonValue.Int(counter), JsonValue.Int(writtenAt))
        // Ids are ASCII, so String order equals code point order.
        val ordered = states.sortedBy { it.itemId }
        if (ordered.size > maxRecords) throw SyncFormatException("too-many-records", "${ordered.size} > $maxRecords")
        for (i in 1 until ordered.size) {
            if (ordered[i - 1].itemId == ordered[i].itemId) throw SyncFormatException("duplicate-id", ordered[i].itemId)
        }
        val used = HashSet<List<Byte>>()
        fun uniqueNonce(): ByteArray {
            val n = SealedItem.nonce(random)
            if (!used.add(n.toList())) throw SyncFormatException("nonce-reuse", "nonce source repeated a nonce")
            return n
        }
        val sealed = ArrayList<JsonValue>(ordered.size)
        for (s in ordered) sealed.add(SealedItem.seal(key, s, uniqueNonce()))
        val header = CanonicalJson.encode(
            ViewHeader(FORMAT, key.groupId, deviceId, key.epoch, counter, writtenAt).json(),
            Dialect.UTF8,
        )
        val nonce = uniqueNonce()
        val body = CryptoBox.sealGcm(key.fileKey, nonce, CanonicalJson.encode(JsonValue.Arr(sealed), Dialect.UTF8), header)
        return MAGIC_BYTES + header + byteArrayOf(0x0A) + nonce + body
    }

    /** Parses, authenticates and opens a device view file. */
    fun decode(
        data: ByteArray,
        key: GroupKey,
        expectedDeviceId: String?,
        maxBytes: Int = MAX_BYTES,
        maxRecords: Int = MAX_RECORDS,
    ): Pair<ViewHeader, List<ItemState>> {
        if (data.size > maxBytes) throw SyncFormatException("too-large", "${data.size} > $maxBytes")
        val (header, headerBytes, end) = parseHeader(data)
        if (header.groupId != key.groupId) throw SyncFormatException("group-mismatch", "view belongs to another group")
        if (header.epoch != key.epoch) throw SyncFormatException("epoch-mismatch", "view was written under another epoch")
        if (expectedDeviceId != null && header.deviceId != expectedDeviceId) {
            throw SyncFormatException("device-mismatch", "view was written by another device")
        }
        return header to openPayload(data, key, headerBytes, end, maxRecords)
    }

    /** The header of a view file (structure checks only, nothing authenticated): for signing and tests. */
    fun decodeHeader(data: ByteArray): ViewHeader = parseHeader(data).first

    private fun parseHeader(data: ByteArray): Triple<ViewHeader, ByteArray, Int> {
        if (data.size < MAGIC_BYTES.size || !MAGIC_BYTES.indices.all { data[it] == MAGIC_BYTES[it] }) {
            throw SyncFormatException("bad-magic", "not a LocalGateKeys sync view")
        }
        var end = -1
        for (i in MAGIC_BYTES.size until data.size) {
            if (data[i] == 0x0A.toByte()) {
                end = i
                break
            }
        }
        if (end < 0) throw SyncFormatException("bad-header", "missing header line")
        val headerBytes = data.copyOfRange(MAGIC_BYTES.size, end)
        val parsed = try {
            CanonicalJson.parse(headerBytes)
        } catch (e: JsonException) {
            throw SyncFormatException("bad-header", "header is not JSON")
        }
        val h = (parsed as? JsonValue.Obj)?.fields
        if (h == null || h.keys != HEADER_FIELDS) throw SyncFormatException("bad-header", "header fields")
        if (h["format"] != JsonValue.Int(FORMAT)) throw SyncFormatException("bad-header", "unsupported format")
        val groupId = (h["group_id"] as? JsonValue.Str)?.v
        if (groupId == null || !Identifier.isValid(groupId)) throw SyncFormatException("bad-header", "group_id")
        checkHeaderValues(h["device_id"], h["epoch"], h["counter"], h["written_at"])
        val canonical = try {
            CanonicalJson.encode(parsed, Dialect.UTF8)
        } catch (e: JsonException) {
            throw SyncFormatException("bad-header", "header is not canonical-JSON safe")
        }
        if (!canonical.contentEquals(headerBytes)) throw SyncFormatException("header-noncanonical", "header line is not canonical JSON")
        val deviceId = (h["device_id"] as JsonValue.Str).v
        val epoch = (h["epoch"] as JsonValue.Int).v
        val counter = (h["counter"] as JsonValue.Int).v
        val writtenAt = (h["written_at"] as JsonValue.Int).v
        return Triple(ViewHeader(FORMAT, groupId, deviceId, epoch, counter, writtenAt), headerBytes, end)
    }

    private fun openPayload(data: ByteArray, key: GroupKey, headerBytes: ByteArray, end: Int, maxRecords: Int): List<ItemState> {
        val blob = data.copyOfRange(end + 1, data.size)
        if (blob.size < SealedItem.NONCE_LENGTH + SealedItem.TAG_LENGTH) throw SyncFormatException("bad-payload", "payload too short")
        val plain = try {
            CryptoBox.openGcm(
                key.fileKey, blob.copyOfRange(0, SealedItem.NONCE_LENGTH),
                blob.copyOfRange(SealedItem.NONCE_LENGTH, blob.size), headerBytes,
            )
        } catch (e: CryptoBoxException) {
            throw SyncFormatException("auth-failed", "view authentication failed")
        }
        val payload = try {
            CanonicalJson.parse(plain)
        } catch (e: JsonException) {
            throw SyncFormatException("bad-payload", "payload is not JSON")
        }
        val records = (payload as? JsonValue.Arr)?.items ?: throw SyncFormatException("bad-payload", "payload must be a list")
        if (records.size > maxRecords) throw SyncFormatException("too-many-records", "${records.size} > $maxRecords")
        val recordKey = key.recordKey
        val states = ArrayList<ItemState>(records.size)
        val seen = HashSet<String>()
        for (rec in records) {
            val o = (rec as? JsonValue.Obj)?.fields ?: throw SyncFormatException("bad-payload", "record must be an object")
            val rid = (o["id"] as? JsonValue.Str)?.v
            if (rid != null && !seen.add(rid)) throw SyncFormatException("duplicate-id", rid)
            states.add(SealedItem.open(key, rec, recordKey))
        }
        return states
    }
}

/**
 * View signature files (desktop `group.sign_view` / `verify_view_signature`, audit 2026-10-24 M-7; format in the
 * "View signature" block of `sync/group.py`). The view file itself is unchanged; the writer stores this next to it.
 */
object ViewSignature {
    private val LABEL = "lgk-sync-view-sig-v1|".toByteArray(Charsets.US_ASCII)
    const val FORMAT: Long = 1
    const val MAX_BYTES: Int = 4096
    private val FIELDS = setOf("format", "group_id", "device_id", "epoch", "counter", "view_sha256", "signing_public", "sig")

    private fun sha256Hex(data: ByteArray): String = Hex.lower(MessageDigest.getInstance("SHA-256").digest(data))

    private fun body(header: ViewHeader, raw: ByteArray, signingPublic: ByteArray): Map<String, JsonValue> = mapOf(
        "format" to JsonValue.Int(FORMAT), "group_id" to JsonValue.Str(header.groupId),
        "device_id" to JsonValue.Str(header.deviceId), "epoch" to JsonValue.Int(header.epoch),
        "counter" to JsonValue.Int(header.counter), "view_sha256" to JsonValue.Str(sha256Hex(raw)),
        "signing_public" to JsonValue.Str(Base64Std.encode(signingPublic)),
    )

    /** The signature file for the view file [raw] (whose header is [header]), signed by [identity]. */
    fun sign(raw: ByteArray, header: ViewHeader, identity: DeviceIdentity): ByteArray {
        val b = body(header, raw, identity.signingPublicKey)
        val sig = identity.sign(LABEL + CanonicalJson.encode(JsonValue.Obj(b), Dialect.UTF8))
        return CanonicalJson.encode(JsonValue.Obj(b + ("sig" to JsonValue.Str(Base64Std.encode(sig)))), Dialect.UTF8)
    }

    private fun malformed(detail: String): Nothing = throw SyncFormatException("sig-malformed", detail)

    private fun b64(v: JsonValue?, length: Int): ByteArray {
        val s = (v as? JsonValue.Str)?.v ?: malformed("base64 field")
        val out = try {
            Base64Std.decodeStrict(s)
        } catch (e: Base64Exception) {
            malformed("base64 field")
        }
        if (out.size != length) malformed("base64 field")
        return out
    }

    /**
     * The raw Ed25519 key that validly signed [raw] (decoded header [header]); throws [SyncFormatException]
     * `sig-malformed`, `sig-stale` or `sig-mismatch`. Which key is the right one is the transport's policy.
     */
    fun verify(sigRaw: ByteArray, raw: ByteArray, header: ViewHeader): ByteArray {
        if (sigRaw.size > MAX_BYTES) malformed("signature file too large")
        val parsed = try {
            CanonicalJson.parse(sigRaw)
        } catch (e: JsonException) {
            malformed("signature file is not JSON")
        }
        val o = (parsed as? JsonValue.Obj)?.fields ?: malformed("signature fields")
        if (o.keys != FIELDS) malformed("signature fields")
        if (o["format"] != JsonValue.Int(FORMAT)) malformed("unsupported signature format")
        val groupId = (o["group_id"] as? JsonValue.Str)?.v
        val deviceId = (o["device_id"] as? JsonValue.Str)?.v
        if (groupId == null || !Identifier.isValid(groupId) || deviceId == null || !Identifier.isValid(deviceId) ||
            !SealedItem.isInt(o["epoch"]) || !SealedItem.isInt(o["counter"])
        ) {
            malformed("signature header fields")
        }
        val digest = (o["view_sha256"] as? JsonValue.Str)?.v
        if (digest == null || digest.length != 64 || !digest.all { it in '0'..'9' || it in 'a'..'f' }) malformed("view_sha256")
        val public = b64(o["signing_public"], 32)
        val sig = b64(o["sig"], 64)
        val canonical = try {
            CanonicalJson.encode(parsed, Dialect.UTF8)
        } catch (e: JsonException) {
            malformed("signature file is not canonical-JSON safe")
        }
        if (!canonical.contentEquals(sigRaw)) malformed("signature file is not canonical JSON")
        if (groupId != header.groupId || deviceId != header.deviceId ||
            (o["epoch"] as JsonValue.Int).v != header.epoch || (o["counter"] as JsonValue.Int).v != header.counter
        ) {
            throw SyncFormatException("sig-stale", "the signature belongs to another write")
        }
        if (digest != sha256Hex(raw)) throw SyncFormatException("sig-mismatch", "the view differs from the signed one")
        val signed = CanonicalJson.encode(JsonValue.Obj(o - "sig"), Dialect.UTF8)
        if (!Ed25519.verify(sig, LABEL + signed, public)) throw SyncFormatException("sig-mismatch", "the signature does not verify")
        return public
    }
}
