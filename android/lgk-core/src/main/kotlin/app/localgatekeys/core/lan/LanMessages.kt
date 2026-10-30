package app.localgatekeys.core.lan

import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Scalars

/** One message inside the authenticated channel (desktop `lan_sync` "Messages"). */
sealed interface LanMessage {
    data class View(
        val groupId: String,
        val epoch: Long,
        val transfer: String,
        val seq: Long,
        val total: Long,
        val size: Long,
        val view: String,
    ) : LanMessage

    data class Next(val transfer: String, val seq: Long) : LanMessage

    data class Ack(val transfer: String, val seq: Long) : LanMessage

    data class Error(val reason: String) : LanMessage

    /**
     * `{"type":"witness","group_id","epoch","view"}` (2026-10-29): [view] is standard base64 of a witness file (view
     * format 2, zero records, at most [app.localgatekeys.core.sync.Witness.MAX_WITNESS_BYTES]).
     */
    data class Witness(val groupId: String, val epoch: Long, val view: String) : LanMessage
}

object LanMessages {
    /** Raw view bytes per chunk when sending. */
    const val CHUNK_BYTES: Int = 512 * 1024

    /** Largest chunk accepted. */
    const val CHUNK_LIMIT: Int = 560 * 1024
    const val MAX_VIEW_BYTES: Int = ViewFile.MAX_BYTES
    const val MAX_CHUNKS: Long = 65536
    private const val MAX_INT53: Long = (1L shl 53) - 1

    /** Every reason a responder can send in an `error` message. */
    val errorReasons: List<String> = listOf(
        "bad-chunk", "bad-message", "bad-view", "device-mismatch", "epoch-behind", "group-mismatch",
        "local-data", "not-joined", "peer-epoch-behind", "rejoin-required", "revoked", "too-large",
        "unknown-peer",
    )

    private val fields: Map<String, Set<String>> = mapOf(
        "view" to setOf("type", "group_id", "epoch", "transfer", "seq", "total", "size", "view"),
        "next" to setOf("type", "transfer", "seq"),
        "ack" to setOf("type", "transfer", "seq"),
        "error" to setOf("type", "reason"),
        "witness" to setOf("type", "group_id", "epoch", "view"),
    )

    /** Longest `view` text of a `witness` message (base64 of [app.localgatekeys.core.sync.Witness.MAX_WITNESS_BYTES]). */
    val MAX_WITNESS_CHARS: Int = 4 * ((app.localgatekeys.core.sync.Witness.MAX_WITNESS_BYTES + 2) / 3)

    /** Canonical ASCII JSON of the message. */
    fun encode(m: LanMessage): ByteArray {
        val o: Map<String, JsonValue> = when (m) {
            is LanMessage.View -> mapOf(
                "type" to JsonValue.Str("view"), "group_id" to JsonValue.Str(m.groupId), "epoch" to JsonValue.Int(m.epoch),
                "transfer" to JsonValue.Str(m.transfer), "seq" to JsonValue.Int(m.seq), "total" to JsonValue.Int(m.total),
                "size" to JsonValue.Int(m.size), "view" to JsonValue.Str(m.view),
            )
            is LanMessage.Next -> mapOf("type" to JsonValue.Str("next"), "transfer" to JsonValue.Str(m.transfer), "seq" to JsonValue.Int(m.seq))
            is LanMessage.Ack -> mapOf("type" to JsonValue.Str("ack"), "transfer" to JsonValue.Str(m.transfer), "seq" to JsonValue.Int(m.seq))
            is LanMessage.Error -> mapOf("type" to JsonValue.Str("error"), "reason" to JsonValue.Str(m.reason))
            is LanMessage.Witness -> mapOf(
                "type" to JsonValue.Str("witness"), "group_id" to JsonValue.Str(m.groupId), "epoch" to JsonValue.Int(m.epoch),
                "view" to JsonValue.Str(m.view),
            )
        }
        return CanonicalJson.encode(JsonValue.Obj(o), Dialect.ASCII)
    }

    private fun int(v: JsonValue?, low: Long, high: Long = MAX_INT53): Long? {
        val i = (v as? JsonValue.Int)?.v ?: return null
        return if (i in low..high) i else null
    }

    private fun bad() = LanSyncException("bad-message")

    /** `parse_message`: shape checks; throws `too-large` or `bad-message`. */
    fun parse(raw: ByteArray): LanMessage {
        if (raw.size > LanTransport.MAX_MESSAGE_BYTES) throw LanSyncException("too-large")
        val o = try {
            (CanonicalJson.parse(raw) as? JsonValue.Obj)?.fields
        } catch (e: JsonException) {
            null
        } ?: throw bad()
        val type = (o["type"] as? JsonValue.Str)?.v ?: throw bad()
        val want = fields[type] ?: throw bad()
        if (o.keys != want) throw bad()
        if (type == "error") {
            val r = (o["reason"] as? JsonValue.Str)?.v
            if (r == null || Scalars.count(r) !in 1..64) throw bad()
            return LanMessage.Error(r)
        }
        if (type == "witness") {
            val group = (o["group_id"] as? JsonValue.Str)?.v
            val epoch = int(o["epoch"], 1)
            val view = (o["view"] as? JsonValue.Str)?.v
            if (group == null || epoch == null || view == null) throw bad()
            if (view.length > MAX_WITNESS_CHARS) throw LanSyncException("too-large")
            return LanMessage.Witness(group, epoch, view)
        }
        val transfer = (o["transfer"] as? JsonValue.Str)?.v ?: throw bad()
        val tb = transfer.toByteArray(Charsets.UTF_8)
        if (tb.size != 32 || !tb.all { (it >= 0x30 && it <= 0x39) || (it >= 0x61 && it <= 0x66) }) throw bad()
        val seq = int(o["seq"], 0, MAX_CHUNKS - 1) ?: throw bad()
        if (type == "next") return LanMessage.Next(transfer, seq)
        if (type == "ack") return LanMessage.Ack(transfer, seq)
        val group = (o["group_id"] as? JsonValue.Str)?.v ?: throw bad()
        val epoch = int(o["epoch"], 1) ?: throw bad()
        val total = int(o["total"], 1)
        val size = int(o["size"], 1)
        val view = (o["view"] as? JsonValue.Str)?.v
        if (total == null || size == null || view == null) throw bad()
        if (size > MAX_VIEW_BYTES.toLong() || total > MAX_CHUNKS) throw LanSyncException("too-large")
        if (seq >= total || total > size) throw bad()
        if (view.toByteArray(Charsets.UTF_8).size > 4 * ((CHUNK_LIMIT + 2) / 3)) throw LanSyncException("too-large")
        return LanMessage.View(group, epoch, transfer, seq, total, size, view)
    }

    /** Chunks of [CHUNK_BYTES] (the last is what is left). */
    fun splitView(raw: ByteArray): List<ByteArray> =
        (0 until raw.size step CHUNK_BYTES).map { raw.copyOfRange(it, minOf(it + CHUNK_BYTES, raw.size)) }
}
