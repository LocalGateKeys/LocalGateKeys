package app.localgatekeys.core.lan

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std

/**
 * A refused LAN transport step (Swift `LanTransportError`; desktop `transport.FrameError` /
 * `AuthenticationError` / `ReplayError`). [detail] is the Swift associated message, verbatim.
 */
class LanTransportException(val kind: Kind, val detail: String) : Exception("${kind.name.lowercase()}: $detail") {
    enum class Kind { MALFORMED, TOO_LARGE, AUTHENTICATION, REPLAY }
}

/** Transport constants and frame helpers (desktop `sync.transport`). */
object LanTransport {
    const val VERSION: Long = 1
    const val MAX_FRAME_PAYLOAD: Int = 1 shl 20
    const val MAX_MESSAGE_BYTES: Int = MAX_FRAME_PAYLOAD - 256
    const val SESSION_ID_BYTES: Int = 16

    /** 4-byte big-endian length prefix + payload (1 ... 1 MiB). */
    fun encodeFrame(payload: ByteArray): ByteArray {
        if (payload.size !in 1..MAX_FRAME_PAYLOAD) {
            throw LanTransportException(LanTransportException.Kind.TOO_LARGE, "Frame payload is empty or exceeds the bound")
        }
        val n = payload.size
        val out = ByteArray(4 + n)
        out[0] = (n ushr 24).toByte()
        out[1] = (n ushr 16).toByte()
        out[2] = (n ushr 8).toByte()
        out[3] = n.toByte()
        payload.copyInto(out, 4)
        return out
    }

    /** Strips and checks the length prefix of exactly one frame. */
    fun decodeFrame(frame: ByteArray): ByteArray {
        if (frame.size < 4) throw LanTransportException(LanTransportException.Kind.MALFORMED, "Frame is truncated")
        val n = ((frame[0].toInt() and 0xFF) shl 24) or ((frame[1].toInt() and 0xFF) shl 16) or
            ((frame[2].toInt() and 0xFF) shl 8) or (frame[3].toInt() and 0xFF)
        if (n < 1 || n > MAX_FRAME_PAYLOAD) {
            throw LanTransportException(LanTransportException.Kind.TOO_LARGE, "Frame length is outside the bound")
        }
        if (frame.size != 4 + n) {
            throw LanTransportException(LanTransportException.Kind.MALFORMED, "Frame contains trailing or missing bytes")
        }
        return frame.copyOfRange(4, frame.size)
    }

    internal fun canonical(v: JsonValue): ByteArray {
        val data = try {
            CanonicalJson.encode(v, Dialect.ASCII)
        } catch (e: JsonException) {
            throw LanTransportException(LanTransportException.Kind.MALFORMED, "Transport message is not serializable")
        }
        if (data.size > MAX_FRAME_PAYLOAD) {
            throw LanTransportException(LanTransportException.Kind.TOO_LARGE, "Transport message exceeds the frame bound")
        }
        return data
    }

    /** Strict canonical base64 with an optional exact length. */
    internal fun b64(v: JsonValue?, length: Int?, field: String): ByteArray {
        val raw = try {
            Base64Std.decodeStrict((v as? JsonValue.Str)?.v ?: throw Base64Exception())
        } catch (e: Base64Exception) {
            throw LanTransportException(LanTransportException.Kind.MALFORMED, "$field is malformed")
        }
        if (length != null && raw.size != length) {
            throw LanTransportException(LanTransportException.Kind.MALFORMED, "$field has an invalid length")
        }
        return raw
    }
}
