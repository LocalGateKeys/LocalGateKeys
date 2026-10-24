package app.localgatekeys.core.lan

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.Scalars

private fun malformed(detail: String): PairingException = PairingException(PairingException.Kind.MALFORMED, detail)

/** Pairing canonical JSON: sorted keys, compact, `ensure_ascii=True`, at most 64 KiB (Swift `Pairing`). */
internal object Pairing {
    const val MAX_TRANSCRIPT_BYTES = 64 * 1024
    const val MAX_INT53: Long = (1L shl 53) - 1

    fun canonical(v: JsonValue): ByteArray {
        val data = try {
            CanonicalJson.encode(v, Dialect.ASCII)
        } catch (e: JsonException) {
            throw malformed("Pairing transcript is not serializable")
        }
        if (data.size > MAX_TRANSCRIPT_BYTES) throw malformed("Pairing transcript is too large")
        return data
    }

    /** `base64.b64decode(validate=True)` plus an exact length. */
    fun b64(v: JsonValue?, length: Int, field: String): ByteArray {
        val raw = try {
            Base64Std.decodeStrict((v as? JsonValue.Str)?.v ?: throw malformed("$field is malformed"))
        } catch (e: Base64Exception) {
            throw malformed("$field is malformed")
        }
        if (raw.size != length) throw malformed("$field has an invalid length")
        return raw
    }

    fun ident(v: JsonValue?, field: String): String {
        val s = (v as? JsonValue.Str)?.v
        if (s == null || !Identifier.isValid(s)) throw malformed("$field is malformed")
        return s
    }

    /** `_text`: non-empty string of at most [limit] code points without NUL. */
    fun text(v: JsonValue?, field: String, limit: Int): String {
        val s = (v as? JsonValue.Str)?.v
        if (s == null || s.isEmpty() || Scalars.count(s) > limit || s.contains('\u0000')) throw malformed("$field is malformed")
        return s
    }

    /** `_private_lan_endpoint`: a literal LAN address (normalised like Python `str(ip_address)`) and a port. */
    fun endpoint(host: JsonValue?, port: JsonValue?): LanEndpointFields {
        val h = (host as? JsonValue.Str)?.v
        if (h == null || h.toByteArray(Charsets.UTF_8).size > 255) throw malformed("Pairing endpoint host is malformed")
        val norm = LanAddress.normalisedLan(h) ?: throw malformed("Pairing endpoint must be a private LAN address")
        val p = (port as? JsonValue.Int)?.v
        if (p == null || p < 1 || p > 65535) throw malformed("Pairing endpoint port is malformed")
        return LanEndpointFields(norm, p.toInt())
    }

    fun strictJson(data: ByteArray): JsonValue = try {
        CanonicalJson.parse(data)
    } catch (e: JsonException) {
        throw malformed("Enrollment message is malformed")
    }
}

/** The validated, normalised parts of an endpoint. */
internal class LanEndpointFields(val host: String, val port: Int)
