package app.localgatekeys.core.records

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Url

/** Decoded JWT parts. Times are seconds since the epoch; only JSON integers count, so numeric strings stay null. */
data class JwtInfo(
    val header: JsonValue,
    val claims: JsonValue,
    val alg: String?,
    val issued: Long?,
    val notBefore: Long?,
    val expires: Long?,
) {
    fun expired(now: Long): Boolean = expires != null && expires <= now
}

/**
 * Read-only JWT decode for API-key items; the signature is never checked.
 * Mirror of Python `jwt_view.decode_jwt` and Swift `JWTView`; vectors in `tests/vectors/jwt/cases.json`.
 */
object JwtView {
    const val MAX_CHARS = 16 * 1024
    private const val MAX_TIMESTAMP = 32503680000L // 3000-01-01T00:00:00Z; later values are ignored

    /** Decodes `header.payload.signature` (base64url, no padding); null when [value] is not a JWT. */
    fun decode(value: String): JwtInfo? {
        if (value.length > MAX_CHARS) return null
        val parts = value.split('.')
        if (parts.size != 3 || parts[0].isEmpty() || parts[1].isEmpty()) return null
        if (!parts.all { p -> p.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' } }) return null
        val header = part(parts[0]) ?: return null
        val claims = part(parts[1]) ?: return null
        val alg = (header.obj().fields["alg"] as? JsonValue.Str)?.v
        return JwtInfo(header, claims, alg, time(claims, "iat"), time(claims, "nbf"), time(claims, "exp"))
    }

    private fun part(text: String): JsonValue? {
        val bytes = Base64Url.decodeLenient(text, MAX_CHARS) ?: return null
        val json = try {
            CanonicalJson.parse(bytes)
        } catch (_: Exception) {
            return null
        }
        return if (json is JsonValue.Obj) json else null
    }

    private fun time(claims: JsonValue, name: String): Long? {
        val v = (claims.obj().fields[name] as? JsonValue.Int)?.v ?: return null
        return if (v in 0..MAX_TIMESTAMP) v else null
    }
}
