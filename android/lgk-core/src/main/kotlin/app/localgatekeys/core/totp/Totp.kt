package app.localgatekeys.core.totp

import app.localgatekeys.core.records.PyStrip
import java.io.ByteArrayOutputStream
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Thrown exactly where `src/localvault/totp.py` raises `TotpError`. Port of Swift `TOTPError`. */
class TotpException(val kind: Kind) : Exception(kind.name) {
    enum class Kind {
        INVALID_SECRET_LENGTH, EMPTY_SECRET, INVALID_BASE32, SECRET_TOO_SHORT, SECRET_TOO_LONG,
        UNSUPPORTED_DIGITS, UNSUPPORTED_PERIOD, UNSUPPORTED_ALGORITHM, INVALID_TIMESTAMP,

        /** `parse_otpauth_uri`: "Expected an otpauth://totp URI", duplicate or invalid parameters, label/issuer too long. */
        NOT_OTPAUTH_URI, DUPLICATE_PARAMETER, INVALID_PARAMETER, LABEL_TOO_LONG,
    }
}

/** The stored `totp` dict shape the desktop writes: secret, algorithm, digits, period. */
data class TotpConfig(
    val secret: String,
    val algorithm: String = "SHA1",
    val digits: Int = 6,
    val period: Int = 30,
) {
    /** Never prints the secret. */
    override fun toString(): String = "TotpConfig(algorithm=$algorithm, digits=$digits, period=$period)"
}

/** RFC 6238 TOTP. Secret handling mirrors `totp.py` `_compact_secret` / `_decode_base32`. Port of Swift `TOTP`. */
object Totp {
    private const val MIN_SECRET_BYTES = 10
    private const val MAX_SECRET_BYTES = 128
    private const val MAX_URI_LENGTH = 16 * 1024

    private fun err(kind: TotpException.Kind) = TotpException(kind)

    private fun cps(s: String): IntArray = s.codePoints().toArray()

    private fun str(cp: IntArray, from: Int = 0, to: Int = cp.size): String {
        val sb = StringBuilder()
        for (i in from until to) sb.appendCodePoint(cp[i])
        return sb.toString()
    }

    /** Desktop: reject > 4096 code points; drop "-" and whitespace; uppercase; reject empty. */
    internal fun compactSecret(value: String): String {
        val scalars = cps(value)
        if (scalars.size > 4096) throw err(TotpException.Kind.INVALID_SECRET_LENGTH)
        val kept = StringBuilder()
        for (s in scalars) if (s != '-'.code && !PyStrip.isSpace(s)) kept.appendCodePoint(s)
        val compact = kept.toString().uppercase(java.util.Locale.ROOT)
        if (compact.isEmpty()) throw err(TotpException.Kind.EMPTY_SECRET)
        return compact
    }

    /**
     * Mirrors `base64.b32decode(compact + "=" * ((8 - len % 8) % 8), casefold=True)`: a literal "=" in the
     * input is NOT stripped, so it only passes when the padded total is valid.
     */
    internal fun decodeBase32(compact: String): ByteArray {
        val base = cps(compact)
        val chars = base + IntArray((8 - base.size % 8) % 8) { '='.code }
        var end = chars.size
        while (end > 0 && chars[end - 1] == '='.code) end--
        val pad = chars.size - end
        if (pad !in listOf(0, 1, 3, 4, 6)) throw err(TotpException.Kind.INVALID_BASE32)
        val out = ByteArrayOutputStream()
        var acc = 0
        var bits = 0
        for (i in 0 until end) {
            val c = chars[i]
            val v = when (c) {
                in 0x41..0x5A -> c - 0x41
                in 0x32..0x37 -> c - 0x32 + 26
                else -> throw err(TotpException.Kind.INVALID_BASE32)
            }
            acc = (acc shl 5) or v
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out.write((acc shr bits) and 0xFF)
                acc = acc and ((1 shl bits) - 1)
            }
        }
        if (out.size() < MIN_SECRET_BYTES) throw err(TotpException.Kind.SECRET_TOO_SHORT)
        if (out.size() > MAX_SECRET_BYTES) throw err(TotpException.Kind.SECRET_TOO_LONG)
        return out.toByteArray()
    }

    fun code(secret: String, algorithm: String, digits: Int, period: Int, at: Long): String {
        if (digits !in 6..8) throw err(TotpException.Kind.UNSUPPORTED_DIGITS)
        if (period !in 15..120) throw err(TotpException.Kind.UNSUPPORTED_PERIOD)
        val alg = algorithm.uppercase(java.util.Locale.ROOT)
        val macName = when (alg) {
            "SHA1" -> "HmacSHA1"
            "SHA256" -> "HmacSHA256"
            "SHA512" -> "HmacSHA512"
            else -> throw err(TotpException.Kind.UNSUPPORTED_ALGORITHM)
        }
        if (at < 0) throw err(TotpException.Kind.INVALID_TIMESTAMP)
        val key = decodeBase32(compactSecret(secret))
        val counter = at / period
        val msg = ByteArray(8) { ((counter shr (8 * (7 - it))) and 0xFF).toByte() }
        val mac = Mac.getInstance(macName)
        mac.init(SecretKeySpec(key, macName))
        val digest = mac.doFinal(msg)
        val o = digest[digest.size - 1].toInt() and 0x0F
        val bin = ((digest[o].toInt() and 0x7F) shl 24) or
            ((digest[o + 1].toInt() and 0xFF) shl 16) or
            ((digest[o + 2].toInt() and 0xFF) shl 8) or
            (digest[o + 3].toInt() and 0xFF)
        var modulus = 1L
        repeat(digits) { modulus *= 10 }
        return (bin.toLong() % modulus).toString().padStart(digits, '0')
    }

    /** `totp.normalize_secret`: the compact upper-case secret, after checking it decodes to 10..128 bytes. */
    fun normalizeSecret(v: String): String {
        val compact = compactSecret(v)
        decodeBase32(compact)
        return compact
    }

    /** `totp.parse_otpauth_uri`, keeping the keys the desktop stores (secret, algorithm, digits, period). */
    fun parseOtpauthUri(uri: String): TotpConfig {
        val all = cps(uri)
        if (all.size > MAX_URI_LENGTH) throw err(TotpException.Kind.NOT_OTPAUTH_URI)
        var lo = 0
        var hi = all.size
        while (lo < hi && PyStrip.isSpace(all[lo])) lo++
        while (hi > lo && PyStrip.isSpace(all[hi - 1])) hi--
        // urlsplit drops embedded tab, CR and LF.
        val sb = StringBuilder()
        for (i in lo until hi) {
            val c = all[i]
            if (c != 0x09 && c != 0x0D && c != 0x0A) sb.appendCodePoint(c)
        }
        var u = sb.toString()
        val hash = u.indexOf('#')
        if (hash >= 0) u = u.substring(0, hash)
        val sep = u.indexOf("://")
        if (sep < 0 || u.substring(0, sep).lowercase(java.util.Locale.ROOT) != "otpauth") throw err(TotpException.Kind.NOT_OTPAUTH_URI)
        val rest = u.substring(sep + 3)
        var netEnd = rest.indexOfFirst { it == '/' || it == '?' }
        if (netEnd < 0) netEnd = rest.length
        if (rest.substring(0, netEnd).lowercase(java.util.Locale.ROOT) != "totp") throw err(TotpException.Kind.NOT_OTPAUTH_URI)
        val afterNet = rest.substring(netEnd)
        val q = afterNet.indexOf('?')
        val path = if (q >= 0) afterNet.substring(0, q) else afterNet
        val queryText = if (q >= 0) afterNet.substring(q + 1) else ""
        val query = LinkedHashMap<String, MutableList<String>>()
        var fields = 0
        for (pair in queryText.split('&')) {
            if (pair.isEmpty()) continue
            fields++
            if (fields > 64) throw err(TotpException.Kind.NOT_OTPAUTH_URI)
            val parts = pair.split('=', limit = 2)
            fun dec(s: String) = pyUnquote(s.replace('+', ' '))
            // parse_qs(keep_blank_values=True): a bare "name" is kept with the value "".
            query.getOrPut(dec(parts[0])) { mutableListOf() }.add(if (parts.size == 2) dec(parts[1]) else "")
        }

        fun single(name: String, def: String): String {
            val v = query[name] ?: return def
            if (v.size != 1) throw err(TotpException.Kind.DUPLICATE_PARAMETER)
            return v[0]
        }

        fun intParam(name: String, def: Int): Int {
            val v = single(name, "")
            if (query[name] == null) return def
            if (v.isEmpty() || cps(v).size > 6 || !cps(v).all { it in 0x30..0x39 }) throw err(TotpException.Kind.INVALID_PARAMETER)
            return v.toInt()
        }

        val secret = normalizeSecret(single("secret", ""))
        val digits = intParam("digits", 6)
        val period = intParam("period", 30)
        val algorithm = single("algorithm", "SHA1").uppercase(java.util.Locale.ROOT)
        if (digits !in 6..8) throw err(TotpException.Kind.UNSUPPORTED_DIGITS)
        if (period !in 15..120) throw err(TotpException.Kind.UNSUPPORTED_PERIOD)
        if (algorithm != "SHA1" && algorithm != "SHA256" && algorithm != "SHA512") throw err(TotpException.Kind.UNSUPPORTED_ALGORITHM)
        val issuer = single("issuer", "")
        if (cps(issuer).size > 256 || cps(path).size > 1024) throw err(TotpException.Kind.LABEL_TOO_LONG)
        return TotpConfig(secret, algorithm, digits, period)
    }

    /** Foundation's `.whitespacesAndNewlines`: Zs, tab, LF..CR, U+0085, U+2028, U+2029. */
    private fun isTrimSpace(c: Int): Boolean =
        c in 0x09..0x0D || c == 0x85 || c == 0x2028 || c == 0x2029 || Character.getType(c) == Character.SPACE_SEPARATOR.toInt()

    /**
     * A base32 secret or an `otpauth://totp` URI, the way the desktop editor's `config()` reads its field.
     * [defaults] supplies algorithm/digits/period for a bare secret. Returns null for an empty field.
     */
    fun parseField(text: String, defaults: TotpConfig? = null): TotpConfig? {
        val all = cps(text)
        var lo = 0
        var hi = all.size
        while (lo < hi && isTrimSpace(all[lo])) lo++
        while (hi > lo && isTrimSpace(all[hi - 1])) hi--
        val trimmed = str(all, lo, hi)
        if (trimmed.isEmpty()) return null
        if (trimmed.startsWith("otpauth://")) return parseOtpauthUri(trimmed)
        val d = defaults ?: TotpConfig("")
        return TotpConfig(normalizeSecret(trimmed), d.algorithm, d.digits, d.period)
    }

    /**
     * Python `urllib.parse.unquote`: each valid %XX becomes a byte, malformed escapes stay literal, and the
     * bytes decode as UTF-8 with invalid sequences replaced by U+FFFD.
     */
    internal fun pyUnquote(s: String): String {
        if (!s.contains('%')) return s
        val u = s.toByteArray(Charsets.UTF_8)
        fun hex(b: Byte): Int = when (b.toInt()) {
            in 0x30..0x39 -> b - 0x30
            in 0x41..0x46 -> b - 0x41 + 10
            in 0x61..0x66 -> b - 0x61 + 10
            else -> -1
        }
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < u.size) {
            if (u[i].toInt() == 0x25 && i + 2 < u.size && hex(u[i + 1]) >= 0 && hex(u[i + 2]) >= 0) {
                out.write((hex(u[i + 1]) shl 4) or hex(u[i + 2]))
                i += 3
            } else {
                out.write(u[i].toInt())
                i++
            }
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }

    /** Short user-facing text for a parse error. */
    fun message(e: TotpException): String = when (e.kind) {
        TotpException.Kind.EMPTY_SECRET -> "The 2FA secret is empty."
        TotpException.Kind.INVALID_BASE32, TotpException.Kind.INVALID_SECRET_LENGTH -> "The 2FA secret is not valid Base32."
        TotpException.Kind.SECRET_TOO_SHORT -> "The 2FA secret is too short."
        TotpException.Kind.SECRET_TOO_LONG -> "The 2FA secret is too long."
        TotpException.Kind.UNSUPPORTED_DIGITS -> "This 2FA setup uses an unsupported digit count."
        TotpException.Kind.UNSUPPORTED_PERIOD -> "This 2FA setup uses an unsupported period."
        TotpException.Kind.UNSUPPORTED_ALGORITHM -> "This 2FA setup uses an unsupported algorithm."
        TotpException.Kind.NOT_OTPAUTH_URI -> "Enter a Base32 secret or an otpauth://totp link."
        TotpException.Kind.DUPLICATE_PARAMETER, TotpException.Kind.INVALID_PARAMETER -> "The otpauth link has an invalid parameter."
        TotpException.Kind.LABEL_TOO_LONG -> "The otpauth link's label or issuer is too long."
        TotpException.Kind.INVALID_TIMESTAMP -> "The 2FA secret is not valid."
    }
}
