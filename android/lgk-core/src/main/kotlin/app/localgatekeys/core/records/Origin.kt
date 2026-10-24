package app.localgatekeys.core.records

import app.localgatekeys.core.primitives.Scalars

/** Origin errors. `INVALID` carries the desktop's message verbatim; `NEEDS_PUNYCODE` asks for the `xn--` form. */
class OriginException(val kind: Kind, message: String) : Exception(message) {
    enum class Kind { INVALID, NEEDS_PUNYCODE }

    companion object {
        fun invalid(message: String) = OriginException(Kind.INVALID, message)

        fun needsPunycode() = OriginException(Kind.NEEDS_PUNYCODE, "needsPunycode")
    }
}

/**
 * Origin canonicalisation (desktop `localvault.origin`), ASCII hosts only. Port of Swift `Records/Origin.swift`.
 *
 * Mirrors Python's `urlsplit` + `canonicalize_origin` / `normalize_url`. A non-ASCII host throws
 * `NEEDS_PUNYCODE`: the phone does not carry UTS-46, so the editor asks for the `xn--` form.
 *
 * Every delimiter searched for here is ASCII, so UTF-16 index arithmetic on [String] is the same as working on
 * code points (a surrogate unit never equals an ASCII character).
 */
object Origin {
    internal class Split(
        val scheme: String,
        val netloc: String,
        val hasNetloc: Boolean,
        val path: String,
        val query: String,
        val fragment: String,
    ) {
        val hasUserInfo: Boolean get() = netloc.contains('@')

        /** Text after the last `@`. */
        private val hostinfo: String
            get() {
                val at = netloc.lastIndexOf('@')
                return if (at >= 0) netloc.substring(at + 1) else netloc
            }

        /** Python `SplitResult.hostname`: lower-cased, null when empty. */
        val hostname: String?
            get() {
                val info = hostinfo
                val open = info.indexOf('[')
                val host = if (open >= 0) {
                    val rest = info.substring(open + 1)
                    val close = rest.indexOf(']')
                    if (close >= 0) rest.substring(0, close) else rest
                } else {
                    val colon = info.indexOf(':')
                    if (colon >= 0) info.substring(0, colon) else info
                }
                return if (host.isEmpty()) null else host.lowercase()
            }

        /** Python 3.14 `SplitResult.port`. */
        fun port(): Int? {
            val info = hostinfo
            val close = info.indexOf(']')
            val tail: String
            if (close >= 0) {
                val after = info.substring(close + 1)
                val colon = after.indexOf(':')
                if (colon < 0) return null
                tail = after.substring(colon + 1)
            } else {
                val colon = info.indexOf(':')
                if (colon < 0) return null
                tail = info.substring(colon + 1)
            }
            if (tail.isEmpty()) return null
            val n = if (tail.all { it in '0'..'9' }) tail.toIntOrNull() else null
            if (n == null || n > 65535) throw OriginException.invalid("Invalid port")
            return n
        }
    }

    private fun isSchemeChar(c: Char): Boolean =
        c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '+' || c == '-' || c == '.'

    private fun isAsciiLetter(c: Char): Boolean = c in 'a'..'z' || c in 'A'..'Z'

    private fun isAscii(s: String): Boolean = s.all { it.code < 0x80 }

    private fun isHexDigit(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

    private val ipvFuture = Regex("[vV][a-fA-F0-9]+\\.[^\\n]+")

    /** Python 3.14 `urllib.parse._check_bracketed_host`: an IPvFuture literal, or an IPv6 address (zone allowed). */
    private fun checkBracketedHost(hostname: String) {
        if (hostname.startsWith("v") || hostname.startsWith("V")) {
            if (!ipvFuture.matches(hostname)) throw OriginException.invalid("Invalid IPv6 URL")
            return
        }
        // `ipaddress.ip_address`: an IPv4 address is refused in brackets; an IPv6 address may carry `%zone`.
        val pct = hostname.indexOf('%')
        val addr = if (pct >= 0) hostname.substring(0, pct) else hostname
        if (pct >= 0) {
            val zone = hostname.substring(pct + 1)
            if (zone.isEmpty() || zone.contains('%')) throw OriginException.invalid("Invalid IPv6 URL")
        }
        if (ipv6(addr) == null) throw OriginException.invalid("Invalid IPv6 URL")
    }

    /**
     * Python 3.14 `urllib.parse._check_bracketed_netloc`: nothing before `[`, nothing between `]` and `:port`, and
     * a valid bracketed host. `https://evil.com[::1]` is refused, not read as `https://[::1]`.
     */
    private fun checkBracketedNetloc(netloc: String) {
        val hostAndPort = netloc.substring(netloc.lastIndexOf('@') + 1)
        val open = hostAndPort.indexOf('[')
        val hostname: String
        if (open >= 0) {
            if (open > 0) throw OriginException.invalid("Invalid IPv6 URL")
            val bracketed = hostAndPort.substring(open + 1)
            val close = bracketed.indexOf(']')
            hostname = if (close >= 0) bracketed.substring(0, close) else bracketed
            val port = if (close >= 0) bracketed.substring(close + 1) else ""
            if (port.isNotEmpty() && !port.startsWith(":")) throw OriginException.invalid("Invalid IPv6 URL")
        } else {
            val colon = hostAndPort.indexOf(':')
            hostname = if (colon >= 0) hostAndPort.substring(0, colon) else hostAndPort
        }
        checkBracketedHost(hostname)
    }

    /** Python `urllib.parse.urlsplit` (3.14 rules, including the bracketed-netloc checks). Only the left is stripped. */
    internal fun split(value: String): Split {
        var start = 0
        while (start < value.length && value[start].code <= 0x20) start++
        var s = value.substring(start).filter { it != '\t' && it != '\r' && it != '\n' }
        var scheme = ""
        val colon = s.indexOf(':')
        if (colon > 0 && isAsciiLetter(s[0]) && (0 until colon).all { isSchemeChar(s[it]) }) {
            scheme = s.substring(0, colon).lowercase()
            s = s.substring(colon + 1)
        }
        var netloc = ""
        var hasNetloc = false
        if (s.length >= 2 && s[0] == '/' && s[1] == '/') {
            hasNetloc = true
            var stop = 2
            while (stop < s.length && s[stop] != '/' && s[stop] != '?' && s[stop] != '#') stop++
            netloc = s.substring(2, stop)
            s = s.substring(stop)
            if (netloc.contains('[') != netloc.contains(']')) throw OriginException.invalid("Invalid IPv6 URL")
            if (netloc.contains('[')) checkBracketedNetloc(netloc)
        }
        var fragment = ""
        val hash = s.indexOf('#')
        if (hash >= 0) {
            fragment = s.substring(hash + 1)
            s = s.substring(0, hash)
        }
        var query = ""
        val q = s.indexOf('?')
        if (q >= 0) {
            query = s.substring(q + 1)
            s = s.substring(0, q)
        }
        return Split(scheme, netloc, hasNetloc, s, query, fragment)
    }

    /** WHATWG forbidden domain code points (C0 controls and whitespace are checked separately). */
    private const val FORBIDDEN_HOST_CHARS = "#/:<>?@[\\]^|%\u007f"

    /** Desktop `_has_space_or_control`: a C0 control or Python whitespace anywhere. */
    internal fun hasSpaceOrControl(s: String): Boolean = s.codePoints().anyMatch { it < 32 || PyStrip.isSpace(it) }

    /** Desktop `_check_host_chars`: refuse a host browsers would refuse (`paypal.com\.evil.com`). */
    private fun checkHostChars(host: String) {
        if (host.codePoints().anyMatch { it < 32 || PyStrip.isSpace(it) || (it < 0x80 && FORBIDDEN_HOST_CHARS.indexOf(it.toChar()) >= 0) }) {
            throw OriginException.invalid("Host contains a character that browsers do not allow")
        }
    }

    /** Lower-case, strip one trailing dot, refuse forbidden code points, and apply Python's ASCII IDNA label checks. */
    internal fun asciiHost(raw: String): String {
        var host = raw
        if (host.endsWith(".")) host = host.dropLast(1)
        if (host.isEmpty()) throw OriginException.invalid("Origin is missing a host")
        checkHostChars(host)
        if (host.endsWith(".")) throw OriginException.invalid("Invalid internationalized host name")
        if (!isAscii(host)) throw OriginException.needsPunycode()
        val lower = host.lowercase()
        val labels = lower.split(".")
        for (label in labels.dropLast(1)) {
            if (label.isEmpty() || label.length >= 64) throw OriginException.invalid("Invalid internationalized host name")
        }
        if (labels.last().length >= 64) throw OriginException.invalid("Invalid internationalized host name")
        return lower
    }

    internal fun ipv4(s: String): IntArray? {
        val parts = s.split(".")
        if (parts.size != 4) return null
        val out = IntArray(4)
        for ((i, p) in parts.withIndex()) {
            if (p.length !in 1..3 || !p.all { it in '0'..'9' }) return null
            if (p.length != 1 && p.startsWith("0")) return null
            val n = p.toInt()
            if (n > 255) return null
            out[i] = n
        }
        return out
    }

    private fun ipv6Groups(text: String, allowV4: Boolean): List<Int>? {
        if (text.isEmpty()) return emptyList()
        val out = ArrayList<Int>()
        val parts = text.split(":")
        for ((i, g) in parts.withIndex()) {
            if (allowV4 && i == parts.size - 1 && g.contains('.')) {
                val v4 = ipv4(g) ?: return null
                out.add(v4[0] shl 8 or v4[1])
                out.add(v4[2] shl 8 or v4[3])
                continue
            }
            if (g.length !in 1..4 || !g.all(::isHexDigit)) return null
            out.add(g.toInt(16))
        }
        return out
    }

    /** Python `ipaddress.IPv6Address` parsing (no zone ids): 16 bytes, or null. */
    internal fun ipv6(s: String): IntArray? {
        if (s.isEmpty() || s.contains('%') || !isAscii(s)) return null
        val all: List<Int>
        val r = s.indexOf("::")
        if (r >= 0) {
            val left = s.substring(0, r)
            val right = s.substring(r + 2)
            if (right.contains("::")) return null
            val l = ipv6Groups(left, false) ?: return null
            val rr = ipv6Groups(right, true) ?: return null
            if (l.size + rr.size >= 8) return null
            all = l + List(8 - l.size - rr.size) { 0 } + rr
        } else {
            val g = ipv6Groups(s, true) ?: return null
            if (g.size != 8) return null
            all = g
        }
        val out = IntArray(16)
        for ((i, v) in all.withIndex()) {
            out[2 * i] = v shr 8
            out[2 * i + 1] = v and 0xFF
        }
        return out
    }

    internal fun isLoopback(host: String): Boolean {
        if (host == "localhost" || host.endsWith(".localhost")) return true
        ipv4(host)?.let { return it[0] == 127 }
        ipv6(host)?.let { v6 -> return (0 until 15).all { v6[it] == 0 } && v6[15] == 1 }
        return false
    }

    internal fun render(host: String): String = if (ipv4(host) == null && ipv6(host) != null) "[$host]" else host

    /**
     * Desktop `_url_host`: a bracketed host must be a plain IPv6 address (no zone id, not IPv4-mapped, not
     * IPvFuture); any other host goes through [asciiHost].
     */
    internal fun urlHost(p: Split, missing: String): String {
        val raw = p.hostname ?: throw OriginException.invalid(missing)
        if (!p.netloc.substring(p.netloc.lastIndexOf('@') + 1).contains('[')) return asciiHost(raw)
        if (raw.contains('%')) throw OriginException.invalid("IPv6 zone identifiers are not supported")
        val v6 = ipv6(raw) ?: throw OriginException.invalid("Invalid IPv6 URL")
        if ((0 until 10).all { v6[it] == 0 } && v6[10] == 0xFF && v6[11] == 0xFF) {
            throw OriginException.invalid("IPv4-mapped IPv6 addresses are not supported")
        }
        return raw
    }

    /** Desktop `canonicalize_origin`: exact `scheme://host[:port]` for credential scoping. */
    fun canonicalize(value: String): String {
        val n = Scalars.count(value)
        if (n <= 0 || n > 2048) {
            throw OriginException.invalid("Origin must be a non-empty string shorter than 2049 characters")
        }
        if (hasSpaceOrControl(value)) throw OriginException.invalid("Origin contains whitespace or a control character")
        val p = split(value)
        if (p.hasUserInfo) throw OriginException.invalid("Origins must not contain user information")
        if (p.query.isNotEmpty() || p.fragment.isNotEmpty()) {
            throw OriginException.invalid("Expected an origin, not a URL with a query or fragment")
        }
        if (p.path != "" && p.path != "/") throw OriginException.invalid("Expected an origin without a path")
        if (p.scheme != "https" && p.scheme != "http") {
            throw OriginException.invalid("Only HTTPS origins are allowed (HTTP is limited to localhost)")
        }
        val host = urlHost(p, "Origin is missing a host")
        if (p.scheme == "http" && !isLoopback(host)) {
            throw OriginException.invalid("Plain HTTP is allowed only for loopback test origins")
        }
        val port = p.port()
        val def = if (p.scheme == "https") 443 else 80
        val suffix = if (port == null || port == def) "" else ":$port"
        return "${p.scheme}://${render(host)}$suffix"
    }

    /** Desktop `_split_url`: (scheme, ascii host, port or null, path, query). */
    internal class UrlParts(val scheme: String, val host: String, val port: Int?, val path: String, val query: String)

    internal fun splitURL(value: String): UrlParts {
        val n = Scalars.count(value)
        if (n <= 0 || n > 4096) throw OriginException.invalid("URL must be a non-empty string shorter than 4097 characters")
        if (hasSpaceOrControl(value)) throw OriginException.invalid("URL contains whitespace or a control character")
        val p = split(value)
        if (p.scheme != "https" && p.scheme != "http") throw OriginException.invalid("Only http(s) URLs can be matched")
        if (p.hasUserInfo) throw OriginException.invalid("URLs must not contain user information")
        val host = urlHost(p, "URL is missing a host")
        var port = p.port()
        if (port == (if (p.scheme == "https") 443 else 80)) port = null
        return UrlParts(p.scheme, host, port, p.path.ifEmpty { "/" }, p.query)
    }

    /** Desktop `normalize_url`. */
    fun normalizeUrl(value: String): String {
        val u = splitURL(value)
        val out = StringBuilder("${u.scheme}://${render(u.host)}")
        if (u.port != null) out.append(":${u.port}")
        out.append(if (u.path.startsWith("/")) u.path else "/" + u.path)
        if (u.query.isNotEmpty()) out.append("?").append(u.query)
        return out.toString()
    }

    /** Desktop `origin_of`. */
    fun originOf(value: String): String {
        val u = splitURL(value)
        return "${u.scheme}://${render(u.host)}" + (u.port?.let { ":$it" } ?: "")
    }
}
