package app.localgatekeys.core.lan

/**
 * The address ranges a LAN sync endpoint may use (desktop `sync.lan_address`).
 *
 * Literal IPv4/IPv6 text only, parsed like Python's `ipaddress.ip_address`. Accepted networks:
 * 10/8, 172.16/12, 192.168/16, 169.254/16, 127/8, ::1/128, fe80::/10, fc00::/7. An IPv4-mapped
 * IPv6 address is never accepted, nor is an IPv6 address with a zone id (`fe80::1%eth0`).
 */
object LanAddress {
    sealed interface Parsed {
        class V4(bytes: ByteArray) : Parsed {
            private val b = bytes.copyOf()
            val bytes: ByteArray get() = b.copyOf()

            override fun equals(other: Any?): Boolean = other is V4 && b.contentEquals(other.b)

            override fun hashCode(): Int = b.contentHashCode()
        }

        class V6(bytes: ByteArray) : Parsed {
            private val b = bytes.copyOf()
            val bytes: ByteArray get() = b.copyOf()

            override fun equals(other: Any?): Boolean = other is V6 && b.contentEquals(other.b)

            override fun hashCode(): Int = b.contentHashCode() + 1
        }
    }

    val networks: List<String> = listOf(
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "127.0.0.0/8", "::1/128", "fe80::/10", "fc00::/7",
    )

    fun isLan(text: String): Boolean {
        val p = parse(text) ?: return false
        return isLan(p)
    }

    internal fun isLan(p: Parsed): Boolean = when (p) {
        is Parsed.V4 -> {
            val b = p.bytes.map { it.toInt() and 0xFF }
            b[0] == 10 || (b[0] == 172 && b[1] and 0xF0 == 16) || (b[0] == 192 && b[1] == 168) ||
                (b[0] == 169 && b[1] == 254) || b[0] == 127
        }
        is Parsed.V6 -> {
            val b = p.bytes.map { it.toInt() and 0xFF }
            if ((0 until 15).all { b[it] == 0 } && b[15] == 1) true
            else (b[0] == 0xFE && b[1] and 0xC0 == 0x80) || b[0] and 0xFE == 0xFC
        }
    }

    /** The canonical text (Python `str(ip_address(text))`) of a LAN address, or null. */
    internal fun normalisedLan(text: String): String? {
        val p = parse(text) ?: return null
        if (!isLan(p)) return null
        return format(p)
    }

    /** Python `ipaddress.ip_address` parsing; a zone id (`%...`) returns null (never accepted here). */
    fun parse(text: String): Parsed? {
        if (text.toByteArray(Charsets.UTF_8).size > 255 || !text.all { it.code < 128 }) return null
        parseV4(text)?.let { return Parsed.V4(it) }
        if (text.contains('%')) return null
        parseV6(text)?.let { return Parsed.V6(it) }
        return null
    }

    private fun parseV4(s: String): ByteArray? {
        val parts = s.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for ((i, p) in parts.withIndex()) {
            if (p.length !in 1..3 || !p.all { it in '0'..'9' }) return null
            if (p.length > 1 && p[0] == '0') return null // Python rejects leading zeros
            val v = p.toInt()
            if (v > 255) return null
            out[i] = v.toByte()
        }
        return out
    }

    private fun hex(s: String): Int? {
        if (s.length !in 1..4 || !s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
        return s.toInt(16)
    }

    private fun parseV6(text: String): ByteArray? {
        val parts = text.split(':').toMutableList()
        if (parts.size < 3) return null
        val last = parts.last()
        if (last.contains('.')) {
            val v4 = parseV4(last) ?: return null
            val u = v4.map { it.toInt() and 0xFF }
            parts.removeAt(parts.size - 1)
            parts.add(((u[0] shl 8) or u[1]).toString(16))
            parts.add(((u[2] shl 8) or u[3]).toString(16))
        }
        if (parts.size > 9) return null
        var skip: Int? = null
        for (i in 1 until parts.size - 1) {
            if (parts[i].isEmpty()) {
                if (skip != null) return null
                skip = i
            }
        }
        val hextets = ArrayList<Int>()
        if (skip != null) {
            var head = parts.subList(0, skip).toList()
            var rest = parts.subList(skip + 1, parts.size).toList()
            if (head.isNotEmpty() && head.first() == "") {
                if (head.size != 1) return null
                head = emptyList()
            }
            if (rest.isNotEmpty() && rest.last() == "") {
                if (rest.size != 1) return null
                rest = emptyList()
            }
            val missing = 8 - head.size - rest.size
            if (missing < 1) return null
            for (p in head) hextets.add(hex(p) ?: return null)
            repeat(missing) { hextets.add(0) }
            for (p in rest) hextets.add(hex(p) ?: return null)
        } else {
            if (parts.size != 8) return null
            for (p in parts) hextets.add(hex(p) ?: return null)
        }
        if (hextets.size != 8) return null
        val out = ByteArray(16)
        for ((i, h) in hextets.withIndex()) {
            out[2 * i] = (h shr 8).toByte()
            out[2 * i + 1] = (h and 0xFF).toByte()
        }
        return out
    }

    /** Python `str()` of the address: dotted IPv4, RFC 5952-style compressed lowercase IPv6. */
    internal fun format(p: Parsed): String = when (p) {
        is Parsed.V4 -> p.bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
        is Parsed.V6 -> {
            val b = p.bytes
            val h = (0 until 8).map { ((b[2 * it].toInt() and 0xFF) shl 8) or (b[2 * it + 1].toInt() and 0xFF) }
            var bestStart = -1
            var bestLen = 0
            var curStart = -1
            var curLen = 0
            for ((i, v) in h.withIndex()) {
                if (v == 0) {
                    if (curStart < 0) {
                        curStart = i
                        curLen = 0
                    }
                    curLen++
                    if (curLen > bestLen) {
                        bestStart = curStart
                        bestLen = curLen
                    }
                } else {
                    curStart = -1
                    curLen = 0
                }
            }
            val words = h.map { it.toString(16) }
            if (bestLen > 1) {
                words.subList(0, bestStart).joinToString(":") + "::" + words.subList(bestStart + bestLen, words.size).joinToString(":")
            } else {
                words.joinToString(":")
            }
        }
    }
}
