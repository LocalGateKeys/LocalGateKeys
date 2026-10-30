package app.localgatekeys.core.lan

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.primitives.CryptoBox
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Finding the paired host on the local network after its address changed (desktop `sync.discovery`, Bonjour / mDNS).
 *
 * A host announces [SERVICE_TYPE] with a neutral instance name and the TXT record `{"v": "1", "t": <tag>}`; the tag
 * changes every UTC day and only group members can compute it. It only says where to dial: identity is still the
 * pinned keys checked by the session hello. Format pinned by `tests/vectors/sync/discovery.json`.
 */
object Discovery {
    const val SERVICE_TYPE = "_lgksync._tcp"
    const val TXT_VERSION = "1"

    /** At most this many announced addresses are dialled per run (plan: security rules). */
    const val MAX_CANDIDATES = 4

    private val DISCOVER_INFO = "localgatekeys|sync|discover|v1|".toByteArray(Charsets.US_ASCII)
    private const val TAG_BYTES = 10
    private const val DAY = 86_400L
    private val DAY_FORMAT: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC)

    /** HKDF-SHA256 over the group key, salt = group id, info = `localgatekeys|sync|discover|v1|<epoch>`. */
    fun discoveryKey(groupKey: GroupKey): ByteArray =
        CryptoBox.hkdf(
            groupKey.key, groupKey.groupId.toByteArray(Charsets.UTF_8),
            DISCOVER_INFO + groupKey.epoch.toString().toByteArray(Charsets.US_ASCII), 32,
        )

    /** The UTC date `YYYY-MM-DD` of a Unix time in seconds. */
    fun utcDay(now: Long): String = DAY_FORMAT.format(Instant.ofEpochSecond(now))

    /** base32(HMAC-SHA256(discovery key, host device id + "|" + day)[:10]), lowercase, no padding (16 characters). */
    fun tag(groupKey: GroupKey, hostDeviceId: String, day: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(discoveryKey(groupKey), "HmacSHA256"))
        val digest = mac.doFinal(hostDeviceId.toByteArray(Charsets.UTF_8) + "|".toByteArray() + day.toByteArray(Charsets.US_ASCII))
        return base32Lower(digest.copyOf(TAG_BYTES))
    }

    /** The tags accepted for [hostDeviceId] at [now]: today's and yesterday's (UTC), so a skewed clock still matches. */
    fun acceptedTags(groupKey: GroupKey, hostDeviceId: String, now: Long): Set<String> =
        setOf(tag(groupKey, hostDeviceId, utcDay(now)), tag(groupKey, hostDeviceId, utcDay(now - DAY)))

    /** One resolved announcement: the host address text, the port and the TXT record. */
    data class Announcement(val host: String, val port: Int, val txt: Map<String, String>)

    /**
     * The addresses worth dialling, in browse order: version 1, an accepted tag, a private LAN address, a valid port;
     * duplicates and [alreadyTried] (the pinned address) dropped; at most [MAX_CANDIDATES].
     */
    fun candidates(found: List<Announcement>, accepted: Set<String>, alreadyTried: LanEndpoint?): List<LanEndpoint> {
        val out = LinkedHashSet<LanEndpoint>()
        for (a in found) {
            if (out.size >= MAX_CANDIDATES) break
            if (a.txt["v"] != TXT_VERSION) continue
            val t = a.txt["t"] ?: continue
            if (t !in accepted) continue
            if (a.port !in 1..65535 || !LanAddress.isLan(a.host) || !routable(a.host)) continue
            val e = try {
                LanEndpoint(a.host, a.port)
            } catch (_: PairingException) {
                continue
            }
            if (e != alreadyTried) out.add(e)
        }
        return out.toList()
    }

    /**
     * Discovery dials only a dotted IPv4 address outside loopback (127/8), link-local (169.254/16) and 0/8: an
     * announcement is unauthenticated, so it must not aim the phone at its own services. The pinned address keeps the
     * wider [LanAddress.isLan] rule.
     */
    fun routable(host: String): Boolean {
        val parts = host.split(".")
        if (parts.size != 4 || parts.any { it.isEmpty() || it.length > 3 || !it.all(Char::isDigit) }) return false
        val b = parts.map { it.toInt() }
        if (b.any { it > 255 }) return false
        return b[0] != 127 && b[0] != 0 && !(b[0] == 169 && b[1] == 254)
    }

    private const val ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"

    private fun base32Lower(data: ByteArray): String {
        val sb = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                sb.append(ALPHABET[(buffer shr (bits - 5)) and 31])
                bits -= 5
            }
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (5 - bits)) and 31])
        return sb.toString()
    }
}
