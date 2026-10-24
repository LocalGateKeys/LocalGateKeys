package app.localgatekeys.core.primitives

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

object UUID5 {
    /** RFC 4122 URL namespace. */
    val namespaceUrl: UUID = UUID.fromString("6ba7b811-9dad-11d1-80b4-00c04fd430c8")

    fun make(ns: UUID, name: String): UUID {
        val sha = MessageDigest.getInstance("SHA-1")
        sha.update(ByteBuffer.allocate(16).putLong(ns.mostSignificantBits).putLong(ns.leastSignificantBits).array())
        sha.update(name.toByteArray(Charsets.UTF_8))
        val h = sha.digest().copyOf(16)
        h[6] = ((h[6].toInt() and 0x0F) or 0x50).toByte()
        h[8] = ((h[8].toInt() and 0x3F) or 0x80).toByte()
        val buf = ByteBuffer.wrap(h)
        return UUID(buf.long, buf.long)
    }

    /**
     * Desktop `conflict_copy_id`: the namespace is the item id when it is a hyphenated UUID,
     * else uuid5(URL, "lgk-item:" + id).
     */
    fun conflictCopyId(itemId: String, contentDigest: String): String {
        val hyphenated = itemId.length == 36 && itemId.withIndex().all { (i, c) ->
            if (i == 8 || i == 13 || i == 18 || i == 23) c == '-' else c in '0'..'9' || c in 'A'..'F' || c in 'a'..'f'
        }
        val ns = if (hyphenated) UUID.fromString(itemId) else make(namespaceUrl, "lgk-item:$itemId")
        return make(ns, "lgk-copy:$contentDigest").toString()
    }
}
