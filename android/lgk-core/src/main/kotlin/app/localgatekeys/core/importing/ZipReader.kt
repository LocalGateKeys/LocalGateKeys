package app.localgatekeys.core.importing

import java.util.zip.CRC32
import java.util.zip.DataFormatException
import java.util.zip.Inflater

/** One member of a zip archive, from the central directory. */
class ZipEntry internal constructor(
    val name: String,
    val method: Int,
    val flags: Int,
    val crc: Long,
    val compressedSize: Int,
    val uncompressedSize: Int,
    internal val localHeaderOffset: Int,
    internal val rawName: ByteArray,
) {
    val isEncrypted: Boolean get() = flags and 0x1 != 0
    val isDirectory: Boolean get() = name.endsWith("/")

    override fun toString(): String = "ZipEntry(name=$name, method=$method, size=$uncompressedSize)"
}

/**
 * A bounded reader for untrusted import archives (port of Swift `ZipReader`): classic zip only (zip64 is refused),
 * stored or raw-deflated members, no encrypted members, no `..`/absolute/drive names, no duplicate names, caps on
 * entries, archive size, decompressed size and compression ratio. Every member is CRC-checked, and its local header
 * must carry the central directory's name.
 */
class ZipReader(private val b: ByteArray, maxBytes: Int, maxEntries: Int) {
    enum class Failure(val message: String) {
        CORRUPT("The zip archive is damaged or incomplete"),
        ZIP64("This zip archive uses the zip64 format, which is not supported"),
        UNSAFE_NAME("The zip archive contains a file name that points outside the archive and was refused"),
        DUPLICATE_NAME("The zip archive contains the same file name twice and was refused"),
        TOO_MANY_ENTRIES("The zip archive contains too many files"),
        TOO_LARGE("A file inside the zip archive is too large"),
        RATIO("A file inside the zip archive is compressed suspiciously well and was refused"),
        ENCRYPTED("A file inside the zip archive is encrypted"),
        UNSUPPORTED_METHOD("A file inside the zip archive uses an unsupported compression method"),
    }

    class ZipException(val failure: Failure) : Exception(failure.message)

    private val list: List<ZipEntry>

    init {
        if (b.size > maxBytes) fail(Failure.TOO_LARGE)
        if (b.size < 22) fail(Failure.CORRUPT)
        var eocd = -1
        var i = b.size - 22
        val floor = maxOf(0, b.size - 22 - 65_535)
        while (i >= floor) {
            if (b[i] == 0x50.toByte() && b[i + 1] == 0x4B.toByte() && b[i + 2] == 0x05.toByte() && b[i + 3] == 0x06.toByte()) { eocd = i; break }
            i--
        }
        if (eocd < 0) fail(Failure.CORRUPT)
        var cdEnd = eocd
        if (eocd >= 20 && u32(eocd - 20) == 0x0706_4B50L) {
            cdEnd = eocd - 20
            if (cdEnd >= 56 && u32(cdEnd - 56) == 0x0606_4B50L) cdEnd -= 56
        }
        val disk = u16(eocd + 4)
        val cdDisk = u16(eocd + 6)
        val countHere = u16(eocd + 8)
        val count = u16(eocd + 10)
        val size = u32(eocd + 12)
        val offset = u32(eocd + 16)
        if (count == 0xFFFF || size == 0xFFFF_FFFFL || offset == 0xFFFF_FFFFL) fail(Failure.ZIP64)
        if (disk != 0 || cdDisk != 0 || countHere != count) fail(Failure.CORRUPT)
        if (count > maxEntries) fail(Failure.TOO_MANY_ENTRIES)
        val shift = cdEnd - size - offset
        if (shift < 0) fail(Failure.CORRUPT)
        var p = offset + shift
        val entries = ArrayList<ZipEntry>()
        val seen = HashSet<String>()
        repeat(count) {
            if (p + 46 > cdEnd || u32(p.toInt()) != 0x0201_4B50L) fail(Failure.CORRUPT)
            val q = p.toInt()
            val flags = u16(q + 8)
            val method = u16(q + 10)
            val crc = u32(q + 16)
            val csize = u32(q + 20)
            val usize = u32(q + 24)
            val n = u16(q + 28)
            val extra = u16(q + 30)
            val comment = u16(q + 32)
            val local = u32(q + 42)
            if (csize == 0xFFFF_FFFFL || usize == 0xFFFF_FFFFL || local == 0xFFFF_FFFFL) fail(Failure.ZIP64)
            if (p + 46 + n + extra + comment > cdEnd) fail(Failure.CORRUPT)
            val raw = b.copyOfRange(q + 46, q + 46 + n)
            val name = if (flags and 0x800 != 0) {
                try {
                    Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(raw)).toString()
                } catch (e: Exception) {
                    fail(Failure.CORRUPT)
                }
            } else {
                val sb = StringBuilder()
                for (x in raw) sb.appendCodePoint(cp437(x.toInt() and 0xFF))
                sb.toString()
            }
            if (!isSafe(name)) fail(Failure.UNSAFE_NAME)
            if (!seen.add(name)) fail(Failure.DUPLICATE_NAME)
            if (csize > Int.MAX_VALUE || usize > Int.MAX_VALUE || local + shift > Int.MAX_VALUE) fail(Failure.CORRUPT)
            entries.add(ZipEntry(name, method, flags, crc, csize.toInt(), usize.toInt(), (local + shift).toInt(), raw))
            p += 46 + n + extra + comment
        }
        list = entries
    }

    private fun u16(i: Int): Int = (b[i].toInt() and 0xFF) or ((b[i + 1].toInt() and 0xFF) shl 8)
    private fun u32(i: Int): Long = (u16(i).toLong()) or (u16(i + 2).toLong() shl 16)

    fun entries(): List<ZipEntry> = list

    fun entry(name: String): ZipEntry? = list.firstOrNull { it.name == name }

    /** The member's bytes, refusing more than [limit] decompressed bytes and anything [Failure] names. */
    fun read(e: ZipEntry, limit: Int): ByteArray {
        if (e.isEncrypted) fail(Failure.ENCRYPTED)
        if (e.method != 0 && e.method != 8) fail(Failure.UNSUPPORTED_METHOD)
        if (e.uncompressedSize > limit) fail(Failure.TOO_LARGE)
        checkRatio(e.uncompressedSize.toLong(), e.compressedSize.toLong())
        val p = e.localHeaderOffset
        if (p + 30 > b.size || b[p] != 0x50.toByte() || b[p + 1] != 0x4B.toByte() || b[p + 2] != 0x03.toByte() || b[p + 3] != 0x04.toByte()) {
            fail(Failure.CORRUPT)
        }
        val n = u16(p + 26)
        val extra = u16(p + 28)
        val start = p + 30 + n + extra
        if (p + 30 + n > b.size || !(e.rawName.isEmpty() || b.copyOfRange(p + 30, p + 30 + n).contentEquals(e.rawName))) fail(Failure.CORRUPT)
        if (start > b.size || e.compressedSize > b.size - start) fail(Failure.CORRUPT)
        val out: ByteArray = if (e.method == 0) {
            if (e.compressedSize != e.uncompressedSize) fail(Failure.CORRUPT)
            b.copyOfRange(start, start + e.compressedSize)
        } else {
            val ratioCap = maxOf(RATIO_FLOOR.toLong(), e.compressedSize.toLong() * MAX_RATIO)
            inflate(b, start, e.compressedSize, limit, ratioCap)
        }
        val crc = CRC32().apply { update(out) }.value
        if (out.size != e.uncompressedSize || crc != e.crc) fail(Failure.CORRUPT)
        return out
    }

    override fun toString(): String = "ZipReader(entries=${list.size})"

    companion object {
        const val MAX_RATIO = 200
        const val RATIO_FLOOR = 1024 * 1024
        const val DEFAULT_MAX_ENTRIES = 20_005

        private fun fail(f: Failure): Nothing = throw ZipException(f)

        /** Relative names only: no empty, `.` or `..` component, no leading slash or backslash, no drive letter, no NUL. */
        fun isSafe(name: String): Boolean {
            if (name.isEmpty() || name.contains('\u0000')) return false
            if (name.startsWith("/") || name.startsWith("\\")) return false
            val u = Py.cps(name)
            if (u.size >= 2 && u[1] == ':'.code) return false
            val parts = name.split('/', '\\')
            for ((i, part) in parts.withIndex()) {
                if (part == ".." || part == ".") return false
                if (part.isEmpty() && i != parts.size - 1) return false
            }
            return true
        }

        fun checkRatio(uncompressed: Long, compressed: Long) {
            if (uncompressed > RATIO_FLOOR && uncompressed / maxOf(compressed, 1L) > MAX_RATIO) fail(Failure.RATIO)
        }

        /** Raw DEFLATE, bounded by [limit] (too large) and [ratioLimit] (ratio) output bytes. */
        internal fun inflate(src: ByteArray, off: Int, len: Int, limit: Int, ratioLimit: Long): ByteArray {
            val inf = Inflater(true)
            try {
                // A raw stream may need one extra dummy byte at the end (java.util.zip's documented quirk).
                val input = src.copyOfRange(off, off + len) + byteArrayOf(0)
                inf.setInput(input)
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(64 * 1024)
                while (!inf.finished()) {
                    val k = try {
                        inf.inflate(buf)
                    } catch (e: DataFormatException) {
                        fail(Failure.CORRUPT)
                    }
                    if (k > 0) {
                        if (out.size() + k > limit) fail(Failure.TOO_LARGE)
                        if (out.size() + k > ratioLimit) fail(Failure.RATIO)
                        out.write(buf, 0, k)
                    } else if (inf.needsInput() || inf.needsDictionary()) {
                        fail(Failure.CORRUPT)
                    }
                }
                return out.toByteArray()
            } finally {
                inf.end()
            }
        }

        private val CP437_HIGH = intArrayOf(
            0xC7, 0xFC, 0xE9, 0xE2, 0xE4, 0xE0, 0xE5, 0xE7, 0xEA, 0xEB, 0xE8, 0xEF, 0xEE, 0xEC, 0xC4, 0xC5,
            0xC9, 0xE6, 0xC6, 0xF4, 0xF6, 0xF2, 0xFB, 0xF9, 0xFF, 0xD6, 0xDC, 0xA2, 0xA3, 0xA5, 0x20A7, 0x192,
            0xE1, 0xED, 0xF3, 0xFA, 0xF1, 0xD1, 0xAA, 0xBA, 0xBF, 0x2310, 0xAC, 0xBD, 0xBC, 0xA1, 0xAB, 0xBB,
            0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
            0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
            0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
            0x3B1, 0xDF, 0x393, 0x3C0, 0x3A3, 0x3C3, 0xB5, 0x3C4, 0x3A6, 0x398, 0x3A9, 0x3B4, 0x221E, 0x3C6, 0x3B5, 0x2229,
            0x2261, 0xB1, 0x2265, 0x2264, 0x2320, 0x2321, 0xF7, 0x2248, 0xB0, 0x2219, 0xB7, 0x221A, 0x207F, 0xB2, 0x25A0, 0xA0,
        )

        fun cp437(x: Int): Int = if (x < 0x80) x else CP437_HIGH[x - 0x80]
    }
}
