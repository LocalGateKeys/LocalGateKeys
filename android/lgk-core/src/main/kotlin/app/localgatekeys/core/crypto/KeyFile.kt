package app.localgatekeys.core.crypto

import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.RandomSource
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import javax.xml.parsers.SAXParserFactory
import org.xml.sax.Attributes
import org.xml.sax.InputSource
import org.xml.sax.SAXException
import org.xml.sax.ext.DefaultHandler2

/** The file looks like a KeePass XML key file but is not a valid one, or its key is not 32 bytes. */
class KeyFileException(message: String) : Exception(message)

/**
 * KeePass key files (docs/formats/COMPOSITE_KEY_V1.md §1.1; Python `src/localvault/keyfile.py`), tried in order:
 *
 * 1. XML (the file trimmed of ASCII space/tab/CR/LF starts with `<?xml` or `<KeyFile`): `Meta/Version` starting with
 *    "2" means hex data with an optional `Hash` check, anything else Base64 data. A DOCTYPE or malformed XML is refused.
 * 2. exactly 32 bytes: the file itself;
 * 3. exactly 64 bytes, all hex digits: the decoded hex;
 * 4. anything else: SHA-256 of the whole file.
 */
object KeyFile {
    const val KEY_SIZE = 32
    /** Larger than any real key file (the Windows app's `MAX_KEYFILE_BYTES`); a reader stops after this many bytes. */
    const val MAX_BYTES = 64 * 1024 * 1024
    private const val MAX_ELEMENTS = 10_000

    /**
     * Test hook: false skips the Xerces-only parser features, as on Android (expat), so the tests prove that the
     * handler's own DOCTYPE and entity refusals hold without them.
     */
    @Volatile internal var parserFeatures = true

    private fun isWhitespace(b: Int) = b == 0x20 || b == 0x09 || b == 0x0a || b == 0x0d

    /** The key material under KeePass rules; XML data may have any length (an importer's view). */
    fun keyMaterial(data: ByteArray): ByteArray {
        var start = 0
        var end = data.size
        while (start < end && isWhitespace(data[start].toInt() and 0xff)) start++
        while (end > start && isWhitespace(data[end - 1].toInt() and 0xff)) end--
        if (startsWith(data, start, end, "<?xml") || startsWith(data, start, end, "<KeyFile")) {
            val text = data.copyOfRange(start, end)
            try {
                return xmlKey(text)
            } finally {
                text.fill(0)
            }
        }
        if (data.size == KEY_SIZE) return data.copyOf()
        if (data.size == 2 * KEY_SIZE && data.all { isHexDigit(it.toInt() and 0xff) }) {
            return hexDecode(CharArray(data.size) { (data[it].toInt() and 0xff).toChar() }, wipe = true)
        }
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    /** The 32-byte key of a key file used as an unlock factor; XML data of another length is refused. */
    fun keyFromBytes(data: ByteArray): ByteArray {
        val key = keyMaterial(data)
        if (key.size != KEY_SIZE) {
            key.fill(0)
            throw KeyFileException("Key file data must be 32 bytes")
        }
        return key
    }

    /** A KeePass XML 2.0 key file for [key] in the layout KeePass and KeePassXC write. */
    fun keepassXmlV2(key: ByteArray): ByteArray {
        require(key.size == KEY_SIZE) { "key must be 32 bytes" }
        val hex = Hex.lower(key).uppercase()
        val groups = hex.chunked(8)
        val lines = groups.chunked(4).joinToString("") { "\n            " + it.joinToString(" ") }
        val checksum = Hex.lower(MessageDigest.getInstance("SHA-256").digest(key).copyOf(4)).uppercase()
        return (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<KeyFile>\n" +
                "    <Meta>\n" +
                "        <Version>2.0</Version>\n" +
                "    </Meta>\n" +
                "    <Key>\n" +
                "        <Data Hash=\"$checksum\">$lines\n" +
                "        </Data>\n" +
                "    </Key>\n" +
                "</KeyFile>\n"
            ).toByteArray(Charsets.US_ASCII)
    }

    /** A new random KeePass XML 2.0 key file ("Create key file"); it also opens in KeePass and KeePassXC. */
    fun newKeepassXmlV2(random: RandomSource): ByteArray {
        val key = random.bytes(KEY_SIZE)
        try {
            return keepassXmlV2(key)
        } finally {
            key.fill(0)
        }
    }

    private fun startsWith(b: ByteArray, start: Int, end: Int, prefix: String): Boolean =
        end - start >= prefix.length && prefix.indices.all { b[start + it].toInt() == prefix[it].code }

    private fun hexValue(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    /** Hex digits (either case, even count, already checked) to bytes; [wipe] zeroes [chars] afterwards. */
    private fun hexDecode(chars: CharArray, wipe: Boolean): ByteArray {
        try {
            return ByteArray(chars.size / 2) { ((hexValue(chars[2 * it]) shl 4) or hexValue(chars[2 * it + 1])).toByte() }
        } finally {
            if (wipe) chars.fill('\u0000')
        }
    }

    private fun isHexDigit(c: Int) = c in 0x30..0x39 || c in 0x41..0x46 || c in 0x61..0x66

    /** Which element texts the key needs; text is the character data before an element's first child (ElementTree's `.text`). */
    private class Collector : DefaultHandler2() {
        private val path = ArrayList<String?>()
        private var elements = 0
        var version: StringBuilder? = null
        var data: StringBuilder? = null
        var hash: String? = null
        private var collecting: StringBuilder? = null

        override fun startDTD(name: String?, publicId: String?, systemId: String?) = throw SAXException(DOCTYPE)

        override fun resolveEntity(name: String?, publicId: String?, baseURI: String?, systemId: String?): InputSource =
            throw SAXException(DOCTYPE)

        override fun startElement(uri: String?, localName: String?, qName: String?, attributes: Attributes) {
            if (++elements > MAX_ELEMENTS) throw SAXException("too many elements")
            collecting = null
            // Namespaced elements are not the plain names ElementTree's find() looks for.
            val name = if (uri.isNullOrEmpty()) localName?.ifEmpty { qName } else null
            path.add(name)
            val depth = path.size
            if (depth == 3 && path[1] == "Meta" && path[2] == "Version" && version == null) {
                version = StringBuilder().also { collecting = it }
            } else if (depth == 3 && path[1] == "Key" && path[2] == "Data" && data == null) {
                data = StringBuilder().also { collecting = it }
                hash = attributes.getValue("", "Hash") ?: attributes.getValue("Hash")
            }
        }

        override fun endElement(uri: String?, localName: String?, qName: String?) {
            path.removeAt(path.size - 1)
            collecting = null
        }

        override fun characters(ch: CharArray, start: Int, length: Int) {
            collecting?.append(ch, start, length)
        }
    }

    private const val DOCTYPE = "Key file contains a DOCTYPE and was rejected"

    private fun xmlKey(text: ByteArray): ByteArray {
        val collector = Collector()
        try {
            val factory = SAXParserFactory.newInstance()
            factory.isNamespaceAware = true
            factory.isValidating = false
            if (parserFeatures) for ((feature, on) in listOf(
                "http://apache.org/xml/features/disallow-doctype-decl" to true,
                "http://xml.org/sax/features/external-general-entities" to false,
                "http://xml.org/sax/features/external-parameter-entities" to false,
                "http://apache.org/xml/features/nonvalidating/load-external-dtd" to false,
            )) {
                // Not every parser knows every feature (Android's expat-based one); startDTD refuses a DOCTYPE anyway.
                try { factory.setFeature(feature, on) } catch (e: Exception) {}
            }
            val reader = factory.newSAXParser().xmlReader
            reader.contentHandler = collector
            reader.entityResolver = collector
            reader.setProperty("http://xml.org/sax/properties/lexical-handler", collector)
            reader.errorHandler = object : org.xml.sax.helpers.DefaultHandler() {
                override fun fatalError(e: org.xml.sax.SAXParseException) = throw e
                override fun error(e: org.xml.sax.SAXParseException) = throw e
            }
            reader.parse(InputSource(ByteArrayInputStream(text)))
        } catch (e: SAXException) {
            if (e.message?.contains("DOCTYPE") == true) throw KeyFileException(DOCTYPE)
            throw KeyFileException("Key file XML is malformed")
        } catch (e: Exception) {
            throw KeyFileException("Key file XML is malformed")
        }
        val version = (collector.version?.toString() ?: "").trim { isWhitespace(it.code) }.ifEmpty { "1.0" }
        // The key text as a wipeable char array (the builder is overwritten too); no String copy of it is made.
        val raw = collector.data ?: StringBuilder()
        val payload = CharArray(raw.count { !isWhitespace(it.code) })
        var n = 0
        for (i in raw.indices) if (!isWhitespace(raw[i].code)) payload[n++] = raw[i]
        for (i in raw.indices) raw.setCharAt(i, '\u0000')
        try {
            if (payload.isEmpty()) throw KeyFileException("Key file XML has no key data")
            if (version.startsWith("2")) {
                if (payload.size % 2 != 0 || !payload.all { it.code < 128 && isHexDigit(it.code) }) {
                    throw KeyFileException("Key file 2.0 data must be hexadecimal")
                }
                val key = hexDecode(payload, wipe = false)
                val expected = collector.hash
                if (!expected.isNullOrEmpty()) {
                    val actual = Hex.lower(MessageDigest.getInstance("SHA-256").digest(key))
                    if (expected.length > actual.length || !actual.substring(0, expected.length).equals(expected, ignoreCase = true)) {
                        key.fill(0)
                        throw KeyFileException("Key file hash does not match its data")
                    }
                }
                return key
            }
            return base64(payload) ?: throw KeyFileException("Key file 1.0 data must be Base64")
        } finally {
            payload.fill('\u0000')
        }
    }

    /** Python `base64.b64decode(s, validate=True)`: the standard alphabet, correct padding; spare bits are ignored. */
    private fun base64(s: CharArray): ByteArray? {
        var len = s.size
        while (len > 0 && s[len - 1] == '=') len--
        val pads = s.size - len
        if (pads > 2 || (0 until len).any { val c = s[it]; !(c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '+' || c == '/') }) return null
        val needed = when (len % 4) {
            0 -> 0
            2 -> 2
            3 -> 1
            else -> return null
        }
        if (pads != needed || (len == 0 && pads > 0)) return null
        val out = ByteArray(len * 6 / 8)
        var o = 0
        var acc = 0
        var bits = 0
        for (i in 0 until len) {
            val c = s[i]
            val v = when (c) {
                in 'A'..'Z' -> c - 'A'
                in 'a'..'z' -> c - 'a' + 26
                in '0'..'9' -> c - '0' + 52
                '+' -> 62
                else -> 63
            }
            acc = ((acc shl 6) or v) and 0xFFFFFF
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out[o++] = ((acc shr bits) and 0xFF).toByte()
            }
        }
        return out
    }
}
