package app.localgatekeys.core.importing

/**
 * Port of the Windows `detect.py` (via Swift `ImportDetect`): content sniffing with the file name as a hint. Returns
 * null wherever Windows refuses the file (PGP, KeePass 1, unknown JSON/XML/zip, binary or empty files). Formats this
 * phone cannot read yet are still named (see [ImportFormat.supported]).
 */
object ImportDetect {
    private val KDBX_MAGIC = byteArrayOf(0x03, 0xD9.toByte(), 0xA2.toByte(), 0x9A.toByte())
    private val DASHLANE_ZIP_FILES = setOf("credentials.csv", "securenotes.csv", "payments.csv", "ids.csv", "personalinfo.csv")
    private val SPACE = setOf(0xFEFF, ' '.code, '\t'.code, '\r'.code, '\n'.code)

    fun detect(data: ByteArray, filename: String): ImportFormat? {
        if (data.size > ImportSource.MAX_ARCHIVE_BYTES) return null
        val suffix = Py.casefold(pathSuffix(filename))
        if (startsWith(data, KDBX_MAGIC)) {
            if (data.size >= 8 && data[4] == 0x65.toByte() && data[5] == 0xFB.toByte() && data[6] == 0x4B.toByte() && data[7] == 0xB5.toByte()) {
                return null
            }
            return ImportFormat.KEEPASS_KDBX
        }
        if (suffix == ".kdbx" || suffix == ".kdb") return null
        if (data.size >= 2 && data[0] == 0x50.toByte() && data[1] == 0x4B.toByte()) {
            val names = zipNames(data) ?: return null
            if ("export.data" in names) return ImportFormat.ONE_PASSWORD_1PUX
            val base = names.map { Py.casefold(it.split('/').last()) }.toSet()
            if ("data.pgp" in base) return null
            if ("data.json" in base) return ImportFormat.PROTON_PASS
            if (base.any { it in DASHLANE_ZIP_FILES }) return ImportFormat.DASHLANE
            return null
        }
        if (suffix == ".1pux" || suffix == ".1pif") return null
        var k = 0
        while (k < data.size && (data[k].toInt() and 0xFF) in setOf(0x20, 0x09, 0x0A, 0x0D, 0x0B, 0x0C)) k++
        val pgp = "-----BEGIN PGP MESSAGE-----".toByteArray(Charsets.US_ASCII)
        if (data.size - k >= pgp.size && data.copyOfRange(k, k + pgp.size).contentEquals(pgp) || suffix == ".pgp" || suffix == ".gpg") return null
        val limit = 4 * 1024 * 1024
        val text = try {
            ImportText.decode(if (data.size > limit) data.copyOf(limit) else data)
        } catch (e: ImportException) {
            return null
        }
        val stripped = Py.lstrip(text, SPACE)
        if (stripped.startsWith("{")) {
            val full = try {
                ImportText.decode(data)
            } catch (e: ImportException) {
                return null
            }
            return detectJson(full)
        }
        if (stripped.startsWith("<")) return if (Py.prefix(stripped, 4096).contains("<KeePassFile")) ImportFormat.KEEPASS_XML else null
        if (stripped.isEmpty() || Py.prefix(stripped, 4096).contains('\u0000')) return null
        val first = Py.splitlines(stripped).firstOrNull() ?: ""
        if (suffix in setOf("", ".csv", ".txt", ".tsv") || first.contains(',') || first.contains(';') || first.contains('\t')) {
            val full = try {
                ImportText.decode(data)
            } catch (e: ImportException) {
                return null
            }
            return detectCsv(full)
        }
        return null
    }

    private fun startsWith(b: ByteArray, p: ByteArray): Boolean = b.size >= p.size && p.indices.all { b[it] == p[it] }

    /** `PurePath.suffix`. */
    internal fun pathSuffix(filename: String): String {
        val name = filename.split('/').last()
        val dot = name.lastIndexOf('.')
        if (dot <= 0 || dot == name.length - 1) return ""
        return name.substring(dot)
    }

    internal fun detectJson(text: String): ImportFormat? {
        val doc = try {
            PyJson.parse(text)
        } catch (e: Exception) {
            return null
        }
        if (!doc.isObject) return null
        if (doc["vaults"]?.isObject == true) return if (doc["encrypted"]?.isTrue == true) null else ImportFormat.PROTON_PASS
        if (doc["encrypted"]?.isTrue == true) {
            if (doc["passwordProtected"]?.truthy != true) return null
            if (doc.has("data")) return ImportFormat.BITWARDEN_ENCRYPTED
        }
        if (doc["items"]?.isList == true) return ImportFormat.BITWARDEN
        if (doc["accounts"]?.isList == true) return ImportFormat.ONE_PASSWORD_1PUX
        return null
    }

    private fun dashlaneClassify(keys: Set<String>): String {
        fun has(vararg s: String) = keys.containsAll(s.toList())
        if (has("cc number", "account name") || has("cc number", "expiration month")) return "payments"
        if (has("first name", "last name", "item name")) return "personal"
        if (has("type", "number", "name", "issue date", "expiration date")) return "ids"
        if (has("title", "password") && keys.any { it in setOf("username2", "otpsecret", "otpurl", "category") }) return "credentials"
        if (keys == setOf("title", "note") || keys == setOf("title", "note", "category")) return "notes"
        if (has("title", "url", "password")) return "credentials"
        return ""
    }

    internal fun detectCsv(text: String): ImportFormat? {
        val header = try {
            CsvTable.header(text)
        } catch (e: ImportException) {
            return null
        }
        val keys = header.map(CsvTable::normalizeHeader).toSet()
        fun has(vararg s: String) = keys.containsAll(s.toList())
        return when {
            has("type", "name", "url", "username", "password", "note", "totp", "vault") -> ImportFormat.PROTON_PASS
            has("login uri", "login username", "login password") -> ImportFormat.BITWARDEN
            has("url", "username", "password", "extra", "grouping") -> ImportFormat.LAST_PASS
            has("title", "password") && keys.any { it in setOf("username2", "otpsecret") } ||
                (has("title", "url", "username", "password", "note") && "category" in keys) -> ImportFormat.DASHLANE
            keys == setOf("title", "note") || keys == setOf("title", "note", "category") -> ImportFormat.DASHLANE
            dashlaneClassify(keys) in setOf("payments", "personal", "ids") -> ImportFormat.DASHLANE
            has("title", "url", "username", "password") && keys.any { it in setOf("favorite", "archived", "tags") } -> ImportFormat.ONE_PASSWORD_CSV
            has("url", "username", "password", "httprealm", "formactionorigin") -> ImportFormat.FIREFOX
            has("title", "url", "username", "password", "otpauth") -> ImportFormat.APPLE_CSV
            has("account", "login name", "password") || has("group", "title", "username", "password", "url") -> ImportFormat.KEEPASS_CSV
            has("name", "url", "username", "password") -> ImportFormat.CHROME
            has("title", "url", "username", "password", "note") -> ImportFormat.DASHLANE
            else -> ImportFormat.GENERIC
        }
    }

    /** Member names from the zip central directory (null when it cannot be read). */
    internal fun zipNames(b: ByteArray): List<String>? {
        fun u16(i: Int) = (b[i].toInt() and 0xFF) or ((b[i + 1].toInt() and 0xFF) shl 8)
        fun u32(i: Int): Long = u16(i).toLong() or (u16(i + 2).toLong() shl 16)
        if (b.size < 22) return null
        var eocd = -1
        var i = b.size - 22
        val floor = maxOf(0, b.size - 22 - 65_535)
        while (i >= floor) {
            if (b[i] == 0x50.toByte() && b[i + 1] == 0x4B.toByte() && b[i + 2] == 0x05.toByte() && b[i + 3] == 0x06.toByte()) { eocd = i; break }
            i--
        }
        if (eocd < 0) return null
        val count = u16(eocd + 10)
        val size = u32(eocd + 12)
        val offset = u32(eocd + 16)
        val shift = eocd - size - offset
        if (shift < 0) return null
        var p = offset + shift
        val names = ArrayList<String>()
        repeat(count) {
            if (p + 46 > b.size) return null
            val q = p.toInt()
            if (b[q] != 0x50.toByte() || b[q + 1] != 0x4B.toByte() || b[q + 2] != 0x01.toByte() || b[q + 3] != 0x02.toByte()) return null
            val flags = u16(q + 8)
            val n = u16(q + 28)
            val extra = u16(q + 30)
            val comment = u16(q + 32)
            if (q + 46 + n > b.size) return null
            val raw = b.copyOfRange(q + 46, q + 46 + n)
            names.add(
                if (flags and 0x800 != 0) String(raw, Charsets.UTF_8)
                else buildString { for (x in raw) appendCodePoint(ZipReader.cp437(x.toInt() and 0xFF)) },
            )
            p += 46 + n + extra + comment
        }
        return names
    }
}
