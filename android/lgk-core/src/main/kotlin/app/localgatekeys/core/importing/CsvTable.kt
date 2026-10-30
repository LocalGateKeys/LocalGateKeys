package app.localgatekeys.core.importing

/** One data row of a CSV: [values] keyed by [CsvTable.normalizeHeader], the first column with a key wins. */
internal class CsvRow(val number: Int, val cells: List<String>, val values: Map<String, String>) {
    fun pick(vararg names: String): String {
        for (n in names) {
            val v = values[CsvTable.normalizeHeader(n)]
            if (!v.isNullOrEmpty()) return v
        }
        return ""
    }

    override fun toString(): String = "CsvRow(number=$number, cells=${cells.size})"
}

/**
 * CSV the way the Windows importers read it (Python's `csv` module, excel dialect, sniffed delimiter): RFC 4180 quoting,
 * a leading BOM dropped, CRLF / LF / CR line ends. Port of Swift `CSVTable`.
 */
internal object CsvTable {
    const val FIELD_LIMIT = 131_072

    fun normalizeHeader(name: String): String {
        var s = Py.strip(name.replace("﻿", ""))
        s = Py.casefold(s).replace('_', ' ').replace('-', ' ')
        return Py.split(s).joinToString(" ")
    }

    fun sniffDelimiter(text: String): Int {
        val head = Py.splitlines(Py.prefix(text, 4096)).firstOrNull() ?: ""
        var best = ','.code
        var bestCount = 0
        for (d in intArrayOf(','.code, ';'.code, '\t'.code)) {
            val n = head.codePoints().filter { it == d }.count().toInt()
            if (n > bestCount) { best = d; bestCount = n }
        }
        return best
    }

    /** Windows `read_csv_table`: (raw header, rows). */
    fun read(text: String, maxRows: Int = ImportSource.MAX_CSV_ROWS): Pair<List<String>, List<CsvRow>> {
        if (text.contains('\u0000')) throw ImportException.malformed("CSV contains null characters")
        val reader = Reader(text, sniffDelimiter(text))
        val header = reader.next()
        if (header == null || header.none { Py.strip(it).isNotEmpty() }) throw ImportException.malformed("CSV has no header row")
        val raw = header.map { Py.strip(it.replace("﻿", "")) }
        val keys = raw.map(::normalizeHeader)
        val rows = ArrayList<CsvRow>()
        var number = 1
        while (true) {
            val values = reader.next() ?: break
            number += 1
            if (values.isEmpty() || values.all { Py.strip(it).isEmpty() }) continue
            val dict = HashMap<String, String>()
            for ((k, v) in keys.zip(values)) if (k.isNotEmpty() && k !in dict) dict[k] = v
            rows.add(CsvRow(number, values, dict))
            if (rows.size > maxRows) throw ImportException.malformed("At most ${Py.thousands(maxRows)} rows per CSV import")
        }
        return raw to rows
    }

    fun header(text: String): List<String> = read(text).first

    /** CPython `_csv.c` reader (strict off, doublequote on, no escape character). */
    private class Reader(text: String, val delimiter: Int) {
        enum class State { START_RECORD, START_FIELD, IN_FIELD, IN_QUOTED, QUOTE_IN_QUOTED, EAT_CRNL }

        val u = Py.cps(text)
        var pos = 0
        var state = State.START_RECORD
        var fields = ArrayList<String>()
        val field = StringBuilder()
        var fieldLen = 0

        private fun save() { fields.add(field.toString()); field.setLength(0); fieldLen = 0 }
        private fun add(c: Int) {
            if (fieldLen >= FIELD_LIMIT) throw ImportException.malformed("CSV is malformed")
            field.appendCodePoint(c)
            fieldLen++
        }

        fun next(): List<String>? {
            fields = ArrayList(); field.setLength(0); fieldLen = 0; state = State.START_RECORD
            do {
                if (pos >= u.size) {
                    if (fieldLen > 0 || state == State.IN_QUOTED) { save(); return fields }
                    return null
                }
                var end = pos
                while (end < u.size && u[end] != '\n'.code && u[end] != '\r'.code) end++
                if (end < u.size) end += if (u[end] == '\r'.code && end + 1 < u.size && u[end + 1] == '\n'.code) 2 else 1
                for (i in pos until end) process(u[i])
                process(null)
                pos = end
            } while (state != State.START_RECORD)
            return fields
        }

        private fun process(c: Int?) {
            val nl = c == '\n'.code || c == '\r'.code
            when (state) {
                State.START_RECORD -> {
                    if (c == null) return
                    if (nl) { state = State.EAT_CRNL; return }
                    state = State.START_FIELD
                    process(c)
                }
                State.START_FIELD -> when {
                    c == null || nl -> { save(); state = if (c == null) State.START_RECORD else State.EAT_CRNL }
                    c == '"'.code -> state = State.IN_QUOTED
                    c == delimiter -> save()
                    else -> { add(c); state = State.IN_FIELD }
                }
                State.IN_FIELD -> when {
                    c == null || nl -> { save(); state = if (c == null) State.START_RECORD else State.EAT_CRNL }
                    c == delimiter -> { save(); state = State.START_FIELD }
                    else -> add(c)
                }
                State.IN_QUOTED -> {
                    if (c == null) return
                    if (c == '"'.code) state = State.QUOTE_IN_QUOTED else add(c)
                }
                State.QUOTE_IN_QUOTED -> when {
                    c == '"'.code -> { add('"'.code); state = State.IN_QUOTED }
                    c == delimiter -> { save(); state = State.START_FIELD }
                    c == null || nl -> { save(); state = if (c == null) State.START_RECORD else State.EAT_CRNL }
                    else -> { add(c); state = State.IN_FIELD }
                }
                State.EAT_CRNL -> {
                    if (nl) return
                    if (c == null) { state = State.START_RECORD; return }
                    throw ImportException.malformed("CSV is malformed")
                }
            }
        }
    }
}

/** The Windows `ImportedRecord` builder (port of Swift `ImportRecord`). */
internal class ImportRecord(
    var kind: String = "login",
    var title: String = "",
    var notes: String = "",
    var folder: String = "",
    var favourite: Boolean = false,
    var created: Long? = null,
    var modified: Long? = null,
    var tags: List<String> = emptyList(),
    var row: Int? = null,
) {
    var username = ""
    var password = ""
    var urls: MutableList<String> = ArrayList()
    var totp = ""
    val fields = ArrayList<ImportCustomField>()
    val identity = LinkedHashMap<String, String>()
    val card = LinkedHashMap<String, String>()

    /** `add_custom_field`: skips blanks, at most 50 fields, names cut to 100 and values to 4,096 characters. */
    fun addField(name: String, value: String?, hidden: Boolean = false) {
        if (value == null || name.isEmpty() || value.isEmpty() || fields.size >= 50) return
        fields.add(ImportCustomField(Py.prefix(name, 100), Py.prefix(value, 4096), hidden))
    }

    fun addField(name: String, value: PyJson?, hidden: Boolean = false) {
        if (value == null || value == PyJson.Null) return
        addField(name, value.str, hidden)
    }

    val candidate: ImportCandidate
        get() {
            val urls = urls.filter { it.isNotEmpty() }
            val k = when (kind) {
                "login" -> ImportCandidate.Kind.LOGIN
                "card" -> ImportCandidate.Kind.CARD
                "identity" -> ImportCandidate.Kind.IDENTITY
                else -> ImportCandidate.Kind.NOTE
            }
            return ImportCandidate(
                kind = k, title = title,
                username = if (k == ImportCandidate.Kind.LOGIN) username else "",
                password = if (k == ImportCandidate.Kind.LOGIN) password else "",
                urls = urls, notes = notes, totp = totp, folder = folder, tags = tags,
                customFields = fields.filter { it.name.isNotEmpty() }, favourite = favourite,
                created = created, modified = modified, sourceRow = row,
                card = if (k == ImportCandidate.Kind.CARD) LinkedHashMap(card) else emptyMap(),
                identity = if (k == ImportCandidate.Kind.IDENTITY) LinkedHashMap(identity) else emptyMap(),
            )
        }

    companion object {
        val CARD_KEYS = setOf("cardholder", "number", "expiry", "cvv", "pin", "brand")

        /** `__post_init__` for the card dictionary: known keys, stripped, non-empty. */
        fun cleanCard(d: Map<String, String>): Map<String, String> {
            val out = LinkedHashMap<String, String>()
            for ((k, v) in d) if (k in CARD_KEYS && v.isNotEmpty()) out[k] = Py.strip(v)
            return out
        }
    }
}

internal object ImportRules {
    fun checkCount(n: Int) {
        if (n > ImportSource.MAX_RECORDS) throw ImportException(ImportException.Kind.TOO_MANY_ROWS)
    }

    fun result(records: List<ImportRecord>, diagnostics: List<String>): ImportResult {
        checkCount(records.size)
        return ImportResult(records.map { it.candidate }, diagnostics.map { ImportSkip(message = it) })
    }

    fun truthy(s: String): Boolean = Py.casefold(Py.strip(s)) in setOf("1", "true", "yes", "y", "on", "favorite")

    /** `totp_uri_from_secret`. */
    fun totpUri(secret: String, label: String = ""): String {
        val value = Py.strip(secret)
        if (value.isEmpty()) return ""
        if (Py.casefold(value).startsWith("otpauth://")) return value
        val compact = Py.rstrip(Py.split(value.replace("-", "")).joinToString("").uppercase(), setOf('='.code))
        if (compact.isEmpty()) return ""
        return "otpauth://totp/${Py.quote(label.ifEmpty { "account" }, "@:")}?secret=$compact"
    }

    private val MONTHS = listOf(
        "january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december",
    )

    /** `card_expiry`: `MM/YYYY`, or "" when unusable. */
    fun cardExpiry(month: String, year: String = ""): String {
        var m = Py.strip(month)
        var y = Py.strip(year)
        if (m.isNotEmpty() && y.isEmpty()) {
            val compact = m.replace(" ", "")
            if (Py.isAsciiDigits(compact) && Py.len(compact) == 6) {
                y = compact.substring(0, 4); m = compact.substring(4)
            } else {
                for (sep in charArrayOf('/', '-', ',', '.')) {
                    val p = Py.partition(compact, sep) ?: continue
                    if (Py.len(p.first) == 4 && Py.isAsciiDigits(p.first)) { y = p.first; m = p.second } else { m = p.first; y = p.second }
                    break
                }
            }
        }
        val key = Py.casefold(m)
        val short = MONTHS.map { Py.prefix(it, 3) }
        val number: Int = when {
            key in MONTHS -> MONTHS.indexOf(key) + 1
            !Py.isAsciiDigits(key) && Py.prefix(key, 3) in short -> short.indexOf(Py.prefix(key, 3)) + 1
            Py.isAsciiDigits(m) -> m.toIntOrNull() ?: return ""
            else -> return ""
        }
        if (number !in 1..12 || !Py.isAsciiDigits(y) || Py.len(y) !in setOf(2, 4)) return ""
        val yv = (y.toIntOrNull() ?: return "") + if (Py.len(y) == 2) 2000 else 0
        return "%02d/%04d".format(number, yv)
    }

    /** `host_title`: the URL's host name, else the URL itself. */
    fun hostTitle(url: String): String {
        val s = Py.strip(url)
        return hostname(s) ?: s
    }

    /** `urlsplit(url).hostname` (null when absent or the URL is refused). */
    fun hostname(url: String): String? {
        var rest = Py.lstrip(url, (0..0x20).toSet()).replace("\t", "").replace("\r", "").replace("\n", "")
        val colon = rest.indexOf(':')
        if (colon > 0) {
            val scheme = rest.substring(0, colon)
            val schemeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-."
            if (scheme[0] in 'a'..'z' || scheme[0] in 'A'..'Z') {
                if (scheme.all { it in schemeChars }) rest = rest.substring(colon + 1)
            }
        }
        if (!rest.startsWith("//")) return null
        val after = rest.substring(2)
        val netloc = after.takeWhile { it != '/' && it != '?' && it != '#' }
        if (netloc.contains('[') != netloc.contains(']')) return null
        val host = netloc.split('@').last()
        var name = if (host.contains('[')) host.split('[', limit = 2)[1].split(']', limit = 2)[0] else host.split(':', limit = 2)[0]
        name = name.lowercase()
        return name.ifEmpty { null }
    }
}
