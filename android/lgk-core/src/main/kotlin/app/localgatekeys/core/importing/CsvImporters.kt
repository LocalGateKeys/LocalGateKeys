package app.localgatekeys.core.importing

/** Chrome / Edge / Brave, Firefox and Safari (Apple Passwords) CSV exports (Windows `load_browser_csv`). */
internal object BrowserCsv {
    enum class Layout { CHROME, FIREFOX, SAFARI }

    fun classify(header: List<String>): Layout? {
        val keys = header.map(CsvTable::normalizeHeader).toSet()
        if (keys.containsAll(setOf("url", "username", "password", "httprealm", "formactionorigin"))) return Layout.FIREFOX
        if (keys.containsAll(setOf("title", "url", "username", "password", "otpauth")) && keys.none { it in setOf("favorite", "archived", "tags") }) {
            return Layout.SAFARI
        }
        if (keys.containsAll(setOf("name", "url", "username", "password"))) return Layout.CHROME
        return null
    }

    fun load(data: ByteArray): ImportResult {
        val (header, rows) = CsvTable.read(ImportText.text(data))
        val layout = classify(header) ?: Layout.CHROME
        val records = ArrayList<ImportRecord>()
        val diagnostics = ArrayList<String>()
        for (row in rows) {
            var url = Py.strip(row.pick("url"))
            if (url.isEmpty() && layout == Layout.FIREFOX) url = Py.strip(row.pick("formActionOrigin"))
            val username = row.pick("username")
            val password = row.pick("password")
            if (url.isEmpty() && username.isEmpty() && password.isEmpty()) {
                diagnostics.add("Row ${row.number}: empty row; skipped.")
                continue
            }
            val name = row.pick("name", "title")
            val title = name.ifEmpty { ImportRules.hostTitle(url) }
            val r = ImportRecord(kind = "login", title = title, notes = row.pick("note", "notes"), row = row.number)
            r.username = username
            r.password = password
            if (url.isNotEmpty()) r.urls.add(url)
            r.totp = ImportRules.totpUri(row.pick("otpauth", "totp"), title)
            if (layout == Layout.FIREFOX) {
                r.created = ImportTime.parse(row.pick("timeCreated"))
                r.modified = ImportTime.parse(row.pick("timePasswordChanged")) ?: ImportTime.parse(row.pick("timeLastUsed"))
            }
            records.add(r)
        }
        return ImportRules.result(records, diagnostics)
    }
}

/** Any CSV, through a column mapping (Windows `load_generic_csv`). */
object GenericCsv {
    /** Windows `FIELD_ALIASES`, in the order targets are guessed. */
    private val ALIASES: List<Pair<String, List<String>>> = listOf(
        "title" to listOf("name", "title", "account", "label", "item"),
        "url" to listOf("url", "login uri", "web site", "website", "uri", "login url", "site", "address", "hostname"),
        "username" to listOf("username", "login username", "login name", "user name", "user", "login", "email"),
        "password" to listOf("password", "login password", "pass", "pwd", "secret"),
        "notes" to listOf("notes", "note", "comments", "comment", "extra", "notesplain"),
        "totp" to listOf("totp", "login totp", "otpauth", "otp", "one-time password", "otpsecret", "totp secret"),
    )

    /** The raw header row, for the column chooser. */
    fun header(data: ByteArray): List<String> = CsvTable.header(ImportText.text(data))

    /** Windows `guess_mapping`. */
    fun suggestMapping(header: List<String>): GenericCsvMapping {
        val keys = header.map(CsvTable::normalizeHeader)
        val chosen = HashMap<String, Int>()
        val used = HashSet<String>()
        for ((target, names) in ALIASES) {
            for (alias in names) {
                val key = CsvTable.normalizeHeader(alias)
                val i = keys.indexOf(key)
                if (i >= 0 && key !in used) {
                    chosen[target] = i
                    used.add(key)
                    break
                }
            }
        }
        return GenericCsvMapping(chosen["title"], chosen["url"], chosen["username"], chosen["password"], chosen["notes"], chosen["totp"])
    }

    fun candidates(data: ByteArray, options: ImportOptions): ImportResult {
        val (header, rows) = CsvTable.read(ImportText.text(data))
        val m = options.mapping ?: suggestMapping(header)
        for (i in listOfNotNull(m.title, m.url, m.username, m.password, m.notes, m.totp)) {
            if (i !in header.indices) throw ImportException.malformed("Column ${i + 1} does not exist in the CSV header")
        }
        if (m.password == null && m.notes == null) {
            throw ImportException.malformed("CSV columns could not be mapped; choose the password column")
        }
        val records = ArrayList<ImportRecord>()
        val diagnostics = ArrayList<String>()
        for (row in rows) {
            fun cell(i: Int?): String = if (i != null && i < row.cells.size) row.cells[i] else ""
            val url = Py.strip(cell(m.url))
            val username = cell(m.username)
            val password = cell(m.password)
            val named = cell(m.title)
            val title = named.ifEmpty { ImportRules.hostTitle(url) }
            val notes = cell(m.notes)
            if (url.isEmpty() && username.isEmpty() && password.isEmpty()) {
                if (notes.isNotEmpty()) {
                    records.add(ImportRecord(kind = "note", title = title.ifEmpty { "Row ${row.number}" }, notes = notes, row = row.number))
                } else {
                    diagnostics.add("Row ${row.number}: empty row; skipped.")
                }
                continue
            }
            val r = ImportRecord(kind = "login", title = title, notes = notes, row = row.number)
            r.username = username
            r.password = password
            if (url.isNotEmpty()) r.urls.add(url)
            r.totp = ImportRules.totpUri(cell(m.totp), title)
            records.add(r)
        }
        return ImportRules.result(records, diagnostics)
    }
}
