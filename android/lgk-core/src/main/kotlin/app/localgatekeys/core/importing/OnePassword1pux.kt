package app.localgatekeys.core.importing

import app.localgatekeys.core.json.PythonFloat

/** 1Password 1PUX archives (Windows `onepassword.load_1pux`): `export.data` inside a zip (or the bare JSON). */
internal object OnePassword1pux {
    const val MAX_EXPORT_DATA_BYTES = 16 * 1024 * 1024
    const val CORRUPT_MESSAGE = "1PUX archive is corrupted or unsupported"

    private val LOGIN_CATEGORIES = setOf("001", "005", "102", "109", "110", "111", "112")
    private val CATEGORY_NAMES = mapOf(
        "001" to "Login", "002" to "Credit Card", "003" to "Secure Note", "004" to "Identity", "005" to "Password",
        "006" to "Document", "100" to "Software License", "101" to "Bank Account", "102" to "Database",
        "103" to "Driver License", "104" to "Outdoor License", "105" to "Membership", "106" to "Passport",
        "107" to "Reward Program", "108" to "Social Security Number", "109" to "Wireless Router", "110" to "Server",
        "111" to "Email Account", "112" to "API Credential", "113" to "Medical Record", "114" to "Crypto Wallet",
    )
    private val IDENTITY_IDS = mapOf(
        "firstname" to "given_name", "initial" to "middle_name", "lastname" to "family_name", "company" to "company",
        "jobtitle" to "job_title", "email" to "email", "defphone" to "phone", "cellphone" to "phone", "homephone" to "phone",
        "busphone" to "phone", "website" to "website",
    )
    private val CARD_IDS = mapOf("cardholder" to "cardholder", "ccnum" to "number", "cvv" to "cvv", "expiry" to "expiry", "pin" to "pin", "type" to "brand")
    private val ADDRESS_KEYS = listOf("street" to "address_line1", "city" to "city", "state" to "state", "zip" to "postal_code", "country" to "country")
    private val SENSITIVE_HINTS = listOf("password", "secret", "pin", "key", "number", "cvv", "code", "token", "seed", "passphrase")

    fun candidates(data: ByteArray): ImportResult = records(exportData(data))

    /** Windows `read_export_data`. */
    fun exportData(data: ByteArray): PyJson {
        val source = ImportText.bounded(data, ImportSource.MAX_ARCHIVE_BYTES)
        var raw = source
        if (source.size >= 2 && source[0] == 0x50.toByte() && source[1] == 0x4B.toByte()) {
            val zip = try {
                ZipReader(source, ImportSource.MAX_ARCHIVE_BYTES, ZipReader.DEFAULT_MAX_ENTRIES)
            } catch (e: ZipReader.ZipException) {
                throw archiveError(e.failure)
            }
            val entry = zip.entry("export.data") ?: throw ImportException.malformed("1PUX archive does not contain export.data")
            if (entry.uncompressedSize > MAX_EXPORT_DATA_BYTES) throw ImportException.malformed("export.data is too large")
            if (entry.isEncrypted) throw ImportException.malformed("export.data is encrypted inside the 1PUX archive; export again from 1Password")
            if (entry.method != 0 && entry.method != 8) throw ImportException.malformed("export.data uses an unsupported ZIP compression method")
            raw = try {
                zip.read(entry, MAX_EXPORT_DATA_BYTES)
            } catch (e: ZipReader.ZipException) {
                if (e.failure == ZipReader.Failure.TOO_LARGE) throw ImportException.malformed("export.data is too large")
                throw archiveError(e.failure)
            }
        }
        if (raw.size > MAX_EXPORT_DATA_BYTES) throw ImportException.malformed("export.data is too large")
        val doc = try {
            PyJson.parse(ImportText.decode(raw))
        } catch (e: Exception) {
            throw ImportException.malformed("export.data is not valid JSON")
        }
        if (!doc.isObject) throw ImportException.malformed("export.data is not a 1Password export object")
        return doc
    }

    fun archiveError(f: ZipReader.Failure): ImportException = when (f) {
        ZipReader.Failure.CORRUPT, ZipReader.Failure.ZIP64, ZipReader.Failure.UNSUPPORTED_METHOD, ZipReader.Failure.ENCRYPTED ->
            ImportException.malformed(CORRUPT_MESSAGE)
        else -> ImportException.malformed(f.message)
    }

    /** Windows `records_from_export`. */
    fun records(doc: PyJson): ImportResult {
        val accounts = (doc["accounts"] as? PyJson.Arr)?.items ?: throw ImportException.malformed("export.data has no 'accounts' list")
        val records = ArrayList<ImportRecord>()
        val diagnostics = ArrayList<String>()
        var trashed = 0
        var index = 0
        for (account in accounts) {
            if (!account.isObject) continue
            for (vault in account["vaults"]?.list ?: emptyList()) {
                if (!vault.isObject) continue
                val attrs = vault["attrs"]?.takeIf { it.isObject } ?: PyJson.Obj(emptyList())
                val vaultName = PyJson.text(attrs["name"])
                for (item in vault["items"]?.list ?: emptyList()) {
                    index++
                    ImportRules.checkCount(index)
                    if (!item.isObject) { diagnostics.add("Item $index: not an object; skipped."); continue }
                    if (item["trashed"]?.truthy == true || Py.casefold(PyJson.text(item["state"])) == "trashed") {
                        trashed++
                        continue
                    }
                    records.add(record(item, vaultName, index))
                }
            }
        }
        if (trashed > 0) diagnostics.add("$trashed items in the 1Password trash were not imported.")
        return ImportRules.result(records, diagnostics)
    }

    private fun obj(v: PyJson?): PyJson = if (v != null && v.isObject) v else PyJson.Obj(emptyList())

    /** Windows `item_to_record`. */
    fun record(item: PyJson, vaultName: String, row: Int): ImportRecord {
        val overview = obj(item["overview"])
        val details = obj(item["details"])
        val categoryValue = item["categoryUuid"]
        val category = if (categoryValue != null && categoryValue.truthy) categoryValue.str else "001"
        val title = PyJson.text(overview["title"])
        val urls = ArrayList<String>()
        if (overview["url"]?.truthy == true) urls.add(overview["url"]!!.str)
        for (entry in overview["urls"]?.list ?: emptyList()) {
            if (!entry.isObject) continue
            val u = entry["url"]
            if (u != null && u.truthy && u.str !in urls) urls.add(u.str)
        }
        var folder = vaultName
        if (Py.casefold(PyJson.text(item["state"])) == "archived") folder = if (vaultName.isEmpty()) "Archive" else "$vaultName/Archive"
        val r = ImportRecord(
            title = title, notes = PyJson.text(details["notesPlain"]), folder = folder, favourite = item["favIndex"]?.truthy ?: false,
            created = ImportTime.parse(item["createdAt"]), modified = ImportTime.parse(item["updatedAt"]),
            tags = (overview["tags"]?.list ?: emptyList()).map { it.str }, row = row,
        )
        when {
            category == "003" -> r.kind = "note"
            category == "004" -> r.kind = "identity"
            category == "002" -> r.kind = "card"
            category in LOGIN_CATEGORIES -> {
                r.kind = "login"
                val (u, p) = loginFields(details)
                r.username = u; r.password = p
                r.urls = ArrayList(urls)
            }
            else -> {
                r.kind = "note"
                r.addField("1Password category", CATEGORY_NAMES[category] ?: category)
            }
        }
        for (section in details["sections"]?.list ?: emptyList()) {
            if (!section.isObject) continue
            for (field in section["fields"]?.list ?: emptyList()) if (field.isObject) apply(field, r, title)
        }
        if (r.kind == "identity") {
            val name = Py.strip(listOf("given_name", "middle_name", "family_name").joinToString(" ") { r.identity[it] ?: "" })
            if (name.isNotEmpty() && r.identity["name"] == null) r.identity["name"] = Py.split(name).joinToString(" ")
        }
        if (category == "006" || details["documentAttributes"]?.truthy == true) {
            r.addField("Attached file", "The file itself was not imported. Save it from 1Password and add it to LocalGateKeys as a document.")
        }
        return r
    }

    private fun apply(field: PyJson, r: ImportRecord, title: String) {
        val fieldId = Py.casefold(PyJson.text(field["id"]))
        val titleValue = field["title"]
        val idValue = field["id"]
        val label = if (titleValue != null && titleValue.truthy) titleValue.str else if (idValue != null && idValue.truthy) idValue.str else ""
        val (type, text) = fieldValue(field["value"])
        if (text.isEmpty()) return
        if (type == "totp") {
            if (r.totp.isEmpty()) r.totp = ImportRules.totpUri(text, title)
            return
        }
        if (r.kind == "identity") {
            val address = field["value"]?.get("address")
            if (type == "address" && address != null && address.isObject) {
                for ((key, target) in ADDRESS_KEYS) {
                    val v = address[key]
                    if (v != null && v.truthy) r.identity[target] = v.str
                }
                return
            }
            val target = IDENTITY_IDS[fieldId]
            if (target != null && (r.identity[target] ?: "").isEmpty()) {
                r.identity[target] = text
                return
            }
        }
        if (r.kind == "card") {
            val target = CARD_IDS[fieldId]
            if (target != null && (r.card[target] ?: "").isEmpty()) {
                val value = if (fieldId == "expiry") ImportRules.cardExpiry(text) else text
                if (value.isNotEmpty()) { r.card[target] = value; return }
            }
        }
        if (r.kind == "login") {
            if (fieldId == "username" && r.username.isEmpty()) { r.username = text; return }
            if (fieldId == "password" && r.password.isEmpty()) { r.password = text; return }
        }
        if (type == "url" && r.kind == "login") {
            if (text !in r.urls) r.urls.add(text)
            return
        }
        val lowerLabel = Py.casefold(label)
        val hidden = type in setOf("concealed", "creditCardNumber", "sshKey") || field["guarded"]?.truthy == true ||
            SENSITIVE_HINTS.any { fieldId.contains(it) || lowerLabel.contains(it) }
        r.addField(label, text, hidden)
    }

    /** Windows `_login_fields`. */
    fun loginFields(details: PyJson): Pair<String, String> {
        var username = ""
        var password = ""
        for (field in details["loginFields"]?.list ?: emptyList()) {
            if (!field.isObject) continue
            val designation = Py.casefold(PyJson.text(field["designation"]))
            val value = PyJson.text(field["value"])
            if (designation == "username" && username.isEmpty()) username = value
            else if (designation == "password" && password.isEmpty()) password = value
            else if (designation.isEmpty() && field["fieldType"] == PyJson.Str("P") && password.isEmpty()) password = value
        }
        if (password.isEmpty() && details["password"]?.truthy == true) password = details["password"]!!.str
        return username to password
    }

    /** Windows `_field_value`: (type, text) of a section field value object. */
    fun fieldValue(value: PyJson?): Pair<String, String> {
        if (value == null || !value.isObject) return "" to ""
        val key = value.firstKey ?: return "" to ""
        val raw = value[key] ?: return "" to ""
        if (raw == PyJson.Null) return key to ""
        if (raw.isObject && key == "email") return key to PyJson.text(raw["email_address"])
        if (raw.isObject && key == "address") {
            val parts = listOf("street", "city", "state", "zip", "country").map { PyJson.text(raw[it]) }
            return key to parts.filter { it.isNotEmpty() }.joinToString(", ")
        }
        val integer: Long? = when (raw) {
            is PyJson.Int -> raw.v
            is PyJson.Bool -> if (raw.v) 1 else 0
            else -> null
        }
        if (integer != null) {
            val text = raw.str
            if (key == "monthYear") {
                val u = Py.cps(text)
                return key to if (u.size == 6) Py.str(u, 4, 6) + "/" + Py.str(u, 0, 4) else text
            }
            if (key == "date") return key to (date(integer) ?: text)
            return key to text
        }
        if (raw is PyJson.Float && key == "date" && raw.v.isFinite() && kotlin.math.abs(raw.v) < 1e15) return key to (date(raw.v.toLong()) ?: raw.str)
        if (raw.isObject || raw.isList) return key to dumps(raw)
        return key to raw.str
    }

    /** `datetime.fromtimestamp(int(raw), tz=UTC).strftime("%Y-%m-%d")`, null where Python raises. */
    private fun date(seconds: Long): String? {
        val day = try {
            java.time.LocalDate.ofEpochDay(Math.floorDiv(seconds, 86400L))
        } catch (e: java.time.DateTimeException) {
            return null
        }
        if (day.year !in 1..9999) return null
        return "%04d-%02d-%02d".format(day.year, day.monthValue, day.dayOfMonth)
    }

    /** `json.dumps(value, ensure_ascii=False)`. */
    fun dumps(v: PyJson): String = when (v) {
        PyJson.Null -> "null"
        is PyJson.Bool -> if (v.v) "true" else "false"
        is PyJson.Int -> v.v.toString()
        is PyJson.Float -> when {
            v.v.isNaN() -> "NaN"
            v.v.isInfinite() -> if (v.v > 0) "Infinity" else "-Infinity"
            else -> PythonFloat.repr(v.v)
        }
        is PyJson.Str -> {
            val out = StringBuilder("\"")
            v.v.codePoints().forEach { c ->
                when (c) {
                    '"'.code -> out.append("\\\"")
                    '\\'.code -> out.append("\\\\")
                    '\n'.code -> out.append("\\n")
                    '\r'.code -> out.append("\\r")
                    '\t'.code -> out.append("\\t")
                    0x08 -> out.append("\\b")
                    0x0C -> out.append("\\f")
                    else -> if (c < 0x20) out.append("\\u%04x".format(c)) else out.appendCodePoint(c)
                }
            }
            out.append('"').toString()
        }
        is PyJson.Arr -> v.items.joinToString(", ", "[", "]") { dumps(it) }
        is PyJson.Obj -> {
            val keys = LinkedHashSet<String>()
            for ((k, _) in v.pairs) keys.add(k)
            keys.joinToString(", ", "{", "}") { dumps(PyJson.Str(it)) + ": " + dumps(v[it]!!) }
        }
    }
}
