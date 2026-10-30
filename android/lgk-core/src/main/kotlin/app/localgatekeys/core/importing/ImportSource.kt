package app.localgatekeys.core.importing

/**
 * The import sources the apps understand; [raw] values match the iPhone/Mac `ImportFormat` (vectors use them).
 * Android reads [supported] ones; the rest are recognised so the app can say "import it on your PC".
 */
enum class ImportFormat(val raw: String, val label: String) {
    APPLE_CSV("appleCSV", "Safari passwords CSV"),
    CHROME("chrome", "Chrome / Edge / Brave passwords CSV"),
    FIREFOX("firefox", "Firefox logins CSV"),
    BITWARDEN("bitwarden", "Bitwarden JSON"),
    BITWARDEN_ENCRYPTED("bitwardenEncrypted", "Bitwarden password-protected JSON"),
    ONE_PASSWORD_1PUX("onePassword1PUX", "1Password export (.1pux)"),
    ONE_PASSWORD_CSV("onePasswordCSV", "1Password CSV"),
    LAST_PASS("lastPass", "LastPass CSV"),
    KEEPASS_KDBX("keePassKDBX", "KeePass 2 database (.kdbx)"),
    KEEPASS_XML("keePassXML", "KeePass 2 XML export"),
    KEEPASS_CSV("keePassCSV", "KeePass / KeePassXC CSV"),
    PROTON_PASS("protonPass", "Proton Pass export (.zip / JSON)"),
    DASHLANE("dashlane", "Dashlane export (.zip of CSV files)"),
    GENERIC("generic", "Generic CSV (choose columns)"),
    ;

    /** Whether this phone can read the format (v1: browser CSVs, Bitwarden, 1Password .1pux and generic CSV). */
    val supported: Boolean get() = this in SUPPORTED

    /** The format asks for the file's password before it is read. */
    val needsPassword: Boolean get() = this == BITWARDEN_ENCRYPTED

    companion object {
        private val SUPPORTED = setOf(APPLE_CSV, CHROME, FIREFOX, BITWARDEN, BITWARDEN_ENCRYPTED, ONE_PASSWORD_1PUX, GENERIC)

        fun fromRaw(raw: String): ImportFormat? = entries.firstOrNull { it.raw == raw }
    }
}

/** Column indices chosen for a CSV the app does not recognise. */
data class GenericCsvMapping(
    val title: Int? = null,
    val url: Int? = null,
    val username: Int? = null,
    val password: Int? = null,
    val notes: Int? = null,
    val totp: Int? = null,
)

/** [password] opens an encrypted export (used once, never stored). toString never shows it. */
class ImportOptions(val password: String? = null, val mapping: GenericCsvMapping? = null) {
    override fun toString(): String = "ImportOptions(password=${if (password == null) "none" else "set"}, mapping=$mapping)"
}

data class ImportCustomField(val name: String, val value: String, val hidden: Boolean) {
    override fun toString(): String = "ImportCustomField(name=$name, hidden=$hidden)"
}

/**
 * One item parsed from an import source, before it becomes a vault record (the iPhone's `ImportCandidate`, flattened).
 * [totp] is an `otpauth://` URI or "". [card] keys: cardholder, number, expiry (MM/YYYY), cvv, pin, brand; [identity]
 * keys as on Windows (name, given_name, email, ...). toString shows no values.
 */
data class ImportCandidate(
    val kind: Kind,
    val title: String,
    val username: String = "",
    val password: String = "",
    val urls: List<String> = emptyList(),
    val notes: String = "",
    val totp: String = "",
    val folder: String = "",
    val tags: List<String> = emptyList(),
    val customFields: List<ImportCustomField> = emptyList(),
    val favourite: Boolean = false,
    val created: Long? = null,
    val modified: Long? = null,
    val sourceRow: Int? = null,
    val card: Map<String, String> = emptyMap(),
    val identity: Map<String, String> = emptyMap(),
) {
    enum class Kind(val raw: String) { LOGIN("login"), NOTE("note"), CARD("card"), IDENTITY("identity") }

    override fun toString(): String = "ImportCandidate(kind=$kind, row=$sourceRow, fields=${customFields.size})"
}

/** A source item that was not imported, or a note about what was left out (the Windows diagnostics). */
data class ImportSkip(val row: Int? = null, val message: String)

data class ImportResult(val candidates: List<ImportCandidate> = emptyList(), val skipped: List<ImportSkip> = emptyList())

/** An import that failed; [message] is the Windows wording (never a value from the file). */
class ImportException(val kind: Kind, val detail: String = "") : Exception(kind.name) {
    enum class Kind { TOO_LARGE, TOO_MANY_ROWS, UNKNOWN_FORMAT, MALFORMED, NEEDS_PASSWORD, WRONG_PASSWORD, UNSUPPORTED }

    override val message: String
        get() = when (kind) {
            Kind.TOO_LARGE -> "Import source exceeds 8 MiB"
            Kind.TOO_MANY_ROWS -> "At most 5,000 records per import"
            Kind.UNKNOWN_FORMAT -> "The file could not be recognised as a password-manager export; it may be damaged."
            Kind.MALFORMED, Kind.UNSUPPORTED -> detail
            Kind.NEEDS_PASSWORD -> "This export is password protected"
            Kind.WRONG_PASSWORD -> "Wrong password or corrupted export (MAC mismatch)"
        }

    val isWrongPassword: Boolean get() = kind == Kind.WRONG_PASSWORD

    companion object {
        fun malformed(m: String) = ImportException(Kind.MALFORMED, m)
    }
}

/** Runs the importer for a format (Windows `load_records`), with the Windows caps. */
object ImportSource {
    const val MAX_SOURCE_BYTES = 8 * 1024 * 1024

    /** The largest file the phone opens at all (archives, and the picker's read limit). */
    const val MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
    const val MAX_RECORDS = 5_000
    const val MAX_CSV_ROWS = 20_000
    const val MAX_DIAGNOSTICS = 50

    fun candidates(data: ByteArray, format: ImportFormat, options: ImportOptions = ImportOptions()): ImportResult {
        if (data.size > MAX_ARCHIVE_BYTES) throw ImportException.malformed("Import source exceeds 64 MiB")
        val result = when (format) {
            ImportFormat.APPLE_CSV, ImportFormat.CHROME, ImportFormat.FIREFOX -> BrowserCsv.load(data)
            ImportFormat.BITWARDEN -> BitwardenJson.candidates(data, options)
            ImportFormat.BITWARDEN_ENCRYPTED -> BitwardenEncrypted.candidates(data, options)
            ImportFormat.ONE_PASSWORD_1PUX -> OnePassword1pux.candidates(data)
            ImportFormat.GENERIC -> GenericCsv.candidates(data, options)
            else -> throw ImportException(
                ImportException.Kind.UNSUPPORTED,
                "${format.label} files cannot be imported on this phone yet. Import it in the LocalGateKeys app on your PC, then sync.",
            )
        }
        return result.copy(skipped = capDiagnostics(result.skipped))
    }

    internal fun capDiagnostics(list: List<ImportSkip>): List<ImportSkip> {
        if (list.size <= MAX_DIAGNOSTICS) return list
        val extra = list.size - MAX_DIAGNOSTICS
        return list.take(MAX_DIAGNOSTICS) + ImportSkip(message = "...and ${Py.thousands(extra)} more ${if (extra == 1) "message" else "messages"}.")
    }
}
