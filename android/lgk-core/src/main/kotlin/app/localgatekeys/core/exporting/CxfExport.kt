package app.localgatekeys.core.exporting

import app.localgatekeys.core.importing.CxfImport
import app.localgatekeys.core.importing.ImportCandidate
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Url
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.sync.StoreSnapshot
import java.net.URLDecoder
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset

/** Something the export left out, named so the person knows ([title] is the item's title; "" for an item that is gone). */
data class CxfDiagnostic(val kind: Kind, val title: String) {
    enum class Kind { FIELDS_LEFT_OUT, KIND_SKIPPED, PASSKEY_NOTES_LEFT_OUT }
}

/** An export that wrote nothing. */
class CxfExportException(val kind: Kind, val title: String = "") : Exception(kind.name) {
    enum class Kind { CHOOSE_ITEMS, PASSKEY_KEY_MISSING, NOTHING_TO_EXPORT }
}

/**
 * The selected items as records, passkeys still without their private keys; [passkeys] maps each selected passkey's
 * item id to its title. toString shows no values.
 */
class CxfExportPlan internal constructor(
    internal val records: List<Pair<String, ImportCandidate>>,
    val passkeys: Map<String, String>,
    val diagnostics: List<CxfDiagnostic>,
) {
    val count: Int get() = records.size

    override fun toString(): String = "CxfExportPlan(records=${records.size}, passkeys=${passkeys.size}, diagnostics=${diagnostics.size})"
}

/** The file's bytes (plaintext secrets: write them, then clear them) and what it holds. toString shows no bytes. */
class CxfExportResult(val bytes: ByteArray, val count: Int, val diagnostics: List<CxfDiagnostic>) {
    override fun toString(): String = "CxfExportResult(size=${bytes.size}, count=$count, diagnostics=${diagnostics.size})"
}

/**
 * Credential Exchange Format (CXF v1.0) account export, the exact inverse of [CxfImport] (port of the Windows
 * `exporters/cxf.py`): one `Account` document with an item per record, so a file written here imports back into the
 * same records.
 *
 * * login -> `basic-auth` (always, even when empty), its 2FA setup as a `totp` credential, its notes as a `note`;
 * * note -> an item with a single `note` credential;
 * * passkey -> a `passkey` credential whose `key` is the base64url PKCS#8 DER private key.
 *
 * Only the selected items are exported. Private keys are never read by [plan]: [export] asks its `release` callback for
 * them (the app's owner check) only when a passkey is selected, and when it refuses (throws) or leaves one out nothing
 * is made. The document is built fully in memory, so a failed export leaves no file behind.
 */
object CxfExport {
    private val ALGORITHMS = mapOf("SHA1" to "sha1", "SHA256" to "sha256", "SHA512" to "sha512")

    private fun s(v: String): JsonValue = JsonValue.Str(v)

    private fun newId(random: RandomSource): String = Base64Url.encodeNoPad(random.bytes(16))

    private fun field(value: String, random: RandomSource, type: String = "string"): JsonValue =
        JsonValue.Obj(linkedMapOf("id" to s(newId(random)), "fieldType" to s(type), "value" to s(value)))

    /** Percent-decoding without turning `+` into a space (Python `unquote`). */
    private fun unquote(text: String): String = try {
        URLDecoder.decode(text.replace("+", "%2B"), "UTF-8")
    } catch (e: Exception) {
        text
    }

    /** An `otpauth://totp` URI split into a CXF `totp` credential (Windows `_totp_credential`), or null. */
    internal fun totpCredential(uri: String): JsonValue? {
        val sep = uri.indexOf("://")
        if (sep < 0 || uri.substring(0, sep).lowercase() != "otpauth") return null
        val rest = uri.substring(sep + 3).substringBefore('#')
        val netEnd = rest.indexOfFirst { it == '/' || it == '?' }.let { if (it < 0) rest.length else it }
        if (rest.substring(0, netEnd).lowercase() != "totp") return null
        val after = rest.substring(netEnd)
        val path = after.substringBefore('?')
        val queryText = if (after.contains('?')) after.substringAfter('?') else ""
        val query = LinkedHashMap<String, String>()
        for (pair in queryText.split('&')) {
            val parts = pair.split('=', limit = 2)
            if (parts.size != 2 || parts[1].isEmpty()) continue
            fun dec(x: String) = try { URLDecoder.decode(x, "UTF-8") } catch (e: Exception) { x }
            val key = dec(parts[0]).lowercase()
            if (key !in query) query[key] = dec(parts[1])
        }
        val secret = (query["secret"] ?: "").trim()
        if (secret.isEmpty()) return null
        val label = unquote(path.trimStart('/'))
        var issuer = query["issuer"] ?: ""
        val colon = label.indexOf(':')
        val account: String
        if (colon >= 0) {
            if (issuer.isEmpty()) issuer = label.substring(0, colon)
            account = label.substring(colon + 1)
        } else {
            account = if (label == "account") "" else label
        }
        fun number(key: String, default: Int): Int {
            val v = query[key] ?: return default
            return if (v.isNotEmpty() && v.length <= 6 && v.all { it in '0'..'9' }) v.toInt() else default
        }
        val out = linkedMapOf(
            "type" to s("totp"), "secret" to s(secret), "period" to JsonValue.Int(number("period", 30).toLong()),
            "digits" to JsonValue.Int(number("digits", 6).toLong()),
            "algorithm" to s(ALGORITHMS[(query["algorithm"] ?: "SHA1").uppercase()] ?: "sha1"),
        )
        if (account.isNotEmpty()) out["username"] = s(account)
        if (issuer.isNotEmpty()) out["issuer"] = s(issuer)
        return JsonValue.Obj(out)
    }

    private fun dateStamp(text: String): Long? = try {
        LocalDate.parse(text).atStartOfDay().toEpochSecond(ZoneOffset.UTC)
    } catch (e: Exception) {
        null
    }

    private fun item(record: ImportCandidate, now: Long, random: RandomSource): JsonValue {
        val credentials = ArrayList<JsonValue>()
        var created = record.created
        when (record.kind) {
            ImportCandidate.Kind.LOGIN -> {
                // Always present, even when empty: without it the importer would read the item as a note (or drop it).
                credentials.add(
                    JsonValue.Obj(
                        linkedMapOf(
                            "type" to s("basic-auth"), "username" to field(record.username, random),
                            "password" to field(record.password, random, "concealed-string"),
                        ),
                    ),
                )
                if (record.totp.isNotEmpty()) totpCredential(record.totp)?.let { credentials.add(it) }
                if (record.notes.isNotEmpty()) credentials.add(JsonValue.Obj(linkedMapOf("type" to s("note"), "content" to field(record.notes, random))))
            }
            ImportCandidate.Kind.NOTE -> credentials.add(JsonValue.Obj(linkedMapOf("type" to s("note"), "content" to field(record.notes, random))))
            ImportCandidate.Kind.PASSKEY -> {
                val p = record.passkey
                credentials.add(
                    JsonValue.Obj(
                        linkedMapOf(
                            "type" to s("passkey"), "credentialId" to s(p["credential_id"] ?: ""), "rpId" to s(p["relying_party_id"] ?: ""),
                            "username" to s(p["user_name"] ?: ""), "userDisplayName" to s(p["user_display_name"] ?: ""),
                            "userHandle" to s(p["user_handle"] ?: ""), "key" to s(p["private_key"] ?: ""),
                        ),
                    ),
                )
                created = dateStamp(p["created"] ?: "") ?: created
            }
            else -> throw IllegalArgumentException("CXF export cannot hold a ${record.kind.raw} record")
        }
        val out = linkedMapOf<String, JsonValue>("id" to s(newId(random)))
        if (created != null && created != 0L) out["creationAt"] = JsonValue.Int(created)
        out["modifiedAt"] = JsonValue.Int(record.modified ?: created?.takeIf { it != 0L } ?: now)
        out["title"] = s(record.title)
        out["scope"] = JsonValue.Obj(linkedMapOf("urls" to JsonValue.Arr(record.urls.map(::s)), "androidApps" to JsonValue.Arr(emptyList())))
        out["credentials"] = JsonValue.Arr(credentials)
        return JsonValue.Obj(out)
    }

    /**
     * One CXF `Account` document with an item per record (logins, notes and passkeys only; anything else throws
     * IllegalArgumentException). [now] (Unix seconds) dates items whose modification time is unknown.
     */
    fun build(records: List<ImportCandidate>, now: Long, random: RandomSource, exporterName: String = "LocalGateKeys"): ByteArray {
        val doc = JsonValue.Obj(
            linkedMapOf(
                "id" to s(newId(random)), "username" to s(exporterName), "email" to s(""), "collections" to JsonValue.Arr(emptyList()),
                "items" to JsonValue.Arr(records.map { item(it, now, random) }), "extensions" to JsonValue.Arr(emptyList()),
            ),
        )
        return CanonicalJson.encode(doc, Dialect.UTF8)
    }

    // MARK: vault -> records

    private fun str(v: JsonValue?): String = when (v) {
        is JsonValue.Str -> v.v
        is JsonValue.Int -> v.v.toString()
        else -> ""
    }

    private fun obj(v: JsonValue?): Map<String, JsonValue> = (v as? JsonValue.Obj)?.fields ?: emptyMap()

    private fun stamp(v: JsonValue?): Long? = (v as? JsonValue.Int)?.v?.takeIf { it != 0L }

    /** The live record of [id] and its namespace wire name, or null when missing or deleted. */
    private fun live(snapshot: StoreSnapshot, id: String): Pair<String, Map<String, JsonValue>>? {
        if (snapshot.meta[id]?.deleted == true) return null
        // A collection state is never an item (`StoreSnapshot.itemRecords`).
        if (app.localgatekeys.core.sync.CollectionStates.isReserved(id, snapshot.records[id])) return null
        val w = obj(snapshot.records[id])
        val ns = (w["ns"] as? JsonValue.Str)?.v ?: return null
        val r = (w["record"] as? JsonValue.Obj)?.fields ?: return null
        return ns to r
    }

    private fun entryUrls(r: Map<String, JsonValue>): List<String> {
        val scope = obj(r["scope"])
        val rows = (scope["urls"] as? JsonValue.Arr)?.items ?: emptyList()
        val urls = rows.mapNotNull { row -> str(obj(row)["url"]).takeIf { it.isNotEmpty() } }
        if (urls.isNotEmpty()) return urls
        val origin = str(scope["origin"])
        return if (origin.isNotEmpty()) listOf(origin) else emptyList()
    }

    /** The login as a record, and whether it held data CXF has no place for (custom fields, recovery codes). */
    private fun loginRecord(r: Map<String, JsonValue>, includeTotp: Boolean): Pair<ImportCandidate, Boolean> {
        val web = r["kind"] == s("web")
        val label = str(r["label"])
        val origin = str(obj(r["scope"])["origin"])
        val username = str(r["username"])
        var totp = ""
        val t = obj(r["totp"])
        if (includeTotp && str(t["secret"]).isNotEmpty()) {
            val issuer = str(t["issuer"])
            val name = if (issuer.isNotEmpty() && username.isNotEmpty()) "$issuer:$username" else username.ifEmpty { issuer }
            totp = CxfImport.totpUri(
                str(t["secret"]), label = name, issuer = issuer,
                digits = (t["digits"] as? JsonValue.Int)?.v?.toInt()?.takeIf { it != 0 } ?: 6,
                period = (t["period"] as? JsonValue.Int)?.v?.toInt()?.takeIf { it != 0 } ?: 30,
                algorithm = str(t["algorithm"]).ifEmpty { "SHA1" },
            )
        }
        val scope = obj(r["scope"])
        val dropped = ((r["custom_fields"] as? JsonValue.Arr)?.items?.isNotEmpty() == true) ||
            ((r["recovery_codes"] as? JsonValue.Arr)?.items?.any { str(it).isNotEmpty() } == true) ||
            (!web && (str(scope["exe_path"]).isNotEmpty() || str(scope["window_title"]).isNotEmpty()))
        val record = ImportCandidate(
            kind = ImportCandidate.Kind.LOGIN, title = label.ifEmpty { if (web && origin.isNotEmpty()) origin else "Credential" },
            username = username, password = str(r["password"]), urls = if (web) entryUrls(r) else emptyList(),
            notes = str(r["notes"]), totp = totp, created = stamp(r["created_at"]), modified = stamp(r["updated_at"]),
        )
        return record to dropped
    }

    /** The passkey without its private key (added once released). */
    private fun passkeyRecord(r: Map<String, JsonValue>): ImportCandidate {
        val p = obj(r["payload"])
        val values = LinkedHashMap<String, String>()
        for (key in CxfImport.PASSKEY_KEYS) if (key != "private_key") values[key] = str(p[key])
        if (values["created"].isNullOrEmpty()) {
            stamp(r["created_at"])?.let { values["created"] = Instant.ofEpochSecond(it).atOffset(ZoneOffset.UTC).toLocalDate().toString() }
        }
        val rp = values["relying_party_id"] ?: ""
        return ImportCandidate(
            kind = ImportCandidate.Kind.PASSKEY, title = str(r["title"]).ifEmpty { rp }, username = values["user_name"] ?: "",
            urls = if (rp.isNotEmpty()) listOf("https://$rp") else emptyList(), passkey = values.filterValues { it.isNotEmpty() },
        )
    }

    /** Collects the selected items ([ids], in order, repeats dropped); throws [CxfExportException] for none. */
    fun plan(snapshot: StoreSnapshot, ids: List<String>, includeTotp: Boolean = true): CxfExportPlan {
        val wanted = ids.distinct()
        if (wanted.isEmpty()) throw CxfExportException(CxfExportException.Kind.CHOOSE_ITEMS)
        val records = ArrayList<Pair<String, ImportCandidate>>()
        val passkeys = LinkedHashMap<String, String>()
        val diagnostics = ArrayList<CxfDiagnostic>()
        for (id in wanted) {
            val (ns, r) = live(snapshot, id) ?: run {
                // Deleted since it was listed: no title to show (never the raw id).
                diagnostics.add(CxfDiagnostic(CxfDiagnostic.Kind.KIND_SKIPPED, "")); null
            } ?: continue
            val kind = str(r["kind"])
            when {
                ns == Namespace.ENTRY.wire && (kind == "web" || kind == "desktop") -> {
                    val (record, dropped) = loginRecord(r, includeTotp)
                    records.add(id to record)
                    if (dropped) diagnostics.add(CxfDiagnostic(CxfDiagnostic.Kind.FIELDS_LEFT_OUT, record.title))
                }
                ns == Namespace.ITEM.wire && kind == "passkey" -> {
                    val record = passkeyRecord(r)
                    if (str(obj(r["payload"])["notes"]).isNotBlank()) diagnostics.add(CxfDiagnostic(CxfDiagnostic.Kind.PASSKEY_NOTES_LEFT_OUT, record.title))
                    passkeys[id] = record.title
                    records.add(id to record)
                }
                ns == Namespace.ITEM.wire && kind == "note" -> {
                    val p = obj(r["payload"])
                    val record = ImportCandidate(
                        kind = ImportCandidate.Kind.NOTE, title = str(r["title"]), notes = str(p["body"]),
                        created = stamp(r["created_at"]), modified = stamp(r["updated_at"]),
                    )
                    if ((p["fields"] as? JsonValue.Arr)?.items?.isNotEmpty() == true) {
                        diagnostics.add(CxfDiagnostic(CxfDiagnostic.Kind.FIELDS_LEFT_OUT, record.title))
                    }
                    records.add(id to record)
                }
                else -> {
                    val title = str(r["title"]).ifEmpty { str(r["label"]) }
                    diagnostics.add(CxfDiagnostic(CxfDiagnostic.Kind.KIND_SKIPPED, title))
                }
            }
        }
        return CxfExportPlan(records, passkeys, diagnostics)
    }

    /** The stored private keys of the passkeys [ids] (what the app's `release` returns after the owner check). */
    fun privateKeys(snapshot: StoreSnapshot, ids: Collection<String>): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (id in ids) {
            val (ns, r) = live(snapshot, id) ?: continue
            if (ns != Namespace.ITEM.wire || r["kind"] != s("passkey")) continue
            str(obj(r["payload"])["private_key"]).takeIf { it.isNotEmpty() }?.let { out[id] = it }
        }
        return out
    }

    /**
     * The file for [plan] with the [released] private keys (item id -> key). Every selected passkey needs its key, or
     * [CxfExportException] with [CxfExportException.Kind.PASSKEY_KEY_MISSING] and nothing is made.
     */
    fun finish(plan: CxfExportPlan, released: Map<String, String>, now: Long, random: RandomSource, exporterName: String = "LocalGateKeys"): CxfExportResult {
        val records = plan.records.map { (id, record) ->
            if (record.kind != ImportCandidate.Kind.PASSKEY) return@map record
            val key = released[id]
            if (key.isNullOrEmpty()) throw CxfExportException(CxfExportException.Kind.PASSKEY_KEY_MISSING, record.title)
            val payload = LinkedHashMap<String, String>()
            for (k in CxfImport.PASSKEY_KEYS) (if (k == "private_key") key else record.passkey[k])?.let { payload[k] = it }
            record.copy(passkey = payload)
        }
        if (records.isEmpty()) throw CxfExportException(CxfExportException.Kind.NOTHING_TO_EXPORT)
        return CxfExportResult(build(records, now, random, exporterName), records.size, plan.diagnostics)
    }

    /**
     * The selected items ([ids]) as a CXF file. [release] gets the ids of the selected passkeys and returns their private
     * keys; it is called only when a passkey is selected, after every other record is collected, and anything it
     * throws (the person declined) propagates with nothing made.
     */
    fun export(
        snapshot: StoreSnapshot,
        ids: List<String>,
        release: (List<String>) -> Map<String, String>,
        now: Long,
        random: RandomSource,
        includeTotp: Boolean = true,
    ): CxfExportResult {
        val plan = plan(snapshot, ids, includeTotp)
        val released = if (plan.passkeys.isEmpty()) emptyMap() else release(plan.passkeys.keys.toList())
        return finish(plan, released, now, random)
    }
}
