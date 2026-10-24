package app.localgatekeys.core.records

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Casefold
import app.localgatekeys.core.primitives.Scalars
import java.security.MessageDigest

/**
 * `REJECTED`: the desktop would refuse this record ([detail] is for humans only). `NEEDS_PUNYCODE`: a non-ASCII
 * host, the editor asks for the `xn--` form. `NOT_PHONE_KIND`: a kind the phone never edits; such records pass
 * through untouched.
 */
class NormaliseException(val kind: Kind, val detail: String = "") : Exception(detail.ifEmpty { kind.name }) {
    enum class Kind { REJECTED, NEEDS_PUNYCODE, NOT_PHONE_KIND }
}

/**
 * The phone's record normaliser: desktop `vault_bridge.normal_form` for web logins (`entry`) and every synced
 * typed kind (`item`). It is used only for records the phone edits; every other record (desktop logins,
 * documents) is stored and republished exactly as received. Where Python's behaviour is hard to match exactly
 * (non-ASCII bookmark hosts, odd base64), the phone refuses rather than guesses.
 *
 * Port of Swift `Records/Normalise.swift`; sections keep the Swift order.
 */
object Normalise {
    private typealias Obj = Map<String, JsonValue>

    val phoneEntryKinds: Set<String> = setOf("web")

    /** Everything the desktop syncs except `document` (its file never leaves the PC). */
    val phoneItemKinds: Set<String> = setOf(
        "note", "card", "identity", "passkey", "bookmark", "license", "purchase", "warranty", "subscription",
        "bank_account", "ssh_key", "api_key", "wifi",
    )

    /** Desktop `item_schema.ITEM_KINDS`; a kind outside it is rejected, not passed through. */
    internal val itemKinds: Set<String> = setOf(
        "web", "desktop", "note", "bookmark", "document", "license", "purchase", "warranty", "subscription",
        "identity", "card", "bank_account", "ssh_key", "api_key", "wifi", "passkey",
    )

    private val entryFields: Set<String> = setOf(
        "id", "kind", "label", "username", "password", "scope", "created_at", "updated_at", "favorite", "tags",
        "notes", "totp", "recovery_codes", "custom_fields", "policy", "password_history", "site_icon",
    )
    private val localTrustScopeKeys = listOf(
        "sign_in_selector", "embedded_web_fill_approved", "browser_approval", "browser_approvals", "sync_pairing",
        "pairing_secret", "pairing_state",
    )
    private val matchModes: Set<String> = setOf("exact_origin", "host", "base_domain", "starts_with")

    fun normalForm(ns: Namespace, record: JsonValue): JsonValue = when (ns) {
        Namespace.ENTRY -> entry(record)
        Namespace.ITEM -> item(record)
        Namespace.LICENSE -> throw NormaliseException(NormaliseException.Kind.NOT_PHONE_KIND)
    }

    // MARK: helpers

    private fun reject(detail: String) = NormaliseException(NormaliseException.Kind.REJECTED, detail)

    private fun notPhoneKind() = NormaliseException(NormaliseException.Kind.NOT_PHONE_KIND)

    private fun str(s: String): JsonValue = JsonValue.Str(s)

    private val EMPTY: JsonValue = JsonValue.Str("")

    private fun len(s: String): Int = Scalars.count(s)

    private fun text(v: JsonValue?, field: String, limit: Int, allowEmpty: Boolean): String {
        val s = (v as? JsonValue.Str)?.v ?: throw reject("$field must be text")
        if (!allowEmpty && s.isEmpty()) throw reject("$field cannot be empty")
        if (len(s) > limit) throw reject("$field is too long")
        if (s.contains('\u0000')) throw reject("$field contains a null character")
        return s
    }

    private fun isAsciiDigits(s: String): Boolean = s.isNotEmpty() && s.all { it in '0'..'9' }

    private fun isAscii(s: String): Boolean = s.all { it.code < 0x80 }

    private fun isUpper(c: Char): Boolean = c in 'A'..'Z'

    private fun isDigit(c: Char): Boolean = c in '0'..'9'

    /** `uuid.UUID(text)` re-rendered: lower-case 8-4-4-4-12. */
    private fun uuid(v: JsonValue?, field: String): String {
        var s = text(v, field, 128, allowEmpty = false)
        s = s.replace("urn:", "").replace("uuid:", "")
        s = s.trim { it == '{' || it == '}' }
        val hex = s.filter { it != '-' }.lowercase()
        if (hex.length != 32 || !hex.all { it in '0'..'9' || it in 'a'..'f' }) throw reject("$field must be a UUID")
        return listOf(0 until 8, 8 until 12, 12 until 16, 16 until 20, 20 until 32).joinToString("-") { hex.substring(it) }
    }

    private fun timestamp(v: JsonValue?, field: String): Long {
        val n = (v as? JsonValue.Int)?.v
        if (n == null || n < 0) throw reject("$field must be a bounded UTC timestamp")
        return n
    }

    // MARK: entries (web logins)

    private fun entry(record: JsonValue): JsonValue {
        val rec = ((record as? JsonValue.Obj) ?: throw reject("Unsupported credential type")).fields.toMutableMap()
        if (rec["kind"] == JsonValue.Str("desktop")) throw notPhoneKind()
        val unknown = rec.keys - entryFields
        if (unknown.isNotEmpty()) {
            val names = unknown.sortedWith(Scalars::compare).joinToString(", ", "[", "]") { "'$it'" }
            throw reject("Credential contains unsupported fields: $names")
        }
        // vault._validate_legacy_payload
        if (rec["kind"] != JsonValue.Str("web")) throw reject("Unsupported credential type")
        for ((field, limit) in listOf("id" to 128, "label" to 512, "username" to 512, "password" to 4096)) {
            text(rec[field], field, limit, allowEmpty = field == "username" || field == "password")
        }
        val scope = ((rec["scope"] as? JsonValue.Obj) ?: throw reject("Credential scope is missing")).fields.toMutableMap()
        val originText = when (val o = scope["origin"]) {
            null -> ""
            is JsonValue.Str -> o.v
            else -> throw reject("Origin must be a non-empty string shorter than 2049 characters")
        }
        scope["origin"] = str(origin { Origin.canonicalize(originText) })
        if (rec["tags"] != null && rec["tags"] !is JsonValue.Arr) throw reject("Invalid tags")
        rec["policy"] = policy(rec["policy"])
        // _canonical_entry
        for (name in listOf("created_at", "updated_at")) {
            if (rec[name] == null) continue
            val n = (rec[name] as? JsonValue.Int)?.v
            if (n == null || n < 0) throw reject("Credential $name is malformed")
        }
        if (rec["favorite"] != null && rec["favorite"] !is JsonValue.Bool) throw reject("Credential favorite is malformed")
        val tags = list(rec["tags"] ?: JsonValue.Arr(emptyList()), 20, "Credential tags are malformed")
        for (t in tags) text(t, "tag", 40, allowEmpty = false)
        if (rec["notes"] != null) text(rec["notes"], "notes", 20000, allowEmpty = true)
        val codes = list(rec["recovery_codes"] ?: JsonValue.Arr(emptyList()), 100, "Credential recovery codes are malformed")
        for (c in codes) text(c, "recovery code", 512, allowEmpty = false)
        val fields = list(rec["custom_fields"] ?: JsonValue.Arr(emptyList()), 50, "Custom fields are malformed")
        for (row in fields) scalarDict(row, "custom field")
        val totp = rec["totp"]
        if (totp != null && totp != JsonValue.Null) {
            scalarDict(totp, "TOTP")
            checkTOTP(totp)
        }
        val history = list(rec["password_history"] ?: JsonValue.Arr(emptyList()), 5, "Password history is malformed")
        val canonicalHistory = ArrayList<JsonValue>()
        for (row in history) {
            val r = (row as? JsonValue.Obj)?.fields
            if (r == null || !(r.keys - setOf("password", "changed_at", "replaced_at")).isEmpty()) {
                throw reject("Password history is malformed")
            }
            val changed = r["changed_at"] ?: r["replaced_at"] ?: JsonValue.Null
            val at = (changed as? JsonValue.Int)?.v
            if (at == null || at < 0) throw reject("Credential password history time is malformed")
            canonicalHistory.add(
                JsonValue.Obj(
                    mapOf(
                        "password" to str(text(r["password"], "password", 4096, allowEmpty = true)),
                        "changed_at" to JsonValue.Int(at),
                    ),
                ),
            )
        }
        if (rec["password_history"] != null) rec["password_history"] = JsonValue.Arr(canonicalHistory)
        if (rec["site_icon"] != null && rec["site_icon"] !is JsonValue.Str) throw reject("Credential icon is malformed")
        scope["urls"]?.let { scope["urls"] = webURLs(it) }
        rec["scope"] = JsonValue.Obj(scope.toMap())
        val size = CanonicalJson.encode(JsonValue.Obj(rec.toMap()), Dialect.UTF8).size
        if (size > 512 * 1024) throw reject("Credential is too large")
        // _strip_entry_local
        rec.remove("site_icon")
        for (key in localTrustScopeKeys) scope.remove(key)
        rec["scope"] = JsonValue.Obj(scope.toMap())
        val p = rec["policy"]
        if (p is JsonValue.Obj) rec["policy"] = JsonValue.Obj(p.fields - "sign_in")
        return JsonValue.Obj(rec.toMap())
    }

    private inline fun origin(body: () -> String): String = try {
        body()
    } catch (e: OriginException) {
        when (e.kind) {
            OriginException.Kind.NEEDS_PUNYCODE -> throw NormaliseException(NormaliseException.Kind.NEEDS_PUNYCODE)
            OriginException.Kind.INVALID -> throw reject(e.message ?: "")
        }
    }

    private fun list(v: JsonValue, max: Int, message: String): List<JsonValue> {
        val a = (v as? JsonValue.Arr)?.items
        if (a == null || a.size > max) throw reject(message)
        return a
    }

    /** access_policy.normalized_policy */
    private fun policy(raw: JsonValue?): JsonValue {
        val p: Obj = (raw as? JsonValue.Obj)?.fields ?: emptyMap()
        val fill = p["fill"] ?: str("click")
        val signIn = p["sign_in"] ?: str("inherit")
        return JsonValue.Obj(
            mapOf(
                "fill" to if (fill == str("click") || fill == str("never")) fill else str("never"),
                "sign_in" to if (signIn in listOf(str("inherit"), str("never"), str("enabled"))) signIn else str("never"),
                "require_master_password" to JsonValue.Bool((p["require_master_password"] ?: JsonValue.Bool(false)) == JsonValue.Bool(true)),
                "save_prompts" to JsonValue.Bool((p["save_prompts"] ?: JsonValue.Bool(true)) == JsonValue.Bool(true)),
            ),
        )
    }

    private fun scalarDict(v: JsonValue, name: String) {
        val o = (v as? JsonValue.Obj)?.fields
        if (o == null || o.size > 16) throw reject("$name is malformed")
        for ((key, value) in o) {
            text(str(key), "$name key", 100, allowEmpty = false)
            when (value) {
                JsonValue.Null, is JsonValue.Bool, is JsonValue.Int -> {}
                is JsonValue.Float -> if (!value.v.isFinite()) throw reject("$name is malformed")
                is JsonValue.Str -> text(value, name, 4096, allowEmpty = true)
                else -> throw reject("$name is malformed")
            }
        }
    }

    private fun checkTOTP(v: JsonValue) {
        val t = (v as? JsonValue.Obj)?.fields ?: return
        for (name in listOf("secret", "algorithm")) {
            if (t[name] != null && t[name] !is JsonValue.Str) throw reject("TOTP $name must be text")
        }
        t["digits"]?.let { d ->
            val n = (d as? JsonValue.Int)?.v
            if (n == null || n !in 6L..8L) throw reject("TOTP digits are unsupported")
        }
        t["period"]?.let { p ->
            val n = (p as? JsonValue.Int)?.v
            if (n == null || n !in 15L..120L) throw reject("TOTP period is unsupported")
        }
    }

    /** item_schema.validate_web_urls */
    internal fun webURLs(value: JsonValue): JsonValue {
        if (value == JsonValue.Null) return JsonValue.Arr(emptyList())
        val rows = (value as? JsonValue.Arr)?.items
        if (rows == null || rows.size > 20) throw reject("urls must be a list of at most 20 rows")
        val out = ArrayList<JsonValue>()
        // Kotlin String equality compares UTF-16 units, which is code-point equality (no normalisation).
        val seen = HashSet<String>()
        for (raw in rows) {
            val row: Obj = when (raw) {
                is JsonValue.Str -> mapOf("url" to raw)
                is JsonValue.Obj -> raw.fields
                else -> throw reject("url row must be an object")
            }
            if (!(row.keys - setOf("url", "match")).isEmpty()) throw reject("url row contains unsupported data")
            val mode = ((row["match"] ?: str("exact_origin")) as? JsonValue.Str)?.v
            if (mode == null || mode !in matchModes) throw reject("url match mode is unsupported")
            val rawURL = text(row["url"] ?: EMPTY, "url", 4096, allowEmpty = false)
            val url = origin {
                if (mode == "exact_origin") {
                    Origin.canonicalize(rawURL)
                } else {
                    val u = Origin.normalizeUrl(rawURL)
                    if (u.startsWith("http://")) Origin.canonicalize(Origin.originOf(u))
                    u
                }
            }
            if (!seen.add(url + "\u0000" + mode)) continue
            out.add(JsonValue.Obj(mapOf("url" to str(url), "match" to str(mode))))
        }
        return JsonValue.Arr(out)
    }

    // MARK: typed items

    private fun item(record: JsonValue): JsonValue {
        val rec = (record as? JsonValue.Obj)?.fields ?: throw reject("catalog item must be an object")
        val allowed = setOf(
            "id", "kind", "title", "created_at", "updated_at", "revision", "favorite", "tags", "collection_ids", "payload",
        )
        if (!(rec.keys - allowed).isEmpty()) throw reject("catalog item contains unsupported fields")
        val kind = text(rec["kind"] ?: EMPTY, "item kind", 32, allowEmpty = false)
        if (kind !in itemKinds) throw reject("Unsupported item kind: $kind")
        if (kind !in phoneItemKinds) throw notPhoneKind()
        val id = uuid(rec["id"], "item id")
        val title = text(rec["title"] ?: EMPTY, "item title", 512, allowEmpty = false)
        val created = timestamp(rec["created_at"], "created_at")
        val updated = timestamp(rec["updated_at"], "updated_at")
        if (updated < created) throw reject("updated_at cannot be earlier than created_at")
        rec["revision"]?.let { r ->
            val n = (r as? JsonValue.Int)?.v
            if (n == null || n < 1) throw reject("item revision is malformed")
        }
        val favorite = rec["favorite"] ?: JsonValue.Bool(false)
        if (favorite !is JsonValue.Bool) throw reject("favorite must be boolean")
        val tags = normalizeTags(rec["tags"] ?: JsonValue.Arr(emptyList()))
        collectionIDs(rec["collection_ids"] ?: JsonValue.Arr(emptyList()))
        val payload = validatePayload(kind, rec["payload"] ?: JsonValue.Obj(emptyMap())) - "document_ids"
        return JsonValue.Obj(
            mapOf(
                "id" to str(id), "kind" to str(kind), "title" to str(title), "created_at" to JsonValue.Int(created),
                "updated_at" to JsonValue.Int(updated), "favorite" to favorite,
                "tags" to JsonValue.Arr(tags.map { str(it) }), "payload" to JsonValue.Obj(payload),
            ),
        )
    }

    private fun casefold(s: String): String = Casefold.fold(s)

    private fun normalizeTags(v: JsonValue): List<String> {
        if (v == JsonValue.Null) return emptyList()
        val a = (v as? JsonValue.Arr)?.items ?: throw reject("tags must be a list of text values")
        val out = ArrayList<String>()
        // Keyed on code points (Kotlin String equality), as Python compares; no normalisation.
        val seen = HashSet<String>()
        for (t in a) {
            val tag = PyStrip.strip(text(t, "tag", 40, allowEmpty = false))
            if (tag.isEmpty()) continue
            if (seen.add(casefold(tag))) out.add(tag)
        }
        if (out.size > 20) throw reject("At most 20 tags are supported per item")
        return out
    }

    private fun collectionIDs(v: JsonValue) {
        if (v == JsonValue.Null) return
        val a = (v as? JsonValue.Arr)?.items ?: throw reject("collection_ids must be a list")
        val seen = HashSet<String>()
        for (x in a) seen.add(uuid(x, "collection id"))
        if (seen.size > 20) throw reject("An item cannot belong to more than 20 collections")
    }

    private fun optionalTemplateID(p: Obj): JsonValue {
        val t = p["template_id"]
        if (t == null || t == JsonValue.Null) return JsonValue.Null
        return str(text(t, "template id", 128, allowEmpty = false))
    }

    private fun validatePayload(kind: String, value: JsonValue): Obj {
        val p = (value as? JsonValue.Obj)?.fields ?: throw reject("$kind payload must be an object")
        return when (kind) {
            "note" -> {
                if (!(p.keys - setOf("body", "fields", "template_id")).isEmpty()) {
                    throw reject("note payload contains unsupported data")
                }
                val body = text(p["body"] ?: EMPTY, "note body", 20_000, allowEmpty = true)
                mapOf(
                    "body" to str(body),
                    "fields" to JsonValue.Arr(customFields(p["fields"] ?: JsonValue.Null)),
                    "template_id" to optionalTemplateID(p),
                )
            }
            "identity" -> identity(p)
            "card" -> card(p)
            "passkey" -> passkey(p)
            "bookmark" -> {
                if (!(p.keys - setOf("url", "notes", "template_id")).isEmpty()) {
                    throw reject("bookmark payload contains unsupported data")
                }
                mapOf(
                    "url" to str(bookmarkURL(p["url"] ?: EMPTY)),
                    "notes" to str(text(p["notes"] ?: EMPTY, "bookmark notes", 20_000, allowEmpty = true)),
                    "template_id" to optionalTemplateID(p),
                )
            }
            "license" -> license(p)
            "purchase", "warranty", "subscription" -> purchaseLike(kind, p)
            "bank_account" -> bankAccount(p)
            "ssh_key" -> sshKey(p)
            "api_key" -> apiKey(p)
            "wifi" -> wifi(p)
            else -> throw notPhoneKind()
        }
    }

    /** Code-point order, as Python compares `str`. */
    private fun pyLess(a: String, b: String): Boolean = Scalars.compare(a, b) < 0

    // MARK: bookmarks

    /**
     * item_schema.validate_bookmark_url. Stricter than the desktop in two places it is not worth matching:
     * a non-ASCII host asks for the `xn--` form, and a bracketed host must be an IPv6 address.
     */
    private fun bookmarkURL(v: JsonValue): String {
        val url = text(v, "bookmark URL", 4096, allowEmpty = false)
        if (url.codePoints().anyMatch { it < 32 || PyStrip.isSpace(it) }) {
            throw reject("bookmark URL contains whitespace or a control character")
        }
        val parts = try {
            Origin.split(url)
        } catch (e: OriginException) {
            throw reject("bookmark URL is malformed")
        }
        if (parts.scheme != "http" && parts.scheme != "https") throw reject("bookmark URL must use http or https")
        if (parts.netloc.isEmpty() || parts.hostname == null) throw reject("bookmark URL must contain a host")
        if (parts.hasUserInfo) throw reject("bookmark URL must not contain embedded credentials")
        if (!isAscii(parts.netloc)) throw NormaliseException(NormaliseException.Kind.NEEDS_PUNYCODE)
        val open = parts.netloc.indexOf('[')
        val close = parts.netloc.indexOf(']')
        if (open >= 0 && close >= 0 && open < close && Origin.ipv6(parts.netloc.substring(open + 1, close)) == null) {
            throw reject("bookmark URL is malformed")
        }
        return url
    }

    // MARK: licences, purchases, warranties, subscriptions

    /** item_schema `_uuid_list`: at most `limit` UUIDs, no duplicates. */
    private fun uuidList(v: JsonValue?, field: String, limit: Int): List<String> {
        if (v == null || v == JsonValue.Null) return emptyList()
        val a = (v as? JsonValue.Arr)?.items
        if (a == null || a.size > limit) throw reject("$field must be a list of at most $limit IDs")
        val seen = HashSet<String>()
        val out = ArrayList<String>()
        for (x in a) {
            val id = uuid(x, field)
            if (!seen.add(id)) throw reject("$field contains a duplicate ID")
            out.add(id)
        }
        return out
    }

    private fun license(p: Obj): Obj {
        val allowed = setOf(
            "license_value", "product", "vendor", "purchase_date", "expiration_date", "document_ids", "notes", "template_id",
        )
        if (!(p.keys - allowed).isEmpty()) throw reject("license payload contains unsupported data")
        val expiration = isoDate(p["expiration_date"] ?: EMPTY, "expiration date")
        val purchase = isoDate(p["purchase_date"] ?: EMPTY, "purchase date")
        if (purchase.isNotEmpty() && expiration.isNotEmpty() && pyLess(expiration, purchase)) {
            throw reject("expiration date cannot precede purchase date")
        }
        return linkedMapOf(
            "license_value" to str(text(p["license_value"] ?: EMPTY, "license value", 4096, allowEmpty = true)),
            "product" to str(text(p["product"] ?: EMPTY, "product", 512, allowEmpty = true)),
            "vendor" to str(text(p["vendor"] ?: EMPTY, "vendor", 512, allowEmpty = true)),
            "purchase_date" to str(purchase),
            "expiration_date" to str(expiration),
            "document_ids" to JsonValue.Arr(
                uuidList(p["document_ids"] ?: JsonValue.Arr(emptyList()), "document_ids", 50).map { str(it) },
            ),
            "notes" to str(text(p["notes"] ?: EMPTY, "license notes", 20_000, allowEmpty = true)),
            "template_id" to optionalTemplateID(p),
        )
    }

    /** item_schema `_currency`: three ASCII letters, upper-cased. */
    private fun currency(v: JsonValue): String {
        val raw = text(v, "currency", 3, allowEmpty = false)
        // Python upper-cases some non-ASCII letters to ASCII ones; the phone takes ASCII only.
        if (!isAscii(raw)) throw reject("currency must be a three-letter code")
        val c = raw.uppercase()
        if (c.length != 3 || !c.all(::isUpper)) throw reject("currency must be a three-letter code")
        return c
    }

    private fun purchaseLike(kind: String, p: Obj): Obj {
        val allowed = setOf(
            "product", "vendor", "provider", "purchase_date", "expiration_date", "renewal_date", "amount_minor",
            "currency", "document_ids", "notes", "active", "template_id",
        )
        if (!(p.keys - allowed).isEmpty()) throw reject("$kind payload contains unsupported data")
        val purchase = isoDate(p["purchase_date"] ?: EMPTY, "purchase date")
        val expiration = isoDate(p["expiration_date"] ?: EMPTY, "expiration date")
        val renewal = isoDate(p["renewal_date"] ?: EMPTY, "renewal date")
        if (purchase.isNotEmpty() && expiration.isNotEmpty() && pyLess(expiration, purchase)) {
            throw reject("expiration date cannot precede purchase date")
        }
        if (purchase.isNotEmpty() && renewal.isNotEmpty() && pyLess(renewal, purchase)) {
            throw reject("renewal date cannot precede purchase date")
        }
        if (p["amount_minor"] == null && p["currency"] != null) throw reject("currency requires amount_minor")
        if (p["amount_minor"] != null && p["currency"] == null) throw reject("amount_minor requires currency")
        val amount = ((p["amount_minor"] ?: JsonValue.Int(0)) as? JsonValue.Int)?.v
        if (amount == null || amount !in -1_000_000_000_000_000L..1_000_000_000_000_000L) {
            throw reject("amount_minor must be a bounded integer in minor currency units")
        }
        val code = currency(p["currency"] ?: str("XXX"))
        val active = p["active"] ?: JsonValue.Bool(true)
        if (active !is JsonValue.Bool) throw reject("active must be boolean")
        return linkedMapOf(
            "product" to str(text(p["product"] ?: EMPTY, "product", 512, allowEmpty = true)),
            "vendor" to str(text(p["vendor"] ?: EMPTY, "vendor", 512, allowEmpty = true)),
            "provider" to str(text(p["provider"] ?: EMPTY, "provider", 512, allowEmpty = true)),
            "purchase_date" to str(purchase),
            "expiration_date" to str(expiration),
            "renewal_date" to str(renewal),
            "amount_minor" to JsonValue.Int(amount),
            "currency" to str(code),
            "document_ids" to JsonValue.Arr(
                uuidList(p["document_ids"] ?: JsonValue.Arr(emptyList()), "document_ids", 50).map { str(it) },
            ),
            "notes" to str(text(p["notes"] ?: EMPTY, "$kind notes", 20_000, allowEmpty = true)),
            "active" to active,
            "template_id" to optionalTemplateID(p),
        )
    }

    // MARK: bank accounts

    /** item_schema `_IBAN_RE`: `^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$`. */
    private fun looksLikeIBAN(s: String): Boolean {
        // A non-ASCII code point (or surrogate) never passes the character checks, so UTF-16 length is safe here.
        if (s.length !in 15..34) return false
        return isUpper(s[0]) && isUpper(s[1]) && isDigit(s[2]) && isDigit(s[3]) &&
            (4 until s.length).all { isUpper(s[it]) || isDigit(s[it]) }
    }

    /** item_schema.validate_iban's mod-97 check on a compact upper-case IBAN. */
    private fun ibanChecksumOK(s: String): Boolean {
        var rem = 0
        for (x in s.substring(4) + s.substring(0, 4)) {
            val v = if (isDigit(x)) x.code - 48 else x.code - 55
            rem = (if (v < 10) rem * 10 + v else rem * 100 + v) % 97
        }
        return rem == 1
    }

    private fun bankAccount(p: Obj): Obj {
        val allowed = setOf("bank", "account_holder", "account_number", "number_format", "routing", "pin", "notes", "template_id")
        if (!(p.keys - allowed).isEmpty()) throw reject("bank account payload contains unsupported data")
        var account = PyStrip.strip(text(p["account_number"] ?: EMPTY, "account number", 64, allowEmpty = true))
        var format = ""
        if (account.isNotEmpty()) {
            val compact = account.replace(" ", "").uppercase()
            if (looksLikeIBAN(compact)) {
                // Python upper-cases non-ASCII letters too (ß → SS); refuse those rather than risk a mismatch.
                if (!isAscii(account)) throw reject("IBAN is malformed")
                if (!ibanChecksumOK(compact)) throw reject("IBAN failed its checksum")
                account = compact
                format = "iban"
            } else {
                if (account.any { it.code < 32 }) throw reject("account number contains a control character")
                format = "other"
            }
        }
        val rawRouting = PyStrip.strip(text(p["routing"] ?: EMPTY, "routing or BIC", 34, allowEmpty = true))
        if (!isAscii(rawRouting)) throw reject("routing or BIC must be alphanumeric")
        val routing = rawRouting.uppercase()
        if (routing.isNotEmpty() && !routing.all { isUpper(it) || isDigit(it) || it == '-' }) {
            throw reject("routing or BIC must be alphanumeric")
        }
        return linkedMapOf(
            "bank" to str(text(p["bank"] ?: EMPTY, "bank", 256, allowEmpty = true)),
            "account_holder" to str(text(p["account_holder"] ?: EMPTY, "account holder", 256, allowEmpty = true)),
            "account_number" to str(account),
            "number_format" to str(format),
            "routing" to str(routing),
            "pin" to str(digits(p["pin"] ?: EMPTY, "bank PIN", 4, 8)),
            "notes" to str(text(p["notes"] ?: EMPTY, "bank account notes", 20_000, allowEmpty = true)),
            "template_id" to optionalTemplateID(p),
        )
    }

    // MARK: SSH keys

    private val pemFormats: List<Pair<String, String>> = listOf(
        "-----BEGIN OPENSSH PRIVATE KEY-----" to "openssh",
        "-----BEGIN RSA PRIVATE KEY-----" to "pem-rsa",
        "-----BEGIN EC PRIVATE KEY-----" to "pem-ec",
        "-----BEGIN DSA PRIVATE KEY-----" to "pem-dsa",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" to "pem-pkcs8-encrypted",
        "-----BEGIN PRIVATE KEY-----" to "pem-pkcs8",
        "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----" to "ssh2",
        "PuTTY-User-Key-File-" to "putty",
    )
    private val opensshKeyTypes = listOf("ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-")

    /** item_schema.sniff_private_key_format */
    private fun keyFormat(privateKey: String): String {
        val s = PyStrip.strip(privateKey)
        if (s.isEmpty()) return ""
        for ((header, name) in pemFormats) {
            if (!s.startsWith(header)) continue
            val head = Scalars.truncate(s, 512)
            if (name == "pem-rsa" && head.contains("Proc-Type: 4,ENCRYPTED")) return "pem-rsa-encrypted"
            return name
        }
        return "unknown"
    }

    private fun isB64Char(c: Char): Boolean =
        c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '+' || c == '/'

    /**
     * Foundation `Data(base64Encoded:)` on text already limited to the standard alphabet plus at most two
     * trailing `=`: the length must be a multiple of four (padding required), spare bits are ignored (as Python's
     * non-strict `a2b_base64` does). Null when malformed.
     */
    private fun decodeBase64Padded(s: String): ByteArray? {
        if (s.length % 4 != 0) return null
        val body = s.trimEnd('=')
        if (body.length % 4 == 1) return null
        val out = java.io.ByteArrayOutputStream()
        var acc = 0
        var bits = 0
        for (c in body) {
            val v = when (c) {
                in 'A'..'Z' -> c - 'A'
                in 'a'..'z' -> c - 'a' + 26
                in '0'..'9' -> c - '0' + 52
                '+' -> 62
                '/' -> 63
                else -> return null
            }
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((acc shr bits) and 0xFF)
            }
        }
        return out.toByteArray()
    }

    /** item_schema.openssh_fingerprint: `SHA256:<base64, unpadded>` for an OpenSSH public key line, "" otherwise. */
    private fun opensshFingerprint(publicKey: String): String {
        val parts = PyStrip.split(publicKey)
        if (parts.size < 2 || opensshKeyTypes.none { parts[0].startsWith(it) }) return ""
        val b64 = parts[1]
        // `b64decode(validate=True)`: the standard alphabet, then at most two `=` at the very end.
        var body = 0
        while (body < b64.length && isB64Char(b64[body])) body++
        val pad = b64.substring(body)
        val blob = if (pad.length <= 2 && pad.all { it == '=' }) decodeBase64Padded(b64) else null
        if (blob == null) throw reject("OpenSSH public key is not valid base64")
        if (blob.isEmpty()) throw reject("OpenSSH public key is empty")
        val digest = Base64Std.encode(MessageDigest.getInstance("SHA-256").digest(blob)).trimEnd('=')
        return "SHA256:$digest"
    }

    private fun sshKey(p: Obj): Obj {
        val allowed = setOf("private_key", "public_key", "passphrase", "fingerprint", "key_format", "notes", "template_id")
        if (!(p.keys - allowed).isEmpty()) throw reject("SSH key payload contains unsupported data")
        val privateKey = text(p["private_key"] ?: EMPTY, "private key", 20_000, allowEmpty = true)
        val publicKey = text(p["public_key"] ?: EMPTY, "public key", 20_000, allowEmpty = true)
        val computed = opensshFingerprint(publicKey)
        val fingerprint = if (computed.isEmpty()) {
            PyStrip.strip(text(p["fingerprint"] ?: EMPTY, "fingerprint", 128, allowEmpty = true))
        } else {
            computed
        }
        return linkedMapOf(
            "private_key" to str(privateKey),
            "public_key" to str(publicKey),
            "passphrase" to str(text(p["passphrase"] ?: EMPTY, "passphrase", 4096, allowEmpty = true)),
            "fingerprint" to str(fingerprint),
            "key_format" to str(keyFormat(privateKey)),
            "notes" to str(text(p["notes"] ?: EMPTY, "SSH key notes", 20_000, allowEmpty = true)),
            "template_id" to optionalTemplateID(p),
        )
    }

    // MARK: API keys, Wi-Fi

    private fun apiKey(p: Obj): Obj {
        if (!(p.keys - setOf("service", "key", "secret", "expires", "notes", "template_id")).isEmpty()) {
            throw reject("API key payload contains unsupported data")
        }
        return linkedMapOf(
            "service" to str(text(p["service"] ?: EMPTY, "service", 512, allowEmpty = true)),
            "key" to str(text(p["key"] ?: EMPTY, "API key", 4096, allowEmpty = true)),
            "secret" to str(text(p["secret"] ?: EMPTY, "API secret", 4096, allowEmpty = true)),
            "expires" to str(isoDate(p["expires"] ?: EMPTY, "API key expiry")),
            "notes" to str(text(p["notes"] ?: EMPTY, "API key notes", 20_000, allowEmpty = true)),
            "template_id" to optionalTemplateID(p),
        )
    }

    val wifiSecurityTypes: List<String> = listOf("none", "wep", "wpa", "wpa2", "wpa3", "wpa2-enterprise", "wpa3-enterprise")

    private fun wifi(p: Obj): Obj {
        if (!(p.keys - setOf("ssid", "password", "security", "hidden", "notes", "template_id")).isEmpty()) {
            throw reject("Wi-Fi payload contains unsupported data")
        }
        val rawSecurity = ((p["security"] ?: str("wpa2")) as? JsonValue.Str)?.v
            ?: throw reject("Wi-Fi security type must be text")
        var security = casefold(PyStrip.strip(rawSecurity))
        if (security.isEmpty()) security = "wpa2"
        if (security !in wifiSecurityTypes) throw reject("Wi-Fi security type is unsupported")
        val hidden = p["hidden"] ?: JsonValue.Bool(false)
        if (hidden !is JsonValue.Bool) throw reject("Wi-Fi hidden flag must be boolean")
        return linkedMapOf(
            "ssid" to str(text(p["ssid"] ?: EMPTY, "SSID", 32, allowEmpty = true)),
            "password" to str(text(p["password"] ?: EMPTY, "Wi-Fi password", 4096, allowEmpty = true)),
            "security" to str(security),
            "hidden" to hidden,
            "notes" to str(text(p["notes"] ?: EMPTY, "Wi-Fi notes", 20_000, allowEmpty = true)),
            "template_id" to optionalTemplateID(p),
        )
    }

    private fun customFields(v: JsonValue): List<JsonValue> {
        if (v == JsonValue.Null) return emptyList()
        val a = (v as? JsonValue.Arr)?.items
        if (a == null || a.size > 50) throw reject("template fields must be a list of at most 50 values")
        return a.map { f ->
            val o = (f as? JsonValue.Obj)?.fields ?: throw reject("template field must be an object")
            if (!(o.keys - setOf("name", "value", "hidden")).isEmpty()) throw reject("template field contains unsupported data")
            JsonValue.Obj(
                linkedMapOf(
                    "name" to str(text(o["name"] ?: EMPTY, "field name", 100, allowEmpty = false)),
                    "value" to str(text(o["value"] ?: EMPTY, "field value", 4096, allowEmpty = true)),
                    "hidden" to JsonValue.Bool((o["hidden"] ?: JsonValue.Bool(false)) == JsonValue.Bool(true)),
                ),
            )
        }
    }

    private val identityLimits: Map<String, Int> = linkedMapOf(
        "name" to 256, "given_name" to 128, "middle_name" to 128, "family_name" to 128, "organization" to 256,
        "company" to 256, "job_title" to 160, "email" to 320, "phone" to 64, "address" to 1024,
        "address_line1" to 256, "address_line2" to 256, "city" to 128, "state" to 128, "postal_code" to 64,
        "country" to 128, "website" to 2048,
    )

    private fun identity(p: Obj): Obj {
        if (!(p.keys - identityLimits.keys - "template_id").isEmpty()) throw reject("identity payload contains unsupported fields")
        val out = LinkedHashMap<String, JsonValue>()
        var total = 0
        for ((field, limit) in identityLimits) {
            if (p[field] == null) continue
            val t = text(p[field], "identity field $field", limit, allowEmpty = true)
            out[field] = str(t)
            total += len(t)
        }
        if (total > 8192) throw reject("identity payload is too large")
        p["template_id"]?.let { t ->
            out["template_id"] = if (t == JsonValue.Null) JsonValue.Null else str(text(t, "template id", 128, allowEmpty = false))
        }
        return out
    }

    // MARK: cards

    private fun cardNumber(v: JsonValue): String {
        val t = text(v, "card number", 64, allowEmpty = true)
        val digits = t.replace(" ", "").replace("-", "")
        if (digits.isEmpty()) return ""
        if (!isAsciiDigits(digits)) throw reject("card number must contain digits only")
        if (digits.length !in 12..19) throw reject("card number must be 12 to 19 digits")
        return digits
    }

    private fun luhn(digits: String): Boolean {
        var total = 0
        for ((i, c) in digits.reversed().withIndex()) {
            var d = c.code - 48
            if (i % 2 == 1) {
                d *= 2
                if (d > 9) d -= 9
            }
            total += d
        }
        return total % 10 == 0
    }

    private fun cardBrand(digits: String): String {
        val n = digits.length
        fun prefix(k: Int): Int = digits.substring(0, k).toInt()
        val p2 = prefix(2)
        val p3 = prefix(3)
        val p4 = prefix(4)
        val p6 = prefix(6)
        if ((p2 == 34 || p2 == 37) && n == 15) return "amex"
        if (digits.startsWith("4") && n in listOf(13, 16, 19)) return "visa"
        if ((p2 in 51..55 || p4 in 2221..2720) && n == 16) return "mastercard"
        if ((p4 == 6011 || p6 in 622126..622925 || p3 in 644..649 || p2 == 65) && n in 16..19) return "discover"
        if ((p3 in 300..305 || p4 == 3095 || p2 in listOf(36, 38, 39)) && n in 14..19) return "diners"
        if (p4 in 3528..3589 && n in 16..19) return "jcb"
        if (p2 == 62 && n in 16..19) return "unionpay"
        if ((p2 == 50 || p2 in 56..69) && n in 12..19) return "maestro"
        return "unknown"
    }

    private fun cardExpiry(v: JsonValue): String {
        val t = PyStrip.strip(text(v, "card expiry", 10, allowEmpty = true))
        if (t.isEmpty()) return ""
        val sc = t.codePoints().toArray()
        fun isDigitCp(c: Int) = c in 0x30..0x39
        var i = 0
        while (i < sc.size && isDigitCp(sc[i])) i++
        val month = String(sc, 0, i)
        var j = i
        while (j < sc.size && PyStrip.isSpace(sc[j])) j++
        if (month.length !in 1..2 || j >= sc.size || (sc[j] != '/'.code && sc[j] != '-'.code)) {
            throw reject("card expiry must be MM/YY")
        }
        j++
        while (j < sc.size && PyStrip.isSpace(sc[j])) j++
        var year = String(sc, j, sc.size - j)
        if (!isAsciiDigits(year) || (year.length != 2 && year.length != 4)) throw reject("card expiry must be MM/YY")
        val m = month.toInt()
        if (m !in 1..12) throw reject("card expiry month must be 01-12")
        if (year.length == 4) {
            if (!year.startsWith("20")) throw reject("card expiry year is out of range")
            year = year.substring(2)
        }
        return (if (m < 10) "0" else "") + "$m/$year"
    }

    private fun digits(v: JsonValue, field: String, lo: Int, hi: Int): String {
        val t = PyStrip.strip(text(v, field, hi + 16, allowEmpty = true))
        if (t.isEmpty()) return ""
        if (!isAsciiDigits(t) || t.length !in lo..hi) throw reject("$field must be $lo to $hi digits")
        return t
    }

    private fun card(p: Obj): Obj {
        val allowed = setOf(
            "cardholder", "number", "brand", "last4", "expiry", "cvv", "pin", "billing_address_id", "notes", "template_id",
        )
        if (!(p.keys - allowed).isEmpty()) throw reject("card payload contains unsupported data")
        val number = cardNumber(p["number"] ?: EMPTY)
        if (number.isNotEmpty() && !luhn(number)) throw reject("card number failed its checksum")
        val billingRaw = p["billing_address_id"] ?: EMPTY
        val billing = if (billingRaw == JsonValue.Null || billingRaw == EMPTY) "" else uuid(billingRaw, "billing address id")
        return linkedMapOf(
            "cardholder" to str(text(p["cardholder"] ?: EMPTY, "cardholder", 256, allowEmpty = true)),
            "number" to str(number),
            "brand" to str(if (number.isEmpty()) "" else cardBrand(number)),
            "last4" to str(number.takeLast(4)),
            "expiry" to str(cardExpiry(p["expiry"] ?: EMPTY)),
            "cvv" to str(digits(p["cvv"] ?: EMPTY, "card CVV", 3, 4)),
            "pin" to str(digits(p["pin"] ?: EMPTY, "card PIN", 4, 8)),
            "billing_address_id" to str(billing),
            "notes" to str(text(p["notes"] ?: EMPTY, "card notes", 20_000, allowEmpty = true)),
            "template_id" to optionalTemplateID(p),
        )
    }

    // MARK: passkeys

    private val passkeyFields: Set<String> = setOf(
        "relying_party_id", "user_handle", "credential_id", "private_key", "algorithm", "created", "notes",
        "template_id", "user_name", "user_display_name", "rp_name", "discoverable",
    )
    private val passkeyAlgorithms: Set<String> = setOf("ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA")

    /** item_schema `_HOSTNAME_RE`: 1-253 characters of dot-separated `[a-z0-9]` labels (inner `-`), each 1-63 long. */
    private fun isHostname(s: String): Boolean {
        if (Scalars.count(s) !in 1..253) return false
        for (label in s.split(".")) {
            // Only ASCII passes the character check, so UTF-16 length equals the code-point count when it matters.
            if (!label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }) return false
            if (label.length !in 1..63 || label.first() == '-' || label.last() == '-') return false
        }
        return true
    }

    /** item_schema `_base64url`: text up to 1024, stripped, `^[A-Za-z0-9_\-]+=*$` when non-empty. */
    private fun base64url(v: JsonValue, field: String): String {
        val t = PyStrip.strip(text(v, field, 1024, allowEmpty = true))
        if (t.isEmpty()) return t
        var i = 0
        while (i < t.length && (t[i] in 'A'..'Z' || t[i] in 'a'..'z' || t[i] in '0'..'9' || t[i] == '_' || t[i] == '-')) i++
        val body = i
        while (i < t.length && t[i] == '=') i++
        if (body == 0 || i != t.length) throw reject("$field must be base64url text")
        return t
    }

    /**
     * item_schema `_date` (allow_empty): None or "" gives "", else Python 3.12 `date.fromisoformat` on up to 10
     * characters: `YYYY-MM-DD`, `YYYYMMDD`, `YYYY-Www[-D]`, `YYYYWww[D]`. The text is kept as given.
     */
    private fun isoDate(v: JsonValue?, field: String): String {
        if (v == null || v == JsonValue.Null || v == EMPTY) return ""
        val t = text(v, field, 10, allowEmpty = false)
        fun fail() = reject("$field must be an ISO date (YYYY-MM-DD)")
        if (!isAscii(t)) throw fail()
        val c = t
        fun num(from: Int, to: Int): Int? {
            if (to > c.length || !(from until to).all { isDigit(c[it]) }) return null
            return c.substring(from, to).toInt()
        }
        val year = if (c.length >= 7) num(0, 4) else null
        if (year == null || year < 1) throw fail()
        val dash = c[4] == '-'
        val rest = c.substring(if (dash) 5 else 4)
        if (rest.startsWith("W")) {
            // ISO week date
            val w = rest.substring(1)
            fun n(a: String): Int? = if (a.isEmpty() || !a.all(::isDigit)) null else a.toInt()
            val week: Int
            val day: Int
            if (w.length == 2) {
                week = n(w.substring(0, 2)) ?: throw fail()
                day = 1
            } else if (dash && w.length == 4 && w[2] == '-') {
                week = n(w.substring(0, 2)) ?: throw fail()
                day = n(w.substring(3, 4)) ?: throw fail()
            } else if (!dash && w.length == 3) {
                week = n(w.substring(0, 2)) ?: throw fail()
                day = n(w.substring(2, 3)) ?: throw fail()
            } else {
                throw fail()
            }
            if (day !in 1..7 || week < 1) throw fail()
            if (week > 52) {
                // A year has week 53 when it starts on a Thursday, or a Wednesday in a leap year.
                val jan1 = weekday(year, 1, 1) // 1 = Monday
                if (!(week == 53 && (jan1 == 4 || (jan1 == 3 && isLeap(year))))) throw fail()
            }
            return t
        }
        val month: Int
        val dayOfMonth: Int
        if (dash) {
            if (c.length != 10 || c[7] != '-') throw fail()
            month = num(5, 7) ?: throw fail()
            dayOfMonth = num(8, 10) ?: throw fail()
        } else {
            if (c.length != 8) throw fail()
            month = num(4, 6) ?: throw fail()
            dayOfMonth = num(6, 8) ?: throw fail()
        }
        val days = listOf(31, if (isLeap(year)) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
        if (month !in 1..12 || dayOfMonth !in 1..days[month - 1]) throw fail()
        return t
    }

    private fun isLeap(y: Int): Boolean = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)

    /** ISO weekday (1 = Monday) by Sakamoto's method. */
    private fun weekday(y0: Int, m: Int, d: Int): Int {
        val t = intArrayOf(0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4)
        val y = if (m < 3) y0 - 1 else y0
        val w = (y + y / 4 - y / 100 + y / 400 + t[m - 1] + d) % 7 // 0 = Sunday
        return if (w == 0) 7 else w
    }

    /** item_schema.validate_passkey_fields */
    private fun passkey(p: Obj): Obj {
        if (!(p.keys - passkeyFields).isEmpty()) throw reject("passkey payload contains unsupported data")
        val rpID = casefold(PyStrip.strip(text(p["relying_party_id"] ?: EMPTY, "relying party id", 253, allowEmpty = true)))
        if (rpID.isNotEmpty() && !isHostname(rpID)) throw reject("relying party id must be a bare hostname")
        val algorithm = when (val a = p["algorithm"]) {
            null, JsonValue.Null, EMPTY -> ""
            is JsonValue.Str -> if (a.v in passkeyAlgorithms) a.v else throw reject("passkey algorithm is unsupported")
            else -> throw reject("passkey algorithm is unsupported")
        }
        val discoverable = p["discoverable"] ?: JsonValue.Bool(true)
        if (discoverable !is JsonValue.Bool) throw reject("passkey discoverable flag must be true or false")
        fun t(k: String, field: String, limit: Int): JsonValue = str(text(p[k] ?: EMPTY, field, limit, allowEmpty = true))
        return linkedMapOf(
            "relying_party_id" to str(rpID),
            "user_handle" to str(base64url(p["user_handle"] ?: EMPTY, "user handle")),
            "credential_id" to str(base64url(p["credential_id"] ?: EMPTY, "credential id")),
            "private_key" to t("private_key", "passkey private key", 20_000),
            "algorithm" to str(algorithm),
            "created" to str(isoDate(p["created"], "passkey created date")),
            "notes" to t("notes", "passkey notes", 20_000),
            "user_name" to t("user_name", "passkey user name", 256),
            "user_display_name" to t("user_display_name", "passkey display name", 256),
            "rp_name" to t("rp_name", "passkey site name", 256),
            "discoverable" to discoverable,
            "template_id" to optionalTemplateID(p),
        )
    }
}
