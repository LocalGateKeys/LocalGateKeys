package app.localgatekeys.android.vault

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Origin
import app.localgatekeys.core.sync.StoreSnapshot
import java.net.URI

internal fun JsonValue?.stringOrNull(): String? = (this as? JsonValue.Str)?.v

internal fun JsonValue?.objectOrNull(): Map<String, JsonValue>? = (this as? JsonValue.Obj)?.fields

internal fun JsonValue?.listOrNull(): List<JsonValue>? = (this as? JsonValue.Arr)?.items

/** The short name a website login gets from its origin (desktop `friendly_origin_label`). */
object OriginLabel {
    val loginSubdomains = listOf("www.", "app.", "login.", "accounts.", "account.", "auth.", "signin.", "secure.", "my.", "id.")

    /** "https://accounts.example.com:8443" -> "example.com". An IPv6 host or an empty one gives the origin back. */
    fun friendly(origin: String): String {
        var host = origin
        val at = origin.indexOf("://")
        if (at >= 0) {
            host = origin.substring(at + 3).substringBefore('/')
            val colon = host.lastIndexOf(':')
            if (colon >= 0) host = host.substring(0, colon)
        }
        if (host.startsWith("[")) return origin
        for (p in loginSubdomains) {
            if (host.startsWith(p) && host.count { it == '.' } >= 2) {
                host = host.substring(p.length)
                break
            }
        }
        return host.ifEmpty { origin }
    }
}

/**
 * One live record, decoded from its synced wrapper, with the list projection the desktop shows
 * (`agent.py` `_summary_title`, `row_target`, `kind_label`).
 */
data class VaultItem(
    val id: String,
    val kind: String,
    val title: String,
    val username: String,
    /** The WEBSITE / APPLICATION column. */
    val target: String,
    /** Cards only: "•••• 6411" (plus " · 08/27" with an expiry). Never the full number; null when it has fewer than 4 digits. */
    val cardSummary: String?,
    val tags: List<String>,
    val favorite: Boolean,
    val updatedAt: Long,
    /** `created_at`; 0 when missing (the sort rule's missing timestamp). */
    val createdAt: Long = 0L,
    val record: Map<String, JsonValue>,
) {
    /** Never shows the record: it holds passwords and two-factor secrets. */
    override fun toString(): String = "VaultItem(id=$id, kind=$kind)"

    fun kindLabel(t: Txt): String = kindLabel(kind, t)
    val isLogin: Boolean get() = kind == "web" || kind == "desktop"

    /** `totp` is an object with a `secret`. */
    val hasTotp: Boolean get() = record["totp"].objectOrNull()?.containsKey("secret") == true

    /** The list subtitle: username, else the card's masked last four, else the target, else the kind. */
    fun listSubtitle(t: Txt): String = when {
        username.isNotEmpty() -> username
        cardSummary != null -> cardSummary
        else -> target.ifEmpty { kindLabel(t) }
    }

    /** A login's password, or a Wi-Fi network's; null when empty or the kind has none. */
    val copyablePassword: String?
        get() {
            val p = record["password"].stringOrNull()
                ?: if (kind == "wifi") record["payload"].objectOrNull()?.get("password").stringOrNull() else null
            return p?.takeIf { it.isNotEmpty() }
        }

    /** An http(s) address to open in the browser: a web login's site or a bookmark. */
    val openableUrl: String?
        get() {
            val raw = when (kind) {
                "web" -> pageAddress(record["scope"].objectOrNull())
                "bookmark" -> record["payload"].objectOrNull()?.get("url").stringOrNull()
                else -> null
            } ?: return null
            val uri = try { URI(raw) } catch (_: Exception) { return null }
            val scheme = uri.scheme?.lowercase()
            return if ((scheme == "https" || scheme == "http") && !uri.host.isNullOrEmpty()) raw else null
        }

    companion object {
        /**
         * Desktop `web_page_address`: a web login's origin, or the first `starts_with` row on that same origin (an
         * imported full page address, 2026-10-29). Display and Open website only; matching uses every row.
         */
        fun pageAddress(scope: Map<String, JsonValue>?): String? {
            val origin = scope?.get("origin").stringOrNull() ?: return null
            val rows = (scope?.get("urls") as? JsonValue.Arr)?.items ?: return origin
            for (row in rows) {
                val o = row.objectOrNull() ?: continue
                if (o["match"].stringOrNull() != "starts_with") continue
                val url = o["url"].stringOrNull() ?: continue
                val same = try { Origin.originOf(url) == origin } catch (e: Exception) { false }
                if (same) return url
            }
            return origin
        }

        /** Live records of the snapshot: no tombstones, no licence states, nothing without a record and a kind. */
        fun items(snapshot: StoreSnapshot): List<VaultItem> = snapshot.records.mapNotNull { (id, wrapper) ->
            if (snapshot.meta[id]?.deleted == true) return@mapNotNull null
            val w = wrapper.objectOrNull() ?: return@mapNotNull null
            val ns = w["ns"].stringOrNull() ?: return@mapNotNull null
            if (ns == Namespace.LICENSE.wire) return@mapNotNull null
            val r = w["record"] as? JsonValue.Obj ?: return@mapNotNull null
            of(id, r)
        }

        /** Null when the record has no string `kind`. */
        fun of(id: String, record: JsonValue.Obj): VaultItem? {
            val r = record.fields
            val kind = r["kind"].stringOrNull() ?: return null
            val scope = r["scope"].objectOrNull() ?: emptyMap()
            val payload = r["payload"].objectOrNull() ?: emptyMap()
            var title = r["title"].stringOrNull() ?: r["label"].stringOrNull() ?: ""
            val origin = scope["origin"].stringOrNull()
            if (kind == "web" && origin != null && title == origin) title = OriginLabel.friendly(origin)
            return VaultItem(
                id = id,
                kind = kind,
                title = title,
                username = r["username"].stringOrNull() ?: "",
                target = safeDisplay(rowTarget(kind, scope, payload)),
                cardSummary = if (kind == "card") cardSummary(payload) else null,
                tags = r["tags"].listOrNull()?.mapNotNull { it.stringOrNull() } ?: emptyList(),
                favorite = r["favorite"] == JsonValue.Bool(true),
                updatedAt = (r["updated_at"] as? JsonValue.Int)?.v ?: 0L,
                createdAt = (r["created_at"] as? JsonValue.Int)?.v ?: 0L,
                record = r,
            )
        }

        /** "•••• 6411", or "•••• 6411 · 08/27" with an expiry. Only the last four digits ever leave the payload. */
        fun cardSummary(payload: Map<String, JsonValue>): String? {
            val digits = (payload["number"].stringOrNull() ?: "").filter { it in '0'..'9' }
            if (digits.length < 4) return null
            var out = "•••• " + digits.takeLast(4)
            val expiry = safeDisplay(payload["expiry"].stringOrNull() ?: "", 10).trim { it == ' ' || it == '\t' }
            if (expiry.isNotEmpty()) out += " · $expiry"
            return out
        }

        private val kindLabelIds = mapOf(
            "web" to R.string.new_item_web, "desktop" to R.string.kind_desktop, "card" to R.string.new_item_card,
            "bank_account" to R.string.new_item_bank_account, "ssh_key" to R.string.new_item_ssh_key, "api_key" to R.string.new_item_api_key,
            "wifi" to R.string.new_item_wifi, "passkey" to R.string.new_item_passkey, "note" to R.string.kind_note,
            "identity" to R.string.new_item_identity, "purchase" to R.string.new_item_purchase, "subscription" to R.string.new_item_subscription,
            "warranty" to R.string.new_item_warranty, "license" to R.string.new_item_license, "bookmark" to R.string.new_item_bookmark,
            "document" to R.string.detail_pane_document,
        )

        /** `agent.py` `kind_label`; a kind this version does not know shows its raw name capitalised. */
        fun kindLabel(kind: String, t: Txt): String {
            kindLabelIds[kind]?.let { return t.s(it) }
            val s = kind.replace('_', ' ').trim { it == ' ' || it == '\t' }
            if (s.isEmpty()) return t.s(R.string.kind_unknown)
            return capitalized(s)
        }

        /** First character upper case, the rest lower case. */
        internal fun capitalized(s: String): String {
            if (s.isEmpty()) return s
            val n = s.offsetByCodePoints(0, 1)
            return s.substring(0, n).uppercase() + s.substring(n).lowercase()
        }

        private val targetFields = mapOf(
            "passkey" to listOf("relying_party_id"), "api_key" to listOf("service"), "wifi" to listOf("ssid"),
            "bank_account" to listOf("bank"), "license" to listOf("vendor", "product"),
            "purchase" to listOf("vendor", "product"), "warranty" to listOf("vendor", "product"),
            "subscription" to listOf("vendor", "provider", "product"), "ssh_key" to listOf("fingerprint"),
        )

        /** `agent.py` `row_target`. */
        fun rowTarget(kind: String, scope: Map<String, JsonValue>, payload: Map<String, JsonValue>): String = when (kind) {
            "web" -> scope["origin"].stringOrNull() ?: ""
            "desktop" -> (scope["exe_path"].stringOrNull() ?: "").split('/', '\\').lastOrNull { it.isNotEmpty() } ?: ""
            "bookmark" -> payload["url"].stringOrNull()?.let { hostOf(it) } ?: ""
            "card" -> capitalized(payload["brand"].stringOrNull() ?: "")
            else -> (targetFields[kind] ?: emptyList())
                .mapNotNull { payload[it].stringOrNull()?.trim() }
                .filter { it.isNotEmpty() }
                .joinToString(" · ")
        }

        private fun hostOf(url: String): String? = try { URI(url).host } catch (_: Exception) { null }

        /**
         * `agent.py` `_safe_display`: control, format, surrogate, private-use, unassigned, line and paragraph
         * separators and every space separator but U+0020 become spaces; at most [maxLength] characters.
         */
        fun safeDisplay(s: String, maxLength: Int = 120): String {
            val out = StringBuilder()
            var i = 0
            var n = 0
            while (i < s.length && n < maxLength) {
                val cp = s.codePointAt(i)
                i += Character.charCount(cp)
                n++
                val bad = when (Character.getType(cp).toByte()) {
                    Character.CONTROL, Character.FORMAT, Character.SURROGATE, Character.PRIVATE_USE, Character.UNASSIGNED,
                    Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR,
                    -> true
                    Character.SPACE_SEPARATOR -> cp != 0x20
                    else -> false
                }
                if (bad) out.append(' ') else out.appendCodePoint(cp)
            }
            return out.toString()
        }
    }
}
