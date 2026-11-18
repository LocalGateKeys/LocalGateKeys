package app.localgatekeys.android.duress

import app.localgatekeys.android.R
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.License
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot

/** What Settings shows for the duress password. [on] is false inside a duress session (it looks not set up there). */
data class DuressStatus(val pro: Boolean, val appPasswordOn: Boolean, val on: Boolean, val hours: Int)

/**
 * Settings > Security > Duress password (sub-plan 08), built by the app over [DuressVault] and the open vault.
 * Passwords cross as the typed text only and are never stored.
 */
class DuressSeams(
    val status: suspend () -> DuressStatus,
    /** The current app password, the duress password twice and the hours; throws [DuressException] or a password error. */
    val setUp: suspend (current: String, password: String, confirm: String, hours: Int) -> Unit,
    val remove: suspend () -> Unit,
) {
    override fun toString(): String = "DuressSeams"
}

/** The words of the duress screens, free of Compose. */
object DuressText {
    fun message(e: DuressException, t: Txt): String = when (e.code) {
        "same" -> t.s(R.string.duress_err_same)
        "close" -> t.s(R.string.duress_err_close)
        "near_duress" -> t.s(R.string.duress_err_near)
        "mismatch" -> t.s(R.string.duress_err_mismatch)
        "hours" -> t.s(R.string.duress_err_hours, DuressVault.MIN_HOURS, DuressVault.MAX_HOURS)
        "exists" -> t.s(R.string.duress_err_exists)
        "needs_password" -> t.s(R.string.duress_needs_app_password)
        "pro" -> t.s(R.string.duress_pro_only)
        "unavailable" -> t.s(R.string.duress_err_unavailable)
        else -> t.s(R.string.duress_err_generic)
    }

    val HOURS = listOf(1, 2, 4, 8, 12, 24, 48, 72, 168)
}

/**
 * A few plausible items for a new second vault (desktop `_sample_items`): the owner's most used user name on two
 * common sites with random passwords, two notes and two bookmarks, titled in the person's language.
 */
object DuressSamples {
    private const val ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    private fun password(random: RandomSource): String {
        val sb = StringBuilder()
        while (sb.length < 16) {
            val b = random.bytes(1)[0].toInt() and 0xFF
            if (b < 4 * ALPHABET.length) sb.append(ALPHABET[b % ALPHABET.length]) // no modulo bias
        }
        return sb.toString()
    }

    private fun mostUsedUsername(real: StoreSnapshot): String = real.records.values.mapNotNull { w ->
        val f = (w as? JsonValue.Obj)?.fields ?: return@mapNotNull null
        val r = (f["record"] as? JsonValue.Obj)?.fields ?: return@mapNotNull null
        if (r["kind"] != JsonValue.Str("web")) null else (r["username"] as? JsonValue.Str)?.v?.takeIf { it.isNotEmpty() }
    }.groupingBy { it }.eachCount().maxByOrNull { it.value }?.key ?: ""

    fun seed(store: ItemStore, real: StoreSnapshot, t: Txt, random: RandomSource, now: Long) {
        val records = ArrayList<Map<String, JsonValue>>()
        val user = mostUsedUsername(real)
        for ((label, origin) in listOf("Wikipedia" to "https://www.wikipedia.org", "Amazon" to "https://www.amazon.com")) {
            records += EditorModel.newRecord(EditorKind.WEB, now, random).toMutableMap().apply {
                this["label"] = JsonValue.Str(label)
                this["username"] = JsonValue.Str(user)
                this["password"] = JsonValue.Str(password(random))
                this["scope"] = JsonValue.Obj(mapOf("origin" to JsonValue.Str(origin)))
            }
        }
        val code = ((random.bytes(2).let { ((it[0].toInt() and 0xFF) shl 8) or (it[1].toInt() and 0xFF) }) % 10000).toString().padStart(4, '0')
        for ((title, body) in listOf(
            t.s(R.string.duress_sample_shopping_title) to t.s(R.string.duress_sample_shopping_body),
            t.s(R.string.duress_sample_bike_title) to t.s(R.string.duress_sample_bike_body, code),
        )) {
            records += EditorModel.newRecord(EditorKind.NOTE, now, random).toMutableMap().apply {
                this["title"] = JsonValue.Str(title)
                this["payload"] = JsonValue.Obj(mapOf("body" to JsonValue.Str(body)))
            }
        }
        for ((title, url) in listOf(
            t.s(R.string.duress_sample_weather) to "https://www.accuweather.com/",
            t.s(R.string.duress_sample_news) to "https://www.bbc.com/news",
        )) {
            records += EditorModel.newRecord(EditorKind.BOOKMARK, now, random).toMutableMap().apply {
                this["title"] = JsonValue.Str(title)
                this["payload"] = JsonValue.Obj(mapOf("url" to JsonValue.Str(url)))
            }
        }
        val snap = store.load()
        val out = LinkedHashMap(snap.records)
        for (r in records) {
            val kind = (r["kind"] as JsonValue.Str).v
            val ns = EditorKind.entries.first { it.raw == kind }.ns
            val normal = Normalise.normalForm(ns, JsonValue.Obj(r))
            out[(r["id"] as JsonValue.Str).v] = Wrapper.make(ns, normal)
        }
        // The real vault's licence states (Pro from the desktop licence), copied as they are: the second vault shows
        // the same plan, so Pro features do not vanish there (review 5a #5). They are signed and carry no secrets.
        for ((id, wrapper) in real.records) {
            val w = (wrapper as? JsonValue.Obj)?.fields ?: continue
            if (id.startsWith(License.ID_PREFIX) && w["ns"] == JsonValue.Str(Namespace.LICENSE.wire)) out[id] = wrapper
        }
        store.commit(StoreChange(snap.revision, out, snap.meta, snap.sync))
    }
}
