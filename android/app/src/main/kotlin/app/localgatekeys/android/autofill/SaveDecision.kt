package app.localgatekeys.android.autofill

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Casefold
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.Origin
import app.localgatekeys.core.records.PasswordHistory
import app.localgatekeys.core.records.PyStrip
import app.localgatekeys.core.records.UrlMatcher
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot

/** What the save sheet offers for a login the person just typed. */
sealed interface SaveDecision {
    data object New : SaveDecision

    /** The free plan is full and there is no Pro: Save is refused with the limit message. */
    data object NeedsPro : SaveDecision

    data class Update(val itemId: String) : SaveDecision

    data class Unchanged(val itemId: String) : SaveDecision

    companion object {
        /** Shown when the free plan is full. */
        fun limitMessage(t: Txt): String = t.plural(R.plurals.autofill_limit_message, ItemLimit.FREE_ITEMS, ItemLimit.FREE_ITEMS)

        private fun text(v: JsonValue?): String = (v as? JsonValue.Str)?.v ?: ""

        private fun sameUser(a: String, b: String): Boolean = Casefold.fold(PyStrip.strip(a)) == Casefold.fold(PyStrip.strip(b))

        private fun live(s: StoreSnapshot): List<Pair<String, Map<String, JsonValue>>> = s.records.entries.mapNotNull { (id, w) ->
            if (s.meta[id]?.deleted == true) return@mapNotNull null
            val f = (w as? JsonValue.Obj)?.fields ?: return@mapNotNull null
            if (f["ns"] != JsonValue.Str(Namespace.ENTRY.wire)) return@mapNotNull null
            val r = (f["record"] as? JsonValue.Obj)?.fields ?: return@mapNotNull null
            if (r["kind"] != JsonValue.Str("web")) null else id to r
        }

        /** Existing login for [target] and [username] (web: URL match; app: the local pairings), then the limit. */
        fun decide(
            s: StoreSnapshot,
            target: FillTarget,
            username: String,
            password: String,
            isPro: Boolean,
            matcher: FillMatcher,
            index: FillIndex,
        ): SaveDecision {
            val existing = live(s).filter { (id, r) -> matcher.recordMatches(r, id, target, index) && sameUser(text(r["username"]), username) }
                .sortedByDescending { (_, r) -> (r["updated_at"] as? JsonValue.Int)?.v ?: 0L }
                .firstOrNull()
            if (existing != null) {
                val (id, r) = existing
                return if (text(r["password"]) == password) Unchanged(id) else Update(id)
            }
            return if (ItemLimit.allows(ItemLimit.Action.CREATE, s, isPro)) New else NeedsPro
        }

        /** The title a new login gets: the site's host without `www.`. */
        fun titleFor(origin: String): String = try {
            UrlMatcher.hostOf(origin).removePrefix("www.")
        } catch (e: Exception) {
            origin
        }

        /** A new web login in normal form (throws `NormaliseException` / `OriginException` for a bad website). */
        fun newRecord(website: String, username: String, password: String, now: Long, random: RandomSource): JsonValue {
            val origin = Origin.canonicalize(Origin.originOf(PyStrip.strip(website)))
            val r = LinkedHashMap(EditorModel.newRecord(app.localgatekeys.android.editor.EditorKind.WEB, now, random))
            r["label"] = JsonValue.Str(titleFor(origin))
            r["username"] = JsonValue.Str(username)
            r["password"] = JsonValue.Str(password)
            r["scope"] = JsonValue.Obj(mapOf("origin" to JsonValue.Str(origin)))
            return Normalise.normalForm(Namespace.ENTRY, JsonValue.Obj(r))
        }

        /** [record] with [password] and the old one in its history. */
        fun updatedRecord(record: Map<String, JsonValue>, password: String, now: Long): JsonValue {
            val old = text(record["password"])
            val r = LinkedHashMap(record)
            r["password"] = JsonValue.Str(password)
            r["updated_at"] = JsonValue.Int(now)
            return Normalise.normalForm(Namespace.ENTRY, JsonValue.Obj(PasswordHistory.push(r, old, now)))
        }

        /** The change that writes [record] (normal form) over [s]. */
        fun change(s: StoreSnapshot, record: JsonValue): StoreChange {
            val id = ((record as JsonValue.Obj).fields["id"] as JsonValue.Str).v
            val records = LinkedHashMap(s.records)
            records[id] = Wrapper.make(Namespace.ENTRY, record)
            return StoreChange(s.revision, records, s.meta, s.sync)
        }

        fun recordOf(s: StoreSnapshot, id: String): Map<String, JsonValue>? = live(s).firstOrNull { it.first == id }?.second
    }
}
