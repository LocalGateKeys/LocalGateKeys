package app.localgatekeys.android.access

import app.localgatekeys.android.collections.CollectionsModel
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.core.access.AccessRules
import app.localgatekeys.core.history.ItemHistory
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange

/**
 * A web login's Access rules (contract section 4): `policy.require_master_password`, `policy.fill` and
 * `scope.access`, written as a synced edit (`updated_at` = now). Setting or tightening needs Pro
 * (`access_policies`); loosening or removing never does.
 */
object AccessRulesModel {
    /** What the sheet starts from. */
    data class Form(val reauth: Boolean, val neverFill: Boolean, val settings: AccessRules.Settings, val unknownRule: Boolean)

    fun form(record: Map<String, JsonValue>): Form {
        val policy = (record["policy"] as? JsonValue.Obj)?.fields ?: emptyMap()
        val raw = AccessRules.accessOf(record)
        val unknown = raw != null && ((raw as? JsonValue.Obj)?.fields?.keys?.let { !AccessRules.KEYS.containsAll(it) } ?: true)
        return Form(
            reauth = AccessRules.strictPolicy(policy),
            neverFill = policy["fill"] == JsonValue.Str("never"),
            settings = AccessRules.Settings.of(raw),
            unknownRule = unknown,
        )
    }

    /** [record] with the form applied (the caller stamps and normalises). */
    fun applied(record: Map<String, JsonValue>, f: Form): Map<String, JsonValue> =
        AccessRules.withAccess(AccessRules.withPolicy(record, f.reauth, f.neverFill), f.settings.write())

    /** A date the sheet accepts: empty, or `YYYY-MM-DD`. */
    fun validDate(s: String): Boolean = s.isEmpty() || AccessRules.isoDate(s) != null

    /** Whether [f] loosens or removes any rule [old] has (later date, unticked rule): that needs the owner's check. */
    fun loosens(old: Map<String, JsonValue>, f: Form): Boolean = AccessRules.tightens(applied(old, f), old)

    /** Whether saving [f] on login [id] needs the owner's check first ([loosens]); unreadable counts as yes. */
    fun needsOwner(store: ItemStore, id: String, f: Form): Boolean = try {
        val old = ((store.load().records[id] as? JsonValue.Obj)?.fields?.get("record") as? JsonValue.Obj)?.fields
        old == null || loosens(old, f)
    } catch (e: Exception) {
        true
    }

    /**
     * Saves [f] on login [id]. NEEDS_PRO for a tightening without Pro; INVALID for a bad date or a view-only item;
     * FAILED for a loosening without [ownerConfirmed] (scan A-M2: anyone holding the unlocked phone could untick the
     * rules and then copy freely).
     */
    fun save(store: ItemStore, id: String, f: Form, isPro: Boolean, clock: UnixClock, ownerConfirmed: Boolean = false): SaveResult = try {
        val snap = store.load()
        val w = (snap.records[id] as? JsonValue.Obj)?.fields
        val old = (w?.get("record") as? JsonValue.Obj)?.fields
        when {
            snap.meta[id]?.deleted == true || w?.get("ns") != JsonValue.Str(Namespace.ENTRY.wire) || old == null -> SaveResult.FAILED
            old["kind"] != JsonValue.Str("web") -> SaveResult.INVALID
            f.unknownRule || !validDate(f.settings.expires) -> SaveResult.INVALID
            CollectionsModel.itemIsReadOnly(id, snap) -> SaveResult.INVALID
            else -> {
                val new = applied(old, f)
                if (ItemHistory.canon(JsonValue.Obj(new)).contentEquals(ItemHistory.canon(JsonValue.Obj(old)))) {
                    SaveResult.UNCHANGED
                } else if (!isPro && AccessRules.tightens(old, new)) {
                    SaveResult.NEEDS_PRO
                } else if (!ownerConfirmed && AccessRules.tightens(new, old)) {
                    SaveResult.FAILED
                } else {
                    val stamped = LinkedHashMap(new)
                    stamped["updated_at"] = JsonValue.Int(clock.now)
                    val records = LinkedHashMap(snap.records)
                    records[id] = Wrapper.make(Namespace.ENTRY, Normalise.normalForm(Namespace.ENTRY, JsonValue.Obj(stamped)))
                    store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
                    SaveResult.SAVED
                }
            }
        }
    } catch (e: Exception) {
        SaveResult.FAILED
    }
}
