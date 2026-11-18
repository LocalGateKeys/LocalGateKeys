package app.localgatekeys.android.trash

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.android.reminders.Reminder
import app.localgatekeys.android.reminders.ReminderDays
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.core.sync.ShareTrash
import app.localgatekeys.core.sync.TravelMode
import app.localgatekeys.core.importing.ImportUndo

/** A [LocalData] that breaks a limit, or a file whose contents are not local data. Never carries content. */
class LocalDataException(val detail: String) : Exception(detail)

/**
 * Data that stays on this phone and never syncs: Recently deleted, its preferences and the expiry reminders (a port of
 * the trash and reminder parts of `ios/LGKCore/Sources/LGKCore/Local/LocalData.swift`, same JSON keys). Top-level keys
 * this version does not use (the iPhone's events, collections) are kept in [extra] untouched, so a later feature can
 * add its own. A file written before reminders moved here (no `reminders` key) reads as no reminders.
 *
 * Collections (sub-plan 07) live in the item store as `col:`/`cm:` records. Only which of them this phone made as
 * starters stays here ([starterCollectionIds], `starter_collection_ids`, never synced). Older local collections
 * (`extra["collections"]` and `extra["memberships"]`, the Mac's shape) are read once by the migration
 * ([legacyCollections], [legacyMemberships]) and then dropped ([withoutLegacyCollections]).
 */
data class LocalData(
    val trash: List<TrashRow> = emptyList(),
    val preferences: Preferences = Preferences(),
    val extra: Map<String, JsonValue> = emptyMap(),
    /** Expiry reminders (content-free rows: ids, dates, state). */
    val reminders: List<Reminder> = emptyList(),
    /** The store collections this phone made as starters (`CollectionCatalog.starters`): the flag never syncs. */
    val starterCollectionIds: List<String> = emptyList(),
) {
    /**
     * One Recently deleted row: the full record as stored, kept as its canonical JSON text (UTF-8) so a restore gives
     * back exactly the same bytes, and when it was deleted (Unix seconds). [toString] never shows the record.
     */
    class TrashRow(val recordJson: String, val deletedAt: Long) {
        /** The deleted record, parsed back with the canonical parser. */
        fun record(): JsonValue = CanonicalJson.parse(recordJson.toByteArray(Charsets.UTF_8))

        override fun equals(other: Any?): Boolean =
            other is TrashRow && other.recordJson == recordJson && other.deletedAt == deletedAt

        override fun hashCode(): Int = recordJson.hashCode() * 31 + deletedAt.hashCode()
        override fun toString(): String = "TrashRow(deletedAt=$deletedAt)"

        companion object {
            fun of(record: JsonValue, deletedAt: Long): TrashRow =
                TrashRow(String(CanonicalJson.encode(record, Dialect.UTF8), Charsets.UTF_8), deletedAt)
        }
    }

    data class Preferences(
        val trashRetentionDays: Int = 30,
        val trashAutoPurge: Boolean = true,
        val reminderDefaultLeadDays: Int = 0,
    )

    /** Checks every limit; throws [LocalDataException] (the detail names the rule, never content). */
    fun validated(): LocalData {
        if (trash.size > MAX_TRASH) throw LocalDataException("trash exceeds its limit")
        for (row in trash) {
            val r = try {
                row.record()
            } catch (e: JsonException) {
                throw LocalDataException("trash record must be a JSON object")
            }
            if (r !is JsonValue.Obj) throw LocalDataException("trash record must be a JSON object")
            if (row.deletedAt < 0) throw LocalDataException("trash deleted_at is malformed")
        }
        if (preferences.trashRetentionDays !in 1..365) throw LocalDataException("trash retention is malformed")
        if (preferences.reminderDefaultLeadDays !in 0..3650) throw LocalDataException("reminder default lead days is malformed")
        if (reminders.size > MAX_REMINDERS) throw LocalDataException("reminders exceed the limit")
        val ids = HashSet<String>()
        for (r in reminders) {
            if (r.id.isEmpty() || !ids.add(r.id)) throw LocalDataException("reminder ids are malformed")
            if (r.itemId.isEmpty()) throw LocalDataException("reminder item id is malformed")
            if (ReminderDays.dayNumber(r.dueDate) == null) throw LocalDataException("reminder due date is malformed")
            if (r.leadDays !in 0..Reminder.MAX_LEAD_DAYS) throw LocalDataException("reminder lead_days is malformed")
            if (r.snoozeUntil.isNotEmpty() && ReminderDays.dayNumber(r.snoozeUntil) == null) throw LocalDataException("reminder snooze_until is malformed")
            if (r.lastNotified.length > 32) throw LocalDataException("reminder last_notified is malformed")
        }
        if (starterCollectionIds.size > CollectionCatalog.MAX_COLLECTIONS) throw LocalDataException("starter collections exceed the limit")
        if (starterCollectionIds.toSet().size != starterCollectionIds.size || starterCollectionIds.any { !ShareKeyring.isCanonicalUuid(it) }) {
            throw LocalDataException("starter collection ids are malformed")
        }
        return this
    }

    /** Whether older local collections are still here (the migration has not cleared them yet). */
    val hasLegacyCollections: Boolean get() = extra.containsKey(LEGACY_COLLECTIONS) || extra.containsKey(LEGACY_MEMBERSHIPS)

    /**
     * Older local collections (`extra["collections"]`, the Mac's `LocalData.collections` shape), for the one-time
     * migration into the store. Lenient: a row that is not a usable collection is left out (never blocks the rest).
     */
    fun legacyCollections(): List<CollectionCatalog.LegacyCollection> {
        val rows = (extra[LEGACY_COLLECTIONS] as? JsonValue.Arr)?.items ?: return emptyList()
        val out = ArrayList<CollectionCatalog.LegacyCollection>()
        val seen = HashSet<String>()
        for (row in rows) {
            val f = (row as? JsonValue.Obj)?.fields ?: continue
            val id = ((f["id"] as? JsonValue.Str)?.v ?: continue).lowercase()
            if (!ShareKeyring.isCanonicalUuid(id) || !seen.add(id)) continue
            val name = (f["name"] as? JsonValue.Str)?.v?.takeIf { !it.contains('\u0000') } ?: continue
            val description = (f["description"] as? JsonValue.Str)?.v
                ?.takeIf { !it.contains('\u0000') && it.codePointCount(0, it.length) <= LEGACY_DESCRIPTION } ?: ""
            val created = ((f["created_at"] as? JsonValue.Int)?.v ?: 0L).coerceAtLeast(0L)
            val updated = ((f["updated_at"] as? JsonValue.Int)?.v ?: created).coerceAtLeast(created)
            out.add(
                CollectionCatalog.LegacyCollection(
                    id, codePoints(name, LEGACY_NAME), description, created, updated, (f["starter"] as? JsonValue.Bool)?.v == true,
                ),
            )
        }
        return out
    }

    /** Older local memberships (`extra["memberships"]`: item id -> collection ids), for the migration. Lenient. */
    fun legacyMemberships(): Map<String, List<String>> {
        val o = (extra[LEGACY_MEMBERSHIPS] as? JsonValue.Obj)?.fields ?: return emptyMap()
        val out = LinkedHashMap<String, List<String>>()
        for ((item, v) in o) {
            val ids = (v as? JsonValue.Arr)?.items?.mapNotNull { (it as? JsonValue.Str)?.v?.lowercase() }
                ?.filter { ShareKeyring.isCanonicalUuid(it) } ?: continue
            if (ids.isNotEmpty()) out[item.lowercase()] = ids
        }
        return out
    }

    /** This data without the older local collections and memberships (after the migration moved them). */
    fun withoutLegacyCollections(): LocalData = copy(extra = extra - LEGACY_COLLECTIONS - LEGACY_MEMBERSHIPS)

    /**
     * Feature pack 2026-11-15 (contract section 0): device-local state kept under its own top-level key, read from
     * [extra] so older and newer phones keep each other's keys byte for byte. Never synced, never in a backup.
     */
    val travelMode: TravelMode.Setting get() = TravelMode.Setting.of(extra[TRAVEL_MODE])

    fun withTravelMode(s: TravelMode.Setting): LocalData =
        copy(extra = if (s == TravelMode.Setting.OFF) extra - TRAVEL_MODE else extra + (TRAVEL_MODE to s.json()))

    /** Item history rows (`item_history`, contract section 1.2), oldest first. */
    val itemHistory: List<JsonValue> get() = (extra[ITEM_HISTORY] as? JsonValue.Arr)?.items ?: emptyList()

    fun withItemHistory(rows: List<JsonValue>): LocalData =
        copy(extra = if (rows.isEmpty()) extra - ITEM_HISTORY else extra + (ITEM_HISTORY to JsonValue.Arr(rows)))

    /** The ids of the records in the trash rows. */
    fun trashIds(rows: List<TrashRow> = trash): Set<String> = rows.mapNotNullTo(HashSet()) {
        try {
            ((it.record() as? JsonValue.Obj)?.fields?.get("id") as? JsonValue.Str)?.v
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Forgets the item history of the records in [gone], trash rows deleted for good (scan A-M3: "Delete forever" must
     * not leave the old passwords in the history). An id still in the trash (deleted twice) keeps its history.
     */
    fun forgetHistoryOf(gone: List<TrashRow>): LocalData {
        if (gone.isEmpty() || itemHistory.isEmpty()) return this
        val ids = trashIds(gone) - trashIds()
        if (ids.isEmpty()) return this
        val kept = itemHistory.filter { app.localgatekeys.core.history.ItemHistory.Row.of(it)?.itemId !in ids }
        return if (kept.size == itemHistory.size) this else withItemHistory(kept)
    }

    /** The last import's undo journal (`last_import`, contract section 6.1), or null. */
    val lastImport: ImportUndo.Journal? get() = ImportUndo.Journal.of(extra[LAST_IMPORT])

    fun withLastImport(j: ImportUndo.Journal?): LocalData =
        copy(extra = if (j == null) extra - LAST_IMPORT else extra + (LAST_IMPORT to j.json()))

    /** Passkey upgrade dismissals (`passkey_upgrade_dismissed`: registrable domain -> Unix seconds). */
    val passkeyUpgradeDismissed: Map<String, Long>
        get() = (extra[PASSKEY_DISMISSED] as? JsonValue.Obj)?.fields?.mapNotNull { (k, v) -> (v as? JsonValue.Int)?.v?.let { k to it } }?.toMap() ?: emptyMap()

    /** [domain] dismissed at [now]; at most [MAX_DISMISSALS] entries, the oldest dropped first. */
    fun withPasskeyDismissed(domain: String, now: Long): LocalData {
        val all = (passkeyUpgradeDismissed + (domain to now)).entries.sortedWith(compareByDescending<Map.Entry<String, Long>> { it.value }.thenBy { it.key })
            .take(MAX_DISMISSALS).sortedBy { it.key }
        return copy(extra = extra + (PASSKEY_DISMISSED to JsonValue.Obj(LinkedHashMap(all.associate { it.key to JsonValue.Int(it.value) }))))
    }

    /** Drops Recently deleted rows older than the retention period, when auto-purge is on. */
    fun purgeExpiredTrash(now: Long): LocalData {
        if (!preferences.trashAutoPurge) return this
        val days = preferences.trashRetentionDays.coerceIn(1, 365).toLong()
        val cutoff = now - days * 86_400
        val gone = trash.filter { it.deletedAt < cutoff }
        if (gone.isEmpty()) return this
        return copy(trash = trash.filter { it.deletedAt >= cutoff }).forgetHistoryOf(gone)
    }

    override fun toString(): String =
        "LocalData(trash=${trash.size}, reminders=${reminders.size}, starters=${starterCollectionIds.size}, preferences=$preferences, " +
            "extra=${extra.keys.sorted()})"

    companion object {
        /** One limit with the share runner's trash check (sub-plan 07): a removal it allows always fits here. */
        const val MAX_TRASH = ShareTrash.MAX_TRASH
        const val MAX_REMINDERS = 20_000
        val EMPTY = LocalData()

        const val TRAVEL_MODE = "travel_mode"
        const val ITEM_HISTORY = "item_history"
        const val LAST_IMPORT = "last_import"
        const val PASSKEY_DISMISSED = "passkey_upgrade_dismissed"
        const val MAX_DISMISSALS = 500

        private const val TRASH = "trash"
        private const val PREFERENCES = "preferences"
        private const val REMINDERS = "reminders"
        private const val STARTERS = "starter_collection_ids"
        private const val LEGACY_COLLECTIONS = "collections"
        private const val LEGACY_MEMBERSHIPS = "memberships"
        private const val LEGACY_NAME = 100
        private const val LEGACY_DESCRIPTION = 500

        /** The first [max] code points of [s]. */
        private fun codePoints(s: String, max: Int): String =
            if (s.codePointCount(0, s.length) <= max) s else s.substring(0, s.offsetByCodePoints(0, max))

        /** The iPhone's status words (`pending`, not Android's in-memory ACTIVE). */
        private fun statusWire(s: Reminder.Status): String = if (s == Reminder.Status.ACTIVE) "pending" else s.wire

        private fun statusOf(wire: String): Reminder.Status = when (wire) {
            "pending" -> Reminder.Status.ACTIVE
            Reminder.Status.SNOOZED.wire -> Reminder.Status.SNOOZED
            Reminder.Status.DISMISSED.wire -> Reminder.Status.DISMISSED
            else -> throw LocalDataException("reminder status")
        }

        /** Canonical JSON (UTF-8), the iPhone's keys. */
        fun encode(d: LocalData): ByteArray {
            val o = LinkedHashMap<String, JsonValue>(d.extra)
            o[TRASH] = JsonValue.Arr(
                d.trash.map { JsonValue.Obj(mapOf("record" to JsonValue.Str(it.recordJson), "deleted_at" to JsonValue.Int(it.deletedAt))) },
            )
            o[REMINDERS] = JsonValue.Arr(
                d.reminders.map {
                    JsonValue.Obj(
                        mapOf(
                            "id" to JsonValue.Str(it.id),
                            "item_id" to JsonValue.Str(it.itemId),
                            "due_date" to JsonValue.Str(it.dueDate),
                            "lead_days" to JsonValue.Int(it.leadDays.toLong()),
                            "status" to JsonValue.Str(statusWire(it.status)),
                            "snooze_until" to JsonValue.Str(it.snoozeUntil),
                            "last_notified" to JsonValue.Str(it.lastNotified),
                        ),
                    )
                },
            )
            // Written only when there are some, so data without starters keeps its old shape.
            if (d.starterCollectionIds.isNotEmpty()) o[STARTERS] = JsonValue.Arr(d.starterCollectionIds.map { JsonValue.Str(it) })
            o[PREFERENCES] = JsonValue.Obj(
                mapOf(
                    "trash_retention_days" to JsonValue.Int(d.preferences.trashRetentionDays.toLong()),
                    "trash_auto_purge" to JsonValue.Bool(d.preferences.trashAutoPurge),
                    "reminder_default_lead_days" to JsonValue.Int(d.preferences.reminderDefaultLeadDays.toLong()),
                ),
            )
            return CanonicalJson.encode(JsonValue.Obj(o), Dialect.UTF8)
        }

        /** The inverse of [encode], validated; throws [LocalDataException] for anything else. */
        fun decode(bytes: ByteArray): LocalData {
            val o = try {
                (CanonicalJson.parse(bytes) as? JsonValue.Obj)?.fields
            } catch (e: JsonException) {
                null
            } ?: throw LocalDataException("not local data")
            val rows = (o[TRASH] as? JsonValue.Arr)?.items ?: throw LocalDataException("trash")
            val trash = rows.map { v ->
                val f = (v as? JsonValue.Obj)?.fields ?: throw LocalDataException("trash row")
                val record = (f["record"] as? JsonValue.Str)?.v ?: throw LocalDataException("trash record")
                val at = (f["deleted_at"] as? JsonValue.Int)?.v ?: throw LocalDataException("trash deleted_at")
                TrashRow(record, at)
            }
            val p = (o[PREFERENCES] as? JsonValue.Obj)?.fields ?: throw LocalDataException("preferences")
            fun int(k: String): Int = (p[k] as? JsonValue.Int)?.v?.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()
                ?: throw LocalDataException(k)
            val prefs = Preferences(
                trashRetentionDays = int("trash_retention_days"),
                trashAutoPurge = (p["trash_auto_purge"] as? JsonValue.Bool)?.v ?: throw LocalDataException("trash_auto_purge"),
                reminderDefaultLeadDays = int("reminder_default_lead_days"),
            )
            // Optional: files from before reminders moved here have none.
            val reminders = when (val v = o[REMINDERS]) {
                null -> emptyList()
                is JsonValue.Arr -> v.items.map { item ->
                    val f = (item as? JsonValue.Obj)?.fields ?: throw LocalDataException("reminder row")
                    fun str(k: String) = (f[k] as? JsonValue.Str)?.v ?: throw LocalDataException("reminder $k")
                    val lead = (f["lead_days"] as? JsonValue.Int)?.v?.takeIf { it in 0..Reminder.MAX_LEAD_DAYS.toLong() }?.toInt()
                        ?: throw LocalDataException("reminder lead_days")
                    Reminder(str("id"), str("item_id"), str("due_date"), lead, statusOf(str("status")), str("snooze_until"), str("last_notified"))
                }
                else -> throw LocalDataException(REMINDERS)
            }
            val starters = when (val v = o[STARTERS]) {
                null -> emptyList()
                is JsonValue.Arr -> v.items.map { (it as? JsonValue.Str)?.v ?: throw LocalDataException(STARTERS) }
                else -> throw LocalDataException(STARTERS)
            }
            return LocalData(trash, prefs, o - TRASH - PREFERENCES - REMINDERS - STARTERS, reminders, starters).validated()
        }
    }
}
