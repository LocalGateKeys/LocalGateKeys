package app.localgatekeys.android.importing

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.vault.LocalStoreException
import app.localgatekeys.core.importing.ImportCandidate
import app.localgatekeys.core.importing.ImportCustomField
import app.localgatekeys.core.importing.ImportResult
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Casefold
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.NormaliseException
import app.localgatekeys.core.records.Origin
import app.localgatekeys.core.records.PyStrip
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.totp.Totp

/** What the person chose for one row (Windows `import_workflow.DECISIONS`; `add` is [ADD]). */
enum class ImportDecision(@StringRes val label: Int) {
    ADD(R.string.import_decision_add),
    SKIP(R.string.import_decision_skip),

    /** Overwrite the existing item's title, password and details. */
    REPLACE(R.string.incoming_sheet_replace),

    /** Keep a secure-note copy beside the existing account (Windows `keep_both`). */
    KEEP_BOTH(R.string.incoming_sheet_keep_both),
}

enum class ImportRowStatus { NEW, DUPLICATE, CONFLICT, SKIPPED_SOURCE }

/** One record as it will be saved (Windows `ImportedRecord` after `normalise_records`). toString shows no values. */
data class ImportDraft(
    val kind: Kind,
    val title: String = "",
    val username: String = "",
    val password: String = "",
    val notes: String = "",
    val totp: String = "",
    val urls: List<String> = emptyList(),
    val customFields: List<ImportCustomField> = emptyList(),
    val tags: List<String> = emptyList(),
    val folder: String = "",
    val favourite: Boolean = false,
    val identity: Map<String, String> = emptyMap(),
    val card: Map<String, String> = emptyMap(),
) {
    enum class Kind(val raw: String) { LOGIN("login"), NOTE("note"), CARD("card"), IDENTITY("identity") }

    override fun toString(): String = "ImportDraft(kind=$kind, fields=${customFields.size})"
}

/** One review row. [webUrls]: the login's canonical origins (the first is the primary one), at most 20. */
data class ImportRow(
    val id: Int,
    val sourceRow: Int,
    val draft: ImportDraft,
    /** Values a card or identity cannot hold, kept in an "extra details" secure note. */
    val extra: ImportDraft? = null,
    val webUrls: List<String> = emptyList(),
    val base: ImportRowStatus = ImportRowStatus.NEW,
    val decision: ImportDecision = ImportDecision.ADD,
    val targetId: String? = null,
    /** The target record as reviewed; the commit refuses a target that changed since. */
    val targetRecord: JsonValue? = null,
    /** No free slot left on the free plan ("Needs Pro"). */
    val limited: Boolean = false,
    /** Why the source row could not be imported (the Windows message), for [ImportRowStatus.SKIPPED_SOURCE]. */
    val reason: String? = null,
) {
    val kind: ImportDraft.Kind get() = draft.kind
    val title: String get() = draft.title
    val origin: String get() = webUrls.firstOrNull() ?: ""

    /** A repeat of an earlier row of the same import (Windows `in_import_duplicate`). */
    val inImportDuplicate: Boolean get() = base == ImportRowStatus.DUPLICATE && targetId == null

    fun stateLabel(t: Txt): String = if (limited) t.s(R.string.import_needs_pro) else t.s(decision.label)

    /** Live items this row's decision creates: the free-plan slots it needs (Windows `new_items`). */
    val newItems: Int
        get() {
            val extraCount = if (extra == null) 0 else 1
            return when (decision) {
                ImportDecision.SKIP -> 0
                ImportDecision.ADD, ImportDecision.KEEP_BOTH -> 1 + if (kind == ImportDraft.Kind.LOGIN) 0 else extraCount
                ImportDecision.REPLACE -> if (kind == ImportDraft.Kind.LOGIN) 0 else extraCount
            }
        }

    /** The decisions this row can take (Windows `ImportPlan.set_decision`). */
    val choices: List<ImportDecision>
        get() = when {
            base == ImportRowStatus.SKIPPED_SOURCE -> listOf(ImportDecision.SKIP)
            base == ImportRowStatus.NEW -> listOf(ImportDecision.ADD, ImportDecision.SKIP)
            inImportDuplicate -> listOf(ImportDecision.SKIP, ImportDecision.KEEP_BOTH)
            else -> listOf(ImportDecision.SKIP, ImportDecision.REPLACE, ImportDecision.KEEP_BOTH)
        }

    override fun toString(): String = "ImportRow(id=$id, row=$sourceRow, kind=$kind, base=$base, decision=$decision, limited=$limited)"
}

data class ImportOutcome(val created: Int, val updated: Int, val skipped: Int, val limited: Int) {
    /** "3 added · 1 updated · 2 skipped · 4 waiting: upgrade to Pro, then import again"; zero parts left out. */
    fun notice(t: Txt): String {
        val parts = ArrayList<String>()
        if (created > 0) parts.add(t.plural(R.plurals.import_outcome_added, created, created))
        if (updated > 0) parts.add(t.plural(R.plurals.import_outcome_updated, updated, updated))
        if (skipped > 0) parts.add(t.plural(R.plurals.import_outcome_skipped, skipped, skipped))
        if (limited > 0) parts.add(t.plural(R.plurals.import_outcome_waiting, limited, limited))
        return if (parts.isEmpty()) t.s(R.string.import_outcome_nothing) else parts.joinToString(" · ")
    }
}

class ImportReviewException(val kind: Kind, val row: Int = 0, val detail: String = "") : Exception(kind.name) {
    enum class Kind { TARGET_CHANGED, TARGET_REVISION_CHANGED, ITEM_LIMIT, INVALID, ITEM_NOT_SAVED }

    /** What the person reads; [message] stays the stable kind name. */
    fun text(t: Txt): String = when (kind) {
        Kind.TARGET_CHANGED -> t.s(R.string.import_workflow_import_target_changed_after_review)
        Kind.TARGET_REVISION_CHANGED -> t.s(R.string.import_workflow_import_target_revision_changed_after)
        Kind.ITEM_LIMIT -> t.plural(R.plurals.import_error_item_limit, ItemLimit.FREE_ITEMS, ItemLimit.FREE_ITEMS)
        Kind.INVALID -> t.s(R.string.import_workflow_row, row, detail)
        Kind.ITEM_NOT_SAVED -> t.s(R.string.import_error_row_not_saved, row)
    }
}

/**
 * The review step of an import: a port of `ios/App/Import/ImportReviewModel.swift` (itself Windows `import_workflow.py`:
 * `normalise_records`, `classify_rows`, `set_decision`/`recompute_limits`/`limit_note`, `apply_import_plan`) without
 * passkeys. Rows already in the vault default to Skip, repeats inside the import too (a repeat with another password
 * is kept as a secure-note copy); on the free plan rows past the free slots are "Needs Pro" and two-factor keys are
 * kept as hidden custom fields. Records are made as the phone editor makes them ([EditorModel.newRecord], core
 * `Normalise.normalForm`, `Wrapper.make`) and [commit] writes every reviewed row in one store commit.
 */
class ImportReview(
    result: ImportResult,
    snapshot: StoreSnapshot,
    isPro: Boolean,
    private val clock: UnixClock,
    private val random: RandomSource,
    private val t: Txt,
) {
    var rows: List<ImportRow>
        private set

    /** Windows review messages (capped at 50 plus an "...and N more" line). */
    val issues: List<String>

    /** Free slots left on the free plan; null on Pro. */
    val freeSlots: Int? = freeSlots(snapshot, isPro)

    init {
        val (normal, normIssues) = normalise(result.candidates, t)
        val list = normal.toMutableList()
        var issues = cap(normIssues, t)
        if (freeSlots != null) issues = issues + keepTotpAsFields(list, t)
        classify(list, snapshot)
        for (skip in result.skipped) {
            val row = skip.row ?: 0
            list.add(
                ImportRow(
                    list.size, row, ImportDraft(ImportDraft.Kind.NOTE, title = t.s(R.string.import_row_n, row)),
                    base = ImportRowStatus.SKIPPED_SOURCE, decision = ImportDecision.SKIP, reason = skip.message,
                ),
            )
        }
        rows = list
        this.issues = cap(result.skipped.map { it.message }, t) + issues
        recomputeLimits()
    }

    /** Windows `ImportPlan.set_decision`: a decision the row cannot take is ignored. */
    fun set(decision: ImportDecision, id: Int) {
        val i = rows.indexOfFirst { it.id == id }
        if (i < 0 || decision !in rows[i].choices) return
        rows = rows.toMutableList().also { it[i] = it[i].copy(decision = decision) }
        recomputeLimits()
    }

    /** Every row that is in the vault already (same data or not) set to [decision] where it can take it. */
    fun setAllExisting(decision: ImportDecision) {
        rows = rows.map { r -> if (r.base == ImportRowStatus.CONFLICT || r.base == ImportRowStatus.DUPLICATE) { if (decision in r.choices) r.copy(decision = decision) else r } else r }
        recomputeLimits()
    }

    private fun recomputeLimits() {
        var remaining = freeSlots
        rows = rows.map { r ->
            val needed = r.newItems
            val limited = remaining?.let { needed > 0 && needed > it } ?: false
            if (!limited && remaining != null) remaining -= needed
            r.copy(limited = limited)
        }
    }

    private val importedCount: Int get() = rows.count { it.decision != ImportDecision.SKIP && !it.limited }

    /** Windows `limit_note`: "" on Pro. */
    val limitNote: String
        get() {
            val slots = freeSlots ?: return ""
            val limited = rows.count { it.limited }
            if (limited == 0) return t.plural(R.plurals.import_free_slots_left, slots, slots)
            return t.plural(R.plurals.import_workflow_will_be_imported_on_free, importedCount, importedCount) + " " +
                t.plural(R.plurals.import_workflow_need_pro, limited, limited)
        }

    val summary: String
        get() {
            val parts = ArrayList<String>()
            if (rows.none { it.limited }) parts.add(t.plural(R.plurals.import_will_be_imported, importedCount, importedCount))
            if (limitNote.isNotEmpty()) parts.add(limitNote)
            val skipped = rows.count { it.decision == ImportDecision.SKIP && !it.limited }
            if (skipped > 0) parts.add(t.plural(R.plurals.import_outcome_skipped, skipped, skipped))
            return parts.joinToString(" · ")
        }

    val willImport: Int get() = importedCount

    /**
     * Applies the reviewed rows in one commit (none when nothing changes), re-checking every target and the free slots
     * against the store as it is now; a stale commit is planned again once. Call off the main thread.
     */
    fun commit(store: ItemStore): ImportOutcome = try {
        apply(store)
    } catch (e: LocalStoreException) {
        if (e.kind != LocalStoreException.Kind.STALE) throw e
        apply(store)
    }

    private fun apply(store: ItemStore): ImportOutcome {
        val snap = store.load()
        val records = LinkedHashMap(snap.records)
        val stamp = clock.now
        if (freeSlots != null) {
            val needed = rows.filter { !it.limited }.sumOf { it.newItems }
            if (needed > maxOf(0, ItemLimit.FREE_ITEMS - ItemLimit.liveCount(snap))) throw ImportReviewException(ImportReviewException.Kind.ITEM_LIMIT)
        }
        val work = snap.copy(records = records)
        var created = 0
        var updated = 0
        var skipped = 0
        var limited = 0
        for (row in rows) {
            if (row.limited) { limited++; continue }
            when (row.decision) {
                ImportDecision.SKIP -> skipped++
                ImportDecision.ADD -> {
                    if (row.kind == ImportDraft.Kind.LOGIN && match(row.origin, row.draft.username, work.copy(records = records)) != null) {
                        throw ImportReviewException(ImportReviewException.Kind.TARGET_CHANGED)
                    }
                    create(row.draft, row, records, stamp); created++
                    row.extra?.let { create(it, row, records, stamp); created++ }
                }
                ImportDecision.KEEP_BOTH -> {
                    if (row.kind == ImportDraft.Kind.LOGIN) {
                        val copy = loginAsNote(row.draft, row.sourceRow).copy(title = prefix("${row.draft.title} (imported copy)", MAX_TITLE))
                        create(copy, row, records, stamp); created++
                    } else {
                        create(row.draft, row, records, stamp); created++
                        row.extra?.let { create(it, row, records, stamp); created++ }
                    }
                }
                ImportDecision.REPLACE -> {
                    update(row, row.targetId ?: throw ImportReviewException(ImportReviewException.Kind.TARGET_CHANGED), records, snap, stamp)
                    updated++
                    if (row.kind != ImportDraft.Kind.LOGIN) row.extra?.let { create(it, row, records, stamp); created++ }
                }
            }
        }
        if (created + updated > 0) store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
        return ImportOutcome(created, updated, skipped, limited)
    }

    private fun create(d: ImportDraft, row: ImportRow, records: MutableMap<String, JsonValue>, stamp: Long) {
        val record: MutableMap<String, JsonValue>
        val ns: Namespace
        when (d.kind) {
            ImportDraft.Kind.LOGIN -> {
                record = LinkedHashMap(EditorModel.newRecord(EditorKind.WEB, stamp, random))
                record["label"] = JsonValue.Str(d.title)
                record["username"] = JsonValue.Str(d.username)
                record["password"] = JsonValue.Str(d.password)
                val scope = linkedMapOf<String, JsonValue>("origin" to JsonValue.Str(row.origin))
                val pages = webPages(d.urls, row.webUrls)
                if (row.webUrls.size > 1 || pages.isNotEmpty()) scope["urls"] = urlRows(row.webUrls, pages)
                record["scope"] = JsonValue.Obj(scope)
                if (d.notes.isNotEmpty()) record["notes"] = JsonValue.Str(d.notes)
                totpValue(d.totp)?.let { record["totp"] = it }
                if (d.customFields.isNotEmpty()) record["custom_fields"] = fieldsJson(d.customFields)
                record["tags"] = JsonValue.Arr(d.tags.map { JsonValue.Str(it) })
                record["favorite"] = JsonValue.Bool(d.favourite)
                ns = Namespace.ENTRY
            }
            else -> {
                val kind = when (d.kind) {
                    ImportDraft.Kind.CARD -> EditorKind.CARD
                    ImportDraft.Kind.IDENTITY -> EditorKind.IDENTITY
                    else -> EditorKind.NOTE
                }
                record = LinkedHashMap(EditorModel.newRecord(kind, stamp, random))
                record["title"] = JsonValue.Str(d.title)
                // The phone has no collections: the folder becomes a tag (Windows' fallback).
                val tags = if (d.folder.isNotEmpty()) cleanTags(d.tags + folderTag(d.folder)) else d.tags
                record["tags"] = JsonValue.Arr(tags.map { JsonValue.Str(it) })
                record["favorite"] = JsonValue.Bool(d.favourite)
                record["payload"] = JsonValue.Obj(payload(d))
                ns = Namespace.ITEM
            }
        }
        put(record, ns, records, isNew = true)
            ?: throw ImportReviewException(ImportReviewException.Kind.ITEM_NOT_SAVED, row.sourceRow)
    }

    private fun update(row: ImportRow, id: String, records: MutableMap<String, JsonValue>, snap: StoreSnapshot, stamp: Long) {
        if (snap.meta[id]?.deleted == true) throw ImportReviewException(ImportReviewException.Kind.TARGET_CHANGED)
        val stored = ((records[id] as? JsonValue.Obj)?.fields?.get("record") as? JsonValue.Obj)?.fields
            ?: throw ImportReviewException(ImportReviewException.Kind.TARGET_CHANGED)
        val reviewed = row.targetRecord
        if (reviewed == null || !EditorModel.same(JsonValue.Obj(stored), reviewed)) {
            throw ImportReviewException(ImportReviewException.Kind.TARGET_REVISION_CHANGED)
        }
        var rec: MutableMap<String, JsonValue> = LinkedHashMap(stored)
        val d = row.draft
        val oldTags = ((rec["tags"] as? JsonValue.Arr)?.items ?: emptyList()).mapNotNull { (it as? JsonValue.Str)?.v }
        rec["tags"] = JsonValue.Arr(cleanTags(oldTags + d.tags).map { JsonValue.Str(it) })
        rec["favorite"] = JsonValue.Bool(d.favourite || rec["favorite"] == JsonValue.Bool(true))
        val ns: Namespace
        if (row.kind == ImportDraft.Kind.LOGIN) {
            rec["label"] = JsonValue.Str(d.title)
            if ((rec["password"] as? JsonValue.Str)?.v != d.password) rec = withNewPassword(rec, d.password, stamp)
            if (d.notes.isNotEmpty()) rec["notes"] = JsonValue.Str(d.notes)
            totpValue(d.totp)?.let { rec["totp"] = it }
            if (d.customFields.isNotEmpty()) rec["custom_fields"] = fieldsJson(d.customFields)
            val scope = (rec["scope"] as? JsonValue.Obj)?.fields
            val pages = webPages(d.urls, row.webUrls)
            if ((row.webUrls.size > 1 || pages.isNotEmpty()) && scope != null) {
                // A login without rows has just its origin (desktop `web_urls` migrates it the same way).
                val existing = (scope["urls"] as? JsonValue.Arr)?.items
                    ?: (scope["origin"] as? JsonValue.Str)?.let { listOf(urlRow(it.v, "exact_origin")) } ?: emptyList()
                val added = (urlRows(row.webUrls, pages) as JsonValue.Arr).items.filter { it !in existing }
                rec["scope"] = JsonValue.Obj(LinkedHashMap(scope).apply { put("urls", JsonValue.Arr((existing + added).take(MAX_WEB_URLS))) })
            }
            ns = Namespace.ENTRY
        } else {
            rec["title"] = JsonValue.Str(d.title)
            val p = LinkedHashMap(payload(d))
            val template = ((rec["payload"] as? JsonValue.Obj)?.fields?.get("template_id"))
            if (template != null && template != JsonValue.Null) p["template_id"] = template
            rec["payload"] = JsonValue.Obj(p)
            ns = Namespace.ITEM
        }
        rec["updated_at"] = JsonValue.Int(stamp)
        put(rec, ns, records) ?: throw ImportReviewException(ImportReviewException.Kind.ITEM_NOT_SAVED, row.sourceRow)
    }

    override fun toString(): String = "ImportReview(rows=${rows.size}, freeSlots=$freeSlots)"

    companion object {
        const val MAX_WEB_URLS = 20
        const val MAX_FIELDS = 50
        const val MAX_FIELD_VALUE = 4096
        const val MAX_FIELD_NAME = 100
        const val MAX_TAGS = 20
        const val MAX_TAG_LENGTH = 40
        const val MAX_TITLE = 512
        const val MAX_NOTE_BODY = 20_000
        const val MAX_DIAGNOSTICS = 50
        const val HISTORY_LIMIT = app.localgatekeys.core.records.PasswordHistory.WRITE_LIMIT
        private val IDENTITY_LIMITS = mapOf(
            "name" to 256, "given_name" to 128, "middle_name" to 128, "family_name" to 128, "organization" to 256, "company" to 256,
            "job_title" to 160, "email" to 320, "phone" to 64, "address" to 1024, "address_line1" to 256, "address_line2" to 256,
            "city" to 128, "state" to 128, "postal_code" to 64, "country" to 128, "website" to 2048,
        )
        private const val IDENTITY_MAX_TOTAL = 8192

        /** Free slots left on the free plan (Windows `free_item_slots`); null on Pro. */
        fun freeSlots(snapshot: StoreSnapshot, isPro: Boolean): Int? =
            if (isPro) null else maxOf(0, ItemLimit.FREE_ITEMS - ItemLimit.liveCount(snapshot))

        private fun len(s: String) = s.codePointCount(0, s.length)
        fun prefix(s: String, n: Int): String = if (len(s) <= n) s else s.substring(0, s.offsetByCodePoints(0, n))
        private fun suffix(s: String, n: Int): String = if (len(s) <= n) s else s.substring(s.offsetByCodePoints(0, len(s) - n))
        private fun strip(s: String) = PyStrip.strip(s)
        /** A number as shown to the person (the locale's digit grouping). */
        private fun grouped(n: Int): String = java.text.NumberFormat.getIntegerInstance().format(n)

        fun cap(messages: List<String>, t: Txt): List<String> {
            if (messages.size <= MAX_DIAGNOSTICS) return messages
            val extra = messages.size - MAX_DIAGNOSTICS
            return messages.take(MAX_DIAGNOSTICS) + t.plural(R.plurals.import_more_messages, extra, grouped(extra))
        }

        // MARK: normalise (Windows normalise_records)

        internal fun normalise(candidates: List<ImportCandidate>, t: Txt): Pair<List<ImportRow>, List<String>> {
            val rows = ArrayList<ImportRow>()
            val issues = ArrayList<String>()
            val seen = HashMap<Pair<String, String>, Pair<Int, String>>()
            val upgradedRows = ArrayList<Int>()
            fun add(
                number: Int, d: ImportDraft, extra: ImportDraft? = null, web: List<String> = emptyList(),
                base: ImportRowStatus = ImportRowStatus.NEW, decision: ImportDecision = ImportDecision.ADD, reason: String? = null,
            ) {
                rows.add(ImportRow(rows.size, number, d, extra, web, base, decision, reason = reason))
            }
            for ((index, c) in candidates.withIndex()) {
                val number = c.sourceRow ?: (index + 1)
                var d = draft(c)
                if (hasNull(d)) {
                    val m = t.s(R.string.import_workflow_row_null_characters_in_fields, number)
                    issues.add(m); add(number, d, base = ImportRowStatus.SKIPPED_SOURCE, decision = ImportDecision.SKIP, reason = m); continue
                }
                if (d.folder.isNotEmpty()) d = d.copy(folder = stripChars(d.folder.replace('\\', '/'), "/ "))
                d = d.copy(tags = cleanTags(d.tags))
                d = fitFields(d, number, issues, t)
                when (d.kind) {
                    ImportDraft.Kind.LOGIN -> {
                        val (web, other, upgraded) = webRows(d.urls)
                        var reason = ""
                        if (web.isEmpty()) {
                            reason = t.s(if (d.urls.isEmpty()) R.string.import_workflow_row_login_has_no_website else R.string.import_workflow_row_login_has_no_usable_website, number)
                        } else if (d.password.isEmpty()) {
                            reason = t.s(R.string.import_workflow_row_login_has_no_password, number)
                        } else if (len(d.password) > 4096 || len(d.username) > 512) {
                            val m = t.s(R.string.import_workflow_row_password_or_username_is, number)
                            issues.add(m); add(number, d, base = ImportRowStatus.SKIPPED_SOURCE, decision = ImportDecision.SKIP, reason = m); continue
                        }
                        if (reason.isNotEmpty()) {
                            issues.add(reason)
                            add(number, fitNotes(loginAsNote(d, number), number, issues, t)); continue
                        }
                        if (upgraded) upgradedRows.add(number)
                        for (url in other) {
                            val host = url.split("://").last().split('/', limit = 2).first()
                            val (next, ok) = addField(d, "Other website or app", url, hidden = host.contains('@'))
                            d = next
                            if (!ok) issues.add(t.s(R.string.import_workflow_row_too_many_custom_fields, number))
                        }
                        if (d.totp.isNotEmpty() && totpValue(d.totp) == null) {
                            issues.add(t.s(R.string.import_workflow_row_one_time_password_secret, number))
                            d = addField(d, "One-time password (unrecognised)", d.totp, hidden = true).first.copy(totp = "")
                        }
                        val tag = folderTag(d.folder)
                        if (tag.isNotEmpty()) d = d.copy(tags = cleanTags(d.tags + tag))
                        d = fitNotes(d, number, issues, t)
                        d = d.copy(title = title(d, number, web[0]))
                        val key = web[0] to d.username
                        val first = seen[key]
                        if (first != null) {
                            if (first.second == d.password) {
                                issues.add(t.s(R.string.import_workflow_row_same_account_as_row, number, first.first))
                                add(number, d, web = web, base = ImportRowStatus.DUPLICATE, decision = ImportDecision.SKIP)
                            } else {
                                issues.add(t.s(R.string.import_workflow_row_same_website_and_username, number, first.first))
                                add(number, d, web = web, base = ImportRowStatus.DUPLICATE, decision = ImportDecision.KEEP_BOTH)
                            }
                        } else {
                            seen[key] = number to d.password
                            add(number, d, web = web)
                        }
                    }
                    ImportDraft.Kind.CARD -> {
                        if (d.card.isNotEmpty()) {
                            val problem = cardProblem(d, t)
                            if (problem != null) {
                                issues.add(t.s(R.string.import_workflow_row_card_details_could_not, number, problem))
                                add(number, fitNotes(cardAsNote(d, number), number, issues, t)); continue
                            }
                            d = d.copy(title = title(d, number))
                            val extra = companion(d, d.title, d.customFields)
                            add(number, d.copy(customFields = emptyList()), extra = extra?.let { fitFields(it, number, issues, t) }); continue
                        }
                        var note = fitNotes(cardAsNote(d, number), number, issues, t)
                        note = note.copy(title = title(note, number))
                        add(number, fitFields(note, number, issues, t))
                    }
                    ImportDraft.Kind.IDENTITY -> {
                        val extraFields = ArrayList<ImportCustomField>()
                        val kept = LinkedHashMap<String, String>()
                        var total = 0
                        for (name in d.identity.keys.sorted()) {
                            val value = d.identity[name]!!
                            val limit = IDENTITY_LIMITS[name]
                            if (limit == null || len(value) > limit || total + len(value) > IDENTITY_MAX_TOTAL) {
                                extraFields.add(ImportCustomField(capitalize(name.replace('_', ' ')), prefix(value, MAX_FIELD_VALUE), false))
                                continue
                            }
                            kept[name] = value; total += len(value)
                        }
                        if (extraFields.isNotEmpty()) {
                            val names = extraFields.map { Casefold.fold(it.name) }.toSortedSet().joinToString(", ")
                            issues.add(t.s(R.string.import_workflow_row_identity_values_without_a, number, names))
                        }
                        d = d.copy(identity = kept)
                        d = d.copy(title = title(d, number))
                        var extra = companion(d, d.title, extraFields + d.customFields, notes = d.notes)
                        if (extra != null) extra = fitNotes(extra, number, issues, t)
                        add(number, d, extra = extra?.let { fitFields(it, number, issues, t) })
                    }
                    ImportDraft.Kind.NOTE -> {
                        d = fitNotes(d, number, issues, t)
                        d = d.copy(title = title(d, number))
                        add(number, fitFields(d, number, issues, t))
                    }
                }
            }
            if (upgradedRows.isNotEmpty()) {
                val shown = upgradedRows.take(10).joinToString(", ") + if (upgradedRows.size > 10) " ..." else ""
                issues.add(t.plural(R.plurals.import_issue_http_upgraded, upgradedRows.size, upgradedRows.size, shown))
            }
            return rows to issues
        }

        private fun capitalize(s: String): String = if (s.isEmpty()) s else s.substring(0, 1).uppercase() + s.substring(1).lowercase()

        private fun stripChars(s: String, chars: String): String = s.trim { it in chars }

        /** The candidate as a Windows `ImportedRecord`; a non-login's 2FA key becomes a hidden custom field. */
        internal fun draft(c: ImportCandidate): ImportDraft {
            val kind = when (c.kind) {
                ImportCandidate.Kind.LOGIN -> ImportDraft.Kind.LOGIN
                ImportCandidate.Kind.NOTE -> ImportDraft.Kind.NOTE
                ImportCandidate.Kind.CARD -> ImportDraft.Kind.CARD
                ImportCandidate.Kind.IDENTITY -> ImportDraft.Kind.IDENTITY
            }
            var d = ImportDraft(
                kind, title = c.title, username = c.username, password = c.password, notes = c.notes,
                totp = if (kind == ImportDraft.Kind.LOGIN) c.totp else "", urls = c.urls, customFields = c.customFields,
                tags = c.tags, folder = c.folder, favourite = c.favourite, identity = c.identity, card = c.card,
            )
            if (kind != ImportDraft.Kind.LOGIN && c.totp.isNotEmpty()) d = addField(d, "One-time password (otpauth)", c.totp, hidden = true).first
            return d
        }

        /** Windows `_keep_totp_as_fields`: on the free plan a login's two-factor key becomes a hidden custom field. */
        internal fun keepTotpAsFields(rows: MutableList<ImportRow>, t: Txt): List<String> {
            var kept = 0
            for (i in rows.indices) {
                val r = rows[i]
                if (r.kind != ImportDraft.Kind.LOGIN || r.draft.totp.isEmpty()) continue
                val (d, ok) = addField(r.draft, "Two-factor key (needs Pro)", r.draft.totp, hidden = true)
                if (ok) { rows[i] = r.copy(draft = d.copy(totp = "")); kept++ }
            }
            if (kept == 0) return emptyList()
            return listOf(t.plural(R.plurals.import_issue_totp_kept, kept, kept))
        }

        // MARK: classify (Windows classify_rows)

        internal fun classify(rows: MutableList<ImportRow>, snap: StoreSnapshot) {
            val logins = HashMap<Pair<String, String>, Pair<String, Map<String, JsonValue>>>()
            val catalog = HashMap<String, Pair<String, Map<String, JsonValue>>>()
            for (id in snap.records.keys.sorted()) {
                if (snap.meta[id]?.deleted == true) continue
                val w = (snap.records[id] as? JsonValue.Obj)?.fields ?: continue
                val r = (w["record"] as? JsonValue.Obj)?.fields ?: continue
                val ns = (w["ns"] as? JsonValue.Str)?.v
                if (ns == Namespace.ENTRY.wire && r["kind"] == JsonValue.Str("web")) {
                    val raw = ((r["scope"] as? JsonValue.Obj)?.fields?.get("origin") as? JsonValue.Str)?.v ?: continue
                    val origin = try { Origin.canonicalize(raw) } catch (e: Exception) { continue }
                    val key = origin to ((r["username"] as? JsonValue.Str)?.v ?: "")
                    if (key !in logins) logins[key] = id to r
                } else if (ns == Namespace.ITEM.wire) {
                    val kind = (r["kind"] as? JsonValue.Str)?.v ?: continue
                    val key = kind + "\u0000" + Casefold.fold((r["title"] as? JsonValue.Str)?.v ?: "")
                    if (key !in catalog) catalog[key] = id to r
                }
            }
            for (i in rows.indices) {
                val row = rows[i]
                if (row.base == ImportRowStatus.SKIPPED_SOURCE) continue
                if (row.inImportDuplicate) {
                    // A copy kept by an earlier run of the same import is not made again.
                    if (row.decision == ImportDecision.KEEP_BOTH && row.kind == ImportDraft.Kind.LOGIN) {
                        val copy = loginAsNote(row.draft, row.sourceRow).copy(title = prefix("${row.draft.title} (imported copy)", MAX_TITLE))
                        val existing = catalog["note\u0000" + Casefold.fold(copy.title)]
                        if (existing != null && sameItem(existing.second, copy)) rows[i] = row.copy(decision = ImportDecision.SKIP)
                    }
                    continue
                }
                val target: Pair<String, Map<String, JsonValue>>
                val same: Boolean
                if (row.kind == ImportDraft.Kind.LOGIN) {
                    target = logins[row.origin to row.draft.username] ?: continue
                    same = (target.second["password"] as? JsonValue.Str)?.v == row.draft.password
                } else {
                    target = catalog[row.kind.raw + "\u0000" + Casefold.fold(row.title)] ?: continue
                    same = sameItem(target.second, row.draft)
                }
                rows[i] = row.copy(
                    targetId = target.first, targetRecord = JsonValue.Obj(target.second),
                    base = if (same) ImportRowStatus.DUPLICATE else ImportRowStatus.CONFLICT, decision = ImportDecision.SKIP,
                )
            }
        }

        private fun sameItem(stored: Map<String, JsonValue>, d: ImportDraft): Boolean {
            val p = (stored["payload"] as? JsonValue.Obj)?.fields ?: emptyMap()
            return when (d.kind) {
                ImportDraft.Kind.NOTE ->
                    ((p["body"] as? JsonValue.Str)?.v ?: "") == d.notes && (p["fields"] ?: JsonValue.Arr(emptyList())) == fieldsJson(d.customFields)
                ImportDraft.Kind.CARD -> {
                    val wanted = normalisedCard(d) ?: emptyMap()
                    listOf("number", "expiry", "cardholder").all { (p[it] ?: JsonValue.Str("")) == (wanted[it] ?: JsonValue.Str("")) }
                }
                ImportDraft.Kind.IDENTITY -> (p - "template_id") == d.identity.mapValues { JsonValue.Str(it.value) }
                ImportDraft.Kind.LOGIN -> false
            }
        }

        // MARK: Windows helpers

        /** Windows `_web_url`: (canonical origin, upgraded from http), or null when the text is not a website. */
        internal fun webUrl(value: String): Pair<String, Boolean>? {
            var text = strip(value)
            if (text.isEmpty() || text.codePoints().anyMatch { PyStrip.isSpace(it) } || len(text) > 2048) return null
            if (!text.contains("://")) {
                val host = text.split('/', limit = 2).first()
                if (!host.contains('.') || host.startsWith(".") || host.contains('@')) return null
                text = "https://$text"
            }
            val sep = text.indexOf("://")
            if (sep < 0) return null
            val scheme = text.substring(0, sep).lowercase()
            val rest = text.substring(sep + 3)
            val netloc = rest.takeWhile { it != '/' && it != '?' && it != '#' }
            if (netloc.contains('@')) return null
            var host = netloc.lowercase()
            val close = host.indexOf(']')
            if (host.startsWith("[") && close > 0) host = host.substring(1, close) else if (host.contains(':')) host = host.substring(0, host.indexOf(':'))
            var upgraded = false
            if (scheme == "http" && host !in setOf("localhost", "127.0.0.1", "::1")) { text = "https://$rest"; upgraded = true }
            val origin = try {
                Origin.canonicalize(Origin.originOf(text))
            } catch (e: Exception) {
                return null
            }
            return origin to upgraded
        }

        /** Windows `_web_rows`: (website origins, at most 20; other addresses; any upgraded). */
        internal fun webRows(urls: List<String>): Triple<List<String>, List<String>, Boolean> {
            val rows = ArrayList<String>()
            val other = ArrayList<String>()
            var upgradedAny = false
            for (url in urls) {
                val w = webUrl(url)
                if (w == null) { other.add(url); continue }
                upgradedAny = upgradedAny || w.second
                if (w.first !in rows) rows.add(w.first)
            }
            if (rows.size > MAX_WEB_URLS) { other.addAll(rows.subList(MAX_WEB_URLS, rows.size)); return Triple(rows.take(MAX_WEB_URLS), other, upgradedAny) }
            return Triple(rows, other, upgradedAny)
        }

        /**
         * Windows `_web_page` (2026-10-29): the full page address of a website URL whose origin is [origin], or null
         * when it is just the site. Same upgrade rules as [webUrl]; `normalize_url` form (no fragment).
         */
        internal fun webPage(value: String, origin: String): String? {
            var text = strip(value)
            if (!text.contains("://")) text = "https://$text"
            if (text.length >= 7 && text.substring(0, 7).lowercase() == "http://" && !origin.startsWith("http://")) {
                text = "https://" + text.substring(7)
            }
            val page = try {
                Origin.normalizeUrl(text).takeIf { Origin.canonicalize(Origin.originOf(it)) == origin }
            } catch (e: Exception) {
                null
            } ?: return null
            return if (page == origin || page == "$origin/") null else page
        }

        /**
         * Windows `_web_rows` page rows: the full addresses of [urls] (deduplicated) on one of [origins]. They are
         * stored as `starts_with` rows after the exact-origin rows, so they match only pages those rows already match.
         */
        internal fun webPages(urls: List<String>, origins: List<String>): List<String> {
            val out = ArrayList<String>()
            for (url in urls) {
                val origin = webUrl(url)?.first ?: continue
                if (origin !in origins) continue
                val page = webPage(url, origin) ?: continue
                if (page !in out) out.add(page)
            }
            return out
        }

        private fun urlRow(url: String, match: String): JsonValue =
            JsonValue.Obj(linkedMapOf("url" to JsonValue.Str(url), "match" to JsonValue.Str(match)))

        internal fun urlRows(origins: List<String>, pages: List<String> = emptyList()): JsonValue =
            JsonValue.Arr(
                (origins.map { urlRow(it, "exact_origin") } + pages.map { urlRow(it, "starts_with") }).take(MAX_WEB_URLS),
            )

        /** Windows `_add_field`: the draft, and false when the field did not fit whole. */
        internal fun addField(d: ImportDraft, name: String, value: String, hidden: Boolean): Pair<ImportDraft, Boolean> {
            if (value.isEmpty()) return d to true
            if (d.customFields.size >= MAX_FIELDS) return d to false
            val f = ImportCustomField(prefix(name, MAX_FIELD_NAME), prefix(value, MAX_FIELD_VALUE), hidden)
            return d.copy(customFields = d.customFields + f) to (len(value) <= MAX_FIELD_VALUE)
        }

        /** Windows `_fit_notes`: notes past the vault limit move into "Notes (continued N)" fields. */
        internal fun fitNotes(d: ImportDraft, number: Int, issues: MutableList<String>, t: Txt, limit: Int = MAX_NOTE_BODY): ImportDraft {
            if (len(d.notes) <= limit) return d
            var overflow = d.notes.substring(d.notes.offsetByCodePoints(0, limit))
            val fields = d.customFields.toMutableList()
            var part = 1
            while (overflow.isNotEmpty() && fields.size < MAX_FIELDS) {
                fields.add(ImportCustomField("Notes (continued $part)", prefix(overflow, MAX_FIELD_VALUE), false))
                overflow = if (len(overflow) <= MAX_FIELD_VALUE) "" else overflow.substring(overflow.offsetByCodePoints(0, MAX_FIELD_VALUE))
                part++
            }
            if (overflow.isNotEmpty()) {
                issues.add(t.plural(R.plurals.import_issue_notes_overflow, len(overflow), number, len(overflow)))
            }
            return d.copy(notes = prefix(d.notes, limit), customFields = fields)
        }

        /** Windows `_fit_fields`: at most 50 fields, 100-character names, 4,096-character values. */
        internal fun fitFields(d: ImportDraft, number: Int, issues: MutableList<String>, t: Txt): ImportDraft =
            d.copy(
                customFields = d.customFields.take(MAX_FIELDS).map { f ->
                    val name = prefix(f.name, MAX_FIELD_NAME)
                    var value = f.value
                    if (len(value) > MAX_FIELD_VALUE) {
                        issues.add(t.plural(R.plurals.import_issue_field_shortened, MAX_FIELD_VALUE, number, name, MAX_FIELD_VALUE))
                        value = prefix(value, MAX_FIELD_VALUE)
                    }
                    ImportCustomField(name, value, f.hidden)
                },
            )

        private fun hasNull(d: ImportDraft): Boolean {
            val values = listOf(d.title, d.username, d.password, d.notes, d.totp, d.folder) + d.urls + d.identity.values + d.card.values +
                d.customFields.flatMap { listOf(it.name, it.value) }
            return values.any { it.contains('\u0000') }
        }

        /** Windows `_folder_tag`: "Work / Sub", the last 40 characters. */
        internal fun folderTag(folder: String): String {
            val text = folder.replace('\\', '/').split('/').map { strip(it) }.filter { it.isNotEmpty() }.joinToString(" / ")
            return strip(suffix(text, MAX_TAG_LENGTH))
        }

        /** Windows `_clean_tags`: stripped, 40 characters, no repeats, at most 20. */
        internal fun cleanTags(tags: List<String>): List<String> {
            val out = ArrayList<String>()
            for (tag in tags) {
                val text = prefix(strip(tag), MAX_TAG_LENGTH)
                if (text.isNotEmpty() && text !in out) out.add(text)
            }
            return out.take(MAX_TAGS)
        }

        /** Windows `_title`: the title, else the fallback, username or first address, at most 512 characters. */
        internal fun title(d: ImportDraft, number: Int, fallback: String = ""): String {
            val raw = listOf(d.title, fallback, d.username, d.urls.firstOrNull() ?: "").firstOrNull { it.isNotEmpty() } ?: "Imported row $number"
            val text = prefix(strip(raw), MAX_TITLE)
            return text.ifEmpty { "Imported row $number" }
        }

        /** The vault `totp` object for an `otpauth://` URI, or null when it is not valid (Windows `totp_dict`). */
        internal fun totpValue(uri: String): JsonValue? {
            if (uri.isEmpty()) return null
            val c = try {
                Totp.parseOtpauthUri(uri)
            } catch (e: Exception) {
                return null
            }
            return JsonValue.Obj(
                linkedMapOf(
                    "secret" to JsonValue.Str(c.secret), "algorithm" to JsonValue.Str(c.algorithm),
                    "digits" to JsonValue.Int(c.digits.toLong()), "period" to JsonValue.Int(c.period.toLong()),
                ),
            )
        }

        private fun fieldsJson(fields: List<ImportCustomField>): JsonValue = JsonValue.Arr(
            fields.map {
                JsonValue.Obj(linkedMapOf("name" to JsonValue.Str(it.name), "value" to JsonValue.Str(it.value), "hidden" to JsonValue.Bool(it.hidden)))
            },
        )

        /** Windows `_login_as_note`: a secure note keeping every value of a login. */
        internal fun loginAsNote(d: ImportDraft, number: Int): ImportDraft {
            val fields = ArrayList<ImportCustomField>()
            for ((i, url) in d.urls.withIndex()) fields.add(ImportCustomField(if (i == 0) "Website" else "Website ${i + 1}", prefix(url, MAX_FIELD_VALUE), false))
            if (d.username.isNotEmpty()) fields.add(ImportCustomField("Username", prefix(d.username, MAX_FIELD_VALUE), false))
            if (d.password.isNotEmpty()) fields.add(ImportCustomField("Password", prefix(d.password, MAX_FIELD_VALUE), true))
            if (d.totp.isNotEmpty()) fields.add(ImportCustomField("One-time password (otpauth)", prefix(d.totp, MAX_FIELD_VALUE), true))
            fields.addAll(d.customFields)
            return ImportDraft(
                ImportDraft.Kind.NOTE, title = title(d, number), notes = d.notes, customFields = fields.take(MAX_FIELDS),
                tags = d.tags, folder = d.folder, favourite = d.favourite,
            )
        }

        /** Windows `_card_as_note`. */
        private fun cardAsNote(d: ImportDraft, number: Int): ImportDraft {
            val labels = listOf(
                Triple("cardholder", "Cardholder", false), Triple("number", "Card number", true), Triple("expiry", "Expiry", false),
                Triple("cvv", "Security code", true), Triple("pin", "PIN", true), Triple("brand", "Brand", false),
            )
            val fields = labels.mapNotNull { (key, label, hidden) -> d.card[key]?.takeIf { it.isNotEmpty() }?.let { ImportCustomField(label, it, hidden) } } +
                d.customFields
            return ImportDraft(
                ImportDraft.Kind.NOTE, title = title(d, number), notes = d.notes, customFields = fields.take(MAX_FIELDS),
                tags = d.tags, folder = d.folder, favourite = d.favourite,
            )
        }

        /** Windows `_companion`: the "extra details" note for values a card or identity cannot hold. */
        private fun companion(d: ImportDraft, title: String, fields: List<ImportCustomField>, notes: String = ""): ImportDraft? {
            if (fields.isEmpty() && notes.isEmpty()) return null
            return ImportDraft(
                ImportDraft.Kind.NOTE, title = prefix("$title (extra details)", MAX_TITLE), notes = notes,
                customFields = fields.take(MAX_FIELDS), tags = d.tags, folder = d.folder,
            )
        }

        /** Windows `card_payload` before validation: a `MM/20YY` expiry becomes `MM/YY`. */
        private fun cardFields(d: ImportDraft): Map<String, JsonValue> {
            var expiry = d.card["expiry"] ?: ""
            val parts = expiry.split('/', limit = 2)
            if (parts.size == 2 && parts[1].length == 4 && parts[1].startsWith("20")) expiry = parts[0] + "/" + parts[1].substring(2)
            return linkedMapOf(
                "cardholder" to JsonValue.Str(d.card["cardholder"] ?: ""), "number" to JsonValue.Str(d.card["number"] ?: ""),
                "expiry" to JsonValue.Str(expiry), "cvv" to JsonValue.Str(d.card["cvv"] ?: ""), "pin" to JsonValue.Str(d.card["pin"] ?: ""),
                "notes" to JsonValue.Str(d.notes),
            )
        }

        private fun probeCard(d: ImportDraft): JsonValue = Normalise.normalForm(
            Namespace.ITEM,
            JsonValue.Obj(
                linkedMapOf(
                    "id" to JsonValue.Str("00000000-0000-4000-8000-000000000000"), "kind" to JsonValue.Str("card"),
                    "title" to JsonValue.Str("card"), "created_at" to JsonValue.Int(0), "updated_at" to JsonValue.Int(0),
                    "payload" to JsonValue.Obj(cardFields(d)),
                ),
            ),
        )

        private fun normalisedCard(d: ImportDraft): Map<String, JsonValue>? = try {
            ((probeCard(d) as? JsonValue.Obj)?.fields?.get("payload") as? JsonValue.Obj)?.fields
        } catch (e: Exception) {
            null
        }

        private fun cardProblem(d: ImportDraft, t: Txt): String? = try {
            probeCard(d)
            null
        } catch (e: NormaliseException) {
            if (e.kind == NormaliseException.Kind.REJECTED) e.detail else e.kind.name
        } catch (e: Exception) {
            t.s(R.string.import_card_unreadable)
        }

        private fun payload(d: ImportDraft): Map<String, JsonValue> = when (d.kind) {
            ImportDraft.Kind.CARD -> cardFields(d)
            ImportDraft.Kind.IDENTITY -> d.identity.mapValues { JsonValue.Str(it.value) }
            else -> linkedMapOf("body" to JsonValue.Str(d.notes), "fields" to fieldsJson(d.customFields))
        }

        /** The live web login with this canonical origin and exactly this username (desktop `_web_login_match`). */
        fun match(origin: String, username: String, snapshot: StoreSnapshot): String? {
            for (id in snapshot.records.keys.sorted()) {
                if (snapshot.meta[id]?.deleted == true) continue
                val w = (snapshot.records[id] as? JsonValue.Obj)?.fields ?: continue
                if (w["ns"] != JsonValue.Str(Namespace.ENTRY.wire)) continue
                val r = (w["record"] as? JsonValue.Obj)?.fields ?: continue
                if (r["kind"] != JsonValue.Str("web")) continue
                val raw = ((r["scope"] as? JsonValue.Obj)?.fields?.get("origin") as? JsonValue.Str)?.v ?: continue
                val canonical = try { Origin.canonicalize(raw) } catch (e: Exception) { continue }
                if (canonical == origin && (r["username"] as? JsonValue.Str)?.v == username) return id
            }
            return null
        }

        /** [stored] with [password] replaced; the old one goes to the front of `password_history` (at most [HISTORY_LIMIT]). */
        fun withNewPassword(stored: Map<String, JsonValue>, password: String, now: Long): MutableMap<String, JsonValue> {
            val record = LinkedHashMap(stored)
            val history = ((record["password_history"] as? JsonValue.Arr)?.items ?: emptyList()).toMutableList()
            history.add(
                0,
                JsonValue.Obj(linkedMapOf("password" to (stored["password"] as? JsonValue.Str ?: JsonValue.Str("")), "changed_at" to JsonValue.Int(now))),
            )
            record["password_history"] = JsonValue.Arr(history.take(HISTORY_LIMIT))
            record["password"] = JsonValue.Str(password)
            record["updated_at"] = JsonValue.Int(now)
            val created = record["created_at"]
            if (created is JsonValue.Int && created.v > now) record["created_at"] = JsonValue.Int(now)
            return record
        }

        /** Normalises and wraps the record as the editor does; the record id, or null when refused or a new id collides. */
        private fun put(record: Map<String, JsonValue>, ns: Namespace, records: MutableMap<String, JsonValue>, isNew: Boolean = false): String? {
            val normal = try {
                Normalise.normalForm(ns, JsonValue.Obj(record))
            } catch (e: Exception) {
                return null
            }
            val id = ((normal as? JsonValue.Obj)?.fields?.get("id") as? JsonValue.Str)?.v ?: return null
            if (isNew && records[id] != null) return null
            records[id] = Wrapper.make(ns, normal)
            return id
        }
    }
}
