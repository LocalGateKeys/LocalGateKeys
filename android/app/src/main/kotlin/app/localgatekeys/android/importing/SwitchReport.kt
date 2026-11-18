package app.localgatekeys.android.importing

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.json.JsonValue

/**
 * The switch report after an import (feature pack contract 2026-11-15 section 6.1, scan A-L12), a port of Windows
 * `import_report.build_report`: what landed per item kind, counted from the records the import's own commit wrote
 * (never from the parsed file, so it can never claim more than arrived), existing items updated, passkeys imported vs
 * skipped, custom fields kept, duplicates found, and by name what was not brought over and why. [toString] shows counts
 * only (no names).
 */
data class SwitchReport(
    /** Rows the file gave: reviewed rows plus rows it could not provide (Windows `total`). */
    val total: Int,
    /** Reviewed rows that were written (Windows `written`: rows, not records). */
    val written: Int,
    /** New items, the sum of [kinds]. */
    val added: Int,
    /** Rows that changed an existing item (Windows `max(0, written - added)`). */
    val updated: Int,
    /** New items per stored kind (`web` for logins, `passkey` on its own), ordered by kind. */
    val kinds: List<KindCount>,
    val passkeys: Passkeys,
    /** Custom fields on the rows that were written. */
    val fieldsKept: Int,
    /** Rows that were already in the vault with the same data. */
    val duplicates: Int,
    /** Reviewed rows not brought over, by name, with the reason. */
    val notCarried: List<NotCarried>,
    /** Rows the file could not provide (listed by their messages in the review's notes). */
    val unreadableRows: Int,
) {
    data class KindCount(val kind: String, val count: Int)

    data class Passkeys(val total: Int, val imported: Int, val skipped: Int)

    /** [name] is the row's title or address ("" when it has neither). */
    data class NotCarried(val row: Int, val name: String, val reason: SkipReason) {
        override fun toString(): String = "NotCarried(row=$row, reason=$reason)"
    }

    /** Windows `_skip_reason` (the `switchReport.reason*` texts). */
    enum class SkipReason(val code: String) {
        NEEDS_PRO("needs_pro"),
        DUPLICATE("duplicate"),
        SKIPPED("skipped"),
        UNREADABLE("unreadable"),
    }

    val skipped: Int get() = notCarried.size + unreadableRows

    override fun toString(): String =
        "SwitchReport(total=$total, written=$written, added=$added, updated=$updated, kinds=$kinds, skipped=$skipped)"

    /** "Imported 6 of 7." or "Imported 6 of 7, 1 skipped (already in the vault: 1)." (Windows `toast_text`). */
    fun summary(t: Txt): String {
        if (skipped == 0) return t.s(R.string.import_report_toast_all, written, total)
        // Reasons by count, most first; equal counts keep the order they first appear in (Python's stable sort).
        val counts = LinkedHashMap<SkipReason, Int>()
        for (row in notCarried) counts[row.reason] = (counts[row.reason] ?: 0) + 1
        val why = counts.entries.sortedByDescending { it.value }.joinToString(", ") { "${reasonText(it.key, t)}: ${it.value}" }
        return t.s(R.string.import_report_toast_skipped, written, total, skipped, why.ifEmpty { reasonText(SkipReason.UNREADABLE, t) })
    }

    companion object {
        /** The stored kind of an import row (Windows `_ROW_KIND`: a login is `web`). */
        fun kindOf(k: ImportDraft.Kind): String = if (k == ImportDraft.Kind.LOGIN) "web" else k.raw

        /** Taken = written (Windows `RowFacts.taken`): not skipped and not held back by the free plan. */
        fun taken(r: ImportRow): Boolean = r.decision != ImportDecision.SKIP && !r.limited

        fun reason(r: ImportRow): SkipReason = when {
            r.limited -> SkipReason.NEEDS_PRO
            r.base == ImportRowStatus.DUPLICATE -> SkipReason.DUPLICATE
            else -> SkipReason.SKIPPED
        }

        @androidx.annotation.StringRes
        fun reasonRes(reason: SkipReason): Int = when (reason) {
            SkipReason.NEEDS_PRO -> R.string.import_report_reason_needs_pro
            SkipReason.DUPLICATE -> R.string.import_report_reason_duplicate
            SkipReason.SKIPPED -> R.string.import_report_reason_skipped
            SkipReason.UNREADABLE -> R.string.import_report_reason_unreadable
        }

        fun reasonText(reason: SkipReason, t: Txt): String = t.s(reasonRes(reason))

        /** "2 logins", "1 passkey" (`import.reportCount`). */
        fun countLine(c: KindCount, t: Txt): String = t.plural(
            when (c.kind) {
                "web", "desktop" -> R.plurals.import_report_count_logins
                "passkey" -> R.plurals.import_report_count_passkeys
                "note" -> R.plurals.import_report_count_notes
                "card" -> R.plurals.import_report_count_cards
                "identity" -> R.plurals.import_report_count_identities
                else -> R.plurals.import_report_count_items
            },
            c.count, c.count,
        )

        /**
         * The report of an import whose review had [rows] and whose commit turned [before] into [after] (id -> live
         * record, read back from that commit). New ids are counted by their committed `kind`.
         */
        fun build(rows: List<ImportRow>, before: Map<String, Map<String, JsonValue>>, after: Map<String, Map<String, JsonValue>>): SwitchReport {
            val facts = rows.filter { it.base != ImportRowStatus.SKIPPED_SOURCE }
            // Windows `skipped_rows`: source rows the file could not give. That is a row the review dropped (it has a row
            // number) or a reader message that ends in "skipped." ("Item 7: in the Bitwarden trash; skipped."); other
            // reader messages are notes about the file ("Bitwarden does not export passkeys ..."), listed in the notes only.
            val unreadable = rows.count {
                it.base == ImportRowStatus.SKIPPED_SOURCE && (it.sourceRow > 0 || it.reason.orEmpty().trimEnd().endsWith("skipped."))
            }
            // Windows `landed`: ids present after the import and not before it, per kind.
            val arrived = LinkedHashMap<String, Int>()
            for ((id, rec) in after) {
                if (id in before) continue
                val kind = (rec["kind"] as? JsonValue.Str)?.v ?: continue
                arrived[kind] = (arrived[kind] ?: 0) + 1
            }
            val kinds = arrived.entries.filter { it.value > 0 }.sortedBy { it.key }.map { KindCount(it.key, it.value) }
            val added = kinds.sumOf { it.count }
            val taken = facts.filter(::taken)
            val written = taken.size
            val passkeyRows = facts.filter { it.kind == ImportDraft.Kind.PASSKEY }
            val passkeysIn = minOf(arrived["passkey"] ?: 0, passkeyRows.count(::taken))
            val passkeysUpdated = passkeyRows.count { taken(it) && it.decision == ImportDecision.REPLACE }
            return SwitchReport(
                total = facts.size + unreadable,
                written = written,
                added = added,
                updated = maxOf(0, written - added),
                kinds = kinds,
                passkeys = Passkeys(passkeyRows.size, passkeysIn + passkeysUpdated, maxOf(0, passkeyRows.size - passkeysIn - passkeysUpdated)),
                fieldsKept = taken.sumOf { it.draft.customFields.size },
                duplicates = facts.count { it.base == ImportRowStatus.DUPLICATE },
                notCarried = facts.filterNot(::taken).map { NotCarried(it.sourceRow, it.title.ifEmpty { it.origin }, reason(it)) },
                unreadableRows = unreadable,
            )
        }
    }
}
