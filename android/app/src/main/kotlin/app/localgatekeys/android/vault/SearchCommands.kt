package app.localgatekeys.android.vault

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.editor.EditorKind

/**
 * UX plan 2026-10-27 workstream 5: the vault search doubles as the command palette. A query that starts with `>`
 * lists actions instead of items; the words after it narrow the list (every word must appear in the title or the
 * keywords, case-insensitive). Android has no Security or Trash screens, so those commands are not offered here.
 */
sealed class SearchCommand(@StringRes val titleRes: Int, val keywords: String) {
    /** The command's name in the person's language. [keywords] stay English as well: they are search terms, not shown. */
    fun title(t: Txt): String = t.s(titleRes)

    data class NewItem(val kind: EditorKind) : SearchCommand(kind.newTitle, "new add create item ${kind.raw}")
    data object GeneratePassword : SearchCommand(R.string.command_generate_password_title, "generator passphrase random")
    data object ScanQr : SearchCommand(R.string.cmd_scan_qr, "scan qr camera pair sync pc")
    data object Lock : SearchCommand(R.string.topbar_lock, "lock vault close")
    data object SyncNow : SearchCommand(R.string.sync_status_page_sync_now, "sync refresh pc")
    data object SyncStatus : SearchCommand(R.string.command_sync_status_title, "sync devices status")
    data object Settings : SearchCommand(R.string.command_settings_title, "settings preferences options")
    data object Import : SearchCommand(R.string.cmd_import, "settings import csv bitwarden 1password keepass")
    data object ExportBackup : SearchCommand(R.string.cmd_export_backup, "settings backup export save")
    data object RestoreBackup : SearchCommand(R.string.recovery_page_restore_title, "settings backup restore")
    data object ReceiveShare : SearchCommand(R.string.cmd_receive_share, "settings share incoming lgkshare")
    data object ShowSetup : SearchCommand(R.string.settings_setup_title, "settings setup onboarding")

    override fun toString(): String = "SearchCommand(${javaClass.simpleName})"

    companion object {
        const val PREFIX = '>'

        /** Every command in palette order; RootScaffold offers the ones its seams can run. */
        val all: List<SearchCommand> =
            EditorKind.entries.map { NewItem(it) } + listOf(
                GeneratePassword, ScanQr, Lock, SyncNow, SyncStatus, Settings, Import, ExportBackup, RestoreBackup,
                ReceiveShare, ShowSetup,
            )

        /** True when [query] is a command query (leading spaces allowed). */
        fun isCommandQuery(query: String): Boolean = query.trimStart().startsWith(PREFIX)

        /**
         * The commands of [available] that match [query], in [available]'s order; null when [query] is not a command
         * query (the item search applies). A bare `>` lists them all.
         */
        fun parse(query: String, t: Txt, available: List<SearchCommand> = all): List<SearchCommand>? {
            if (!isCommandQuery(query)) return null
            val words = query.trimStart().drop(1).lowercase().split(' ', '\t').filter { it.isNotEmpty() }
            return available.filter { c ->
                val hay = "${c.title(t)} ${c.keywords}".lowercase()
                words.all { hay.contains(it) }
            }
        }
    }
}

/** Ctrl+K on a hardware keyboard opens the vault search (workstream 5). */
object SearchShortcut {
    /** Android's `KeyEvent.KEYCODE_K` and `ACTION_DOWN` (kept as numbers so this stays a plain unit). */
    const val KEYCODE_K = 39
    const val ACTION_DOWN = 0

    fun matches(keyCode: Int, action: Int, ctrl: Boolean, alt: Boolean, shift: Boolean, repeat: Int): Boolean =
        keyCode == KEYCODE_K && action == ACTION_DOWN && ctrl && !alt && !shift && repeat == 0
}
