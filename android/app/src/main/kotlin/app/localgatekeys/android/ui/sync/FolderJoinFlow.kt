package app.localgatekeys.android.ui.sync

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncWording
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** What the system folder picker handed back. */
sealed interface FolderPick {
    /** [uri]: the picked tree URI, its read and write permission already persisted. */
    class Picked(val uri: String) : FolderPick {
        /** The URI names the person's folders: never shown. */
        override fun toString(): String = "Picked"
    }

    /** The person closed the picker. */
    data object Cancelled : FolderPick

    /** No picker could open, or the picked folder's permission could not be kept. */
    data object Failed : FolderPick
}

/**
 * The system folder picker. [pick] opens it (ignored while one is already open). Its outcomes arrive on [results],
 * buffered until collected, so a pick that comes back after the activity was recreated still reaches the screen (the
 * URI itself is never put in saved state).
 */
interface FolderPicking {
    fun pick()

    val results: Flow<FolderPick>
}

/** What a picker result becomes (pure, so the lock rule is tested on the JVM). */
object FolderPickResults {
    /**
     * [stillUnlocked] false (the vault locked during the trip, Ruling 21): the pick is dropped, nothing is persisted
     * (null). No [uri]: cancelled. Otherwise the folder's permission is persisted ([persist]); a failure there is Failed.
     */
    fun <U : Any> decide(uri: U?, stillUnlocked: Boolean, persist: (U) -> String): FolderPick? = when {
        !stillUnlocked -> null
        uri == null -> FolderPick.Cancelled
        else -> try {
            FolderPick.Picked(persist(uri))
        } catch (e: Exception) {
            FolderPick.Failed
        }
    }
}

/**
 * The password sheet's state for one picked folder. The password lives only here, in memory, until [take] hands it to
 * the join (it is never saved, not even across rotation); toString shows neither it nor the folder.
 */
class FolderPasswordForm(
    val uri: String,
    val creating: Boolean = false,
    /** A new password for this phone's Wi-Fi group (Add a cloud folder to this group); only with [creating]. */
    val adding: Boolean = false,
) {
    private val _password = MutableStateFlow("")
    val password: StateFlow<String> = _password.asStateFlow()

    private val _confirm = MutableStateFlow("")
    /** The repeated password (only when [creating] a new group). */
    val confirm: StateFlow<String> = _confirm.asStateFlow()

    private val _problem = MutableStateFlow<String?>(null)
    /** Shown in the sheet (the two passwords differ); cleared on typing. */
    val problem: StateFlow<String?> = _problem.asStateFlow()

    fun update(text: String) {
        _password.value = text
        _problem.value = null
    }

    fun updateConfirm(text: String) {
        _confirm.value = text
        _problem.value = null
    }

    internal fun setProblem(text: String?) {
        _problem.value = text
    }

    /** Join is enabled only with a password; Create also needs the repeat. */
    val canJoin: Boolean get() = _password.value.isNotEmpty() && (!creating || _confirm.value.isNotEmpty())

    /** Both entries are the same (always true when joining). */
    val matches: Boolean get() = !creating || _password.value == _confirm.value

    /** The password, once: both fields are cleared. */
    fun take(): String {
        val p = _password.value
        _password.value = ""
        _confirm.value = ""
        return p
    }

    override fun toString(): String = "FolderPasswordForm(password=${if (_password.value.isEmpty()) "empty" else "set"})"
}

/**
 * Cloud-folder join from the Sync tab (Swift `SyncScreen` picker and password sheet): pick the folder, then, unless this
 * phone already syncs through the group's folder (choose it again: no password), enter the folder group's sync password
 * and join (new member) or attach (already in the group by QR) through [sync]. Every end that does not keep the picked
 * folder gives its permission up again.
 */
class FolderJoinFlow(private val sync: SyncCoordinator, private val t: Txt) {
    private val words = SyncWording(t)

    private val _form = MutableStateFlow<FolderPasswordForm?>(null)
    /** The password sheet (null: closed). */
    val form: StateFlow<FolderPasswordForm?> = _form.asStateFlow()

    /** The next pick starts a new group (Start a new folder) instead of joining. Only in memory. */
    private var creatingNext = false

    private val _error = MutableStateFlow<String?>(null)
    /** A picker failure, in the desktop's wording (the coordinator reports everything else). */
    val error: StateFlow<String?> = _error.asStateFlow()

    /** Call before opening the picker for "Start a new folder…" (the screen checks Pro first). */
    fun startCreate() {
        creatingNext = true
        addingNext = false
    }

    /** The next pick gives this phone's Wi-Fi group the folder (Add a cloud folder to this group). Only in memory. */
    private var addingNext = false

    /** The add waiting for the "New sync key" confirmation: the folder and the new password (never shown or saved). */
    private var pendingFresh: Pair<String, String>? = null

    private val _freshKeyText = MutableStateFlow<String?>(null)
    /** The "New sync key" confirmation (null: closed): a Wi-Fi device was removed, so the folder gets a new key. */
    val freshKeyText: StateFlow<String?> = _freshKeyText.asStateFlow()

    /** Call before opening the picker for "Add a cloud folder to this group…" (the screen checks Pro first). */
    fun startAdd() {
        creatingNext = false
        addingNext = true
    }

    /** Call before opening the picker for a join (clears a create or an add that was never picked). */
    fun startJoin() {
        creatingNext = false
        addingNext = false
    }

    suspend fun picked(result: FolderPick) {
        _error.value = null
        val creating = creatingNext
        val adding = addingNext
        creatingNext = false
        addingNext = false
        when (result) {
            FolderPick.Cancelled -> {}
            FolderPick.Failed -> _error.value = words.errorText("folder-error")
            is FolderPick.Picked -> {
                sync.refreshMembership()
                val m = sync.membership.value
                if (creating && !m.joined) {
                    _form.value = FolderPasswordForm(result.uri, creating = true)
                } else if (adding && m.joined && !m.hasFolder) {
                    _form.value = FolderPasswordForm(result.uri, creating = true, adding = true)
                } else if (sync.membership.value.hasFolder) {
                    sync.joinFolder(result.uri, "") // choose the folder again: no password
                } else {
                    _form.value = FolderPasswordForm(result.uri)
                }
            }
        }
    }

    /**
     * Join (or create, for a "Start a new folder" form) from the password sheet; false (and nothing happens) without a
     * password. Create keeps the sheet open with a message when the two entries differ; otherwise the sheet closes.
     */
    suspend fun join(): Boolean {
        val f = _form.value ?: return false
        if (!f.canJoin) return false
        if (!f.matches) {
            f.setProblem(t.s(R.string.folder_passwords_mismatch))
            return false
        }
        val password = f.take()
        _form.value = null
        if (f.adding) {
            // A removed Wi-Fi device still knows the key: the folder gets a new one, after a confirmation.
            val m = sync.membership.value
            if (m.lanPeers.any { it.revoked }) {
                pendingFresh = f.uri to password
                val peers = (m.lanPeers.filter { !it.revoked }.map { it.deviceId } + listOfNotNull(m.peer?.deviceId)).distinct()
                _freshKeyText.value = words.newKeyFolderText(peers.map { words.deviceLabel(it, m.names + m.lanPeers.associate { p -> p.deviceId to p.name }) })
                return false
            }
            return sync.createFolder(f.uri, password, add = true)
        }
        return if (f.creating) sync.createFolder(f.uri, password) else sync.joinFolder(f.uri, password)
    }

    /** Continue in the "New sync key" confirmation: the folder is added with a new key. */
    suspend fun confirmFreshKey(): Boolean {
        val (uri, password) = pendingFresh ?: return false
        pendingFresh = null
        _freshKeyText.value = null
        return sync.createFolder(uri, password, add = true, freshKey = true)
    }

    /** The "New sync key" confirmation was cancelled: the picked folder is not used. */
    suspend fun cancelFreshKey() {
        pendingFresh = null
        _freshKeyText.value = null
        sync.releaseUnusedFolders()
    }

    /** The password sheet was cancelled: the picked folder is not used. */
    suspend fun cancel() {
        _form.value?.take()
        _form.value = null
        sync.releaseUnusedFolders()
    }

    override fun toString(): String = "FolderJoinFlow(sheet=${_form.value != null})"
}
