package app.localgatekeys.android.ui.sync

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
class FolderPasswordForm(val uri: String) {
    private val _password = MutableStateFlow("")
    val password: StateFlow<String> = _password.asStateFlow()

    fun update(text: String) {
        _password.value = text
    }

    /** Join is enabled only with a password. */
    val canJoin: Boolean get() = _password.value.isNotEmpty()

    /** The password, once: the field is cleared. */
    fun take(): String {
        val p = _password.value
        _password.value = ""
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
class FolderJoinFlow(private val sync: SyncCoordinator) {
    private val _form = MutableStateFlow<FolderPasswordForm?>(null)
    /** The password sheet (null: closed). */
    val form: StateFlow<FolderPasswordForm?> = _form.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    /** A picker failure, in the desktop's wording (the coordinator reports everything else). */
    val error: StateFlow<String?> = _error.asStateFlow()

    suspend fun picked(result: FolderPick) {
        _error.value = null
        when (result) {
            FolderPick.Cancelled -> {}
            FolderPick.Failed -> _error.value = SyncWording.errorText("folder-error")
            is FolderPick.Picked -> {
                sync.refreshMembership()
                if (sync.membership.value.hasFolder) {
                    sync.joinFolder(result.uri, "") // choose the folder again: no password
                } else {
                    _form.value = FolderPasswordForm(result.uri)
                }
            }
        }
    }

    /** Join from the password sheet; false (and nothing happens) without a password. The sheet closes either way. */
    suspend fun join(): Boolean {
        val f = _form.value ?: return false
        if (!f.canJoin) return false
        val password = f.take()
        _form.value = null
        return sync.joinFolder(f.uri, password)
    }

    /** The password sheet was cancelled: the picked folder is not used. */
    suspend fun cancel() {
        _form.value?.take()
        _form.value = null
        sync.releaseUnusedFolders()
    }

    override fun toString(): String = "FolderJoinFlow(sheet=${_form.value != null})"
}
