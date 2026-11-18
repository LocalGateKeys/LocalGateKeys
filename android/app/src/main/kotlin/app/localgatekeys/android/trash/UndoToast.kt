package app.localgatekeys.android.trash

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * "Moved to Recently deleted · Undo" at the bottom of the screen for 5 seconds (port of `ios/App/Trash/UndoToast.swift`),
 * and the short message that follows an undo ("Item restored"). One instance for the app, hosted over every tab and
 * pushed screen by `UndoToastHost`. The host runs the timer and calls [hide] with the serial it showed, so a newer
 * message is never hidden by an older timer.
 */
class UndoToast {
    /** [undo] null: an information message only. [announcement] is what TalkBack reads. */
    class Shown(
        val message: String,
        val announcement: String,
        val serial: Int,
        val millis: Long,
        internal val undo: (suspend () -> Unit)?,
    ) {
        val hasUndo: Boolean get() = undo != null
        override fun toString(): String = "Shown(serial=$serial, undo=$hasUndo)"
    }

    private val _current = MutableStateFlow<Shown?>(null)
    val current: StateFlow<Shown?> = _current.asStateFlow()
    private var serial = 0

    /** Shows [message] with an Undo button for [millis]; a newer message replaces it. */
    @Synchronized
    fun show(message: String, announcement: String = message, millis: Long = PhoneTrash.UNDO_MILLIS, undo: suspend () -> Unit) {
        _current.value = Shown(message, announcement, ++serial, millis, undo)
    }

    /** A message without Undo ("Item restored", or why the undo failed). */
    @Synchronized
    fun info(message: String, millis: Long = SHORT_MILLIS) {
        _current.value = Shown(message, message, ++serial, millis, null)
    }

    /** Undo was tapped: the toast goes and its action runs (once). */
    suspend fun undo() {
        val run = synchronized(this) {
            val shown = _current.value ?: return
            _current.value = null
            shown.undo
        }
        run?.invoke()
    }

    /** The timer of show [serial] ran out; a newer message stays. */
    @Synchronized
    fun hide(serial: Int) {
        if (_current.value?.serial == serial) _current.value = null
    }

    /** Gone at once (the vault locked, or the shell went away). */
    @Synchronized
    fun dismiss() {
        _current.value = null
    }

    override fun toString(): String = "UndoToast(showing=${_current.value != null})"

    companion object {
        const val SHORT_MILLIS = 1_600L
        const val LONG_MILLIS = 3_000L
    }
}
