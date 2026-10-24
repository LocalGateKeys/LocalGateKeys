package app.localgatekeys.android.unlock

import android.view.KeyEvent
import android.view.MotionEvent
import androidx.compose.runtime.staticCompositionLocalOf

/**
 * Reports idle-lock activity ([AppLockModel.noteActivity]) without ever taking part in input: the activity's
 * `dispatchTouchEvent` / `dispatchKeyEvent` pass every event through [dispatchTouch] / [dispatchKey], which look at
 * it and return the activity's own result unchanged. Soft-keyboard typing never reaches the activity's dispatch, so
 * text fields report their changes through [textChanged] (or wrap their callback with [reporting]); screens get the
 * monitor from [LocalActivityMonitor].
 */
class ActivityMonitor(private val onActivity: () -> Unit) {
    /** Counts a touch that begins (first or further finger), then passes the event on. Never consumes it. */
    fun dispatchTouch(actionMasked: Int, pass: () -> Boolean): Boolean {
        if (actionMasked == MotionEvent.ACTION_DOWN || actionMasked == MotionEvent.ACTION_POINTER_DOWN) onActivity()
        return pass()
    }

    /** Counts a hardware key press, then passes the event on. Never consumes it. */
    fun dispatchKey(action: Int, pass: () -> Boolean): Boolean {
        if (action == KeyEvent.ACTION_DOWN) onActivity()
        return pass()
    }

    /** A text field's value changed. */
    fun textChanged() = onActivity()

    /** [onValueChange] that also reports the change as activity. */
    fun <T> reporting(onValueChange: (T) -> Unit): (T) -> Unit = { textChanged(); onValueChange(it) }
}

/** The app's activity monitor (null in previews and tests). */
val LocalActivityMonitor = staticCompositionLocalOf<ActivityMonitor?> { null }
