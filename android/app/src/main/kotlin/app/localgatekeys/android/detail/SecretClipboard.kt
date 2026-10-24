package app.localgatekeys.android.detail

import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.unlock.LockScheduler
import app.localgatekeys.android.unlock.LockTimer
import app.localgatekeys.android.unlock.OwnedClipboard
import app.localgatekeys.core.primitives.UnixClock

/** The system clipboard as the app writes it; [SystemClipboardSink] on the phone, a fake in tests. */
interface ClipboardSink {
    /** Puts [text] on the clipboard; [sensitive] hides it from previews and the keyboard's clipboard strip. */
    fun set(text: String, sensitive: Boolean)

    /**
     * Our last copy while the clipboard verifiably still holds it; null otherwise (someone else's clip, an empty
     * clipboard, or the app may not look now: Android 10+ hides the clipboard from apps without window focus).
     */
    fun current(): String?

    fun clear()
}

/** Seconds that keep counting in deep sleep (`SystemClock.elapsedRealtime`), unlike a Handler's uptime clock. */
class ElapsedClock : UnixClock {
    override val now: Long get() = android.os.SystemClock.elapsedRealtime() / 1000
}

/**
 * Copies secrets marked sensitive and clears them after the expiry chosen in Settings (60 seconds by default). The app
 * shares one instance, so locking can clear what the detail screen or the Codes row copied. A port of
 * `ios/App/Detail/SecretClipboard.swift`: where the iPhone sets a pasteboard expiration date, this keeps a deadline.
 *
 * Ruling 14: the clipboard is never cleared without checking that it still holds our copy ([ClipboardSink.current]),
 * and that check needs window focus. An expiry or a lock that happens while the app has no focus only marks the copy
 * due; [focusChanged] (window focus) and [checkDue] (resume, unlock, lock) run the check later: clear if still ours,
 * otherwise just forget it. The deadline is kept on [clock] (elapsed time, which runs in deep sleep); the [scheduler]
 * timer only covers the app being on screen when it passes, and every focus or check also compares the deadline, so an
 * overdue copy is handled at once.
 *
 * Main thread only.
 */
class SecretClipboard(
    private val sink: ClipboardSink,
    private val settings: AppSettings,
    private val scheduler: LockScheduler,
    private val clock: UnixClock,
) : OwnedClipboard {
    /** What we last copied, while it may still be on the clipboard; null when we hold nothing. */
    private var own: String? = null
    private var deadline: Long? = null
    private var due = false
    private var focused = false
    private var expiryTimer: LockTimer? = null

    val expirySeconds: Long get() = settings.clipboardExpiry.seconds

    /** True while a copy waits for focus to be checked and cleared. */
    val isDue: Boolean get() = due

    fun copy(text: String) {
        expiryTimer?.cancel()
        sink.set(text, sensitive = true)
        own = text
        due = false
        val seconds = expirySeconds
        deadline = clock.now + seconds
        expiryTimer = scheduler.schedule(seconds) {
            expiryTimer = null
            expire()
        }
    }

    /** The app's window gained or lost focus; gaining it runs the check of a due or overdue copy. */
    fun focusChanged(hasFocus: Boolean) {
        focused = hasFocus
        if (hasFocus) checkDue()
    }

    /** Handles our copy if it is due (deadline passed, or a deferred lock): checked and cleared now, or once focused. */
    fun checkDue() {
        if (own == null) return
        val d = deadline ?: return
        if (!due && clock.now < d) return
        expire()
    }

    /** A lock: clear our copy now if it is still there, or check as soon as the app may look. */
    override fun clearIfOwned() = expire()

    private fun expire() {
        if (own == null) return
        if (focused) clearChecked() else due = true
    }

    /** The tag check, then the clear. Our copy is forgotten either way. */
    private fun clearChecked() {
        val ours = own
        expiryTimer?.cancel()
        expiryTimer = null
        own = null
        deadline = null
        due = false
        if (ours != null && sink.current() == ours) sink.clear()
    }

    /** Never shows the copied text. */
    override fun toString(): String = "SecretClipboard(holdsCopy=${own != null}, due=$due, expirySeconds=$expirySeconds)"
}
