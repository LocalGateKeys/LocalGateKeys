package app.localgatekeys.android.detail

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import java.util.UUID

/** The few clipboard calls [SystemClipboardSink] makes, so its ownership rules run in JVM tests. */
interface ClipboardPort {
    /** Puts a plain-text clip carrying [tag] (and the sensitive flag when [sensitive]). */
    fun put(text: String, sensitive: Boolean, tag: String)

    /** The tag of the clip on the clipboard ("" when it has none); null when it is empty or this app may not look now. */
    fun visibleTag(): String?

    fun clear()

    /** [listener] runs when the clipboard changes while this app may look. */
    fun onChange(listener: () -> Unit)
}

/**
 * The phone's clipboard. Copies are marked sensitive (`ClipDescription.EXTRA_IS_SENSITIVE`; Android 12 and older read
 * the same key), so the system overlay and the keyboard's clipboard strip show dots instead of the secret.
 *
 * Ownership without reading anyone's text: each copy carries a fresh random tag in its description extras, and only the
 * description is ever read back (reading clip content would show "pasted from your clipboard" for other apps' copies).
 * [current] is our text only while the clipboard visibly carries our tag (like the iPhone's pasteboard change count);
 * any other clip, seen here or by the change listener (which runs while the app has focus), makes the copy not ours.
 * Without window focus Android 10+ hides the clipboard: then [current] is null but ownership is kept, and
 * [SecretClipboard] defers its clear until focus returns (Ruling 14: never a clear without this check).
 *
 * One instance per process (the listener stays registered for the app's life). Main thread only.
 */
class SystemClipboardSink(private val port: ClipboardPort) : ClipboardSink {
    constructor(context: Context) : this(AndroidClipboardPort(context))

    private var ownText: String? = null
    private var ownTag: String? = null

    init {
        port.onChange {
            val t = port.visibleTag()
            if (t != null && t != ownTag) forget()
        }
    }

    override fun set(text: String, sensitive: Boolean) {
        val tag = UUID.randomUUID().toString()
        ownText = text
        ownTag = tag
        port.put(text, sensitive, tag)
    }

    override fun current(): String? {
        val t = port.visibleTag() ?: return null // empty, or not ours to look at now: never claimed blind
        if (t != ownTag) forget()
        return ownText
    }

    override fun clear() {
        forget()
        port.clear()
    }

    private fun forget() {
        ownText = null
        ownTag = null
    }

    override fun toString(): String = "SystemClipboardSink(holdsCopy=${ownText != null})"
}

/** [ClipboardPort] over the system `ClipboardManager`. */
class AndroidClipboardPort(context: Context) : ClipboardPort {
    private val manager = context.applicationContext.getSystemService(ClipboardManager::class.java)

    override fun put(text: String, sensitive: Boolean, tag: String) = manager.setPrimaryClip(clip(text, sensitive, tag))

    override fun visibleTag(): String? {
        val d = try {
            manager.primaryClipDescription
        } catch (_: SecurityException) {
            null
        } ?: return null
        return tagOf(d) ?: ""
    }

    override fun clear() {
        manager.clearPrimaryClip() // API 28+; minSdk is 29
    }

    override fun onChange(listener: () -> Unit) {
        manager.addPrimaryClipChangedListener { listener() }
    }

    companion object {
        /** `ClipDescription.EXTRA_IS_SENSITIVE` (API 33); the same string works as an extra on older versions. */
        val EXTRA_IS_SENSITIVE: String =
            if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE"

        /** Marks the clip as this app's copy (a random tag per copy; it says nothing about the text). */
        const val EXTRA_OWNER_TAG = "app.localgatekeys.android.extra.COPY_TAG"

        fun tagOf(d: ClipDescription): String? = d.extras?.getString(EXTRA_OWNER_TAG)

        /** A plain-text clip without a label, carrying [tag]; [sensitive] marks it so the system never previews it. */
        fun clip(text: String, sensitive: Boolean, tag: String): ClipData {
            val clip = ClipData.newPlainText("", text)
            clip.description.extras = PersistableBundle().apply {
                if (sensitive) putBoolean(EXTRA_IS_SENSITIVE, true)
                putString(EXTRA_OWNER_TAG, tag)
            }
            return clip
        }
    }
}
