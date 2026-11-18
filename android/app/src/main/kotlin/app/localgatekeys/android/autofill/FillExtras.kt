package app.localgatekeys.android.autofill

import android.content.Intent
import android.os.SystemClock
import androidx.annotation.VisibleForTesting
import app.localgatekeys.android.unlock.HandlerLockScheduler
import app.localgatekeys.android.unlock.LockScheduler
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/** A [FillTarget] in an Intent's extras (our own unexported activities only; never a secret). */
object FillExtras {
    private const val KIND = "lgk.target.kind"
    private const val VALUE = "lgk.target.value"
    private const val BROWSER = "lgk.target.browser"
    private const val CERT = "lgk.target.cert"
    private const val SCHEME_KNOWN = "lgk.target.schemeKnown"

    fun put(i: Intent, t: FillTarget): Intent = when (t) {
        is FillTarget.Web -> i.putExtra(KIND, "web").putExtra(VALUE, t.origin).putExtra(BROWSER, t.browser).putExtra(SCHEME_KNOWN, t.schemeKnown)
        is FillTarget.App -> i.putExtra(KIND, "app").putExtra(VALUE, t.packageName).putExtra(CERT, t.cert)
    }

    fun get(i: Intent): FillTarget? {
        val v = i.getStringExtra(VALUE) ?: return null
        return when (i.getStringExtra(KIND)) {
            "web" -> FillTarget.Web(v, i.getStringExtra(BROWSER) ?: "", i.getBooleanExtra(SCHEME_KNOWN, false))
            "app" -> FillTarget.App(v, i.getStringExtra(CERT) ?: "")
            else -> null
        }
    }
}

/**
 * What the person typed, from `onSaveRequest` to the save sheet, kept in this process only: the Intent that opens the
 * sheet goes through the system and carries just a random token. Entries are taken once, dropped two minutes after
 * they were put (a timer, so a dismissed system save prompt does not leave the password in memory), and all dropped
 * when the vault locks or a duress session opens ([clear]).
 */
object PendingSaves {
    class Pending(val target: FillTarget, val username: String, val password: String, val at: Long) {
        override fun toString(): String = "Pending(target=$target)"
    }

    private const val TTL_SECONDS = 120L
    private val map = ConcurrentHashMap<String, Pending>()
    private val random = SecureRandom()

    /** Test seams: the elapsed-time clock (milliseconds) and the timer that drops an entry at its deadline. */
    @VisibleForTesting
    internal var now: () -> Long = { SystemClock.elapsedRealtime() }

    @VisibleForTesting
    internal var scheduler: LockScheduler? = null

    private fun timers(): LockScheduler = scheduler ?: HandlerLockScheduler().also { scheduler = it }

    fun put(target: FillTarget, username: String, password: String): String {
        val at = now()
        map.entries.removeIf { at - it.value.at > TTL_SECONDS * 1000 }
        val token = ByteArray(16).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }
        map[token] = Pending(target, username, password, at)
        timers().schedule(TTL_SECONDS) { map.remove(token) }
        return token
    }

    fun take(token: String?): Pending? {
        token ?: return null
        val p = map.remove(token) ?: return null
        return if (now() - p.at > TTL_SECONDS * 1000) null else p
    }

    /** The vault locked (or a duress session opened): nothing typed waits for a save any more. */
    fun clear() {
        map.clear()
    }
}
